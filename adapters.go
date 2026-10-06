package main

// ===================== v3.2.0 协议适配层（Protocol Adapters）=====================
//
// 四类协议的「请求构建 / 响应归一」适配器：
//   openai-compat  —— 既有主力路径（绝大多数 provider）
//   anthropic      —— /v1/messages，系统提示词走独立 system 字段
//   gemini         —— generateContent，role=model、x-goog-api-key 头
//   ollama         —— /api/chat 原生（既有实现复用）
//
// 两级缓存（均带命中率指标，config v32.responseCache 可调）：
//   ① 协议适配缓存：messages → 目标协议请求体（JSON 序列化）按内容哈希缓存，
//      避免重复格式转换与序列化开销；
//   ② 响应缓存：完整请求（tenant + provider + model + messages）→ 响应文本，
//      TTL 内直接命中（默认 300s / 1024 条 / LRU 淘汰）。
//      —— key 含租户标识，杜绝跨租户命中；缓存值仅为模型输出文本，不含密钥；
//      —— 配置热重载时全量失效（v32CacheInvalidate）。
//
// 安全不变量：适配层只做格式转换；WAF / PII 脱敏 / 语义分级在进入适配层之前
// 已由 handleChat 链路完成，缓存命中的响应同样来自「已过安全链」的出站结果。

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ===================== 协议适配缓存 =====================

var (
	adaptMu    sync.Mutex
	adaptCache = map[string]*list.Element{}
	adaptLRU   list.List
	adaptHits  int64
	adaptMiss  int64
)

type adaptEntry struct {
	key  string
	body []byte
}

const adaptCacheMax = 128

// adaptKey 适配缓存键：协议 + 模型 + 消息内容哈希
func adaptKey(protocol, model string, msgs []Message) string {
	h := sha256.New()
	h.Write([]byte(protocol))
	h.Write([]byte{0})
	h.Write([]byte(model))
	h.Write([]byte{0})
	for _, m := range msgs {
		h.Write([]byte(m.Role))
		h.Write([]byte{0})
		h.Write([]byte(m.Content))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// adaptCacheGet / adaptCachePut LRU 读写
func adaptCacheGet(key string) ([]byte, bool) {
	adaptMu.Lock()
	defer adaptMu.Unlock()
	if el, ok := adaptCache[key]; ok {
		adaptLRU.MoveToFront(el)
		adaptHits++
		return el.Value.(*adaptEntry).body, true
	}
	adaptMiss++
	return nil, false
}

func adaptCachePut(key string, body []byte) {
	adaptMu.Lock()
	defer adaptMu.Unlock()
	if el, ok := adaptCache[key]; ok {
		el.Value.(*adaptEntry).body = body
		adaptLRU.MoveToFront(el)
		return
	}
	adaptCache[key] = adaptLRU.PushFront(&adaptEntry{key: key, body: body})
	if len(adaptCache) > adaptCacheMax {
		if tail := adaptLRU.Back(); tail != nil {
			k := tail.Value.(*adaptEntry).key
			adaptLRU.Remove(tail)
			delete(adaptCache, k)
		}
	}
}

// buildRequestBody 协议适配主入口：构建目标协议请求体（带适配缓存）。
// buildRequestBody v3.3.0：协议分发（+opts 透传 tools；custom 协议由调用方构建，
// 本函数跳过——custom 模板与 provider 绑定，不进协议适配缓存）。
// 适配缓存键包含 tools 哈希，避免同消息不同 tools 的响应串缓存。
func buildRequestBody(protocol, model string, msgs []Message, opts ChatOpts) ([]byte, error) {
	key := adaptKey(protocol, model, msgs)
	if len(opts.Tools) > 0 {
		h := sha256.Sum256(opts.Tools)
		key += fmt.Sprintf(":t%x", h[:8])
	}
	if body, ok := adaptCacheGet(key); ok {
		return body, nil
	}
	var body []byte
	var err error
	switch protocol {
	case "anthropic":
		body, err = buildAnthropicBody(model, msgs)
	case "gemini":
		body, err = buildGeminiBody(model, msgs)
	case "custom":
		return nil, fmt.Errorf("custom 协议需经 buildCustomBody（模板与 provider 绑定）")
	default: // openai-compat
		body, err = buildOpenAIBodyEx(model, msgs, opts)
	}
	if err != nil {
		return nil, err
	}
	adaptCachePut(key, body)
	return body, nil
}

// openAIMessages v3.3.0：按 OpenAI 格式重建消息列表——
// 纯文本消息保持 {"role","content"} 字符串形态（与历史完全一致，字节级不变）；
// 带图片的消息展开为多模态 content 数组（text + image_url 部件）。
func openAIMessages(msgs []Message) []interface{} {
	out := make([]interface{}, 0, len(msgs))
	for _, m := range msgs {
		if len(m.Images) == 0 {
			out = append(out, map[string]interface{}{"role": m.Role, "content": m.Content})
			continue
		}
		parts := []interface{}{}
		if m.Content != "" {
			parts = append(parts, map[string]interface{}{"type": "text", "text": m.Content})
		}
		for _, u := range m.Images {
			parts = append(parts, map[string]interface{}{
				"type":      "image_url",
				"image_url": map[string]string{"url": u},
			})
		}
		out = append(out, map[string]interface{}{"role": m.Role, "content": parts})
	}
	return out
}

func buildOpenAIBody(model string, msgs []Message) ([]byte, error) {
	return buildOpenAIBodyEx(model, msgs, ChatOpts{})
}

// buildOpenAIBodyEx v3.3.0：多模态 content 数组 + tools/tool_choice 透传
func buildOpenAIBodyEx(model string, msgs []Message, opts ChatOpts) ([]byte, error) {
	body := map[string]interface{}{
		"model":      model,
		"messages":   openAIMessages(msgs),
		"max_tokens": 2048,
		"stream":     false,
	}
	if len(opts.Tools) > 0 && string(opts.Tools) != "null" {
		body["tools"] = json.RawMessage(opts.Tools)
	}
	if len(opts.ToolChoice) > 0 && string(opts.ToolChoice) != "null" {
		body["tool_choice"] = json.RawMessage(opts.ToolChoice)
	}
	return json.Marshal(body)
}


func buildAnthropicBody(model string, msgs []Message) ([]byte, error) {
	// system 消息合并进顶层 system 字段；其余保持顺序
	var sysParts []string
	type anthroMsg struct {
		role   string
		blocks []interface{} // 非 nil = 多模态消息（v3.3.0）
	}
	var chat []anthroMsg
	for _, m := range msgs {
		if m.Role == "system" {
			sysParts = append(sysParts, m.Content)
			continue
		}
		role := m.Role
		if role != "user" && role != "assistant" {
			role = "user"
		}
		if len(m.Images) > 0 {
			// v3.3.0 多模态：anthropic content blocks（text + image）
			blocks := []interface{}{}
			if m.Content != "" {
				blocks = append(blocks, map[string]interface{}{"type": "text", "text": m.Content})
			}
			for _, u := range m.Images {
				if src, ok := anthropicImageSource(u); ok {
					blocks = append(blocks, map[string]interface{}{"type": "image", "source": src})
				}
			}
			chat = append(chat, anthroMsg{role: role, blocks: blocks})
			continue
		}
		chat = append(chat, anthroMsg{role: role, blocks: []interface{}{map[string]interface{}{"type": "text", "text": m.Content}}})
	}
	if len(chat) == 0 {
		chat = []anthroMsg{{role: "user", blocks: []interface{}{map[string]interface{}{"type": "text", "text": ""}}}}
	}
	msgsOut := make([]interface{}, 0, len(chat))
	for _, m := range chat {
		msgsOut = append(msgsOut, map[string]interface{}{"role": m.role, "content": m.blocks})
	}
	body := map[string]interface{}{
		"model":      model,
		"max_tokens": 2048,
		"messages":   msgsOut,
	}
	if len(sysParts) > 0 {
		body["system"] = strings.Join(sysParts, "\n\n")
	}
	return json.Marshal(body)
}

// anthropicImageSource v3.3.0：URL → anthropic image source 对象。
// data:URL → base64 内联；http(s):// → url 引用（由 anthropic 侧拉取）。
// 其它格式返回 ok=false（该图跳过，不影响文本与其余图片）。
func anthropicImageSource(u string) (map[string]interface{}, bool) {
	if strings.HasPrefix(u, "data:") {
		mime, data, ok := splitDataURL(u)
		if !ok {
			return nil, false
		}
		return map[string]interface{}{
			"type": "base64", "media_type": mime, "data": data,
		}, true
	}
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return map[string]interface{}{"type": "url", "url": u}, true
	}
	return nil, false
}

func buildGeminiBody(model string, msgs []Message) ([]byte, error) {
	var sysParts []string
	contents := []map[string]interface{}{}
	for _, m := range msgs {
		if m.Role == "system" {
			sysParts = append(sysParts, m.Content)
			continue
		}
		role := "user"
		if m.Role == "assistant" {
			role = "model"
		}
		if len(m.Images) > 0 {
			// v3.3.0 多模态：data:URL → inline_data；http(s):// → file_data
			parts := []interface{}{}
			if m.Content != "" {
				parts = append(parts, map[string]interface{}{"text": m.Content})
			}
			for _, u := range m.Images {
				if p, ok := geminiImagePart(u); ok {
					parts = append(parts, p)
				}
			}
			contents = append(contents, map[string]interface{}{"role": role, "parts": parts})
			continue
		}
		contents = append(contents, map[string]interface{}{
			"role":  role,
			"parts": []map[string]string{{"text": m.Content}},
		})
	}
	if len(contents) == 0 {
		contents = []map[string]interface{}{{"role": "user", "parts": []map[string]string{{"text": ""}}}}
	}
	body := map[string]interface{}{"contents": contents}
	if len(sysParts) > 0 {
		body["systemInstruction"] = map[string]interface{}{
			"parts": []map[string]string{{"text": strings.Join(sysParts, "\n\n")}},
		}
	}
	return json.Marshal(body)
}

// splitDataURL v3.3.0：拆 data:URL → (mime, base64 数据)。格式不符返回 ok=false。
func splitDataURL(u string) (mime, data string, ok bool) {
	if !strings.HasPrefix(u, "data:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(u, "data:")
	i := strings.Index(rest, ",")
	if i < 0 {
		return "", "", false
	}
	meta := rest[:i]
	data = rest[i+1:]
	mime = strings.TrimSpace(strings.Split(meta, ";")[0])
	if mime == "" || !strings.Contains(mime, "/") {
		mime = "image/png"
	}
	return mime, data, true
}

// geminiImagePart v3.3.0：URL → gemini part 对象
func geminiImagePart(u string) (map[string]interface{}, bool) {
	if strings.HasPrefix(u, "data:") {
		mime, data, ok := splitDataURL(u)
		if !ok {
			return nil, false
		}
		return map[string]interface{}{"inline_data": map[string]string{"mime_type": mime, "data": data}}, true
	}
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return map[string]interface{}{"file_data": map[string]string{"file_uri": u}}, true
	}
	return nil, false
}

// ===================== 响应归一 =====================

// parseOpenAIContent 从 OpenAI 兼容响应提取回复文本
func parseOpenAIContent(data []byte) (string, bool) {
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return string(data), true // 非 JSON：整体作为文本返回（与既有行为一致）
	}
	if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if msg, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := msg["content"].(string); ok {
					return content, true
				}
			}
		}
	}
	return string(data), true
}

// parseAnthropicContent 从 Anthropic /v1/messages 响应提取回复文本
func parseAnthropicContent(data []byte) (string, bool) {
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(data, &result); err != nil || len(result.Content) == 0 {
		return "", false
	}
	var sb strings.Builder
	for _, c := range result.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	return sb.String(), true
}

// parseGeminiContent 从 generateContent 响应提取回复文本
func parseGeminiContent(data []byte) (string, bool) {
	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(data, &result); err != nil || len(result.Candidates) == 0 {
		return "", false
	}
	var sb strings.Builder
	for _, p := range result.Candidates[0].Content.Parts {
		sb.WriteString(p.Text)
	}
	return sb.String(), true
}

// parseOpenAIFull v3.3.0：openai-compat 富解析——内容 + usage + tool_calls。
// 与 parseOpenAIContent 语义兼容：解析不出任何字段时 content 返回原文。
func parseOpenAIFull(data []byte) (content string, usage Usage, toolCalls []ToolCall) {
	var result struct {
		Choices []struct {
			Message struct {
				Content   string          `json:"content"`
				ToolCalls []ToolCall      `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		content = string(data)
		return content, usage, nil
	}
	if len(result.Choices) > 0 {
		content = result.Choices[0].Message.Content
		for i := range result.Choices[0].Message.ToolCalls {
			tc := result.Choices[0].Message.ToolCalls[i]
			if tc.Type == "" {
				tc.Type = "function"
			}
			toolCalls = append(toolCalls, tc)
		}
	}
	if result.Usage != nil {
		usage = Usage{
			PromptTokens:     result.Usage.PromptTokens,
			CompletionTokens: result.Usage.CompletionTokens,
			TotalTokens:      result.Usage.TotalTokens,
		}
		if usage.TotalTokens == 0 {
			usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
		}
	}
	if content == "" && usage.TotalTokens == 0 && len(toolCalls) == 0 {
		// JSON 但非 openai 结构：整包文本（与 parseOpenAIContent 兜底一致）
		content = string(data)
	}
	return content, usage, toolCalls
}

// parseAnthropicUsage v3.3.0：anthropic usage（input/output tokens）
func parseAnthropicUsage(data []byte) Usage {
	var result struct {
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(data, &result)
	return Usage{
		PromptTokens:     result.Usage.InputTokens,
		CompletionTokens: result.Usage.OutputTokens,
		TotalTokens:      result.Usage.InputTokens + result.Usage.OutputTokens,
	}
}

// parseGeminiUsage v3.3.0：gemini usageMetadata
func parseGeminiUsage(data []byte) Usage {
	var result struct {
		UsageMetadata struct {
			PromptTokenCount     int64 `json:"promptTokenCount"`
			CandidatesTokenCount int64 `json:"candidatesTokenCount"`
			TotalTokenCount      int64 `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	_ = json.Unmarshal(data, &result)
	return Usage{
		PromptTokens:     result.UsageMetadata.PromptTokenCount,
		CompletionTokens: result.UsageMetadata.CandidatesTokenCount,
		TotalTokens:      result.UsageMetadata.TotalTokenCount,
	}
}

// ===================== 响应缓存（tenant 隔离 · v3.2.3 分片锁）=====================

type respEntry struct {
	value    string
	expireAt time.Time
	el       *list.Element
}

// respShard v3.2.3 性能升级 v2：响应缓存按 key 哈希切 16 片，每片独立 mutex + LRU，
// 高并发下争用面从全局 1 把锁降到 1/16；命中/未命中计数随片存放，cacheStats 聚合。
// 语义变化（有意为之并在此声明）：容量上限按片均分（(max+15)/16），LRU 淘汰在片内进行——
// 极端 key 分布不均时总条数可能略低于全局上限，仍满足「不超过 max」的硬约束。
const respShardCount = 16

type respShard struct {
	mu     sync.Mutex
	cache  map[string]*respEntry
	lru    list.List
	hits   int64
	misses int64
}

var respShards [respShardCount]respShard

func init() {
	for i := range respShards {
		respShards[i].cache = map[string]*respEntry{}
	}
}

// respShardFor key → 分片（FNV-1a 低成本稳定散列；仅取前 8 字节 + 长度，
// 生产 key 为 64 位 hex sha256，前 8 字节已充分均匀，避免长 key 逐字节全扫开销）
func respShardFor(key string) *respShard {
	var h uint32 = 2166136261
	n := len(key)
	if n > 8 {
		n = 8
	}
	for i := 0; i < n; i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	h ^= uint32(len(key))
	h *= 16777619
	return &respShards[h%respShardCount]
}

// v32RespCacheEnabled 响应缓存开关（默认开；config v32.responseCache.enabled=false 关）
func v32RespCacheEnabled() bool {
	if e := cfg.V32Config.ResponseCache.Enabled; e != nil {
		return *e
	}
	return true
}

func v32RespCacheTTL() time.Duration {
	if t := cfg.V32Config.ResponseCache.TTLSec; t > 0 {
		return time.Duration(t) * time.Second
	}
	return 300 * time.Second
}

func v32RespCacheMax() int {
	if m := cfg.V32Config.ResponseCache.MaxEntries; m > 0 {
		return m
	}
	// v3.2.0：默认 1024 条。注册表已覆盖 24 云端 provider + 8 本地运行时，
	// 256 条在多 provider 并行时工作集轻松超限、LRU 抖动直接吃掉命中率；
	// 单条仅存字符串回复（非原始响应体），1024 条内存占用仍为 MB 级。
	return 1024
}

// respShardMax 单分片容量上限：总量约束 ≤ v32RespCacheMax()
func respShardMax() int {
	return (v32RespCacheMax() + respShardCount - 1) / respShardCount
}

// respCacheKey 响应缓存键：tenant + provider + model + messages 内容哈希。
// tenant 入键 → 跨租户永不命中（即使提示词完全相同）。
func respCacheKey(tenant, provider, model string, msgs []Message) string {
	h := sha256.New()
	h.Write([]byte(tenant))
	h.Write([]byte{0})
	h.Write([]byte(provider))
	h.Write([]byte{0})
	h.Write([]byte(model))
	h.Write([]byte{0})
	for _, m := range msgs {
		h.Write([]byte(m.Role))
		h.Write([]byte{0})
		h.Write([]byte(m.Content))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func respCacheGet(key string) (string, bool) {
	sh := respShardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if e, ok := sh.cache[key]; ok {
		if time.Now().Before(e.expireAt) {
			sh.lru.MoveToFront(e.el)
			sh.hits++
			return e.value, true
		}
		// 过期淘汰
		sh.lru.Remove(e.el)
		delete(sh.cache, key)
	}
	sh.misses++
	return "", false
}

func respCachePut(key, value string) {
	sh := respShardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	ttl := v32RespCacheTTL()
	if e, ok := sh.cache[key]; ok {
		e.value = value
		e.expireAt = time.Now().Add(ttl)
		sh.lru.MoveToFront(e.el)
		return
	}
	el := sh.lru.PushFront(key)
	sh.cache[key] = &respEntry{value: value, expireAt: time.Now().Add(ttl), el: el}
	if len(sh.cache) > respShardMax() {
		if tail := sh.lru.Back(); tail != nil {
			k := tail.Value.(string)
			if e, ok := sh.cache[k]; ok {
				sh.lru.Remove(e.el)
			}
			delete(sh.cache, k)
		}
	}
}

// v32CacheInvalidate 全量失效（配置热重载时调用；语义与 tier1 缓存失效对齐）
func v32CacheInvalidate(reason string) {
	adaptMu.Lock()
	adaptCache = map[string]*list.Element{}
	adaptLRU.Init()
	adaptMu.Unlock()
	for i := range respShards {
		sh := &respShards[i]
		sh.mu.Lock()
		sh.cache = map[string]*respEntry{}
		sh.lru.Init()
		sh.mu.Unlock()
	}
	logMsg("[V32] 缓存全量失效: " + reason)
}

// cacheStats 缓存指标快照（分片聚合）
func cacheStats() map[string]interface{} {
	adaptMu.Lock()
	adaptTotal := adaptHits + adaptMiss
	adaptRate := 0.0
	if adaptTotal > 0 {
		adaptRate = float64(adaptHits) / float64(adaptTotal) * 100
	}
	adaptEntries := len(adaptCache)
	adaptMu.Unlock()
	var respHits, respMisses, respEntries int64
	for i := range respShards {
		sh := &respShards[i]
		sh.mu.Lock()
		respHits += sh.hits
		respMisses += sh.misses
		respEntries += int64(len(sh.cache))
		sh.mu.Unlock()
	}
	respTotal := respHits + respMisses
	respRate := 0.0
	if respTotal > 0 {
		respRate = float64(respHits) / float64(respTotal) * 100
	}
	return map[string]interface{}{
		"enabled":       v32RespCacheEnabled(),
		"adaptCache":    map[string]interface{}{"entries": adaptEntries, "hits": adaptHits, "misses": adaptMiss, "hitRatePct": round2(adaptRate)},
		"responseCache": map[string]interface{}{"entries": respEntries, "hits": respHits, "misses": respMisses, "hitRatePct": round2(respRate), "ttlSec": int(v32RespCacheTTL().Seconds()), "maxEntries": v32RespCacheMax(), "shards": respShardCount},
	}
}

// handleV32Cache GET /api/admin/v32/cache —— 缓存指标（admin.read）
func handleV32Cache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	writeJSON(w, cacheStats())
}

// ===================== provider 出站调用（适配层主路径）=====================

// callProviderChat 经注册表调用一个 provider（v3.3.0：包装 Full 版，无 tools 路径）。
func callProviderChat(spec ProviderSpec, model string, msgs []Message, tenant, trace string) (string, error) {
	content, _, _, err := callProviderChatFull(spec, model, msgs, tenant, trace, ChatOpts{})
	return content, err
}

// callProviderChatFull v3.3.0：经注册表调用一个 provider 的富路径——
// 熔断检查 → 响应缓存 → 协议适配（含 custom 模板协议）→ 共享连接池出站 →
// 响应归一（内容 + usage + tool_calls）→ 熔断记录 → 缓存回填。
// tenant 为空串时（如 handleUrgent 等无身份路径）用 "-" 占位。
func callProviderChatFull(spec ProviderSpec, model string, msgs []Message, tenant, trace string, opts ChatOpts) (content string, usage Usage, toolCalls []ToolCall, err error) {
	if !providerEnabled(spec) {
		return "", usage, nil, fmt.Errorf("provider %s 已禁用（config providers.%s.enabled=false）", spec.ID, spec.ID)
	}
	if !cbAllow(spec.ID) {
		return "", usage, nil, fmt.Errorf("provider %s 熔断中（连续失败，冷却后自动恢复；详见 /api/admin/v32/providers）", spec.ID)
	}
	key, hasKey := providerAPIKey(spec)
	if spec.Kind == "cloud" && !hasKey {
		return "", usage, nil, fmt.Errorf("provider %s 未配置密钥（config.json providers.%s.apiKey 或环境变量 %s）", spec.ID, spec.ID, spec.KeyEnv)
	}

	// v3.3.0：custom 协议必须带模板定义
	if spec.Protocol == "custom" && spec.Custom == nil {
		return "", usage, nil, fmt.Errorf("provider %s 声明 custom 协议但缺少 custom 模板定义", spec.ID)
	}

	// 响应缓存命中 → 直接返回（不再出站）；tools 请求不进缓存（结果含函数调用，
	// 缓存整段文本会丢 tool_calls 语义）
	tenantKey := tenant
	if tenantKey == "" {
		tenantKey = "-"
	}
	ck := respCacheKey(tenantKey, spec.ID, model, msgs)
	if len(opts.Tools) > 0 {
		ck += ":tools"
	}
	cacheable := v32RespCacheEnabled() && len(opts.Tools) == 0
	if cacheable {
		if v, ok := respCacheGet(ck); ok {
			return v, usage, nil, nil
		}
	}

	if spec.Protocol == "custom" {
		content, usage, err = callCustomProvider(spec, model, msgs, key, trace)
		if err != nil {
			cbRecord(spec.ID, false)
			return "", usage, nil, err
		}
		if cacheable {
			respCachePut(ck, content)
		}
		return content, usage, nil, nil
	}

	body, err := buildRequestBody(spec.Protocol, model, msgs, opts)
	if err != nil {
		cbRecord(spec.ID, false)
		return "", usage, nil, err
	}
	endpoint := providerChatEndpoint(spec, model)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		cbRecord(spec.ID, false)
		return "", usage, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	switch spec.Protocol {
	case "anthropic":
		req.Header.Set("x-api-key", key)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "gemini":
		req.Header.Set("x-goog-api-key", key)
	default:
		if hasKey {
			req.Header.Set("Authorization", "Bearer "+key)
		}
	}
	traceHeaderForward(req, trace)

	obsStart := time.Now()
	resp, err := httpClientLong.Do(req)
	backendLabel := spec.ID
	if err != nil {
		obsRecordBackend(trace, backendLabel, false, time.Since(obsStart).Milliseconds(), 0)
		cbRecord(spec.ID, false)
		return "", usage, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	ok := resp.StatusCode == 200
	obsRecordBackend(trace, backendLabel, ok, time.Since(obsStart).Milliseconds(), resp.StatusCode)
	cbRecord(spec.ID, ok)
	if !ok {
		return "", usage, nil, fmt.Errorf("上游 %s: %s", spec.ID, strings.TrimSpace(string(data)))
	}

	switch spec.Protocol {
	case "anthropic":
		if c, okp := parseAnthropicContent(data); okp {
			content = c
		} else {
			content = string(data)
		}
		usage = parseAnthropicUsage(data)
	case "gemini":
		if c, okp := parseGeminiContent(data); okp {
			content = c
		} else {
			content = string(data)
		}
		usage = parseGeminiUsage(data)
	default:
		var tcs []ToolCall
		content, usage, tcs = parseOpenAIFull(data)
		// 无结构化结果时 parseOpenAIFull 会把整包当文本；usage 全 0 时不误报
		toolCalls = tcs
	}
	if cacheable {
		respCachePut(ck, content)
	}
	return content, usage, toolCalls, nil
}

// callCustomProvider v3.3.0：custom 协议出站——任意 HTTP 后端模板化接入。
// 模板占位符（值替换，非注入执行）：
//   {{.Key}} {{.Model}} {{.System}} {{.User}} {{.Prompt}}={{.User}}
//   {{.MessagesJSON}}  消息数组 [{role,content}] 的 JSON 串
// headers 值同样支持占位符展开（典型：Authorization: Bearer {{.Key}}）。
func callCustomProvider(spec ProviderSpec, model string, msgs []Message, key, trace string) (string, Usage, error) {
	c := spec.Custom
	method := strings.ToUpper(strings.TrimSpace(c.Method))
	if method == "" {
		method = http.MethodPost
	}
	// 汇总模板上下文
	var system, user string
	for _, m := range msgs {
		if m.Role == "system" {
			system += m.Content + "\n"
		}
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			user = msgs[i].Content
			break
		}
	}
	msgsJSON, _ := json.Marshal(msgs)
	ctxVals := map[string]string{
		"Key":           key,
		"Model":         model,
		"System":        strings.TrimSuffix(system, "\n"),
		"User":          user,
		"Prompt":        user,
		"MessagesJSON":  string(msgsJSON),
		"Trace":         trace,
	}
	bodyBytes, err := buildCustomBody(c.Body, ctxVals)
	if err != nil {
		return "", Usage{}, err
	}
	base, _ := providerEffectiveURL(spec)
	endpoint := strings.TrimSuffix(base, "/") + c.Path
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.Headers {
		req.Header.Set(k, expandTemplate(v, ctxVals))
	}
	traceHeaderForward(req, trace)
	obsStart := time.Now()
	resp, err := httpClientLong.Do(req)
	if err != nil {
		obsRecordBackend(trace, spec.ID, false, time.Since(obsStart).Milliseconds(), 0)
		return "", Usage{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	obsRecordBackend(trace, spec.ID, resp.StatusCode == 200, time.Since(obsStart).Milliseconds(), resp.StatusCode)
	if resp.StatusCode != 200 {
		return "", Usage{}, fmt.Errorf("上游 %s: %s", spec.ID, strings.TrimSpace(string(data)))
	}
	content, ok := extractJSONPath(data, c.ResponsePath)
	if !ok {
		return "", Usage{}, fmt.Errorf("provider %s：responsePath %q 未命中响应结构", spec.ID, c.ResponsePath)
	}
	return content, Usage{}, nil
}

// buildCustomBody 递归展开模板值（map / slice / string 均支持）
func buildCustomBody(tpl interface{}, vals map[string]string) ([]byte, error) {
	expanded := expandValue(tpl, vals)
	return json.Marshal(expanded)
}

func expandValue(v interface{}, vals map[string]string) interface{} {
	switch t := v.(type) {
	case string:
		return expandTemplate(t, vals)
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, vv := range t {
			out[k] = expandValue(vv, vals)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(t))
		for _, vv := range t {
			out = append(out, expandValue(vv, vals))
		}
		return out
	default:
		return v
	}
}

func expandTemplate(s string, vals map[string]string) string {
	for k, v := range vals {
		s = strings.ReplaceAll(s, "{{."+k+"}}", v)
	}
	return s
}

// extractJSONPath 点路径取值（a.b.0.c）；叶子为字符串返回其值，
// 其它类型返回 JSON 序列化文本
func extractJSONPath(data []byte, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	var cur interface{}
	if err := json.Unmarshal(data, &cur); err != nil {
		return "", false
	}
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]interface{}:
			v, ok := node[seg]
			if !ok {
				return "", false
			}
			cur = v
		case []interface{}:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return "", false
			}
			cur = node[idx]
		default:
			return "", false
		}
	}
	switch leaf := cur.(type) {
	case string:
		return leaf, true
	default:
		b, err := json.Marshal(leaf)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}
