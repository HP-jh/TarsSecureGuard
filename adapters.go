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
func buildRequestBody(protocol, model string, msgs []Message) ([]byte, error) {
	key := adaptKey(protocol, model, msgs)
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
	default: // openai-compat
		body, err = buildOpenAIBody(model, msgs)
	}
	if err != nil {
		return nil, err
	}
	adaptCachePut(key, body)
	return body, nil
}

func buildOpenAIBody(model string, msgs []Message) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"model":      model,
		"messages":   msgs,
		"max_tokens": 2048,
		"stream":     false,
	})
}

func buildAnthropicBody(model string, msgs []Message) ([]byte, error) {
	// system 消息合并进顶层 system 字段；其余保持顺序
	var sysParts []string
	var chat []Message
	for _, m := range msgs {
		if m.Role == "system" {
			sysParts = append(sysParts, m.Content)
			continue
		}
		role := m.Role
		if role != "user" && role != "assistant" {
			role = "user"
		}
		chat = append(chat, Message{Role: role, Content: m.Content})
	}
	if len(chat) == 0 {
		chat = []Message{{Role: "user", Content: ""}}
	}
	body := map[string]interface{}{
		"model":      model,
		"max_tokens": 2048,
		"messages":   chat,
	}
	if len(sysParts) > 0 {
		body["system"] = strings.Join(sysParts, "\n\n")
	}
	return json.Marshal(body)
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

// callProviderChat 经注册表调用一个 provider：熔断检查 → 响应缓存 → 协议适配 →
// 共享连接池出站 → 响应归一 → 熔断记录 → 缓存回填。
// tenant 为空串时（如 handleUrgent 等无身份路径）用 "-" 占位。
func callProviderChat(spec ProviderSpec, model string, msgs []Message, tenant, trace string) (string, error) {
	if !providerEnabled(spec) {
		return "", fmt.Errorf("provider %s 已禁用（config providers.%s.enabled=false）", spec.ID, spec.ID)
	}
	if !cbAllow(spec.ID) {
		return "", fmt.Errorf("provider %s 熔断中（连续失败，冷却后自动恢复；详见 /api/admin/v32/providers）", spec.ID)
	}
	key, hasKey := providerAPIKey(spec)
	if spec.Kind == "cloud" && !hasKey {
		return "", fmt.Errorf("provider %s 未配置密钥（config.json providers.%s.apiKey 或环境变量 %s）", spec.ID, spec.ID, spec.KeyEnv)
	}

	// 响应缓存命中 → 直接返回（不再出站）
	tenantKey := tenant
	if tenantKey == "" {
		tenantKey = "-"
	}
	ck := respCacheKey(tenantKey, spec.ID, model, msgs)
	if v32RespCacheEnabled() {
		if v, ok := respCacheGet(ck); ok {
			return v, nil
		}
	}

	body, err := buildRequestBody(spec.Protocol, model, msgs)
	if err != nil {
		cbRecord(spec.ID, false)
		return "", err
	}
	endpoint := providerChatEndpoint(spec, model)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		cbRecord(spec.ID, false)
		return "", err
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
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	ok := resp.StatusCode == 200
	obsRecordBackend(trace, backendLabel, ok, time.Since(obsStart).Milliseconds(), resp.StatusCode)
	cbRecord(spec.ID, ok)
	if !ok {
		return "", fmt.Errorf("上游 %s: %s", spec.ID, strings.TrimSpace(string(data)))
	}

	var content string
	switch spec.Protocol {
	case "anthropic":
		if c, okp := parseAnthropicContent(data); okp {
			content = c
		} else {
			content = string(data)
		}
	case "gemini":
		if c, okp := parseGeminiContent(data); okp {
			content = c
		} else {
			content = string(data)
		}
	default:
		content, _ = parseOpenAIContent(data)
	}
	if v32RespCacheEnabled() {
		respCachePut(ck, content)
	}
	return content, nil
}
