package main

// v3.0.0 B 线：语义检测分级分流（semanticGuard 模块）
//
// 设计依据：架构方案第三节 B 线 + 锦衣卫裁定 1（fail-close）全项：
//   - 静态规则先行：命中拒绝规则直接 block，命中放行规则直接 allow
//   - 灰区（<5% 流量预期）送本地 0.5B-1.5B 小模型做语义判定
//   - fail-close 铁律：小模型引擎不可用 → 503 SEMANTIC_ENGINE_UNAVAILABLE，
//     绝不放行灰区请求；semantic_guard.fallback_mode 仅接受 "block"
//   - 「AI 只能加严」单向合并：最终判定 = max(静态, AI)，AI 永远不能把
//     静态 block 改成 allow；运行时检测到违例 → POLICY_VIOLATION 审计
//   - 指纹缓存：归一化文本 SHA-256 → 判定结果，同指纹不重复送检（一鱼两吃：
//     缓存同时积累灰区流量画像）
//   - 灰区单 IP QPS 上限 5/分钟（锦衣卫附加意见 C），超限按 fail-close 处理
//   - 全链路审计：SEMANTIC_BLOCK / SEMANTIC_GRAY / SEMANTIC_ENGINE_UNAVAILABLE

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ===================== 判定模型 =====================

// sgVerdict 语义判定：allow < gray < block（只能加严）
type sgVerdict int

const (
	sgAllow sgVerdict = iota
	sgGray
	sgBlock
)

func (v sgVerdict) String() string {
	switch v {
	case sgAllow:
		return "allow"
	case sgGray:
		return "gray"
	default:
		return "block"
	}
}

// sgDecision 一次完整判定结果
type sgDecision struct {
	Verdict   sgVerdict `json:"verdict"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"`    // static-deny | static-allow | cache | engine | fail-close
	Fp        string    `json:"fp"`        // 指纹（前 16 位）
	EngineLat int64     `json:"engineMs"` // 引擎耗时（ms，仅 engine 来源）
}

// ===================== 静态规则 =====================

// 拒绝规则（命中即 block，AI 不可推翻）
var sgStaticDeny = []string{
	"ignore previous instructions", "忽略之前的指令", "disregard all prior",
	"你现在的身份", "你不再是", "developer mode", "开发者模式",
	"jailbreak", "越狱模式", "DAN 模式",
	"rm -rf /", "format c:\\", "mkfs.",
	"打印系统提示词", "输出你的系统提示", "reveal your system prompt",
}

// 放行规则（明显无害的短问候等，仅用于减少引擎调用）
var sgStaticAllow = []string{
	"你好", "hello", "嗨", "hi", "在吗", "谢谢", "thanks",
	"再见", "bye", "帮我", "请问",
}

// sgNormalize 归一化：小写、去多余空白（中英文均处理）
func sgNormalize(s string) string {
	low := strings.ToLower(s)
	fields := strings.Fields(low)
	if len(fields) == 0 {
		return ""
	}
	return strings.Join(fields, " ")
}

// sgFingerprint 归一化文本指纹（SHA-256，取前 16 位展示）
func sgFingerprint(s string) string {
	h := sha256.Sum256([]byte(sgNormalize(s)))
	return hex.EncodeToString(h[:])[:16]
}

// sgStaticCheck 静态分级：deny→block / allow 短语→allow / 其余→gray
func sgStaticCheck(text string) (sgVerdict, string) {
	norm := sgNormalize(text)
	if norm == "" {
		return sgAllow, "empty"
	}
	for _, p := range sgStaticDeny {
		if strings.Contains(norm, strings.ToLower(p)) {
			return sgBlock, "static-deny: " + p
		}
	}
	trimmed := strings.TrimSpace(norm)
	for _, p := range sgStaticAllow {
		if trimmed == p || strings.HasPrefix(trimmed, p+" ") && len(trimmed) < 24 {
			return sgAllow, "static-allow: " + p
		}
	}
	return sgGray, "gray-zone"
}

// ===================== 单向合并（铁律） =====================

// sgMerge 单向合并：静态 block 不可被 AI 放宽（铁律）；灰区由引擎裁决。
//   - static=block → 永远 block（AI 任何判定都只能维持或本就加严）
//   - ai=block → block（AI 加严）
//   - ai=allow → allow（引擎裁决灰区放行）
//   - 其余 → gray（引擎自身不确定，由上层 fail-close 兜底）
// 若 AI 判定试图把静态 block 放宽 → 运行时 POLICY_VIOLATION 审计（锦衣卫裁定 2 三层约束之运行时层）。
func sgMerge(static, ai sgVerdict, ctx string) sgVerdict {
	if static == sgBlock && ai != sgBlock {
		auditLog("POLICY_VIOLATION", "system",
			fmt.Sprintf("语义合并违例：静态 block 被 AI %s 试图放宽（ctx=%s），已按铁律取 block", ai, ctx))
		return sgBlock
	}
	if ai == sgBlock {
		return sgBlock // AI 加严：允许
	}
	if ai == sgAllow {
		return sgAllow // 引擎裁决灰区放行（static 最多是 gray）
	}
	return sgGray
}

// ===================== 状态 =====================

type sgCacheEntry struct {
	verdict  sgVerdict
	reason   string
	expireAt time.Time
}

var (
	sgMu       sync.Mutex
	sgCache    = map[string]sgCacheEntry{} // fp -> verdict
	sgGrayIP   = map[string]*tokenBucket{} // 灰区单 IP 令牌桶（5/min）
	sgStats    = struct{ Total, Gray, Blocked, CacheHit, EngineFail uint64 }{}
	sgHTTPCli  = &http.Client{Timeout: 3 * time.Second}
)

// ===================== 配置 =====================

type sgConfig struct {
	Enabled       bool
	EngineURL     string // 本地小模型引擎端点（POST JSON）
	FallbackMode  string // 仅接受 "block"（锦衣卫裁定 1）
	GrayIPPerMin  int    // 灰区单 IP 上限，默认 5
	CacheTTLMin   int    // 指纹缓存 TTL，默认 60
	CacheMaxItems int
}

func sgGetConfig() sgConfig {
	c := v3Config()
	out := sgConfig{Enabled: true, FallbackMode: "block", GrayIPPerMin: 5, CacheTTLMin: 60, CacheMaxItems: 4096}
	// 模块注册表开关优先（模块关 = 用户显式选择，静态 deny 仍生效但灰区不送检）
	if !moduleEnabledByID("semanticGuard") {
		out.Enabled = false
	}
	if c.SemanticGuard.Enabled != nil {
		if *c.SemanticGuard.Enabled {
			out.Enabled = true // 显式开启优先于模块表默认
		} else {
			out.Enabled = false
		}
	}
	out.EngineURL = c.SemanticGuard.EngineURL
	if c.SemanticGuard.FallbackMode != "" {
		out.FallbackMode = c.SemanticGuard.FallbackMode
	}
	// fallback_mode 白名单校验：非 block 一律按 block（fail-close）
	if out.FallbackMode != "block" {
		auditLog("POLICY_VIOLATION", "system",
			fmt.Sprintf("semantic_guard.fallback_mode=%q 非法（仅允许 block），已强制回退 block", out.FallbackMode))
		out.FallbackMode = "block"
	}
	if c.SemanticGuard.GrayIPPerMin > 0 {
		out.GrayIPPerMin = c.SemanticGuard.GrayIPPerMin
	}
	if c.SemanticGuard.CacheTTLMin > 0 {
		out.CacheTTLMin = c.SemanticGuard.CacheTTLMin
	}
	return out
}

// ===================== 引擎调用 =====================

type sgEngineRequest struct {
	Text string `json:"text"`
}

type sgEngineResponse struct {
	Verdict string `json:"verdict"` // block | allow | gray
	Reason  string `json:"reason"`
}

// sgEngineAsk 调用本地小模型引擎。任何错误 = 引擎不可用（fail-close 由调用方处理）。
func sgEngineAsk(engineURL, text string) (sgVerdict, string, int64, error) {
	start := time.Now()
	body, _ := json.Marshal(sgEngineRequest{Text: text})
	resp, err := sgHTTPCli.Post(engineURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return sgGray, "", 0, fmt.Errorf("引擎连接失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return sgGray, "", 0, fmt.Errorf("引擎返回 %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return sgGray, "", 0, err
	}
	var er sgEngineResponse
	if err := json.Unmarshal(raw, &er); err != nil {
		return sgGray, "", 0, fmt.Errorf("引擎响应解析失败: %v", err)
	}
	lat := time.Since(start).Milliseconds()
	switch strings.ToLower(er.Verdict) {
	case "block":
		return sgBlock, er.Reason, lat, nil
	case "allow":
		return sgAllow, er.Reason, lat, nil
	default:
		return sgGray, er.Reason, lat, nil // 引擎自身不确定 → 视为灰区 → fail-close
	}
}

// ===================== 主入口 =====================

// sgLastUserText 提取最后一条用户消息文本
func sgLastUserText(msgs []Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" || msgs[i].Role == "human" {
			return msgs[i].Content
		}
	}
	return ""
}

// sgClassify 全链路判定。blockSecond=true 表示第二阶段（已有初判后的复核）。
func sgClassify(text, clientIP string) sgDecision {
	cfg := sgGetConfig()
	fp := sgFingerprint(text)
	sgMu.Lock()
	sgStats.Total++
	sgMu.Unlock()

	if !cfg.Enabled {
		// 模块关闭：静态 deny 仍然生效（security-core 不可关闭的一部分），
		// 灰区不再送检、不 fail-close —— 模块级开关是用户显式选择。
		if v, why := sgStaticCheck(text); v == sgBlock {
			sgMu.Lock()
			sgStats.Blocked++
			sgMu.Unlock()
			return sgDecision{Verdict: sgBlock, Reason: why, Source: "static-deny", Fp: fp}
		}
		return sgDecision{Verdict: sgAllow, Reason: "semanticGuard off", Source: "static", Fp: fp}
	}

	// 1) 静态分级
	static, why := sgStaticCheck(text)
	if static == sgBlock {
		sgMu.Lock()
		sgStats.Blocked++
		sgMu.Unlock()
		return sgDecision{Verdict: sgBlock, Reason: why, Source: "static-deny", Fp: fp}
	}
	if static == sgAllow {
		return sgDecision{Verdict: sgAllow, Reason: why, Source: "static-allow", Fp: fp}
	}

	// 2) 灰区：指纹缓存命中 → 直接复用（缓存值只经单向合并产生，可信任）
	sgMu.Lock()
	sgStats.Gray++
	if e, ok := sgCache[fp]; ok && time.Now().Before(e.expireAt) {
		sgStats.CacheHit++
		sgMu.Unlock()
		v := e.verdict
		if v == sgBlock {
			sgStats.Blocked++
		}
		return sgDecision{Verdict: v, Reason: e.reason, Source: "cache", Fp: fp}
	}
	sgMu.Unlock()

	// 3) 灰区单 IP QPS 上限（锦衣卫附加意见 C）：超限按 fail-close
	if !sgTakeGrayQuota(clientIP, cfg.GrayIPPerMin) {
		sgMu.Lock()
		sgStats.EngineFail++
		sgMu.Unlock()
		return sgDecision{Verdict: sgBlock, Reason: "灰区检测配额超限（单 IP " + fmt.Sprint(cfg.GrayIPPerMin) + "/分钟）", Source: "fail-close", Fp: fp}
	}

	// 4) 引擎判定（fail-close：不可用即拒绝灰区请求，绝不放行）
	if cfg.EngineURL == "" {
		sgMu.Lock()
		sgStats.EngineFail++
		sgMu.Unlock()
		return sgDecision{Verdict: sgBlock, Reason: "语义引擎未配置（semantic_guard.engine_url）", Source: "fail-close", Fp: fp}
	}
	ai, aiWhy, lat, err := sgEngineAsk(cfg.EngineURL, text)
	if err != nil {
		sgMu.Lock()
		sgStats.EngineFail++
		sgMu.Unlock()
		auditLog("SEMANTIC_ENGINE_UNAVAILABLE", "system", fmt.Sprintf("灰区请求 fail-close：%v", err))
		return sgDecision{Verdict: sgBlock, Reason: "语义引擎不可用，fail-close 拒绝: " + err.Error(), Source: "fail-close", Fp: fp}
	}

	// 5) 单向合并 + 缓存
	final := sgMerge(static, ai, fp)
	sgCachePut(fp, final, "engine: "+aiWhy, cfg)
	sgMu.Lock()
	if final == sgBlock {
		sgStats.Blocked++
	}
	sgMu.Unlock()
	return sgDecision{Verdict: final, Reason: "engine: " + aiWhy, Source: "engine", Fp: fp, EngineLat: lat}
}

// sgTakeGrayQuota 灰区单 IP 令牌桶（容量=quota/分钟）
func sgTakeGrayQuota(ip string, perMin int) bool {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return true // 本机不限
	}
	sgMu.Lock()
	defer sgMu.Unlock()
	k := "sggray:" + ip
	b, ok := sgGrayIP[ip]
	if !ok {
		b = &tokenBucket{tokens: float64(perMin), lastRef: time.Now()}
		sgGrayIP[ip] = b
		if len(sgGrayIP) > 4096 {
			for kk, bb := range sgGrayIP {
				if time.Since(bb.lastRef) > 10*time.Minute {
					delete(sgGrayIP, kk)
				}
			}
		}
	}
	_ = k
	now := time.Now()
	b.tokens += float64(perMin) * now.Sub(b.lastRef).Minutes()
	if b.tokens > float64(perMin) {
		b.tokens = float64(perMin)
	}
	b.lastRef = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// sgCachePut 写缓存（带 TTL 与容量上限）
func sgCachePut(fp string, v sgVerdict, reason string, cfg sgConfig) {
	sgMu.Lock()
	defer sgMu.Unlock()
	// 只缓存确定判定；gray 不缓存（引擎不确定本身不可复用）
	if v == sgGray {
		return
	}
	if len(sgCache) >= cfg.CacheMaxItems {
		oldest := ""
		var oldestT time.Time
		for k, e := range sgCache {
			if oldest == "" || e.expireAt.Before(oldestT) {
				oldest, oldestT = k, e.expireAt
			}
		}
		if oldest != "" {
			delete(sgCache, oldest)
		}
	}
	sgCache[fp] = sgCacheEntry{verdict: v, reason: reason, expireAt: time.Now().Add(time.Duration(cfg.CacheTTLMin) * time.Minute)}
}

// ===================== chat 链路集成 =====================

// semanticGuardChat 在 handleChat 内调用：返回 false = 已写响应（拒绝），上层 return
func semanticGuardChat(w http.ResponseWriter, r *http.Request, req *ChatRequest) bool {
	text := sgLastUserText(req.Messages)
	if text == "" {
		return true
	}
	dec := sgClassify(text, clientIP(r))
	switch dec.Verdict {
	case sgBlock:
		auditLog("SEMANTIC_BLOCK", userFromRequestSafe(r), fmt.Sprintf("fp=%s 来源=%s 原因=%s", dec.Fp, dec.Source, dec.Reason))
		ipRepPenalty(clientIP(r), 15, "semantic-block")
		code := http.StatusForbidden
		if dec.Source == "fail-close" {
			code = http.StatusServiceUnavailable // 503 SEMANTIC_ENGINE_UNAVAILABLE（锦衣卫裁定 1）
		}
		writeJSONStatus(w, code, map[string]string{
			"error":  "内容被安全护栏拦截（AI 判定只能加严，不可放宽）",
			"detail": dec.Reason,
			"source": dec.Source,
		})
		return false
	case sgGray:
		// 引擎返回 gray 也按 fail-close 处理（不确定即拒绝）——在 sgClassify 已合并，
		// 这里兜底：不可能到达（merge 后 gray 视作需拒绝）。保守写 503。
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "SEMANTIC_ENGINE_UNAVAILABLE"})
		return false
	}
	if dec.Source == "engine" || dec.Source == "cache" {
		auditLog("SEMANTIC_GRAY_PASS", userFromRequestSafe(r), fmt.Sprintf("fp=%s 灰区经语义引擎复核放行（%dms）", dec.Fp, dec.EngineLat))
	}
	return true
}

// userFromRequestSafe 鉴权信息仅用于审计展示，失败不阻断
func userFromRequestSafe(r *http.Request) string {
	name, _, ok := userFromRequest(r)
	if !ok {
		return "anonymous"
	}
	return name
}

// ===================== 管理端点 =====================

// handleSemanticStatus 灰区流量画像（评分榜/动态防护可视化数据源）
func handleSemanticStatus(w http.ResponseWriter, r *http.Request) {
	sgMu.Lock()
	st := sgStats
	cacheLen := len(sgCache)
	sgMu.Unlock()
	writeJSON(w, map[string]interface{}{
		"enabled":        sgGetConfig().Enabled,
		"total":          st.Total,
		"gray":           st.Gray,
		"blocked":        st.Blocked,
		"cacheHit":       st.CacheHit,
		"engineFail":     st.EngineFail,
		"cacheItems":     cacheLen,
		"grayShare":      sharePct(st.Gray, st.Total),
		"fallbackMode":   sgGetConfig().FallbackMode,
		"engineURLSet":   sgGetConfig().EngineURL != "",
	})
}

func sharePct(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}
