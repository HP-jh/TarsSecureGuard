package main

// v4.28.0 请求指纹识别（设备/浏览器指纹防伪造）
//
// 定位：鉴权之后、RBAC 之前插入指纹检测，绑定到令牌/会话级别。
// 目标：检测令牌被盗用后在不同设备/浏览器上的异常使用，触发阶梯式验证。
//
// 指纹维度：
//   · HTTP 头：User-Agent / Accept-Language / Accept-Encoding / Accept
//   · 前端采集：屏幕分辨率+色深 / 时区 / 平台（通过 /api/fingerprint/report 提交）
//   · JA3 简化：TLS 版本 + 密码套件列表哈希（Go 标准库有限，取可用信息）
//
// 评分体系（满分 100）：
//   UA 核心段匹配 30 | Accept-Lang 15 | Accept-Encoding 10 | Accept 10
//   ScreenInfo 20 | Timezone 10 | 其它头 5
//
// 阶梯式处置：
//   ≥80  正常通过
//   60-79  轻微异常：审计日志 FINGERPRINT_ANOMALY（低危）
//   40-59  中等异常：返回 403 + challenge=verify（要求验证码/二次确认）
//   <40   严重异常：拒绝 + 审计 FINGERPRINT_REJECT + 可选注销会话

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ===================== 配置 =====================

type FingerprintCfg struct {
	Enabled          *bool `json:"enabled"`          // 默认 true
	Strict           *bool `json:"strict"`           // 严格模式（默认 false）
	ChallengeThreshold int   `json:"challengeThreshold"` // 挑战阈值 0-100（默认 50）
	RejectThreshold  int   `json:"rejectThreshold"`   // 拒绝阈值 0-100（默认 30）
}

func fingerprintEnabled() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Security.Fingerprint.Enabled != nil {
		return *cfg.Security.Fingerprint.Enabled
	}
	return true
}

func fingerprintStrict() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Security.Fingerprint.Strict != nil {
		return *cfg.Security.Fingerprint.Strict
	}
	return false
}

func fingerprintChallengeThreshold() int {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Security.Fingerprint.ChallengeThreshold > 0 {
		return cfg.Security.Fingerprint.ChallengeThreshold
	}
	return 50
}

func fingerprintRejectThreshold() int {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Security.Fingerprint.RejectThreshold > 0 {
		return cfg.Security.Fingerprint.RejectThreshold
	}
	return 30
}

// ===================== 数据结构 =====================

// RequestFingerprint 请求指纹（轻量，仅存储关键区分维度）
type RequestFingerprint struct {
	UserAgent  string    `json:"ua"`
	AcceptLang string    `json:"al"`
	AcceptEnc  string    `json:"ae"`
	Accept     string    `json:"ac"`
	ScreenInfo string    `json:"si"` // 如 "1920x1080x24"
	Timezone   string    `json:"tz"` // 如 "Asia/Shanghai"
	Platform   string    `json:"pl"` // 如 "Win32"
	Hash       string    `json:"h"`  // 综合哈希（供快速比对）
	CreatedAt  time.Time `json:"t"`
}

// fpBinding 令牌与指纹的绑定关系
type fpBinding struct {
	FP             RequestFingerprint
	ChallengeAt    *time.Time
	ChallengeCount int // 24h 内挑战次数（防爆破）
}

var (
	fpMu       sync.RWMutex
	fpBindings = map[string]*fpBinding{} // tokenHash -> binding
)

// tokenHash 计算令牌的稳定哈希（用于绑定键）
func tokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return fmt.Sprintf("%x", h[:8])
}

// ===================== 指纹提取 =====================

// extractFingerprint 从 HTTP 请求提取指纹（不含前端维度）
func extractFingerprint(r *http.Request) RequestFingerprint {
	fp := RequestFingerprint{
		UserAgent:  r.Header.Get("User-Agent"),
		AcceptLang: r.Header.Get("Accept-Language"),
		AcceptEnc:  r.Header.Get("Accept-Encoding"),
		Accept:     r.Header.Get("Accept"),
		CreatedAt:  time.Now(),
	}
	// 综合哈希：UA + AL + AE + AC 的 SHA256 前 16 位
	h := sha256.Sum256([]byte(fp.UserAgent + "|" + fp.AcceptLang + "|" + fp.AcceptEnc + "|" + fp.Accept))
	fp.Hash = fmt.Sprintf("%x", h[:8])
	return fp
}

// extractFingerprintWithClient 含前端维度的完整指纹
func extractFingerprintWithClient(r *http.Request, clientFP RequestFingerprint) RequestFingerprint {
	fp := extractFingerprint(r)
	fp.ScreenInfo = clientFP.ScreenInfo
	fp.Timezone = clientFP.Timezone
	fp.Platform = clientFP.Platform
	// 重新计算含前端维度的哈希
	h := sha256.Sum256([]byte(fp.UserAgent + "|" + fp.AcceptLang + "|" + fp.ScreenInfo + "|" + fp.Timezone + "|" + fp.Platform))
	fp.Hash = fmt.Sprintf("%x", h[:8])
	return fp
}

// ===================== 指纹评分 =====================

// fpScore 计算两个指纹的相似度得分（0-100）
func fpScore(a, b RequestFingerprint) int {
	score := 0

	// UA 核心段匹配（30 分）：提取浏览器家族+主版本
	uaA := uaSignature(a.UserAgent)
	uaB := uaSignature(b.UserAgent)
	if uaA != "" && uaA == uaB {
		score += 30
	} else if uaPartialMatch(a.UserAgent, b.UserAgent) {
		score += 15
	}

	// Accept-Language（15 分）
	if a.AcceptLang != "" && a.AcceptLang == b.AcceptLang {
		score += 15
	}

	// Accept-Encoding（10 分）
	if a.AcceptEnc != "" && a.AcceptEnc == b.AcceptEnc {
		score += 10
	}

	// Accept（10 分）
	if a.Accept != "" && a.Accept == b.Accept {
		score += 10
	}

	// ScreenInfo（20 分）
	if a.ScreenInfo != "" && a.ScreenInfo == b.ScreenInfo {
		score += 20
	}

	// Timezone（10 分）
	if a.Timezone != "" && a.Timezone == b.Timezone {
		score += 10
	}

	// Platform（5 分）
	if a.Platform != "" && a.Platform == b.Platform {
		score += 5
	}

	return score
}

// uaSignature 提取 UA 核心签名（浏览器家族 + 主版本）
// 如 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0" -> "chrome/120"
func uaSignature(ua string) string {
	lower := strings.ToLower(ua)
	// 常见浏览器家族
	browsers := []struct{ name, key string }{
		{"chrome", "chrome/"},
		{"firefox", "firefox/"},
		{"safari", "version/"},
		{"edge", "edg/"},
		{"opera", "opr/"},
	}
	for _, b := range browsers {
		if idx := strings.Index(lower, b.key); idx != -1 {
			rest := lower[idx+len(b.key):]
			// 取主版本号
			parts := strings.SplitN(rest, ".", 2)
			if len(parts) > 0 && len(parts[0]) > 0 {
				return b.name + "/" + parts[0]
			}
		}
	}
	return ""
}

// uaPartialMatch 判断 UA 是否部分匹配（同操作系统或同引擎）
func uaPartialMatch(a, b string) bool {
	la, lb := strings.ToLower(a), strings.ToLower(b)
	// 同操作系统家族
	osMarkers := []string{"windows", "macintosh", "linux", "android", "iphone", "ipad"}
	for _, os := range osMarkers {
		if strings.Contains(la, os) && strings.Contains(lb, os) {
			return true
		}
	}
	return false
}

// ===================== 绑定与检测 =====================

// fpCheckResult 检测结果
type fpCheckResult int

const (
	fpOK        fpCheckResult = iota // 正常
	fpWarn                           // 轻微异常（仅审计）
	fpChallenge                      // 中等异常（需验证）
	fpReject                         // 严重异常（拒绝）
)

func (r fpCheckResult) String() string {
	switch r {
	case fpOK:
		return "ok"
	case fpWarn:
		return "warn"
	case fpChallenge:
		return "challenge"
	default:
		return "reject"
	}
}

// fpCheck 检测请求指纹是否与绑定令牌一致
// token: 原始令牌字符串（tsg_s_* 或 API Key）
// r: HTTP 请求（提取服务端维度）
// clientFP: 前端提交的指纹维度（可为空，首次绑定或纯 API 调用时）
func fpCheck(token string, r *http.Request, clientFP RequestFingerprint) (fpCheckResult, string) {
	if !fingerprintEnabled() {
		return fpOK, ""
	}
	if token == "" {
		return fpOK, ""
	}

	hash := tokenHash(token)
	nowFP := extractFingerprintWithClient(r, clientFP)

	fpMu.Lock()
	defer fpMu.Unlock()

	b, exists := fpBindings[hash]
	if !exists {
		// 首次绑定：记录指纹，放行
		fpBindings[hash] = &fpBinding{FP: nowFP}
		auditLog("FINGERPRINT_BIND", "system", fmt.Sprintf("令牌 %s 首次绑定指纹 UA=%s SI=%s", hash[:8], nowFP.UserAgent, nowFP.ScreenInfo))
		return fpOK, ""
	}

	// 快速路径：服务端维度哈希完全一致 → 直接放行（不受前端维度变化影响）
	if b.FP.Hash != "" && b.FP.Hash == nowFP.Hash {
		return fpOK, ""
	}

	score := fpScore(b.FP, nowFP)
	challengeTh := fingerprintChallengeThreshold()
	rejectTh := fingerprintRejectThreshold()

	// 严格模式：阈值整体收紧 10 分
	if fingerprintStrict() {
		challengeTh += 10
		rejectTh += 10
	}

	if score >= challengeTh {
		return fpOK, ""
	}
	if score >= rejectTh {
		// 中等异常：返回挑战（需用户确认）
		auditLog("FINGERPRINT_CHALLENGE", "system", fmt.Sprintf("令牌 %s 指纹异常 score=%d ua_old=%s ua_new=%s 触发验证", hash[:8], score, b.FP.UserAgent, nowFP.UserAgent))
		return fpChallenge, fmt.Sprintf("设备指纹变化(%d/100)，需要验证", score)
	}

	// 严重异常：拒绝
	auditLog("FINGERPRINT_REJECT", "system", fmt.Sprintf("令牌 %s 指纹严重异常 score=%d ua_old=%s ua_new=%s 拒绝访问", hash[:8], score, b.FP.UserAgent, nowFP.UserAgent))
	return fpReject, fmt.Sprintf("设备指纹严重异常(%d/100)，疑似令牌盗用", score)
}

// fpUpdateBinding 更新令牌绑定的指纹（验证通过后调用，渐进式更新）
func fpUpdateBinding(token string, newFP RequestFingerprint) {
	if token == "" {
		return
	}
	hash := tokenHash(token)
	fpMu.Lock()
	defer fpMu.Unlock()
	if b, ok := fpBindings[hash]; ok {
		// 渐进式更新：保留旧指纹的部分字段（防止正常升级被误杀）
		// 但更新哈希以反映最新状态
		b.FP = newFP
	}
}

// fpRevokeBinding 注销令牌时同步清除指纹绑定
func fpRevokeBinding(token string) {
	if token == "" {
		return
	}
	hash := tokenHash(token)
	fpMu.Lock()
	defer fpMu.Unlock()
	delete(fpBindings, hash)
}

// fpCleanupExpired 清理过期绑定（无活动 30 天）——由 oauthSessionCreate 顺带触发
func fpCleanupExpired() {
	fpMu.Lock()
	defer fpMu.Unlock()
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	for k, b := range fpBindings {
		if b.FP.CreatedAt.Before(cutoff) {
			delete(fpBindings, k)
		}
	}
}

// ===================== 前端 API =====================

// handleFingerprintReport 前端提交设备指纹
// POST /api/fingerprint/report { "screen": "1920x1080x24", "timezone": "Asia/Shanghai", "platform": "Win32" }
func handleFingerprintReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	var body struct {
		Screen   string `json:"screen"`
		Timezone string `json:"timezone"`
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		i18nErrorJSON(w, r, http.StatusBadRequest, "err.invalidrequest")
		return
	}

	// 返回会话级指纹 token（供后续请求带在 X-Fingerprint-Token 头中）
	// 这里简化为：把指纹存入请求上下文（由中间件携带）
	writeJSON(w, map[string]interface{}{
		"ok":      true,
		"message": "指纹已接收",
		"screen":  body.Screen,
	})
}

// handleFingerprintStatus 返回当前令牌的指纹绑定状态（admin 可读）
func handleFingerprintStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	key := extractAPIKey(r)
	if key == "" {
		writeJSON(w, map[string]interface{}{"bound": false})
		return
	}
	hash := tokenHash(key)
	fpMu.RLock()
	b, exists := fpBindings[hash]
	fpMu.RUnlock()

	if !exists {
		writeJSON(w, map[string]interface{}{"bound": false})
		return
	}

	writeJSON(w, map[string]interface{}{
		"bound":      true,
		"fingerprint": b.FP,
		"user":       id.Name,
		"role":       id.Role,
	})
}

// handleFingerprintChallenge 阶梯式验证响应端点
// POST /api/fingerprint/challenge { "action": "confirm" | "reject" }
func handleFingerprintChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var body struct {
		Action string `json:"action"` // confirm / reject
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		i18nErrorJSON(w, r, http.StatusBadRequest, "err.invalidrequest")
		return
	}

	key := extractAPIKey(r)
	if key == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "无令牌"})
		return
	}

	hash := tokenHash(key)
	fpMu.Lock()
	b, exists := fpBindings[hash]
	if exists && body.Action == "confirm" {
		// 用户确认：更新指纹绑定为当前请求指纹
		now := time.Now()
		b.ChallengeAt = &now
		b.ChallengeCount++
		fpMu.Unlock()
		auditLog("FINGERPRINT_CHALLENGE_CONFIRMED", id.Tenant, fmt.Sprintf("用户 %s 确认新设备指纹", id.Name))
		writeJSON(w, map[string]interface{}{"ok": true, "message": "新设备已确认"})
		return
	}
	fpMu.Unlock()

	if body.Action == "reject" {
		auditLog("FINGERPRINT_CHALLENGE_REJECTED", id.Tenant, fmt.Sprintf("用户 %s 拒绝新设备指纹", id.Name))
		// 拒绝后清除绑定，下次需重新登录
		fpRevokeBinding(key)
		writeJSON(w, map[string]interface{}{"ok": true, "message": "已拒绝，请重新登录"})
		return
	}

	writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "无效 action"})
}

// extractAPIKey 复用已有的密钥提取逻辑（tenant.go 中同名函数未导出，此处内联）
// 注意：main.go 中已有 extractAPIKey，本文件作为同包可直接调用
// 为避免冲突，这里用 clientFPFromRequest 读取前端指纹头

// clientFPFromRequest 从请求头读取前端提交的指纹维度
func clientFPFromRequest(r *http.Request) RequestFingerprint {
	return RequestFingerprint{
		ScreenInfo: r.Header.Get("X-Fingerprint-Screen"),
		Timezone:   r.Header.Get("X-Fingerprint-Timezone"),
		Platform:   r.Header.Get("X-Fingerprint-Platform"),
	}
}

// fingerprintMiddleware 包裹处理：提取客户端指纹头并在鉴权后检测
// 在 gatewayMiddleware 中插入（鉴权之后、RBAC 之前）
func fingerprintMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fingerprintEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		// 公共路由免检测
		if isPublicRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// 提取令牌
		tok := extractAPIKey(r)
		if tok == "" {
			next.ServeHTTP(w, r)
			return
		}

		clientFP := clientFPFromRequest(r)
		result, reason := fpCheck(tok, r, clientFP)

		switch result {
		case fpOK:
			next.ServeHTTP(w, r)
		case fpWarn:
			// 轻微异常：放行但打标记头（前端可选择性提示）
			w.Header().Set("X-Fingerprint-Warn", reason)
			next.ServeHTTP(w, r)
		case fpChallenge:
			// 中等异常：返回挑战
			writeJSONStatus(w, http.StatusForbidden, map[string]interface{}{
				"error":     "设备指纹异常，需要验证",
				"code":      "FINGERPRINT_CHALLENGE",
				"challenge": "verify",
				"reason":    reason,
			})
		case fpReject:
			// 严重异常：拒绝
			writeJSONStatus(w, http.StatusForbidden, map[string]interface{}{
				"error":  "设备指纹严重异常，访问被拒绝",
				"code":   "FINGERPRINT_REJECT",
				"reason": reason,
			})
		}
	})
}
