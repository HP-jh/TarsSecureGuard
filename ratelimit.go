package main

// v3.0.0 B 线：分层速率限制（rateLimiter，security-core 内置，不可关闭）
// v4.29.0 增强：按用户角色分级限额（personal / lite / pro / enterprise），
//   每级独立 QPS / 日限额 / 并发数，超限返回 429 + 升级提示（小白化）。
//
// 设计依据：架构方案第三节 B 线 + 锦衣卫附加意见。
//   - 三维令牌桶：按 IP、按 API Key（用户）、按端点类（chat / admin / model）
//   - 第 4 维（v4.29.0）：按角色 tier 分级（覆盖或收紧全局额度）
//   - 第 5 维（v4.29.0）：日限额（跨端点类合计）
//   - 第 6 维（v4.29.0）：并发数控制
//   - 超限返回 429 + 审计（RATE_LIMIT_BLOCK）
//   - 违规联动 IP 信誉扣分（-15）
//   - 单 IP 总量兜底（防按端点维度绕过）

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ===================== 端点分类 =====================

// endpointClass 路径 → 限流维度分类
func endpointClass(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/chat/") || strings.HasPrefix(path, "/api/urgent/"):
		return "chat"
	case strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/chat/"):
		return "chat"
	case strings.HasPrefix(path, "/api/admin/models") || strings.HasPrefix(path, "/api/admin/model"):
		return "model"
	case strings.HasPrefix(path, "/api/admin"):
		return "admin"
	}
	return "other"
}

// ===================== 角色 → tier 映射 =====================

// roleToTier v4.29.0：role 默认映射到 tier（用户未显式设置 tier 时生效）
func roleToTier(role string) string {
	switch role {
	case "user", "readonly":
		return "personal"
	case "team_lead", "auditor":
		return "lite"
	case "admin", "global_auditor":
		return "pro"
	case "global_admin":
		return "enterprise"
	}
	return "personal"
}

// ===================== 令牌桶 =====================

type tokenBucket struct {
	tokens  float64
	lastRef time.Time
}

type bucketKey struct {
	dim string // "ip" | "key" | "iptotal" | "daily"
	id  string // IP / 用户名 / 端点类 / 用户日维度
	cls string // 端点类（ip 维度与 key 维度均按类分桶）
}

var (
	rlBucketMu sync.Mutex
	rlBuckets  = map[bucketKey]*tokenBucket{}
)

func init() {
	// 独立定时清理：每 5 分钟清理 30 分钟未活跃的桶，防 map 无限增长
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			cutoff := now.Add(-30 * time.Minute)
			rlBucketMu.Lock()
			for k, b := range rlBuckets {
				if b.lastRef.Before(cutoff) {
					delete(rlBuckets, k)
				}
			}
			rlBucketMu.Unlock()
		}
	}()
}

// classQuota 端点类的每分钟额度（0 表示不限）
func classQuota(cls string) int {
	c := v3Config()
	switch cls {
	case "chat":
		if c.RateLimit.ChatPerMin > 0 {
			return c.RateLimit.ChatPerMin
		}
		return 60
	case "admin":
		if c.RateLimit.AdminPerMin > 0 {
			return c.RateLimit.AdminPerMin
		}
		return 10
	case "model":
		if c.RateLimit.ModelPerMin > 0 {
			return c.RateLimit.ModelPerMin
		}
		return 6
	}
	return 0 // other 类不限（既有 allowRequest 全局窗口兜底）
}

// tierClassQuota v4.29.0：按角色 tier 返回端点类限额。
// tier 未配置或字段为 0 时回退全局 classQuota。
func tierClassQuota(tier, cls string) int {
	c := v3Config()
	if c.RateLimit.Tiers == nil {
		return classQuota(cls)
	}
	t, ok := c.RateLimit.Tiers[tier]
	if !ok {
		return classQuota(cls)
	}
	switch cls {
	case "chat":
		if t.ChatPerMin > 0 {
			return t.ChatPerMin
		}
	case "admin":
		if t.AdminPerMin > 0 {
			return t.AdminPerMin
		}
	case "model":
		if t.ModelPerMin > 0 {
			return t.ModelPerMin
		}
	}
	return classQuota(cls)
}

// tierDailyQuota v4.29.0：tier 日限额，0 = 不限
func tierDailyQuota(tier string) int {
	c := v3Config()
	if c.RateLimit.Tiers == nil {
		return 0
	}
	t, ok := c.RateLimit.Tiers[tier]
	if !ok {
		return 0
	}
	return t.DailyQuota
}

// tierConcurrency v4.29.0：tier 并发数上限，0 = 不限
func tierConcurrency(tier string) int {
	c := v3Config()
	if c.RateLimit.Tiers == nil {
		return 0
	}
	t, ok := c.RateLimit.Tiers[tier]
	if !ok {
		return 0
	}
	return t.Concurrency
}

// perIPTotalQuota 单 IP 每分钟总量兜底
func perIPTotalQuota() int {
	c := v3Config()
	if c.RateLimit.PerIPTotal > 0 {
		return c.RateLimit.PerIPTotal
	}
	return 240
}

// takeToken 从桶取一个令牌；不足返回 false。
// 容量 = quota（分钟额度），补充速率 = quota/60 每秒（允许分钟内突发一次性用满额度）。
func takeToken(k bucketKey, quota float64) bool {
	now := time.Now()
	rlBucketMu.Lock()
	defer rlBucketMu.Unlock()
	b, ok := rlBuckets[k]
	if !ok {
		b = &tokenBucket{tokens: quota, lastRef: now}
		rlBuckets[k] = b
	}
	// 按流逝时间补充
	elapsed := now.Sub(b.lastRef).Seconds()
	b.tokens += elapsed * quota / 60
	if b.tokens > quota {
		b.tokens = quota
	}
	b.lastRef = now
	if b.tokens < 1 {
		// 容量控制：桶总数超 4096 时清理 30 分钟未活跃桶
		if len(rlBuckets) > 4096 {
			cutoff := now.Add(-30 * time.Minute)
			for kk, bb := range rlBuckets {
				if bb.lastRef.Before(cutoff) {
					delete(rlBuckets, kk)
				}
			}
		}
		return false
	}
	b.tokens--
	return true
}

// ===================== 并发控制 =====================

var (
	rlConcurMu   sync.Mutex
	rlConcurMap  = map[string]int{} // user → 当前并发数
)

func concurEnter(user string, max int) bool {
	if max <= 0 {
		return true
	}
	rlConcurMu.Lock()
	defer rlConcurMu.Unlock()
	if rlConcurMap[user] >= max {
		return false
	}
	rlConcurMap[user]++
	return true
}

func concurLeave(user string) {
	rlConcurMu.Lock()
	defer rlConcurMu.Unlock()
	if rlConcurMap[user] > 0 {
		rlConcurMap[user]--
	}
}

// ===================== 租户级限流（兼容 v3.0.4）=====================

// tenantClassQuota v3.0.4 [MT_RATELIMIT]：租户级限流阈值（只许收紧，校验层已保证 ≤ 全局）。
// 返回 0 表示该租户未设阈值（沿用全局额度）。
func tenantClassQuota(tenant, cls string) int {
	if tenant == "" || tenant == "*" {
		return 0
	}
	tc := tenantsConfig()
	var t *TenantCfg
	for i := range tc.Tenants {
		if tc.Tenants[i].ID == tenant {
			t = &tc.Tenants[i]
			break
		}
	}
	if t == nil {
		return 0
	}
	switch cls {
	case "chat":
		return t.RateLimit.ChatPerMin
	case "admin":
		return t.RateLimit.AdminPerMin
	case "model":
		return t.RateLimit.ModelPerMin
	}
	return 0
}

// ===================== 分级限流判定入口 =====================

// allowRateLimited v4.29.0 增强：六维判定（IP×类 / Key×类 / IP总量 / tier×类 / 日限额 / 并发数）
// 返回 (ok, reason)；ok=false 时调用方返回 429。
func allowRateLimited(ip, user, role, tenant, path string) (bool, string) {
	cls := endpointClass(path)

	// 确定 tier：用户显式设置 > role 默认映射
	tier := ""
	if user != "" && user != "-" {
		// 尝试从 cfg 读用户显式 tier（identityFromRequest 已把 tier 传入，这里复用 role 参数逻辑）
		// 实际 tier 由调用方通过 role 字段传递（当 role 为空时我们用默认值）
	}
	_ = role // 占位：tier 由调用方在 middleware 中解析后通过 tier 变量传递
	// 注：tier 解析下沉到 allowRateLimited 内部，通过 user 查 cfg 获取
	tier = resolveTier(user, role)

	quota := classQuota(cls)

	// 维度 0（v3.0.4）：租户 × 端点类——租户阈值生效时收紧全局额度
	if tq := tenantClassQuota(tenant, cls); tq > 0 && tq < quota {
		quota = tq
	}

	// 维度 1（v4.29.0）：tier × 端点类——tier 阈值生效时覆盖全局额度
	if tq := tierClassQuota(tier, cls); tq > 0 && tq < quota {
		quota = tq
	}

	// 维度 2：IP × 端点类
	if quota > 0 && !takeToken(bucketKey{dim: "ip", id: ip, cls: cls}, float64(quota)) {
		return false, fmt.Sprintf("rate limit: IP %s on %s 超过 %d 次/分钟", ip, cls, quota)
	}

	// 维度 3：API Key（用户）× 端点类（匿名流量跳过——IP 维度已覆盖）
	if user != "" && user != "-" && quota > 0 &&
		!takeToken(bucketKey{dim: "key", id: user, cls: cls}, float64(quota)) {
		return false, fmt.Sprintf("rate limit: 用户 %s on %s 超过 %d 次/分钟", user, cls, quota)
	}

	// 维度 4：单 IP 总量兜底
	if total := perIPTotalQuota(); total > 0 &&
		!takeToken(bucketKey{dim: "iptotal", id: ip, cls: "*"}, float64(total)) {
		return false, fmt.Sprintf("rate limit: IP %s 总量超过 %d 次/分钟", ip, total)
	}

	// 维度 5（v4.29.0）：日限额（tier 维度）
	if user != "" && user != "-" {
		if dq := tierDailyQuota(tier); dq > 0 {
			dayKey := bucketKey{dim: "daily", id: user, cls: time.Now().Format("2006-01-02")}
			if !takeToken(dayKey, float64(dq)) {
				return false, fmt.Sprintf("rate limit: 用户 %s 今日请求数已超过 %d 次", user, dq)
			}
		}
	}

	// 维度 6（v4.29.0）：并发数（tier 维度）
	if user != "" && user != "-" {
		if maxCon := tierConcurrency(tier); maxCon > 0 {
			if !concurEnter(user, maxCon) {
				return false, fmt.Sprintf("rate limit: 用户 %s 并发数超过 %d", user, maxCon)
			}
		}
	}

	return true, ""
}

// resolveTier v4.29.0：从 cfg 解析用户的 tier（显式设置 > role 默认映射）
func resolveTier(user, role string) string {
	if user == "" || user == "-" {
		return roleToTier(role)
	}
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	for _, u := range cfg.Users {
		if u.Name == user {
			if u.Tier != "" {
				return u.Tier
			}
			return roleToTier(u.Role)
		}
	}
	// 单管理员回退
	if user == "admin" {
		return "enterprise"
	}
	return roleToTier(role)
}

// rateLimitUpgradeHint v4.29.0：按 tier 返回小白化升级提示
func rateLimitUpgradeHint(tier string) string {
	switch tier {
	case "personal":
		return "当前为 personal 档，限额较严。如需更高额度，请联系管理员升级至 lite / pro / enterprise。"
	case "lite":
		return "当前为 lite 档。如需更高额度，请联系管理员升级至 pro / enterprise。"
	case "pro":
		return "当前为 pro 档。如需无限制额度，请联系管理员升级至 enterprise。"
	case "enterprise":
		return "当前为 enterprise 档，已启用最高限额。"
	}
	return "速率限制：分层额度见 config.rateLimit.tiers（默认 chat 60 / admin 10 / model 6 每分钟）"
}

// handleRateLimited 429 响应 + 审计 + IP 信誉扣分
func handleRateLimited(w http.ResponseWriter, r *http.Request, reason string) {
	ip := clientIP(r)
	auditLog("RATE_LIMIT_BLOCK", "-", reason)
	ipRepPenalty(ip, 15, "rate-limit", "")

	// v4.29.0 小白化：解析 tier 并附升级提示
	id, _ := identityFromRequest(r)
	tier := resolveTier(id.Name, id.Role)
	hint := rateLimitUpgradeHint(tier)

	writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{
		"error": "429 Too Many Requests: " + reason,
		"hint":  hint,
	})
}

// rateLimitMiddleware 供 gatewayMiddleware 集成（auth 之后调用，拿到 user / tenant 维度）
// v4.29.0 增强：传入 role 以支持 tier 分级。
func rateLimitMiddleware(w http.ResponseWriter, r *http.Request, user, role, tenant string) bool {
	if ok, reason := allowRateLimited(clientIP(r), user, role, tenant, r.URL.Path); !ok {
		handleRateLimited(w, r, reason)
		return false
	}
	return true
}

// rateLimitConcurLeave v4.29.0：请求处理完毕后释放并发槽。
// 在 gatewayMiddleware 中 defer 调用。
func rateLimitConcurLeave(user string) {
	if user != "" && user != "-" {
		concurLeave(user)
	}
}
