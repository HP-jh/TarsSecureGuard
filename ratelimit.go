package main

// v3.0.0 B 线：分层速率限制（rateLimiter，security-core 内置，不可关闭）
//
// 设计依据：架构方案第三节 B 线 + 锦衣卫附加意见。
//   - 三维令牌桶：按 IP、按 API Key（用户）、按端点类（chat / admin / model）
//   - 超限返回 429 + 审计（RATE_LIMIT_BLOCK）
//   - 违规联动 IP 信誉扣分（-15）
//   - 单 IP 总量兜底（防按端点维度绕过）
//
// 实现为简单令牌桶：容量 = 速率（每分钟额度），每秒补充 rate/60。

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
	case strings.HasPrefix(path, "/api/admin/models") || strings.HasPrefix(path, "/api/admin/model"):
		return "model"
	case strings.HasPrefix(path, "/api/admin"):
		return "admin"
	}
	return "other"
}

// ===================== 令牌桶 =====================

type tokenBucket struct {
	tokens  float64
	lastRef time.Time
}

type bucketKey struct {
	dim string // "ip" | "key" | "iptotal"
	id  string // IP / 用户名 / 端点类
	cls string // 端点类（ip 维度与 key 维度均按类分桶）
}

var (
	rlBucketMu sync.Mutex
	rlBuckets  = map[bucketKey]*tokenBucket{}
)

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

// allowRateLimited 三维判定入口（gatewayMiddleware 调用）。
// 返回 (ok, reason)；ok=false 时调用方返回 429。
// v3.0.4 增第 4 维：租户 × 端点类（[MT_RATELIMIT]，阈值只许比全局严）。
func allowRateLimited(ip, user, tenant, path string) (bool, string) {
	cls := endpointClass(path)
	quota := classQuota(cls)
	// 维度 0（v3.0.4）：租户 × 端点类——租户阈值生效时收紧全局额度
	if tq := tenantClassQuota(tenant, cls); tq > 0 && tq < quota {
		quota = tq
	}
	// 维度 1：IP × 端点类
	if quota > 0 && !takeToken(bucketKey{dim: "ip", id: ip, cls: cls}, float64(quota)) {
		return false, fmt.Sprintf("rate limit: IP %s on %s 超过 %d 次/分钟", ip, cls, quota)
	}
	// 维度 2：API Key（用户）× 端点类（匿名流量跳过——IP 维度已覆盖）
	if user != "" && user != "-" && quota > 0 &&
		!takeToken(bucketKey{dim: "key", id: user, cls: cls}, float64(quota)) {
		return false, fmt.Sprintf("rate limit: 用户 %s on %s 超过 %d 次/分钟", user, cls, quota)
	}
	// 维度 3：单 IP 总量兜底
	if total := perIPTotalQuota(); total > 0 &&
		!takeToken(bucketKey{dim: "iptotal", id: ip, cls: "*"}, float64(total)) {
		return false, fmt.Sprintf("rate limit: IP %s 总量超过 %d 次/分钟", ip, total)
	}
	return true, ""
}

// handleRateLimited 429 响应 + 审计 + IP 信誉扣分
func handleRateLimited(w http.ResponseWriter, r *http.Request, reason string) {
	ip := clientIP(r)
	auditLog("RATE_LIMIT_BLOCK", "-", reason)
	ipRepPenalty(ip, 15, "rate-limit")
	mRateLimitTotal.Inc()
	w.Header().Set("Retry-After", "60")
	writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{
		"error": "429 Too Many Requests: " + reason,
		"hint":  "速率限制：分层额度见 config.rateLimit（默认 chat 60 / admin 10 / model 6 每分钟）",
	})
}

// rateLimitMiddleware 供 gatewayMiddleware 集成（auth 之后调用，拿到 user / tenant 维度）
func rateLimitMiddleware(w http.ResponseWriter, r *http.Request, user, tenant string) bool {
	if ok, reason := allowRateLimited(clientIP(r), user, tenant, r.URL.Path); !ok {
		handleRateLimited(w, r, reason)
		return false
	}
	return true
}
