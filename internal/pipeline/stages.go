// Package pipeline 提供 TSG 安全管道的标准阶段实现
//
// 这些阶段对应原 gatewayMiddleware 中的各检测步骤，
// 但解耦为独立、可测试、可组合的 Stage 实现。
// 参考：腾讯 NT 架构的消息处理阶段 + 字节双线程的安全边界隔离

package pipeline

import (
	"context"
	"encoding/json"
	"net/http"
)

// ---- 安全阶段：IP 封禁检测 ----

// IPBanCheckStage 检测 IP 是否处于动态封禁期
// 对应原 gatewayMiddleware 中的 isBanned(clientIP(r)) 步骤
type IPBanCheckStage struct {
	IsBanned func(ip string) bool
	OnBlock  func(ip, path string) // 审计回调
}

func (s IPBanCheckStage) Name() string { return "ip-ban-check" }

func (s IPBanCheckStage) Execute(_ context.Context, rc *RequestContext, w http.ResponseWriter, _ *http.Request) StageResult {
	if s.IsBanned == nil || !s.IsBanned(rc.ClientIP) {
		return Continue
	}
	rc.IPBanned = true
	if s.OnBlock != nil {
		s.OnBlock(rc.ClientIP, "")
	}
	writeBlockResponse(w, http.StatusForbidden, "IP_BANNED", "IP 处于动态封禁期")
	return Halt
}

// ---- 安全阶段：WAF 检测 ----

// WAFCheckStage Web 应用防火墙检测
// 对应原 wafCheck(r) 步骤
type WAFCheckStage struct {
	Check    func(r *http.Request) string // 返回命中规则名，空 = 未命中
	OnHit    func(ip, rule string)        // 联动 IP 信誉扣分等
}

func (s WAFCheckStage) Name() string { return "waf-check" }

func (s WAFCheckStage) Execute(_ context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.Check == nil {
		return Continue
	}
	reason := s.Check(r)
	if reason == "" {
		return Continue
	}
	rc.WAFHit = reason
	if s.OnHit != nil {
		s.OnHit(rc.ClientIP, reason)
	}
	writeBlockResponse(w, http.StatusForbidden, "WAF_BLOCKED", reason)
	return Halt
}

// ---- 安全阶段：CORS 预检 ----

// CORSPreflightStage 处理 OPTIONS 预检请求
type CORSPreflightStage struct {
	IsTrustedOrigin func(origin string) bool
}

func (s CORSPreflightStage) Name() string { return "cors-preflight" }

func (s CORSPreflightStage) Execute(_ context.Context, _ *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if r.Method != http.MethodOptions {
		return Continue
	}
	origin := r.Header.Get("Origin")
	if origin != "" && s.IsTrustedOrigin != nil && !s.IsTrustedOrigin(origin) {
		writeBlockResponse(w, http.StatusForbidden, "CORS_DENIED", "origin not allowed")
		return Halt
	}
	w.WriteHeader(http.StatusNoContent)
	return Halt
}

// ---- 安全阶段：认证 ----

// AuthStage 入站鉴权（API Key / OAuth 会话）
type AuthStage struct {
	IsPublicRoute  func(path string) bool
	Authenticate   func(r *http.Request) (*Identity, bool)
}

// Identity 认证后的身份信息
type Identity struct {
	Name     string
	TenantID string
	Role     string
	Groups   []string
}

func (s AuthStage) Name() string { return "auth" }

func (s AuthStage) Execute(_ context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	// 公共路由直接放行
	if s.IsPublicRoute != nil && s.IsPublicRoute(r.URL.Path) {
		return Continue
	}
	if s.Authenticate == nil {
		return Continue
	}
	id, ok := s.Authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="TarsSecureGuard"`)
		writeBlockResponse(w, http.StatusUnauthorized, "UNAUTHORIZED", "请提供有效的 API Key")
		return Halt
	}
	rc.Authed = true
	rc.UserID = id.Name
	rc.TenantID = id.TenantID
	rc.Role = id.Role
	rc.Groups = id.Groups
	return Continue
}

// ---- 安全阶段：RBAC 权限检查 ----

// RBACCheckStage 基于角色的访问控制
type RBACCheckStage struct {
	Check func(userID, method, path, role string, groups []string) (bool, string)
}

func (s RBACCheckStage) Name() string { return "rbac-check" }

func (s RBACCheckStage) Execute(_ context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if !rc.Authed || s.Check == nil {
		return Continue
	}
	ok, reason := s.Check(rc.UserID, r.Method, r.URL.Path, rc.Role, rc.Groups)
	if ok {
		return Continue
	}
	writeBlockResponse(w, http.StatusForbidden, "FORBIDDEN", "权限不足: "+reason)
	return Halt
}

// ---- 安全阶段：配额检查 ----

// QuotaCheckStage 租户/用户/组日配额检查
type QuotaCheckStage struct {
	RouteClass func(path string) string
	Check      func(tenant, user string, groups []string) (bool, string)
}

func (s QuotaCheckStage) Name() string { return "quota-check" }

func (s QuotaCheckStage) Execute(_ context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if !rc.Authed || s.Check == nil {
		return Continue
	}
	if s.RouteClass != nil && s.RouteClass(r.URL.Path) != "chat" {
		return Continue
	}
	ok, why := s.Check(rc.TenantID, rc.UserID, rc.Groups)
	if ok {
		return Continue
	}
	writeBlockResponse(w, http.StatusTooManyRequests, "QUOTA_EXCEEDED", why)
	return Halt
}

// ---- 安全阶段：速率限制 ----

// RateLimitStage 三维令牌桶限流（IP×端点类 / Key×端点类 / IP 总量）
type RateLimitStage struct {
	Check func(w http.ResponseWriter, r *http.Request, user, tenant string) bool
}

func (s RateLimitStage) Name() string { return "rate-limit" }

func (s RateLimitStage) Execute(_ context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.Check == nil {
		return Continue
	}
	if !s.Check(w, r, rc.UserID, rc.TenantID) {
		rc.RateLimitHit = true
		return Halt // Check 已写入 429 响应
	}
	return Continue
}

// ---- 观测阶段：请求计数 ----

// MetricsStage 请求计数和响应时间统计
type MetricsStage struct {
	OnRequest     func()
	OnComplete    func(statusCode int, duration int64)
}

func (s MetricsStage) Name() string { return "metrics" }

func (s MetricsStage) Execute(_ context.Context, _ *RequestContext, _ http.ResponseWriter, _ *http.Request) StageResult {
	if s.OnRequest != nil {
		s.OnRequest()
	}
	return Continue
}

// ---- 辅助函数 ----

func writeBlockResponse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
