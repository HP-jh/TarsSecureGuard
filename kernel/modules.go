// Package kernel: SecurityModules — 安全模块实现
//
// 每个安全检查从 gatewayMiddleware 的硬编码中提取为独立的 SecurityModule。
// 参考腾讯 MT 架构组件化：每个模块有明确的版本、开关边界和接口。
//
// 现有 gatewayMiddleware 的安全检查顺序：
//   0. IP 封禁检测
//   1. WAF 检测（含速率限制 + 请求体扫描）
//   2. CORS 预检
//   3. 入站鉴权
//   4. RBAC 矩阵
//   5. 配额检查
//   6. 分层速率限制
//
// 拆分为独立模块后，每个模块可独立测试、独立开关、独立 profile。

package kernel

import (
	"context"
	"net/http"
)

// ===================== IP Ban Stage =====================

// IPBanStage 检查 IP 是否处于动态封禁期
// 对应原 gatewayMiddleware 中的 isBanned(clientIP(r))
type IPBanStage struct {
	IsBanned func(ip string) bool // 注入：IP 封禁判定函数
	OnBlock  func(w http.ResponseWriter, r *http.Request, reason string) // 注入：拦截回调
}

func (s *IPBanStage) Name() string { return "ip-ban-check" }
func (s *IPBanStage) Version() string { return "5.1.0" }

func (s *IPBanStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	if s.IsBanned == nil {
		return Continue // 无注入 → 跳过
	}
	if s.IsBanned(rc.RemoteIP) {
		rc.IPBanned = true
		if s.OnBlock != nil {
			s.OnBlock(w, r, "IP 处于动态封禁期")
		}
		return Halt
	}
	return Continue
}

// Execute 实现 Stage 接口（委托到 Check）
func (s *IPBanStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}

// ===================== WAF Stage =====================

// WAFStage 执行 WAF 检测（含速率限制 + 请求体扫描 + Scanner UA + 敏感路径）
// 对应原 gatewayMiddleware 中的 wafCheck(r)
type WAFStage struct {
	Detect  func(r *http.Request) string // 注入：WAF 检测函数，返回命中规则名
	OnBlock func(w http.ResponseWriter, r *http.Request, reason string) // 注入：拦截回调
}

func (s *WAFStage) Name() string { return "waf" }
func (s *WAFStage) Version() string { return "5.1.0" }

func (s *WAFStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	if s.Detect == nil {
		return Continue
	}
	reason := s.Detect(r)
	if reason != "" {
		rc.WAFHit = reason
		if s.OnBlock != nil {
			s.OnBlock(w, r, reason)
		}
		return Halt
	}
	return Continue
}
// Execute implements Stage interface (delegates to Check)
func (s *WAFStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}


// ===================== CORS Stage =====================

// CORSStage 跨域预检
// 对应原 gatewayMiddleware 中的 OPTIONS 处理
type CORSStage struct {
	IsTrustedOrigin func(origin string) bool // 注入：可信源判定
}

func (s *CORSStage) Name() string { return "cors" }
func (s *CORSStage) Version() string { return "5.1.0" }

func (s *CORSStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	if r.Method != http.MethodOptions {
		return Continue
	}
	origin := r.Header.Get("Origin")
	if origin != "" && s.IsTrustedOrigin != nil && !s.IsTrustedOrigin(origin) {
		w.WriteHeader(http.StatusForbidden)
		return Halt
	}
	w.WriteHeader(http.StatusNoContent)
	return Halt
}
// Execute implements Stage interface (delegates to Check)
func (s *CORSStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}


// ===================== Auth Stage =====================

// AuthStage 入站鉴权
// 对应原 gatewayMiddleware 中的 userFromRequest
type AuthStage struct {
	IsPublicRoute func(path string) bool // 注入：公共路由判定
	Authenticate  func(r *http.Request) (userID, tenant, role string, groups []string, ok bool) // 注入：鉴权函数
}

func (s *AuthStage) Name() string { return "auth" }
func (s *AuthStage) Version() string { return "5.1.0" }

func (s *AuthStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	// 公共路由放行
	if s.IsPublicRoute != nil && s.IsPublicRoute(rc.Path) {
		rc.Authed = true
		return Continue
	}
	if s.Authenticate == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return Halt
	}
	userID, tenant, role, groups, ok := s.Authenticate(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return Halt
	}
	rc.Authed = true
	rc.UserID = userID
	rc.TenantID = tenant
	rc.Role = role
	rc.Groups = groups
	return Continue
}
// Execute implements Stage interface (delegates to Check)
func (s *AuthStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}


// ===================== RBAC Stage =====================

// RBACStage 角色权限矩阵检查
// 对应原 gatewayMiddleware 中的 rbacCheck
type RBACStage struct {
	Verify func(userID, method, path string) (bool, string) // 注入：RBAC 检查
}

func (s *RBACStage) Name() string { return "rbac" }
func (s *RBACStage) Version() string { return "5.1.0" }

func (s *RBACStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	if s.Verify == nil {
		return Continue
	}
	if !rc.Authed {
		return Continue
	}
	ok, reason := s.Verify(rc.UserID, rc.Method, rc.Path)
	if !ok {
		_ = reason
		w.WriteHeader(http.StatusForbidden)
		return Halt
	}
	return Continue
}
// Execute implements Stage interface (delegates to Check)
func (s *RBACStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}


// ===================== RateLimit Stage =====================

// RateLimitStage 分层速率限制
// 对应原 gatewayMiddleware 中的 rateLimitMiddleware
type RateLimitStage struct {
	Allow func(userID, tenant, method, path string) bool // 注入：限流判定
}

func (s *RateLimitStage) Name() string { return "rate-limit" }
func (s *RateLimitStage) Version() string { return "5.1.0" }

func (s *RateLimitStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	if s.Allow == nil {
		return Continue
	}
	if !s.Allow(rc.UserID, rc.TenantID, rc.Method, rc.Path) {
		rc.RateLimitHit = true
		w.WriteHeader(http.StatusTooManyRequests)
		return Halt
	}
	return Continue
}
// Execute implements Stage interface (delegates to Check)
func (s *RateLimitStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}


// ===================== Quota Stage =====================

// QuotaStage 租户/用户/组三层日配额检查
// 对应原 gatewayMiddleware 中的 quotaCheck
type QuotaStage struct {
	Verify func(tenant, userID string, groups []string) (bool, string) // 注入：配额检查
}

func (s *QuotaStage) Name() string { return "quota" }
func (s *QuotaStage) Version() string { return "5.1.0" }

func (s *QuotaStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	if s.Verify == nil {
		return Continue
	}
	ok, why := s.Verify(rc.TenantID, rc.UserID, rc.Groups)
	if !ok {
		_ = why
		w.WriteHeader(http.StatusTooManyRequests)
		return Halt
	}
	return Continue
}
// Execute implements Stage interface (delegates to Check)
func (s *QuotaStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}

