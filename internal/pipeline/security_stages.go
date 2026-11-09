package pipeline

import (
	"context"
	"net/http"
)

// SecurityStages 将现有安全函数包装为 Pipeline Stages
// 这些 stages 对应 gatewayMiddleware 中的安全检查步骤

// IPBanStage 检查 IP 是否被封禁
type IPBanStage struct {
	isBanned func(ip string) bool
}

func NewIPBanStage(isBanned func(string) bool) *IPBanStage {
	return &IPBanStage{isBanned: isBanned}
}

func (s *IPBanStage) Name() string { return "ip-ban-check" }

func (s *IPBanStage) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.isBanned == nil {
		return Continue
	}
	if s.isBanned(rc.ClientIP) {
		rc.IPBanned = true
		http.Error(w, "IP banned", http.StatusForbidden)
		return Halt
	}
	return Continue
}

// WAFStage Web 应用防火墙检查
type WAFStage struct {
	wafCheck func(r *http.Request) string
}

func NewWAFStage(wafCheck func(*http.Request) string) *WAFStage {
	return &WAFStage{wafCheck: wafCheck}
}

func (s *WAFStage) Name() string { return "waf-check" }

func (s *WAFStage) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.wafCheck == nil {
		return Continue
	}
	if reason := s.wafCheck(r); reason != "" {
		rc.WAFHit = reason
		http.Error(w, "WAF blocked: "+reason, http.StatusForbidden)
		return Halt
	}
	return Continue
}

// RateLimitStage 速率限制检查
type RateLimitStage struct {
	rateLimitCheck func(r *http.Request, user string) bool
}

func NewRateLimitStage(check func(*http.Request, string) bool) *RateLimitStage {
	return &RateLimitStage{rateLimitCheck: check}
}

func (s *RateLimitStage) Name() string { return "rate-limit" }

func (s *RateLimitStage) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.rateLimitCheck == nil {
		return Continue
	}
	if !s.rateLimitCheck(r, rc.UserID) {
		rc.RateLimitHit = true
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return Halt
	}
	return Continue
}

// AuthStage 认证检查
type AuthStage struct {
	authenticate func(r *http.Request) (*Identity, bool)
}

func NewAuthStage(auth func(*http.Request) (*Identity, bool)) *AuthStage {
	return &AuthStage{authenticate: auth}
}

func (s *AuthStage) Name() string { return "auth" }

func (s *AuthStage) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.authenticate == nil {
		return Continue
	}
	identity, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return Halt
	}
	rc.Authed = true
	rc.UserID = identity.Name
	rc.TenantID = identity.TenantID
	rc.Role = identity.Role
	rc.Groups = identity.Groups
	return Continue
}

// RBACStage 基于角色的访问控制
type RBACStage struct {
	rbacCheck func(method, path, role string, groups []string) (bool, string)
}

func NewRBACStage(check func(string, string, string, []string) (bool, string)) *RBACStage {
	return &RBACStage{rbacCheck: check}
}

func (s *RBACStage) Name() string { return "rbac" }

func (s *RBACStage) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.rbacCheck == nil || !rc.Authed {
		return Continue
	}
	ok, reason := s.rbacCheck(r.Method, r.URL.Path, rc.Role, rc.Groups)
	if !ok {
		http.Error(w, "Forbidden: "+reason, http.StatusForbidden)
		return Halt
	}
	return Continue
}

// QuotaStage 配额检查
type QuotaStage struct {
	quotaCheck func(tenant, user string, groups []string) (bool, string)
}

func NewQuotaStage(check func(string, string, []string) (bool, string)) *QuotaStage {
	return &QuotaStage{quotaCheck: check}
}

func (s *QuotaStage) Name() string { return "quota" }

func (s *QuotaStage) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.quotaCheck == nil || !rc.Authed {
		return Continue
	}
	ok, reason := s.quotaCheck(rc.TenantID, rc.UserID, rc.Groups)
	if !ok {
		http.Error(w, "Quota exceeded: "+reason, http.StatusTooManyRequests)
		return Halt
	}
	return Continue
}

// SecurityHeadersStage 设置安全响应头
type SecurityHeadersStage struct {
	setHeaders func(w http.ResponseWriter, r *http.Request)
}

func NewSecurityHeadersStage(setHeaders func(http.ResponseWriter, *http.Request)) *SecurityHeadersStage {
	return &SecurityHeadersStage{setHeaders: setHeaders}
}

func (s *SecurityHeadersStage) Name() string { return "security-headers" }

func (s *SecurityHeadersStage) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if s.setHeaders != nil {
		s.setHeaders(w, r)
	}
	return Continue
}

// BodyLimitStage 限制请求体大小
type BodyLimitStage struct {
	maxBytes int64
}

func NewBodyLimitStage(maxBytes int64) *BodyLimitStage {
	return &BodyLimitStage{maxBytes: maxBytes}
}

func (s *BodyLimitStage) Name() string { return "body-limit" }

func (s *BodyLimitStage) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	if r.Body != nil && s.maxBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.maxBytes)
	}
	return Continue
}
