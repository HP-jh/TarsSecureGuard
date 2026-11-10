// Package ratelimit: Rate limiting service — 分层令牌桶速率限制，security-core 内置不可关闭。
//
// 三维令牌桶：按 IP、按 API Key（用户）、按端点类（chat/admin/model）；
// 超限返回 429 + 审计（RATE_LIMIT_BLOCK）。

package ratelimit

import "net/http"

// ===================== 接口定义 =====================

// Limiter 限流器。
type Limiter interface {
	// Allow 判断请求是否允许通过（按 IP+Key+EndpointClass 三维令牌桶）。
	Allow(ip, userID, tenant, endpointClass string) bool
	// EndpointClass 路径 → 限流维度分类（chat/admin/model/other）。
	EndpointClass(path string) string
}

// Middleware 限流中间件（用于非 kernel 路径的 rateLimitMiddleware 迁移）。
type Middleware interface {
	// Apply 执行完整限流逻辑：检查 IP/Key/Class 三个维度令牌桶；
	// 超限时写 429 + 审计 + 联动 IP 信誉扣分（-15）。
	Apply(w http.ResponseWriter, r *http.Request, userID, tenant string) bool
}

// ===================== Service =====================

// Service 是速率限制子系统入口。
type Service struct {
	allowFn        func(string, string, string, string) bool
	classFn        func(string) string
	applyFn        func(http.ResponseWriter, *http.Request, string, string) bool
}

// NewService 构建速率限制 Service。
func NewService(allowFn func(string, string, string, string) bool,
	classFn func(string) string, applyFn func(http.ResponseWriter, *http.Request, string, string) bool) *Service {

	return &Service{
		allowFn: allowFn, classFn: classFn, applyFn: applyFn,
	}
}

// Limiter returns the Limiter interface.
func (s *Service) Limiter() Limiter { return s }
// Middleware returns the Middleware interface.
func (s *Service) Middleware() Middleware { return s }

func (s *Service) Allow(ip, userID, tenant, endpointClass string) bool {
	return s.allowFn(ip, userID, tenant, endpointClass)
}
func (s *Service) EndpointClass(path string) string                   { return s.classFn(path) }
func (s *Service) Apply(w http.ResponseWriter, r *http.Request, userID, tenant string) bool {
	return s.applyFn(w, r, userID, tenant)
}
