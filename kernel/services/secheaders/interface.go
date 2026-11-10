// Package secheaders: Security response headers service — HTTP 安全响应头自动加固。
//
// 自动为所有 HTTP 响应添加安全响应头（X-Frame-Options, X-Content-Type-Options,
// CSP, Referrer-Policy, Permissions-Policy, HSTS），防止常见客户端攻击。
// 默认启用，零配置开箱即用。

package secheaders

import "net/http"

// ===================== 接口定义 =====================

// HeadersInjector 安全响应头注入器。
type HeadersInjector interface {
	// Inject 在响应中注入所有配置的安全头（不调用 next，供 middleware 组合用）。
	Inject(w http.ResponseWriter, r *http.Request)
	// Enabled 判断全局开关。
	Enabled() bool
	// ShouldSkip 判断指定路径是否在排除列表中。
	ShouldSkip(path string) bool
}

// Middleware 包装后的标准 http.Handler 中间件（保持与现有 securityHeadersMiddleware 等价）。
type Middleware interface {
	// Handler 返回一个完整的 http.Handler 中间件链（可挂载到 mux）。
	Handler(next http.Handler) http.Handler
}

// ===================== Service =====================

// Service 是安全响应头子系统入口。
type Service struct {
	injectFn func(http.ResponseWriter, *http.Request)
	enabledFn func() bool
	skipFn   func(string) bool
	middlewareFn func(http.Handler) http.Handler
}

// NewService 构建安全响应头 Service。
func NewService(injectFn func(http.ResponseWriter, *http.Request),
	enabledFn func() bool, skipFn func(string) bool,
	middlewareFn func(http.Handler) http.Handler) *Service {

	return &Service{
		injectFn: injectFn, enabledFn: enabledFn, skipFn: skipFn,
		middlewareFn: middlewareFn,
	}
}

// HeadersInjector returns the HeadersInjector interface.
func (s *Service) HeadersInjector() HeadersInjector { return s }
// Middleware returns the Middleware interface.
func (s *Service) Middleware() Middleware { return s }

func (s *Service) Inject(w http.ResponseWriter, r *http.Request) { s.injectFn(w, r) }
func (s *Service) Enabled() bool                                { return s.enabledFn() }
func (s *Service) ShouldSkip(path string) bool                  { return s.skipFn(path) }
func (s *Service) Handler(next http.Handler) http.Handler       { return s.middlewareFn(next) }
