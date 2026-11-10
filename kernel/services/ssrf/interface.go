// Package ssrf: SSRF (Server-Side Request Forgery) prevention service — 从 root main 中提取的出站请求防护服务。
//
// 设计原则：零重复造轮子。ssrfguard.go 判定逻辑零 diff from v4.3.0，只搬家+去锁。

package ssrf

import (
	"net/http"
)

// ===================== 接口定义 =====================

// TransportProvider 提供 SSRF 加固的 http.Transport / *http.Client。
type TransportProvider interface {
	// GuardedClient 构造 SSRF 加固客户端（严格模式：禁用重定向+IP校验）
	GuardedClient(timeout int64) *http.Client
	// StrictTransport 构造严格模式 Transport（用于用户可控 URL 的出站池）
	StrictTransport() *http.Transport
	// LocalAllowTransport 构造允许回环/私网的 Transport（仅用于固定端点池如 ollama）
	LocalAllowTransport(allowLocal, allowPrivate bool) *http.Transport
}

// RedirectValidator 重定向目标校验器。
type RedirectValidator interface {
	// Validate 校验 3xx 重定向目标：协议白名单 + 禁止裸 IP/凭据注入
	// 通过返回清洗后的绝对 URL；否则返回 ""。
	Validate(resp *http.Response) (string, bool)
}

// ===================== Service =====================

// Service 是 SSRF 子系统入口。
type Service struct {
	guardedClientFn    func(int64) *http.Client
	strictTransportFn  func() *http.Transport
	localTransportFn    func(bool, bool) *http.Transport
	redirectValidateFn func(*http.Response) (string, bool)
}

// NewService 构建 SSRF Service。函数指针指向根包 ssrfguard.go 现有逻辑。
func NewService(guardedFn func(int64) *http.Client, strictFn func() *http.Transport,
	localFn func(bool, bool) *http.Transport, redirectFn func(*http.Response) (string, bool)) *Service {

	s := &Service{
		guardedClientFn:    guardedFn,
		strictTransportFn:  strictFn,
		localTransportFn:   localFn,
		redirectValidateFn: redirectFn,
	}
	return s
}

// ClientProvider returns TransportProvider
func (s *Service) ClientProvider() TransportProvider { return s }
// RedirectValidator returns RedirectValidator
func (s *Service) RedirectValidator() RedirectValidator { return s }

// GuardedClient implements TransportProvider
func (s *Service) GuardedClient(timeout int64) *http.Client       { return s.guardedClientFn(timeout) }
// StrictTransport implements TransportProvider
func (s *Service) StrictTransport() *http.Transport               { return s.strictTransportFn() }
// LocalAllowTransport implements TransportProvider
func (s *Service) LocalAllowTransport(allowLocal, allowPrivate bool) *http.Transport {
	return s.localTransportFn(allowLocal, allowPrivate)
}

// Validate implements RedirectValidator
func (s *Service) Validate(resp *http.Response) (string, bool) { return s.redirectValidateFn(resp) }
