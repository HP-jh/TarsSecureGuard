// Package kernel: ServiceRegistry — 系统服务注册表（鸿蒙微内核"系统服务框架"精神的 Go 表达）。
//
// 设计原则：
//   - 每个子系统对应一个 service getter（不是 IPC，Go 中用 interface）；
//   - kernel_bridge.go 统一构建所有 Service 并注入根包函数闭包；
//   - 零重复造轮子——Service 内部调用根包现有函数，不重新实现安全逻辑。
//
// 参考：
//   - Huawei Hongmeng microkernel "system service framework" (spirit only, not IPC)
//   - Strangler Fig Pattern (Martin Fowler) — progressive migration path

package kernel

import (

	"github.com/HP-jh/TarsSecureGuard/kernel/services/waf"
	"github.com/HP-jh/TarsSecureGuard/kernel/services/ssrf"
	"github.com/HP-jh/TarsSecureGuard/kernel/services/audit"
	"github.com/HP-jh/TarsSecureGuard/kernel/services/csp"
	"github.com/HP-jh/TarsSecureGuard/kernel/services/iprep"
	"github.com/HP-jh/TarsSecureGuard/kernel/services/ratelimit"
	"github.com/HP-jh/TarsSecureGuard/kernel/services/secheaders"
)

// ===================== StageResult 别名（供 services 包引用，避免循环依赖）=====================
// Note: StageResult is defined in kernel.go; it must be forward-declared here via re-export.

// ===================== ServiceRegistry =====================

// ServiceRegistry 是所有内核服务的注册表。
// kernel_bridge.go 负责构建各 Service 实例并填入此表。
type ServiceRegistry struct {
	WAF        *waf.Service
	SSRF       *ssrf.Service
	Audit      *audit.Service
	CSP        *csp.Service
	IPRep      *iprep.Service
	RateLimit  *ratelimit.Service
	SecHeaders *secheaders.Service
}

// NewServiceRegistry 创建空注册表（由 bridge 层填充）。
func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{}
}

// ===================== 从注册表获取各 Service 接口的便捷方法 =====================

// WAF returns the WAF subsystem checker/scanner/masker.
func (r *ServiceRegistry) WAFChecker() waf.Detector          { return r.WAF.Checker() }
func (r *ServiceRegistry) WAFScanner() waf.Scanner           { return r.WAF.Scanner() }
func (r *ServiceRegistry) WAFMasker() waf.PIIMasker          { return r.WAF.PIIMasker() }

// SSRF returns the SSRF transport provider and redirect validator.
func (r *ServiceRegistry) SSRFClientProvider() ssrf.TransportProvider     { return r.SSRF.ClientProvider() }
func (r *ServiceRegistry) SSRFRedirectValidator() ssrf.RedirectValidator  { return r.SSRF.RedirectValidator() }

// Audit returns the audit logger, verifier, exporter.
func (r *ServiceRegistry) AuditLogger() audit.Logger             { return r.Audit.Logger() }
func (r *ServiceRegistry) AuditVerifier() audit.Verifier         { return r.Audit.Verifier() }
func (r *ServiceRegistry) AuditExporter() audit.Exporter         { return r.Audit.Exporter() }

// CSP returns the CSP generator and report collector.
func (r *ServiceRegistry) CSPGenerator() csp.Generator            { return r.CSP.Generator() }
func (r *ServiceRegistry) CSPReporter() csp.Reporter              { return r.CSP.Reporter() }

// IPRep returns the IP reputation scorer.
func (r *ServiceRegistry) IPScorer() iprep.Scorer                 { return r.IPRep.Scorer() }

// RateLimit returns the rate limiter.
func (r *ServiceRegistry) RateLimiter() ratelimit.Limiter         { return r.RateLimit.Limiter() }
func (r *ServiceRegistry) RateMiddleware() ratelimit.Middleware   { return r.RateLimit.Middleware() }

// SecHeaders returns the security headers injector.
func (r *ServiceRegistry) HeadersInjector() secheaders.HeadersInjector { return r.SecHeaders.HeadersInjector() }
func (r *ServiceRegistry) HeaderMiddleware() secheaders.Middleware    { return r.SecHeaders.Middleware() }

// ===================== Service 接口定义 —— 用于在 ServiceModule 中使用 =====================

// ServiceModule 是 SecurityModule 的扩展，表示一个带 Service 引用的模块。
// kernel_bridge.go 构建 Stage 时会同时持有 Service 的接口引用。
type ServiceModule interface {
	SecurityModule
	// SetServiceRef 注入特定 Service 的接口引用（让模块能调用更精细的服务能力）
	SetServiceRef(name string, ref interface{})
}

// RegisterService 将已创建的 Service 注册到注册表中。
// 这是 kernel_bridge.go 中 fillServices() 的核心逻辑。
func (r *ServiceRegistry) RegisterService(name string, svc interface{}) {
	switch v := svc.(type) {
	case *waf.Service:
		r.WAF = v
	case *ssrf.Service:
		r.SSRF = v
	case *audit.Service:
		r.Audit = v
	case *csp.Service:
		r.CSP = v
	case *iprep.Service:
		r.IPRep = v
	case *ratelimit.Service:
		r.RateLimit = v
	case *secheaders.Service:
		r.SecHeaders = v
	}
}
