// Package csp: Content Security Policy service — CSP策略自动生成与报告收集。
//
// 根据嵌入的前端资源自动推导 CSP 头，支持 report-only 模式。

package csp

import "net/http"

// ===================== 接口定义 =====================

// Generator CSP策略生成器。
type Generator interface {
	// Generate 根据前端资源自动推导并生成 CSP 策略字符串。
	Generate() string
	// ReportOnly 判断当前是否为 report-only 模式。
	ReportOnly() bool
	// Enabled 判断 CSP 是否启用。
	Enabled() bool
}

// Reporter CSP违规报告收集器。
type Reporter interface {
	// Collect 处理浏览器上报的 CSP 违规报告。
	Collect(w http.ResponseWriter, r *http.Request)
	// GetReports 获取最近收集的违规报告（最多10条）。
	GetReports() []string
}

// ===================== Service =====================

// Service 是 CSP 子系统入口。
type Service struct {
	genFn       func() string
	reportOnlyFn func() bool
	enabledFn   func() bool
	collectFn   func(http.ResponseWriter, *http.Request)
	reportsFn   func() []string
}

// NewService 构建 CSP Service。
func NewService(genFn func() string, reportOnlyFn func() bool, enabledFn func() bool,
	collectFn func(http.ResponseWriter, *http.Request), reportsFn func() []string) *Service {

	return &Service{
		genFn: genFn, reportOnlyFn: reportOnlyFn, enabledFn: enabledFn,
		collectFn: collectFn, reportsFn: reportsFn,
	}
}

// Generator returns the Generator interface.
func (s *Service) Generator() Generator { return s }
// Reporter returns the Reporter interface.
func (s *Service) Reporter() Reporter { return s }

func (s *Service) Generate() string                        { return s.genFn() }
func (s *Service) ReportOnly() bool                        { return s.reportOnlyFn() }
func (s *Service) Enabled() bool                           { return s.enabledFn() }
func (s *Service) Collect(w http.ResponseWriter, r *http.Request) { s.collectFn(w, r) }
func (s *Service) GetReports() []string                    { return s.reportsFn() }
