// Package waf: WAF (Web Application Firewall) service — 从 root main 中提取的 WAF 系统服务。
//
// 设计原则：零重复造轮子，只拆不重改。内部调用根包现有判定函数，不改安全红线。
// 参考：OWASP CRS (coreruleset.org) — 规则模块化、可独立开关、带回归测试

package waf

import "net/http"

// ===================== 接口定义 =====================

// Detector 检测引擎接口，暴露 WAF 的核心检测能力。
type Detector interface {
	// Check 执行完整 WAF 检测链：速率限制 → HTTP方法 → UA黑名单 → 敏感路径
	// → Host注入 → Header CRLF → 请求走私 → Body扫描 → URL/Query正则匹配。
	// 返回首个命中原因；"" 表示通过。
	Check(r *http.Request) string

	// Enabled 判断 WAF 是否启用（读取配置快照）
	Enabled() bool

	// StrictMode 判断是否为严格模式（strict 模式扫 PII/XSS/SQLi/PromptInjection）
	StrictMode() bool
}

// Scanner UA / 路径扫描器。
type Scanner interface {
	// MatchUA 检测 User-Agent 是否命中扫描器黑名单，命中返回特征串
	MatchUA(ua string) string
	// MatchPath 检测路径是否命中敏感路径探测特征，命中返回命中的特征串
	MatchPath(p string) string
}

// PII 脱敏器。
type PIIMasker interface {
	// Mask 对输入文本中的 PII 按配置强度进行脱敏替换
	Mask(s string) string
	// Enabled 判断脱敏是否开启
	Enabled() bool
	// Level 返回当前脱敏强度级别（full | partial | hash）
	Level() string
}

// ===================== Service —— 组合三个子接口 =====================

// Service 是 WAF 子系统入口，组合检测器、扫描器、脱敏器。
// 由桥接层构建并注入函数指针。
type Service struct {
	detector   Detector
	scanner    Scanner
	masker     PIIMasker
	onBlock    func(w http.ResponseWriter, r *http.Request, reason string)
}

// NewService 构建 WAF Service。funcCheck/main 包函数闭包。
func NewService(checkFn func(*http.Request) string, enabledFn func() bool,
	strictFn func() bool, uaFn func(string) string, pathFn func(string) string,
	maskFn func(string) string, maskerEnabledFn func() bool, levelFn func() string,
	onBlockCb func(w http.ResponseWriter, r *http.Request, reason string)) *Service {

	s := &Service{onBlock: onBlockCb}
	s.detector = &detectorImpl{check: checkFn, enabled: enabledFn, strict: strictFn}
	s.scanner = &scannerImpl{ua: uaFn, path: pathFn}
	s.masker = &maskerImpl{mask: maskFn, enabled: maskerEnabledFn, level: levelFn}
	return s
}

// Checker 返回 Detector 接口
func (s *Service) Checker() Detector { return s.detector }
// Scanner 返回 Scanner 接口
func (s *Service) Scanner() Scanner { return s.scanner }
// PIIMasker 返回 PIIMasker 接口
func (s *Service) PIIMasker() PIIMasker { return s.masker }
// OnBlock 返回拦截回调
func (s *Service) OnBlock() func(http.ResponseWriter, *http.Request, string) { return s.onBlock }

// ===================== 内联实现：函数指针代理到根包 =====================

type detectorImpl struct {
	check    func(*http.Request) string
	enabled  func() bool
	strict   func() bool
}

func (d *detectorImpl) Check(r *http.Request) string  { return d.check(r) }
func (d *detectorImpl) Enabled() bool                 { return d.enabled() }
func (d *detectorImpl) StrictMode() bool              { return d.strict() }

type scannerImpl struct {
	ua   func(string) string
	path func(string) string
}

func (s *scannerImpl) MatchUA(ua string) string      { return s.ua(ua) }
func (s *scannerImpl) MatchPath(p string) string     { return s.path(p) }

type maskerImpl struct {
	mask     func(string) string
	enabled  func() bool
	level    func() string
}

func (m *maskerImpl) Mask(s string) string             { return m.mask(s) }
func (m *maskerImpl) Enabled() bool                    { return m.enabled() }
func (m *maskerImpl) Level() string                    { return m.level() }
