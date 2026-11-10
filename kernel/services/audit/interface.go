// Package audit: Audit log service — 结构化 JSONL + 哈希链防篡改审计日志。
//
// 设计原则：auditv2.go hash-chain 判定逻辑零 diff from v4.3.0，只搬家+去锁。

package audit



// ===================== 接口定义 =====================

// Logger 审计日志写入接口。
type Logger interface {
	// Log 记录一条审计事件（action, target, detail）。
	Log(action, target, detail string)
	// LogWithFields 记录带字段的审计事件。
	LogWithFields(action, target, user, tenant, group, ip, trace, detail string)
	// Flush 强制同步写盘（可选，通常不需要）
	Flush()
}

// Verifier 审计链完整性验证器。
type Verifier interface {
	// VerifyDate 验证指定日期的审计链完整性，返回首个断点 seq 和错误。
	VerifyDate(date string) (int, string)
	// EntryCount 返回指定日期审计条目数量。
	EntryCount(date string) int
}

// Exporter 审计数据导出器。
type Exporter interface {
	// ExportDate 按租户行级过滤导出指定日期审计条目为 JSONL 字节。
	ExportDate(date, tenantFilter string) ([]byte, error)
}

// ===================== Service =====================

// Service 是审计子系统入口。
type Service struct {
	logFn         func(action, target, detail string)
	logFieldsFn   func(action, target, user, tenant, group, ip, trace, detail string)
	flushFn       func()
	verifyFn      func(string) (int, string)
	countFn       func(string) int
	exportFn      func(string, string) ([]byte, error)
}

// NewService 构建审计 Service。函数指针指向根包 auditv2.go 现有逻辑。
func NewService(logFn func(string, string, string), logFieldsFn func(string, string, string, string, string, string, string, string),
	flushFn func(), verifyFn func(string) (int, string), countFn func(string) int,
	exportFn func(string, string) ([]byte, error)) *Service {

	return &Service{
		logFn:        logFn,
		logFieldsFn:  logFieldsFn,
		flushFn:      flushFn,
		verifyFn:     verifyFn,
		countFn:      countFn,
		exportFn:     exportFn,
	}
}

// Logger returns the Logger interface implementation.
func (s *Service) Logger() Logger { return s }
// Verifier returns the Verifier interface implementation.
func (s *Service) Verifier() Verifier { return s }
// Exporter returns the Exporter interface implementation.
func (s *Service) Exporter() Exporter { return s }

func (s *Service) Log(action, target, detail string)          { s.logFn(action, target, detail) }
func (s *Service) LogWithFields(action, target, user, tenant, group, ip, trace, detail string) {
	s.logFieldsFn(action, target, user, tenant, group, ip, trace, detail)
}
func (s *Service) Flush()                                     { s.flushFn() }
func (s *Service) VerifyDate(date string) (int, string)       { return s.verifyFn(date) }
func (s *Service) EntryCount(date string) int                 { return s.countFn(date) }
func (s *Service) ExportDate(date, tenantFilter string) ([]byte, error) {
	return s.exportFn(date, tenantFilter)
}
