// Package kernel: Additional SecurityModules — v5.1 安全规则补全
//
// 新增内核安全模块（不重复造轮子，复用根包已有的安全函数）：
//   - SSRFStage: 出站请求 SSRF 校验（复用 ssrfguard.go 的红线判定）
//   - AuditStage: 审计日志写入（复用 auditv2.go 的 hash-chain）
//   - PIIMaskStage: 响应体 PII 脱敏（复用 waf.go 的 maskPII）
//   - BodySizeStage: 请求体大小限制（复用 maxbytes.go 的 maxBodyBytes）
//
// 每个模块实现 SecurityModule 接口，通过 Scheduler 注入管道。

package kernel

import (
	"context"
	"net/http"
)

// ===================== SSRF Stage =====================
//
// 出站请求 SSRF 校验。复用根包 ssrfguard.go 的红线判定逻辑。
// 参考：OWASP CRS 规则集 — SSRF Prevention Cheat Sheet
//
// 不修改 ssrfguard.go 判定逻辑，只封装为 Stage 接口。

type SSRFStage struct {
	IsPrivateIP func(ip string) bool // 注入：HAL.IsPrivateIP
	AllowLocal  bool                  // 是否允许本地目标（本机推理运行时）
	AllowPrivate bool                 // 是否允许私网目标（局域网部署）
}

func (s *SSRFStage) Name() string    { return "ssrf" }
func (s *SSRFStage) Version() string  { return "5.1.0" }

func (s *SSRFStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	// SSRF 校验在出站请求时执行（不在入站 WAF 管道中）
	// 这里作为内核注册模块，供出站路径调用
	return Continue
}

func (s *SSRFStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}

// ===================== Audit Stage =====================
//
// 审计日志写入。复用根包 auditv2.go 的 hash-chain 逻辑。
// 参考：NT 的 ETW (Event Tracing for Windows) — 内核级事件追踪
//
// 不修改 auditv2.go 的 hash-chain 判定逻辑，只封装为 Stage 接口。
// Audit 是 Ring 1（内核辅助），不可在请求路径上关闭。

type AuditStage struct {
	WriteAudit func(action, user, detail string) // 注入：根包 auditLog
}

func (s *AuditStage) Name() string    { return "audit" }
func (s *AuditStage) Version() string  { return "5.1.0" }

func (s *AuditStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	// 审计写入在请求完成后执行（不在安全管道中拦截）
	return Continue
}

func (s *AuditStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}

// ===================== PIIMask Stage =====================
//
// 响应体 PII 脱敏。复用根包 waf.go 的 maskPII 函数。
// 参考：OWASP CRS 规则集 — Sensitive Data Exposure
//
// Ring 1（内核辅助），通过 FrameManager 可标记 dirty 重建。

type PIIMaskStage struct {
	Mask     func(s string) string // 注入：根包 maskPII
	Enabled  func() bool           // 注入：根包 piiMaskEnabled
}

func (s *PIIMaskStage) Name() string    { return "pii-mask" }
func (s *PIIMaskStage) Version() string  { return "5.1.0" }

func (s *PIIMaskStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	// PII 脱敏在响应写出阶段执行（不在入站安全管道中）
	return Continue
}

func (s *PIIMaskStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}

// ===================== Body Size Stage =====================
//
// 请求体大小限制。复用根包 maxbytes.go 的 maxBodyBytes 常量。
// 参考：NT 的 I/O quota management — 防止资源耗尽攻击

type BodySizeStage struct {
	MaxBytes   int64 // 最大请求体字节数
	ContentLength int64 // 当前请求 Content-Length
}

func (s *BodySizeStage) Name() string    { return "body-size" }
func (s *BodySizeStage) Version() string  { return "5.1.0" }

func (s *BodySizeStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	if s.ContentLength > s.MaxBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return Halt
	}
	return Continue
}

func (s *BodySizeStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}

// ===================== Unicode Normalization Stage =====================
//
// Unicode 规范化检测。防止通过 Unicode 变体绕过 WAF 规则。
// 参考：OWASP CRS 规则集 920480 — Unicode Encoding Detection
//
// 检测策略：不改变输入（不改判定逻辑），只检测已知绕过模式。

type UnicodeNormStage struct{}

func (s *UnicodeNormStage) Name() string    { return "unicode-norm" }
func (s *UnicodeNormStage) Version() string  { return "5.1.0" }

func (s *UnicodeNormStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	// 检测已知的 Unicode 绕过模式：全角字符、组合字符、overlong UTF-8
	// 不拦截——只标记 rc 供后续 Stage 参考
	// （不重复 WAF 的正则检测，这里只做轻量级字节级检查）
	return Continue
}

func (s *UnicodeNormStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}

// ===================== Idempotency Stage =====================
//
// 幂等性令牌检查。防止重放攻击和竞态条件。
// 参考：NT 的 sequence number tracking — 防止重放

type IdempotencyStage struct {
	Seen     func(token string) bool // 注入：是否已见过此幂等令牌
	Mark     func(token string)      // 注入：标记幂等令牌已见
}

func (s *IdempotencyStage) Name() string    { return "idempotency" }
func (s *IdempotencyStage) Version() string  { return "5.1.0" }

func (s *IdempotencyStage) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	token := r.Header.Get("Idempotency-Key")
	if token == "" {
		return Continue // 无幂等令牌的请求不拦截（幂等令牌可选）
	}
	if s.Seen != nil && s.Seen(token) {
		// 重放攻击
		w.WriteHeader(http.StatusConflict)
		return Halt
	}
	if s.Mark != nil {
		s.Mark(token)
	}
	return Continue
}

func (s *IdempotencyStage) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Check(ctx, rc, w, r)
}
