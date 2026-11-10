// Package pipeline 提供与现有 gatewayMiddleware 的桥接适配器
//
// 这个文件是渐进式重构的关键：允许新的 Pipeline 架构与现有的
// gatewayMiddleware 并存，逐步迁移而非一次性重写。
//
// 迁移策略（Strangler Fig Pattern）：
//   1. Phase 1: Pipeline 作为 gatewayMiddleware 的旁路观测器（只记录不干预）
//   2. Phase 2: 逐个阶段从 gatewayMiddleware 迁移到 Pipeline Stage
//   3. Phase 3: gatewayMiddleware 退化为简单的 Pipeline.Execute 调用
//   4. Phase 4: 删除 gatewayMiddleware，Pipeline 成为唯一入口

package pipeline

import (
	"net/http"
	"time"
)

// Bridge 是新旧架构之间的桥接器
// 它实现了 http.Handler 接口，可以直接替换现有的 gatewayMiddleware
type Bridge struct {
	pipeline *Pipeline
	// 可选：保留对旧中间件的引用（用于渐进式迁移）
	legacyMiddleware http.Handler
	// 迁移阶段控制
	mode BridgeMode
}

// BridgeMode 控制桥接器的工作模式
type BridgeMode int

const (
	// ModeShadow 影子模式：Pipeline 执行但不影响响应，用于验证
	ModeShadow BridgeMode = iota
	// ModeGradual 渐进模式：Pipeline 处理已迁移的阶段，旧中间件处理其余
	ModeGradual
	// ModeFull 完全模式：Pipeline 完全接管，旧中间件不再执行
	ModeFull
)

// NewBridge 创建桥接器
func NewBridge(pipeline *Pipeline, mode BridgeMode) *Bridge {
	return &Bridge{
		pipeline: pipeline,
		mode:     mode,
	}
}

// WithLegacy 设置旧中间件引用（渐进模式使用）
func (b *Bridge) WithLegacy(legacy http.Handler) *Bridge {
	b.legacyMiddleware = legacy
	return b
}

// ServeHTTP 实现 http.Handler 接口
// 根据模式决定如何协调新旧架构
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 构建请求上下文
	rc := &RequestContext{
		TraceID:   extractTraceID(r),
		ClientIP:  extractClientIP(r),
		UserAgent: r.UserAgent(),
		StartTime: time.Now(),
	}

	switch b.mode {
	case ModeShadow:
		// 影子模式：旧中间件处理请求，Pipeline 并行执行用于观测
		b.executeShadow(w, r, rc)
	case ModeGradual:
		// 渐进模式：Pipeline 处理已迁移阶段，然后交给旧中间件
		b.executeGradual(w, r, rc)
	case ModeFull:
		// 完全模式：Pipeline 完全接管
		b.executeFull(w, r, rc)
	}
}

// executeShadow 影子模式实现
func (b *Bridge) executeShadow(w http.ResponseWriter, r *http.Request, rc *RequestContext) {
	// 旧中间件处理实际请求
	if b.legacyMiddleware != nil {
		b.legacyMiddleware.ServeHTTP(w, r)
	}

	// Pipeline 并行执行（只记录，不影响响应）
	// 使用 shadowWriter 捕获 Pipeline 的输出用于对比
	sw := &shadowWriter{header: make(http.Header)}
	b.pipeline.Execute(sw, r, rc)

	// 记录观测数据（可用于后续分析和验证）
	// TODO: 发送到观测系统
}

// executeGradual 渐进模式实现
func (b *Bridge) executeGradual(w http.ResponseWriter, r *http.Request, rc *RequestContext) {
	// Pipeline 执行已迁移的阶段
	halted := b.pipeline.Execute(w, r, rc)
	if halted {
		return // Pipeline 已终止（如 IP 被封禁、WAF 拦截等）
	}

	// 未终止的请求交给旧中间件继续处理
	if b.legacyMiddleware != nil {
		b.legacyMiddleware.ServeHTTP(w, r)
	}
}

// executeFull 完全模式实现
func (b *Bridge) executeFull(w http.ResponseWriter, r *http.Request, rc *RequestContext) {
	halted := b.pipeline.Execute(w, r, rc)
	if !halted {
		// Pipeline 未终止但也没有 handler 处理，返回 404
		http.NotFound(w, r)
	}
}

// shadowWriter 用于影子模式的 ResponseWriter 包装器
// 它捕获 Pipeline 的输出但不真正写入响应
type shadowWriter struct {
	header     http.Header
	statusCode int
	body       []byte
}

func (sw *shadowWriter) Header() http.Header {
	return sw.header
}

func (sw *shadowWriter) Write(data []byte) (int, error) {
	sw.body = append(sw.body, data...)
	return len(data), nil
}

func (sw *shadowWriter) WriteHeader(statusCode int) {
	sw.statusCode = statusCode
}

// 辅助函数

func extractTraceID(r *http.Request) string {
	// 从请求头或 context 中提取 trace_id
	if tid := r.Header.Get("X-Trace-Id"); tid != "" {
		return tid
	}
	// TODO: 从 context 中提取（如果 observability 层已设置）
	return ""
}

func extractClientIP(r *http.Request) string {
	// 简单实现：从 RemoteAddr 提取
	// 生产环境可能需要考虑 X-Forwarded-For 等代理头
	host := r.RemoteAddr
	// 移除端口
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

// MiddlewareAdapter 将 Pipeline 包装为标准的 http.Handler 中间件
// 这样可以直接在现有的 mux.Handle 中使用
func MiddlewareAdapter(pipeline *Pipeline, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := &RequestContext{
			TraceID:   extractTraceID(r),
			ClientIP:  extractClientIP(r),
			UserAgent: r.UserAgent(),
			StartTime: time.Now(),
		}

		halted := pipeline.Execute(w, r, rc)
		if !halted && next != nil {
			next.ServeHTTP(w, r)
		}
	})
}

// PipelineHandler 将 Pipeline 包装为独立的 http.Handler
// 适用于 Pipeline 完全接管的场景
func PipelineHandler(pipeline *Pipeline) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := &RequestContext{
			TraceID:   extractTraceID(r),
			ClientIP:  extractClientIP(r),
			UserAgent: r.UserAgent(),
			StartTime: time.Now(),
		}

		halted := pipeline.Execute(w, r, rc)
		if !halted {
			http.NotFound(w, r)
		}
	})
}

// BuildSecurityPipeline 构建标准的安全管道
// 这个函数展示了如何将现有的安全检测步骤组织成 Pipeline
func BuildSecurityPipeline(config SecurityPipelineConfig) *Pipeline {
	stages := []Stage{}

	// 1. IP 封禁检测
	if config.IPBanCheck != nil {
		stages = append(stages, IPBanCheckStage{
			IsBanned: config.IPBanCheck,
			OnBlock:  config.OnIPBlocked,
		})
	}

	// 2. WAF 检测
	if config.WAFCheck != nil {
		stages = append(stages, WAFCheckStage{
			Check: config.WAFCheck,
			OnHit: config.OnWAFHit,
		})
	}

	// 3. CORS 预检
	if config.IsTrustedOrigin != nil {
		stages = append(stages, CORSPreflightStage{
			IsTrustedOrigin: config.IsTrustedOrigin,
		})
	}

	// 4. 认证
	if config.Authenticate != nil {
		stages = append(stages, AuthStage{
			IsPublicRoute: config.IsPublicRoute,
			Authenticate:  config.Authenticate,
		})
	}

	// 5. RBAC
	if config.RBACCheck != nil {
		stages = append(stages, RBACCheckStage{
			Check: config.RBACCheck,
		})
	}

	// 6. 配额检查
	if config.QuotaCheck != nil {
		stages = append(stages, QuotaCheckStage{
			RouteClass: config.RouteClass,
			Check:      config.QuotaCheck,
		})
	}

	// 7. 速率限制
	if config.RateLimitCheck != nil {
		stages = append(stages, RateLimitStage{
			Check: config.RateLimitCheck,
		})
	}

	// 8. 指标收集
	if config.OnRequest != nil {
		stages = append(stages, MetricsStage{
			OnRequest: config.OnRequest,
		})
	}

	p := New(stages...)
	if config.Observer != nil {
		p.WithObserver(config.Observer)
	}
	return p
}

// SecurityPipelineConfig 安全管道的配置
type SecurityPipelineConfig struct {
	// 检测函数
	IPBanCheck      func(ip string) bool
	WAFCheck        func(r *http.Request) string
	IsTrustedOrigin func(origin string) bool
	Authenticate    func(r *http.Request) (*Identity, bool)
	RBACCheck       func(userID, method, path, role string, groups []string) (bool, string)
	QuotaCheck      func(tenant, user string, groups []string) (bool, string)
	RateLimitCheck  func(w http.ResponseWriter, r *http.Request, user, tenant string) bool

	// 辅助函数
	IsPublicRoute func(path string) bool
	RouteClass    func(path string) string

	// 回调
	OnIPBlocked func(ip, path string)
	OnWAFHit    func(ip, rule string)
	OnRequest   func()

	// 观测
	Observer Observer
}

// ExampleBuildPipeline 示例：如何从现有的 gatewayMiddleware 迁移到 Pipeline
// 这个函数展示了渐进式迁移的第一步
func ExampleBuildPipeline() *Pipeline {
	config := SecurityPipelineConfig{
		// 这里填入现有的检测函数引用
		// 例如：IPBanCheck: isBanned,
		//       WAFCheck: wafCheck,
		//       等等...

		// 观测器（可选）
		// Observer: &PrometheusObserver{},
	}

	return BuildSecurityPipeline(config)
}

// MigrationGuide 迁移指南（文档化在代码中）
//
// Phase 1: 影子模式验证
//   bridge := NewBridge(pipeline, ModeShadow).WithLegacy(gatewayMiddleware(mux))
//   server.Handler = bridge
//   // 运行一段时间，对比 Pipeline 和旧中间件的判定结果
//
// Phase 2: 渐进式迁移
//   bridge := NewBridge(pipeline, ModeGradual).WithLegacy(partialMiddleware)
//   // 逐步将阶段从 partialMiddleware 移到 pipeline
//
// Phase 3: 完全接管
//   bridge := NewBridge(pipeline, ModeFull)
//   // 删除旧的 gatewayMiddleware 代码
//
// Phase 4: 清理
//   server.Handler = PipelineHandler(pipeline)
//   // 删除 bridge.go 和旧中间件代码
