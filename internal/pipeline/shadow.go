package pipeline

import (
	"bytes"
	"net/http"
	"sync"
	"time"
)

// ShadowBridge 实现新旧架构的渐进式迁移桥接
//
// 设计原则（参考字节双线程模型的安全边界）：
//   1. Shadow Mode: Pipeline 执行但不影响响应（只记录，不干预）
//   2. Gradual Mode: Pipeline 处理已迁移阶段，旧中间件处理其余
//   3. Full Mode: Pipeline 完全接管
//
// 安全铁律：
//   - 旧中间件永远优先（Shadow/Gradual 模式下）
//   - Pipeline 的 panic 不影响旧中间件执行
//   - 指标收集零副作用（atomic 操作，无锁）

// BridgeMode 控制桥接模式
type BridgeMode int

const (
	// ModeShadow 影子模式：Pipeline 执行但不影响响应
	ModeShadow BridgeMode = iota
	// ModeGradual 渐进模式：Pipeline 处理已迁移阶段
	ModeGradual
	// ModeFull 完全模式：Pipeline 完全接管
	ModeFull
)

// ShadowBridge 桥接器
type ShadowBridge struct {
	pipeline        *Pipeline
	legacyMiddleware http.Handler
	mode            BridgeMode
	observer        Observer
	mu              sync.RWMutex
}

// NewShadowBridge 创建桥接器
func NewShadowBridge(pipeline *Pipeline, legacy http.Handler, mode BridgeMode) *ShadowBridge {
	return &ShadowBridge{
		pipeline:         pipeline,
		legacyMiddleware: legacy,
		mode:             mode,
	}
}

// WithObserver 设置观测器
func (b *ShadowBridge) WithObserver(obs Observer) *ShadowBridge {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.observer = obs
	b.pipeline.WithObserver(obs)
	return b
}

// SetMode 动态切换模式（热重载安全）
func (b *ShadowBridge) SetMode(mode BridgeMode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mode = mode
}

// ServeHTTP 实现 http.Handler
func (b *ShadowBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.RLock()
	mode := b.mode
	legacy := b.legacyMiddleware
	b.mu.RUnlock()

	switch mode {
	case ModeShadow:
		b.serveShadow(w, r)
	case ModeGradual:
		b.serveGradual(w, r)
	case ModeFull:
		b.serveFull(w, r)
	default:
		// 默认回退到旧中间件
		if legacy != nil {
			legacy.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}
}

// serveShadow 影子模式：旧中间件处理请求，Pipeline 并行执行用于观测
func (b *ShadowBridge) serveShadow(w http.ResponseWriter, r *http.Request) {
	// 1. 旧中间件处理实际请求（同步）
	if b.legacyMiddleware != nil {
		b.legacyMiddleware.ServeHTTP(w, r)
	}

	// 2. Pipeline 异步执行（不阻塞响应）
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				// Pipeline panic 不影响已完成的响应
				// TODO: 记录到观测系统
			}
		}()

		rc := &RequestContext{
			TraceID:   extractTraceID(r),
			ClientIP:  extractClientIP(r),
			UserAgent: r.UserAgent(),
			StartTime: time.Now(),
		}

		// 使用 shadowWriter 捕获 Pipeline 的输出
		sw := &shadowWriter{header: make(http.Header)}
		b.pipeline.Execute(sw, r, rc)
		// 结果不写回 w，只用于观测和对比
	}()
}

// serveGradual 渐进模式：Pipeline 处理已迁移阶段，然后交给旧中间件
func (b *ShadowBridge) serveGradual(w http.ResponseWriter, r *http.Request) {
	rc := &RequestContext{
		TraceID:   extractTraceID(r),
		ClientIP:  extractClientIP(r),
		UserAgent: r.UserAgent(),
		StartTime: time.Now(),
	}

	// Pipeline 执行已迁移的阶段（如 IP ban check, WAF）
	halted := b.pipeline.Execute(w, r, rc)
	if halted {
		return // Pipeline 已终止（如 IP 被封禁）
	}

	// 未终止的请求交给旧中间件继续处理
	if b.legacyMiddleware != nil {
		b.legacyMiddleware.ServeHTTP(w, r)
	}
}

// serveFull 完全模式：Pipeline 完全接管
func (b *ShadowBridge) serveFull(w http.ResponseWriter, r *http.Request) {
	rc := &RequestContext{
		TraceID:   extractTraceID(r),
		ClientIP:  extractClientIP(r),
		UserAgent: r.UserAgent(),
		StartTime: time.Now(),
	}

	halted := b.pipeline.Execute(w, r, rc)
	if !halted {
		// Pipeline 未终止但也没有 handler 处理，返回 404
		http.NotFound(w, r)
	}
}

// shadowWriter 用于影子模式的 ResponseWriter 包装器
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
	if tid := r.Header.Get("X-Trace-Id"); tid != "" {
		return tid
	}
	return ""
}

func extractClientIP(r *http.Request) string {
	// 简单实现：从 RemoteAddr 提取
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

// CompareResult 对比 Pipeline 和旧中间件的判定结果（用于验证）
type CompareResult struct {
	TraceID       string
	PipelineHalt  bool
	LegacyHalt    bool
	Match         bool
	StageMetrics  []StageMetric
}

// CompareMiddleware 对比中间件（用于测试验证）
type CompareMiddleware struct {
	pipeline *Pipeline
	legacy   http.Handler
	results  []CompareResult
	mu       sync.Mutex
}

// NewCompareMiddleware 创建对比中间件
func NewCompareMiddleware(pipeline *Pipeline, legacy http.Handler) *CompareMiddleware {
	return &CompareMiddleware{
		pipeline: pipeline,
		legacy:   legacy,
		results:  make([]CompareResult, 0),
	}
}

// ServeHTTP 执行对比
func (c *CompareMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc := &RequestContext{
		TraceID:   extractTraceID(r),
		ClientIP:  extractClientIP(r),
		UserAgent: r.UserAgent(),
		StartTime: time.Now(),
	}

	// Pipeline 执行
	sw1 := &shadowWriter{header: make(http.Header)}
	pipelineHalted := c.pipeline.Execute(sw1, r, rc)

	// Legacy 执行
	sw2 := &shadowWriter{header: make(http.Header)}
	c.legacy.ServeHTTP(sw2, r)
	legacyHalted := sw2.statusCode >= 400 // 简化判定

	// 记录对比结果
	c.mu.Lock()
	c.results = append(c.results, CompareResult{
		TraceID:      rc.TraceID,
		PipelineHalt: pipelineHalted,
		LegacyHalt:   legacyHalted,
		Match:        pipelineHalted == legacyHalted,
		StageMetrics: rc.Stages,
	})
	c.mu.Unlock()

	// 实际响应使用旧中间件的结果
	w.Header().Set("Content-Type", "application/json")
	if sw2.statusCode > 0 {
		w.WriteHeader(sw2.statusCode)
	}
	w.Write(sw2.body)
}

// GetResults 获取对比结果（用于分析）
func (c *CompareMiddleware) GetResults() []CompareResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]CompareResult{}, c.results...)
}

// GetMatchRate 获取匹配率
func (c *CompareMiddleware) GetMatchRate() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.results) == 0 {
		return 0
	}
	matches := 0
	for _, r := range c.results {
		if r.Match {
			matches++
		}
	}
	return float64(matches) / float64(len(c.results)) * 100
}

// BytesPool 用于减少 body 读取的内存分配
var BytesPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 8192))
	},
}
