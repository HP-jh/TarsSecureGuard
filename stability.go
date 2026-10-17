package main

// ===================== v3.9.0 交互层稳定性与快捷性 =====================
//
// 目标：在现有 v3.x 模块间通信路径上增强稳定性，不重构整个架构。
//
// 措施：
//   1. 错误边界 — 各模块 panic 捕获，防止单点崩溃拖垮全局
//   2. 超时与重试 — 外调/内调统一超时 + 指数退避重试
//   3. 降级策略 — 依赖故障时回退到本地/默认/缓存
//   4. 链路追踪 — 请求级 trace_id 透传，各模块打点
//   5. 批量请求合并 — 短时间窗口内同类请求合并为批量调用
//   6. 缓存复用 — 热点路径结果缓存（TTL + LRU）
//   7. 热点路径常量化 — 高频配置项预计算为常量
//   8. 慢操作采样 — 超过阈值的操作自动记录详细日志

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ===================== 1. 错误边界 =====================

// SafeCall 带 panic 恢复的通用包装
type SafeCallResult struct {
	Result interface{}
	Err    error
	Panic  interface{}
	Duration time.Duration
}

func SafeCall(name string, fn func() interface{}) SafeCallResult {
	start := time.Now()
	var result interface{}
	var err error
	var panicVal interface{}

	func() {
		defer func() {
			if r := recover(); r != nil {
				panicVal = r
				err = fmt.Errorf("panic in %s: %v", name, r)
				auditLog("PANIC_RECOVER", "-", fmt.Sprintf("%s: %v", name, r))
			}
		}()
		result = fn()
	}()

	return SafeCallResult{
		Result:   result,
		Err:      err,
		Panic:    panicVal,
		Duration: time.Since(start),
	}
}

// ModuleBoundary HTTP Handler 级别的错误边界
func ModuleBoundary(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				auditLog("BOUNDARY_PANIC", clientIP(r), fmt.Sprintf("%s: %v", name, rec))
				writeJSONStatus(w, http.StatusInternalServerError, map[string]string{
					"error": "internal error",
					"hint":  "module boundary recovered",
				})
			}
		}()
		next(w, r)
	}
}

// ===================== 2. 超时与重试 =====================

// RetryConfig 重试配置
type RetryConfig struct {
	MaxRetries  int           `json:"max_retries"`
	BaseDelay   time.Duration `json:"base_delay"`
	MaxDelay    time.Duration `json:"max_delay"`
	Timeout     time.Duration `json:"timeout"`
}

var defaultRetry = RetryConfig{
	MaxRetries: 3,
	BaseDelay:  100 * time.Millisecond,
	MaxDelay:   5 * time.Second,
	Timeout:    30 * time.Second,
}

func WithRetry(name string, cfg RetryConfig, fn func(ctx context.Context) error) error {
	var lastErr error
	for i := 0; i <= cfg.MaxRetries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		err := fn(ctx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if i < cfg.MaxRetries {
			delay := cfg.BaseDelay * time.Duration(1<<i)
			if delay > cfg.MaxDelay {
				delay = cfg.MaxDelay
			}
			auditLog("RETRY", "-", fmt.Sprintf("%s attempt=%d delay=%s err=%v", name, i+1, delay, err))
			time.Sleep(delay)
		}
	}
	return fmt.Errorf("%s failed after %d retries: %w", name, cfg.MaxRetries, lastErr)
}

// ===================== 3. 降级策略 =====================

// FallbackChain 降级链：主逻辑 -> 备选1 -> 备选2 -> 默认值
type FallbackChain struct {
	Name     string
	Primary  func() (interface{}, error)
	Fallback []func() (interface{}, error)
	Default  interface{}
}

func (f *FallbackChain) Execute() (interface{}, error) {
	if f.Primary != nil {
		res, err := f.Primary()
		if err == nil {
			return res, nil
		}
		auditLog("FALLBACK", "-", fmt.Sprintf("%s primary failed: %v", f.Name, err))
	}
	for i, fn := range f.Fallback {
		res, err := fn()
		if err == nil {
			auditLog("FALLBACK", "-", fmt.Sprintf("%s fallback-%d ok", f.Name, i))
			return res, nil
		}
		auditLog("FALLBACK", "-", fmt.Sprintf("%s fallback-%d failed: %v", f.Name, i, err))
	}
	if f.Default != nil {
		auditLog("FALLBACK", "-", fmt.Sprintf("%s using default", f.Name))
		return f.Default, nil
	}
	return nil, fmt.Errorf("%s: all fallbacks exhausted", f.Name)
}

// ===================== 4. 链路追踪 =====================

var traceCounter uint64

type TraceContext struct {
	TraceID   string
	SpanID    string
	StartTime time.Time
	Modules   []TraceSpan
}

type TraceSpan struct {
	Module    string        `json:"module"`
	Start     time.Time     `json:"start"`
	Duration  time.Duration `json:"duration"`
	Status    string        `json:"status"` // ok / error / timeout / fallback
	Detail    string        `json:"detail"`
}

func NewTrace() *TraceContext {
	id := atomic.AddUint64(&traceCounter, 1)
	return &TraceContext{
		TraceID:   fmt.Sprintf("trace-%d-%d", time.Now().Unix(), id),
		SpanID:    fmt.Sprintf("span-%d", id),
		StartTime: time.Now(),
		Modules:   make([]TraceSpan, 0),
	}
}

func (t *TraceContext) Record(module, status, detail string, start time.Time) {
	t.Modules = append(t.Modules, TraceSpan{
		Module:   module,
		Start:    start,
		Duration: time.Since(start),
		Status:   status,
		Detail:   detail,
	})
}

func (t *TraceContext) InjectHeader(h http.Header) {
	h.Set("X-TSG-Trace-ID", t.TraceID)
}

func TraceFromHeader(h http.Header) *TraceContext {
	traceID := h.Get("X-TSG-Trace-ID")
	if traceID == "" {
		return NewTrace()
	}
	return &TraceContext{
		TraceID:   traceID,
		SpanID:    fmt.Sprintf("span-%d", atomic.AddUint64(&traceCounter, 1)),
		StartTime: time.Now(),
		Modules:   make([]TraceSpan, 0),
	}
}

// ===================== 5. 批量请求合并 =====================

// BatchRequest 批量合并器（简化版：同路径 + 同方法窗口合并）
type BatchRequest struct {
	mu        sync.Mutex
	window    time.Duration
	maxSize   int
	pending   map[string][]*batchedReq // key = method+path
	flushChan chan string
}

type batchedReq struct {
	w    http.ResponseWriter
	r    *http.Request
	done chan struct{}
}

func NewBatchRequest(window time.Duration, maxSize int) *BatchRequest {
	br := &BatchRequest{
		window:    window,
		maxSize:   maxSize,
		pending:   make(map[string][]*batchedReq),
		flushChan: make(chan string, 100),
	}
	go br.loop()
	return br
}

func (b *BatchRequest) loop() {
	ticker := time.NewTicker(b.window)
	defer ticker.Stop()
	for key := range b.flushChan {
		b.flush(key)
	}
}

func (b *BatchRequest) Add(key string, w http.ResponseWriter, r *http.Request) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	req := &batchedReq{w: w, r: r, done: make(chan struct{})}
	b.pending[key] = append(b.pending[key], req)

	if len(b.pending[key]) >= b.maxSize {
		select {
		case b.flushChan <- key:
		default:
		}
	}
	// 简化：不真正合并，只返回 false 表示未合并（后续可扩展）
	return false
}

func (b *BatchRequest) flush(key string) {
	b.mu.Lock()
	batch := b.pending[key]
	delete(b.pending, key)
	b.mu.Unlock()

	if len(batch) == 0 {
		return
	}
	// 简化：逐个处理（未来可实现真正的批量代理）
	for _, req := range batch {
		close(req.done)
	}
}

// ===================== 6. 缓存复用 =====================

// SimpleCache 带 TTL 的简单缓存（LRU 简化版：最大条目数限制 + 定时清理）
type SimpleCache struct {
	mu       sync.RWMutex
	items    map[string]*cacheItem
	maxItems int
	ttl      time.Duration
}

type cacheItem struct {
	value      interface{}
	expiresAt  time.Time
	accessCount int64
}

func NewSimpleCache(maxItems int, ttl time.Duration) *SimpleCache {
	sc := &SimpleCache{
		items:    make(map[string]*cacheItem),
		maxItems: maxItems,
		ttl:      ttl,
	}
	go sc.cleanupLoop()
	return sc
}

func (c *SimpleCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	atomic.AddInt64(&item.accessCount, 1)
	return item.value, true
}

func (c *SimpleCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.items) >= c.maxItems {
		// 简化淘汰：随机删一个
		for k := range c.items {
			delete(c.items, k)
			break
		}
	}
	c.items[key] = &cacheItem{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *SimpleCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.expiresAt) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

// 全局热点缓存实例
var hotPathCache *SimpleCache

// ===================== 7. 热点路径常量化 =====================

// HotConstants 预计算的热点常量（启动时从 config 计算一次，运行期只读）
type HotConstants struct {
	APIKeyHash       string
	WAFEnabled       bool
	AuditEnabled     bool
}

var hotConst HotConstants
var hotConstOnce sync.Once

func RefreshHotConstants() {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	hotConst = HotConstants{
		APIKeyHash:     hashContent(cfg.Security.APIKey),
		WAFEnabled:     cfg.Security.WAFEnabled,
		AuditEnabled:   cfg.Security.AuditLogEnabled,
	}
}

// ===================== 8. 慢操作采样 =====================

// SlowOpSampler 慢操作采样器
type SlowOpSampler struct {
	threshold time.Duration
}

func NewSlowOpSampler(threshold time.Duration) *SlowOpSampler {
	return &SlowOpSampler{threshold: threshold}
}

func (s *SlowOpSampler) Observe(name string, start time.Time, detail string) {
	d := time.Since(start)
	if d > s.threshold {
		auditLog("SLOW_OP", "-", fmt.Sprintf("%s took %s | %s", name, d, detail))
	}
}

var slowSampler *SlowOpSampler

func initStability() {
	hotPathCache = NewSimpleCache(1000, 5*time.Minute)
	slowSampler = NewSlowOpSampler(500 * time.Millisecond)
	hotConstOnce.Do(RefreshHotConstants)
}
