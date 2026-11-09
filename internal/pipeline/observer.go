package pipeline

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Note: Observer interface is defined in pipeline.go

// MetricsObserver 收集指标用于 Prometheus 导出或日志记录
// 零依赖实现，使用 atomic 计数器
type MetricsObserver struct {
	// Stage 级别的计数器
	StageHits     map[string]*int64 // Continue 次数
	StageHalts    map[string]*int64 // Halt 次数
	StageErrors   map[string]*int64 // Error 次数
	StageDuration map[string]*int64 // 累计耗时 (ns)
	
	// Pipeline 级别的计数器
	TotalRequests int64
	HaltedRequests int64
}

// NewMetricsObserver 创建指标观察者
func NewMetricsObserver() *MetricsObserver {
	return &MetricsObserver{
		StageHits:     make(map[string]*int64),
		StageHalts:    make(map[string]*int64),
		StageErrors:   make(map[string]*int64),
		StageDuration: make(map[string]*int64),
	}
}

// OnStageStart 实现 Observer 接口
func (m *MetricsObserver) OnStageStart(stage string, rc *RequestContext) {
	// 可选：记录开始时间或其他指标
}

// OnStageEnd 实现 Observer 接口
func (m *MetricsObserver) OnStageEnd(stage string, rc *RequestContext, result StageResult, duration time.Duration) {
	atomic.AddInt64(&m.TotalRequests, 1)
	
	// 根据结果更新对应的计数器
	switch result {
	case Continue:
		if counter, ok := m.StageHits[stage]; ok {
			atomic.AddInt64(counter, 1)
		} else {
			var val int64 = 1
			m.StageHits[stage] = &val
		}
	case Halt:
		atomic.AddInt64(&m.HaltedRequests, 1)
		if counter, ok := m.StageHalts[stage]; ok {
			atomic.AddInt64(counter, 1)
		} else {
			var val int64 = 1
			m.StageHalts[stage] = &val
		}
	}
	
	// 记录耗时
	if counter, ok := m.StageDuration[stage]; ok {
		atomic.AddInt64(counter, int64(duration))
	} else {
		var val int64 = int64(duration)
		m.StageDuration[stage] = &val
	}
}

// OnPipelineComplete 实现 Observer 接口
func (m *MetricsObserver) OnPipelineComplete(rc *RequestContext, halted bool) {
	// Pipeline 完成时的回调，可用于记录总体统计
	if halted {
		// 已在 OnStageEnd 中计数
	}
}

// GetStageMetrics 获取指定 Stage 的指标快照
func (m *MetricsObserver) GetStageMetrics(stageName string) map[string]interface{} {
	var hits, halts, errors, durationNs int64
	
	if counter, ok := m.StageHits[stageName]; ok {
		hits = atomic.LoadInt64(counter)
	}
	if counter, ok := m.StageHalts[stageName]; ok {
		halts = atomic.LoadInt64(counter)
	}
	if counter, ok := m.StageErrors[stageName]; ok {
		errors = atomic.LoadInt64(counter)
	}
	if counter, ok := m.StageDuration[stageName]; ok {
		durationNs = atomic.LoadInt64(counter)
	}
	
	total := hits + halts + errors
	avgDurationMs := float64(0)
	if total > 0 {
		avgDurationMs = float64(durationNs) / float64(total) / 1e6
	}
	
	return map[string]interface{}{
		"hits":            hits,
		"halts":           halts,
		"errors":          errors,
		"total":           total,
		"avg_duration_ms": avgDurationMs,
	}
}

// GetPipelineMetrics 获取 Pipeline 整体指标快照
func (m *MetricsObserver) GetPipelineMetrics() map[string]interface{} {
	total := atomic.LoadInt64(&m.TotalRequests)
	halted := atomic.LoadInt64(&m.HaltedRequests)
	
	haltRate := float64(0)
	if total > 0 {
		haltRate = float64(halted) / float64(total) * 100
	}
	
	return map[string]interface{}{
		"total_requests":  total,
		"halted_requests": halted,
		"halt_rate_pct":   haltRate,
	}
}

// LogObserver 将 Pipeline 执行结果输出到日志（用于调试和审计）
type LogObserver struct {
	LogFunc func(format string, args ...interface{})
}

// OnStageStart 实现 Observer 接口
func (l *LogObserver) OnStageStart(stage string, rc *RequestContext) {
	if l.LogFunc != nil {
		l.LogFunc("[PIPELINE] Stage %s started", stage)
	}
}

// OnStageEnd 实现 Observer 接口
func (l *LogObserver) OnStageEnd(stage string, rc *RequestContext, result StageResult, duration time.Duration) {
	if l.LogFunc == nil {
		return
	}
	
	resultStr := "CONTINUE"
	if result == Halt {
		resultStr = "HALT"
	}
	
	l.LogFunc("[PIPELINE] Stage %s: %s (duration=%v)", stage, resultStr, duration)
}

// OnPipelineComplete 实现 Observer 接口
func (l *LogObserver) OnPipelineComplete(rc *RequestContext, halted bool) {
	if l.LogFunc == nil {
		return
	}
	
	if halted {
		l.LogFunc("[PIPELINE] Pipeline halted")
	}
}

// MultiObserver 组合多个 Observer
type MultiObserver struct {
	observers []Observer
}

// NewMultiObserver 创建组合观察者
func NewMultiObserver(observers ...Observer) *MultiObserver {
	return &MultiObserver{observers: observers}
}

// OnStageStart 广播到所有观察者
func (m *MultiObserver) OnStageStart(stage string, rc *RequestContext) {
	for _, obs := range m.observers {
		obs.OnStageStart(stage, rc)
	}
}

// OnStageEnd 广播到所有观察者
func (m *MultiObserver) OnStageEnd(stage string, rc *RequestContext, result StageResult, duration time.Duration) {
	for _, obs := range m.observers {
		obs.OnStageEnd(stage, rc, result, duration)
	}
}

// OnPipelineComplete 广播到所有观察者
func (m *MultiObserver) OnPipelineComplete(rc *RequestContext, halted bool) {
	for _, obs := range m.observers {
		obs.OnPipelineComplete(rc, halted)
	}
}

// String 返回指标的字符串表示（用于日志）
func (m *MetricsObserver) String() string {
	metrics := m.GetPipelineMetrics()
	return fmt.Sprintf("Pipeline: total=%d, halted=%d (%.2f%%)",
		metrics["total_requests"],
		metrics["halted_requests"],
		metrics["halt_rate_pct"])
}
