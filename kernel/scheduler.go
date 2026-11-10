// Package kernel: Scheduler — 请求生命周期管理
//
// 参考：
//   - Microsoft IRP / I/O Stack Location：请求是自包含对象，每层拥有上下文
//   - SEDA (SOSP 2001)：Stage + 有界队列 + 自适应降载
//   - Envoy threading model：main thread 管配置/统计，worker 各自 event loop

package kernel

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// Scheduler 统一管理请求生命周期（类比 OS 进程调度器）。
// 负责：请求上下文构造、Stage 管道执行、panic recovery、超时/取消传播。
type Scheduler struct {
	stages []Stage
	started bool
}

// NewScheduler 创建调度器，注入安全管道各 Stage
func NewScheduler(stages ...Stage) *Scheduler {
	return &Scheduler{stages: stages}
}

// AddStage 追加阶段
func (s *Scheduler) AddStage(stage Stage) {
	s.stages = append(s.stages, stage)
}

// Start 启动调度器
func (s *Scheduler) Start() {
	s.started = true
}

// Stop 停止调度器
func (s *Scheduler) Stop() {
	s.started = false
}

// Execute 执行请求管道（类比 OS syscall 入口）。
// 每个 Stage 独立 recover，单阶段 panic 不影响其他阶段和主进程。
// 参考 LLVM PassManager (CGO 2004)：每个 Pass 独立、可组合、可观测。
func (s *Scheduler) Execute(ctx context.Context, w http.ResponseWriter, r *http.Request) (halted bool) {
	// 构造请求上下文（IRP）
	rc := &RequestCtx{
		TraceID:   extractTraceID(r),
		ConnID:    extractConnID(r),
		StartTime: time.Now(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Header:    r.Header,
		RemoteIP:  extractRemoteIP(r),
		Deadline:  time.Now().Add(30 * time.Second), // 默认 30s 超时
	}

	return s.executeStages(ctx, rc, w, r)
}

// ExecuteWithCtx 使用预构造的请求上下文执行（用于 Shadow Bridge 等高级模式）
func (s *Scheduler) ExecuteWithCtx(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) (halted bool) {
	return s.executeStages(ctx, rc, w, r)
}

// executeStages 逐阶段执行管道
func (s *Scheduler) executeStages(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) (halted bool) {
	for _, stage := range s.stages {
		result := s.executeStage(stage, ctx, rc, w, r)
		if result == Halt {
			return true
		}
	}
	return false
}

// executeStage 执行单个阶段（含 panic recovery + 指标记录）
// fail-close 语义：panic → Halt（拒绝请求，不让错误请求穿透）
func (s *Scheduler) executeStage(stage Stage, ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) (result StageResult) {
	stageName := stage.Name()
	start := time.Now()

	defer func() {
		duration := time.Since(start)
		if rec := recover(); rec != nil {
			// fail-close：panic 时拒绝请求
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			result = Halt
			rc.Stages = append(rc.Stages, StageMetric{
				Name:     stageName,
				Duration: duration,
				Result:   Halt,
				Error:    fmt.Sprintf("PANIC: %v\n%s", rec, buf[:n]),
			})
		} else {
			rc.Stages = append(rc.Stages, StageMetric{
				Name:     stageName,
				Duration: duration,
				Result:   result,
			})
		}
	}()

	return stage.Execute(ctx, rc, w, r)
}

// Stages 返回当前管道的阶段名列表
func (s *Scheduler) Stages() []string {
	names := make([]string, len(s.stages))
	for i, st := range s.stages {
		names[i] = st.Name()
	}
	return names
}

// ===================== 辅助函数 =====================

func extractTraceID(r *http.Request) string {
	if id := r.Header.Get("X-Trace-ID"); id != "" {
		return id
	}
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func extractConnID(r *http.Request) string {
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func extractRemoteIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
