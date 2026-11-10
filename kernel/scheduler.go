// Package kernel: Scheduler — 请求生命周期管理
//
// v5.1 深度内核化：每个请求是一个"进程"，经历完整的生命周期：
//   1. Spawn（创建 RequestCtx + IRP 栈 + APC 队列）
//   2. Dispatch（逐 Stage 执行管道，每 Stage Push/Pop I/O Stack Location）
//   3. DeliverAPC（在 Stage 之间检查 APC 队列，处理异步中断）
//   4. Complete（完成例程回调，资源回收，IRP 栈弹出）
//
// 参考：
//   - Microsoft Learn IRP / I/O Stack Location：每层 Push/Pop 栈帧
//   - SEDA (SOSP 2001)：Stage + 有界队列 + 自适应降载
//   - Envoy threading model：main thread 管配置/统计，worker 不碰 IO
//   - NT APC (KiDeliverApc)：Stage 间检查 APC 队列
//   - Gecko Incremental Reflow：dirty bits 只重跑受影响 Stage

package kernel

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// Scheduler 统一管理请求生命周期（类比 OS 进程调度器）。
// 负责：请求上下文构造、IRP 栈管理、Stage 管道执行、APC 派发、
// panic recovery（Bugcheck）、超时/取消传播、资源回收。
type Scheduler struct {
	stages   []Stage
	irpDepth int           // IRP 栈最大深度
	sink     ContentSink   // 内容接收器（增量推送）
	bugcheck BugcheckHandler // Bugcheck 处理函数
	started  bool
}

// NewScheduler 创建调度器，注入安全管道各 Stage
func NewScheduler(stages ...Stage) *Scheduler {
	return &Scheduler{
		stages:   stages,
		irpDepth: 32,
		sink:     NoopSink{},
	}
}

// AddStage 追加阶段
func (s *Scheduler) AddStage(stage Stage) {
	s.stages = append(s.stages, stage)
}

// SetContentSink 设置内容接收器（Gecko Content Sink）
func (s *Scheduler) SetContentSink(sink ContentSink) {
	s.sink = sink
}

// SetBugcheckHandler 设置 Bugcheck 处理函数
func (s *Scheduler) SetBugcheckHandler(h BugcheckHandler) {
	s.bugcheck = h
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
// 这是完整的请求生命周期：
//  1. 构造 RequestCtx（Spawn）
//  2. 构造 IRP 栈
//  3. 逐 Stage 执行（每 Stage Push/Pop I/O Stack Location）
//  4. Stage 间派发 APC（检查异步中断）
//  5. 完成后回调 ContentSink
func (s *Scheduler) Execute(ctx context.Context, w http.ResponseWriter, r *http.Request) (halted bool) {
	// === Spawn: 构造请求上下文（IRP）===
	rc := &RequestCtx{
		TraceID:   extractTraceID(r),
		ConnID:    extractConnID(r),
		StartTime: time.Now(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Header:    r.Header,
		RemoteIP:  extractRemoteIP(r),
		Deadline:  time.Now().Add(30 * time.Second),
	}
	rc.APCHandle = NewAPCQueue()

	// 构造 IRP 栈
	irp := NewIRPStack(s.irpDepth)

	return s.executePipeline(ctx, rc, irp, w, r)
}

// ExecuteWithCtx 使用预构造的请求上下文执行（用于 Shadow Bridge）
func (s *Scheduler) ExecuteWithCtx(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) (halted bool) {
	irp := NewIRPStack(s.irpDepth)
	return s.executePipeline(ctx, rc, irp, w, r)
}

// executePipeline 核心管道执行逻辑
// 每个 Stage：Push I/O Stack Location → Execute → Pop + DeliverAPC
func (s *Scheduler) executePipeline(ctx context.Context, rc *RequestCtx, irp *IRPStack, w http.ResponseWriter, r *http.Request) (halted bool) {
	for _, stage := range s.stages {
		// === DeliverAPC: Stage 间检查 APC 队列 ===
		// 类比 NT 的 KiDeliverApc：在安全边界检查是否有异步中断
		if apc := s.deliverAPCs(rc); apc {
			// 有高优先级 APC（如 IP 封禁中断）：立即终止请求
			s.sink.OnComplete(rc, true)
			return true
		}

		// === Push: 推入 I/O Stack Location ===
		loc := IOStackLocation{
			StageName: stage.Name(),
			Ring:      Ring2, // 默认 Ring 2（系统服务）；Ring 0 Stage 自己声明
		}
		if _, err := irp.Push(loc); err != nil {
			// IRP 栈溢出 → Bugcheck
			TriggerBugcheck(BugcheckIRPStackOverflow, err.Error(), rc.TraceID, irp, s.bugcheck)
			s.sink.OnComplete(rc, true)
			return true
		}

		// === Execute: 执行 Stage ===
		result := s.executeStage(stage, ctx, rc, irp, w, r)

		// === Pop: 弹出 I/O Stack Location ===
		if top, err := irp.Pop(); err == nil && top.CompletionRoutine != nil {
			// 完成例程（类比 NT 的 IoCompletion）：下层完成 → 回调上层
			result = top.CompletionRoutine(rc, result, fmt.Errorf(top.Error))
		}

		// === ContentSink: 增量推送 Stage 结果 ===
		s.sink.OnStageResult(stage.Name(), result, rc)

		if result == Halt {
			s.sink.OnComplete(rc, true)
			return true
		}
	}

	s.sink.OnComplete(rc, false)
	return false
}

// executeStage 执行单个阶段（含 panic recovery + Bugcheck + 指标记录）
// fail-close 语义：panic → Bugcheck → Halt（拒绝请求）
func (s *Scheduler) executeStage(stage Stage, ctx context.Context, rc *RequestCtx, irp *IRPStack, w http.ResponseWriter, r *http.Request) (result StageResult) {
	stageName := stage.Name()
	start := time.Now()

	defer func() {
		duration := time.Since(start)
		if rec := recover(); rec != nil {
			// === Bugcheck: 不可恢复错误 ===
			// 不 panic（不像 NT 蓝屏），记录审计 + 返回 Halt
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			errMsg := fmt.Sprintf("PANIC: %v\n%s", rec, buf[:n])

			result = TriggerBugcheck(
				BugcheckPanic,
				errMsg,
				rc.TraceID,
				irp,
				s.bugcheck,
			)
			rc.Stages = append(rc.Stages, StageMetric{
				Name:     stageName,
				Duration: duration,
				Result:   Halt,
				Error:    errMsg,
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

// deliverAPCs 派发 APC 队列（类比 NT 的 KiDeliverApc）
// 返回 true 表示有高优先级 APC 需要中断请求
func (s *Scheduler) deliverAPCs(rc *RequestCtx) bool {
	if rc.APCHandle == nil {
		return false
	}
	for {
		apc, ok := rc.APCHandle.Dequeue()
		if !ok {
			break
		}
		// 内核或紧急优先级的 APC 需要中断请求
		if apc.Priority >= APCKernel {
			return true
		}
		// 用户态 APC：记录但不中断
		_ = apc
	}
	return false
}

// Stages 返回当前管道的阶段名列表
func (s *Scheduler) Stages() []string {
	return s.stageNames()
}

func (s *Scheduler) stageNames() []string {
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
