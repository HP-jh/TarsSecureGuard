// Package kernel: APC + Bugcheck + Exception Port
//
// 参考 NT 的异步/异常机制：
//   - APC (Asynchronous Procedure Call)：请求进行中需要中断（如 IP 被封了）
//   - Bugcheck：不可恢复的内核错误 → 记录 + 拒绝请求 + 触发告警
//   - Exception Port：Stage 执行中的异常分发到统一的异常处理端口
//
// 类比 Gecko 的 Content Sink：增量推送（不是攒着一次吐），
// 以及 Gecko 的 Frame Construction 检查点：增量构建，在关键点 flush。

package kernel

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ===================== APC (异步过程调用) =====================
//
// 场景：请求正在被处理时，安全子系统检测到该连接的 IP 被加入封禁表。
// 此时需要异步中断请求 → APC 机制：向请求的 APC 队列投递中断请求。
// 参考 NT 的 KeInsertQueueApc / KiDeliverApc。

// APC 一个异步过程调用
type APC struct {
	ID        uint64
	Reason    string        // 中断原因（如 "IP封禁", "配置热重载"）
	Priority  APCPriority   // 优先级
	Timeout   time.Duration // 中断超时
	Timestamp time.Time
	Cancel    atomic.Bool // 是否已被取消（类比 NT 的 KeCancelApc）
}

// APCPriority APC 优先级
type APCPriority int

const (
	APCNormal  APCPriority = iota // 用户态 APC（低优先级）
	APCKernel                      // 内核态 APC（高优先级，如 IP 封禁中断）
	APCUrgent                      // 紧急（如 panic recovery）
)

// APCQueue 请求级 APC 队列（每个请求有自己的队列）
// 类比 NT 的 KAPC：每个线程（请求）有自己的 APC 队列
type APCQueue struct {
	mu      sync.Mutex
	entries []APC
	pending atomic.Int64
}

// NewAPCQueue 创建 APC 队列
func NewAPCQueue() *APCQueue {
	return &APCQueue{
		entries: make([]APC, 0, 4),
	}
}

// Enqueue 投递 APC（类比 NT 的 KeInsertQueueApc）
// 高优先级 APC 排在队列前面
func (q *APCQueue) Enqueue(apc APC) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// 按优先级插入：紧急 > 内核 > 用户
	insertAt := len(q.entries)
	for i, e := range q.entries {
		if apc.Priority > e.Priority {
			insertAt = i
			break
		}
	}
	q.entries = append(q.entries, APC{}); copy(q.entries[insertAt+1:], q.entries[insertAt:])
	q.entries[insertAt] = apc
	q.pending.Add(1)
}

// Dequeue 取出最高优先级的 APC（类比 NT 的 KiDeliverApc）
func (q *APCQueue) Dequeue() (*APC, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.entries) == 0 {
		return nil, false
	}
	apc := q.entries[0]
	q.entries = q.entries[1:]
	q.pending.Add(-1)
	return &apc, true
}

// Pending 返回待处理的 APC 数量
func (q *APCQueue) Pending() int64 {
	return q.pending.Load()
}

// ===================== Bugcheck (不可恢复错误) =====================
//
// 参考 NT 的 KeBugCheck：不可恢复的内核错误 → 记录 dump + 停止。
// 在安全网关上下文中：Bugcheck = 记录详细审计 + 拒绝请求 + 触发告警。
// 不停止整个进程（不像 NT 的蓝屏），因为需要保持其他请求的服务能力。

// BugcheckCode Bugcheck 错误码
type BugcheckCode int

const (
	BugcheckPanic         BugcheckCode = iota + 1 // 1: Stage panic
	BugcheckRingViolation                         // 2: 保护环违例
	BugcheckIRPStackOverflow                     // 3: IRP 栈溢出
	BugcheckAPCTimeout                           // 4: APC 超时未处理
	BugcheckObjectLeak                           // 5: 对象引用泄漏
	BugcheckFailClose                            // 6: Fail-close 触发
)

func (c BugcheckCode) String() string {
	switch c {
	case BugcheckPanic:
		return "STAGE_PANIC"
	case BugcheckRingViolation:
		return "RING_VIOLATION"
	case BugcheckIRPStackOverflow:
		return "IRP_STACK_OVERFLOW"
	case BugcheckAPCTimeout:
		return "APC_TIMEOUT"
	case BugcheckObjectLeak:
		return "OBJECT_LEAK"
	case BugcheckFailClose:
		return "FAIL_CLOSE"
	default:
		return fmt.Sprintf("BUGCHECK_%d", int(c))
	}
}

// BugcheckData Bugcheck 数据（类比 NT 的 KBUGCHECK_DATA）
type BugcheckData struct {
	Code      BugcheckCode
	Message   string
	TraceID   string
	Stack     []IOStackLocation // IRP 栈快照（用于审计）
	Timestamp time.Time
	Recovery  string // 恢复动作描述
}

// BugcheckHandler Bugcheck 处理函数（由 main.go 注入）
type BugcheckHandler func(data BugcheckData)

// bugcheckTracker 全局 Bugcheck 计数器（fail-close 次数统计）
var bugcheckCount atomic.Int64

// TriggerBugcheck 触发 Bugcheck（类比 NT 的 KeBugCheck）
// 不 panic（不像 NT 蓝屏），而是记录审计 + 返回 Halt（拒绝当前请求）
func TriggerBugcheck(code BugcheckCode, msg, traceID string, stack *IRPStack, handler BugcheckHandler) StageResult {
	bugcheckCount.Add(1)
	data := BugcheckData{
		Code:      code,
		Message:   msg,
		TraceID:   traceID,
		Stack:     nil,
		Timestamp: time.Now(),
		Recovery:  "request rejected (fail-close), process continues",
	}
	if stack != nil {
		data.Stack = stack.StackTrace()
	}
	if handler != nil {
		handler(data)
	}
	return Halt
}

// BugcheckCount 返回累计 Bugcheck 次数（用于诊断端点）
func BugcheckCount() int64 {
	return bugcheckCount.Load()
}

// ===================== Exception Port (异常分发) =====================
//
// 参考 NT 的异常端口：Stage 执行中的异常不直接 panic，
// 而是分发到统一的异常处理端口，由内核决定如何处理（拒绝请求、降级、重试）。

// ExceptionData 异常数据
type ExceptionData struct {
	StageName string
	Error     error
	TraceID   string
	Recoverable bool
}

// ExceptionHandler 异常处理函数
// 返回 Continue（恢复）或 Halt（拒绝）
type ExceptionHandler func(data ExceptionData) StageResult

// defaultExceptionHandler 默认异常处理：fail-close
func defaultExceptionHandler(data ExceptionData) StageResult {
	return Halt
}

// ExceptionPort 异常端口
type ExceptionPort struct {
	handler ExceptionHandler
}

// NewExceptionPort 创建异常端口
func NewExceptionPort() *ExceptionPort {
	return &ExceptionPort{handler: defaultExceptionHandler}
}

// SetHandler 设置异常处理函数
func (p *ExceptionPort) SetHandler(h ExceptionHandler) {
	p.handler = h
}

// Dispatch 分发异常（类比 NT 的 KiDispatchException）
func (p *ExceptionPort) Dispatch(data ExceptionData) StageResult {
	return p.handler(data)
}
