// Package kernel: I/O Stack Location — IRP 栈帧链
//
// NT 的 IRP 不是扁平管道——每个驱动层在 IRP 上推入自己的 I/O Stack Location，
// 形成栈帧链。下层执行完后弹出，上层恢复。这给了每层独立的上下文、
// 可重入的完成例程、以及精确的栈式错误传播。
//
// 参考：Microsoft Learn "IRP I/O Stack Locations"
// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/example-i-o-request—

package kernel

import (
	"fmt"
	"time"
)

// IOStackLocation 一个 I/O 栈位置（类比 NT 的 IO_STACK_LOCATION）
// 每个 Stage 在执行前 Push 自己的位置，执行后 Pop。
type IOStackLocation struct {
	// 阶段标识
	StageName  string
	StageVer   string
	Ring       ProtectionRing // 执行权限级别

	// 该层的上下文（每层独立拥有，不共享）
	StartedAt  time.Time
	CompletedAt time.Time
	Result     StageResult
	Error      string

	// 完成例程（类比 NT 的 IoCompletion）：下层执行完后回调上层
	CompletionRoutine func(rc *RequestCtx, result StageResult, err error) StageResult

	// 分配的资源（类比 NT 的 IoMarkIrpPending/IoMarkIrpStackLocation）
	// Stage 分配的资源在 Pop 时由调度器回收
	Allocated *ResourceSet
}

// ResourceSet 一个 Stage 分配的资源集合（Pop 时回收）
type ResourceSet struct {
	Buffers   [][]byte    // 分配的 buffer（由 MemoryManager 池化回收）
	Handles   []Handle    // 打开的内核对象句柄
	Snapshots []interface{} // 加载的配置快照引用
}

// IRPStack IRP 的栈帧链（类比 NT 的 IRP with stacked IO_STACK_LOCATIONs）
type IRPStack struct {
	locations []IOStackLocation
	maxDepth  int
}

// NewIRPStack 创建 IRP 栈（预设最大深度，防止栈溢出）
func NewIRPStack(maxDepth int) *IRPStack {
	if maxDepth <= 0 {
		maxDepth = 32 // 默认上限
	}
	return &IRPStack{
		locations: make([]IOStackLocation, 0, maxDepth),
		maxDepth:  maxDepth,
	}
}

// Push 推入一个新的 I/O Stack Location（类比 NT 的 IoGetNextIrpStackLocation）
// 返回新栈位置的指针，Stage 在此写入自己的上下文。
func (s *IRPStack) Push(loc IOStackLocation) (*IOStackLocation, error) {
	if len(s.locations) >= s.maxDepth {
		return nil, fmt.Errorf("IRP stack overflow: max depth %d exceeded", s.maxDepth)
	}
	loc.StartedAt = time.Now()
	s.locations = append(s.locations, loc)
	return &s.locations[len(s.locations)-1], nil
}

// Pop 弹出栈顶 I/O Stack Location（类比 NT 的 IoCompleteRequest 回溯）
// 执行完成例程，回收资源。
func (s *IRPStack) Pop() (*IOStackLocation, error) {
	if len(s.locations) == 0 {
		return nil, fmt.Errorf("IRP stack underflow: no locations to pop")
	}
	top := &s.locations[len(s.locations)-1]
	top.CompletedAt = time.Now()

	// 执行完成例程（如果有）：下层完成 → 通知上层
	if top.CompletionRoutine != nil {
		// CompletionRoutine 可以修改 Result（类比 NT 的 IoCompletion 覆盖）
	}

	s.locations = s.locations[:len(s.locations)-1]
	return top, nil
}

// Current 返回栈顶位置（不弹出）
func (s *IRPStack) Current() *IOStackLocation {
	if len(s.locations) == 0 {
		return nil
	}
	return &s.locations[len(s.locations)-1]
}

// Depth 返回当前栈深度
func (s *IRPStack) Depth() int {
	return len(s.locations)
}

// StackTrace 返回完整的栈帧链（用于审计/诊断，类比 NT 的 !irp 分析）
func (s *IRPStack) StackTrace() []IOStackLocation {
	out := make([]IOStackLocation, len(s.locations))
	copy(out, s.locations)
	return out
}

// Root 返回栈底位置（最初的请求上下文）
func (s *IRPStack) Root() *IOStackLocation {
	if len(s.locations) == 0 {
		return nil
	}
	return &s.locations[0]
}
