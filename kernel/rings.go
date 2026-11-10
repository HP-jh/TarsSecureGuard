// Package kernel: Protection Rings — 保护环 + Syscall 边界
//
// 参考 NT 的 Ring 0 (kernel) / Ring 3 (user) 保护模型：
//   - Ring 0: 安全核心（不可绕过，不可关闭）
//   - Ring 1: 安全辅助（IP信誉、审计、CSP——可配置但不可在请求路径上关）
//   - Ring 2: 系统服务（限流、配额、路由——可配置可关）
//   - Ring 3: 用户态（chat handler、模型管理——完全用户可控）
//
// 安全不变量：Ring 0 永远执行，Ring 3 无法阻止 Ring 0 的检查。
// 类比：用户态程序无法跳过内核的安全检查。

package kernel

import "fmt"

// ProtectionRing 保护环级别
type ProtectionRing int

const (
	Ring0 ProtectionRing = iota // Ring0 内核态：安全核心（不可关闭）
	Ring1                        // Ring1 内核辅助：审计/IP信誉/CSP
	Ring2                        // Ring2 系统服务：限流/配额/路由
	Ring3                        // Ring3 用户态：业务 handler
)

func (r ProtectionRing) String() string {
	switch r {
	case Ring0:
		return "Ring0(kernel)"
	case Ring1:
		return "Ring1(audit)"
	case Ring2:
		return "Ring2(system)"
	case Ring3:
		return "Ring3(user)"
	default:
		return fmt.Sprintf("Ring?(%d)", int(r))
	}
}

// CanBypass 检查一个环是否能跳过另一个环
// 规则：高权限环可以跳过低权限环；低权限绝不能跳过高权限
func (r ProtectionRing) CanBypass(other ProtectionRing) bool {
	return r < other // 数值越小 = 权限越高
}

// RingViolationError 环违例（用户态尝试跳过内核态检查）
type RingViolationError struct {
	Caller   ProtectionRing
	Target   ProtectionRing
	StageName string
}

func (e *RingViolationError) Error() string {
	return fmt.Sprintf("ring violation: %s attempted to bypass %s stage %q",
		e.Caller, e.Target, e.StageName)
}

// SyscallTable 系统调用表（类比 NT 的 SSDT/System Service Dispatch Table）
// 用户态通过 syscall 号调用内核服务，不直接访问内核数据结构。
type SyscallTable struct {
	entries map[SyscallNumber]*SyscallEntry
}

// SyscallNumber 系统调用号
type SyscallNumber int

const (
	SysWAFCheck      SyscallNumber = 1  // WAF 检查
	SysSSRFCheck     SyscallNumber = 2  // SSRF 检查
	SysAuditLog      SyscallNumber = 3  // 审计日志
	SysPIIMask       SyscallNumber = 4  // PII 脱敏
	SysRateLimit     SyscallNumber = 5  // 速率限制
	SysRBACCheck     SyscallNumber = 6  // RBAC 权限检查
	SysQuotaCheck    SyscallNumber = 7  // 配额检查
	SysConfigSnapshot SyscallNumber = 8 // 配置快照读
	SysIPReputation  SyscallNumber = 9  // IP 信誉查询
	SysCSPGenerate   SyscallNumber = 10 // CSP 生成
)

// SyscallEntry 单个系统调用表项
type SyscallEntry struct {
	Number  SyscallNumber
	Name    string
	Ring    ProtectionRing // 此 syscall 所需的最低权限
	Handler SyscallHandler
}

// SyscallHandler 系统调用处理函数
// 参数从 RequestCtx 获取，返回 StageResult + 错误。
type SyscallHandler func(rc *RequestCtx, args interface{}) (StageResult, error)

// NewSyscallTable 创建系统调用表
func NewSyscallTable() *SyscallTable {
	return &SyscallTable{
		entries: make(map[SyscallNumber]*SyscallEntry),
	}
}

// Register 注册系统调用
func (t *SyscallTable) Register(num SyscallNumber, name string, ring ProtectionRing, handler SyscallHandler) {
	t.entries[num] = &SyscallEntry{
		Number:  num,
		Name:    name,
		Ring:    ring,
		Handler: handler,
	}
}

// Invoke 调用系统调用（类比 NT 的 KeServiceDescriptorTable 派发）
// caller 是调用者的权限环；如果 caller 权限低于 syscall 要求，拒绝。
func (t *SyscallTable) Invoke(caller ProtectionRing, num SyscallNumber, rc *RequestCtx, args interface{}) (StageResult, error) {
	entry, ok := t.entries[num]
	if !ok {
		return Halt, fmt.Errorf("unknown syscall: %d", num)
	}
	// 权限检查：低权限不能调用高权限 syscall
	if !caller.CanBypass(entry.Ring) && caller != entry.Ring {
		return Halt, &RingViolationError{
			Caller:    caller,
			Target:    entry.Ring,
			StageName: entry.Name,
		}
	}
	return entry.Handler(rc, args)
}

// Entries 返回所有已注册的 syscall（用于 /api/admin/kernel/syscalls 诊断端点）
func (t *SyscallTable) Entries() []SyscallEntry {
	entries := make([]SyscallEntry, 0, len(t.entries))
	for _, e := range t.entries {
		entries = append(entries, *e)
	}
	return entries
}
