// Package kernel 实现 TarsSecureGuard 的内核层。
//
// v5.1 内核化重构：将安全网关视为操作系统内核来设计。
//
// 架构分层（参考 OS kernel 设计 + 腾讯 MT 组件化模型）：
//
//	┌─────────────────────────────────────────────────┐
//	│  User Space (handlers: chat, models, tools, admin) │
//	│                    ↕ syscall                      │
//	├─────────────────────────────────────────────────┯
//	│  Kernel Space                                     │
//	│  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
//	│  │ Scheduler │  │ Security │  │  Config  │        │
//	│  │ (IRP生命周期)│  │Subsystem │  │  Store   │        │
//	│  └──────────┘  └──────────┘  └──────────┘        │
//	│  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
//	│  │ Memory Mgr│  │Identity  │  │Observ.   │        │
//	│  │ (pool/buf) │  │(RBAC/Quota)│ │(metrics) │        │
//	│  └──────────┘  └──────────┘  └──────────┘        │
//	└─────────────────────────────────────────────────┘
//
// 核心概念：
//   - Request 是"进程"：有 PID(TraceID)、上下文(RequestCtx)、资源限制、生命周期
//   - 安全检查是"内核态"：不可绕过，Stage 结果只允许 Continue/Halt/Skip
//   - Handler 是"用户态"：通过 syscall 接口获取内核服务
//   - Config 是"内核状态"：RCU 快照发布，请求路径零锁读
//
// 参考来源：
//   - Microsoft Learn IRP / I/O Stack Location：请求对象化、每层上下文
//   - SEDA (SOSP 2001)：Stage + 有界队列 + 自适应降载
//   - LLVM PassManager (CGO 2004)：Stage 是纯变换、可独立开关
//   - Envoy threading model：main thread 管配置/统计，worker 不碰 IO
//   - CloudWeGo netpoll：主从 Reactor、一连接一 goroutine 的成本
//   - RCU (McKenzie & Slingwine 1998)：快照发布 + 宽限期回收
package kernel

import (
	"context"
	"net/http"
	"time"
)

// ===================== 内核核心类型 =====================

// Kernel 是内核入口，持有所有子系统的引用。
// 由 main.go 在启动时构造（Boot），贯穿整个进程生命周期。
type Kernel struct {
	Scheduler   *Scheduler
	Security    *SecuritySubsystem
	ConfigStore *ConfigStore
	Memory      *MemoryManager
	Identity    *IdentitySubsystem
	Observer    *Observer
	bootTime    time.Time
}

// NewKernel 创建内核实例（各子系统由 main.go 注入具体实现）
func NewKernel() *Kernel {
	return &Kernel{
		bootTime: time.Now(),
	}
}

// Boot 内核启动序列（类比 OS boot）：
// 1. 初始化配置存储
// 2. 启动安全子系统
// 3. 启动调度器
// 4. 启动内存管理器
// 5. 启动观测层
func (k *Kernel) Boot() error {
	if k.ConfigStore != nil {
		k.ConfigStore.Start()
	}
	if k.Security != nil {
		k.Security.Start()
	}
	if k.Scheduler != nil {
		k.Scheduler.Start()
	}
	if k.Memory != nil {
		k.Memory.Start()
	}
	if k.Observer != nil {
		k.Observer.Start()
	}
	return nil
}

// Shutdown 内核关闭序列（类比 OS shutdown）：逆序停止
func (k *Kernel) Shutdown() {
	if k.Observer != nil {
		k.Observer.Stop()
	}
	if k.Memory != nil {
		k.Memory.Stop()
	}
	if k.Scheduler != nil {
		k.Scheduler.Stop()
	}
	if k.Security != nil {
		k.Security.Stop()
	}
	if k.ConfigStore != nil {
		k.ConfigStore.Stop()
	}
}

// Uptime 内核运行时长
func (k *Kernel) Uptime() time.Duration {
	return time.Since(k.bootTime)
}

// ===================== 请求上下文 (IRP) =====================

// RequestCtx 是贯穿整个请求生命周期的自包含对象。
// 参考 Microsoft IRP / I/O Stack Location：每层拥有自己的上下文，
// 生命周期由 Scheduler 统一管理（超时/取消/buffer 回收）。
type RequestCtx struct {
	// 请求标识（类比进程 PID）
	TraceID   string
	ConnID    string
	StartTime time.Time

	// 请求数据（只读快照，由调度器填充）
	Method   string
	Path     string
	Header   http.Header
	Body     []byte
	RemoteIP string
	Deadline time.Time

	// 认证结果（由 Identity 子系统填充）
	Authed   bool
	UserID   string
	TenantID string
	Role     string
	Groups   []string

	// 安全检测结果（由 Security 子系统各 Stage 填充）
	WAFHit       string
	SemanticHit  string
	RateLimitHit bool
	IPBanned     bool
	PIIFound     bool
	IPReputation int

	// 路由决策
	Backend  string
	Model    string
	Explored bool

	// Per-Connection Context（同一条 keep-alive 连接上只算一次）
	TLSState string

	// 执行指标（每 Stage 的耗时和结果）
	Stages []StageMetric
}

// StageMetric 单个阶段执行指标
type StageMetric struct {
	Name     string
	Duration time.Duration
	Result   StageResult
	Error    string
}

// StageResult 阶段处理结果（硬约束：只允许 Continue/Halt/Skip）
type StageResult int

const (
	Continue StageResult = iota // 继续执行下一阶段
	Halt                        // 终止管道（已写入响应）
	Skip                        // 跳过当前阶段
)

// ===================== Stage 接口 =====================

// Stage 是内核管道中的一个处理阶段。
// 参考 LLVM PassManager (CGO 2004)：Stage 是纯变换、可独立开关与 profile。
// 参考 SEDA (SOSP 2001)：每个 Stage 是独立的有界处理单元。
type Stage interface {
	// Name 阶段名称（用于审计和观测）
	Name() string
	// Execute 执行阶段逻辑
	// 通过 w 写入响应时应返回 Halt
	Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult
}

// StageFunc 函数适配器
type StageFunc struct {
	StageName string
	Fn        func(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult
}

func (s StageFunc) Name() string { return s.StageName }
func (s StageFunc) Execute(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Fn(ctx, rc, w, r)
}

// ===================== 子系统接口 =====================

// SecurityModule 安全模块接口（WAF/SSRF/Audit/PII/CSP 各实现一个）
// 每个模块是内核态的独立组件，有明确的版本和开关边界。
type SecurityModule interface {
	Name() string
	Version() string
	// Check 执行安全检查，返回 Continue（放行）或 Halt（拦截）
	Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult
}

// ConfigSnapshoter 配置快照接口（RCU 模式）
// 控制面构造不可变快照 → atomic 发布 → 请求路径零锁读
type ConfigSnapshoter interface {
	// Snapshot 返回当前配置的只读快照
	Snapshot() interface{}
	// Refresh 控制面刷新快照（热重载后调用）
	Refresh()
}
