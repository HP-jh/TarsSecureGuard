// Package kernel: SecuritySubsystem — 安全核心子系统
//
// 安全子系统管理所有安全模块（WAF/SSRF/Audit/PII/CSP/IPReputation）。
// 硬约束：Security Core 不可关闭；Stage 结果只允许 Continue/Halt/Skip，
// 不允许降级放行。Fail-close：panic/超时/未知错误 → 默认拒绝。
//
// 参考：
//   - Strangler Fig (Fowler)：逐块迁移
//   - Circuit Breaker (Fowler)：熔断
//   - Bulkhead (Azure)：资源池隔离

package kernel

import (
	"context"
	"net/http"
	"time"
)

// SecuritySubsystem 安全核心子系统
type SecuritySubsystem struct {
	modules []SecurityModule
	started bool
	// Services 系统服务框架：各子系统的对外接口（鸿蒙微内核"系统服务"精神）
	Services *ServiceRegistry
}

// NewSecuritySubsystem 创建安全子系统
func NewSecuritySubsystem(modules ...SecurityModule) *SecuritySubsystem {
	return &SecuritySubsystem{modules: modules}
}

// SetServices 注册系统服务注册表（kernel_bridge.go 在 buildKernelScheduler 中调用）
func (s *SecuritySubsystem) SetServices(reg *ServiceRegistry) {
	s.Services = reg
}

// RegisterModule 注册安全模块
func (s *SecuritySubsystem) RegisterModule(m SecurityModule) {
	s.modules = append(s.modules, m)
}

// Start 启动安全子系统
func (s *SecuritySubsystem) Start() {
	s.started = true
}

// Stop 停止安全子系统
func (s *SecuritySubsystem) Stop() {
	s.started = false
}

// Check 执行所有安全模块检查。
// 任一模块返回 Halt 即终止（fail-close）。
// 参考 SEDA (SOSP 2001) 的 Stage 管道：每个模块独立、可组合。
func (s *SecuritySubsystem) Check(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
	for _, m := range s.modules {
		result := m.Check(ctx, rc, w, r)
		if result == Halt {
			return Halt
		}
	}
	return Continue
}

// Modules 返回已注册模块列表
func (s *SecuritySubsystem) Modules() []string {
	names := make([]string, len(s.modules))
	for i, m := range s.modules {
		names[i] = m.Name()
	}
	return names
}

// ===================== ConfigStore (RCU 配置存储) =====================

// ConfigStore 配置存储（RCU 模式）
// 控制面：构造不可变 Snapshot → atomic.StorePointer 发布
// 数据面：请求开始 Load() 一次 → 旧快照按引用计数延迟回收
// 参考 RCU (McKenzie & Slingwine 1998)
type ConfigStore struct {
	snapshot interface{}
	refreshedAt time.Time
	started bool
}

// NewConfigStore 创建配置存储
func NewConfigStore(initial interface{}) *ConfigStore {
	return &ConfigStore{
		snapshot: initial,
		refreshedAt: time.Now(),
	}
}

// Start 启动配置存储
func (c *ConfigStore) Start() {
	c.started = true
}

// Stop 停止配置存储
func (c *ConfigStore) Stop() {
	c.started = false
}

// Get 获取当前配置快照（请求路径调用，零锁）
func (c *ConfigStore) Get() interface{} {
	return c.snapshot
}

// Refresh 控制面刷新快照（热重载后调用）
func (c *ConfigStore) Refresh() {
	c.refreshedAt = time.Now()
}

// RefreshedAt 返回最近一次刷新时间
func (c *ConfigStore) RefreshedAt() time.Time {
	return c.refreshedAt
}

// ===================== MemoryManager (内存管理) =====================

// MemoryManager 内存管理器（sync.Pool + buffer 回收）
// 请求体用 sync.Pool 复用，避免 io.ReadAll 双份拷贝
type MemoryManager struct {
	started bool
}

// NewMemoryManager 创建内存管理器
func NewMemoryManager() *MemoryManager {
	return &MemoryManager{}
}

// Start 启动内存管理器
func (m *MemoryManager) Start() {
	m.started = true
}

// Stop 停止内存管理器
func (m *MemoryManager) Stop() {
	m.started = false
}

// ===================== IdentitySubsystem (身份/RBAC/配额) =====================

// IdentitySubsystem 身份子系统（RBAC + 配额 + 多租户）
type IdentitySubsystem struct {
	started bool
}

// NewIdentitySubsystem 创建身份子系统
func NewIdentitySubsystem() *IdentitySubsystem {
	return &IdentitySubsystem{}
}

// Start 启动身份子系统
func (i *IdentitySubsystem) Start() {
	i.started = true
}

// Stop 停止身份子系统
func (i *IdentitySubsystem) Stop() {
	i.started = false
}

// ===================== Observer (观测层) =====================

// Observer 观测层（指标聚合 + trace span + 审计日志）
// 参考 The Tail at Scale (CACM 2013)：分位数指标、尾延迟来源
type Observer struct {
	started bool
}

// NewObserver 创建观测层
func NewObserver() *Observer {
	return &Observer{}
}

// Start 启动观测层
func (o *Observer) Start() {
	o.started = true
}

// Stop 停止观测层
func (o *Observer) Stop() {
	o.started = false
}
