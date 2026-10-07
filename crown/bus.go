package crown

import (
	"fmt"
	"sort"
	"sync"
)

// Module 是挂在冠环（Crown Bus）上的模块。
// 模块必须显式声明依赖（Deps 返回依赖的 ModuleID），由总线统一校验闭合、
// 拓扑排序后启停；模块之间不得私持引用或直接互调。
// Start 之外的常驻 goroutine 不允许；Stop 必须幂等。
type Module interface {
	ModuleID() string
	Deps() []string
	Start() error
	Stop()
}

// Bus 是模块注册表与生命周期管理器（冠环三原语之一：注册/启停；
// invoke/emit 总线事件在后续批次随审计域接入）。
type Bus struct {
	mu      sync.Mutex
	modules map[string]Module
	started []string // 已成功 Start 的模块，按启动顺序
}

// NewBus 构造空总线。
func NewBus() *Bus { return &Bus{modules: map[string]Module{}} }

// Register 注册模块。拒绝 nil、空 ID 与重复 ID。
func (b *Bus) Register(m Module) error {
	if m == nil {
		return fmt.Errorf("crown: register nil module")
	}
	id := m.ModuleID()
	if id == "" {
		return fmt.Errorf("crown: register module with empty id")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, dup := b.modules[id]; dup {
		return fmt.Errorf("crown: duplicate module id %q", id)
	}
	b.modules[id] = m
	return nil
}

// Module 返回已注册模块（未注册时 ok=false）。
func (b *Bus) Module(id string) (Module, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.modules[id]
	return m, ok
}

// IDs 返回已注册模块 ID 的排序快照（诊断/测试用）。
func (b *Bus) IDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ids := make([]string, 0, len(b.modules))
	for id := range b.modules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Validate 校验依赖闭合：引用的依赖必须已注册、不允许自依赖、不允许循环依赖。
func (b *Bus) Validate() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, m := range b.modules {
		for _, d := range m.Deps() {
			if d == id {
				return fmt.Errorf("crown: module %q depends on itself", id)
			}
			if _, ok := b.modules[d]; !ok {
				return fmt.Errorf("crown: module %q depends on unregistered module %q", id, d)
			}
		}
	}
	if _, err := topoOrder(b.modules); err != nil {
		return err
	}
	return nil
}

// StartAll 按依赖拓扑序启动全部模块（同级按 ID 字典序，保证确定性）。
// 任一模块 Start 失败：反向停止已启动模块（回滚），返回原始错误。
func (b *Bus) StartAll() error {
	b.mu.Lock()
	order, err := topoOrder(b.modules)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	modules := b.modules
	b.mu.Unlock()

	var started []string
	for _, id := range order {
		if err := modules[id].Start(); err != nil {
			for i := len(started) - 1; i >= 0; i-- {
				modules[started[i]].Stop()
			}
			return fmt.Errorf("crown: start module %q failed: %w", id, err)
		}
		started = append(started, id)
	}

	b.mu.Lock()
	b.started = started
	b.mu.Unlock()
	return nil
}

// StopAll 按启动逆序停止全部模块（幂等，可重复调用）。
func (b *Bus) StopAll() {
	b.mu.Lock()
	started := b.started
	modules := b.modules
	b.started = nil
	b.mu.Unlock()

	for i := len(started) - 1; i >= 0; i-- {
		if m, ok := modules[started[i]]; ok {
			m.Stop()
		}
	}
}

// Started 返回已启动模块顺序的快照（诊断/测试用）。
func (b *Bus) Started() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.started))
	copy(out, b.started)
	return out
}

// topoOrder 对模块做 Kahn 拓扑排序；同级按 ID 字典序保证确定性。
// 存在环时返回错误。调用方须持锁（只读 b）。
func topoOrder(modules map[string]Module) ([]string, error) {
	indeg := make(map[string]int, len(modules))
	dependents := make(map[string][]string, len(modules))
	for id, m := range modules {
		if _, ok := indeg[id]; !ok {
			indeg[id] = 0
		}
		for _, d := range m.Deps() {
			// 依赖合法性由 Validate 先行校验；此处对未注册依赖跳过以防裸调。
			if _, ok := modules[d]; !ok {
				continue
			}
			indeg[id]++
			dependents[d] = append(dependents[d], id)
		}
	}

	var ready []string
	for id, deg := range indeg {
		if deg == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)

	var order []string
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		order = append(order, id)
		var next []string
		for _, dep := range dependents[id] {
			indeg[dep]--
			if indeg[dep] == 0 {
				next = append(next, dep)
			}
		}
		sort.Strings(next)
		ready = append(ready, next...)
		sort.Strings(ready)
	}
	if len(order) != len(modules) {
		return nil, fmt.Errorf("crown: dependency cycle detected among modules")
	}
	return order, nil
}
