// Package kernel: Object Manager + Handle Table + Reference Counting
//
// 参考 NT 的内核对象管理器 (ObOpenObjectByName / ObReferenceObject)：
//   - 每个内核资源（配置快照、IP 封禁表、审计日志句柄等）是内核对象
//   - 通过 Handle 引用，句柄表管理引用计数
//   - 引用计数归零时回收（类比 NT 的 ObfDereferenceObject）
//   - 配置快照用 RCU：旧快照在所有引用归零后才回收
//
// 参考 RCU (McKenzie & Slingwine 1998)：快照发布 + 宽限期回收。

package kernel

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// ObjectType 内核对象类型
type ObjectType string

const (
	ObjConfigSnapshot ObjectType = "ConfigSnapshot"
	ObjIPBanEntry     ObjectType = "IPBanEntry"
	ObjAuditHandle    ObjectType = "AuditHandle"
	ObjRateLimitEntry ObjectType = "RateLimitEntry"
	ObjPoolBuffer     ObjectType = "PoolBuffer"
)

// KernelObject 内核对象（有类型、有引用计数、有句柄）
type KernelObject struct {
	Type      ObjectType
	Name      string
	Data      interface{}
	refCount  atomic.Int64
	createdAt int64 // Unix nano
}

// RefCount 返回当前引用计数
func (o *KernelObject) RefCount() int64 {
	return o.refCount.Load()
}

// Increment 引用计数 +1
func (o *KernelObject) Increment() {
	o.refCount.Add(1)
}

// Decrement 引用计数 -1，归零返回 true（可回收）
func (o *KernelObject) Decrement() bool {
	return o.refCount.Add(-1) <= 0
}

// Handle 内核句柄（类比 NT 的 HANDLE）
type Handle uint64

// InvalidHandle 无效句柄（类比 NT 的 NULL handle）
const InvalidHandle Handle = 0

// ObjectManager 内核对象管理器
// 类比 NT 的 ObCreateObject / ObOpenObjectByName / ObfDereferenceObject
type ObjectManager struct {
	mu     sync.RWMutex
	objects map[Handle]*KernelObject
	nextID  atomic.Uint64
}

// NewObjectManager 创建对象管理器
func NewObjectManager() *ObjectManager {
	return &ObjectManager{
		objects: make(map[Handle]*KernelObject),
	}
}

// Create 创建内核对象，返回句柄
// 类比 NT 的 ObCreateObject
func (m *ObjectManager) Create(objType ObjectType, name string, data interface{}) Handle {
	id := m.nextID.Add(1)
	if id == 0 {
		id = m.nextID.Add(1) // 跳过 0（InvalidHandle）
	}
	obj := &KernelObject{
		Type:      objType,
		Name:      name,
		Data:      data,
		createdAt: 0, // 设置在 RequestCtx.StartTime
	}
	obj.refCount.Store(1) // 创建者持有一个引用
	m.mu.Lock()
	m.objects[Handle(id)] = obj
	m.mu.Unlock()
	return Handle(id)
}

// Reference 通过句柄引用对象（引用计数 +1）
// 类比 NT 的 ObReferenceObjectByHandle
func (m *ObjectManager) Reference(h Handle) (*KernelObject, error) {
	m.mu.RLock()
	obj, ok := m.objects[h]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("invalid handle: %d", h)
	}
	obj.Increment()
	return obj, nil
}

// Dereference 解除引用（引用计数 -1，归零时回收）
// 类比 NT 的 ObfDereferenceObject
// 配合 RCU：配置快照在所有引用归零后延迟回收
func (m *ObjectManager) Dereference(h Handle) {
	m.mu.RLock()
	obj, ok := m.objects[h]
	m.mu.RUnlock()
	if !ok {
		return
	}
	if obj.Decrement() {
		// 引用归零：从表中移除并回收
		// （对配置快照，这里是 RCU 的宽限期结束点）
		m.mu.Lock()
		// 双检（防止竞态：另一个 goroutine 可能在我们拿写锁前又引用了它）
		if obj.RefCount() <= 0 {
			delete(m.objects, h)
		}
		m.mu.Unlock()
	}
}

// Get 直接获取对象（不增加引用计数，用于只读访问）
func (m *ObjectManager) Get(h Handle) (*KernelObject, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[h]
	return obj, ok
}

// Count 返回当前活跃对象数（用于诊断端点）
func (m *ObjectManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objects)
}

// ListByType 返回指定类型的所有对象（用于诊断）
func (m *ObjectManager) ListByType(objType ObjectType) []*KernelObject {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*KernelObject
	for _, obj := range m.objects {
		if obj.Type == objType {
			result = append(result, obj)
		}
	}
	return result
}
