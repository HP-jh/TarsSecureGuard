// realtime.go — 实时监控（目：Ordo-RealtimeMonitor）
// 基于eBPF/ETW的轻量行为监控骨架（当前为兼容层，实际探针按需加载）
package realtime

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Event 实时监控事件
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`      // file/network/process/dns
	Action    string    `json:"action"`    // read/write/connect/exec/resolve
	Target    string    `json:"target"`    // 文件路径/URL/进程名/域名
	PID       int       `json:"pid"`
	UID       string    `json:"uid"`
	RiskScore int       `json:"risk_score"`
}

// Monitor 实时监控器
type Monitor struct {
	enabled  atomic.Bool
	mu       sync.RWMutex
	events   []Event
	maxEvents int
	handlers []func(Event)
}

// NewMonitor 创建监控器
func NewMonitor() *Monitor {
	m := &Monitor{maxEvents: 10000}
	m.enabled.Store(true)
	return m
}

// Start 启动监控（当前为轮询模拟，实际可替换为eBPF加载）
func (m *Monitor) Start(ctx context.Context) error {
	go m.loop(ctx)
	return nil
}

// Stop 停止监控
func (m *Monitor) Stop(ctx context.Context) error {
	m.enabled.Store(false)
	return nil
}

func (m *Monitor) loop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !m.enabled.Load() {
				return
			}
			m.poll()
		}
	}
}

// poll 轮询检测点（占位，实际接入系统探针）
func (m *Monitor) poll() {
	// 占位：实际实现中此处接入eBPF ring buffer 或 ETW事件流
}

// Record 手动记录事件（用于上层模块上报）
func (m *Monitor) Record(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	if len(m.events) > m.maxEvents {
		m.events = m.events[len(m.events)-m.maxEvents:]
	}
	for _, h := range m.handlers {
		go h(e)
	}
}

// Events 返回最近N条事件
func (m *Monitor) Events(n int) []Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n > len(m.events) {
		n = len(m.events)
	}
	result := make([]Event, n)
	copy(result, m.events[len(m.events)-n:])
	return result
}

// OnEvent 注册事件处理器
func (m *Monitor) OnEvent(fn func(Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, fn)
}

// Stats 返回统计摘要
func (m *Monitor) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	counts := map[string]int{"file": 0, "network": 0, "process": 0, "dns": 0}
	for _, e := range m.events {
		counts[e.Type]++
	}
	return map[string]interface{}{
		"enabled":     m.enabled.Load(),
		"total":       len(m.events),
		"by_type":     counts,
		"max_events":  m.maxEvents,
	}
}
