// Package kernel: Gecko Engine mechanisms — Dirty bits, Content Sink, Reflow
//
// 参考 Gecko (Firefox) 引擎的工程哲学：
//   - Dirty Bits + Incremental Reflow：配置变更只标记受影响的 Stage dirty，
//     只重跑 dirty Stage，不全量重跑管道（类比 Gecko 的增量 reflow）
//   - Content Sink：增量推送安全检查结果（不等管道跑完再吐结果）
//   - Frame Construction：每个安全模块映射到 Frame 对象，
//     可独立销毁/重建（类比 Gecko 的 frame construction）
//
// 来源：Gecko source on GitHub (https://github.com/nicolo-ribaudo/tc39-proposal-structs)
// 以及 Mozilla Wiki "Gecko" 页面。

package kernel

import (
	"sync"
	"sync/atomic"
	"time"
)

// ===================== Dirty Bits + Incremental Reflow =====================
//
// Gecko 的 Incremental Reflow：DOM 变更只标记受影响的 subtree dirty，
// 下次 reflow 只处理 dirty subtree。我们的对应：
//   - 配置热重载时，只标记受影响的 Stage 为 dirty
//   - 下次请求只重跑 dirty Stage（其他 Stage 用缓存的 result）
//   - dirty Stage 执行完后清除 dirty bit

// DirtyTracker 追踪 Stage 的 dirty 状态
type DirtyTracker struct {
	mu     sync.RWMutex
	dirty  map[string]bool       // stageName → dirty
	lastReflow time.Time          // 上次 reflow 时间
	reflowCount atomic.Int64      // 总 reflow 次数
}

// NewDirtyTracker 创建 dirty tracker
func NewDirtyTracker() *DirtyTracker {
	return &DirtyTracker{
		dirty: make(map[string]bool),
	}
}

// MarkDirty 标记 Stage 为 dirty（配置变更时调用）
func (d *DirtyTracker) MarkDirty(stageName string) {
	d.mu.Lock()
	d.dirty[stageName] = true
	d.mu.Unlock()
}

// MarkAllDirty 标记所有 Stage 为 dirty（全量热重载时调用）
func (d *DirtyTracker) MarkAllDirty(stageNames []string) {
	d.mu.Lock()
	for _, name := range stageNames {
		d.dirty[name] = true
	}
	d.mu.Unlock()
}

// IsDirty 检查 Stage 是否 dirty
func (d *DirtyTracker) IsDirty(stageName string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.dirty[stageName]
}

// ClearDirty 清除 Stage 的 dirty 标记（Stage 执行完后调用）
func (d *DirtyTracker) ClearDirty(stageName string) {
	d.mu.Lock()
	delete(d.dirty, stageName)
	d.mu.Unlock()
}

// Reflow 执行增量 reflow：返回需要重跑的 Stage 列表，并清除 dirty 标记
// 类比 Gecko 的 ProcessReflowCommands：只处理 dirty 的 subtree
func (d *DirtyTracker) Reflow(allStages []string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var dirty []string
	for _, name := range allStages {
		if d.dirty[name] {
			dirty = append(dirty, name)
			delete(d.dirty, name) // 清除 dirty 标记（类比 Gecko 的 clear dirty bits）
		}
	}
	d.lastReflow = time.Now()
	d.reflowCount.Add(1)
	return dirty
}

// ReflowCount 返回总 reflow 次数
func (d *DirtyTracker) ReflowCount() int64 {
	return d.reflowCount.Load()
}

// ===================== Content Sink (增量推送) =====================
//
// Gecko 的 ContentSink：SAX 解析器边解析边构建 DOM，不攒着全部内容再处理。
// 我们的对应：安全检查可以增量推送结果（如 WAF 拦截后立即写 HTTP 403，
// 不等管道跑完）。ContentSink 是结果推送的统一接口。

// ContentSink 内容接收器（增量推送）
// 每个 Stage 可以通过 ContentSink 向客户端增量推送数据
// （类比 Gecko 的 nsIContentSink / ProcessContentSink）
type ContentSink interface {
	// OnStageResult 某个 Stage 完成时的回调
	OnStageResult(stageName string, result StageResult, rc *RequestCtx)
	// OnWAFHit WAF 命中时推送（增量，不等管道跑完）
	OnWAFHit(rc *RequestCtx, rule string)
	// OnAuthResult 鉴权结果推送
	OnAuthResult(rc *RequestCtx, authed bool, userID string)
	// OnComplete 管道完成时推送
	OnComplete(rc *RequestCtx, halted bool)
}

// NoopSink 空实现（默认）
type NoopSink struct{}

func (NoopSink) OnStageResult(string, StageResult, *RequestCtx)     {}
func (NoopSink) OnWAFHit(*RequestCtx, string)                       {}
func (NoopSink) OnAuthResult(*RequestCtx, bool, string)             {}
func (NoopSink) OnComplete(*RequestCtx, bool)                        {}

// ===================== Frame Construction (帧构造) =====================
//
// Gecko 的 Frame Construction：DOM 节点 → Frame 对象（每个 Frame 是独立的
// 渲染单元）。我们的对应：每个安全模块是一个 Frame，可以独立销毁/重建。
// 配置变更时，只重建 dirty Frame，不重建整个管道。

// Frame 一个安全模块的帧对象
type Frame struct {
	Name       string
	Version    string
	Ring       ProtectionRing
	Dirty      bool
	BuiltAt    time.Time
	RebuildCount int
}

// FrameManager 帧管理器
type FrameManager struct {
	frames map[string]*Frame
	mu     sync.RWMutex
}

// NewFrameManager 创建帧管理器
func NewFrameManager() *FrameManager {
	return &FrameManager{
		frames: make(map[string]*Frame),
	}
}

// BuildFrame 构建一个 Frame（首次注册或重建）
func (m *FrameManager) BuildFrame(name, version string, ring ProtectionRing) *Frame {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.frames[name]
	if !ok {
		f = &Frame{Name: name, Version: version, Ring: ring}
		m.frames[name] = f
	}
	f.Dirty = false
	f.BuiltAt = time.Now()
	f.RebuildCount++
	return f
}

// MarkFrameDirty 标记 Frame 为 dirty（需要重建）
func (m *FrameManager) MarkFrameDirty(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.frames[name]; ok {
		f.Dirty = true
	}
}

// RebuildDirty 重建所有 dirty Frame（返回重建的 Frame 列表）
func (m *FrameManager) RebuildDirty() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rebuilt []string
	for name, f := range m.frames {
		if f.Dirty {
			f.Dirty = false
			f.BuiltAt = time.Now()
			f.RebuildCount++
			rebuilt = append(rebuilt, name)
		}
	}
	return rebuilt
}

// Frames 返回所有 Frame 信息（用于诊断端点）
func (m *FrameManager) Frames() []Frame {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Frame, 0, len(m.frames))
	for _, f := range m.frames {
		result = append(result, *f)
	}
	return result
}
