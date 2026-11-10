// Package pipeline 实现请求处理管道
//
// v5.1 重构：参考腾讯 MT 架构的管道设计（参考 CloudWeGo netpoll 主从 Reactor 模型），
// 结合 Microsoft IRP / I/O Stack Location 的请求对象化思想：
//   - 请求是自包含对象（RequestContext），每层拥有自己的上下文
//   - 生命周期由调度器统一管理（超时/取消/buffer 回收）
//   - Per-Connection Context：限流/TLS 状态/IP 信誉在同一条 keep-alive 连接上只算一次
//   - ctx 取消传播：客户端断开 → 立刻回收 buffer、取消上游
//
// 参考：
//   - Microsoft Learn IRP / I/O Stack Location：请求对象化、每层上下文
//   - SEDA (SOSP 2001)：Stage + 有界队列 + 自适应降载
//   - LLVM PassManager (CGO 2004)：Stage 是纯变换、可独立开关与 profile
//   - Envoy threading model：main thread 管配置/统计，worker 各自 event loop

package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// StageResult 表示单个阶段的处理结果
type StageResult int

const (
	// Continue 继续执行下一阶段
	Continue StageResult = iota
	// Halt 终止管道（已写入响应，不再执行后续阶段）
	Halt
	// Skip 跳过当前阶段（不计入审计，用于条件性旁路）
	Skip
)

// RequestContext 贯穿整个管道的请求上下文（避免 context.Value 滥用）
// v5.1 §3.1 参考 Microsoft IRP / I/O Stack Location：
// 请求是自包含对象，每层拥有自己的上下文，生命周期由调度器统一管理。
// 参考：腾讯 MT 架构的连接级上下文复用设计。
type RequestContext struct {
	// 请求元数据（IRP: I/O Stack Location 层级信息）
	TraceID   string
	ClientIP  string
	UserAgent string
	StartTime time.Time

	// v5.1 §3.1 IRP 扩展：请求自包含对象
	Method   string
	Path     string
	Header   http.Header // 请求头快照（只读）
	Body     []byte      // 请求体快照（只读，已 pool 化）
	Identity string      // 认证身份
	Snapshot interface{} // 配置快照（RCU 模式的不可变快照）
	Action   string      // 请求动作（如 "chat", "tool_call", "admin"）
	Deadline time.Time   // 请求截止时间（超时/取消由调度器管理）

	// Per-Connection Context（§3.1：限流/TLS 状态/IP 信誉在同一连接上只算一次）
	ConnID       string // 连接唯一标识
	TLSState     string // TLS 状态（"tls", "plain"）
	IPReputation int    // IP 信誉分（0-100）

	// 鉴权结果（由 AuthStage 填充）
	Authed   bool
	UserID   string
	TenantID string
	Role     string
	Groups   []string

	// 安全检测结果（由 SecurityStages 填充）
	WAFHit       string // WAF 命中规则名（空 = 未命中）
	SemanticHit  string // 语义检测命中
	RateLimitHit bool   // 限流命中
	IPBanned     bool   // IP 被封禁
	PIIFound     bool   // 发现 PII

	// 路由决策（由 RouterStage 填充）
	Backend  string
	Model    string
	Explored bool

	// 观测数据
	Stages []StageMetric
}

// StageMetric 记录单个阶段的执行指标
type StageMetric struct {
	Name     string
	Duration time.Duration
	Result   StageResult
	Error    string
}

// Stage 是管道中的一个处理阶段
type Stage interface {
	// Name 返回阶段名称（用于日志和观测）
	Name() string
	// Execute 执行阶段逻辑，返回结果
	// 实现者通过 w 写入响应时应返回 Halt
	Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult
}

// StageFunc 是 Stage 接口的函数适配器
type StageFunc struct {
	StageName string
	Fn        func(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult
}

func (s StageFunc) Name() string { return s.StageName }
func (s StageFunc) Execute(ctx context.Context, rc *RequestContext, w http.ResponseWriter, r *http.Request) StageResult {
	return s.Fn(ctx, rc, w, r)
}

// Pipeline 是有序的处理阶段管道
type Pipeline struct {
	stages   []Stage
	mu       sync.RWMutex
	observer Observer // 可选的观测器
}

// Observer 管道观测接口（Prometheus 指标 / 审计日志 / trace span）
type Observer interface {
	OnStageStart(stage string, rc *RequestContext)
	OnStageEnd(stage string, rc *RequestContext, result StageResult, duration time.Duration)
	OnPipelineComplete(rc *RequestContext, halted bool)
}

// New 创建新的管道
func New(stages ...Stage) *Pipeline {
	return &Pipeline{stages: stages}
}

// WithObserver 设置观测器
func (p *Pipeline) WithObserver(obs Observer) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observer = obs
	return p
}

// AddStage 追加阶段到管道末尾
func (p *Pipeline) AddStage(s Stage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stages = append(p.stages, s)
}

// InsertStageBefore 在指定阶段之前插入新阶段
func (p *Pipeline) InsertStageBefore(name string, s Stage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, existing := range p.stages {
		if existing.Name() == name {
			p.stages = append(p.stages[:i], append([]Stage{s}, p.stages[i:]...)...)
			return nil
		}
	}
	return fmt.Errorf("stage %q not found", name)
}

// Execute 执行管道（参考阿里巴巴编译器的 Pass Manager）
// 每个阶段独立 recover，单阶段 panic 不影响其他阶段和主进程
func (p *Pipeline) Execute(w http.ResponseWriter, r *http.Request, rc *RequestContext) (halted bool) {
	p.mu.RLock()
	stages := make([]Stage, len(p.stages))
	copy(stages, p.stages)
	obs := p.observer
	p.mu.RUnlock()

	for _, stage := range stages {
		result := p.executeStage(stage, w, r, rc, obs)
		if result == Halt {
			if obs != nil {
				obs.OnPipelineComplete(rc, true)
			}
			return true
		}
	}

	if obs != nil {
		obs.OnPipelineComplete(rc, false)
	}
	return false
}

// executeStage 执行单个阶段，包含 panic recovery 和观测埋点
func (p *Pipeline) executeStage(s Stage, w http.ResponseWriter, r *http.Request, rc *RequestContext, obs Observer) (result StageResult) {
	stageName := s.Name()

	if obs != nil {
		obs.OnStageStart(stageName, rc)
	}

	start := time.Now()
	defer func() {
		duration := time.Since(start)
		if rec := recover(); rec != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			result = Halt
			rc.Stages = append(rc.Stages, StageMetric{
				Name:     stageName,
				Duration: duration,
				Result:   Halt,
				Error:    fmt.Sprintf("PANIC: %v\n%s", rec, buf[:n]),
			})
			if obs != nil {
				obs.OnStageEnd(stageName, rc, Halt, duration)
			}
		} else {
			rc.Stages = append(rc.Stages, StageMetric{
				Name:     stageName,
				Duration: duration,
				Result:   result,
			})
			if obs != nil {
				obs.OnStageEnd(stageName, rc, result, duration)
			}
		}
	}()

	return s.Execute(r.Context(), rc, w, r)
}

// Stages 返回当前阶段列表（只读快照，用于调试/管理端点）
func (p *Pipeline) Stages() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, len(p.stages))
	for i, s := range p.stages {
		names[i] = s.Name()
	}
	return names
}

// Len 返回阶段数量
func (p *Pipeline) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.stages)
}
