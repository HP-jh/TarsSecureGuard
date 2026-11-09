// Package pipeline 实现请求处理管道（参考阿里巴巴编译架构 + 腾讯 NT 管道模式）
//
// 核心思想：将 gatewayMiddleware 的线性硬编码拆分为可组合、可配置的处理管道。
// 每个阶段（Stage）职责单一，通过 Pipeline 组合，支持：
//   - 阶段跳过（按配置或运行时条件）
//   - 阶段短路（任一阶段可终止管道）
//   - 观测埋点（每个阶段自动记录耗时和结果）
//   - 故障隔离（单阶段 panic 不影响其他阶段）
//
// 设计参考：
//   - 腾讯 NT 架构：消息管道的 stage 模式
//   - 字节双线程模型：UI/Logic 分离的安全边界
//   - 阿里巴巴编译器：IR Pass 管道（每 pass 独立、可组合、可观测）

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
// 参考：字节双线程模型的共享状态设计
type RequestContext struct {
	// 请求元数据
	TraceID   string
	ClientIP  string
	UserAgent string
	StartTime time.Time

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
