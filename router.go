package main

// v3.0.0 C 线：两阶段智能路由（smartRouter 模块）
//
// 设计依据：架构方案第三节 C 线 + 锦衣卫附加意见 D：
//   - 阶段一：静态规则路由（现有 routeChat，确定性、可预测，永远兜底）
//   - 阶段二：ε-greedy bandit —— 仅当多个后端同时可达时，按探索率 ε 随机换选，
//     否则选历史加权奖励最优者；ε 从 0.1 衰减至 0.02
//   - 奖励函数：成功 1/(1+latency_s)，失败 -1；单次调用即反馈
//   - 防伪造（附加意见 D）：非 admin 用户的结果反馈权重 ×0.1，
//     防止刷评分操纵路由；route_preview 仅 admin
//   - 状态持久化 state/router.json，重启不丢；Python lm-eval 边车按需（Tier 2，不捆绑）

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ===================== 状态 =====================

type rtArm struct {
	Calls     uint64  `json:"calls"`
	Successes uint64  `json:"successes"`
	Failures  uint64  `json:"failures"`
	RewSum    float64 `json:"rewSum"` // 加权奖励和
	AvgLatMs  float64 `json:"avgLatMs"`
}

type rtState struct {
	Arms      map[string]*rtArm `json:"arms"`
	Decisions uint64            `json:"decisions"`
	Epsilon   float64           `json:"epsilon"`
}

var (
	rtMu    sync.Mutex
	rtSt    = rtState{Arms: map[string]*rtArm{}, Epsilon: 0.1}
	rtRng   = rand.New(rand.NewSource(time.Now().UnixNano()))
)

const rtStateFile = "state/router.json"

// ===================== 配置 =====================

func rtEnabled() bool {
	c := v3Config()
	if c.Router.Enabled != nil {
		return *c.Router.Enabled && moduleEnabledByID("smartRouter")
	}
	return moduleEnabledByID("smartRouter")
}

func rtEpsilonBounds() (start, min float64) {
	c := v3Config()
	start, min = 0.1, 0.02
	if c.Router.EpsilonStart > 0 && c.Router.EpsilonStart <= 1 {
		start = c.Router.EpsilonStart
	}
	if c.Router.EpsilonMin > 0 && c.Router.EpsilonMin <= start {
		min = c.Router.EpsilonMin
	}
	return
}

// ===================== 持久化 =====================

func rtSave() {
	rtMu.Lock()
	defer rtMu.Unlock()
	_ = os.MkdirAll(filepath.Dir(rtStateFile), 0o755)
	b, _ := json.Marshal(rtSt)
	_ = os.WriteFile(rtStateFile, b, 0o600)
}

func rtLoad() {
	rtMu.Lock()
	defer rtMu.Unlock()
	b, err := os.ReadFile(rtStateFile)
	if err != nil {
		return
	}
	var st rtState
	if json.Unmarshal(b, &st) == nil && st.Arms != nil {
		rtSt = st
		start, min := rtEpsilonBounds()
		if rtSt.Epsilon <= 0 || rtSt.Epsilon > start {
			rtSt.Epsilon = start
		}
		if rtSt.Epsilon < min {
			rtSt.Epsilon = min
		}
	}
}

// ===================== 候选与选择 =====================

// rtCandidates 返回当前可达的后端候选（静态路由的自动分支同源判定）
func rtCandidates() []string {
	var out []string
	if running, _ := modelState(); running {
		out = append(out, "llama")
	}
	if lmsReachable() {
		out = append(out, "lmstudio")
	}
	if ollamaReachable() {
		out = append(out, "ollama")
	}
	return out
}

// rtPick 两阶段选择：返回 (backend, explored)。candidates 由调用方给定。
func rtPick(candidates []string) (string, bool) {
	rtMu.Lock()
	defer rtMu.Unlock()
	if len(candidates) == 0 {
		return "", false
	}
	if len(candidates) == 1 {
		return candidates[0], false
	}
	_, minEps := rtEpsilonBounds()
	// ε 衰减：每次决策 ×0.995，下限 minEps
	if rtSt.Epsilon > minEps {
		rtSt.Epsilon *= 0.995
		if rtSt.Epsilon < minEps {
			rtSt.Epsilon = minEps
		}
	}
	rtSt.Decisions++
	if rtRng.Float64() < rtSt.Epsilon {
		// 探索：随机候选
		return candidates[rtRng.Intn(len(candidates))], true
	}
	// 利用：加权平均奖励最高（无样本的候选给 0.5 先验，鼓励冷启动探索）
	best, bestScore := "", -1e9
	for _, c := range candidates {
		arm := rtSt.Arms[c]
		score := 0.5
		if arm != nil && arm.Calls > 0 {
			score = arm.RewSum / float64(arm.Calls)
			// 成功率极低的候选直接跳过（<20% 且样本 ≥5）
			if arm.Calls >= 5 && float64(arm.Successes)/float64(arm.Calls) < 0.2 {
				score -= 10
			}
		}
		if score > bestScore {
			best, bestScore = c, score
		}
	}
	return best, false
}

// ===================== 反馈（防伪造） =====================

// rtRecordOutcome 记录一次路由结果。role 非 admin 权重 ×0.1（锦衣卫附加意见 D）。
func rtRecordOutcome(backend string, ok bool, latency time.Duration, role string) {
	rtMu.Lock()
	arm, exists := rtSt.Arms[backend]
	if !exists {
		arm = &rtArm{}
		rtSt.Arms[backend] = arm
	}
	weight := 1.0
	if role != "admin" {
		weight = 0.1 // 防伪造：非 admin 反馈降权
	}
	var rew float64
	if ok {
		rew = 1.0 / (1.0 + latency.Seconds())
	} else {
		rew = -1.0
	}
	arm.Calls++
	if ok {
		arm.Successes++
		arm.AvgLatMs = (arm.AvgLatMs*float64(arm.Successes-1) + float64(latency.Milliseconds())) / float64(arm.Successes)
	} else {
		arm.Failures++
	}
	arm.RewSum += rew * weight
	rtMu.Unlock()
}

// ===================== chat 链路集成 =====================

// routeChatSmart 两阶段路由包装：handleChat 的调用入口。
// 仅当静态路由命中"自动选择"分支且多后端可达时，叠加 bandit 决策；
// 显式指定 backend 前缀（lmstudio/ xxx）的请求完全走静态，不做探索。
func routeChatSmart(model string, msgs []Message, role string) (string, string, bool, error) {
	isAuto := model == "" || model == "auto" || model == "local" || model == "cloud-default"
	if !rtEnabled() || !isAuto {
		content, backend, err := routeChat(model, msgs)
		return content, backend, false, err
	}
	cands := rtCandidates()
	if len(cands) <= 1 {
		// 单候选：直接静态路由（含其错误信息），记录结果
		start := time.Now()
		content, backend, err := routeChat(model, msgs)
		rtRecordOutcome(backend, err == nil, time.Since(start), role)
		return content, backend, false, err
	}
	pick, explored := rtPick(cands)
	if pick == "" {
		content, backend, err := routeChat(model, msgs)
		return content, backend, false, err
	}
	start := time.Now()
	content, backend, err := routeChat(pick, msgs)
	// 防御：routeChat 内部仍可能因可达性变化改判 backend，记录实际 backend
	rtRecordOutcome(backend, err == nil, time.Since(start), role)
	if explored {
		auditLog("ROUTER_EXPLORE", "system", fmt.Sprintf("ε-greedy 探索：%s（ε=%.3f）", backend, rtCurrentEpsilon()))
	}
	return content, backend, explored, err
}

func rtCurrentEpsilon() float64 {
	rtMu.Lock()
	defer rtMu.Unlock()
	return rtSt.Epsilon
}

// ===================== 管理端点 =====================

// handleRouterStatus 路由决策透明化（UI 评分榜/动态防护可视化数据源，admin）
func handleRouterStatus(w http.ResponseWriter, r *http.Request) {
	rtMu.Lock()
	st := rtState{
		Arms:      map[string]*rtArm{},
		Decisions: rtSt.Decisions,
		Epsilon:   rtSt.Epsilon,
	}
	for k, v := range rtSt.Arms {
		cp := *v
		st.Arms[k] = &cp
	}
	rtMu.Unlock()
	writeJSON(w, map[string]interface{}{
		"enabled":     rtEnabled(),
		"epsilon":     st.Epsilon,
		"decisions":   st.Decisions,
		"candidates":  rtCandidates(),
		"arms":        st.Arms,
		"policy":      "两阶段：静态规则优先，bandit 仅优化自动分支；非 admin 反馈权重 ×0.1（防伪造）",
	})
}
