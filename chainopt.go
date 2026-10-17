package main

// ===================== v3.8.0 调用链优化（Chain Optimization）=====================
//
// 按当前职业动态优化 AI 调用链路：
//   - 文字创作者：文字生成工具链路优化（质量 + 稳定性）+ 悬浮框
//   - 学生：主动降低资源占用、优先保障稳定性
//   - 开发者：工具调用链路优化
//   - 研究者：长上下文链路优化
//
// 设计：
//   - ChainOptEngine 在 handleChat / handleV1 等聊天入口前介入
//   - 根据 currentPersona().ChainOpt 调整请求参数（temperature、timeout、工具选择）
//   - ResourceGuard 根据 currentPersona().ResourceStrategy 限制并发与缓存行为
//   - 悬浮框由前端根据 persona 状态渲染

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ===================== 并发与资源控制 =====================

var (
	// personaConcurrency 当前职业并发限制器
	personaSem   chan struct{} // 容量 = MaxConcurrent
	personaSemMu sync.Mutex
)

// initPersonaSemaphore 根据当前职业初始化信号量
func initPersonaSemaphore() {
	p := currentPersona()
	personaSemMu.Lock()
	defer personaSemMu.Unlock()
	semCap := p.ResourceStrategy.MaxConcurrent
	if semCap < 1 {
		semCap = 3
	}
	if semCap > 20 {
		semCap = 20
	}
	if personaSem == nil || cap(personaSem) != semCap {
		personaSem = make(chan struct{}, semCap)
	}
}

// acquirePersonaSlot 获取一个并发槽位（带超时）
func acquirePersonaSlot(timeout time.Duration) bool {
	initPersonaSemaphore()
	select {
	case personaSem <- struct{}{}:
		return true
	case <-time.After(timeout):
		return false
	}
}

// releasePersonaSlot 释放并发槽位
func releasePersonaSlot() {
	select {
	case <-personaSem:
	default:
	}
}

// ===================== 请求参数优化 =====================

// ChatOptHints 传递给聊天处理器的优化提示
type ChatOptHints struct {
	TimeoutBoost   time.Duration `json:"timeoutBoost"`
	CacheFirst     bool          `json:"cacheFirst"`
	StabilityFirst bool          `json:"stabilityFirst"`
	OptimizeText   bool          `json:"optimizeText"`
	ToolChainPref  string        `json:"toolChainPref"`
	RetryPolicy    string        `json:"retryPolicy"`
	MaxTokensBoost int           `json:"maxTokensBoost"`
}

// currentChatHints 根据当前职业生成调用链优化提示
func currentChatHints() ChatOptHints {
	p := currentPersona()
	return ChatOptHints{
		TimeoutBoost:   time.Duration(p.ChainOpt.TimeoutBoostMs) * time.Millisecond,
		CacheFirst:     p.ResourceStrategy.CachePriority,
		StabilityFirst: p.ResourceStrategy.StabilityFirst,
		OptimizeText:   p.ChainOpt.OptimizeTextGen,
		ToolChainPref:  p.ChainOpt.ToolChainPref,
		RetryPolicy:    p.ChainOpt.RetryPolicy,
		MaxTokensBoost: 0,
	}
}

// applyHintsToChatBody 将优化提示应用到聊天请求体（修改 JSON map）
func applyHintsToChatBody(body map[string]interface{}, hints ChatOptHints) {
	if hints.OptimizeText {
		// 文字创作者：降低 temperature 提升确定性，增加 max_tokens
		if _, ok := body["temperature"]; !ok {
			body["temperature"] = 0.5
		} else if t, ok := body["temperature"].(float64); ok && t > 0.7 {
			body["temperature"] = 0.5
		}
		if mt, ok := body["max_tokens"].(float64); ok {
			body["max_tokens"] = mt + 1024
		} else {
			body["max_tokens"] = 4096
		}
	}
	if hints.StabilityFirst {
		// 学生/稳定优先：保守参数，启用缓存
		body["temperature"] = 0.3
		if topP, ok := body["top_p"].(float64); ok && topP > 0.9 {
			body["top_p"] = 0.9
		}
	}
}

// ===================== 资源监控与降载 =====================

var (
	optFailCount   int64 // 最近失败计数（滑动窗口）
	optFailWindow  = time.Minute
	optFailLastReset time.Time
	optFailMu      sync.Mutex
)

// recordOptFail 记录调用链失败，用于触发降载
func recordOptFail() {
	optFailMu.Lock()
	defer optFailMu.Unlock()
	if time.Since(optFailLastReset) > optFailWindow {
		atomic.StoreInt64(&optFailCount, 0)
		optFailLastReset = time.Now()
	}
	atomic.AddInt64(&optFailCount, 1)
}

// shouldThrottle 判断当前是否应降载（学生/稳定优先模式下更敏感）
func shouldThrottle() bool {
	p := currentPersona()
	threshold := int64(10)
	if p.ResourceStrategy.StabilityFirst {
		threshold = 3
	}
	return atomic.LoadInt64(&optFailCount) >= threshold
}

// ===================== REST：当前优化状态 =====================

func handleV38ChainOptStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "仅支持 GET", http.StatusMethodNotAllowed)
		return
	}
	p := currentPersona()
	hints := currentChatHints()
	writeJSON(w, map[string]interface{}{
		"persona":        p.ID,
		"hints":          hints,
		"resource": map[string]interface{}{
			"maxConcurrent":  p.ResourceStrategy.MaxConcurrent,
			"cachePriority":  p.ResourceStrategy.CachePriority,
			"lowPowerMode":   p.ResourceStrategy.LowPowerMode,
			"stabilityFirst": p.ResourceStrategy.StabilityFirst,
		},
		"throttle": shouldThrottle(),
		"failCount": atomic.LoadInt64(&optFailCount),
	})
}
