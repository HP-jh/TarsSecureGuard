// dynamicdefense.go — 动态防御（目：Ordo-DynamicDefense）
// 规则自适应 + ML威胁情报 + 实时参数热重载
package dynamicdefense

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Engine 动态防御引擎
type Engine struct {
	cfg        atomic.Value
	ruleEngine *RuleEngine
	mlEngine   *MLEngine
	hotReload  *HotReloader
}

// Config 动态防御配置
type Config struct {
	Enabled       bool         `json:"enabled"`
	ShadowRules   []ShadowRule `json:"shadow_rules"`
	AutoAdapt     bool         `json:"auto_adapt"`
	MLThreatIntel bool         `json:"ml_threat_intel"`
	HotReloadSec  int          `json:"hot_reload_sec"`
}

// ShadowRule 影子规则
type ShadowRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Hits        int64  `json:"hits"`
	FalsePos    int64  `json:"false_positives"`
	Enabled     bool   `json:"enabled"`
	AutoPromote bool   `json:"auto_promote"`
}

// RuleEngine 规则自适应引擎
type RuleEngine struct {
	shadows map[string]*ShadowRule
	mu      sync.RWMutex
}

// MLEngine 轻量ML威胁情报
type MLEngine struct {
	enabled   bool
	modelPath string
}

// HotReloader 实时参数热重载
type HotReloader struct {
	version   uint64
	mu        sync.RWMutex
	listeners []func(cfg *Config)
}

// NewEngine 创建动态防御引擎
func NewEngine(cfg *Config) *Engine {
	e := &Engine{}
	e.cfg.Store(cfg)
	e.ruleEngine = &RuleEngine{shadows: map[string]*ShadowRule{}}
	for i := range cfg.ShadowRules {
		e.ruleEngine.shadows[cfg.ShadowRules[i].ID] = &cfg.ShadowRules[i]
	}
	e.mlEngine = &MLEngine{enabled: cfg.MLThreatIntel}
	e.hotReload = &HotReloader{version: 1}
	return e
}

// Start 启动引擎
func (e *Engine) Start(ctx context.Context) error {
	go e.adaptLoop(ctx)
	go e.mlLoop(ctx)
	return nil
}

// Stop 停止引擎
func (e *Engine) Stop(ctx context.Context) error { return nil }

func (e *Engine) adaptLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.adaptRules()
		}
	}
}

func (e *Engine) adaptRules() {
	e.ruleEngine.mu.Lock()
	defer e.ruleEngine.mu.Unlock()
	for _, sr := range e.ruleEngine.shadows {
		if !sr.Enabled || sr.Hits == 0 {
			continue
		}
		fpRate := float64(sr.FalsePos) / float64(sr.Hits)
		if fpRate < 0.01 && sr.Hits > 100 && sr.AutoPromote {
			// 误报率<1%且命中>100次 → 可提升为正式规则
		}
	}
}

func (e *Engine) mlLoop(ctx context.Context) {
	if !e.mlEngine.enabled {
		return
	}
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RecordShadowHit 记录影子规则命中
func (e *Engine) RecordShadowHit(ruleID string, isFP bool) {
	e.ruleEngine.mu.Lock()
	defer e.ruleEngine.mu.Unlock()
	if sr, ok := e.ruleEngine.shadows[ruleID]; ok {
		sr.Hits++
		if isFP {
			sr.FalsePos++
		}
	}
}

// HotReload 热重载配置（atomic swap）
func (e *Engine) HotReload(cfg *Config) error {
	e.cfg.Store(cfg)
	atomic.AddUint64(&e.hotReload.version, 1)
	e.hotReload.mu.RLock()
	for _, fn := range e.hotReload.listeners {
		go fn(cfg)
	}
	e.hotReload.mu.RUnlock()
	return nil
}

// Config 获取当前配置
func (e *Engine) Config() *Config {
	return e.cfg.Load().(*Config)
}

// Version 获取配置版本号
func (e *Engine) Version() uint64 {
	return atomic.LoadUint64(&e.hotReload.version)
}

// OnConfigChange 注册配置变更监听
func (e *Engine) OnConfigChange(fn func(cfg *Config)) {
	e.hotReload.mu.Lock()
	defer e.hotReload.mu.Unlock()
	e.hotReload.listeners = append(e.hotReload.listeners, fn)
}

// Status 返回状态摘要
func (e *Engine) Status() map[string]interface{} {
	cfg := e.Config()
	e.ruleEngine.mu.RLock()
	shadowCount := len(e.ruleEngine.shadows)
	e.ruleEngine.mu.RUnlock()
	return map[string]interface{}{
		"enabled":        cfg.Enabled,
		"auto_adapt":     cfg.AutoAdapt,
		"ml_intel":       cfg.MLThreatIntel,
		"shadow_rules":   shadowCount,
		"config_version": e.Version(),
	}
}
