package main

// v4.10.1 Model Alias System — Surpass LLMux
// Kingdom 7 层归位：界·Domain = gateway / 门·Phylum = routing / 纲·Class = model-alias
//
// 借鉴 LLMux 模型别名思路（AGPL-3.0 隔离，Go 自研实现）：
// - 短别名映射到完整模型名 + 可选强制 provider
// - 运行时热重载（config 变化自动生效）
// - 前缀回退：claude-* → anthropic, gemini-* → gemini, 其余 → openai-compat

import (
	"strings"
	"sync"
)

// ModelAlias 单个别名映射项
type ModelAlias struct {
	Alias      string `json:"alias"`      // 短别名，如 "c37"
	Target     string `json:"target"`     // 目标完整模型名，如 "claude-3-7-sonnet-20250219"
	ProviderID string `json:"providerId"` // 可选：强制路由到指定 provider（空则走自动解析）
}

// ModelAliasRegistry 线程安全别名注册表
type ModelAliasRegistry struct {
	mu      sync.RWMutex
	aliases map[string]ModelAlias // key: 小写 alias
}

var modelAliasReg = &ModelAliasRegistry{aliases: make(map[string]ModelAlias)}

// initModelAliases 从配置加载别名表。由 loadConfig 后调用，热重载时复用。
func initModelAliases() {
	modelAliasReg.mu.Lock()
	defer modelAliasReg.mu.Unlock()
	modelAliasReg.aliases = make(map[string]ModelAlias, len(cfg.V4101Config.ModelAliases))
	for _, a := range cfg.V4101Config.ModelAliases {
		if a.Alias == "" || a.Target == "" {
			continue
		}
		modelAliasReg.aliases[strings.ToLower(a.Alias)] = a
	}
}

// resolveModelAlias 解析别名 → (目标模型名, 强制providerID, 是否命中)
// 未命中时返回原值、空 provider、false
func resolveModelAlias(input string) (target string, providerID string, ok bool) {
	modelAliasReg.mu.RLock()
	defer modelAliasReg.mu.RUnlock()
	a, ok := modelAliasReg.aliases[strings.ToLower(input)]
	if !ok {
		return input, "", false
	}
	return a.Target, a.ProviderID, true
}

// resolveModelByPrefix 前缀回退解析（LLMux 思路借鉴）：
//   claude-*      → anthropic 协议
//   gemini-*      → gemini 协议
//   models/gemini → gemini 协议
//   其余          → openai-compat 协议
// 返回 providerID 建议值（空表示让上层自动决策）
func resolveModelByPrefix(model string) (providerID string, protocol string) {
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "claude-"):
		return "anthropic", "anthropic"
	case strings.HasPrefix(m, "gemini-") || strings.HasPrefix(m, "models/gemini-"):
		return "gemini", "gemini"
	default:
		return "", "openai-compat"
	}
}

// expandModelAlias 路由前统一别名展开：
// 1) 查别名表；2) 无别名但含 providerId/model 形式则透传；3) 纯模型名走前缀回退建议
func expandModelAlias(model string) (expanded string, forcedProvider string, hintProtocol string) {
	// 1) 别名表
	if t, pid, ok := resolveModelAlias(model); ok {
		return t, pid, ""
	}
	// 2) 已是 providerId/model 形式
	if _, _, ok := splitProviderModel(model); ok {
		return model, "", ""
	}
	// 3) 前缀回退建议
	suggestedPID, proto := resolveModelByPrefix(model)
	return model, suggestedPID, proto
}
