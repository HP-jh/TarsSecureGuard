package main

// ===================== 自定义 Agent 角色与配置摘要辅助（v2.0.0）=====================

// customAgentList 当前配置的自定义 agent 列表（快照）
func customAgentList() []CustomAgentDef {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return append([]CustomAgentDef(nil), cfg.CustomAgents...)
}

// findCustomAgentPrompt 按角色 ID / 名称查自定义 agent 的 system prompt
func findCustomAgentPrompt(id string) (CustomAgentDef, bool) {
	for _, a := range customAgentList() {
		if a.ID == id || a.Name == id {
			return a, true
		}
	}
	return CustomAgentDef{}, false
}

// moduleStatusSummary 模块开关摘要（handleConfig GET / 状态展示用）
func moduleStatusSummary() map[string]bool {
	modMu.RLock()
	defer modMu.RUnlock()
	out := map[string]bool{"security-core": true} // 安全模块强制加载，永远 true
	for k, v := range modStates {
		out[k] = v
	}
	return out
}

// directConfigSummary 直连层配置摘要
func directConfigSummary() map[string]interface{} {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return map[string]interface{}{
		"transport":      cfg.Direct.Transport,
		"grpcSidecar":    map[string]interface{}{"address": cfg.Direct.GRPCSidecar.Address},
		"fallbackPolicy": "边车不可用自动回落 native",
	}
}
