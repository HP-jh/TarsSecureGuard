package main

import (
	"encoding/json"
	"net/http"
	"time"
)

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


// ========== v4.11.5 多智能体协作 ==========

type AgentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	BuiltIn     bool   `json:"builtIn"`
}

func handleAgentList(w http.ResponseWriter, r *http.Request) {
	var agents []AgentInfo

	// 内置智能体
	builtIns := []AgentInfo{
		{ID: "default", Name: "通用助手", Description: "默认通用助手，回答各类问题", Icon: "🤖", BuiltIn: true},
		{ID: "code-assistant", Name: "代码助手", Description: "擅长编程、代码审查与调试", Icon: "💻", BuiltIn: true},
		{ID: "writing-assistant", Name: "写作助手", Description: "擅长写作、润色与翻译", Icon: "✍️", BuiltIn: true},
		{ID: "security-analyst", Name: "安全分析", Description: "专注安全审计与威胁分析", Icon: "🛡️", BuiltIn: true},
		{ID: "data-analyst", Name: "数据分析", Description: "分析数据并提供洞察", Icon: "📊", BuiltIn: true},
		{ID: "translator", Name: "翻译助手", Description: "进行中英互译", Icon: "🌐", BuiltIn: true},
		{ID: "summarizer", Name: "摘要助手", Description: "提取要点并总结", Icon: "📝", BuiltIn: true},
	}
	agents = append(agents, builtIns...)

	// 自定义智能体
	for _, a := range customAgentList() {
		agents = append(agents, AgentInfo{
			ID:      a.ID,
			Name:    a.Name,
			Icon:    "🎭",
			BuiltIn: false,
		})
	}

	writeJSON(w, map[string]interface{}{"agents": agents})
}

type AgentTeamRequest struct {
	Prompt  string   `json:"prompt"`
	AgentIDs []string `json:"agentIds"`
	Model   string   `json:"model"`
}

type AgentTeamResult struct {
	AgentID   string `json:"agentId"`
	AgentName string `json:"agentName"`
	Content   string `json:"content"`
	Backend   string `json:"backend"`
	LatencyMs int64  `json:"latencyMs"`
	Error     string `json:"error,omitempty"`
}

func handleAgentTeam(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req AgentTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Prompt == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "prompt required"})
		return
	}
	if len(req.AgentIDs) == 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "agentIds required"})
		return
	}

	var results []AgentTeamResult
	for _, agentID := range req.AgentIDs {
		start := time.Now()
		sysPrompt := getAgentPrompt(agentID)
		msgs := []Message{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: req.Prompt},
		}
		content, backend, err := routeChat(req.Model, msgs)
		res := AgentTeamResult{
			AgentID:   agentID,
			AgentName: agentName(agentID),
			Content:   content,
			Backend:   backend,
			LatencyMs: time.Since(start).Milliseconds(),
		}
		if err != nil {
			res.Error = err.Error()
		}
		results = append(results, res)
	}

	writeJSON(w, map[string]interface{}{"results": results, "prompt": req.Prompt})
}

func agentName(id string) string {
	if a, ok := findCustomAgentPrompt(id); ok {
		return a.Name
	}
	switch id {
	case "code-assistant":
		return "代码助手"
	case "writing-assistant":
		return "写作助手"
	case "urgent-responder":
		return "紧急响应"
	case "security-analyst":
		return "安全分析"
	case "translator":
		return "翻译助手"
	case "summarizer":
		return "摘要助手"
	case "data-analyst":
		return "数据分析"
	default:
		return "通用助手"
	}
}
