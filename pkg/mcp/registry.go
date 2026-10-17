// Package mcp provides MCP Marketplace and subprocess management.
// v4.16.0
package mcp

import (
	"fmt"
	"runtime"
	"strings"
)

// Integration describes one MCP server available in the marketplace.
type Integration struct {
	Name        string   `json:"name"`
	Repo        string   `json:"repo"`        // e.g. HP-jh/TarsBifrost
	Description string   `json:"description"`
	BinaryName  string   `json:"binaryName"`  // asset pattern prefix
	Tools       []string `json:"tools"`       // tool names exposed by this MCP
}

// Registry holds the static list of 15 integrations.
var Registry = []Integration{
	{Name: "Bifrost", Repo: "HP-jh/TarsBifrost", Description: "Maxim AI 适配层 — 多模型统一调用", BinaryName: "tars-bifrost", Tools: []string{"bifrost_chat", "bifrost_models"}},
	{Name: "Portkey", Repo: "HP-jh/TarsPortkey", Description: "Portkey LLM Gateway — 统一入口", BinaryName: "tars-portkey", Tools: []string{"portkey_chat", "portkey_guard"}},
	{Name: "OneAPI", Repo: "HP-jh/TarsOneAPI", Description: "OneAPI 多模型网关 — 渠道管理", BinaryName: "tars-oneapi", Tools: []string{"oneapi_chat", "oneapi_channels"}},
	{Name: "LiteLLM", Repo: "HP-jh/TarsLiteLLM", Description: "LiteLLM 100+ LLM 统一调用", BinaryName: "tars-litellm", Tools: []string{"litellm_chat", "litellm_models"}},
	{Name: "Higress", Repo: "HP-jh/TarsHigress", Description: "Higress 云原生 API 网关 — AI 流量治理", BinaryName: "tars-higress", Tools: []string{"higress_route", "higress_plugin"}},
	{Name: "Dify", Repo: "HP-jh/TarsDify", Description: "Dify LLM 应用平台 — 工作流编排", BinaryName: "tars-dify", Tools: []string{"dify_chat", "dify_workflow"}},
	{Name: "LangChain", Repo: "HP-jh/TarsLangChain", Description: "LangChain 编排 — 链式调用", BinaryName: "tars-langchain", Tools: []string{"langchain_chain", "langchain_agent"}},
	{Name: "N8N", Repo: "HP-jh/TarsN8N", Description: "N8N 工作流 — 自动化编排", BinaryName: "tars-n8n", Tools: []string{"n8n_trigger", "n8n_workflow"}},
	{Name: "AutoGPT", Repo: "HP-jh/TarsAutoGPT", Description: "AutoGPT 自主 agent — 目标驱动", BinaryName: "tars-autogpt", Tools: []string{"autogpt_task", "autogpt_browse"}},
	{Name: "RAGFlow", Repo: "HP-jh/TarsRAGFlow", Description: "RAGFlow RAG 引擎 — 检索增强", BinaryName: "tars-ragflow", Tools: []string{"ragflow_search", "ragflow_ingest"}},
	{Name: "Mem0", Repo: "HP-jh/TarsMem0", Description: "Mem0 自改进记忆层 — 上下文记忆", BinaryName: "tars-mem0", Tools: []string{"mem0_recall", "mem0_store"}},
	{Name: "OpenWebUI", Repo: "HP-jh/TarsOpenWebUI", Description: "Open WebUI 自托管界面 — 本地模型", BinaryName: "tars-openwebui", Tools: []string{"openwebui_chat", "openwebui_models"}},
	{Name: "OWASPAgentic", Repo: "HP-jh/TarsOWASPAgentic", Description: "OWASP Agentic Top 10 — 安全检测", BinaryName: "tars-owasp-agentic", Tools: []string{"owasp_scan", "owasp_report"}},
	{Name: "Wazuh", Repo: "HP-jh/TarsWazuh", Description: "Wazuh XDR+SIEM — 威胁检测", BinaryName: "tars-wazuh", Tools: []string{"wazuh_alert", "wazuh_scan"}},
	{Name: "UITarsBridge", Repo: "HP-jh/TarsUITarsBridge", Description: "Tars UI 桥接 — 前端互操作", BinaryName: "tars-ui-tarsbridge", Tools: []string{"bridge_ui", "bridge_event"}},
}

// Find returns an integration by name (case-insensitive).
func Find(name string) (*Integration, int) {
	for i, r := range Registry {
		if strings.EqualFold(r.Name, name) {
			return &Registry[i], i
		}
	}
	return nil, -1
}

// AssetName returns the platform-specific release asset filename.
func (in *Integration) AssetName(version string) string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	name := fmt.Sprintf("%s-%s-%s-%s", in.BinaryName, version, goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// AllNames returns just the names for UI lists.
func AllNames() []string {
	out := make([]string, len(Registry))
	for i, r := range Registry {
		out[i] = r.Name
	}
	return out
}
