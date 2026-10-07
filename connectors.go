package main

// ===================== v3.4.0 连接器生态 =====================
//
// 用户诉求（项 1）：「强化连接能力：打通更多数据源与外部服务，构建开放的
// 连接器生态，让 AI 能够无缝接入各类工具、平台和本地环境」。
//
// 设计：
//   - 连接器 = 「内置模板目录（编译进二进制）+ 用户实例（config v34.connectors）」
//   - 模板声明 endpoint 模板（{{.param}} 占位）、method、headers（值支持 env:VAR
//     引用环境变量，密钥不落盘）、参数 schema；实例提供参数值（如 owner/repo）
//   - 启用的实例自动注册成 AI 可调用工具（工具名 conn_<template>，与内置工具、
//     customTools 同一调用通路：/api/tools/<name> + 守门人策略门 + 审计）
//   - 执行层完全复用 customTools 的 SSRF 红线（连接时实际 IP 校验防 DNS 重绑定、
//     禁重定向、协议白名单、30s 超时、2MB 响应上限），每次调用落审计
//   - API（connectors 模块，默认开）：
//       GET  /api/admin/v34/connectors   目录 + 已启用实例
//       POST /api/admin/v34/connectors   启用/更新/禁用实例 {template, params, enabled}

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// ConnectorParam 连接器参数声明
type ConnectorParam struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Default     string `json:"default,omitempty"`
}

// ConnectorTemplate 连接器模板（内置目录，编译进二进制）
type ConnectorTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"` // code | notify | data | web
	Endpoint    string            `json:"endpoint"` // {{.param}} 占位
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"` // 值支持 env:VAR
	Params      []ConnectorParam `json:"params,omitempty"`
	Docs        string            `json:"docs,omitempty"`
	NoAuth      bool              `json:"noAuth"` // true = 无需任何密钥即可用
}

// ConnectorInstance 用户启用的连接器实例（config v34.connectors）
type ConnectorInstance struct {
	Template string            `json:"template"` // 模板 ID
	Name     string            `json:"name,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
	Enabled  bool              `json:"enabled"`
}

// builtinConnectorTemplates 内置连接器目录（全部公网 HTTPS；免费或可选 env 令牌）
var builtinConnectorTemplates = []ConnectorTemplate{
	{
		ID: "github_repo", Name: "GitHub 仓库信息", Category: "code",
		Description: "查询 GitHub 仓库元信息（stars / forks / 语言 / 描述 / 最近推送）",
		Endpoint:    "https://api.github.com/repos/{{.owner}}/{{.repo}}",
		Headers:     map[string]string{"Accept": "application/vnd.github+json", "Authorization": "env:GITHUB_TOKEN"},
		Params: []ConnectorParam{
			{Name: "owner", Required: true, Description: "仓库所有者"},
			{Name: "repo", Required: true, Description: "仓库名"},
		},
		Docs: "https://docs.github.com/rest/repos",
	},
	{
		ID: "github_issues", Name: "GitHub Issues", Category: "code",
		Description: "查询 GitHub 仓库的 issues 列表（可按状态过滤）",
		Endpoint:    "https://api.github.com/repos/{{.owner}}/{{.repo}}/issues?state={{.state}}&per_page={{.limit}}",
		Headers:     map[string]string{"Accept": "application/vnd.github+json", "Authorization": "env:GITHUB_TOKEN"},
		Params: []ConnectorParam{
			{Name: "owner", Required: true, Description: "仓库所有者"},
			{Name: "repo", Required: true, Description: "仓库名"},
			{Name: "state", Default: "open", Description: "open | closed | all"},
			{Name: "limit", Default: "10", Description: "每页条数（1-100）"},
		},
		Docs: "https://docs.github.com/rest/issues",
	},
	{
		ID: "webhook_notify", Name: "Webhook 通知", Category: "notify",
		Description: "向 Webhook 地址发送 JSON 通知（飞书 / 钉钉 / Slack 自定义机器人格式由调用参数 body 决定）",
		Endpoint:    "{{.url}}", Method: "POST",
		Params: []ConnectorParam{
			{Name: "url", Required: true, Description: "Webhook 完整 URL（https://…）"},
		},
		Docs: "飞书/钉钉/Slack 自定义机器人的 incoming webhook 均可直达",
	},
	{
		ID: "wikipedia_search", Name: "维基百科搜索", Category: "data",
		Description: "维基百科开放搜索（返回标题候选与摘要）",
		Endpoint:    "https://zh.wikipedia.org/w/api.php?action=opensearch&search={{.query}}&limit={{.limit}}&format=json",
		Params: []ConnectorParam{
			{Name: "query", Required: true, Description: "搜索词"},
			{Name: "limit", Default: "5", Description: "返回条数"},
		},
		NoAuth: true,
	},
	{
		ID: "weather", Name: "实时天气", Category: "data",
		Description: "查询指定经纬度的实时天气（Open-Meteo，免费无需 Key）",
		Endpoint:    "https://api.open-meteo.com/v1/forecast?latitude={{.lat}}&longitude={{.lon}}&current=temperature_2m,weather_code,wind_speed_10m",
		Params: []ConnectorParam{
			{Name: "lat", Required: true, Description: "纬度（如 39.90）"},
			{Name: "lon", Required: true, Description: "经度（如 116.40）"},
		},
		NoAuth: true,
	},
	{
		ID: "ip_info", Name: "IP 归属查询", Category: "data",
		Description: "查询 IP 地址的归属地与运营商信息（ipinfo.io）",
		Endpoint:    "https://ipinfo.io/{{.ip}}/json",
		Params:      []ConnectorParam{{Name: "ip", Required: true, Description: "IP 地址"}},
		NoAuth:      true,
	},
	{
		ID: "hn_top", Name: "Hacker News 热榜", Category: "web",
		Description: "Hacker News 当前热榜 story ID 列表（配合 conn_hn_item 取详情）",
		Endpoint:    "https://hacker-news.firebaseio.com/v0/topstories.json",
		NoAuth:      true,
	},
	{
		ID: "hn_item", Name: "Hacker News 条目", Category: "web",
		Description: "按 ID 取 Hacker News 条目详情（标题 / 链接 / 得分 / 评论数）",
		Endpoint:    "https://hacker-news.firebaseio.com/v0/item/{{.id}}.json",
		Params:      []ConnectorParam{{Name: "id", Required: true, Description: "条目 ID"}},
		NoAuth:      true,
	},
}

// connectorTemplatesMap 模板索引
func connectorTemplatesMap() map[string]ConnectorTemplate {
	m := map[string]ConnectorTemplate{}
	for _, t := range builtinConnectorTemplates {
		m[t.ID] = t
	}
	return m
}

// connectorInstances 当前配置的连接器实例
func connectorInstances() []ConnectorInstance {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return append([]ConnectorInstance(nil), cfg.V34Config.Connectors...)
}

// liveConnector 启用中的实例（附模板）
type liveConnector struct {
	Inst ConnectorInstance
	Tpl  ConnectorTemplate
}

// enabledConnectors 返回启用且模板存在的实例
func enabledConnectors() []liveConnector {
	tm := connectorTemplatesMap()
	var out []liveConnector
	for _, inst := range connectorInstances() {
		if !inst.Enabled {
			continue
		}
		if tpl, ok := tm[inst.Template]; ok {
			out = append(out, liveConnector{inst, tpl})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Inst.Template < out[j].Inst.Template })
	return out
}

// connectorToolName 连接器实例的工具名
func connectorToolName(templateID string) string { return "conn_" + templateID }

// expandConnectorParams 展开端点 / 头模板中的 {{.param}} 占位符：
// 调用参数（动态）> 实例 params（静态配置值）> 模板 Default；必填缺失 → 报错
func expandConnectorParams(s string, tpl ConnectorTemplate, instParams map[string]string, callArgs map[string]string) (string, error) {
	var missing []string
	out := s
	for _, p := range tpl.Params {
		val := instParams[p.Name]
		if v, ok := callArgs[p.Name]; ok && v != "" {
			val = v
		}
		if val == "" {
			val = p.Default
		}
		if val == "" && p.Required {
			missing = append(missing, p.Name)
			continue
		}
		out = strings.ReplaceAll(out, "{{."+p.Name+"}}", val)
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("连接器 %s 缺少必填参数: %s", tpl.ID, strings.Join(missing, ", "))
	}
	return out, nil
}

// connectorPassArgs 过滤透传给上游的参数：剥离守门人保留键（_tsgIdentity / confirm_token，
// 防止调用方身份信息泄漏进上游 URL 或请求体）与已被端点模板消费的参数（防重复拼接）。
func connectorPassArgs(tpl ConnectorTemplate, args map[string]interface{}) map[string]interface{} {
	reserved := map[string]bool{"_tsgIdentity": true, "confirm_token": true}
	consumed := map[string]bool{}
	for _, p := range tpl.Params {
		if strings.Contains(tpl.Endpoint, "{{."+p.Name+"}}") {
			consumed[p.Name] = true
		}
	}
	pass := map[string]interface{}{}
	for k, v := range args {
		if reserved[k] || consumed[k] {
			continue
		}
		pass[k] = v
	}
	return pass
}

// executeConnector 执行连接器调用（SSRF 红线由 executeForwardedRequest 统一落实）
func executeConnector(templateID string, args map[string]interface{}) (interface{}, error) {
	for _, lc := range enabledConnectors() {
		if lc.Inst.Template != templateID {
			continue
		}
		callArgs := map[string]string{}
		for k, v := range args {
			if s, ok := v.(string); ok {
				callArgs[k] = s
			} else {
				callArgs[k] = fmt.Sprintf("%v", v)
			}
		}
		endpoint, err := expandConnectorParams(lc.Tpl.Endpoint, lc.Tpl, lc.Inst.Params, callArgs)
		if err != nil {
			return nil, err
		}
		method := strings.ToUpper(strings.TrimSpace(lc.Tpl.Method))
		if method == "" {
			method = http.MethodGet
		}
		result, err := executeForwardedRequest(method, endpoint, lc.Tpl.Headers, nil, connectorPassArgs(lc.Tpl, args))
		status := "ok"
		if err != nil {
			status = "error: " + err.Error()
		}
		auditLog("CONNECTOR_CALL", "system", fmt.Sprintf("connector=%s endpoint=%s status=%s", templateID, endpoint, status))
		return result, err
	}
	return nil, fmt.Errorf("连接器不存在或未启用: %s", templateID)
}

// handleV34Connectors GET：目录 + 实例；POST：启用/更新/禁用实例
func handleV34Connectors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"version":    version,
			"templates":  builtinConnectorTemplates,
			"instances":  connectorInstances(),
			"enabledNum": len(enabledConnectors()),
			"module":     moduleEnabledByID("connectors"),
		})
	case http.MethodPost:
		var req struct {
			Template string            `json:"template"`
			Name     string            `json:"name,omitempty"`
			Params   map[string]string `json:"params,omitempty"`
			Enabled  *bool             `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Template == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 {template, params, enabled}"})
			return
		}
		tpl, ok := connectorTemplatesMap()[req.Template]
		if !ok {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "未知连接器模板: " + req.Template})
			return
		}
		// 参数校验：必填且无默认值的参数必须由实例 params 提供
		for _, p := range tpl.Params {
			if p.Required && p.Default == "" {
				if v, ok := req.Params[p.Name]; !ok || v == "" {
					writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("必填参数 %s 缺失", p.Name)})
					return
				}
			}
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		cfgMu.Lock()
		list := cfg.V34Config.Connectors
		found := false
		for i := range list {
			if list[i].Template == req.Template {
				list[i].Name = req.Name
				list[i].Params = req.Params
				list[i].Enabled = enabled
				found = true
			}
		}
		if !found {
			list = append(list, ConnectorInstance{Template: req.Template, Name: req.Name, Params: req.Params, Enabled: enabled})
		}
		cfg.V34Config.Connectors = list
		cfgMu.Unlock()
		if err := saveConfigChecked(); err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "保存失败: " + err.Error()})
			return
		}
		auditLog("CONNECTOR_CONFIG", "system", fmt.Sprintf("连接器 %s -> enabled=%v", req.Template, enabled))
		writeJSON(w, map[string]interface{}{"ok": true, "template": req.Template, "enabled": enabled})
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}
