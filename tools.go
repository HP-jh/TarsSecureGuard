package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// ===================== 工具注册表 =====================

// toolModuleMap 工具 -> 功能模块归属（v2.0.0）：模块关闭时该工具从列表隐藏、调用被拒。
// 未登记的内置工具默认归 builtinTools（基础面，永远随 builtinTools 开关）。
var toolModuleMap = map[string]string{
	"tars_model_chat":        "chatApi",
	"tars_agent_run":         "chatApi",
	"tars_model_list":        "localModels",
	"tars_model_start":       "localModels",
	"tars_model_stop":        "localModels",
	"tars_lmstudio_list":     "localModels",
	"tars_ollama_list":       "localModels",
	"tars_web_search":        "webSearch",
	"tars_fetch_url":         "webFetch",
	"tars_openapi_overview":  "openapiTools",
	"tars_openapi_operation": "openapiTools",
	"tars_external_mcp":      "mcpExternal",
	"tars_mcp_discover":      "mcpExternal",
	"tars_memory_get":        "memory",
	"tars_memory_set":        "memory",
	"tars_hardware_advisor":  "hardwareAdvisor",
	// v3.2.2 治理层工具（contextGov 模块）
	"tars_shared_memory_set":    "contextGov",
	"tars_shared_memory_get":    "contextGov",
	"tars_shared_memory_list":   "contextGov",
	"tars_shared_memory_delete": "contextGov",
	"tars_shared_info_add":      "contextGov",
	"tars_shared_info_search":   "contextGov",
	"tars_shared_info_delete":   "contextGov",
	"tars_context_build":        "contextGov",
	"tars_context_pack_save":    "contextGov",
	"tars_context_pack_load":    "contextGov",
}

// toolModuleOf 查询工具归属模块（未登记的内置工具默认归 builtinTools）
func toolModuleOf(name string) string {
	if m, ok := toolModuleMap[name]; ok {
		return m
	}
	return "builtinTools"
}

type Tool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
	Handler     func(args map[string]interface{}) (interface{}, error)
}

var tools = map[string]Tool{}

func initTools() {
	tools = map[string]Tool{
		"tars_status": {
			Name: "tars_status", Description: "获取网关运行状态、统计、设备与模型信息",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler:     func(a map[string]interface{}) (interface{}, error) { return statusPayload(), nil },
		},
		"tars_time": {
			Name: "tars_time", Description: "获取当前本地时间",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				now := time.Now()
				return map[string]interface{}{
					"datetime": now.Format("2006-01-02 15:04:05"),
					"date":     now.Format("2006-01-02"),
					"time":     now.Format("15:04:05"),
					"weekday":  now.Weekday().String(),
					"unix":     now.Unix(),
					"timezone": now.Format("MST -0700"),
				}, nil
			},
		},
		"tars_system_info": {
			Name: "tars_system_info", Description: "获取系统硬件、内存、CPU 与磁盘信息",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler:     func(a map[string]interface{}) (interface{}, error) { return getDeviceInfo(), nil },
		},
		"tars_model_list": {
			Name: "tars_model_list", Description: "列出所有可用模型（本地 GGUF / LM Studio / Ollama / 云端）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				ms := getModels()
				return map[string]interface{}{"models": ms, "total": len(ms)}, nil
			},
		},
		"tars_model_start": {
			Name: "tars_model_start", Description: "启动本地 GGUF 模型（如 qwen2.5-3b / qwen2.5-7b / qwen2.5-coder-3b）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"model": map[string]interface{}{"type": "string", "description": "本地模型 ID"},
			}, "required": []string{"model"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				id, _ := a["model"].(string)
				if id == "" {
					id = "qwen2.5-3b"
				}
				if err := startLocalModel(id); err != nil {
					return map[string]interface{}{"success": false, "error": err.Error()}, nil
				}
				return map[string]interface{}{"success": true, "model": id, "running": true, "port": modelPort}, nil
			},
		},
		"tars_model_stop": {
			Name: "tars_model_stop", Description: "停止本地模型",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				stopLocalModel()
				return map[string]interface{}{"success": true, "running": false}, nil
			},
		},
		"tars_model_chat": {
			Name: "tars_model_chat", Description: "向任意模型发起对话（自动路由到本地/LM Studio/Ollama/云端）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"model":    map[string]interface{}{"type": "string", "description": "模型 ID，留空或 auto 自动路由"},
				"messages": map[string]interface{}{"type": "array", "description": "对话消息 [{role,content}]"},
				"prompt":   map[string]interface{}{"type": "string", "description": "或直接传单条用户消息"},
			}, "required": []string{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				model, _ := a["model"].(string)
				prompt, _ := a["prompt"].(string)
				var msgs []Message
				if raw, ok := a["messages"].([]interface{}); ok && len(raw) > 0 {
					for _, r := range raw {
						if m, ok := r.(map[string]interface{}); ok {
							role, _ := m["role"].(string)
							content, _ := m["content"].(string)
							if role == "" {
								role = "user"
							}
							msgs = append(msgs, Message{Role: role, Content: content})
						}
					}
				}
				if len(msgs) == 0 && prompt != "" {
					msgs = []Message{{Role: "user", Content: prompt}}
				}
				if len(msgs) == 0 {
					return map[string]interface{}{"error": "messages 或 prompt 至少提供一个"}, nil
				}
				content, backend, err := routeChat(model, msgs)
				if err != nil {
					return map[string]interface{}{"error": err.Error(), "backend": backend}, nil
				}
				return map[string]interface{}{"model": model, "backend": backend, "content": content}, nil
			},
		},
		"tars_ollama_list": {
			Name: "tars_ollama_list", Description: "列出 Ollama 本地模型（端口 11434）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				return detectOllama(), nil
			},
		},
		"tars_lmstudio_list": {
			Name: "tars_lmstudio_list", Description: "列出 LM Studio 模型（端口 1234）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				return detectLMStudio(), nil
			},
		},
		"tars_file_list": {
			Name: "tars_file_list", Description: "列出目录内容",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": "目录路径"},
			}, "required": []string{"path"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				path, _ := a["path"].(string)
				if path == "" {
					path = `D:\`
				}
				if !isPathAllowed(path, false) {
					return map[string]interface{}{"error": "路径不在授权读取范围内"}, nil
				}
				entries, err := os.ReadDir(path)
				if err != nil {
					return nil, err
				}
				var items []map[string]interface{}
				for _, e := range entries {
					info, _ := e.Info()
					size := int64(0)
					if !e.IsDir() && info != nil {
						size = info.Size()
					}
					mtime := ""
					if info != nil {
						mtime = info.ModTime().Format("2006-01-02 15:04:05")
					}
					items = append(items, map[string]interface{}{
						"name":  e.Name(),
						"dir":   e.IsDir(),
						"size":  size,
						"mtime": mtime,
					})
				}
				sort.Slice(items, func(i, j int) bool {
					di := items[i]["dir"].(bool)
					dj := items[j]["dir"].(bool)
					if di != dj {
						return di
					}
					return items[i]["name"].(string) < items[j]["name"].(string)
				})
				return map[string]interface{}{"path": path, "count": len(items), "items": items}, nil
			},
		},
		"tars_file_read": {
			Name: "tars_file_read", Description: "读取文件内容（文本）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": "文件路径"},
			}, "required": []string{"path"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				path, _ := a["path"].(string)
				if !isPathAllowed(path, false) {
					return map[string]interface{}{"error": "路径不在授权读取范围内"}, nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return nil, err
				}
				if len(data) > maxFetchBytes {
					return nil, fmt.Errorf("文件过大（超过 %d 字节）", maxFetchBytes)
				}
				return map[string]interface{}{"path": path, "size": len(data), "content": string(data)}, nil
			},
		},
		"tars_file_write": {
			Name: "tars_file_write", Description: "写入文件（文本，UTF-8）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"path":    map[string]interface{}{"type": "string", "description": "文件路径"},
				"content": map[string]interface{}{"type": "string", "description": "文件内容"},
			}, "required": []string{"path", "content"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				path, _ := a["path"].(string)
				content, _ := a["content"].(string)
				if !isPathAllowed(path, true) {
					return map[string]interface{}{"error": "路径不在授权写入范围内"}, nil
				}
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					return nil, err
				}
				return map[string]interface{}{"success": true, "path": path, "bytes": len(content)}, nil
			},
		},
		"tars_fetch_url": {
			Name: "tars_fetch_url", Description: "抓取网页内容并转为纯文本",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"url":    map[string]interface{}{"type": "string", "description": "网页 URL"},
				"maxLen": map[string]interface{}{"type": "number", "description": "最大返回字符数"},
			}, "required": []string{"url"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				u, _ := a["url"].(string)
				maxLen := 8000
				if ml, ok := a["maxLen"].(float64); ok && ml > 0 {
					maxLen = int(ml)
				}
				return fetchURLText(u, maxLen)
			},
		},
		"tars_web_search": {
			Name: "tars_web_search", Description: "网络搜索（内置 Bing 源，无需 Key；可选 serper）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"query": map[string]interface{}{"type": "string", "description": "搜索关键词"},
				"count": map[string]interface{}{"type": "number", "description": "结果数量"},
			}, "required": []string{"query"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				q, _ := a["query"].(string)
				count := 8
				if c, ok := a["count"].(float64); ok && c > 0 {
					count = int(c)
				}
				return webSearch(q, count)
			},
		},
		"tars_security_status": {
			Name: "tars_security_status", Description: "获取安全状态与 WAF 拦截统计",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				cfgMu.RLock()
				wafOn := cfg.Security.WAFEnabled
				mode := cfg.Security.Mode
				cfgMu.RUnlock()
				mu.Lock()
				blocks := wafBlocks
				mu.Unlock()
				return map[string]interface{}{
					"wafEnabled":            wafOn,
					"mode":                  mode,
					"wafBlockCount":         blocks,
					"threatIntelBlockCount": 0,
					"domainBlockCount":      0,
					"safeModeTriggerCount":  0,
				}, nil
			},
		},
		"tars_config_get": {
			Name: "tars_config_get", Description: "获取网关配置（敏感 Key 已脱敏）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				cfgMu.RLock()
				defer cfgMu.RUnlock()
				return sanitizedConfig(), nil
			},
		},
		"tars_config_set": {
			Name: "tars_config_set", Description: "更新网关配置（如云端 API Key、搜索后端）并保存",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"path":  map[string]interface{}{"type": "string", "description": "配置路径，如 cloud.deepseek.apiKey / search.engine"},
				"value": map[string]interface{}{},
			}, "required": []string{"path", "value"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				path, _ := a["path"].(string)
				value := a["value"]
				if !isConfigPathAllowed(path) {
					return map[string]interface{}{"error": "不允许通过 API 修改该配置路径: " + path}, nil
				}
				if !validateConfigValue(path, value) {
					return map[string]interface{}{"error": "配置值非法（值域校验拒绝）: " + path}, nil
				}
				cfgMu.Lock()
				cfgJSON, _ := json.Marshal(cfg)
				var root map[string]interface{}
				json.Unmarshal(cfgJSON, &root)
				setJSONPath(root, path, value)
				data, _ := json.Marshal(root)
				err := json.Unmarshal(data, &cfg)
				cfgMu.Unlock()
				if err != nil {
					return nil, err
				}
				saveConfig()
				return map[string]interface{}{"success": true, "path": path, "value": value}, nil
			},
		},
		"tars_memory_set": {
			Name: "tars_memory_set", Description: "写入网关长期记忆（键值）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"key":   map[string]interface{}{"type": "string"},
				"value": map[string]interface{}{"type": "string"},
			}, "required": []string{"key", "value"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				k, _ := a["key"].(string)
				v, _ := a["value"].(string)
				if k == "" || len(k) > 128 {
					return map[string]interface{}{"error": "key 不能为空且不超过 128 字符"}, nil
				}
				if len(v) > 8192 {
					return map[string]interface{}{"error": "value 不能超过 8192 字符"}, nil
				}
				memoryMu.Lock()
				if _, exists := memory[k]; !exists && len(memory) >= memoryLimit {
					memoryMu.Unlock()
					return map[string]interface{}{"error": "记忆条目已达上限"}, nil
				}
				memory[k] = v
				memoryMu.Unlock()
				saveMemory()
				return map[string]interface{}{"success": true, "key": k}, nil
			},
		},
		"tars_memory_get": {
			Name: "tars_memory_get", Description: "读取网关长期记忆",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"key": map[string]interface{}{"type": "string", "description": "键名，留空返回全部"},
			}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				k, _ := a["key"].(string)
				memoryMu.Lock()
				defer memoryMu.Unlock()
				if k != "" {
					return map[string]interface{}{"key": k, "value": memory[k]}, nil
				}
				// 返回副本，避免外部并发写导致 map 读写竞争崩溃
				cp := make(map[string]string, len(memory))
				for kk, vv := range memory {
					cp[kk] = vv
				}
				return map[string]interface{}{"memory": cp}, nil
			},
		},
		"tars_openapi_overview": {
			Name: "tars_openapi_overview", Description: "加载 OpenAPI 规范（URL 或本地文件）并返回 API 概览",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string", "description": "OpenAPI 规范的 URL 或本地文件路径"},
			}, "required": []string{"id"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				id, _ := a["id"].(string)
				return openAPIOverview(id)
			},
		},
		"tars_openapi_operation": {
			Name: "tars_openapi_operation", Description: "从 OpenAPI 规范中获取指定操作详情（按 operationId 或路由）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"id":                 map[string]interface{}{"type": "string", "description": "OpenAPI 规范的 URL 或本地文件路径"},
				"operationIdOrRoute": map[string]interface{}{"type": "string", "description": "操作 ID 或路由路径"},
			}, "required": []string{"id", "operationIdOrRoute"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				id, _ := a["id"].(string)
				op, _ := a["operationIdOrRoute"].(string)
				return openAPIOperation(id, op)
			},
		},
		"tars_agent_run": {
			Name: "tars_agent_run", Description: "运行内置智能体（code-assistant / writing-assistant / translator / summarizer / data-analyst / security-analyst / urgent-responder）",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"agent":  map[string]interface{}{"type": "string", "description": "智能体 ID"},
				"prompt": map[string]interface{}{"type": "string", "description": "任务描述"},
			}, "required": []string{"agent", "prompt"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				agent, _ := a["agent"].(string)
				prompt, _ := a["prompt"].(string)
				sys := getAgentPrompt(agent)
				msgs := []Message{{Role: "system", Content: sys}, {Role: "user", Content: prompt}}
				content, backend, err := routeChat("", msgs)
				if err != nil {
					return map[string]interface{}{"error": err.Error()}, nil
				}
				return map[string]interface{}{"agent": agent, "backend": backend, "response": content}, nil
			},
		},
		"tars_external_mcp": {
			Name: "tars_external_mcp", Description: "调用已注册的外部 MCP 服务器工具（filesystem / fetch），method 为 tools/list 或 tools/call",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"server":    map[string]interface{}{"type": "string", "description": "服务器名 filesystem 或 fetch"},
				"method":    map[string]interface{}{"type": "string", "description": "tools/list 或 tools/call"},
				"tool":      map[string]interface{}{"type": "string", "description": "要调用的工具名"},
				"arguments": map[string]interface{}{"type": "object", "description": "工具参数"},
			}, "required": []string{"server", "method"}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				server, _ := a["server"].(string)
				method, _ := a["method"].(string)
				toolName, _ := a["tool"].(string)
				args, _ := a["arguments"].(map[string]interface{})
				return callExternalMCP(server, method, toolName, args)
			},
		},
		"tars_mcp_discover": {
			Name: "tars_mcp_discover", Description: "发现本地可连接的 AI 服务与 MCP 服务器状态",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			Handler: func(a map[string]interface{}) (interface{}, error) {
				return discoverLocal(), nil
			},
		},
	}
}

func executeTool(name string, args map[string]interface{}) (interface{}, error) {
	// v2.0.0：customTools 用户自定义工具（SSRF 加固执行）
	if _, isCustom := findCustomTool(name); isCustom {
		if !moduleEnabledByID("customTools") {
			return nil, fmt.Errorf("工具所属模块 customTools 已关闭")
		}
		logMsg("[TOOL] " + name + " 被调用（custom）")
		return executeCustomTool(name, args)
	}
	// v3.4.0：连接器生态（conn_<template>，SSRF 加固执行 + 审计）
	if strings.HasPrefix(name, "conn_") {
		if !moduleEnabledByID("connectors") {
			return nil, fmt.Errorf("工具所属模块 connectors 已关闭")
		}
		logMsg("[TOOL] " + name + " 被调用（connector）")
		return executeConnector(strings.TrimPrefix(name, "conn_"), args)
	}
	t, ok := tools[name]
	if !ok {
		return nil, fmt.Errorf("工具不存在: %s", name)
	}
	if m := toolModuleOf(name); !moduleEnabledByID(m) {
		return nil, fmt.Errorf("工具所属模块 %s 已关闭（modules.%s=false）", m, m)
	}
	logMsg(fmt.Sprintf("[TOOL] %s 被调用", name))
	return t.Handler(args)
}

// registerV2Tools v2.0.0 新增内置工具（initTools 之后调用）
func registerV2Tools() {
	if tools == nil {
		tools = map[string]Tool{}
	}
	tools["tars_hardware_advisor"] = Tool{
		Name:        "tars_hardware_advisor",
		Description: "硬件评估与提升建议：CPU/内存/磁盘/GPU 四维评分 + 可执行建议（如内存 8GB 建议跑 3B 以下 Q4_K_M 模型）",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			return assessHardware(), nil
		},
	}
}

func handleToolCall(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/tools/")
	var args map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}
	// v3.2.2 守门人：身份感知的工具执行（策略门 + 二次确认），见 gatekeeper.go
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	result, err := executeToolAs(id, name, args)
	if err != nil {
		if req, isConfirm := err.(*gkConfirmationRequired); isConfirm {
			gkWriteConfirmation(w, req, nil)
			return
		}
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"success": true, "result": result})
}

func toolNames() []string {
	var names []string
	for _, t := range tools {
		if moduleEnabledByID(toolModuleOf(t.Name)) {
			names = append(names, t.Name)
		}
	}
	if moduleEnabledByID("customTools") {
		for _, ct := range customToolList() {
			names = append(names, ct.Name)
		}
	}
	// v3.4.0：启用的连接器实例（conn_<template>）
	if moduleEnabledByID("connectors") {
		for _, lc := range enabledConnectors() {
			names = append(names, connectorToolName(lc.Inst.Template))
		}
	}
	sort.Strings(names)
	return names
}



// ===================== v3.2.2 治理层工具注册 =====================

// registerV322Tools v3.2.2 共享记忆 / 共享信息 / 上下文拓展 MCP 工具
// （initTools 之后调用；身份经 executeToolAs 以保留参数键 _tsgIdentity 注入）
func registerV322Tools() {
	if tools == nil {
		tools = map[string]Tool{}
	}
	strProp := func(desc string) map[string]interface{} {
		return map[string]interface{}{"type": "string", "description": desc}
	}
	numProp := func(desc string) map[string]interface{} {
		return map[string]interface{}{"type": "number", "description": desc}
	}

	tools["tars_shared_memory_set"] = Tool{
		Name:        "tars_shared_memory_set",
		Description: "写入共享记忆（命名空间化 KV：user/tenant/global，读走就近覆盖解析链）。跨客户端/跨会话共享",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"key": strProp("记忆键（≤256 字符）"), "value": strProp("记忆值（≤64KB）"),
			"namespace": strProp("user（默认）/ tenant / global"),
			"ttlSeconds": numProp("可选 TTL（秒），过期自动失效"),
		}, "required": []string{"key", "value"}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, ok := identityFromArgs(a)
			if !ok {
				return nil, fmt.Errorf("共享记忆写入需要身份（经 /api/tools/ 或 /mcp 调用）")
			}
			key, _ := a["key"].(string)
			value, _ := a["value"].(string)
			ns, _ := a["namespace"].(string)
			ttl := 0.0
			if t, ok := a["ttlSeconds"].(float64); ok {
				ttl = t
			}
			e, err := smSet(id, ns, key, value, time.Duration(ttl*float64(time.Second)))
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "key": key, "revision": e.Revision}, nil
		},
	}

	tools["tars_shared_memory_get"] = Tool{
		Name:        "tars_shared_memory_get",
		Description: "按解析链（user → tenant → global）读取共享记忆键",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"key": strProp("记忆键"),
		}, "required": []string{"key"}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, _ := identityFromArgs(a)
			key, _ := a["key"].(string)
			e, ns, ok := smGet(id, key)
			if !ok {
				return map[string]interface{}{"found": false, "key": key}, nil
			}
			return map[string]interface{}{"found": true, "key": key, "value": e.Value, "namespace": ns,
				"updatedBy": e.UpdatedBy, "updatedAt": e.UpdatedAt, "revision": e.Revision}, nil
		},
	}

	tools["tars_shared_memory_list"] = Tool{
		Name:        "tars_shared_memory_list",
		Description: "列出可见共享记忆（解析链合并视图，同键就近层覆盖）",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"prefix": strProp("可选键前缀过滤"),
		}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, _ := identityFromArgs(a)
			prefix, _ := a["prefix"].(string)
			return map[string]interface{}{"items": smList(id, prefix)}, nil
		},
	}

	tools["tars_shared_memory_delete"] = Tool{
		Name:        "tars_shared_memory_delete",
		Description: "删除共享记忆键（仅限自己可写的命名空间）",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"key": strProp("记忆键"), "namespace": strProp("user（默认）/ tenant / global"),
		}, "required": []string{"key"}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, ok := identityFromArgs(a)
			if !ok {
				return nil, fmt.Errorf("共享记忆删除需要身份")
			}
			key, _ := a["key"].(string)
			ns, _ := a["namespace"].(string)
			deleted, err := smDelete(id, ns, key)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "deleted": deleted}, nil
		},
	}

	tools["tars_shared_info_add"] = Tool{
		Name:        "tars_shared_info_add",
		Description: "新增共享信息条目（fact/preference/note/link，带标签与置信度，供上下文组装检索）",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"title": strProp("标题（≤200 字符）"), "content": strProp("内容（≤32KB）"),
			"type": strProp("fact / preference / note / link（默认 note）"),
			"tags": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
			"scope": strProp("tenant（默认）/ global（仅全局角色）"),
			"confidence": map[string]interface{}{"type": "number", "description": "0~1，默认 0.5"},
		}, "required": []string{"title", "content"}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, ok := identityFromArgs(a)
			if !ok {
				return nil, fmt.Errorf("共享信息写入需要身份")
			}
			title, _ := a["title"].(string)
			content, _ := a["content"].(string)
			typ, _ := a["type"].(string)
			scope, _ := a["scope"].(string)
			conf := 0.5
			if c, ok := a["confidence"].(float64); ok {
				conf = c
			}
			var tags []string
			if raw, ok := a["tags"].([]interface{}); ok {
				for _, t := range raw {
					if s, ok := t.(string); ok {
						tags = append(tags, s)
					}
				}
			}
			rec, err := siAdd(id, typ, title, content, tags, scope, conf)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "id": rec.ID, "revision": rec.Revision}, nil
		},
	}

	tools["tars_shared_info_search"] = Tool{
		Name:        "tars_shared_info_search",
		Description: "检索共享信息（标题/标签/内容命中排序，租户隔离）",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"q": strProp("关键词（空=按时间全览）"), "type": strProp("可选类型过滤"),
			"limit": numProp("返回上限（默认 20，最大 200）"),
		}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, _ := identityFromArgs(a)
			q, _ := a["q"].(string)
			typ, _ := a["type"].(string)
			limit := 20
			if l, ok := a["limit"].(float64); ok && l > 0 {
				limit = int(l)
			}
			recs := siSearch(id, q, typ, limit)
			return map[string]interface{}{"items": recs, "count": len(recs)}, nil
		},
	}

	tools["tars_shared_info_delete"] = Tool{
		Name:        "tars_shared_info_delete",
		Description: "删除共享信息条目（本租户条目本租户可删，global 条目仅全局角色）",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"id": strProp("条目 ID（si_ 前缀）"),
		}, "required": []string{"id"}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, ok := identityFromArgs(a)
			if !ok {
				return nil, fmt.Errorf("共享信息删除需要身份")
			}
			recID, _ := a["id"].(string)
			deleted, err := siDelete(id, recID)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "deleted": deleted}, nil
		},
	}

	tools["tars_context_build"] = Tool{
		Name:        "tars_context_build",
		Description: "组装上下文包：共享信息 + 共享记忆按租户隔离与预算合成为可注入 system 文本",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"topic": strProp("可选主题（提升相关共享信息排序）"),
			"includeSharedInfo": map[string]interface{}{"type": "boolean", "description": "默认 true"},
			"includeSharedMemory": map[string]interface{}{"type": "boolean", "description": "默认 true"},
			"maxChars": numProp("字符预算（默认 4096）"),
		}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, _ := identityFromArgs(a)
			opts := ContextBuildOpts{IncludeSharedInfo: true, IncludeSharedMemory: true}
			if v, ok := a["topic"].(string); ok {
				opts.Topic = v
			}
			if v, ok := a["includeSharedInfo"].(bool); ok {
				opts.IncludeSharedInfo = v
			}
			if v, ok := a["includeSharedMemory"].(bool); ok {
				opts.IncludeSharedMemory = v
			}
			if v, ok := a["maxChars"].(float64); ok && v > 0 {
				opts.MaxChars = int(v)
			}
			pack := buildContextPack(id, opts)
			return pack, nil
		},
	}

	tools["tars_context_pack_save"] = Tool{
		Name:        "tars_context_pack_save",
		Description: "保存命名上下文包（可复用/分享，本租户可见）",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"name": strProp("包名（≤100 字符）"), "text": strProp("包内容（≤64KB，可先用 tars_context_build 生成）"),
		}, "required": []string{"name", "text"}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, ok := identityFromArgs(a)
			if !ok {
				return nil, fmt.Errorf("保存上下文包需要身份")
			}
			name, _ := a["name"].(string)
			text, _ := a["text"].(string)
			if err := ctxPackSave(id, name, text); err != nil {
				return nil, err
			}
			return map[string]interface{}{"success": true, "name": name}, nil
		},
	}

	tools["tars_context_pack_load"] = Tool{
		Name:        "tars_context_pack_load",
		Description: "读取命名上下文包（本租户或全局角色）",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"name": strProp("包名"),
		}, "required": []string{"name"}},
		Handler: func(a map[string]interface{}) (interface{}, error) {
			id, ok := identityFromArgs(a)
			if !ok {
				return nil, fmt.Errorf("读取上下文包需要身份")
			}
			name, _ := a["name"].(string)
			text, err := ctxPackLoad(id, name)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"name": name, "text": text}, nil
		},
	}
}
