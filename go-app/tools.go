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
					path = `D:\\`
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
	t, ok := tools[name]
	if !ok {
		return nil, fmt.Errorf("工具不存在: %s", name)
	}
	logMsg("[TOOL] " + name + " 被调用")
	return t.Handler(args)
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
	result, err := executeTool(name, args)
	if err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"success": true, "result": result})
}

func toolNames() []string {
	var names []string
	for _, t := range tools {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return names
}
