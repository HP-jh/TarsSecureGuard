package main

// v3.0.0 D 线：MCP stdio 模式（--mcp-stdio）—— "Your AI's safety belt" 落地件
//
// 设计依据：架构方案第三节 D 线 + 锦衣卫裁定 4（文件工具收敛）：
//   - 任何本地 agent（Claude Code / Cursor / 其它 MCP 客户端）接入 TSG，
//     chat 自动过全套安全链（WAF → 语义分级分流 → 限流 → 信誉 → 路由）
//   - 协议：JSON-RPC 2.0 over stdio（MCP 规范），方法 initialize / tools/list / tools/call
//   - 工具集：tars_guarded_chat / tars_guard_status / tars_route_preview /
//     tars_model_score / tars_module_schema / tars_ip_reputation_unban
//   - 文件工具：本版不提供（锦衣卫裁定 4 的收敛位 —— 默认关的直接形态）；
//     v3.0.x 如需增加，必须带 路径白名单 + filepath.Clean + 读写分设开关 + 进程/PID 审计
//   - unban 等管理操作要求请求方在 env 提供 TSG_ADMIN_KEY，全程审计

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// ===================== JSON-RPC 基础 =====================

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// ===================== MCP 工具定义 =====================

type mcpToolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

func mcpToolList() []mcpToolDef {
	obj := func(props map[string]interface{}, required []string) map[string]interface{} {
		if required == nil {
			required = []string{}
		}
		return map[string]interface{}{"type": "object", "properties": props, "required": required}
	}
	str := func(desc string) map[string]interface{} { return map[string]interface{}{"type": "string", "description": desc} }
	msgArr := map[string]interface{}{
		"type": "array",
		"items": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"role":    map[string]interface{}{"type": "string", "enum": []string{"user", "assistant", "system"}},
				"content": str("消息内容"),
			},
			"required": []string{"role", "content"},
		},
	}
	return []mcpToolDef{
		{
			Name:        "tars_guarded_chat",
			Description: "受防护对话：消息经过 TSG 全套安全链（WAF / PII 脱敏 / 语义分级分流 fail-close / 限流 / 信誉）后路由到本地或云端模型。任何 agent 通过本工具获得 TSG 安全带。",
			InputSchema: obj(map[string]interface{}{"messages": msgArr, "model": str("模型名，留空自动路由")}, []string{"messages"}),
		},
		{
			Name:        "tars_guard_status",
			Description: "资源守护器状态：当前分级（L0-L3）、内存软上限、RSS、eco 档、goroutine 数、模型加载熔断。",
			InputSchema: obj(map[string]interface{}{}, nil),
		},
		{
			Name:        "tars_route_preview",
			Description: "路由预演：给定模型名，展示两阶段路由（静态规则 + ε-greedy bandit）将如何决策，不实际调用。需要管理员密钥。",
			InputSchema: obj(map[string]interface{}{"model": str("模型名")}, []string{"model"}),
		},
		{
			Name:        "tars_model_score",
			Description: "模型评分榜：运行时分（成功率×时延）融合 lm-eval-harness 离线评测（相对参考，诚实标注）。",
			InputSchema: obj(map[string]interface{}{}, nil),
		},
		{
			Name:        "tars_module_schema",
			Description: "模块注册表与开关状态：全部模块 ID、描述、分类、依赖拓扑。",
			InputSchema: obj(map[string]interface{}{}, nil),
		},
		{
			Name:        "tars_ip_reputation_unban",
			Description: "解封指定 IP 并重置信誉分（100）。需要管理员密钥，全程审计。",
			InputSchema: obj(map[string]interface{}{"ip": str("要解封的 IP 地址")}, []string{"ip", "adminKey"}),
		},
	}
}

// ===================== 工具执行 =====================

type mcpCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// mcpAdminKeyOK 管理操作密钥校验（env TSG_ADMIN_KEY 或参数 adminKey）
func mcpAdminKeyOK(args map[string]interface{}) bool {
	want := gatewayAPIKey()
	got, _ := args["adminKey"].(string)
	if got == "" {
		got = os.Getenv("TSG_ADMIN_KEY")
	}
	return want != "" && got == want
}

func mcpExecute(p mcpCallParams) (interface{}, *rpcError) {
	switch p.Name {
	case "tars_guarded_chat":
		msgsRaw, _ := p.Arguments["messages"].([]interface{})
		if len(msgsRaw) == 0 {
			return nil, &rpcError{Code: -32602, Message: "messages 不能为空"}
		}
		var msgs []Message
		for _, m := range msgsRaw {
			mm, _ := m.(map[string]interface{})
			role, _ := mm["role"].(string)
			content, _ := mm["content"].(string)
			msgs = append(msgs, Message{Role: role, Content: content})
		}
		model, _ := p.Arguments["model"].(string)
		// 全套安全链：语义分级分流（fail-close，AI 只能加严）
		lastUser := sgLastUserText(msgs)
		if dec := sgClassify(lastUser, "127.0.0.1"); dec.Verdict == sgBlock {
			auditLog("MCP_SEMANTIC_BLOCK", "mcp-stdio", fmt.Sprintf("fp=%s %s", dec.Fp, dec.Reason))
			return map[string]interface{}{
				"blocked": true, "reason": dec.Reason, "source": dec.Source,
				"notice":  "内容被 TSG 安全护栏拦截：AI 判定只能加严，不可放宽",
			}, nil
		}
		content, backend, _, err := routeChatSmart(model, msgs, "user")
		if err != nil {
			return nil, &rpcError{Code: -32000, Message: err.Error()}
		}
		auditLog("MCP_GUARDED_CHAT", "mcp-stdio", fmt.Sprintf("backend=%s msgs=%d", backend, len(msgs)))
		return map[string]interface{}{"content": content, "backend": backend, "blocked": false}, nil

	case "tars_guard_status":
		return guardStatusSnapshot(), nil

	case "tars_route_preview":
		if !mcpAdminKeyOK(p.Arguments) {
			return nil, &rpcError{Code: -32001, Message: "需要管理员密钥（参数 adminKey 或环境变量 TSG_ADMIN_KEY）"}
		}
		model, _ := p.Arguments["model"].(string)
		auditLog("MCP_ROUTE_PREVIEW", "mcp-stdio", model)
		return routePreview(model, "admin"), nil

	case "tars_model_score":
		return scoreboardSnapshot(), nil

	case "tars_module_schema":
		modMu.RLock()
		states := map[string]bool{}
		for k, v := range modStates {
			states[k] = v
		}
		modMu.RUnlock()
		var out []map[string]interface{}
		for _, m := range moduleRegistry {
			enabled, ok := states[m.ID]
			if !ok {
				enabled = m.Default
			}
			out = append(out, map[string]interface{}{
				"id": m.ID, "name": m.Name, "description": m.Description,
				"category": m.Category, "enabled": enabled, "deps": m.Deps,
			})
		}
		return map[string]interface{}{"modules": out}, nil

	case "tars_ip_reputation_unban":
		if !mcpAdminKeyOK(p.Arguments) {
			return nil, &rpcError{Code: -32001, Message: "需要管理员密钥（参数 adminKey 或环境变量 TSG_ADMIN_KEY）"}
		}
		ip, _ := p.Arguments["ip"].(string)
		if ip == "" {
			return nil, &rpcError{Code: -32602, Message: "ip 不能为空"}
		}
		ipRepUnban("mcp-stdio", ip)
		return map[string]interface{}{"unbanned": ip, "score": ipRepScore(ip)}, nil

	default:
		return nil, &rpcError{Code: -32601, Message: "未知工具: " + p.Name}
	}
}

// ===================== 主循环 =====================

// runMCPStdio --mcp-stdio 入口：逐行读 JSON-RPC，写响应到 stdout
func runMCPStdio() {
	logMsg("[MCP] stdio 模式启动：v" + version + "，工具 " + fmt.Sprint(len(mcpToolList())) + " 个")
	reader := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	dec := json.NewDecoder(reader)
	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return
			}
			continue // 非 JSON 行：忽略（容错），MCP 客户端偶尔发注释放行
		}
		resp := handleMCPMethod(req)
		b, _ := json.Marshal(resp)
		out.WriteString(string(b) + "\n")
		out.Flush()
	}
}

func handleMCPMethod(req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]interface{}{"name": "tarssecureguard", "version": version},
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
		}}
	case "notifications/initialized", "initialized":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID} // 通知：无需回包（ID 为空时序列化即通知）
	case "tools/list":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{"tools": mcpToolList()}}
	case "tools/call":
		var p mcpCallParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "params 解析失败"}}
		}
		result, rerr := mcpExecute(p)
		if rerr != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rerr}
		}
		// MCP 工具结果包装为 content 数组（text 块）+ structuredContent
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"content":            []map[string]interface{}{{"type": "text", "text": mcpResultText(result)}},
			"structuredContent":  result,
		}}
	case "ping":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{}}
	default:
		if len(req.ID) == 0 {
			return rpcResponse{JSONRPC: "2.0"} // 通知类未知方法：不回包
		}
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "未知方法: " + req.Method}}
	}
}

// mcpResultText 把结构化结果转为可读文本（MCP text 块）
func mcpResultText(result interface{}) string {
	b, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprint(result)
	}
	return string(b)
}

// ===================== 快照辅助（供 MCP 与 HTTP 端点共用） =====================

func guardStatusSnapshot() map[string]interface{} {
	// 复用 handleGuardStatus 的数据组装逻辑（无 ResponseWriter 版本）
	guardMu.Lock()
	tier := guardTier
	eco := guardEco
	limit := memLimit
	l3at := guardL3At
	fuse := modelLoadFuse
	guardMu.Unlock()
	tierNames := map[int]string{0: "L0 正常", 1: "L1 黄色(降级非核心)", 2: "L2 橙色(熔断高耗)", 3: "L3 红色(停机流程)"}
	return map[string]interface{}{
		"tier": tierNames[tier], "tierLevel": tier, "ecoMode": eco,
		"memLimitMB": limit >> 20, "rssMB": currentRSSMB(),
		"goroutines": runtime.NumGoroutine(), "modelLoadFuse": fuse, "lastL3At": l3at.Unix(),
	}
}

func scoreboardSnapshot() map[string]interface{} {
	rtMu.Lock()
	arms := map[string]*rtArm{}
	for k, v := range rtSt.Arms {
		cp := *v
		arms[k] = &cp
	}
	eps := rtSt.Epsilon
	rtMu.Unlock()
	var rows []map[string]interface{}
	for model, arm := range arms {
		rows = append(rows, sbFused(arm, model))
	}
	return map[string]interface{}{
		"rows": rows, "epsilon": eps,
		"disclaimer": "lm-eval 分数为同任务集内相对参考，非绝对能力值",
	}
}

// mcpIsStdioFlag 命令行判断
func mcpIsStdioFlag(args []string) bool {
	for _, a := range args {
		if a == "--mcp-stdio" || strings.HasPrefix(a, "--mcp-stdio=") {
			return true
		}
	}
	return false
}
