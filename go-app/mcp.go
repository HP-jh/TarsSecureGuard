package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

func handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	if tool, _ := body["tool"].(string); tool == "_list" {
		var list []map[string]interface{}
		for _, t := range tools {
			list = append(list, map[string]interface{}{"name": t.Name, "description": t.Description})
		}
		sort.Slice(list, func(i, j int) bool { return list[i]["name"].(string) < list[j]["name"].(string) })
		writeJSON(w, map[string]interface{}{"tools": list})
		return
	}

	if tool, _ := body["tool"].(string); tool != "" {
		args, _ := body["args"].(map[string]interface{})
		if args == nil {
			args = map[string]interface{}{}
		}
		result, err := executeTool(tool, args)
		if err != nil {
			writeJSON(w, map[string]interface{}{"error": err.Error(), "tool": tool})
			return
		}
		writeJSON(w, map[string]interface{}{"result": result, "tool": tool})
		return
	}

	method, _ := body["method"].(string)
	switch method {
	case "initialize":
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      body["id"],
			"result": map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{"listChanged": false},
				},
				"serverInfo": map[string]interface{}{"name": "tars-secure-guard", "version": version},
			},
		})
		return
	case "tools/list":
		var list []map[string]interface{}
		for _, t := range tools {
			list = append(list, map[string]interface{}{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": t.InputSchema,
			})
		}
		sort.Slice(list, func(i, j int) bool { return list[i]["name"].(string) < list[j]["name"].(string) })
		writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": body["id"], "result": map[string]interface{}{"tools": list}})
		return
	case "tools/call":
		params, _ := body["params"].(map[string]interface{})
		name, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]interface{})
		if args == nil {
			args = map[string]interface{}{}
		}
		result, err := executeTool(name, args)
		if err != nil {
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": body["id"],
				"result": map[string]interface{}{
					"content": []map[string]interface{}{{"type": "text", "text": "ERROR: " + err.Error()}},
					"isError": true,
				},
			})
			return
		}
		text, _ := json.Marshal(result)
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0", "id": body["id"],
			"result": map[string]interface{}{
				"content": []map[string]interface{}{{"type": "text", "text": string(text)}},
			},
		})
		return
	case "notifications/initialized", "ping":
		writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": body["id"], "result": map[string]interface{}{}})
		return
	default:
		writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": body["id"], "error": map[string]interface{}{"code": -32601, "message": "Method not found: " + method}})
	}
}

func callExternalMCP(serverName, method, toolName string, args map[string]interface{}) (interface{}, error) {
	var server *ExtServer
	for i := range cfg.MCP.ExternalServers {
		if cfg.MCP.ExternalServers[i].Name == serverName {
			server = &cfg.MCP.ExternalServers[i]
			break
		}
	}
	if server == nil {
		return nil, fmt.Errorf("未注册的 MCP 服务器: %s（可用: %s）", serverName, externalServerNames())
	}
	if !server.Enabled {
		return nil, fmt.Errorf("MCP 服务器 %s 已禁用", serverName)
	}
	if _, err := os.Stat(server.Command); err != nil {
		return nil, fmt.Errorf("MCP 服务器 %s 命令不存在: %s", serverName, server.Command)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, server.Command, server.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 %s 失败: %v", serverName, err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	enc := json.NewEncoder(stdin)
	dec := json.NewDecoder(stdout)

	enc.Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2024-11-05", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "tars-gateway", "version": version}}})
	var initResp struct {
		ID     int             `json:"id"`
		Error  json.RawMessage `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := dec.Decode(&initResp); err != nil {
		return nil, fmt.Errorf("%s 初始化失败: %v", serverName, err)
	}
	if len(initResp.Error) > 0 && string(initResp.Error) != "null" {
		return nil, fmt.Errorf("%s 初始化错误: %s", serverName, string(initResp.Error))
	}
	enc.Encode(map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"})

	if method == "tools/list" {
		enc.Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]interface{}{}})
		var resp struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := dec.Decode(&resp); err != nil {
			return nil, err
		}
		if len(resp.Error) > 0 && string(resp.Error) != "null" {
			return nil, fmt.Errorf("tools/list 错误: %s", string(resp.Error))
		}
		var result map[string]interface{}
		json.Unmarshal(resp.Result, &result)
		return map[string]interface{}{"server": serverName, "tools": result["tools"]}, nil
	}

	if method == "tools/call" {
		params := map[string]interface{}{
			"name":      toolName,
			"arguments": args,
		}
		enc.Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": params})
		var resp struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := dec.Decode(&resp); err != nil {
			return nil, err
		}
		if len(resp.Error) > 0 && string(resp.Error) != "null" {
			return nil, fmt.Errorf("tools/call 错误: %s", string(resp.Error))
		}
		var result map[string]interface{}
		json.Unmarshal(resp.Result, &result)
		return map[string]interface{}{"server": serverName, "tool": toolName, "result": result}, nil
	}

	return nil, fmt.Errorf("不支持的方法: %s", method)
}

func externalServerNames() string {
	var names []string
	for _, s := range cfg.MCP.ExternalServers {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}
