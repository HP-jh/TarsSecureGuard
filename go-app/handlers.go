package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"
)

// ===================== 前端 =====================
func handleFrontend(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" && r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(frontendFS, "frontend/index.html")
	if err != nil {
		http.Error(w, "Frontend not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

// ===================== 状态 =====================
func statusPayload() map[string]interface{} {
	uptime := time.Since(startTime).Milliseconds()
	ms := getModels()
	mu.Lock()
	total, succ, fail, blocks := totalReq, successReq, failReq, wafBlocks
	mu.Unlock()
	cfgMu.RLock()
	mode := cfg.Security.Mode
	cfgMu.RUnlock()
	return map[string]interface{}{
		"version":     version,
		"shield_mode": mode,
		"offline":     false,
		"stats": map[string]interface{}{
			"totalRequest":   total,
			"successRequest": succ,
			"failRequest":    fail,
			"wafBlockCount":  blocks,
			"uptime":         uptime,
		},
		"device": getDeviceInfo(),
		"models": ms,
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, statusPayload())
}

func handleFallback(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"enabled":     true,
		"threshold":   3,
		"target":      "local",
		"autoRecover": true,
		"history":     []interface{}{},
	})
}

func handleSecurity(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	blocks := wafBlocks
	mu.Unlock()
	cfgMu.RLock()
	mode := cfg.Security.Mode
	wafOn := cfg.Security.WAFEnabled
	cfgMu.RUnlock()
	writeJSON(w, map[string]interface{}{
		"wafBlockCount":         blocks,
		"threatIntelBlockCount": 0,
		"domainBlockCount":      0,
		"safeModeTriggerCount":  0,
		"mode":                  mode,
		"wafEnabled":            wafOn,
		"firewall":              firewallStatus(),
	})
}

func handleWAFLogs(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	l := append([]string(nil), wafLogs...)
	mu.Unlock()
	writeJSON(w, map[string]interface{}{"logs": l})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	l := append([]string(nil), logs...)
	mu.Unlock()
	writeJSON(w, map[string]interface{}{"logs": l})
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	// POST：批量保存白名单配置（{ "security.mode": "strict", "search.engine": "serper" }）
	if r.Method == http.MethodPost {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
			return
		}
		cfgMu.Lock()
		cfgJSON, _ := json.Marshal(cfg)
		var root map[string]interface{}
		json.Unmarshal(cfgJSON, &root)
		applied := 0
		for path, val := range body {
			if !isConfigPathAllowed(path) {
				continue
			}
			setJSONPath(root, path, val)
			applied++
		}
		data, _ := json.Marshal(root)
		err := json.Unmarshal(data, &cfg)
		cfgMu.Unlock()
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid config value"})
			return
		}
		if applied > 0 {
			saveConfig()
			logMsg(fmt.Sprintf("[CONFIG] 已保存 %d 项配置", applied))
		}
		writeJSON(w, map[string]interface{}{"success": true, "applied": applied})
		return
	}
	cfgMu.RLock()
	eng := cfg.Search.Engine
	hasKey := cfg.Search.APIKey != ""
	cloudOpen := cfg.Cloud.OpenAI.Name
	cloudDeep := cfg.Cloud.DeepSeek.Name
	extServers := cfg.MCP.ExternalServers
	wafOn := cfg.Security.WAFEnabled
	mode := cfg.Security.Mode
	apiKeySet := cfg.Security.APIKey != ""
	cfgMu.RUnlock()
	writeJSON(w, map[string]interface{}{
		"server": map[string]interface{}{
			"port":       port,
			"listenAddr": "127.0.0.1",
		},
		"localModels": getLocalModelList(),
		"fallback": map[string]interface{}{
			"enable":      true,
			"maxRetries":  3,
			"autoRecover": true,
		},
		"security": map[string]interface{}{
			"wafEnabled": wafOn,
			"mode":       mode,
			"apiKeySet":  apiKeySet,
		},
		"search": map[string]interface{}{
			"engine": eng,
			"apiKey": hasKey,
		},
		"cloud": map[string]interface{}{
			"openai":   cloudOpen,
			"deepseek": cloudDeep,
		},
		"mcp": map[string]interface{}{
			"externalServers": extServers,
		},
		"tools": toolNames(),
	})
}

// ===================== 搜索 / 占位 / 发现 =====================
func handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}
	query := body["query"]
	if query == "" {
		query = body["q"]
	}
	res, err := webSearch(query, 8)
	if err != nil {
		writeJSON(w, map[string]interface{}{"query": query, "results": []interface{}{}, "message": err.Error()})
		return
	}
	writeJSON(w, res)
}

// handleFeishu 为飞书 API 占位端点（保留给后续集成）
func handleFeishu(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"endpoint": r.URL.Path,
		"message":  "飞书 API 占位。请在 config.json 配置 App ID/Secret 后启用。",
	})
}

func handleDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	logMsg("[DISCOVERY] 扫描开始")
	writeJSON(w, map[string]interface{}{"success": true, "message": "Scan started"})
}

func handleDiscoveryResults(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, discoverLocal())
}
