package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

func handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	// 只允许 admin 查看审计日志（已在中间件 RBAC 中校验，此处额外确认）
	name, role, _ := userFromRequest(r)
	if role != "admin" {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "仅 admin 可查看审计日志"})
		return
	}
	// 读取当日审计日志文件
	lines := []string{}
	if logFileDir != "" {
		name := filepath.Join(logFileDir, fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02")))
		if data, err := os.ReadFile(name); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(line) != "" {
					lines = append(lines, line)
				}
			}
			// 限制返回最近 500 条
			if len(lines) > 500 {
				lines = lines[len(lines)-500:]
			}
		}
	}
	auditLog("AUDIT_LOG_VIEW", name, fmt.Sprintf("查看审计日志 %d 条", len(lines)))
	writeJSON(w, map[string]interface{}{"logs": lines, "count": len(lines)})
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
		uname, _, _ := userFromRequest(r)
		auditLog("CONFIG_CHANGE", uname, fmt.Sprintf("修改 %d 项配置", applied))
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
	auditOn := cfg.Security.AuditLogEnabled
	users := append([]User(nil), cfg.Users...)
	cfgMu.RUnlock()
	// 脱敏用户 Key
	for i := range users {
		users[i].APIKey = "***"
	}
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
			"wafEnabled":      wafOn,
			"mode":            mode,
			"apiKeySet":       apiKeySet,
			"auditLogEnabled": auditOn,
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
		"users": users,
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

// ===================== 统计面板 API（新增：v1.0.2 功能强化） =====================

// 按小时请求量统计：key 为 Unix 小时时间戳（time.Unix()/3600），供 /api/stats/history 查询
var (
	historyMu    sync.Mutex
	hourlyCounts = map[int64]int{}
)

// recordHourlyRequest 把当前小时的请求量 +1，并顺带清理 24 小时以前的旧桶（防 map 无限增长）
func recordHourlyRequest() {
	h := time.Now().Unix() / 3600
	historyMu.Lock()
	hourlyCounts[h]++
	for k := range hourlyCounts {
		if h-k >= 24 {
			delete(hourlyCounts, k)
		}
	}
	historyMu.Unlock()
}

// handleStats GET /api/stats —— 统计面板数据：
// 总请求数 / 成功率 / WAF 拦截数 / 平均响应时间 / 运行时长 / 当前模型 / 内存占用
func handleStats(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	total, succ, blocks := totalReq, successReq, wafBlocks
	totalMs, samples := respTotalMs, respSamples
	mu.Unlock()

	// 成功率：成功请求 / 总请求（百分比，保留两位小数；无请求时为 0）
	successRate := 0.0
	if total > 0 {
		successRate = float64(succ) / float64(total) * 100
	}
	// 平均响应时间：累计耗时 / 已计时请求数（毫秒）
	avgMs := 0.0
	if samples > 0 {
		avgMs = float64(totalMs) / float64(samples)
	}

	// 当前活跃模型：优先本地 GGUF 模型；未运行时回退展示自动发现的在线模型
	_, cur := modelState()
	activeModel := cur
	if activeModel == "" {
		for _, m := range getDiscoveredModels() {
			if m.Status == "online" {
				activeModel = m.ID
				break
			}
		}
	}

	// 进程内存占用（Go runtime 视角）
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	writeJSON(w, map[string]interface{}{
		"totalRequests":   total,
		"successRate":     fmt.Sprintf("%.2f%%", successRate),
		"wafBlocks":       blocks,
		"avgResponseTime": fmt.Sprintf("%.2fms", avgMs),
		"uptime":          time.Since(startTime).Round(time.Second).String(),
		"uptimeSeconds":   int64(time.Since(startTime).Seconds()),
		"activeModel":     activeModel,
		"memoryUsage": map[string]interface{}{
			"heapAllocMB": fmt.Sprintf("%.2f", float64(m.HeapAlloc)/1024/1024),
			"sysMB":       fmt.Sprintf("%.2f", float64(m.Sys)/1024/1024),
			"numGC":       m.NumGC,
		},
	})
}

// handleStatsHistory GET /api/stats/history —— 最近 24 小时每小时的请求量
// 返回 24 个小时桶（从 23 小时前到当前小时），count 为该小时内的请求数
func handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	curHour := time.Now().Unix() / 3600
	historyMu.Lock()
	history := make([]map[string]interface{}, 0, 24)
	for i := 23; i >= 0; i-- {
		h := curHour - int64(i)
		history = append(history, map[string]interface{}{
			"hour":  time.Unix(h*3600, 0).Format("2006-01-02 15:00"),
			"count": hourlyCounts[h],
		})
	}
	historyMu.Unlock()
	writeJSON(w, map[string]interface{}{"history": history})
}

// handleHealth GET /health —— 健康检查端点（免鉴权，供监控/负载均衡探活）
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status":  "ok",
		"version": version,
		"uptime":  time.Since(startTime).Round(time.Second).String(),
	})
}
