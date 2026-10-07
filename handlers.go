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
	// v3.0.4 [MT_AUDIT_ISOLATION]：审计按租户硬隔离——
	//   global_admin/global_auditor 可查全部（?tenant=x 定向跨租户查询，记 AUDIT_CROSS_TENANT_ACCESS）
	//   admin/auditor 仅本租户；team_lead 仅本租户本组；user/readonly 矩阵层已拒
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	qTenant := r.URL.Query().Get("tenant")
	qGroup := r.URL.Query().Get("group")
	tenant, groups, cross := auditTenantScope(id, qTenant, qGroup)
	if cross {
		auditLogT("AUDIT_CROSS_TENANT_ACCESS", tenant, qGroup, id.Name,
			fmt.Sprintf("global 角色跨租户查询审计日志 tenant=%s group=%s", tenant, qGroup))
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
	// [MT_AUDIT_ISOLATION] 行级强制过滤：非本租户行绝不出网（旧行 TENANT 缺失按 system 处理）
	lines = filterAuditLines(lines, tenant, groups, id.Global)
	auditLogT("AUDIT_LOG_VIEW", id.Tenant, strings.Join(id.Groups, ","), id.Name,
		fmt.Sprintf("查看审计日志 %d 条（租户=%s）", len(lines), tenant))
	writeJSON(w, map[string]interface{}{"logs": lines, "count": len(lines), "tenant": tenant})
}

// validateConfigValue v2.0.0 值域校验：安全与档位类配置拒绝非法值。
// handleConfig POST 与 set_config 内置工具共用，防止绕过（安全模块不可关的铁律在值层也封死）。
func validateConfigValue(path string, val interface{}) bool {
	s, _ := val.(string)
	switch path {
	case "security.mode":
		return s == "normal" || s == "strict"
	case "security.firewall.policy":
		return s == fwPolicyPassive || s == fwPolicyDynamicBan || s == fwPolicyOSLink
	case "security.firewall.banDuration":
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 || d > 24*time.Hour {
			return false
		}
	case "direct.transport":
		return s == "native" || s == "grpc-sidecar"
	case "search.engine":
		return s == "builtin" || s == "serper"
	// v3.0.1 Tier 1：开关必须是布尔；TTL 数值域 0-86400（读取时 60-3600 clamp，0=默认 300）
	case "tier1.enabled":
		_, ok := val.(bool)
		return ok
	case "tier1.cacheTtlSeconds":
		f, ok := val.(float64)
		return ok && f >= 0 && f <= 86400
	}
	return true
}

// handleKeyRotate v3.7.1 P2-10：管理员主动轮换网关密钥
func handleKeyRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	newKey := rotateGatewayKey()
	cfgMu.Lock()
	cfg.Security.APIKey = newKey
	cfgMu.Unlock()
	saveConfig()
	auditLog("SECURITY_KEY_ROTATED", "admin", "管理员通过 UI 主动轮换网关密钥")
	logMsg("[SECURITY] 网关密钥已主动轮换，新密钥见 gateway-key.txt")
	writeJSON(w, map[string]interface{}{"success": true, "message": "密钥已轮换，请查看 gateway-key.txt"})
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
		// 拒绝项先暂存、解锁后再落审计——auditLog 内部会取 cfgMu 读锁，
		// 持写锁期间调用会自死锁并把写锁一起拖死（教训：锁区内禁止任何取读锁的调用）
		var rejected []string
		for path, val := range body {
			if !isConfigPathAllowed(path) {
				// v3.0.4 [ZT_CHANGE_AUDIT]：白名单外路径（含 tenants/users/security.apiKey/
				// 白名单类安全项）不允许经 API 修改——拒绝并审计，绝不静默跳过
				rejected = append(rejected, fmt.Sprintf("%s=… 不在 API 可修改白名单（零信任：租户/用户/密钥/白名单项仅 config.json 管理）", path))
				continue
			}
			// v2.0.0 值域校验（共享函数，与 set_config 工具同一条防线）
			if !validateConfigValue(path, val) {
				rejected = append(rejected, fmt.Sprintf("%s=%v 非法（值域校验拒绝）", path, val))
				continue
			}
			setJSONPath(root, path, val)
			applied++
		}
		data, _ := json.Marshal(root)
		err := json.Unmarshal(data, &cfg)
		cfgMu.Unlock()
		for _, rj := range rejected {
			auditLog("CONFIG_REJECTED", "-", rj)
		}
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid config value"})
			return
		}
		if applied > 0 {
			// 档位类配置变更后立即对齐（不等热重载轮询）；
			// 必须在 cfgMu.Unlock() 之后调用——reconcile 内部会再取读锁，持写锁时调用会自死锁
			saveConfig()
			reconcileModuleWorkers()
			firewallReconcile()
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
	ctools := customToolList()
	for i := range ctools { // secretHeaders 脱敏
		for k := range ctools[i].SecretHeaders {
			ctools[i].SecretHeaders[k] = "***"
		}
	}
	// v3.7.1 P1-4：按角色分级返回配置（viewer/readonly/user 看不到完整 security/users）
	id, _ := identityFromRequest(r)
	secOut := map[string]interface{}{
		"wafEnabled":      wafOn,
		"mode":            mode,
		"apiKeySet":       apiKeySet,
		"auditLogEnabled": auditOn,
	}
	resp := map[string]interface{}{
		"server": map[string]interface{}{
			"port":       port,
			"listenAddr": listenAddr,
		},
		"modules":      moduleStatusSummary(),
		"firewall":     firewallStatusSnapshot(),
		"direct":       directConfigSummary(),
		"customTools":  ctools,
		"customAgents": customAgentList(),
		"localModels":  getLocalModelList(),
		"fallback": map[string]interface{}{
			"enable":      true,
			"maxRetries":  3,
			"autoRecover": true,
		},
		"security": secOut,
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
	}
	// admin/auditor/global 角色可见完整 security + users；其他角色只保留基础 security 字段
	if id.Role == "admin" || id.Role == "auditor" || id.Role == "global_admin" || id.Role == "global_auditor" || id.Role == "team_lead" {
		resp["users"] = users
	} else {
		delete(secOut, "apiKeySet")
	}
	writeJSON(w, resp)
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
