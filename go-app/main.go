package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed frontend/index.html
var frontendFS embed.FS

// ===================== 常量 =====================
const (
	port          = 18889
	modelPort     = 18890
	lmStudioBase  = "http://127.0.0.1:1234"
	ollamaBase    = "http://127.0.0.1:11434"
	version       = "1.0.2"
	apiKeyDefault = "tars-gateway-key"

	// 安全边界常量
	maxBodyBytes          = 5 << 20  // 单个 API 请求体上限 5MB
	maxFetchBytes         = 2 << 20  // 网页抓取/搜索单次读取上限 2MB
	maxOpenAPIBytes       = 10 << 20 // OpenAPI 文档读取上限 10MB
	maxModelDownloadBytes = 64 << 30 // 模型下载大小上限 64GB
	rateLimitWindow       = 10 * time.Second
	rateLimitMax          = 120 // 每 IP 每窗口最大请求数
	wafLogLimit           = 500
	memoryLimit           = 1024
)

// 运行时解析的应用路径（默认以 exe 所在目录为基准，见 resolvePaths）
var (
	modelDir   string
	llamaDir   string
	configPath string
)

// 授权读写根（文件工具安全边界，由 resolvePaths 依据配置与默认布局填充）
var allowedRoots []string

// ===================== 全局状态 =====================
var (
	mu           sync.Mutex
	logs         []string
	wafLogs      []string
	startTime    = time.Now()
	totalReq     int
	successReq   int
	failReq      int
	wafBlocks    int
	respTotalMs  int64 // 已处理请求的累计耗时（毫秒），用于计算平均响应时间
	respSamples  int64 // 已计时的请求次数
	modelProcess *os.Process
	modelRunning bool
	currentModel string // 当前加载的本地 GGUF 模型 id
	cfg          Config
	cfgMu        sync.RWMutex
	memory       = map[string]string{}
	memoryMu     sync.Mutex

	// 本地模型启动互斥（防止并发重复拉起 llama-server）
	starting bool

	// WAF 速率限制状态
	rlMu   sync.Mutex
	rlHits = map[string]*rlEntry{}

	// 可复用的 HTTP 客户端（避免每次请求新建连接）
	httpClientShort = &http.Client{Timeout: 30 * time.Second}
	httpClientLong  = &http.Client{Timeout: 300 * time.Second}
	downloadClient  = &http.Client{} // 模型下载专用：超时由请求 context 控制
)

// ===================== HTTP 主入口 =====================
func main() {
	// 日志文件持久化：初始化 logs/ 目录（失败不影响服务）
	initFileLogging()
	resolveConfigPath()
	loadConfig()
	initTools()
	loadMemory()
	ensureFirewallRule()

	logMsg(fmt.Sprintf("TarsSecureGuard v%s starting...", version))

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleFrontend)
	mux.HandleFunc("/health", handleHealth) // 健康检查（新增，免鉴权）
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/stats", handleStats)                // 统计面板（新增）
	mux.HandleFunc("/api/stats/history", handleStatsHistory) // 24 小时请求量（新增）
	mux.HandleFunc("/api/chat/completions", handleChat)
	mux.HandleFunc("/api/urgent/chat", handleUrgent)
	mux.HandleFunc("/api/admin/models", handleModels)
	mux.HandleFunc("/api/admin/models/start", handleModelStart)
	mux.HandleFunc("/api/admin/models/stop", handleModelStop)
	mux.HandleFunc("/api/admin/models/status", handleModelStatus)
	mux.HandleFunc("/api/admin/device", handleDevice)
	mux.HandleFunc("/api/admin/device/scan", handleDeviceScan)
	mux.HandleFunc("/api/admin/model/download", handleModelDownload)
	mux.HandleFunc("/api/admin/model/download/status", handleModelDownloadStatus)
	mux.HandleFunc("/api/admin/models/open", handleOpenModels)
	mux.HandleFunc("/api/admin/fallback/status", handleFallback)
	mux.HandleFunc("/api/admin/security/status", handleSecurity)
	mux.HandleFunc("/api/admin/security/waf-logs", handleWAFLogs)
	mux.HandleFunc("/api/admin/logs", handleLogs)
	mux.HandleFunc("/api/admin/audit-logs", handleAuditLogs)
	mux.HandleFunc("/api/admin/config", handleConfig)
	mux.HandleFunc("/api/search", handleSearch)
	mux.HandleFunc("/api/feishu/", handleFeishu)
	mux.HandleFunc("/mcp", handleMCP)
	mux.HandleFunc("/api/admin/v32/auto-discovery/scan", handleDiscoveryScan)
	mux.HandleFunc("/api/admin/v32/auto-discovery/results", handleDiscoveryResults)
	mux.HandleFunc("/api/admin/agents/", handleAgent)
	mux.HandleFunc("/api/tools/", handleToolCall)
	mux.HandleFunc("/v1/", handleV1)
	mux.HandleFunc("/v1", handleV1Root)

	server := &http.Server{
		Addr:           fmt.Sprintf("127.0.0.1:%d", port),
		Handler:        gatewayMiddleware(mux),
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   600 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	logMsg(fmt.Sprintf("Listening on http://127.0.0.1:%d", port))

	// 后台自动启动默认本地模型
	go func() {
		time.Sleep(2 * time.Second)
		startLocalModel("qwen2.5-3b")
	}()

	// 后台模型自动发现（新增）：启动 5 秒后首测，之后每 60 秒刷新一次
	go func() {
		time.Sleep(5 * time.Second)
		refreshDiscoveredModels()
		for {
			time.Sleep(60 * time.Second)
			refreshDiscoveredModels()
		}
	}()

	// 配置热重载（新增）：轮询监听 config.json 变化，变化时自动重载
	go watchConfig()

	// 打开浏览器
	go func() {
		time.Sleep(1 * time.Second)
		openBrowser(fmt.Sprintf("http://127.0.0.1:%d", port))
	}()

	log.Printf("TarsSecureGuard v%s running at http://127.0.0.1:%d", version, port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// ===================== 中间件：WAF / 鉴权 / CORS / 统计 =====================
func gatewayMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 请求量按小时统计（新增）：供 /api/stats/history 查询
		recordHourlyRequest()
		setSecurityHeaders(w, r)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		// 1) WAF 检测（含速率限制与请求体扫描）
		if reason := wafCheck(r); reason != "" {
			blockRequest(w, r, reason)
			return
		}
		// 2) 跨域预检：仅放行受信任同源
		if r.Method == http.MethodOptions {
			if o := r.Header.Get("Origin"); o != "" && !isTrustedOrigin(o) {
				writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "origin not allowed"})
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// 3) 入站鉴权（静态前端页面放行，API 一律校验）
		if isPublicRoute(r.URL.Path) {
			mu.Lock()
			totalReq++
			mu.Unlock()
			recordResponseTime(time.Now(), func() { next.ServeHTTP(w, r) })
			return
		}
		name, role, ok := userFromRequest(r)
		if !ok {
			mu.Lock()
			failReq++
			mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Bearer realm="TarsSecureGuard"`)
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: 需要 X-API-Key 或 Authorization: Bearer <key>"})
			return
		}
		// RBAC：admin 端点仅 admin 可访问；其余端点 admin/user 均可；readonly 仅只读
		if isAdminRoute(r.URL.Path) && role != "admin" {
			auditLog("ACCESS_DENIED", name, r.URL.Path+" 需要 admin 角色")
			writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "权限不足: 需要 admin 角色"})
			return
		}
		if r.Method != http.MethodGet && role == "readonly" {
			auditLog("ACCESS_DENIED", name, r.URL.Path+" readonly 用户禁止写操作")
			writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "权限不足: readonly 用户禁止写操作"})
			return
		}
		mu.Lock()
		totalReq++
		mu.Unlock()
		recordResponseTime(time.Now(), func() { next.ServeHTTP(w, r) })
	})
}

// recordResponseTime（新增）：包裹业务处理并累计耗时，供 /api/stats 计算平均响应时间
func recordResponseTime(start time.Time, serve func()) {
	serve()
	mu.Lock()
	respTotalMs += time.Since(start).Milliseconds()
	respSamples++
	mu.Unlock()
}

func isPublicRoute(p string) bool {
	// /health 为健康检查端点（新增），与前端页面一样免鉴权
	return p == "/" || p == "/index.html" || p == "/admin" || p == "/health"
}

func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	// CORS：只对受信任同源回显，绝不使用 *
	if o := r.Header.Get("Origin"); isTrustedOrigin(o) {
		w.Header().Set("Access-Control-Allow-Origin", o)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func isTrustedOrigin(o string) bool {
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	switch u.Host {
	case "127.0.0.1:" + strconv.Itoa(port), "localhost:" + strconv.Itoa(port), "[::1]:" + strconv.Itoa(port):
		return true
	}
	return false
}

func gatewayAPIKey() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Security.APIKey == "" {
		return apiKeyDefault
	}
	return cfg.Security.APIKey
}

func isAuthorized(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		if isTrustedOrigin(o) {
			return true
		}
		return validKey(r)
	}
	return validKey(r)
}

func validKey(r *http.Request) bool {
	key := r.Header.Get("X-API-Key")
	if key == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			key = strings.TrimPrefix(h, "Bearer ")
		}
	}
	want := gatewayAPIKey()
	if key == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(want)) == 1
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type rlEntry struct {
	count    int
	winStart time.Time
}

func allowRequest(ip string) bool {
	now := time.Now()
	rlMu.Lock()
	defer rlMu.Unlock()
	e, ok := rlHits[ip]
	if !ok || now.Sub(e.winStart) >= rateLimitWindow {
		rlHits[ip] = &rlEntry{count: 1, winStart: now}
		return true
	}
	e.count++
	if e.count > rateLimitMax {
		return false
	}
	// 定期清理过期条目，防止 map 无限增长
	if len(rlHits) > 1024 {
		for k, v := range rlHits {
			if now.Sub(v.winStart) >= rateLimitWindow {
				delete(rlHits, k)
			}
		}
	}
	return true
}

// ===================== 通用工具 =====================

// modelState 返回本地模型运行状态与当前模型 id（并发安全快照）
func modelState() (bool, string) {
	mu.Lock()
	defer mu.Unlock()
	return modelRunning, currentModel
}

// sanitizedConfig 返回脱敏后的配置（所有 API Key 一律 ***）
func sanitizedConfig() map[string]interface{} {
	b, _ := json.Marshal(cfg)
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	if cl, ok := m["cloud"].(map[string]interface{}); ok {
		for _, k := range []string{"openai", "deepseek"} {
			if c, ok := cl[k].(map[string]interface{}); ok && c["apiKey"] != "" {
				c["apiKey"] = "***"
			}
		}
	}
	if s, ok := m["search"].(map[string]interface{}); ok && s["apiKey"] != "" {
		s["apiKey"] = "***"
	}
	if sec, ok := m["security"].(map[string]interface{}); ok && sec["apiKey"] != "" {
		sec["apiKey"] = "***"
	}
	// 多用户 Key 脱敏
	if users, ok := m["users"].([]interface{}); ok {
		for _, u := range users {
			if us, ok := u.(map[string]interface{}); ok && us["apiKey"] != "" {
				us["apiKey"] = "***"
			}
		}
	}
	return m
}

// 允许通过 API 修改的配置白名单（防止结构破坏与任意配置注入）
func isConfigPathAllowed(path string) bool {
	allowed := []string{
		"cloud.openai.apiKey", "cloud.openai.baseUrl", "cloud.openai.name",
		"cloud.deepseek.apiKey", "cloud.deepseek.baseUrl", "cloud.deepseek.name",
		"search.apiKey", "search.engine",
		"security.mode", "security.wafEnabled", "security.auditLogEnabled",
	}
	for _, a := range allowed {
		if path == a {
			return true
		}
	}
	return false
}

// ===================== RBAC 与审计日志 =====================

// userFromRequest 从请求中提取用户身份（多用户模式优先，否则回退单管理员）
func userFromRequest(r *http.Request) (name string, role string, ok bool) {
	key := extractAPIKey(r)
	if key == "" {
		return "", "", false
	}
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	// 多用户模式
	for _, u := range cfg.Users {
		if u.Enabled && subtle.ConstantTimeCompare([]byte(key), []byte(u.APIKey)) == 1 {
			return u.Name, u.Role, true
		}
	}
	// 回退单管理员模式
	want := gatewayAPIKey()
	if want != "" && subtle.ConstantTimeCompare([]byte(key), []byte(want)) == 1 {
		return "admin", "admin", true
	}
	return "", "", false
}

// extractAPIKey 从请求头提取 API Key（与 validKey 逻辑一致，但返回 key 本身）
func extractAPIKey(r *http.Request) string {
	key := r.Header.Get("X-API-Key")
	if key == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			key = strings.TrimPrefix(h, "Bearer ")
		}
	}
	return key
}

// requireRole 中间件：拒绝无所需角色的请求
func requireRole(next http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, role, ok := userFromRequest(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="TarsSecureGuard"`)
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		for _, allowed := range roles {
			if role == allowed {
				next(w, r)
				return
			}
		}
		auditLog("ACCESS_DENIED", name, fmt.Sprintf("路径 %s 需要角色 %v，当前 %s", r.URL.Path, roles, role))
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "权限不足: 需要 " + strings.Join(roles, "/")})
	}
}

// isAdminRoute 判断是否为仅 admin 可访问的管理端点
func isAdminRoute(path string) bool {
	adminPaths := []string{
		"/api/admin/models/start", "/api/admin/models/stop",
		"/api/admin/model/download", "/api/admin/config",
		"/api/admin/security/status", "/api/admin/security/waf-logs",
		"/api/admin/logs", "/api/admin/v32/auto-discovery/scan",
	}
	for _, p := range adminPaths {
		if path == p {
			return true
		}
	}
	return false
}

// auditLog 写入审计日志：audit-YYYY-MM-DD.log + 内存日志
func auditLog(action, user, detail string) {
	cfgMu.RLock()
	enabled := cfg.Security.AuditLogEnabled
	cfgMu.RUnlock()
	if !enabled {
		return
	}
	line := fmt.Sprintf("[%s] ACTION=%s USER=%s IP=%s DETAIL=%s",
		time.Now().Format("2006-01-02 15:04:05"), action, user, "-", detail)
	fileLog("audit", line)
	logMsg("[AUDIT] " + line)
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func logMsg(s string) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), s)
	mu.Lock()
	logs = append(logs, line)
	if len(logs) > 500 {
		logs = logs[len(logs)-500:]
	}
	mu.Unlock()
	// 运行日志同步落盘：logs/tars-YYYY-MM-DD.log（新增，内存仍保留最近 500 条）
	fileLog("tars", line)
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(data)
}

func writeJSONStatus(w http.ResponseWriter, code int, data interface{}) {
	w.WriteHeader(code)
	writeJSON(w, data)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

func isPathAllowed(path string, write bool) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	lower := strings.ToLower(abs)
	for _, root := range allowedRoots {
		r, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		rl := strings.ToLower(r)
		// 边界安全：必须是「等于根目录」或「根目录 + 路径分隔符」开头，
		// 避免 D:\TarsSecureGuard 误匹配 D:\TarsSecureGuardEvil
		if abs == r || strings.HasPrefix(lower, rl+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
