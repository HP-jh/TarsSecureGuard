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
	version       = "1.0.1"
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
	resolveConfigPath()
	loadConfig()
	initTools()
	loadMemory()

	logMsg(fmt.Sprintf("TarsSecureGuard v%s starting...", version))

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleFrontend)
	mux.HandleFunc("/api/status", handleStatus)
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
			next.ServeHTTP(w, r)
			return
		}
		if !isAuthorized(r) {
			mu.Lock()
			failReq++
			mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Bearer realm="TarsSecureGuard"`)
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: 需要 X-API-Key 或 Authorization: Bearer <key>"})
			return
		}
		mu.Lock()
		totalReq++
		mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func isPublicRoute(p string) bool {
	return p == "/" || p == "/index.html" || p == "/admin"
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

// sanitizedConfig 返回脱敏后的配置（API Key 一律 ***）
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
	return m
}

// 允许通过 API 修改的配置白名单（防止结构破坏与任意配置注入）
// v1.0.1 起：security.apiKey 不再允许通过 API 修改——防止持有旧 key 的进程
// 把 key 改成新值把合法管理员锁在外面。要改 key 请手动编辑 config.json 后重启。
func isConfigPathAllowed(path string) bool {
	allowed := []string{
		"cloud.openai.apiKey", "cloud.openai.baseUrl", "cloud.openai.name",
		"cloud.deepseek.apiKey", "cloud.deepseek.baseUrl", "cloud.deepseek.name",
		"search.apiKey", "search.engine",
		"security.mode", "security.wafEnabled",
	}
	for _, a := range allowed {
		if path == a {
			return true
		}
	}
	return false
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func logMsg(s string) {
	mu.Lock()
	logs = append(logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), s))
	if len(logs) > 500 {
		logs = logs[len(logs)-500:]
	}
	mu.Unlock()
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
