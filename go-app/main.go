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

const (
	port          = 18889
	modelPort     = 18890
	lmStudioBase  = "http://127.0.0.1:1234"
	ollamaBase    = "http://127.0.0.1:11434"
	version       = "1.0.4"
	apiKeyDefault = "tars-gateway-key"

	maxBodyBytes          = 5 << 20
	maxFetchBytes         = 2 << 20
	maxOpenAPIBytes       = 10 << 20
	maxModelDownloadBytes = 64 << 30
	rateLimitWindow       = 10 * time.Second
	rateLimitMax          = 120
	wafLogLimit           = 500
	memoryLimit           = 1024
)

var (
	modelDir   string
	llamaDir   string
	configPath string
)

var allowedRoots []string

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
	currentModel string
	cfg          Config
	cfgMu        sync.RWMutex
	memory       = map[string]string{}
	memoryMu     sync.Mutex
	starting     bool
	rlMu         sync.Mutex
	rlHits       = map[string]*rlEntry{}

	httpClientShort = &http.Client{Timeout: 30 * time.Second}
	httpClientLong  = &http.Client{Timeout: 300 * time.Second}
	downloadClient  = &http.Client{}
)

func main() {
	resolveConfigPath()
	loadConfig()
	initTools()
	loadMemory()
	initLogDir()
	ensureFirewallRule()

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

	go func() {
		time.Sleep(2 * time.Second)
		startLocalModel("qwen2.5-3b")
	}()

	go func() {
		time.Sleep(1 * time.Second)
		openBrowser(fmt.Sprintf("http://127.0.0.1:%d", port))
	}()

	log.Printf("TarsSecureGuard v%s running at http://127.0.0.1:%d", version, port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func gatewayMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, r)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		if reason := wafCheck(r); reason != "" {
			blockRequest(w, r, reason)
			return
		}
		if r.Method == http.MethodOptions {
			if o := r.Header.Get("Origin"); o != "" && !isTrustedOrigin(o) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
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
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":"unauthorized: 需要 X-API-Key 或 Authorization: Bearer <key>"}`)
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
	if len(rlHits) > 1024 {
		for k, v := range rlHits {
			if now.Sub(v.winStart) >= rateLimitWindow {
				delete(rlHits, k)
			}
		}
	}
	return true
}

func modelState() (bool, string) {
	mu.Lock()
	defer mu.Unlock()
	return modelRunning, currentModel
}

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
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), s)
	mu.Lock()
	logs = append(logs, line)
	if len(logs) > 500 {
		logs = logs[len(logs)-500:]
	}
	mu.Unlock()
	appendLog("gateway.log", s)
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
		if abs == r || strings.HasPrefix(lower, rl+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
