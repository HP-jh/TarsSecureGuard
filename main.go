package main

import (
	"context"
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

// 版本号（v2.1.0 起为 var：构建时经 -ldflags "-X main.version=..." 注入，源码内为默认值）
var version = "3.7.0"

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
	// v3.0.5：self-diagnostic 子命令（tsg doctor）——不启动网关，检查后退出
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "doctor":
			runDoctor(os.Args[2:])
			return
		case "version", "-v", "--version":
			fmt.Println("TarsSecureGuard v" + version)
			return
		}
	}
	// v3.2.1：桌面客户端模式标记——由 Tauri 壳以 sidecar 方式拉起时传 --no-browser，抑制自动打开浏览器
	noBrowser = scanNoBrowserFlag(os.Args)
	// v3.0.0 D 线：MCP stdio 模式（--mcp-stdio）—— 任何本地 agent 的安全带
	if mcpIsStdioFlag(os.Args[1:]) {
		initFileLogging()
		resolveConfigPath()
		loadConfig()
		loadGuardState()
		ipRepLoad()
		rtLoad()
		sbLoadLMEval()
		runMCPStdio()
		return
	}
	// 日志文件持久化：初始化 logs/ 目录（失败不影响服务）
	initFileLogging()
	resolveConfigPath()
	loadConfig()
	// v3.0.1 Tier 1：进程重启 = 缓存全量失效（HMAC 密钥仅存内存，重启后旧缓存必校验失败；
	// 启动即删除，把「正常重启」与「运行中篡改」区分开，后者才落 AUDIT_TIER1_CACHE_TAMPER）
	tier1StartupClear()
	// v3.0.0 A/B 线初始化：守护器状态恢复 + IP 信誉表加载 + 内存软上限
	loadGuardState()
	ipRepLoad()
	applyMemorySoftLimit(int(physicalMemoryGB() * 1024))
	// v3.0.0 C 线初始化：bandit 状态恢复 + lm-eval 离线评测导入（可选，相对参考）
	rtLoad()
	sbLoadLMEval()
	// v3.2.0 provider-registry：加载内置 provider 清单（go:embed 编译进二进制）。
	// 启动即校验：云端 provider 不足 20 个视为打包损坏，直接拒绝启动（fail-fast）。
	if err := loadProviderRegistry(); err != nil {
		log.Fatalf("provider registry load failed: %v", err)
	}
	// v3.2.0 连接池：共享 http.Transport（连接复用 + HTTP/2 + 复用率指标），
	// 替换 v3.0.5 的默认 Transport；初始化后 httpClientShort/Long 共用同一池。
	initPooledClients(cfg.V32Config.Pool.MaxIdleConnsPerHost)
	// eco 档：异步硬件评估，D 档设备自动套用省资源默认值
	go func() {
		if a := assessHardware(); a.Grade == "D" {
			enableEcoMode(fmt.Sprintf("硬件评估 D 档 (score=%d)", a.Scores.Total))
		}
	}()
	initTools()
	registerV2Tools() // v2.0.0 新增内置工具（硬件评估等）
	registerV322Tools() // v3.2.2 治理层工具（共享记忆/共享信息/上下文拓展）
	loadMemory()
	loadSharedMemory() // v3.2.2 共享记忆恢复
	loadSharedInfo()   // v3.2.2 共享信息恢复
	firewallReconcile() // 防火墙策略档位（passive/dynamic-ban/os-link，默认 passive）
	quotaLoad()         // v3.0.4 [MT_QUOTA]：恢复上一次运行的日配额用量（data/quota-usage.json）

	logMsg(fmt.Sprintf("TarsSecureGuard v%s starting...", version))

	// v2.0.0 模块化路由：路由启动时注册一次，经 moduleRoute 包装——
	// 模块关闭时该路由返回 503 + 开启提示（2 秒热重载生效），无需重启服务。
	// security-core 的中间件链（WAF/鉴权/RBAC/审计）硬编码在 gatewayMiddleware，不在此列。
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleFrontend)
	mux.HandleFunc("/health", handleHealth) // 健康检查（免鉴权）
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/stats", moduleRoute("stats", handleStats))                // 统计面板
	mux.HandleFunc("/api/stats/history", moduleRoute("stats", handleStatsHistory)) // 24 小时请求量
	mux.HandleFunc("/api/chat/completions", moduleRoute("chatApi", handleChat))
	mux.HandleFunc("/api/urgent/chat", moduleRoute("urgentChat", handleUrgent))
	mux.HandleFunc("/api/admin/models", moduleRoute("localModels", handleModels))
	mux.HandleFunc("/api/admin/models/start", moduleRoute("localModels", handleModelStart))
	mux.HandleFunc("/api/admin/models/stop", moduleRoute("localModels", handleModelStop))
	mux.HandleFunc("/api/admin/models/status", moduleRoute("localModels", handleModelStatus))
	mux.HandleFunc("/api/admin/device", handleDevice)
	mux.HandleFunc("/api/admin/device/scan", handleDeviceScan)
	mux.HandleFunc("/api/admin/model/download", moduleRoute("modelDownload", handleModelDownload))
	mux.HandleFunc("/api/admin/model/download/status", moduleRoute("modelDownload", handleModelDownloadStatus))
	mux.HandleFunc("/api/admin/models/open", moduleRoute("localModels", handleOpenModels))
	mux.HandleFunc("/api/admin/fallback/status", handleFallback)
	mux.HandleFunc("/api/admin/security/status", handleSecurity)
	mux.HandleFunc("/api/admin/security/waf-logs", handleWAFLogs)
	mux.HandleFunc("/api/admin/logs", handleLogs)
	mux.HandleFunc("/api/admin/audit-logs", handleAuditLogs)
	// v3.0.4 多租户 / 零信任面板：租户状态（含配额用量、按组 audit 视图）、白名单注册表
	mux.HandleFunc("/api/admin/tenants/status", handleTenantsStatus)
	mux.HandleFunc("/api/admin/whitelist/status", handleWhitelistStatus)
	mux.HandleFunc("/api/admin/audit/group-summary", handleAuditGroupSummary)
	mux.HandleFunc("/api/admin/config", handleConfig)
	mux.HandleFunc("/api/admin/modules", handleModules)                                                        // v2.0.0 模块管理
	mux.HandleFunc("/api/admin/hardware/assessment", moduleRoute("hardwareAdvisor", handleHardwareAssessment)) // v2.0.0 硬件评估
	// v3.0.0 B 线：IP 信誉查询与 admin 解封（裁定 6）
	mux.HandleFunc("/api/admin/iprep/status", handleIPRepStatus)
	mux.HandleFunc("/api/admin/semantic/status", handleSemanticStatus)
	mux.HandleFunc("/api/admin/router/status", handleRouterStatus)                              // v3.0.0 C 线：路由决策透明化
	mux.HandleFunc("/api/admin/scoreboard", handleScoreBoard)                                   // v3.0.0 C 线：模型评分榜
	mux.HandleFunc("/api/admin/sidecar/status", moduleRoute("sidecarHub", handleSidecarStatus)) // v3.0.1：sidecar 宿主状态面板
	mux.HandleFunc("/api/admin/sidecar/reload", moduleRoute("sidecarHub", handleSidecarReload)) // v3.0.1：全量重载（admin）
	mux.HandleFunc("/api/ext/", moduleRoute("sidecarHub", handleSidecarProxy))                  // v3.0.1：外置模块反向代理（过网关 WAF/RBAC/审计）
	mux.HandleFunc("/api/admin/iprep/unban", handleIPRepUnban)
	// v3.0.0 A 线：资源守护器面板数据
	mux.HandleFunc("/api/admin/guard/status", handleGuardStatus)
	mux.HandleFunc("/api/search", moduleRoute("webSearch", handleSearch))
	mux.HandleFunc("/api/feishu/", handleFeishu)
	mux.HandleFunc("/mcp", moduleRoute("mcpExternal", handleMCP))
	mux.HandleFunc("/api/admin/v32/auto-discovery/scan", moduleRoute("autoDiscovery", handleDiscoveryScan))
	mux.HandleFunc("/api/admin/v32/auto-discovery/results", moduleRoute("autoDiscovery", handleDiscoveryResults))
	mux.HandleFunc("/api/agents/", moduleRoute("chatApi", handleAgent))
	mux.HandleFunc("/api/tools/", moduleRoute("builtinTools", handleToolCall))
	mux.HandleFunc("/v1/", moduleRoute("chatApi", handleV1))
	mux.HandleFunc("/v1", moduleRoute("chatApi", handleV1Root))
	// v3.0.5 可观测性端点：
	//   /metrics —— Prometheus 拉取（经 gatewayMiddleware 鉴权；RBAC 归 app 类全角色可读）
	//   /api/admin/traces —— 最近 trace 与 span 时间线（admin.read 类，admin/审计角色可读）
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/api/admin/traces", handleTraces)

	// v3.2.0 连接性管理端点（admin.read 类，RBAC 沿用 /api/admin 前缀矩阵）：
	//   /api/admin/v32/providers         —— provider 注册表（keySet 布尔，永不回显密钥）
	//   /api/admin/v32/providers/probe   —— 主动健康探测（POST，admin.write 类）
	//   /api/admin/v32/pool              —— 连接池复用率指标
	//   /api/admin/v32/cache             —— 协议适配 + 响应缓存命中率
	mux.HandleFunc("/api/admin/v32/providers", moduleRoute("cloudModels", handleV32Providers))
	mux.HandleFunc("/api/admin/v32/providers/probe", moduleRoute("cloudModels", handleV32ProvidersProbe))
	mux.HandleFunc("/api/admin/v32/pool", moduleRoute("stats", handleV32Pool))
	mux.HandleFunc("/api/admin/v32/cache", moduleRoute("stats", handleV32Cache))

	// v3.2.2 治理层：共享记忆 / 共享信息 / 上下文组装（contextGov 模块，
	// 业务面端点——租户用户经 API Key / OAuth 会话均可访问，隔离在 handler 内）
	mux.HandleFunc("/api/context/memory", moduleRoute("contextGov", handleSharedMemoryREST))
	mux.HandleFunc("/api/context/info", moduleRoute("contextGov", handleSharedInfoREST))
	mux.HandleFunc("/api/context/build", moduleRoute("contextGov", handleContextBuildREST))
	// v3.3.0 模型能力库：能力矩阵查询 / 覆盖层写入 / 自动改道开关（capabilityHub 模块）
	mux.HandleFunc("/api/admin/v33/capabilities", moduleRoute("capabilityHub", handleV33Capabilities))
	// v3.4.0 Token 测量器：调用计量 / 成本汇总 / 清零 / 轻量估算（tokenMeter 模块）
	mux.HandleFunc("/api/admin/v34/meter", moduleRoute("tokenMeter", handleV34Meter))
	mux.HandleFunc("/api/v34/meter/estimate", moduleRoute("tokenMeter", handleV34MeterEstimate))
	// v3.4.0 连接器生态：模板目录 + 实例管理（connectors 模块）
	mux.HandleFunc("/api/admin/v34/connectors", moduleRoute("connectors", handleV34Connectors))
	// v3.5.0 极致模块化与自适应：裁剪档案 / 自适应建议 / UI 模式
	mux.HandleFunc("/api/admin/v35/profile", moduleRoute("adaptive", handleV35Profile))
	mux.HandleFunc("/api/admin/v35/adaptive", moduleRoute("adaptive", handleV35Adaptive))
	mux.HandleFunc("/api/admin/v35/ui-mode", moduleRoute("adaptive", handleV35UIMode))
	// v3.7.0 扩展器 / 一键配置器：探测本机 AI 工具 + 生成接入片段
	mux.HandleFunc("/api/admin/v37/extender", moduleRoute("extender", handleV37Extender))
	// v3.2.2 治理层：审计 v2（verify 需全局审计视野；export 租户行级过滤）
	mux.HandleFunc("/api/admin/v322/status", handleV322Status)
	mux.HandleFunc("/api/admin/audit/verify", handleAuditVerify)
	mux.HandleFunc("/api/admin/audit/export", handleAuditExport)
	// v3.2.2 治理层：OAuth / IdP（login/callback 为公共路由，见 isPublicRoute；
	// logout 经 gatewayMiddleware 用会话令牌鉴权）
	mux.HandleFunc("/oauth/login", handleOAuthLogin)
	mux.HandleFunc("/oauth/callback", handleOAuthCallback)
	mux.HandleFunc("/oauth/logout", handleOAuthLogout)
	mux.HandleFunc("/api/admin/oauth/status", handleOAuthStatus)

	// v3.0.5 观测层包裹在最外层：生成/透传 trace_id（X-Trace-Id）+ 请求级指标采集，
	// 纯观测不改 gatewayMiddleware 判定逻辑。
	server := &http.Server{
		Addr:           fmt.Sprintf("127.0.0.1:%d", port),
		Handler:        obsMiddleware(gatewayMiddleware(mux)),
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   600 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	registerServer(server) // v3.0.0 A 线：L3 drain 时关闭 listener 用

	logMsg(fmt.Sprintf("Listening on http://127.0.0.1:%d", port))

	// v2.0.0 模块后台工作者：随模块开关启停（context 取消即停，热重载切换无泄漏）
	moduleWorkerFns["autoStartModel"] = func(ctx context.Context) {
		select {
		case <-time.After(2 * time.Second):
			startLocalModel("qwen2.5-3b")
		case <-ctx.Done():
			return
		}
	}
	moduleWorkerFns["autoDiscovery"] = func(ctx context.Context) {
		select {
		case <-time.After(5 * time.Second):
			refreshDiscoveredModels()
		case <-ctx.Done():
			return
		}
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				refreshDiscoveredModels()
			case <-ctx.Done():
				return
			}
		}
	}
	// v3.0.0 A/B 线：资源守护器 worker（5 秒采样；同时驱动 IP 信誉 tick 与持久化）
	moduleWorkerFns["resourceGuardian"] = resourceGuardianWorker
	// v3.0.1：sidecarHub 宿主 worker（modules.d 扫描 + 模块监管 + 优雅停机）
	moduleWorkerFns["sidecarHub"] = sidecarHubWorker
	// v3.2.0：provider 健康探测 worker（熔断打开时加密探测，半开恢复判定）
	moduleWorkerFns["cloudModels"] = func(ctx context.Context) {
		providerHealthWorker(ctx.Done())
	}
	reconcileModuleWorkers()

	// 配置热重载（新增）：轮询监听 config.json 变化，变化时自动重载
	go watchConfig()

	// 打开浏览器（v3.2.1：--no-browser 桌面客户端模式下抑制——窗口由 Tauri 壳承载，不再依赖浏览器）
	if !noBrowser {
		go func() {
			time.Sleep(1 * time.Second)
			openBrowser(fmt.Sprintf("http://127.0.0.1:%d", port))
		}()
	}

	log.Printf("TarsSecureGuard v%s running at http://127.0.0.1:%d", version, port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// ===================== 中间件：WAF / 鉴权 / CORS / 统计 =====================
func gatewayMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// v3.0.0 E 线：panic recovery 全覆盖（handler panic 不再拖垮进程）
		defer func() {
			if p := recover(); p != nil {
				logMsg(fmt.Sprintf("[PANIC] %s %s: %v", r.Method, r.URL.Path, p))
				auditLog("PANIC_RECOVERED", "system", fmt.Sprintf("%s %s: %v", r.Method, r.URL.Path, p))
				writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error（已恢复并审计）"})
			}
		}()
		// 请求量按小时统计（新增）：供 /api/stats/history 查询
		recordHourlyRequest()
		setSecurityHeaders(w, r)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		// 0) dynamic-ban / os-link 档位：处于封禁期的 IP 直接拒绝
		if isBanned(clientIP(r)) {
			blockRequest(w, r, "IP 处于动态封禁期（security.firewall.policy）")
			return
		}
		// 1) WAF 检测（含速率限制与请求体扫描；security-core 永远启用，无开关）
		// v3.0.0 B 线：WAF 命中联动 IP 信誉扣分（-30，锦衣卫裁定 6）
		if reason := wafCheck(r); reason != "" {
			ip := clientIP(r)
			ipRepPenalty(ip, 30, "waf")
			markIPBanned(ip)
			firewallBanIP(ip) // 按防火墙档位施加封禁副作用（passive 档为 no-op）
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
		id, ok := identityFromRequest(r)
		if !ok {
			obsStage(r.Context(), "auth", "401 未授权")
			mu.Lock()
			failReq++
			mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Bearer realm="TarsSecureGuard"`)
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: 需要 X-API-Key 或 Authorization: Bearer <key>"})
			return
		}
		// v3.0.4 RBAC 矩阵（[RBAC_MATRIX]：角色×端点类逐格判定，替换 v3.0.0 的
		// isAdminRoute+readonly 两段式判定；写方法二次判定在 rbacCheck 内）
		if ok, reason := rbacCheck(id, r.Method, r.URL.Path); !ok {
			obsStage(r.Context(), "rbac", reason)
			auditLogT("ACCESS_DENIED", id.Tenant, "", id.Name, r.URL.Path+" "+reason+obsTraceSuffix(r))
			writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "权限不足: " + reason})
			return
		}
		// v3.0.4 [MT_QUOTA] chat 类请求前置配额检查（租户/用户/组三层日配额）
		if routeClass(r.URL.Path) == "chat" {
			if ok, why := quotaCheck(id.Tenant, id.Name, id.Groups); !ok {
				obsStage(r.Context(), "quota", why)
				auditLogT("QUOTA_EXCEEDED", id.Tenant, strings.Join(id.Groups, ","), id.Name, why+obsTraceSuffix(r))
				writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{"error": "配额超限: " + why})
				return
			}
		}
		name := id.Name
		// v3.0.0 B 线：分层速率限制（IP×端点类 / Key×端点类 / IP 总量三维令牌桶，
		// 超限 429 + 审计 + IP 信誉扣分）
		if !rateLimitMiddleware(w, r, name, id.Tenant) {
			return
		}
		mu.Lock()
		totalReq++
		mu.Unlock()
		recordResponseTime(time.Now(), func() {
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)
			// v3.0.0 B 线：扫描型 404 突发联动 IP 信誉扣分（每分钟至多 -10）
			if sw.status == http.StatusNotFound {
				ipRepPenalty(clientIP(r), 10, "scan404")
			}
		})
	})
}

// statusWriter v3.0.0：记录下游 handler 状态码（404 扫描检测用）
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
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
	// v3.2.2：OAuth 登录回调为浏览器跳转入口，登录前必然没有凭据——
	// 免鉴权但不过 WAF 之外的任何豁免（state 一次性 + PKCE 防 CSRF/劫持）
	if p == "/oauth/login" || p == "/oauth/callback" {
		return true
	}
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
	// v3.2.1：Tauri 桌面客户端窗口 origin——macOS/Linux 为 tauri://localhost，
	// Windows 为 http(s)://tauri.localhost。仅窗口 origin 本身受信，鉴权链（API key/RBAC）照常执行；
	// 网关仅监听 127.0.0.1，本机任意进程本可直连，此信任不扩大远程攻击面。
	if u.Scheme == "tauri" && u.Host == "localhost" {
		return true
	}
	if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "tauri.localhost" {
		return true
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
		// v2.0.0：security.wafEnabled 已移除（安全模块不可关闭）；
		// security.mode 保留 normal/strict 切换（POST 值校验拒绝 off，见 handleConfig）
		"security.mode", "security.auditLogEnabled",
		"security.firewall.policy", "security.firewall.banDuration",
		"direct.transport", "direct.grpcSidecar.address",
		// v3.0.1：Tier 1 开关与缓存 TTL（[TIER1_TOGGLE]；关闭仅降级硬件评估精度，
		// security-core 无开关、不在此列）
		"tier1.enabled", "tier1.cacheTtlSeconds",
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
		"/api/admin/modules", "/api/admin/hardware/assessment", // v2.0.0 模块管理 / 硬件评估
		"/api/admin/sidecar/reload", // v3.0.1 sidecar 全量重载（状态查询 /api/admin/sidecar/status 保留普通登录态可读）
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
	// v3.2.2 审计升级：同步落结构化 JSONL 哈希链条目（tenant 感知变体见 auditLogT）
	auditV2Write(action, "*", "", user, "", detail, "")
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

// v3.2.1：桌面客户端模式标记——true 时不自动打开浏览器（Tauri 壳以 sidecar 拉起网关并传 --no-browser）
var noBrowser = false

// scanNoBrowserFlag 扫描参数中的 --no-browser / -no-browser 标记（布尔开关，无值）
func scanNoBrowserFlag(args []string) bool {
	for _, a := range args {
		if a == "--no-browser" || a == "-no-browser" {
			return true
		}
	}
	return false
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
