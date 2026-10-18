package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ===================== WAF 安全模块 =====================

// wafRuleItem 单条 WAF 规则（支持热重载）
type wafRuleItem struct {
	name   string
	re     *regexp.Regexp
	strict bool
}

// 内置默认 WAF 规则（热重载失败时的回滚基线）
var wafBuiltinRules = []wafRuleItem{
	{"路径穿越", regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e|%2e%2f|%252e|%c0%af|%c1%9c)`), false},
	{"命令注入", regexp.MustCompile("(?i)(;\\s*(cmd|powershell|pwsh|bash|sh|wget|curl|net|taskkill|ping|rm|rmdir)\\b|&&\\s*(cmd|powershell|pwsh|bash|sh|wget|curl|net|taskkill|ping|rm|rmdir)\\b|;\\s*\\x60[a-z]+\\x60)"), false},
	{"SQL 注入", regexp.MustCompile(`(?i)(\bunion\b\s+\bselect\b|\binsert\b\s+\binto\b|\bdelete\b\s+\bfrom\b|\bdrop\b\s+\btable\b|/\*|;\s*\bdrop\b|\bsleep\s*\(|\bbenchmark\s*\()`), true},
	{"XSS", regexp.MustCompile(`(?i)(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe|document\.cookie|<\s*object)`), true},
	{"PromptInjection", regexp.MustCompile(`(?i)(ignore\s+(previous|above|prior)|disregard\s+(instructions|rules)|you\s+are\s+now|DAN\s+mode|jailbreak|\bsystem\s*:\s*you\s+are|\bdeveloper\s*mode\b|\bdo\s+anything\s+now\b|\bnew\s+instructions\s*:\s*)`), true},
	{"PII泄漏", regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b|\b\d{3}-\d{2}-\d{4}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b1[3-9]\d{9}\b`), true},
}

// 当前生效的 WAF 规则集（可被热重载替换）
var (
	wafRules        = wafBuiltinRules
	wafRulesMu      sync.RWMutex
	wafNormalMerged *regexp.Regexp
	wafStrictMerged *regexp.Regexp
	wafRulesFile    string
	lastWAFHash     string
)

func init() {
	wafNormalMerged = wafMergeRulesLocked(false)
	wafStrictMerged = wafMergeRulesLocked(true)
}

// wafMergeRulesLocked 把（按 strict 过滤后的）规则模式串逐条以 (?:...) 包裹后 alternation 合并。
// 调用方必须持有 wafRulesMu 读锁（或写锁）。
func wafMergeRulesLocked(strict bool) *regexp.Regexp {
	var parts []string
	for _, r := range wafRules {
		if r.strict && !strict {
			continue
		}
		parts = append(parts, "(?:"+r.re.String()+")")
	}
	if len(parts) == 0 {
		return nil
	}
	return regexp.MustCompile(strings.Join(parts, "|"))
}

// ===================== WAF 规则热重载（v4.27.0）=====================

// wafRuleJSON 外部规则文件中的单条规则定义
type wafRuleJSON struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Strict  bool   `json:"strict"`
}

// wafRulesJSON 外部规则文件根结构
type wafRulesJSON struct {
	Rules []wafRuleJSON `json:"rules"`
}

// resolveWAFRulesPath 确定 waf-rules.json 路径（与 config.json 同目录）
func resolveWAFRulesPath() string {
	if configPath != "" {
		return filepath.Join(filepath.Dir(configPath), "waf-rules.json")
	}
	return filepath.Join(appDir(), "waf-rules.json")
}

// wafRulesHash 计算规则文件 SHA256（空文件或不存在返回空串）
func wafRulesHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// loadWAFRules 从外部 JSON 文件加载 WAF 规则；失败时保留旧规则并记录审计。
// 线程安全：内部加写锁。
func loadWAFRules() error {
	if wafRulesFile == "" {
		wafRulesFile = resolveWAFRulesPath()
	}
	data, err := os.ReadFile(wafRulesFile)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在：回退到内置规则（静默，不记错误）
			wafRulesMu.Lock()
			wafRules = wafBuiltinRules
			wafNormalMerged = wafMergeRulesLocked(false)
			wafStrictMerged = wafMergeRulesLocked(true)
			wafRulesMu.Unlock()
			return nil
		}
		return fmt.Errorf("读取 WAF 规则文件失败: %w", err)
	}
	// 剥离 UTF-8 BOM
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var payload wafRulesJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		auditLog("WAF_RULES_LOAD_FAILED", "system", fmt.Sprintf("JSON 解析失败: %v", err))
		return fmt.Errorf("WAF 规则 JSON 解析失败: %w", err)
	}
	if len(payload.Rules) == 0 {
		auditLog("WAF_RULES_LOAD_FAILED", "system", "规则文件为空数组")
		return errors.New("WAF 规则文件为空")
	}
	// 编译每条规则正则
	compiled := make([]wafRuleItem, 0, len(payload.Rules))
	for i, r := range payload.Rules {
		if r.Name == "" || r.Pattern == "" {
			auditLog("WAF_RULES_LOAD_FAILED", "system", fmt.Sprintf("规则 #%d name/pattern 为空", i))
			return fmt.Errorf("规则 #%d name/pattern 为空", i)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			auditLog("WAF_RULES_LOAD_FAILED", "system", fmt.Sprintf("规则 #%d (%s) 正则编译失败: %v", i, r.Name, err))
			return fmt.Errorf("规则 #%d (%s) 正则编译失败: %w", i, r.Name, err)
		}
		compiled = append(compiled, wafRuleItem{name: r.Name, re: re, strict: r.Strict})
	}
	// 原子替换生效
	wafRulesMu.Lock()
	oldCount := len(wafRules)
	wafRules = compiled
	wafNormalMerged = wafMergeRulesLocked(false)
	wafStrictMerged = wafMergeRulesLocked(true)
	wafRulesMu.Unlock()
	auditLog("WAF_RULES_LOADED", "system", fmt.Sprintf("热重载成功: %d -> %d 条规则", oldCount, len(compiled)))
	logMsg(fmt.Sprintf("[WAF] 规则热重载完成: %d 条规则生效", len(compiled)))
	return nil
}

// watchWAFRules 轮询监听 waf-rules.json 变化，变化时自动重载（无需重启服务）。
// 加载失败时保留旧规则，不中断服务。
func watchWAFRules() {
	wafRulesFile = resolveWAFRulesPath()
	// 启动时先尝试加载一次（若文件存在则覆盖内置规则）
	_ = loadWAFRules()
	lastWAFHash = wafRulesHash(wafRulesFile)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h := wafRulesHash(wafRulesFile)
		if h == "" || h == lastWAFHash {
			continue
		}
		logMsg("[WAF] 检测到规则文件变化，自动重载...")
		if err := loadWAFRules(); err != nil {
			logMsg("[WAF] 规则热重载失败，保留旧规则: " + err.Error())
			auditLog("WAF_RULES_RELOAD_FAILED", "system", err.Error())
			continue
		}
		lastWAFHash = h
		logMsg("[WAF] 规则热重载完成")
	}
}

// wafTriggerBytes 所有 WAF 规则的命中前提：至少含一个 ASCII 触发字节
// （字母/数字，或 . % ; & ` < = : @ / * ( 等）。逐条核验：
//
//	路径穿越需 '.'/'%'；命令注入需 ';'/'&&'/反引号；SQL 注入需字母或 "/*" 或 '('；
//	XSS 需字母或 '<'/':'/'='；PromptInjection 为英文关键词（字母）；PII 需数字/'@'/字母（邮箱）。
//
// 纯中文正文（UTF-8 字节 ≥0x80）不含任何触发字节 → 整串免正则，直接判无命中。
func wafNeedsScan(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 {
			continue // CJK 等多字节字符，单字节跳过
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '%' || c == ';' || c == '&' || c == '`' || c == '<' ||
			c == '=' || c == ':' || c == '@' || c == '/' || c == '*' || c == '(' || c == ')' {
			return true
		}
	}
	return false
}

func wafMatch(s string, strict bool) string {
	// 触发字节预筛：纯中文正文等无触发字节内容整串免正则（绝大多数聊天请求走此快路径）
	if !wafNeedsScan(s) {
		return ""
	}
	wafRulesMu.RLock()
	// 单遍快筛：一条合并正则扫完（替代逐规则多次全串扫描）
	merged := wafNormalMerged
	if strict {
		merged = wafStrictMerged
	}
	if merged != nil && !merged.MatchString(s) {
		wafRulesMu.RUnlock()
		return ""
	}
	// 命中：按原顺序回查个别规则，返回首个命中名（与逐条扫描语义一致）
	for _, rule := range wafRules {
		if rule.strict && !strict {
			continue
		}
		if rule.re.MatchString(s) {
			wafRulesMu.RUnlock()
			return rule.name
		}
	}
	wafRulesMu.RUnlock()
	return ""
}

// ===================== 新增检测规则（v1.0.2 功能强化） =====================

// scannerUABlacklist：常见扫描器 / 渗透工具的 User-Agent 特征（小写子串匹配）
var scannerUABlacklist = []string{
	"sqlmap", "nikto", "nmap scripting engine", "masscan", "zgrab",
	"dirbuster", "gobuster", "ffuf", "nuclei", "wpscan", "acunetix",
	"nessus", "openvas", "metasploit", "burpsuite", "havij", "hydra",
	"w3af", "arachni", "whatweb", "dotdotpwn", "censys", "shodan",
	// v4.6.3 WAF 盲区补全：脚本化 HTTP 客户端与目录扫描器常见 UA 特征
	"nmap", "python-requests", "go-http-client", "curl/", "wget",
	"libwww-perl", "okhttp", "scrapy", "sqlninja",
	"awfuzz", "wfuzz", "xray", "anchashi",
}

// sensitivePathPatterns：敏感路径探测特征（小写子串匹配）。
// 注意：本系统自身的管理面板（/admin）与 API（/api/、/v1/、/mcp）
// 属于合法路由，在 isOwnAppRoute 中豁免，不参与敏感路径拦截，
// 以保证向后兼容、不破坏现有功能。
var sensitivePathPatterns = []string{
	"/.env", "/.git", "/.svn", "/.ssh", "/.aws", "/.ds_store",
	"/.htaccess", "/.htpasswd", "/.idea", "/.dockerenv",
	"/wp-admin", "/wp-login", "/wp-content", "/xmlrpc.php",
	"/phpmyadmin", "/pma/",
	"/admin/", "/administrator",
	"/server-status", "/actuator", "/.bak", "/.sql",
	"/proc/", "/sys/", "/swagger-ui", "/api-docs",
}

// allowedHTTPMethods：允许的 HTTP 方法白名单；
// 之外的方法（TRACE / CONNECT / PATCH 等）视为异常请求。
var allowedHTTPMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
	http.MethodOptions: true,
	http.MethodHead:    true,
}

// isOwnAppRoute 判断请求路径是否本系统自身路由（前端面板 / API / MCP）。
// 这些路径不参与敏感路径拦截，避免误伤自身管理功能。
func isOwnAppRoute(p string) bool {
	return isPublicRoute(p) ||
		strings.HasPrefix(p, "/api/") ||
		strings.HasPrefix(p, "/v1") ||
		p == "/mcp"
}

// scannerUAMatch 检测 User-Agent 是否命中扫描器黑名单，命中返回特征串
// v4.7.6 性能优化：用预编译的合并正则替代 N 次 strings.Contains 子串循环
// （一次 FindStringIndex ≈ 30 次 Contains，UA 是每个请求必走的热路径）
var (
	scannerUARe      = regexp.MustCompile(`(?i)(` + strings.Join(scannerUABlacklist, "|") + `)`)
	scannerUACache   sync.Map // ua 小写 → 匹配特征串（命中即返回，省 regex 重跑）
	scannerUACap     = 4096   // UA 长度上限；超过视为 DoS 攻击候选，直接 miss（不命中也不放入）
)

// scannerUAMatch 检测 User-Agent 是否命中扫描器黑名单，命中返回特征串
func scannerUAMatch(ua string) string {
	if ua == "" || len(ua) > scannerUACap {
		return ""
	}
	// 快路径：缓存
	if v, ok := scannerUACache.Load(ua); ok {
		s, _ := v.(string)
		return s
	}
	// 慢路径：合并正则一次匹配
	m := scannerUARe.FindString(ua)
	if m != "" {
		// 正则匹配大小写不敏感，返回原始小写特征串供 UI/审计展示
		scannerUACache.Store(ua, strings.ToLower(m))
		return strings.ToLower(m)
	}
	// miss 也缓存一份空串，避免重复 UA 反复进 regex
	scannerUACache.Store(ua, "")
	return ""
}

// sensitivePathMatch 检测路径是否命中敏感路径探测特征，命中返回命中的特征串
func sensitivePathMatch(p string) string {
	if p == "" {
		return ""
	}
	lower := strings.ToLower(p)
	for _, s := range sensitivePathPatterns {
		if strings.Contains(lower, s) {
			return s
		}
	}
	return ""
}

func wafEnabled() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.Security.WAFEnabled
}

func wafStrict() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.Security.Mode == "strict"
}

func wafCheck(r *http.Request) string {
	// v2.0.0：security-core 强制加载，无开关；wafEnabled() 保留仅供状态展示
	// 1) 速率限制
	if !allowRequest(clientIP(r)) {
		return "请求频率超限"
	}
	// 2) 异常 HTTP 方法检测（新增）：白名单之外的方法直接拦截
	if !allowedHTTPMethods[r.Method] {
		return "异常 HTTP 方法: " + r.Method
	}
	// 3) User-Agent 黑名单检测（新增）：扫描器 UA 直接拦截
	if hit := scannerUAMatch(r.Header.Get("User-Agent")); hit != "" {
		return "扫描器 User-Agent: " + hit
	}
	// 4) 敏感路径探测检测（新增）：本系统自身路由豁免，其余命中即拦截
	if !isOwnAppRoute(r.URL.Path) {
		if hit := sensitivePathMatch(r.URL.Path); hit != "" {
			return "敏感路径探测: " + hit
		}
	}
	// 4.5) Host 头注入检测（v4.7.1）：拒绝含换行符/空字节的 Host 头，
	// 防止 HTTP 响应分割、缓存投毒、虚拟主机混淆等攻击向量
	if host := r.Host; strings.ContainsAny(host, "\r\n\x00") {
		return "Host 头注入"
	}
	// 4.55) 全请求头 CRLF/NULL 注入检测（v4.7.5）：v4.7.1 只检查了 Host，
	// 但攻击者可通过 X-Forwarded-For / X-Real-IP / Authorization / Cookie 等
	// 任意头注入 CRLF/NULL，造成响应分割、缓存投毒、日志注入。Go 标准库
	// 已禁止 header value 含 \r\n，但仍有中间件层/反代层被攻击的可能；
	// 在 WAF 兜底再检查一次，成本极低。
	for k, vs := range r.Header {
		for _, v := range vs {
			if strings.ContainsAny(v, "\r\n\x00") {
				return "请求头 CRLF/NULL 注入: " + k
			}
		}
	}
	// 4.6) HTTP 请求走私检测（v4.7.1）：同时存在 Content-Length 与
	// Transfer-Encoding 头是经典走私攻击向量，前端可能按一个长度解析、
	// 后端按另一个解析，导致绕过访问控制
	if r.ContentLength >= 0 && r.Header.Get("Transfer-Encoding") != "" {
		return "HTTP 请求走私: CL+TE 双重头"
	}
	// 5) 大文件上传检测（新增）：Content-Length 超过 maxBodyBytes 直接拦截
	if r.ContentLength > maxBodyBytes {
		return "请求体过大"
	}
	// 6) 路径与查询串检测（所有模式都查；查询串先解码再扫，防编码穿越）
	scanQuery := r.URL.RawQuery
	if decoded, err := url.QueryUnescape(scanQuery); err == nil {
		scanQuery = decoded
	}
	if reason := wafMatch(r.URL.Path+" "+scanQuery, false); reason != "" {
		return reason
	}
	// 7) 请求体扫描：工具端点总是扫描；chat 端点扫 messages[].content（strict 规则）；strict 模式下扫描所有端点
	strict := wafStrict()
	toolEndpoint := strings.Contains(r.URL.Path, "/mcp") || strings.HasPrefix(r.URL.Path, "/api/tools/")
	chatEndpoint := strings.Contains(r.URL.Path, "/v1/chat") || strings.Contains(r.URL.Path, "/api/chat")
	if !toolEndpoint && !chatEndpoint && !strict {
		return ""
	}
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return "请求体过大"
			}
			return ""
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		if reason := wafScanBody(b, strict, chatEndpoint); reason != "" {
			return reason
		}
	}
	return ""
}

// wafScanBody：normal 模式只扫描工具调用参数中的字符串值（降低聊天内容误报）；
// chat 端点提取 messages[].content 用 strict 规则扫描（PromptInjection/PII/XSS/SQLi）；
// strict 模式扫描整个请求体。
func wafScanBody(b []byte, strict bool, isChat bool) string {
	if strict {
		return wafMatch(string(b), true)
	}
	// chat 端点：提取 messages[].content 用 strict 规则扫描（成本极低，已走 ASCII 预筛）
	if isChat {
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if json.Unmarshal(b, &req) == nil {
			for _, m := range req.Messages {
				if reason := wafMatch(m.Content, true); reason != "" {
					return reason
				}
			}
		}
		return ""
	}
	// 工具端点扫描
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	var sb strings.Builder
	if t, _ := m["tool"].(string); t != "" {
		sb.WriteString(t)
		sb.WriteByte('\n')
	}
	scanMap := func(mp map[string]interface{}) {
		for _, v := range mp {
			if s, ok := v.(string); ok {
				sb.WriteString(s)
				sb.WriteByte('\n')
			}
		}
	}
	// /api/tools/ 的调用参数直接位于顶层（{"path":...}）
	scanMap(m)
	if args, ok := m["args"].(map[string]interface{}); ok {
		scanMap(args)
	}
	if params, ok := m["params"].(map[string]interface{}); ok {
		if arguments, ok := params["arguments"].(map[string]interface{}); ok {
			scanMap(arguments)
		}
	}
	return wafMatch(sb.String(), false)
}

// piiMaskPatterns PII 脱敏正则（与 WAF 规则中的 PII泄漏 对应）
var piiMaskPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),         // 信用卡
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                              // SSN
	regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), // 邮箱
	regexp.MustCompile(`\b1[3-9]\d{9}\b`),                                    // 中国大陆手机号
}

// piiMaskMerged v3.2.3 性能升级 v2：四条 PII 模式合并为一条 alternation，
// 单遍替换替代四遍逐条替换；所有命中均替换为同一占位符 "****"，输出与逐条实现一致。
var piiMaskMerged = func() *regexp.Regexp {
	var parts []string
	for _, re := range piiMaskPatterns {
		parts = append(parts, "(?:"+re.String()+")")
	}
	return regexp.MustCompile(strings.Join(parts, "|"))
}()

// maskPII 对输入文本中的 PII 进行脱敏替换（****）
// v3.2.3：单遍合并替换替代四遍逐条替换；模式间文法互斥（信用卡/SSN/邮箱/手机号），
// 一遍替换与逐条替换输出一致。
func maskPII(s string) string {
	return piiMaskMerged.ReplaceAllString(s, "****")
}

// maskPIIInMessages 对聊天消息数组中的 content 进行 PII 脱敏
func maskPIIInMessages(msgs []Message) []Message {
	out := make([]Message, len(msgs))
	for i, m := range msgs {
		out[i] = Message{Role: m.Role, Content: maskPII(m.Content)}
	}
	return out
}

func blockRequest(w http.ResponseWriter, r *http.Request, reason string) {
	now := time.Now().Format("15:04:05")
	// v3.0.5 观测埋点（纯观测）：WAF 命中计数 + trace span；日志行追加 TRACE=<id> 便于审计关联
	obsRecordWAF(r, reason)
	line := fmt.Sprintf("[%s] %s %s %s → BLOCKED (%s)%s", now, clientIP(r), r.Method, r.URL.Path, reason, obsTraceSuffix(r))
	mu.Lock()
	wafBlocks++
	if len(wafLogs) >= wafLogLimit {
		wafLogs = wafLogs[len(wafLogs)-wafLogLimit+1:]
	}
	wafLogs = append(wafLogs, line)
	mu.Unlock()
	// WAF 日志同步落盘：logs/waf-YYYY-MM-DD.log（含时间、IP、原因、请求路径）
	fileLog("waf", line)
	logMsg(fmt.Sprintf("[WAF] BLOCK %s %s (%s)", r.Method, r.URL.Path, reason))
	writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "blocked by WAF: " + reason})
}
