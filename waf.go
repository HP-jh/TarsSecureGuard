package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ===================== WAF 安全模块 =====================

// WAF 规则：normal 模式仅检测路径穿越/命令注入等确定性模式；
// strict 模式额外检测 SQLi / XSS / Prompt Injection / PII 等文本模式（对聊天内容可能误报，需按需开启）。
var wafRules = []struct {
	name   string
	re     *regexp.Regexp
	strict bool
}{
	{"路径穿越", regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e|%2e%2f|%252e)`), false},
	{"命令注入", regexp.MustCompile("(?i)(;\\s*(cmd|powershell|pwsh|bash|sh|wget|curl|net|taskkill|ping)\\b|&&|;\\s*\\x60[a-z]+\\x60)"), false},
	{"SQL 注入", regexp.MustCompile(`(?i)(\bunion\b\s+\bselect\b|\binsert\b\s+\binto\b|\bdelete\b\s+\bfrom\b|\bdrop\b\s+\btable\b|/\*|;\s*\bdrop\b|\bsleep\s*\(|\bbenchmark\s*\()`), true},
	{"XSS", regexp.MustCompile(`(?i)(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe|document\.cookie|<\s*object)`), true},
	{"PromptInjection", regexp.MustCompile(`(?i)(ignore\s+(previous|above|prior)|disregard\s+(instructions|rules)|you\s+are\s+now|DAN\s+mode|jailbreak|\bsystem\s*:\s*you\s+are|\bdeveloper\s*mode\b|\bdo\s+anything\s+now\b|\bnew\s+instructions\s*:\s*)`), true},
	{"PII泄漏", regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b|\b\d{3}-\d{2}-\d{4}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b1[3-9]\d{9}\b`), true},
}

// v3.2.3 性能升级 v2：合并正则——normal 与 strict 各预编译为一条 alternation，
// 请求路径单遍扫描替代逐规则多次全串扫描；命中后按原顺序回查个别规则取回命中名，
// 返回值与逐条实现完全一致（首个命中规则名）。规则集静态（包级 var），编译一次。
var (
	wafNormalMerged = wafMergeRules(false)
	wafStrictMerged = wafMergeRules(true)
)

// wafMergeRules 把（按 strict 过滤后的）规则模式串逐条以 (?:...) 包裹后 alternation 合并。
// 独立预编译，不改动 wafRules 原始定义（个别回查仍用原规则对象）。
func wafMergeRules(strict bool) *regexp.Regexp {
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
	// 单遍快筛：一条合并正则扫完（替代逐规则多次全串扫描）
	merged := wafNormalMerged
	if strict {
		merged = wafStrictMerged
	}
	if merged != nil && !merged.MatchString(s) {
		return ""
	}
	// 命中：按原顺序回查个别规则，返回首个命中名（与逐条扫描语义一致）
	for _, rule := range wafRules {
		if rule.strict && !strict {
			continue
		}
		if rule.re.MatchString(s) {
			return rule.name
		}
	}
	return ""
}

// ===================== 新增检测规则（v1.0.2 功能强化） =====================

// scannerUABlacklist：常见扫描器 / 渗透工具的 User-Agent 特征（小写子串匹配）
var scannerUABlacklist = []string{
	"sqlmap", "nikto", "nmap scripting engine", "masscan", "zgrab",
	"dirbuster", "gobuster", "ffuf", "nuclei", "wpscan", "acunetix",
	"nessus", "openvas", "metasploit", "burpsuite", "havij", "hydra",
	"w3af", "arachni", "whatweb", "dotdotpwn",
}

// sensitivePathPatterns：敏感路径探测特征（小写子串匹配）。
// 注意：本系统自身的管理面板（/admin）与 API（/api/、/v1/、/mcp）
// 属于合法路由，在 isOwnAppRoute 中豁免，不参与敏感路径拦截，
// 以保证向后兼容、不破坏现有功能。
var sensitivePathPatterns = []string{
	"/.env", "/.git", "/.svn", "/.ssh", "/.aws", "/.ds_store",
	"/.htaccess", "/.htpasswd", "/.idea",
	"/wp-admin", "/wp-login", "/wp-content", "/xmlrpc.php",
	"/phpmyadmin", "/pma/",
	"/admin/", "/administrator",
	"/server-status", "/actuator", "/.bak", "/.sql",
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
func scannerUAMatch(ua string) string {
	if ua == "" {
		return ""
	}
	lower := strings.ToLower(ua)
	for _, s := range scannerUABlacklist {
		if strings.Contains(lower, s) {
			return s
		}
	}
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
	// 5) 大文件上传检测（新增）：Content-Length 超过 maxBodyBytes 直接拦截
	if r.ContentLength > maxBodyBytes {
		return "请求体过大"
	}
	// 6) 路径与查询串检测（所有模式都查）
	if reason := wafMatch(r.URL.Path+" "+r.URL.RawQuery, false); reason != "" {
		return reason
	}
	// 7) 请求体扫描：工具端点总是扫描；strict 模式下扫描所有端点
	strict := wafStrict()
	toolEndpoint := strings.Contains(r.URL.Path, "/mcp") || strings.HasPrefix(r.URL.Path, "/api/tools/")
	if !toolEndpoint && !strict {
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
		if reason := wafScanBody(b, strict); reason != "" {
			return reason
		}
	}
	return ""
}

// wafScanBody：normal 模式只扫描工具调用参数中的字符串值（降低聊天内容误报），
// strict 模式扫描整个请求体。
func wafScanBody(b []byte, strict bool) string {
	if strict {
		return wafMatch(string(b), true)
	}
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
