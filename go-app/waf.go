package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ===================== WAF 安全模块 =====================
//
// 设计原则（v1.0.1）：
//   - 只检测"试图攻击网关本身/绕过网关保护"的输入
//   - 不做内容审核（不判断用户问 AI 的问题是否违法）
//   - normal 模式只扫工具调用参数和路径；strict 模式扫全部

var wafRules = []struct {
	name   string
	re     *regexp.Regexp
	strict bool
}{
	// --- 路径穿越（含 URL 编码、双重编码、反斜杠变体）---
	{"路径穿越", regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e|%2e%2f|%2e%5c|%252e|%252e%252e|/etc/passwd|/etc/shadow|/proc/self|win\.ini|boot\.ini|\.ssh[/\\]id_|\.aws[/\\]credentials|\.gnupg|\.env\b)`), false},

	// --- 命令注入（;cmd / && / | / $() / 反引号 / 换行符分隔）---
	{"命令注入", regexp.MustCompile(`(?i)(;\s*(cmd|powershell|pwsh|bash|sh|wget|curl|net\b|taskkill|ping|nc\b|python|perl|ruby)\b|\|\s*(cmd|powershell|bash|sh)\b|&&\s*(cmd|powershell|bash|sh)\b|\$\([^)]+\)|\x60[a-z]+\x60|\n\s*(cmd|powershell|bash)\b)`), false},

	// --- 空字节 / 编码绕过 ---
	{"编码绕过", regexp.MustCompile(`\x00|%00`), false},

	// --- SQL 注入（strict，仅工具/管理端点）---
	{"SQL 注入", regexp.MustCompile(`(?i)(\bunion\b\s+\bselect\b|\binsert\b\s+\binto\b|\bdelete\b\s+\bfrom\b|\bdrop\b\s+\btable\b|/\*.*\*/|;\s*\bdrop\b|\bsleep\s*\(\d+\)|\bbenchmark\s*\()`), true},

	// --- XSS（strict，仅工具/管理端点；聊天内容由后端模型自己处理）---
	{"XSS", regexp.MustCompile(`(?i)(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe|document\.cookie|<\s*object|<\s*embed)`), true},

	// --- 试图直接探测网关管理配置（非管理 API 路径不应包含这些）---
	{"敏感路径探测", regexp.MustCompile(`(?i)(/config\.json\b|/\.git|/\.env\b|/wp-admin|/phpmyadmin|/admin\.php|/\.htaccess)`), false},
}

func wafMatch(s string, strict bool) string {
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

// wafDecode 对输入做一次 URL 解码，用于检测 %2e%2e 这类编码绕过
func wafDecode(s string) string {
	if dec, err := url.QueryUnescape(s); err == nil {
		return dec
	}
	return s
}

func wafCheck(r *http.Request) string {
	if !wafEnabled() {
		return ""
	}
	// 1) 速率限制
	if !allowRequest(clientIP(r)) {
		return "请求频率超限"
	}
	// 2) 路径与查询串检测（含 URL 解码后的二次扫描）
	pathAndQuery := r.URL.Path + " " + r.URL.RawQuery
	if reason := wafMatch(pathAndQuery, false); reason != "" {
		return reason
	}
	if reason := wafMatch(wafDecode(pathAndQuery), false); reason != "" {
		return reason + "（编码绕过）"
	}
	// 3) 请求体扫描：工具端点总是扫描；strict 模式下扫描所有端点
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
	// 对工具参数同时做一次 URL 解码扫描，防 %2e%2e 绕过
	if reason := wafMatch(wafDecode(sb.String()), false); reason != "" {
		return reason + "（编码绕过）"
	}
	return wafMatch(sb.String(), false)
}

func blockRequest(w http.ResponseWriter, r *http.Request, reason string) {
	now := time.Now().Format("15:04:05")
	mu.Lock()
	wafBlocks++
	if len(wafLogs) >= wafLogLimit {
		wafLogs = wafLogs[len(wafLogs)-wafLogLimit+1:]
	}
	wafLogs = append(wafLogs, fmt.Sprintf("[%s] %s %s %s → BLOCKED (%s)", now, clientIP(r), r.Method, r.URL.Path, reason))
	mu.Unlock()
	logMsg(fmt.Sprintf("[WAF] BLOCK %s %s (%s)", r.Method, r.URL.Path, reason))
	writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "blocked by WAF: " + reason})
}
