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

var wafRules = []struct {
	name   string
	re     *regexp.Regexp
	strict bool
}{
	{"路径穿越", regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e|%2e%2f|%252e)`), false},
	{"命令注入", regexp.MustCompile("(?i)(;\\s*(cmd|powershell|pwsh|bash|sh|wget|curl|net|taskkill|ping)\\b|&&|;\\s*\\x60[a-z]+\\x60)"), false},
	{"SQL 注入", regexp.MustCompile(`(?i)(\bunion\b\s+\bselect\b|\binsert\b\s+\binto\b|\bdelete\b\s+\bfrom\b|\bdrop\b\s+\btable\b|/\*|;\s*\bdrop\b|\bsleep\s*\(|\bbenchmark\s*\()"), true},
	{"XSS", regexp.MustCompile(`(?i)(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe|document\.cookie|<\s*object)`), true},
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

func wafCheck(r *http.Request) string {
	if !wafEnabled() {
		return ""
	}
	if !allowRequest(clientIP(r)) {
		return "请求频率超限"
	}
	if reason := wafMatch(r.URL.Path+" "+r.URL.RawQuery, false); reason != "" {
		return reason
	}
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

func blockRequest(w http.ResponseWriter, r *http.Request, reason string) {
	now := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s %s %s → BLOCKED (%s)", now, clientIP(r), r.Method, r.URL.Path, reason)
	mu.Lock()
	wafBlocks++
	if len(wafLogs) >= wafLogLimit {
		wafLogs = wafLogs[len(wafLogs)-wafLogLimit+1:]
	}
	wafLogs = append(wafLogs, entry)
	mu.Unlock()
	logMsg(fmt.Sprintf("[WAF] BLOCK %s %s (%s)", r.Method, r.URL.Path, reason))
	appendLog("waf.log", fmt.Sprintf("%s %s %s", clientIP(r), r.Method, r.URL.Path))
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `{"error":"blocked by WAF: %s"}`, reason)
}
