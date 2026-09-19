package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var wafRules = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(union\s+select|or\s+1=1|information_schema|load_file\()`),
	regexp.MustCompile(`(\.\./\.\./|/etc/passwd|/etc/shadow|;\s*rm\s+-rf|;\s*del\s+/[fq])`),
	regexp.MustCompile(`(?i)(<script[\s>]|javascript:\s*|onerror\s*=|onload\s*=|alert\s*\(|<iframe)`),
	regexp.MustCompile(`(?i)(\{\{.*\.env.*\}\}|<\%.*eval|\$\{.*jndi:)`),
}

func wafCheck(r *http.Request) string {
	if gatewayMode() == "off" {
		return ""
	}
	if !allowRequest(clientIP(r)) {
		return "rate limit exceeded"
	}
	if q := r.URL.RawQuery; q != "" {
		if matched := scanRules(q); matched != "" {
			return "query string blocked: " + matched
		}
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "json") || strings.Contains(ct, "form") || ct == "" {
			if r.Body != nil {
				body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
				if err != nil {
					return "body read error"
				}
					r.Body.Close()
					if int64(len(body)) > maxBodyBytes {
						return "body too large"
					}
					if matched := scanRules(string(body)); matched != "" {
						return "body payload blocked: " + matched
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
	}
	return ""
}

func scanRules(s string) string {
	for _, re := range wafRules {
		if loc := re.FindString(s); loc != "" {
			if len(loc) > 40 {
				loc = loc[:40] + "..."
			}
			return loc
		}
	}
	return ""
}

func gatewayMode() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.Security.Mode
}

func blockRequest(w http.ResponseWriter, r *http.Request, reason string) {
	mu.Lock()
	wafBlocks++
	entry := fmt.Sprintf("[%s][%s] %s %s - %s", nowTimeStr(), clientIP(r), r.Method, r.URL.Path, reason)
	wafLogs = append(wafLogs, entry)
	if len(wafLogs) > wafLogLimit {
		wafLogs = wafLogs[len(wafLogs)-wafLogLimit:]
	}
	mu.Unlock()
	logMsg("WAF blocked: " + r.URL.Path + " - " + reason)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, `{"blocked":true}`)
}
