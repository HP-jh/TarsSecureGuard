package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGenerateCSPPolicy 测试 CSP 策略自动生成
func TestGenerateCSPPolicy(t *testing.T) {
	policy := generateCSPPolicy()
	if policy == nil {
		t.Fatal("generateCSPPolicy returned nil")
	}
	if policy.String == "" {
		t.Fatal("CSP policy string is empty")
	}
	if policy.Source != "auto" {
		t.Fatalf("expected source=auto, got %q", policy.Source)
	}
	// 必须包含基础指令
	mustContain := []string{"default-src", "script-src", "style-src", "connect-src", "frame-ancestors"}
	for _, dir := range mustContain {
		if !strings.Contains(policy.String, dir) {
			t.Errorf("CSP policy missing directive: %s", dir)
		}
	}
	// 默认应包含 'self'
	if !strings.Contains(policy.String, "'self'") {
		t.Error("CSP policy missing 'self'")
	}
	// 内联脚本需要 unsafe-inline（前端为单文件内联）
	if !strings.Contains(policy.String, "'unsafe-inline'") {
		t.Error("CSP policy missing 'unsafe-inline' for inline scripts/styles")
	}
	// connect-src 应包含本机回环
	if !strings.Contains(policy.String, "127.0.0.1") {
		t.Error("CSP policy missing 127.0.0.1 in connect-src")
	}
}

// TestGenerateCSPPolicyCustomOverride 测试自定义策略覆盖
func TestGenerateCSPPolicyCustomOverride(t *testing.T) {
	cfgMu.Lock()
	old := cfg.Security.CSP.CustomPolicy
	cfg.Security.CSP.CustomPolicy = "default-src 'none'; script-src 'self'"
	cfgMu.Unlock()
	invalidateCSPCache()
	defer func() {
		cfgMu.Lock()
		cfg.Security.CSP.CustomPolicy = old
		cfgMu.Unlock()
		invalidateCSPCache()
	}()

	policy := generateCSPPolicy()
	if policy.Source != "custom" {
		t.Fatalf("expected source=custom, got %q", policy.Source)
	}
	if policy.String != "default-src 'none'; script-src 'self'" {
		t.Fatalf("unexpected custom policy: %s", policy.String)
	}
}

// TestApplyCSPHeaders 测试 CSP 头应用
func TestApplyCSPHeaders(t *testing.T) {
	// 正常模式
	cfgMu.Lock()
	cfg.Security.CSP.Enabled = true
	cfg.Security.CSP.ReportOnly = false
	cfg.Security.CSP.CustomPolicy = ""
	cfgMu.Unlock()
	invalidateCSPCache()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	applyCSPHeaders(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}
	if strings.Contains(csp, "Report-Only") {
		t.Error("normal mode should not contain Report-Only in header name")
	}
	cro := rec.Header().Get("Content-Security-Policy-Report-Only")
	if cro != "" {
		t.Error("normal mode should not set Report-Only header")
	}

	// report-only 模式
	cfgMu.Lock()
	cfg.Security.CSP.ReportOnly = true
	cfgMu.Unlock()
	invalidateCSPCache()

	rec2 := httptest.NewRecorder()
	applyCSPHeaders(rec2, req)
	if rec2.Header().Get("Content-Security-Policy") != "" {
		t.Error("report-only mode should not set enforce header")
	}
	cro2 := rec2.Header().Get("Content-Security-Policy-Report-Only")
	if cro2 == "" {
		t.Fatal("Content-Security-Policy-Report-Only header missing")
	}

	// 禁用模式
	cfgMu.Lock()
	cfg.Security.CSP.Enabled = false
	cfg.Security.CSP.ReportOnly = false
	cfgMu.Unlock()
	invalidateCSPCache()

	rec3 := httptest.NewRecorder()
	applyCSPHeaders(rec3, req)
	if rec3.Header().Get("Content-Security-Policy") != "" || rec3.Header().Get("Content-Security-Policy-Report-Only") != "" {
		t.Error("disabled mode should not set any CSP header")
	}
}

// TestCSPCache 测试 CSP 缓存机制
func TestCSPCache(t *testing.T) {
	invalidateCSPCache()
	p1 := getCSPPolicy()
	p2 := getCSPPolicy()
	if p1 != p2 {
		t.Error("getCSPPolicy should return cached instance")
	}
	invalidateCSPCache()
	p3 := getCSPPolicy()
	if p1 == p3 {
		t.Error("after invalidate, getCSPPolicy should return new instance")
	}
}

// TestParseCSPString 测试 CSP 字符串解析
func TestParseCSPString(t *testing.T) {
	dirs := parseCSPString("default-src 'self'; script-src 'self' 'unsafe-inline'; img-src data:")
	if len(dirs) != 3 {
		t.Fatalf("expected 3 directives, got %d", len(dirs))
	}
	if dirs[0].Name != "default-src" || len(dirs[0].Values) != 1 || dirs[0].Values[0] != "'self'" {
		t.Errorf("unexpected default-src: %+v", dirs[0])
	}
	if dirs[1].Name != "script-src" || len(dirs[1].Values) != 2 {
		t.Errorf("unexpected script-src: %+v", dirs[1])
	}
}

// TestHandleAdminCSPStatus 测试 CSP 状态查询 API
func TestHandleAdminCSPStatus(t *testing.T) {
	cfgMu.Lock()
	cfg.Security.CSP.Enabled = true
	cfg.Security.CSP.ReportOnly = false
	cfg.Security.CSP.CustomPolicy = ""
	cfgMu.Unlock()
	invalidateCSPCache()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/csp", nil)
	handleAdminCSPStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", resp["enabled"])
	}
	if resp["reportOnly"] != false {
		t.Errorf("expected reportOnly=false, got %v", resp["reportOnly"])
	}
	policy, ok := resp["policy"].(map[string]interface{})
	if !ok {
		t.Fatal("policy field missing or not object")
	}
	if policy["source"] != "auto" {
		t.Errorf("expected source=auto, got %v", policy["source"])
	}
}

// TestHandleAdminCSPUpdate 测试 CSP 配置更新 API
func TestHandleAdminCSPUpdate(t *testing.T) {
	cfgMu.Lock()
	oldEnabled := cfg.Security.CSP.Enabled
	oldReportOnly := cfg.Security.CSP.ReportOnly
	cfg.Security.CSP.Enabled = true
	cfg.Security.CSP.ReportOnly = false
	cfgMu.Unlock()
	invalidateCSPCache()
	defer func() {
		cfgMu.Lock()
		cfg.Security.CSP.Enabled = oldEnabled
		cfg.Security.CSP.ReportOnly = oldReportOnly
		cfgMu.Unlock()
		invalidateCSPCache()
	}()

	// 设置临时 configPath 使 saveConfigChecked 可工作
	oldConfigPath := configPath
	configPath = "/tmp/tsg-test-csp-config.json"
	defer func() { configPath = oldConfigPath }()

	body := map[string]interface{}{"reportOnly": true}
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/security/csp/update", bytes.NewReader(b))
	handleAdminCSPUpdate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	cfgMu.RLock()
	ro := cfg.Security.CSP.ReportOnly
	cfgMu.RUnlock()
	if !ro {
		t.Error("expected reportOnly to be true after update")
	}
}

// TestHandleCSPReport 测试 CSP 违规报告接收
func TestHandleCSPReport(t *testing.T) {
	cspReportMu.Lock()
	cspReports = nil
	cspReportMu.Unlock()

	report := map[string]interface{}{
		"csp-report": map[string]interface{}{
			"document-uri":       "http://127.0.0.1:18889/",
			"blocked-uri":        "https://evil.com/tracker.js",
			"violated-directive": "script-src",
			"original-policy":    "default-src 'self'",
		},
	}
	b, _ := json.Marshal(report)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/security/csp-report", bytes.NewReader(b))
	handleCSPReport(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	cspReportMu.Lock()
	count := len(cspReports)
	cspReportMu.Unlock()
	if count != 1 {
		t.Fatalf("expected 1 report, got %d", count)
	}
}

// TestExtractOrigin 测试来源提取
func TestExtractOrigin(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://cdn.example.com/path/to.js", "https://cdn.example.com"},
		{"http://localhost:3000/api", "http://localhost:3000"},
		{"https://example.com", "https://example.com"},
		{"/relative/path.js", ""},
		{"data:text/javascript,alert(1)", ""},
	}
	for _, c := range cases {
		got := extractOrigin(c.input)
		if got != c.expected {
			t.Errorf("extractOrigin(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
}

// TestGenerateNonce 测试 nonce 生成
func TestGenerateNonce(t *testing.T) {
	n1 := generateNonce()
	n2 := generateNonce()
	if n1 == "" || n2 == "" {
		t.Error("nonce should not be empty")
	}
	if n1 == n2 {
		t.Error("consecutive nonces should differ")
	}
	if len(n1) != 16 {
		t.Errorf("nonce length expected 16, got %d", len(n1))
	}
}

// TestCSPReportMemoryLimit 测试 CSP 报告内存限制
func TestCSPReportMemoryLimit(t *testing.T) {
	cspReportMu.Lock()
	cspReports = nil
	cspReportMu.Unlock()

	report := map[string]interface{}{
		"csp-report": map[string]interface{}{
			"document-uri":       "http://127.0.0.1:18889/",
			"blocked-uri":        "https://evil.com/tracker.js",
			"violated-directive": "script-src",
			"original-policy":    "default-src 'self'",
		},
	}
	b, _ := json.Marshal(report)

	for i := 0; i < 5100; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/admin/security/csp-report", bytes.NewReader(b))
		handleCSPReport(rec, req)
	}

	cspReportMu.Lock()
	count := len(cspReports)
	cspReportMu.Unlock()
	if count > 5000 {
		t.Fatalf("report buffer should be capped at 5000, got %d", count)
	}
	if count < 4900 {
		t.Fatalf("report buffer should retain recent entries, got %d", count)
	}
}

// TestSetSecurityHeadersWithCSP 测试 setSecurityHeaders 集成 CSP
func TestSetSecurityHeadersWithCSP(t *testing.T) {
	cfgMu.Lock()
	cfg.Security.CSP.Enabled = true
	cfg.Security.CSP.ReportOnly = false
	cfg.Security.CSP.CustomPolicy = ""
	cfgMu.Unlock()
	invalidateCSPCache()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	setSecurityHeaders(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options missing")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options missing")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy missing in setSecurityHeaders")
	}
	if !strings.Contains(csp, "default-src") {
		t.Error("CSP should contain default-src")
	}
}
