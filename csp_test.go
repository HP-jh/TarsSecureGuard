package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ===================== v4.34.0 CSP 策略自动生成测试 =====================

func TestVersion434(t *testing.T) {
	if version != "4.34.0" {
		t.Fatalf("版本号应为 4.34.0，实际 %s", version)
	}
}

// TestNormalizeSrc 测试 URL 归一化
func TestNormalizeSrc(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", "'self'"},
		{"/js/app.js", "'self'"},
		{"./style.css", "'self'"},
		{"https://cdn.example.com/lib.js", "https://cdn.example.com"},
		{"https://cdn.example.com:8443/lib.js", "https://cdn.example.com:8443"},
		{"//cdn.example.com/lib.js", "https://cdn.example.com"},
		{"data:image/png;base64,abc", "data:"},
		{"blob:uuid", "blob:"},
		{"javascript:alert(1)", ""},
		{"vbscript:msgbox(1)", ""},
	}
	for _, c := range cases {
		got := normalizeSrc(c.input)
		if got != c.want {
			t.Errorf("normalizeSrc(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// TestExtractResources 测试 HTML 资源提取
func TestExtractResources(t *testing.T) {
	html := `<!doctype html>
<html>
<head>
  <link rel="stylesheet" href="https://cdn.example.com/style.css">
  <link href="https://fonts.example.com/font.css" rel="stylesheet">
  <link rel="icon" href="/favicon.ico">
</head>
<body>
  <script src="https://cdn.example.com/app.js"></script>
  <script>console.log('inline')</script>
  <img src="/logo.png">
  <img src="data:image/png;base64,abc">
  <iframe src="https://embed.example.com/frame"></iframe>
  <form action="/submit"></form>
  <video src="/demo.mp4"></video>
  <source src="/demo.webm">
  <div onerror="alert(1)">x</div>
  <span style="color:red">y</span>
  <style>.a{}</style>
</body>
</html>`

	refs := extractResources([]byte(html))
	m := map[string][]string{}
	for _, r := range refs {
		m[r.directive] = append(m[r.directive], r.value)
	}

	// script-src: 'self' (relative), https://cdn.example.com, 'unsafe-inline' (inline script + onerror)
	if !contains(m["script-src"], "https://cdn.example.com") {
		t.Error("script-src 应包含 https://cdn.example.com")
	}
	if !contains(m["script-src"], "'unsafe-inline'") {
		t.Error("script-src 应包含 'unsafe-inline'（存在内联脚本/onerror）")
	}

	// style-src: https://cdn.example.com, https://fonts.example.com, 'unsafe-inline'
	if !contains(m["style-src"], "https://cdn.example.com") {
		t.Error("style-src 应包含 https://cdn.example.com")
	}
	if !contains(m["style-src"], "https://fonts.example.com") {
		t.Error("style-src 应包含 https://fonts.example.com")
	}

	// img-src: 'self', data:
	if !contains(m["img-src"], "'self'") {
		t.Error("img-src 应包含 'self'")
	}
	if !contains(m["img-src"], "data:") {
		t.Error("img-src 应包含 data:")
	}

	// frame-src: https://embed.example.com
	if !contains(m["frame-src"], "https://embed.example.com") {
		t.Error("frame-src 应包含 https://embed.example.com")
	}

	// form-action: 'self'
	if !contains(m["form-action"], "'self'") {
		t.Error("form-action 应包含 'self'")
	}

	// media-src: 'self'
	if !contains(m["media-src"], "'self'") {
		t.Error("media-src 应包含 'self'")
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// TestBuildCSPPolicy 测试策略生成
func TestBuildCSPPolicy(t *testing.T) {
	refs := []resourceRef{
		{"script-src", "'self'"},
		{"script-src", "https://cdn.example.com"},
		{"style-src", "'self'"},
		{"img-src", "data:"},
	}
	cfg := CSPConfig{Enabled: true, Mode: "enforce"}
	policy := buildCSPPolicy(refs, cfg)
	str := policy.String()

	if !strings.Contains(str, "script-src") {
		t.Error("策略应包含 script-src")
	}
	if !strings.Contains(str, "style-src") {
		t.Error("策略应包含 style-src")
	}
	if !strings.Contains(str, "img-src") {
		t.Error("策略应包含 img-src")
	}
	// 验证分号分隔
	if !strings.Contains(str, ";") {
		t.Error("策略应使用分号分隔指令")
	}
}

// TestBuildCSPPolicyEmpty 测试空资源时生成兜底策略
func TestBuildCSPPolicyEmpty(t *testing.T) {
	cfg := CSPConfig{Enabled: true, Mode: "enforce"}
	policy := buildCSPPolicy(nil, cfg)
	str := policy.String()

	if !strings.Contains(str, "default-src 'self'") {
		t.Errorf("空资源时应生成兜底策略，实际: %s", str)
	}
}

// TestBuildCSPPolicyReportOnly 测试 report-only 模式
func TestBuildCSPPolicyReportOnly(t *testing.T) {
	cfg := CSPConfig{Enabled: true, Mode: "report-only", ReportURI: "/api/csp-report"}
	refs := []resourceRef{{"script-src", "'self'"}}
	policy := buildCSPPolicy(refs, cfg)
	str := policy.String()
	if !strings.Contains(str, "report-uri /api/csp-report") {
		t.Errorf("report-uri 应出现在策略中，实际: %s", str)
	}
}

// TestCSPInterceptWriter 测试响应拦截器
func TestCSPInterceptWriter(t *testing.T) {
	w := httptest.NewRecorder()
	ci := newCSPInterceptWriter(w)

	// 设 Content-Type 为 text/html
	ci.Header().Set("Content-Type", "text/html")
	ci.WriteHeader(http.StatusOK)
	body := []byte("<html><script src='/app.js'></script></html>")
	n, err := ci.Write(body)
	if err != nil {
		t.Fatalf("Write 失败: %v", err)
	}
	if n != len(body) {
		t.Fatalf("Write 返回长度 %d，期望 %d", n, len(body))
	}

	// 底层 ResponseWriter 应收到内容
	if !bytes.Equal(w.Body.Bytes(), body) {
		t.Error("底层 ResponseWriter 未收到正确内容")
	}

	// htmlBody 应返回相同内容
	if !bytes.Equal(ci.htmlBody(), body) {
		t.Error("htmlBody 返回内容与写入不符")
	}
}

// TestCSPInterceptWriterNonHTML 测试非 HTML 响应不缓冲
func TestCSPInterceptWriterNonHTML(t *testing.T) {
	w := httptest.NewRecorder()
	ci := newCSPInterceptWriter(w)

	ci.Header().Set("Content-Type", "application/json")
	ci.WriteHeader(http.StatusOK)
	body := []byte(`{"ok":true}`)
	ci.Write(body)

	if ci.htmlBody() != nil {
		t.Error("非 HTML 响应 htmlBody 应为 nil")
	}
}

// TestCSPMiddlewareIntegration 测试完整中间件集成
func TestCSPMiddlewareIntegration(t *testing.T) {
	// enforce 模式
	cfg.Security.CSP = CSPConfig{Enabled: true, Mode: "enforce"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script src="https://cdn.example.com/app.js"></script></html>`))
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	cspWrapHandler(handler).ServeHTTP(w, r)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("enforce 模式应设置 Content-Security-Policy")
	}
	if !strings.Contains(csp, "https://cdn.example.com") {
		t.Errorf("CSP 应包含外部脚本源，实际: %s", csp)
	}
	if w.Header().Get("Content-Security-Policy-Report-Only") != "" {
		t.Error("enforce 模式不应设置 Report-Only 头")
	}
}

// TestCSPMiddlewareReportOnly 测试 report-only 模式
func TestCSPMiddlewareReportOnly(t *testing.T) {
	cfg.Security.CSP = CSPConfig{Enabled: true, Mode: "report-only"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>alert(1)</script></html>`))
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	cspWrapHandler(handler).ServeHTTP(w, r)

	if w.Header().Get("Content-Security-Policy-Report-Only") == "" {
		t.Fatal("report-only 模式应设置 CSP-Report-Only")
	}
	if w.Header().Get("Content-Security-Policy") != "" {
		t.Error("report-only 模式不应设置 enforce CSP")
	}
}

// TestCSPMiddlewareStaticFallback 测试降级静态模式
func TestCSPMiddlewareStaticFallback(t *testing.T) {
	cfg.Security.CSP = CSPConfig{StaticOnly: true}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script src="https://evil.com/xss.js"></script></html>`))
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	cspWrapHandler(handler).ServeHTTP(w, r)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("降级模式应使用静态兜底策略，实际: %s", csp)
	}
}

// TestCSPMiddlewareJSON 测试 JSON 响应保持静态策略
func TestCSPMiddlewareJSON(t *testing.T) {
	cfg.Security.CSP = CSPConfig{Enabled: true, Mode: "enforce"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/status", nil)
	cspWrapHandler(handler).ServeHTTP(w, r)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("JSON 响应也应设置 CSP（静态兜底）")
	}
}

// TestQuickHash 测试缓存哈希稳定性
func TestQuickHash(t *testing.T) {
	a := quickHash([]byte("hello"))
	b := quickHash([]byte("hello"))
	c := quickHash([]byte("world"))
	if a != b {
		t.Error("相同输入应产生相同哈希")
	}
	if a == c {
		t.Error("不同输入应产生不同哈希")
	}
}

// TestCachedCSP 测试 CSP 缓存
func TestCachedCSP(t *testing.T) {
	body := []byte("<html><script src='/app.js'></script></html>")
	policy := "script-src 'self'; style-src 'self'"
	storeCSP(body, policy)

	got, ok := cachedCSP(body)
	if !ok {
		t.Fatal("缓存应命中")
	}
	if got != policy {
		t.Errorf("缓存值不符: got %q, want %q", got, policy)
	}
}

// TestHasInlineScript 测试内联脚本检测
func TestHasInlineScript(t *testing.T) {
	if !hasInlineScript("<script>alert(1)</script>") {
		t.Error("应检测出内联 script")
	}
	if hasInlineScript(`<script src="/app.js"></script>`) {
		t.Error("有 src 的 script 不应视为内联")
	}
	if hasInlineScript("<div>hello</div>") {
		t.Error("无 script 标签应返回 false")
	}
}

// TestExtractResourcesNoInline 测试无内联资源时
func TestExtractResourcesNoInline(t *testing.T) {
	html := `<html><body><p>hello</p></body></html>`
	refs := extractResources([]byte(html))
	for _, r := range refs {
		if r.value == "'unsafe-inline'" {
			t.Error("无内联脚本/样式/事件时不应出现 'unsafe-inline'")
		}
	}
}
