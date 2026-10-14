// v4.7.5 B17 安全加固：全请求头 CRLF/NULL 注入检测
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestV475VersionBumped(t *testing.T) {
	if version != "4.7.6" {
		t.Fatalf("version expected 4.7.6, got %s", version)
	}
}

// TestV475CRLFInXForwardedFor CRLF 注入 X-Forwarded-For 头必须被拦截
func TestV475CRLFInXForwardedFor(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4\r\nX-Injected: yes")
	if reason := wafCheck(req); reason == "" {
		t.Fatal("CRLF in X-Forwarded-For 必须被拦截")
	} else if !strings.Contains(reason, "CRLF") || !strings.Contains(reason, "X-Forwarded-For") {
		t.Errorf("拦截原因应同时提到 CRLF 和字段名, got %q", reason)
	}
	_ = rec
}

// TestV475NULLInAuthorization NULL 字节注入 Authorization 头必须被拦截
func TestV475NULLInAuthorization(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer abc\x00def")
	if reason := wafCheck(req); reason == "" {
		t.Fatal("NULL in Authorization 必须被拦截")
	} else if !strings.Contains(reason, "Authorization") {
		t.Errorf("拦截原因应提到字段名 Authorization, got %q", reason)
	}
}

// TestV475CRLFInCookie Cookie 注入必须被拦截
func TestV475CRLFInCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Cookie", "session=abc\r\nSet-Cookie: evil=1")
	if reason := wafCheck(req); reason == "" {
		t.Fatal("CRLF in Cookie 必须被拦截")
	} else if !strings.Contains(reason, "Cookie") {
		t.Errorf("拦截原因应提到字段名 Cookie, got %q", reason)
	}
}

// TestV475CRLFInUserAgent UA 注入必须被拦截
func TestV475CRLFInUserAgent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0\r\nX-Evil: pwned")
	if reason := wafCheck(req); reason == "" {
		t.Fatal("CRLF in User-Agent 必须被拦截")
	} else if !strings.Contains(reason, "User-Agent") {
		t.Errorf("拦截原因应提到字段名 User-Agent, got %q", reason)
	}
}

// TestV475NormalHeadersPass 正常头不能被误拦
func TestV475NormalHeadersPass(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("X-API-Key", "sk-test-1234567890")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if reason := wafCheck(req); reason != "" {
		t.Errorf("正常头不应被拦, got %q", reason)
	}
}

// TestV475EmptyValuePass 空值头不应被拦（边界）
func TestV475EmptyValuePass(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-Empty", "")
	if reason := wafCheck(req); reason != "" {
		t.Errorf("空值头不应被拦, got %q", reason)
	}
}

// TestV475HostInjectionStillWorks Host 头注入检测（v4.7.1）必须继续生效
func TestV475HostInjectionStillWorks(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "evil.com\r\nHost: legit.com"
	if reason := wafCheck(req); reason == "" {
		t.Fatal("Host 头注入必须被拦截")
	} else if !strings.Contains(reason, "Host 头注入") {
		t.Errorf("Host 头注入拦截原因不匹配, got %q", reason)
	}
}
