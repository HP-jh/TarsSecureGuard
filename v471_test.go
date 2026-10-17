// v4.7.3 WAF 安全加固测试：Host 头注入检测 + HTTP 请求走私检测
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestV471VersionBumped 版本号必须已升至 4.15.0
func TestV471VersionBumped(t *testing.T) {
	if version != "4.15.1" {
		t.Fatalf("version expected 4.15.0, got %s", version)
	}
}

// TestV471HostHeaderInjectionDetection 验证 WAF 能拦截含换行符/空字节的 Host 头
// 这是 HTTP 响应分割、缓存投毒、虚拟主机混淆等攻击的经典向量
func TestV471HostHeaderInjectionDetection(t *testing.T) {
	// 1) Host 头含 \r\n → 应当被拦截
	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/health", nil)
	req.Host = "evil.com\r\nX-Injected: malicious"
	if reason := wafCheck(req); !strings.Contains(reason, "Host 头注入") {
		t.Errorf("Host 头含 CRLF 应被拦截，实际 reason=%q", reason)
	}

	// 2) Host 头含 \x00 → 应当被拦截
	req2 := httptest.NewRequest(http.MethodPost, "http://example.com/api/chat", nil)
	req2.Host = "evil.com\x00.attacker.com"
	if reason := wafCheck(req2); !strings.Contains(reason, "Host 头注入") {
		t.Errorf("Host 头含 NULL 字节应被拦截，实际 reason=%q", reason)
	}

	// 3) 正常 Host 头 → 不应触发 Host 头注入拦截
	req3 := httptest.NewRequest(http.MethodGet, "http://normal-host.example.com/api/health", nil)
	req3.Host = "normal-host.example.com"
	if reason := wafCheck(req3); reason == "Host 头注入" {
		t.Errorf("正常 Host 头不应被误判，实际 reason=%q", reason)
	}
}

// TestV471HTTPSmugglingDetection 验证 WAF 能拦截同时存在
// Content-Length 和 Transfer-Encoding 头的请求走私攻击
func TestV471HTTPSmugglingDetection(t *testing.T) {
	// 1) 同时设置 Content-Length 和 Transfer-Encoding → 应当被拦截
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/chat", strings.NewReader("body"))
	req.Header.Set("Transfer-Encoding", "chunked")
	req.ContentLength = 4
	if reason := wafCheck(req); !strings.Contains(reason, "HTTP 请求走私") {
		t.Errorf("CL+TE 双重头应被拦截，实际 reason=%q", reason)
	}

	// 2) 仅设置 Content-Length → 不应触发走私拦截（可能被其他规则拦截但不是走私）
	req2 := httptest.NewRequest(http.MethodPost, "http://example.com/api/chat", strings.NewReader("body"))
	req2.ContentLength = 4
	if reason := wafCheck(req2); strings.Contains(reason, "HTTP 请求走私") {
		t.Errorf("仅 Content-Length 不应被识别为走私，实际 reason=%q", reason)
	}

	// 3) 仅设置 Transfer-Encoding → 不应触发走私拦截
	req3 := httptest.NewRequest(http.MethodPost, "http://example.com/api/chat", strings.NewReader("body"))
	req3.Header.Set("Transfer-Encoding", "chunked")
	req3.ContentLength = -1 // 显式不设置 Content-Length
	if reason := wafCheck(req3); strings.Contains(reason, "HTTP 请求走私") {
		t.Errorf("仅 Transfer-Encoding 不应被识别为走私，实际 reason=%q", reason)
	}
}
