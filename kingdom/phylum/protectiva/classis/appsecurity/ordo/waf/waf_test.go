package waf

import (
	"net/http/httptest"
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine(DefaultRules(), "normal")
	if e == nil {
		t.Fatal("engine nil")
	}
	if !e.enabled {
		t.Fatal("should be enabled")
	}
}

func TestCheckRequestClean(t *testing.T) {
	e := NewEngine(DefaultRules(), "normal")
	req := httptest.NewRequest("GET", "http://127.0.0.1:18889/health", nil)
	blocked, reason := e.CheckRequest(req)
	if blocked {
		t.Fatalf("clean request blocked: %s", reason)
	}
}

func TestCheckRequestSQLi(t *testing.T) {
	e := NewEngine(DefaultRules(), "strict")
	// 使用触发字节 ; 确保预筛命中
	req := httptest.NewRequest("GET", "http://127.0.0.1:18889/api?id=1;union+select", nil)
	blocked, reason := e.CheckRequest(req)
	if !blocked {
		t.Fatal("SQLi should be blocked")
	}
	if reason != "SQL注入" {
		t.Fatalf("reason = %s, want SQL注入", reason)
	}
}

func TestCheckRequestXSS(t *testing.T) {
	e := NewEngine(DefaultRules(), "strict")
	req := httptest.NewRequest("GET", "http://127.0.0.1:18889/api?q=<script>alert(1)</script>", nil)
	blocked, _ := e.CheckRequest(req)
	if !blocked {
		t.Fatal("XSS should be blocked")
	}
}

func TestCheckRequestPathTraversal(t *testing.T) {
	e := NewEngine(DefaultRules(), "normal")
	req := httptest.NewRequest("GET", "http://127.0.0.1:18889/api?path=../../etc/passwd", nil)
	blocked, _ := e.CheckRequest(req)
	if !blocked {
		t.Fatal("path traversal should be blocked")
	}
}

func TestEngineDisabled(t *testing.T) {
	e := NewEngine(DefaultRules(), "normal")
	e.SetEnabled(false)
	req := httptest.NewRequest("GET", "http://127.0.0.1:18889/api?id=1;union+select", nil)
	blocked, _ := e.CheckRequest(req)
	if blocked {
		t.Fatal("disabled engine should not block")
	}
}
