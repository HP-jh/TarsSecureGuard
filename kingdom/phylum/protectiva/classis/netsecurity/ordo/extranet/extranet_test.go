package extranet

import (
	"net/http"
	"testing"
)

func TestNewGuard(t *testing.T) {
	g := NewGuard()
	if g == nil {
		t.Fatal("guard nil")
	}
	if !g.enabled {
		t.Fatal("should be enabled by default")
	}
}

func TestGuardCheckAllowlist(t *testing.T) {
	g := NewGuard()
	req, _ := http.NewRequest("GET", "https://github.com/foo", nil)
	ok, reason := g.CheckRequest(req)
	if !ok {
		t.Fatalf("github should be allowed, got: %s", reason)
	}
}

func TestGuardCheckBlocklist(t *testing.T) {
	g := NewGuard()
	req, _ := http.NewRequest("GET", "https://malware.example/test", nil)
	ok, reason := g.CheckRequest(req)
	if ok {
		t.Fatal("malware.example should be blocked")
	}
	if reason == "" {
		t.Fatal("should have block reason")
	}
}

func TestGuardCheckPrivateIP(t *testing.T) {
	g := NewGuard()
	req, _ := http.NewRequest("GET", "http://192.168.1.1/secret", nil)
	ok, reason := g.CheckRequest(req)
	if ok {
		t.Fatal("private IP should be blocked")
	}
	if reason != "private IP blocked" {
		t.Fatalf("reason = %s, want private IP blocked", reason)
	}
}
