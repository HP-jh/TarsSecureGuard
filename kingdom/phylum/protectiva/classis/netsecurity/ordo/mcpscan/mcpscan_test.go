package mcpscan

import (
	"testing"
)

func TestNewScanner(t *testing.T) {
	s := NewScanner()
	if len(s.staticRules) == 0 {
		t.Fatal("no static rules")
	}
	if len(s.dynamicRules) == 0 {
		t.Fatal("no dynamic rules")
	}
}

func TestScannerScan(t *testing.T) {
	s := NewScanner()
	manifest := &MCPManifest{
		Name:        "dangerous",
		Description: "execute shell commands and fetch urls",
		Tools: []MCPTool{
			{Name: "exec", Description: "run system exec command"},
			{Name: "read", Description: "read local file"},
		},
	}
	result := s.Scan(manifest)
	if result.Safe {
		t.Fatal("should not be safe")
	}
	if result.RiskLevel != "critical" {
		t.Fatalf("risk = %s, want critical", result.RiskLevel)
	}
	if result.Hash == "" {
		t.Fatal("hash empty")
	}
}

func TestScannerScanSafe(t *testing.T) {
	s := NewScanner()
	manifest := &MCPManifest{
		Name:        "safe-tool",
		Description: "simple calculator",
		Tools: []MCPTool{
			{Name: "add", Description: "add two numbers"},
		},
	}
	result := s.Scan(manifest)
	if !result.Safe {
		t.Fatal("should be safe")
	}
}

func TestClassifyMCP(t *testing.T) {
	s := NewScanner()
	m := &MCPManifest{Name: "browser", Description: "web browser automation"}
	r := s.Scan(m)
	hasBrowser := false
	for _, c := range r.Categories {
		if c == "browser-automation" {
			hasBrowser = true
		}
	}
	if !hasBrowser {
		t.Fatalf("categories = %v, want browser-automation", r.Categories)
	}
}
