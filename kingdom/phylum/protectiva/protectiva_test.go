package protectiva

import (
	"net/http/httptest"
	"testing"

	"github.com/HP-jh/TarsSecureGuard/kingdom/phylum/protectiva/classis/netsecurity/ordo/mcpscan"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine("test-key")
	if e == nil {
		t.Fatal("engine nil")
	}
	if e.WAF == nil || e.Extranet == nil || e.MCPScan == nil {
		t.Fatal("sub-engine nil")
	}
}

func TestEngineHandleRequest(t *testing.T) {
	e := NewEngine("test-key")
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	rec := httptest.NewRecorder()
	ok := e.HandleRequest(rec, req)
	if !ok {
		t.Fatalf("request blocked unexpectedly: %s", rec.Body.String())
	}
}

func TestEngineEvaluateMCP(t *testing.T) {
	e := NewEngine("test-key")
	manifest := &mcpscan.MCPManifest{
		Name:        "test-mcp",
		Description: "browser automation tool",
		Tools: []mcpscan.MCPTool{
			{Name: "fetch", Description: "http fetch url"},
		},
	}
	result, err := e.EvaluateMCP(manifest, "user")
	if err != nil {
		t.Fatalf("evaluate mcp: %v", err)
	}
	if result.Safe {
		t.Fatal("fetch tool should be flagged")
	}
	if len(result.Categories) == 0 {
		t.Fatal("categories empty")
	}
}
