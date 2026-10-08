package mcpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPInitialize(t *testing.T) {
	srv := NewServer()
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]string{"protocolVersion": "2024-11-05"},
	})
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.HandleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Fatalf("expected jsonrpc 2.0, got %v", resp["jsonrpc"])
	}
}

func TestMCPToolsList(t *testing.T) {
	srv := NewServer()
	srv.RegisterTool(&ToolDef{Name: "toolA", Description: "descA"}, func(args map[string]any) (any, error) {
		return nil, nil
	})

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.HandleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	result := resp["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
}

func TestMCPToolsCall(t *testing.T) {
	srv := NewServer()
	srv.RegisterTool(&ToolDef{Name: "echo", Description: "echoes input"}, func(args map[string]any) (any, error) {
		return args["text"], nil
	})

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "echo",
			"arguments": map[string]string{"text": "hello"},
		},
	})
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.HandleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	result := resp["result"].(map[string]interface{})
	content := result["content"].([]interface{})
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
}
