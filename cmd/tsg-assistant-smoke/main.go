// tsg-assistant-smoke runs live smoke tests against the assistant server.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"tarssecureguard-v41/crownext/assistant"
)

func main() {
	// Start server on a random port
	addr := "127.0.0.1:0"
	if a := os.Getenv("ASSISTANT_ADDR"); a != "" {
		addr = a
	}

	router := assistant.NewModelRouter(time.Hour)
	router.Register(&assistant.ProviderConfig{
		Name: "openai-gpt4", BaseURL: "https://api.openai.com/v1", APIKey: "sk-test",
		Model: "gpt-4o", Weight: 1.0, MaxRPM: 100, Capabilities: []string{"chat", "vision", "tools"},
		Healthy: true, LastCheck: time.Now(),
	})
	router.Register(&assistant.ProviderConfig{
		Name: "anthropic-claude", BaseURL: "https://api.anthropic.com/v1", APIKey: "sk-test2",
		Model: "claude-3-sonnet", Weight: 0.8, MaxRPM: 80, Capabilities: []string{"chat", "tools"},
		Healthy: true, LastCheck: time.Now(),
	})

	registry := assistant.NewToolRegistry(10, 1000)
	registry.Register(&assistant.ToolDefinition{
		Name: "default_model", Description: "Get default model",
		Parameters: json.RawMessage(`{"type":"object","properties":{"action":{"type":"string"}}}`),
	}, func(_ context.Context, _ map[string]interface{}) (interface{}, error) {
		return map[string]string{"default": "gpt-4o"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "user_profile", Description: "Get user profile",
		Parameters: json.RawMessage(`{"type":"object","properties":{"user_id":{"type":"string"}}}`),
	}, func(_ context.Context, _ map[string]interface{}) (interface{}, error) {
		return map[string]string{"user_id": "test", "role": "user"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "rotate_key", Description: "Rotate API key", Dangerous: true, RequiredRBAC: "admin",
		Parameters: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
	}, func(_ context.Context, _ map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "rotated"}, nil
	})

	sessions := assistant.NewSessionManager(20, "/tmp/tsg-assistant")
	pathChecker := func(path string) bool {
		return len(path) > 0 && (path == "/tmp/tsg-safe" || len(path) > len("/tmp/tsg-safe/") && path[:len("/tmp/tsg-safe/")] == "/tmp/tsg-safe/")
	}
	guard := assistant.NewAssistantGuard(pathChecker)
	server := assistant.NewServer(router, registry, sessions, guard)

	// Use httptest for in-process smoke testing
	ts := &http.Server{Addr: addr, Handler: server}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: listen: %v\n", err)
		os.Exit(1)
	}
	go ts.Serve(listener)
	defer ts.Close()

	baseURL := "http://" + listener.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}
	passed := 0
	failed := 0

	check := func(name string, req *http.Request, wantStatus int, checkBody func([]byte) bool) {
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("  FAIL %s: %v\n", name, err)
			failed++
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != wantStatus {
			fmt.Printf("  FAIL %s: status=%d want=%d body=%s\n", name, resp.StatusCode, wantStatus, string(body))
			failed++
			return
		}
		if checkBody != nil && !checkBody(body) {
			fmt.Printf("  FAIL %s: body check failed: %s\n", name, string(body))
			failed++
			return
		}
		fmt.Printf("  PASS %s\n", name)
		passed++
	}

	fmt.Println("=== Assistant Smoke Tests ===")
	fmt.Printf("Base URL: %s\n\n", baseURL)

	// 1. Health
	check("health", mustGet(baseURL+"/api/assistant/health"), 200, func(b []byte) bool {
		var v map[string]interface{}
		return json.Unmarshal(b, &v) == nil && v["status"] == "ok"
	})

	// 2. Create session
	var sessID string
	check("create-session", mustPost(baseURL+"/api/assistant/sessions", `{"user_id":"smoke-user","role":"user"}`), 200, func(b []byte) bool {
		var v map[string]interface{}
		if err := json.Unmarshal(b, &v); err != nil {
			return false
		}
		sid, _ := v["id"].(string)
		sessID = sid
		return sid != ""
	})

	// 3. Get session
	check("get-session", mustGet(baseURL+"/api/assistant/sessions/"+sessID), 200, func(b []byte) bool {
		var v map[string]interface{}
		return json.Unmarshal(b, &v) == nil && v["id"] == sessID
	})

	// 4. Chat auto
	check("chat-auto", mustPost(baseURL+"/api/assistant/chat", `{"session_id":"`+sessID+`","message":"hello","mode":"auto"}`), 200, func(b []byte) bool {
		var v map[string]interface{}
		return json.Unmarshal(b, &v) == nil && v["provider"] != nil
	})

	// 5. Chat manual
	check("chat-manual", mustPost(baseURL+"/api/assistant/chat", `{"session_id":"`+sessID+`","message":"use claude","mode":"manual","provider":"anthropic-claude"}`), 200, func(b []byte) bool {
		var v map[string]interface{}
		return json.Unmarshal(b, &v) == nil && v["provider"] == "anthropic-claude"
	})

	// 6. List tools
	check("list-tools", mustGet(baseURL+"/api/assistant/tools"), 200, func(b []byte) bool {
		var v []interface{}
		return json.Unmarshal(b, &v) == nil && len(v) == 3
	})

	// 7. List providers
	check("list-providers", mustGet(baseURL+"/api/assistant/providers"), 200, func(b []byte) bool {
		var v []interface{}
		return json.Unmarshal(b, &v) == nil && len(v) == 2
	})

	// 8. UI static
	check("ui-html", mustGet(baseURL+"/assistant/"), 200, func(b []byte) bool {
		return bytes.Contains(b, []byte("<html")) || bytes.Contains(b, []byte("<!DOCTYPE"))
	})

	// 9. Confirm gate
	token := guard.RequestConfirmation(sessID, "rotate_key", "test rotation", time.Minute)
	check("confirm-gate", mustPost(baseURL+"/api/assistant/confirm", `{"token":"`+token+`"}`), 200, func(b []byte) bool {
		var v map[string]interface{}
		return json.Unmarshal(b, &v) == nil && v["confirmed"] == true
	})

	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func mustGet(url string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, url, nil)
	return r
}

func mustPost(url, body string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}
