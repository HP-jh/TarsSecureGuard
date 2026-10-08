package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setupTestServer() (*Server, *SessionManager) {
	router := NewModelRouter(time.Hour)
	router.Register(&ProviderConfig{Name: "test", BaseURL: "http://localhost", Model: "gpt-4", Weight: 1.0, Healthy: true, LastCheck: testNow()})
	registry := NewToolRegistry(10, 100)
	registry.Register(&ToolDefinition{Name: "echo", Description: "echo"}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return args["text"], nil
	})
	sessions := NewSessionManager(50, "")
	guard := NewAssistantGuard(func(p string) bool { return true })
	return NewServer(router, registry, sessions, guard), sessions
}

func testNow() time.Time {
	return time.Now()
}

func TestServerCreateSession(t *testing.T) {
	srv, _ := setupTestServer()
	req := httptest.NewRequest("POST", "/api/assistant/sessions", bytes.NewReader([]byte(`{"user_id":"u1","role":"user"}`)))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var sess Session
	if err := json.Unmarshal(w.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	if sess.ID == "" {
		t.Fatal("expected session id")
	}
}

func TestServerListSessions(t *testing.T) {
	srv, sm := setupTestServer()
	sm.NewSession("u1", "user")
	req := httptest.NewRequest("GET", "/api/assistant/sessions", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var list []*Session
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 session, got %d", len(list))
	}
}

func TestServerChat(t *testing.T) {
	srv, sm := setupTestServer()
	sess := sm.NewSession("u1", "user")
	body, _ := json.Marshal(map[string]interface{}{
		"session_id": sess.ID,
		"message":    "hello",
		"mode":       "auto",
	})
	req := httptest.NewRequest("POST", "/api/assistant/chat", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["session_id"] != sess.ID {
		t.Fatalf("session id mismatch")
	}
	if resp["provider"] != "test" {
		t.Fatalf("expected provider test, got %v", resp["provider"])
	}
}

func TestServerChatNewSession(t *testing.T) {
	srv, _ := setupTestServer()
	body, _ := json.Marshal(map[string]interface{}{
		"user_id": "u1",
		"role":    "user",
		"message": "hello",
	})
	req := httptest.NewRequest("POST", "/api/assistant/chat", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["session_id"] == "" {
		t.Fatal("expected new session id")
	}
}

func TestServerTools(t *testing.T) {
	srv, _ := setupTestServer()
	req := httptest.NewRequest("GET", "/api/assistant/tools", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var defs []*ToolDefinition
	if err := json.Unmarshal(w.Body.Bytes(), &defs); err != nil {
		t.Fatal(err)
	}
	if len(defs) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(defs))
	}
}

func TestServerProviders(t *testing.T) {
	srv, _ := setupTestServer()
	req := httptest.NewRequest("GET", "/api/assistant/providers", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var list []*ProviderConfig
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(list))
	}
}

func TestServerConfirm(t *testing.T) {
	srv, _ := setupTestServer()
	token := srv.guard.RequestConfirmation("s1", "delete_key", "x", time.Hour)
	body, _ := json.Marshal(map[string]interface{}{"token": token})
	req := httptest.NewRequest("POST", "/api/assistant/confirm", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["confirmed"] != true {
		t.Fatal("expected confirmed true")
	}
}

func TestServerHealth(t *testing.T) {
	srv, _ := setupTestServer()
	req := httptest.NewRequest("GET", "/api/assistant/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestServerStatic(t *testing.T) {
	srv, _ := setupTestServer()
	req := httptest.NewRequest("GET", "/assistant/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("TSG 智能助手")) {
		t.Fatal("expected assistant UI content")
	}
}
