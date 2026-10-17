package assistant

import (
	"testing"
	"time"
)

func TestConfirmationGateRequestConfirm(t *testing.T) {
	g := NewConfirmationGate()
	token := g.Request("sess1", "delete_key", "delete API key", time.Hour)
	if token == "" {
		t.Fatal("expected token")
	}
	if g.Check(token) {
		t.Fatal("expected not confirmed yet")
	}
	if !g.Confirm(token) {
		t.Fatal("expected confirm success")
	}
	if !g.Check(token) {
		t.Fatal("expected confirmed")
	}
}

func TestConfirmationGateExpiry(t *testing.T) {
	g := NewConfirmationGate()
	token := g.Request("sess1", "delete_key", "x", 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if g.Confirm(token) {
		t.Fatal("expected expired token to fail")
	}
	if g.Check(token) {
		t.Fatal("expected expired token not checkable")
	}
}

func TestConfirmationGatePrune(t *testing.T) {
	g := NewConfirmationGate()
	g.Request("s1", "t1", "x", 1*time.Millisecond)
	g.Request("s2", "t2", "x", time.Hour)
	time.Sleep(10 * time.Millisecond)
	removed := g.Prune()
	if removed != 1 {
		t.Fatalf("expected 1 pruned, got %d", removed)
	}
}

func TestIsDangerous(t *testing.T) {
	if !IsDangerous("delete_key") {
		t.Fatal("expected delete_key dangerous")
	}
	if IsDangerous("echo") {
		t.Fatal("expected echo not dangerous")
	}
}

func TestAssistantGuardPreInvoke(t *testing.T) {
	reg := NewToolRegistry(10, 100)
	reg.Register(&ToolDefinition{Name: "safe", Description: "x"}, nil)
	reg.Register(&ToolDefinition{Name: "admin_only", Description: "x", RequiredRBAC: "admin"}, nil)
	reg.Register(&ToolDefinition{Name: "delete_key", Description: "x", Dangerous: true}, nil)

	checker := func(p string) bool { return p == "/allowed" }
	g := NewAssistantGuard(checker)

	// Safe tool
	ok, reason := g.PreInvoke(reg, "user", "safe", nil, "")
	if !ok {
		t.Fatalf("expected safe allowed, got %s", reason)
	}

	// RBAC denied
	ok, reason = g.PreInvoke(reg, "user", "admin_only", nil, "")
	if ok {
		t.Fatal("expected rbac denied")
	}

	// Dangerous without confirmation
	ok, reason = g.PreInvoke(reg, "admin", "delete_key", nil, "")
	if ok {
		t.Fatal("expected confirmation required")
	}

	// Dangerous with confirmation
	token := g.RequestConfirmation("sess1", "delete_key", "delete key", time.Hour)
	g.ConfirmOperation(token)
	ok, reason = g.PreInvoke(reg, "admin", "delete_key", nil, token)
	if !ok {
		t.Fatalf("expected confirmed dangerous allowed, got %s", reason)
	}

	// File ops path check
	ok, reason = g.PreInvoke(reg, "user", "file_ops_read", map[string]interface{}{"path": "/bad"}, "")
	if ok {
		t.Fatal("expected path denied")
	}
}

func TestAssistantGuardPendingConfirmations(t *testing.T) {
	g := NewAssistantGuard(nil)
	g.RequestConfirmation("s1", "delete_key", "x", time.Hour)
	g.RequestConfirmation("s1", "revoke_key", "y", time.Hour)
	pending := g.PendingConfirmations("s1")
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(pending))
	}
}
