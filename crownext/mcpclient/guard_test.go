package mcpclient

import (
	"context"
	"testing"
)

func TestGuardCheckAllowed(t *testing.T) {
	r := NewRegistry()
	r.RegisterTool(&MCPToolDef{Name: "toolA"}, &ToolPolicy{AllowedRoles: []string{"user"}, MaxCallsPerMin: 10})
	g := NewGuard(r)

	res := g.Check(context.Background(), "user", "agent1", "toolA")
	if !res.Allowed {
		t.Fatalf("expected allowed, got %s", res.Reason)
	}
	if res.NeedConfirm {
		t.Fatal("expected no confirmation required")
	}
}

func TestGuardCheckRBACDenied(t *testing.T) {
	r := NewRegistry()
	r.RegisterTool(&MCPToolDef{Name: "toolA"}, &ToolPolicy{AllowedRoles: []string{"admin"}, MaxCallsPerMin: 10})
	g := NewGuard(r)

	res := g.Check(context.Background(), "user", "agent1", "toolA")
	if res.Allowed {
		t.Fatal("expected denied for rbac")
	}
}

func TestGuardCheckConfirm(t *testing.T) {
	r := NewRegistry()
	r.RegisterTool(&MCPToolDef{Name: "toolA"}, &ToolPolicy{AllowedRoles: []string{"user"}, MaxCallsPerMin: 10, RequireConfirm: true})
	g := NewGuard(r)

	res := g.Check(context.Background(), "user", "agent1", "toolA")
	if !res.Allowed {
		t.Fatalf("expected allowed, got %s", res.Reason)
	}
	if !res.NeedConfirm {
		t.Fatal("expected confirmation required")
	}
}

func TestGuardPostInvoke(t *testing.T) {
	r := NewRegistry()
	r.RegisterTool(&MCPToolDef{Name: "toolA"}, &ToolPolicy{AllowedRoles: []string{"user"}, MaxCallsPerMin: 2})
	g := NewGuard(r)

	g.Check(context.Background(), "user", "agent1", "toolA")
	g.PostInvoke("user", "toolA")
	g.Check(context.Background(), "user", "agent1", "toolA")
	g.PostInvoke("user", "toolA")
	res := g.Check(context.Background(), "user", "agent1", "toolA")
	if res.Allowed {
		t.Fatal("expected quota exceeded after postinvoke")
	}
}
