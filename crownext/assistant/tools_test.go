package assistant

import (
	"context"
	"testing"
)

func TestToolRegistryRegister(t *testing.T) {
	r := NewToolRegistry(10, 100)
	r.Register(&ToolDefinition{Name: "echo", Description: "echo"}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return args["text"], nil
	})
	def, ok := r.GetDefinition("echo")
	if !ok || def.Name != "echo" {
		t.Fatal("expected echo tool")
	}
}

func TestToolRegistryRBAC(t *testing.T) {
	r := NewToolRegistry(10, 100)
	r.Register(&ToolDefinition{Name: "admin_tool", Description: "x", RequiredRBAC: "admin"}, nil)
	if !r.CheckRBAC("admin", "admin_tool") {
		t.Fatal("expected admin can use admin_tool")
	}
	if r.CheckRBAC("user", "admin_tool") {
		t.Fatal("expected user cannot use admin_tool")
	}
	if r.CheckRBAC("user", "unregistered_tool") {
		t.Fatal("expected unregistered tool to fail RBAC")
	}
}

func TestToolRegistryQuota(t *testing.T) {
	r := NewToolRegistry(2, 100)
	if !r.CheckQuota("user", "t1") {
		t.Fatal("expected quota ok initially")
	}
	r.RecordUsage("user", "t1")
	r.RecordUsage("user", "t1")
	if !r.CheckQuota("user", "t1") {
		t.Fatal("expected quota ok at limit")
	}
	r.RecordUsage("user", "t1")
	if r.CheckQuota("user", "t1") {
		t.Fatal("expected quota exceeded")
	}
}

func TestToolRegistryInvoke(t *testing.T) {
	r := NewToolRegistry(10, 100)
	r.Register(&ToolDefinition{Name: "add", Description: "add"}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		a, _ := args["a"].(float64)
		b, _ := args["b"].(float64)
		return a + b, nil
	})
	res := r.Invoke(context.Background(), "sess1", "user", &ToolCall{ID: "c1", Name: "add", Arguments: map[string]interface{}{"a": 1.0, "b": 2.0}}, false)
	if !res.Allowed {
		t.Fatalf("expected allowed, got %s", res.Reason)
	}
	if res.Output != 3.0 {
		t.Fatalf("expected 3, got %v", res.Output)
	}
}

func TestToolRegistryInvokeDangerous(t *testing.T) {
	r := NewToolRegistry(10, 100)
	r.Register(&ToolDefinition{Name: "delete_key", Description: "x", Dangerous: true}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return "deleted", nil
	})
	res := r.Invoke(context.Background(), "sess1", "admin", &ToolCall{ID: "c1", Name: "delete_key"}, false)
	if res.Allowed {
		t.Fatal("expected denied without confirmation")
	}
	if res.Reason != "confirmation required" {
		t.Fatalf("expected confirmation required, got %s", res.Reason)
	}
}

func TestToolRegistryInvokeRBACDenied(t *testing.T) {
	r := NewToolRegistry(10, 100)
	r.Register(&ToolDefinition{Name: "admin_only", Description: "x", RequiredRBAC: "admin"}, nil)
	res := r.Invoke(context.Background(), "sess1", "user", &ToolCall{ID: "c1", Name: "admin_only"}, false)
	if res.Allowed {
		t.Fatal("expected rbac denied")
	}
}

func TestToolRegistryAuditLog(t *testing.T) {
	r := NewToolRegistry(10, 100)
	r.Register(&ToolDefinition{Name: "noop", Description: "x"}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return nil, nil
	})
	r.Invoke(context.Background(), "s1", "user", &ToolCall{ID: "c1", Name: "noop"}, false)
	logs := r.AuditLog(10)
	if len(logs) != 1 {
		t.Fatalf("expected 1 audit log, got %d", len(logs))
	}
}

func TestWrapFileOps(t *testing.T) {
	checker := func(p string) bool { return p == "/allowed" }
	inner := func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return "ok", nil
	}
	wrapped := WrapFileOps(checker, inner)
	_, err := wrapped(context.Background(), map[string]interface{}{"path": "/bad"})
	if err == nil {
		t.Fatal("expected path denied")
	}
	res, err := wrapped(context.Background(), map[string]interface{}{"path": "/allowed"})
	if err != nil || res != "ok" {
		t.Fatal("expected allowed path to succeed")
	}
}
