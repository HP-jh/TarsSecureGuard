package mcpclient

import (
	"testing"
	"time"
)

func TestRegistryCanInvoke(t *testing.T) {
	r := NewRegistry()
	r.RegisterTool(&MCPToolDef{Name: "toolA"}, &ToolPolicy{AllowedRoles: []string{"admin", "user"}, MaxCallsPerMin: 10})

	if !r.CanInvoke("admin", "toolA") {
		t.Fatal("expected admin can invoke toolA")
	}
	if !r.CanInvoke("user", "toolA") {
		t.Fatal("expected user can invoke toolA")
	}
	if r.CanInvoke("guest", "toolA") {
		t.Fatal("expected guest cannot invoke toolA")
	}
}

func TestRegistryQuota(t *testing.T) {
	r := NewRegistry()
	r.RegisterTool(&MCPToolDef{Name: "toolA"}, &ToolPolicy{AllowedRoles: []string{"user"}, MaxCallsPerMin: 2})

	if err := r.CheckQuota("user", "toolA"); err != nil {
		t.Fatalf("first call should pass: %v", err)
	}
	r.RecordCall("user", "toolA")
	if err := r.CheckQuota("user", "toolA"); err != nil {
		t.Fatalf("second call should pass: %v", err)
	}
	r.RecordCall("user", "toolA")
	if err := r.CheckQuota("user", "toolA"); err == nil {
		t.Fatal("third call should exceed quota")
	}
}

func TestRegistryAudit(t *testing.T) {
	r := NewRegistry()
	r.RegisterTool(&MCPToolDef{Name: "toolA"}, &ToolPolicy{AllowedRoles: []string{"user"}, MaxCallsPerMin: 100})
	rec := MCPAuditRecord{
		Timestamp:  time.Now(),
		ToolName:   "toolA",
		Role:       "user",
		AgentID:    "agent1",
		Allowed:    true,
		Reason:     "test",
		DurationMs: 5,
	}
	r.RecordAudit(rec)
	logs := r.AuditLog()
	if len(logs) != 1 {
		t.Fatalf("expected 1 audit log, got %d", len(logs))
	}
}

func TestRegistryAuditCap(t *testing.T) {
	r := NewRegistry()
	r.RegisterTool(&MCPToolDef{Name: "toolA"}, &ToolPolicy{AllowedRoles: []string{"user"}, MaxCallsPerMin: 100})
	for i := 0; i < 10100; i++ {
		r.RecordAudit(MCPAuditRecord{Timestamp: time.Now(), ToolName: "toolA"})
	}
	logs := r.AuditLog()
	if len(logs) != 10000 {
		t.Fatalf("expected audit cap 10000, got %d", len(logs))
	}
}
