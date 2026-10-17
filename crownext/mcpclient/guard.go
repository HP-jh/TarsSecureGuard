package mcpclient

import (
	"context"
	"fmt"
	"time"
)

// Guard provides the RBAC + Quota + Audit triple-gate for MCP invocations.
type Guard struct {
	registry *Registry
}

// NewGuard creates a guard bound to a registry.
func NewGuard(registry *Registry) *Guard {
	return &Guard{registry: registry}
}

// InvokeResult carries the outcome of a guarded invocation.
type InvokeResult struct {
	Allowed    bool
	Reason     string
	AuditRec   MCPAuditRecord
	NeedConfirm bool
}

// Check evaluates RBAC, quota, and confirmation requirements before invocation.
func (g *Guard) Check(ctx context.Context, role, agentID, toolName string) InvokeResult {
	start := time.Now()
	rec := MCPAuditRecord{
		Timestamp: start,
		ToolName:  toolName,
		Role:      role,
		AgentID:   agentID,
	}

	// 1. RBAC check.
	if !g.registry.CanInvoke(role, toolName) {
		rec.Allowed = false
		rec.Reason = fmt.Sprintf("role %s not authorized for tool %s", role, toolName)
		rec.DurationMs = time.Since(start).Milliseconds()
		g.registry.RecordAudit(rec)
		return InvokeResult{Allowed: false, Reason: rec.Reason, AuditRec: rec}
	}

	// 2. Quota check.
	if err := g.registry.CheckQuota(role, toolName); err != nil {
		rec.Allowed = false
		rec.Reason = err.Error()
		rec.DurationMs = time.Since(start).Milliseconds()
		g.registry.RecordAudit(rec)
		return InvokeResult{Allowed: false, Reason: rec.Reason, AuditRec: rec}
	}

	// 3. Confirmation check.
	needConfirm := g.registry.RequiresConfirm(toolName)

	rec.Allowed = true
	rec.Reason = "passed"
	rec.DurationMs = time.Since(start).Milliseconds()
	g.registry.RecordAudit(rec)

	return InvokeResult{
		Allowed:     true,
		Reason:      "passed",
		AuditRec:    rec,
		NeedConfirm: needConfirm,
	}
}

// PostInvoke records the call for quota tracking after a successful invocation.
func (g *Guard) PostInvoke(role, toolName string) {
	g.registry.RecordCall(role, toolName)
}
