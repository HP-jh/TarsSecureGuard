package assistant

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ToolDefinition describes a tool the assistant can invoke.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"` // JSON Schema
	Dangerous   bool            `json:"dangerous"`  // requires confirmation
	RequiredRBAC string         `json:"required_rbac,omitempty"` // minimum role
}

// ToolHandler executes a tool call.
type ToolHandler func(ctx context.Context, args map[string]interface{}) (interface{}, error)

// ToolCall represents a single tool invocation request.
type ToolCall struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolResult is the outcome of a tool call.
type ToolResult struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Output    interface{} `json:"output,omitempty"`
	Error     string      `json:"error,omitempty"`
	Duration  int64       `json:"duration_ms"`
	Allowed   bool        `json:"allowed"`
	Reason    string      `json:"reason,omitempty"`
	Confirmed bool        `json:"confirmed,omitempty"`
}

// ToolRegistry holds registered tools with RBAC + quota + audit.
type ToolRegistry struct {
	mu       sync.RWMutex
	defs     map[string]*ToolDefinition
	handlers map[string]ToolHandler
	// per-role per-tool call counters (simplified quota)
	quotas   map[string]map[string]int // role -> tool -> count
	quotaMax int
	// audit log
	audit    []ToolAuditRecord
	auditCap int
}

// ToolAuditRecord tracks every tool invocation attempt.
type ToolAuditRecord struct {
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`
	ToolName  string    `json:"tool_name"`
	Role      string    `json:"role"`
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason"`
	Confirmed bool      `json:"confirmed"`
	Duration  int64     `json:"duration_ms"`
	ArgsHash  string    `json:"args_hash"` // SHA-256 of args for privacy
}

// NewToolRegistry creates a registry with quota and audit limits.
func NewToolRegistry(quotaMax, auditCap int) *ToolRegistry {
	return &ToolRegistry{
		defs:     make(map[string]*ToolDefinition),
		handlers: make(map[string]ToolHandler),
		quotas:   make(map[string]map[string]int),
		quotaMax: quotaMax,
		auditCap: auditCap,
	}
}

// Register adds a tool definition and handler.
func (r *ToolRegistry) Register(def *ToolDefinition, h ToolHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defs[def.Name] = def
	r.handlers[def.Name] = h
}

// GetDefinition returns a tool's schema.
func (r *ToolRegistry) GetDefinition(name string) (*ToolDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.defs[name]
	return d, ok
}

// ListDefinitions returns all tool schemas (for OpenAI function calling).
func (r *ToolRegistry) ListDefinitions() []*ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ToolDefinition, 0, len(r.defs))
	for _, d := range r.defs {
		out = append(out, d)
	}
	return out
}

// CheckRBAC verifies role has access to a tool.
func (r *ToolRegistry) CheckRBAC(role, toolName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.defs[toolName]
	if !ok {
		return false
	}
	if def.RequiredRBAC == "" {
		return true
	}
	// Simple role hierarchy: admin > user > guest
	hierarchy := map[string]int{"guest": 0, "user": 1, "admin": 2}
	required := hierarchy[def.RequiredRBAC]
	actual := hierarchy[role]
	return actual >= required
}

// CheckQuota verifies role hasn't exceeded per-tool quota.
func (r *ToolRegistry) CheckQuota(role, toolName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.quotaMax <= 0 {
		return true
	}
	if r.quotas[role] == nil {
		return true
	}
	return r.quotas[role][toolName] <= r.quotaMax
}

// RecordUsage increments quota usage.
func (r *ToolRegistry) RecordUsage(role, toolName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.quotas[role] == nil {
		r.quotas[role] = make(map[string]int)
	}
	r.quotas[role][toolName]++
}

// RecordAudit appends an audit record.
func (r *ToolRegistry) RecordAudit(rec ToolAuditRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audit = append(r.audit, rec)
	if len(r.audit) > r.auditCap {
		r.audit = r.audit[len(r.audit)-r.auditCap:]
	}
}

// AuditLog returns recent audit records.
func (r *ToolRegistry) AuditLog(limit int) []ToolAuditRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > len(r.audit) {
		limit = len(r.audit)
	}
	out := make([]ToolAuditRecord, limit)
	for i := 0; i < limit; i++ {
		out[i] = r.audit[len(r.audit)-1-i]
	}
	return out
}

// Invoke executes a tool call with full RBAC + quota + audit.
func (r *ToolRegistry) Invoke(ctx context.Context, sessionID, role string, call *ToolCall, confirmed bool) *ToolResult {
	start := time.Now()
	res := &ToolResult{ID: call.ID, Name: call.Name}

	// 1. RBAC check
	if !r.CheckRBAC(role, call.Name) {
		res.Allowed = false
		res.Reason = "RBAC denied"
		r.recordAudit(sessionID, role, call, res, start)
		return res
	}

	// 2. Quota check
	if !r.CheckQuota(role, call.Name) {
		res.Allowed = false
		res.Reason = "quota exceeded"
		r.recordAudit(sessionID, role, call, res, start)
		return res
	}

	// 3. Dangerous operation confirmation
	def, ok := r.GetDefinition(call.Name)
	if ok && def.Dangerous && !confirmed {
		res.Allowed = false
		res.Reason = "confirmation required"
		res.Confirmed = false
		r.recordAudit(sessionID, role, call, res, start)
		return res
	}

	// 4. Execute
	handler, ok := r.handlers[call.Name]
	if !ok {
		res.Allowed = false
		res.Reason = "handler not found"
		r.recordAudit(sessionID, role, call, res, start)
		return res
	}

	output, err := handler(ctx, call.Arguments)
	res.Duration = time.Since(start).Milliseconds()
	res.Allowed = true
	res.Confirmed = confirmed
	if err != nil {
		res.Error = err.Error()
		res.Reason = "execution error"
	} else {
		res.Output = output
		res.Reason = "success"
	}

	// 5. Record usage and audit
	r.RecordUsage(role, call.Name)
	r.recordAudit(sessionID, role, call, res, start)
	return res
}

func (r *ToolRegistry) recordAudit(sessionID, role string, call *ToolCall, res *ToolResult, start time.Time) {
	argsJSON, _ := json.Marshal(call.Arguments)
	h := sha256.Sum256(argsJSON)
	rec := ToolAuditRecord{
		Timestamp: time.Now(),
		SessionID: sessionID,
		ToolName:  call.Name,
		Role:      role,
		Allowed:   res.Allowed,
		Reason:    res.Reason,
		Confirmed: res.Confirmed,
		Duration:  res.Duration,
		ArgsHash:  fmt.Sprintf("%x", h[:8]),
	}
	r.RecordAudit(rec)
}

// ResetQuotas clears all quota counters (e.g. on window rollover).
func (r *ToolRegistry) ResetQuotas() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.quotas = make(map[string]map[string]int)
}

// ToOpenAITools converts definitions to OpenAI function-calling format.
func (r *ToolRegistry) ToOpenAITools() []map[string]interface{} {
	defs := r.ListDefinitions()
	out := make([]map[string]interface{}, 0, len(defs))
	for _, d := range defs {
		tool := map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name":        d.Name,
				"description": d.Description,
				"parameters":  json.RawMessage(d.Parameters),
			},
		}
		out = append(out, tool)
	}
	return out
}

// IsPathAllowed checks a file path against allowed patterns (anti-symlink escape).
// This is a stub that integrates with TSG core's actual isPathAllowed.
type PathChecker func(path string) bool

// WrapFileOps wraps a file operation handler with path validation.
func WrapFileOps(checker PathChecker, inner ToolHandler) ToolHandler {
	return func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		path, _ := args["path"].(string)
		if path != "" && !checker(path) {
			return nil, fmt.Errorf("assistant: path %q not allowed", path)
		}
		return inner(ctx, args)
	}
}

// roleRank returns numeric rank for role comparison.
func roleRank(role string) int {
	switch strings.ToLower(role) {
	case "admin", "global_admin":
		return 3
	case "user":
		return 2
	case "guest":
		return 1
	default:
		return 0
	}
}
