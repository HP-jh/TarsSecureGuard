// Package mcpclient provides MCP client integration with RBAC, quotas and audit.
package mcpclient

import (
	"fmt"
	"sync"
	"time"
)

// MCPToolDef defines a tool exposed by an MCP server.
type MCPToolDef struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	InputSchema map[string]any    `json:"inputSchema"`
	ServerName  string            `json:"server_name"`
}

// ToolPolicy defines who can call a tool and under what constraints.
type ToolPolicy struct {
	AllowedRoles   []string      // RBAC roles that may invoke this tool
	MaxCallsPerMin int           // Rate limit per role
	RequireConfirm bool          // Whether gatekeeper confirmation is required
	AuditLevel     string        // "audit" | "none"
}

// MCPAuditRecord tracks every tool invocation.
type MCPAuditRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	ToolName   string    `json:"tool_name"`
	ServerName string    `json:"server_name"`
	Role       string    `json:"role"`
	AgentID    string    `json:"agent_id"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason,omitempty"`
	DurationMs int64     `json:"duration_ms"`
}

// Registry tracks MCP tools, their policies, and runtime quotas.
type Registry struct {
	mu        sync.RWMutex
	tools     map[string]*MCPToolDef  // key: toolName
	policies  map[string]*ToolPolicy  // key: toolName
	calls     map[string][]time.Time  // key: role+toolName -> recent call times
	auditLog  []MCPAuditRecord
	maxAudit  int
}

// NewRegistry creates a new MCP tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools:    make(map[string]*MCPToolDef),
		policies: make(map[string]*ToolPolicy),
		calls:    make(map[string][]time.Time),
		maxAudit: 10000,
	}
}

// RegisterTool registers a tool with its policy.
func (r *Registry) RegisterTool(tool *MCPToolDef, policy *ToolPolicy) error {
	if tool == nil || tool.Name == "" {
		return fmt.Errorf("mcpclient: tool name required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.Name] = tool
	r.policies[tool.Name] = policy
	return nil
}

// CanInvoke checks RBAC authorization for a role+tool combination.
func (r *Registry) CanInvoke(role, toolName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	policy, ok := r.policies[toolName]
	if !ok {
		return false
	}
	for _, allowed := range policy.AllowedRoles {
		if allowed == role {
			return true
		}
	}
	return false
}

// CheckQuota verifies rate limits for a role+tool combination.
func (r *Registry) CheckQuota(role, toolName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	policy, ok := r.policies[toolName]
	if !ok {
		return fmt.Errorf("mcpclient: tool %s not registered", toolName)
	}
	key := role + ":" + toolName
	now := time.Now()
	windowStart := now.Add(-time.Minute)

	// Filter calls to last minute.
	var recent []time.Time
	for _, t := range r.calls[key] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}
	r.calls[key] = recent

	if policy.MaxCallsPerMin > 0 && len(recent) >= policy.MaxCallsPerMin {
		return fmt.Errorf("mcpclient: quota exceeded for %s/%s (%d/min)", role, toolName, policy.MaxCallsPerMin)
	}
	return nil
}

// RecordCall records a successful call for quota tracking.
func (r *Registry) RecordCall(role, toolName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := role + ":" + toolName
	r.calls[key] = append(r.calls[key], time.Now())
}

// RecordAudit appends an audit record.
func (r *Registry) RecordAudit(rec MCPAuditRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auditLog = append(r.auditLog, rec)
	if len(r.auditLog) > r.maxAudit {
		r.auditLog = r.auditLog[len(r.auditLog)-r.maxAudit:]
	}
}

// AuditLog returns a copy of recent audit records.
func (r *Registry) AuditLog() []MCPAuditRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]MCPAuditRecord, len(r.auditLog))
	copy(out, r.auditLog)
	return out
}

// GetTool returns a registered tool definition.
func (r *Registry) GetTool(name string) (*MCPToolDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// ListTools returns all registered tool names.
func (r *Registry) ListTools() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.tools))
	for name := range r.tools {
		out = append(out, name)
	}
	return out
}

// RequiresConfirm reports whether a tool requires gatekeeper confirmation.
func (r *Registry) RequiresConfirm(toolName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.policies[toolName]; ok {
		return p.RequireConfirm
	}
	return false
}
