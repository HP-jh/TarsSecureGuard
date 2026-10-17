package assistant

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ConfirmationGate holds pending confirmations for dangerous operations.
type ConfirmationGate struct {
	mu      sync.RWMutex
	pending map[string]*PendingConfirm // token -> confirm
}

// PendingConfirm represents a confirmation request.
type PendingConfirm struct {
	Token       string    `json:"token"`
	SessionID   string    `json:"session_id"`
	ToolName    string    `json:"tool_name"`
	Description string    `json:"description"`
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Confirmed   bool      `json:"confirmed"`
}

// NewConfirmationGate creates a gate with TTL-based expiry.
func NewConfirmationGate() *ConfirmationGate {
	return &ConfirmationGate{pending: make(map[string]*PendingConfirm)}
}

// Request creates a new confirmation token for a dangerous operation.
func (g *ConfirmationGate) Request(sessionID, toolName, description string, ttl time.Duration) string {
	token := generateConfirmToken()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pending[token] = &PendingConfirm{
		Token:       token,
		SessionID:   sessionID,
		ToolName:    toolName,
		Description: description,
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
		Confirmed:   false,
	}
	return token
}

// Confirm marks a token as confirmed.
func (g *ConfirmationGate) Confirm(token string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	pc, ok := g.pending[token]
	if !ok {
		return false
	}
	if time.Now().After(pc.ExpiresAt) {
		delete(g.pending, token)
		return false
	}
	pc.Confirmed = true
	return true
}

// Check verifies if a token is confirmed and not expired.
func (g *ConfirmationGate) Check(token string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	pc, ok := g.pending[token]
	if !ok {
		return false
	}
	if time.Now().After(pc.ExpiresAt) {
		return false
	}
	return pc.Confirmed
}

// Get retrieves a pending confirmation by token.
func (g *ConfirmationGate) Get(token string) (*PendingConfirm, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	pc, ok := g.pending[token]
	if !ok || time.Now().After(pc.ExpiresAt) {
		return nil, false
	}
	return pc, true
}

// Prune removes expired confirmations.
func (g *ConfirmationGate) Prune() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	removed := 0
	for t, pc := range g.pending {
		if now.After(pc.ExpiresAt) {
			delete(g.pending, t)
			removed++
		}
	}
	return removed
}

// DangerousTools is the built-in list of tools requiring confirmation.
var DangerousTools = map[string]bool{
	"delete_key":      true,
	"revoke_key":      true,
	"rotate_key":      true,
	"file_ops_delete": true,
	"persona_ops":     true,
}

// IsDangerous checks if a tool requires confirmation.
func IsDangerous(toolName string) bool {
	return DangerousTools[toolName]
}

// AssistantGuard wraps all security checks for the assistant.
type AssistantGuard struct {
	confirm *ConfirmationGate
	// pathChecker is injected from TSG core
	pathChecker PathChecker
}

// NewAssistantGuard creates a guard with the given path validator.
func NewAssistantGuard(checker PathChecker) *AssistantGuard {
	return &AssistantGuard{
		confirm:     NewConfirmationGate(),
		pathChecker: checker,
	}
}

// PreInvoke checks if a tool call is allowed (RBAC + quota + confirmation).
func (g *AssistantGuard) PreInvoke(registry *ToolRegistry, role, toolName string, args map[string]interface{}, confirmToken string) (bool, string) {
	// Check RBAC
	if !registry.CheckRBAC(role, toolName) {
		return false, "RBAC denied"
	}
	// Check quota
	if !registry.CheckQuota(role, toolName) {
		return false, "quota exceeded"
	}
	// Check dangerous operation confirmation
	if IsDangerous(toolName) {
		if confirmToken == "" {
			return false, "confirmation required"
		}
		if !g.confirm.Check(confirmToken) {
			return false, "confirmation invalid or expired"
		}
	}
	// Check file path if applicable
	if g.pathChecker != nil && strings.HasPrefix(toolName, "file_ops") {
		path, _ := args["path"].(string)
		if path != "" && !g.pathChecker(path) {
			return false, fmt.Sprintf("path %q not allowed", path)
		}
	}
	return true, ""
}

// RequestConfirmation creates a confirmation token for a dangerous operation.
func (g *AssistantGuard) RequestConfirmation(sessionID, toolName, description string, ttl time.Duration) string {
	return g.confirm.Request(sessionID, toolName, description, ttl)
}

// ConfirmOperation marks a token as confirmed.
func (g *AssistantGuard) ConfirmOperation(token string) bool {
	return g.confirm.Confirm(token)
}

// PendingConfirmations returns all pending confirmations for a session.
func (g *AssistantGuard) PendingConfirmations(sessionID string) []*PendingConfirm {
	g.confirm.mu.RLock()
	defer g.confirm.mu.RUnlock()
	out := make([]*PendingConfirm, 0)
	for _, pc := range g.confirm.pending {
		if pc.SessionID == sessionID && time.Now().Before(pc.ExpiresAt) && !pc.Confirmed {
			out = append(out, pc)
		}
	}
	return out
}

func generateConfirmToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "cfm_" + hex.EncodeToString(b)
}
