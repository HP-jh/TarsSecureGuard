package assistant

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Message represents one turn in a conversation.
type Message struct {
	Role      string          `json:"role"`      // "system", "user", "assistant", "tool"
	Content   string          `json:"content"`
	ToolCalls []ToolCall      `json:"tool_calls,omitempty"`
	ToolResults []ToolResult  `json:"tool_results,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// Session holds the full state of an assistant conversation.
type Session struct {
	ID            string            `json:"id"`
	UserID        string            `json:"user_id"`
	Role          string            `json:"role"`          // RBAC role
	Mode          SelectionMode     `json:"mode"`          // auto or manual
	Provider      string            `json:"provider"`      // last used provider
	Messages      []Message         `json:"messages"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	ToolCallChain []string          `json:"tool_call_chain"` // ordered tool call IDs
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// SessionManager persists and manages sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	maxCtx   int           // max messages in context window
	dataDir  string        // directory for file persistence
}

// NewSessionManager creates a manager with context window limit.
func NewSessionManager(maxCtx int, dataDir string) *SessionManager {
	_ = os.MkdirAll(dataDir, 0750)
	return &SessionManager{
		sessions: make(map[string]*Session),
		maxCtx:   maxCtx,
		dataDir:  dataDir,
	}
}

// NewSession creates a fresh session.
func (m *SessionManager) NewSession(userID, role string) *Session {
	id := generateSessionID()
	s := &Session{
		ID:            id,
		UserID:        userID,
		Role:          role,
		Mode:          ModeAuto,
		Messages:      make([]Message, 0, m.maxCtx),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ToolCallChain: make([]string, 0),
		Metadata:      make(map[string]string),
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	_ = m.save(s)
	return s
}

// Get retrieves a session by ID.
func (m *SessionManager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if ok {
		return s, true
	}
	// Try loading from disk
	return m.load(id)
}

// AddMessage appends a message and trims context window.
func (m *SessionManager) AddMessage(sessionID string, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("assistant: session %s not found", sessionID)
	}
	s.Messages = append(s.Messages, msg)
	// Trim context window: keep system message + most recent messages
	if len(s.Messages) > m.maxCtx {
		// Find system message index
		sysIdx := -1
		for i, m := range s.Messages {
			if m.Role == "system" {
				sysIdx = i
				break
			}
		}
		// Keep system message, trim oldest non-system
		if sysIdx >= 0 {
			keep := make([]Message, 0, m.maxCtx)
			keep = append(keep, s.Messages[sysIdx])
			start := len(s.Messages) - (m.maxCtx - 1)
			if start < 0 {
				start = 0
			}
			for i := start; i < len(s.Messages); i++ {
				if i != sysIdx {
					keep = append(keep, s.Messages[i])
				}
			}
			s.Messages = keep
		} else {
			s.Messages = s.Messages[len(s.Messages)-m.maxCtx:]
		}
	}
	s.UpdatedAt = time.Now()
	return m.save(s)
}

// RecordToolCall logs a tool call in the session chain.
func (m *SessionManager) RecordToolCall(sessionID, toolCallID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("assistant: session %s not found", sessionID)
	}
	s.ToolCallChain = append(s.ToolCallChain, toolCallID)
	s.UpdatedAt = time.Now()
	return m.save(s)
}

// SetMode changes selection mode without losing context.
func (m *SessionManager) SetMode(sessionID string, mode SelectionMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("assistant: session %s not found", sessionID)
	}
	s.Mode = mode
	s.UpdatedAt = time.Now()
	return m.save(s)
}

// SetProvider pins a provider for manual mode.
func (m *SessionManager) SetProvider(sessionID, provider string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("assistant: session %s not found", sessionID)
	}
	s.Provider = provider
	s.UpdatedAt = time.Now()
	return m.save(s)
}

// List returns all active sessions.
func (m *SessionManager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// Prune removes sessions older than maxAge.
func (m *SessionManager) Prune(maxAge time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for id, s := range m.sessions {
		if s.UpdatedAt.Before(cutoff) {
			delete(m.sessions, id)
			_ = os.Remove(m.sessionPath(id))
			removed++
		}
	}
	return removed
}

func (m *SessionManager) sessionPath(id string) string {
	return filepath.Join(m.dataDir, id+".json")
}

func (m *SessionManager) save(s *Session) error {
	if m.dataDir == "" {
		return nil
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.sessionPath(s.ID), data, 0600)
}

func (m *SessionManager) load(id string) (*Session, bool) {
	if m.dataDir == "" {
		return nil, false
	}
	data, err := os.ReadFile(m.sessionPath(id))
	if err != nil {
		return nil, false
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false
	}
	m.mu.Lock()
	m.sessions[id] = &s
	m.mu.Unlock()
	return &s, true
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "sess_" + hex.EncodeToString(b)
}

// ToOpenAIMessages converts session messages to OpenAI chat format.
func (s *Session) ToOpenAIMessages() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(s.Messages))
	for _, m := range s.Messages {
		msg := map[string]interface{}{
			"role":    m.Role,
			"content": m.Content,
		}
		if len(m.ToolCalls) > 0 {
			msg["tool_calls"] = m.ToolCalls
		}
		if len(m.ToolResults) > 0 {
			for _, tr := range m.ToolResults {
				out = append(out, map[string]interface{}{
					"role":         "tool",
					"tool_call_id": tr.ID,
					"content":      fmt.Sprintf("%v", tr.Output),
				})
			}
			continue
		}
		out = append(out, msg)
	}
	return out
}
