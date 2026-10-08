package assistant

import (
	"os"
	"testing"
	"time"
)

func TestSessionManagerCreateGet(t *testing.T) {
	m := NewSessionManager(10, "")
	s := m.NewSession("u1", "user")
	if s.ID == "" {
		t.Fatal("expected session id")
	}
	s2, ok := m.Get(s.ID)
	if !ok || s2.ID != s.ID {
		t.Fatal("expected session retrievable")
	}
}

func TestSessionManagerAddMessage(t *testing.T) {
	m := NewSessionManager(3, "")
	s := m.NewSession("u1", "user")
	_ = m.AddMessage(s.ID, Message{Role: "user", Content: "a"})
	_ = m.AddMessage(s.ID, Message{Role: "assistant", Content: "b"})
	_ = m.AddMessage(s.ID, Message{Role: "user", Content: "c"})
	_ = m.AddMessage(s.ID, Message{Role: "assistant", Content: "d"})

	s2, _ := m.Get(s.ID)
	if len(s2.Messages) != 3 {
		t.Fatalf("expected 3 messages after trim, got %d", len(s2.Messages))
	}
}

func TestSessionManagerAddMessageWithSystem(t *testing.T) {
	m := NewSessionManager(3, "")
	s := m.NewSession("u1", "user")
	_ = m.AddMessage(s.ID, Message{Role: "system", Content: "sys"})
	_ = m.AddMessage(s.ID, Message{Role: "user", Content: "a"})
	_ = m.AddMessage(s.ID, Message{Role: "user", Content: "b"})
	_ = m.AddMessage(s.ID, Message{Role: "user", Content: "c"})

	s2, _ := m.Get(s.ID)
	if len(s2.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(s2.Messages))
	}
	// System message should survive
	hasSystem := false
	for _, m := range s2.Messages {
		if m.Role == "system" {
			hasSystem = true
		}
	}
	if !hasSystem {
		t.Fatal("expected system message to survive trimming")
	}
}

func TestSessionManagerPersistence(t *testing.T) {
	dir := "/tmp/assistant_test_" + time.Now().Format("20060102150405")
	defer os.RemoveAll(dir)
	m := NewSessionManager(10, dir)
	s := m.NewSession("u1", "user")
	_ = m.AddMessage(s.ID, Message{Role: "user", Content: "hello"})

	// New manager instance
	m2 := NewSessionManager(10, dir)
	s2, ok := m2.Get(s.ID)
	if !ok {
		t.Fatal("expected session loaded from disk")
	}
	if len(s2.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(s2.Messages))
	}
}

func TestSessionManagerPrune(t *testing.T) {
	m := NewSessionManager(10, "")
	s := m.NewSession("u1", "user")
	// Artificially age the session
	s.UpdatedAt = time.Now().Add(-2 * time.Hour)
	removed := m.Prune(time.Hour)
	if removed != 1 {
		t.Fatalf("expected 1 pruned, got %d", removed)
	}
	_, ok := m.Get(s.ID)
	if ok {
		t.Fatal("expected pruned session gone")
	}
}

func TestSessionToOpenAIMessages(t *testing.T) {
	s := &Session{Messages: []Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "hi"},
		{Role: "assistant", Content: "hello"},
	}}
	out := s.ToOpenAIMessages()
	if len(out) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(out))
	}
	if out[0]["role"] != "system" {
		t.Fatal("expected system first")
	}
}
