package skylink

import (
	"encoding/json"
	"testing"
)

func TestMessengerEncryptDecrypt(t *testing.T) {
	m := NewMessenger(10)
	key := DeriveSharedKey([]byte("secret"))
	m.RegisterKey("peer1", key)
	m.RegisterKey("peer2", key)

	payload := &MessagePayload{Type: "task", Body: json.RawMessage(`{"x":1}`)}
	msg, err := m.Encrypt("peer1", payload)
	if err != nil {
		t.Fatal(err)
	}
	msg.FromPeer = "peer2"

	decrypted, err := m.Decrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted.Type != "task" {
		t.Fatalf("type mismatch: %s", decrypted.Type)
	}
}

func TestMessengerSend(t *testing.T) {
	m := NewMessenger(10)
	key := DeriveSharedKey([]byte("secret"))
	m.RegisterKey("peer1", key)

	payload := &MessagePayload{Type: "heartbeat"}
	msg, err := m.Send("self", "peer1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if msg.FromPeer != "self" {
		t.Fatalf("FromPeer mismatch")
	}

	recv, ok := m.Receive()
	if !ok {
		t.Fatal("expected message in outbox")
	}
	if recv.ID != msg.ID {
		t.Fatal("ID mismatch")
	}
}

func TestMessengerProcess(t *testing.T) {
	m := NewMessenger(10)
	key := DeriveSharedKey([]byte("secret"))
	m.RegisterKey("peer1", key)

	called := false
	m.RegisterHandler("task", func(from string, p *MessagePayload) error {
		called = true
		return nil
	})

	payload := &MessagePayload{Type: "task", Body: json.RawMessage(`{}`)}
	msg, _ := m.Encrypt("peer1", payload)
	msg.FromPeer = "peer1"

	if err := m.Process(msg); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("handler not called")
	}
}

func TestMessengerMissingKey(t *testing.T) {
	m := NewMessenger(10)
	payload := &MessagePayload{Type: "task"}
	_, err := m.Encrypt("unknown", payload)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}
