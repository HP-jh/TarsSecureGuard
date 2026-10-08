package skylink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Message is an encrypted envelope for device-to-device communication.
type Message struct {
	ID        string            `json:"id"`
	FromPeer  string            `json:"from_peer"`
	ToPeer    string            `json:"to_peer"`
	Payload   []byte            `json:"payload"`   // encrypted
	Nonce     []byte            `json:"nonce"`     // AES-GCM nonce
	Timestamp time.Time         `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// MessagePayload is the plaintext inner structure before encryption.
type MessagePayload struct {
	Type    string          `json:"type"`    // e.g. "task", "heartbeat", "content_request"
	Body    json.RawMessage `json:"body"`
	AgentID string          `json:"agent_id,omitempty"`
}

// Messenger handles encrypted device-to-device messaging.
type Messenger struct {
	mu        sync.RWMutex
	keys      map[string][]byte // peerID -> shared key (32-byte)
	outbox    chan *Message
	handlers  map[string]MessageHandler
}

// MessageHandler processes decrypted messages.
type MessageHandler func(fromPeer string, payload *MessagePayload) error

// NewMessenger creates a messenger with a bounded outbox.
func NewMessenger(outboxSize int) *Messenger {
	return &Messenger{
		keys:     make(map[string][]byte),
		outbox:   make(chan *Message, outboxSize),
		handlers: make(map[string]MessageHandler),
	}
}

// RegisterKey stores a pre-negotiated shared key for a peer.
// In production this is derived from a Noise handshake or TLS session.
func (m *Messenger) RegisterKey(peerID string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("skylink: shared key must be 32 bytes, got %d", len(key))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[peerID] = key
	return nil
}

// RegisterHandler binds a handler for a message type.
func (m *Messenger) RegisterHandler(msgType string, h MessageHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[msgType] = h
}

// Encrypt seals a payload for a target peer using AES-256-GCM.
func (m *Messenger) Encrypt(peerID string, payload *MessagePayload) (*Message, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	key, ok := m.keys[peerID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("skylink: no shared key for peer %s", peerID)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	idNonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idNonce); err != nil {
		return nil, err
	}
	idHash := sha256.Sum256(append([]byte(peerID), idNonce...))

	// Seal produces ciphertext || tag. Manually prepend nonce for transport.
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)
	msg := &Message{
		ID:        fmt.Sprintf("%x", idHash[:8]),
		ToPeer:    peerID,
		Payload:   out,
		Nonce:     nonce,
		Timestamp: time.Now(),
	}
	return msg, nil
}

// Decrypt opens a message from a peer.
func (m *Messenger) Decrypt(msg *Message) (*MessagePayload, error) {
	m.mu.RLock()
	key, ok := m.keys[msg.FromPeer]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("skylink: no shared key for peer %s", msg.FromPeer)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(msg.Payload) < gcm.NonceSize() {
		return nil, fmt.Errorf("skylink: payload too short")
	}

	// Payload was sealed with nil dst, so nonce is prepended.
	nonce := msg.Payload[:gcm.NonceSize()]
	ciphertext := msg.Payload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("skylink: decryption failed: %w", err)
	}

	var payload MessagePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// Send encrypts and enqueues a message for delivery.
func (m *Messenger) Send(fromPeer, toPeer string, payload *MessagePayload) (*Message, error) {
	msg, err := m.Encrypt(toPeer, payload)
	if err != nil {
		return nil, err
	}
	msg.FromPeer = fromPeer
	select {
	case m.outbox <- msg:
		return msg, nil
	default:
		return nil, fmt.Errorf("skylink: outbox full")
	}
}

// Receive dequeues a message from the outbox (used by transport goroutine).
func (m *Messenger) Receive() (*Message, bool) {
	select {
	case msg := <-m.outbox:
		return msg, true
	default:
		return nil, false
	}
}

// Process decrypts a received message and dispatches to the appropriate handler.
func (m *Messenger) Process(msg *Message) error {
	payload, err := m.Decrypt(msg)
	if err != nil {
		return err
	}
	m.mu.RLock()
	h, ok := m.handlers[payload.Type]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("skylink: no handler for message type %s", payload.Type)
	}
	return h(msg.FromPeer, payload)
}

// DeriveSharedKey deterministically derives a 32-byte key from a secret using SHA-256.
// Production should use HKDF or a proper KDF; this is a stub for stdlib-only builds.
func DeriveSharedKey(secret []byte) []byte {
	h := sha256.Sum256(secret)
	return h[:]
}
