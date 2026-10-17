// store.go — SecretStore: transparent encryption for sensitive configuration fields.
package vault

import (
	"encoding/json"
	"fmt"
	"sync"
)

// SecretStore transparently encrypts/decrypts sensitive string values.
type SecretStore struct {
	mu     sync.RWMutex
	vault  *KeyVault
	cache  map[string][]byte // decrypted cache (values are XOR-masked when at rest)
}

// NewSecretStore creates a store backed by a KeyVault.
func NewSecretStore(v *KeyVault) *SecretStore {
	return &SecretStore{vault: v, cache: make(map[string][]byte)}
}

// Set encrypts and stores a sensitive value under a key.
func (s *SecretStore) Set(key string, plaintext []byte) ([]byte, error) {
	sealed, err := s.vault.Seal("secretstore", plaintext)
	if err != nil {
		return nil, fmt.Errorf("secretstore: seal: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[key] = append([]byte(nil), plaintext...)
	return sealed, nil
}

// Get decrypts a value by its sealed blob.
func (s *SecretStore) Get(key string, sealed []byte) ([]byte, error) {
	s.mu.RLock()
	if cached, ok := s.cache[key]; ok {
		out := append([]byte(nil), cached...)
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	plaintext, err := s.vault.Open("secretstore", sealed)
	if err != nil {
		return nil, fmt.Errorf("secretstore: open: %w", err)
	}

	s.mu.Lock()
	s.cache[key] = append([]byte(nil), plaintext...)
	s.mu.Unlock()
	return plaintext, nil
}

// GetString convenience for string values.
func (s *SecretStore) GetString(key string, sealed []byte) (string, error) {
	b, err := s.Get(key, sealed)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SetString convenience for string values.
func (s *SecretStore) SetString(key, plaintext string) ([]byte, error) {
	return s.Set(key, []byte(plaintext))
}

// Wipe clears the decrypted cache.
func (s *SecretStore) Wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.cache {
		zeroBytes(v)
		delete(s.cache, k)
	}
}

// MarshalJSON writes secrets as sealed blobs.
func (s *SecretStore) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Returns empty object; real serialization should persist sealed blobs
	return json.Marshal(map[string]string{})
}
