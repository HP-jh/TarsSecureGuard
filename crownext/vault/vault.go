// vault.go — KeyVault: layered key management for worst-case encryption fallback.
// Provides master-key → derived-key → service-key hierarchy with disk encryption.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// KeyVault manages a hierarchy of keys: Master → Derived → Service.
type KeyVault struct {
	mu       sync.RWMutex
	basePath string
	master   []byte   // master key (kept in protected memory when possible)
	salt     []byte   // per-installation salt
	keys     map[string]*serviceKey
}

// serviceKey is a derived key for a specific service/module.
type serviceKey struct {
	name   string
	key    []byte
	created time.Time
}

// NewKeyVault creates a vault at the given directory.
// If no master key exists, one is generated from a passphrase or env variable.
func NewKeyVault(basePath string) (*KeyVault, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("vault: mkdir: %w", err)
	}

	saltPath := filepath.Join(basePath, "vault.salt")
	salt, err := loadOrCreateSalt(saltPath)
	if err != nil {
		return nil, err
	}

	mk, err := loadOrCreateMasterKey(basePath, salt)
	if err != nil {
		return nil, err
	}

	return &KeyVault{
		basePath: basePath,
		master:   mk,
		salt:     salt,
		keys:     make(map[string]*serviceKey),
	}, nil
}

// Derive creates or retrieves a service-specific key.
func (v *KeyVault) Derive(name string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if sk, ok := v.keys[name]; ok {
		return sk.key, nil
	}

	dk := deriveKey(v.master, v.salt, []byte(name))
	v.keys[name] = &serviceKey{name: name, key: dk, created: time.Now()}
	return dk, nil
}

// DeriveString returns a hex-encoded derived key for convenience.
func (v *KeyVault) DeriveString(name string) (string, error) {
	k, err := v.Derive(name)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

// Seal encrypts plaintext with a service key, returning nonce+ciphertext.
func (v *KeyVault) Seal(service string, plaintext []byte) ([]byte, error) {
	key, err := v.Derive(service)
	if err != nil {
		return nil, err
	}
	return seal(key, plaintext)
}

// Open decrypts a sealed blob for a service.
func (v *KeyVault) Open(service string, sealed []byte) ([]byte, error) {
	key, err := v.Derive(service)
	if err != nil {
		return nil, err
	}
	return open(key, sealed)
}

// Wipe securely clears all in-memory keys.
func (v *KeyVault) Wipe() {
	v.mu.Lock()
	defer v.mu.Unlock()
	zeroBytes(v.master)
	for _, sk := range v.keys {
		zeroBytes(sk.key)
	}
	v.keys = make(map[string]*serviceKey)
	v.master = nil
}

// IsHealthy returns true if the vault has a valid master key.
func (v *KeyVault) IsHealthy() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.master) > 0
}

// ── internal helpers ───────────────────────────────────────────────────────

func loadOrCreateSalt(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		return data, nil
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("vault: generate salt: %w", err)
	}
	if err := os.WriteFile(path, salt, 0600); err != nil {
		return nil, fmt.Errorf("vault: write salt: %w", err)
	}
	return salt, nil
}

func loadOrCreateMasterKey(basePath string, salt []byte) ([]byte, error) {
	mkPath := filepath.Join(basePath, "master.key")
	if data, err := os.ReadFile(mkPath); err == nil && len(data) >= 32 {
		return data, nil
	}

	passphrase := os.Getenv("TSG_VAULT_PASSPHRASE")
	if passphrase == "" {
		passphrase = generatePassphrase()
	}

	mk := pbkdf2Derive([]byte(passphrase), salt, 100000, 32)
	if err := os.WriteFile(mkPath, mk, 0600); err != nil {
		return nil, fmt.Errorf("vault: write master key: %w", err)
	}
	return mk, nil
}

func generatePassphrase() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("vault: failed to generate passphrase: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func seal(key, plaintext []byte) ([]byte, error) {
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
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(sealed) < ns {
		return nil, fmt.Errorf("vault: ciphertext too short")
	}
	return gcm.Open(nil, sealed[:ns], sealed[ns:], nil)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
