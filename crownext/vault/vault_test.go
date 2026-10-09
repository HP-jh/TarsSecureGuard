// vault_test.go — comprehensive tests for the vault encryption fallback system.
package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ── KeyVault Tests ─────────────────────────────────────────────────────────

func TestNewKeyVault(t *testing.T) {
	dir := t.TempDir()
	v, err := NewKeyVault(dir)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	if !v.IsHealthy() {
		t.Error("expected healthy vault")
	}
}

func TestKeyVault_Derive(t *testing.T) {
	dir := t.TempDir()
	v, err := NewKeyVault(dir)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}

	k1, err := v.Derive("service-a")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(k1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(k1))
	}

	// Same name → same key
	k2, err := v.Derive("service-a")
	if err != nil {
		t.Fatalf("derive again: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("expected same key for same service")
	}

	// Different name → different key
	k3, err := v.Derive("service-b")
	if err != nil {
		t.Fatalf("derive b: %v", err)
	}
	if bytes.Equal(k1, k3) {
		t.Error("expected different keys for different services")
	}
}

func TestKeyVault_DeriveString(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)
	s, err := v.DeriveString("svc")
	if err != nil {
		t.Fatalf("derive string: %v", err)
	}
	if len(s) != 64 { // hex of 32 bytes
		t.Errorf("expected 64 hex chars, got %d", len(s))
	}
}

func TestKeyVault_SealOpen(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)

	plaintext := []byte("my-super-secret-api-key-12345")
	sealed, err := v.Seal("test", plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("expected non-empty sealed blob")
	}

	opened, err := v.Open("test", sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(plaintext, opened) {
		t.Errorf("expected %q, got %q", plaintext, opened)
	}
}

func TestKeyVault_SealOpen_WrongService(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)

	plaintext := []byte("secret")
	sealed, _ := v.Seal("svc-a", plaintext)

	_, err := v.Open("svc-b", sealed)
	if err == nil {
		t.Error("expected error opening with wrong service key")
	}
}

func TestKeyVault_Wipe(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)
	v.Derive("x")
	v.Wipe()
	if v.IsHealthy() {
		t.Error("expected unhealthy after wipe")
	}
}

func TestKeyVault_Persistence(t *testing.T) {
	dir := t.TempDir()
	v1, _ := NewKeyVault(dir)
	k1, _ := v1.Derive("svc")

	// Simulate restart: create new vault pointing to same dir
	v2, err := NewKeyVault(dir)
	if err != nil {
		t.Fatalf("reopen vault: %v", err)
	}
	k2, _ := v2.Derive("svc")
	if !bytes.Equal(k1, k2) {
		t.Error("expected same derived key after restart")
	}
}

// ── PBKDF2 Tests ───────────────────────────────────────────────────────────

func TestPBKDF2Derive(t *testing.T) {
	key := pbkdf2Derive([]byte("password"), []byte("salt"), 1000, 32)
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}

	// Deterministic
	key2 := pbkdf2Derive([]byte("password"), []byte("salt"), 1000, 32)
	if !bytes.Equal(key, key2) {
		t.Error("expected deterministic output")
	}

	// Different salt → different key
	key3 := pbkdf2Derive([]byte("password"), []byte("SALT"), 1000, 32)
	if bytes.Equal(key, key3) {
		t.Error("expected different key for different salt")
	}
}

// ── SecretStore Tests ──────────────────────────────────────────────────────

func TestSecretStore(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)
	ss := NewSecretStore(v)

	sealed, err := ss.SetString("api-key", "sk-1234567890abcdef")
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	plain, err := ss.GetString("api-key", sealed)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if plain != "sk-1234567890abcdef" {
		t.Errorf("expected original value, got %q", plain)
	}

	ss.Wipe()
}

// ── MemoryProtector Tests ──────────────────────────────────────────────────

func TestMemoryProtector(t *testing.T) {
	mp := NewMemoryProtector(0) // no rotation for test
	data := []byte("sensitive-memory-data")
	if err := mp.Protect(data); err != nil {
		t.Fatalf("protect: %v", err)
	}

	revealed := mp.Reveal()
	if !bytes.Equal(revealed, data) {
		t.Errorf("expected %q, got %q", data, revealed)
	}

	// After Stop, data should be wiped
	mp.Stop()
	revealed2 := mp.Reveal()
	if revealed2 != nil && len(revealed2) > 0 {
		t.Error("expected nil after stop")
	}
}

func TestMemoryProtector_Rotation(t *testing.T) {
	mp := NewMemoryProtector(50 * time.Millisecond)
	data := []byte("rotating-secret-key-data")
	if err := mp.Protect(data); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Reveal before rotation
	before := mp.Reveal()
	if !bytes.Equal(before, data) {
		t.Fatal("reveal before rotation mismatch")
	}

	// Wait for rotation
	time.Sleep(120 * time.Millisecond)

	// Reveal after rotation
	after := mp.Reveal()
	if !bytes.Equal(after, data) {
		t.Fatal("reveal after rotation mismatch")
	}

	mp.Stop()
}

// ── BootSentinel Tests ─────────────────────────────────────────────────────

func TestBootSentinel(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config.json")
	os.WriteFile(f, []byte(`{"key":"value"}`), 0600)

	s := NewBootSentinel("")
	expected, _ := fileSHA256(f)
	s.Register(f, expected, false)

	if err := s.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBootSentinel_Fail(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config.json")
	os.WriteFile(f, []byte(`{"key":"value"}`), 0600)

	s := NewBootSentinel("")
	s.Register(f, "0000000000000000000000000000000000000000000000000000000000000000", false)

	if err := s.Verify(); err == nil {
		t.Error("expected integrity failure")
	}
}

func TestBootSentinel_GenerateManifest(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.json"), []byte("a"), 0600)
	os.WriteFile(filepath.Join(dir, "b.json"), []byte("b"), 0600)

	s := NewBootSentinel("")
	checks, err := s.GenerateManifest(dir, []string{"*.json"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}

	if err := s.Verify(); err != nil {
		t.Fatalf("verify generated: %v", err)
	}
}

// ── EmergencyWipe Tests ────────────────────────────────────────────────────

func TestEmergencyWipe(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)

	ew := NewEmergencyWipe(0)
	ew.Register(v)
	ew.Register(WipeFunc(func() { /* custom wipe */ }))

	v.Derive("test")
	if !v.IsHealthy() {
		t.Fatal("expected healthy before wipe")
	}

	ew.Execute("test wipe")
	if v.IsHealthy() {
		t.Error("expected wiped vault")
	}
}

func TestEmergencyWipe_Trigger(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)

	ew := NewEmergencyWipe(50 * time.Millisecond)
	ew.Register(v)

	v.Derive("test")
	ew.Trigger("anomaly detected")

	time.Sleep(100 * time.Millisecond)
	if v.IsHealthy() {
		t.Error("expected wiped after trigger delay")
	}
}

// ── Integration: Full stack ────────────────────────────────────────────────

func TestFullStack(t *testing.T) {
	dir := t.TempDir()

	// 1. Create vault
	vault, err := NewKeyVault(dir)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}

	// 2. Store a secret
	ss := NewSecretStore(vault)
	sealed, err := ss.SetString("openai-key", "sk-prod-abc123")
	if err != nil {
		t.Fatalf("set secret: %v", err)
	}

	// 3. Memory-protect the master key
	mp := NewMemoryProtector(0)
	if err := mp.Protect(vault.master); err != nil {
		t.Fatalf("memory protect: %v", err)
	}

	// 4. Verify sentinel (skip optional check with empty hash)
	sentinel := NewBootSentinel("")
	saltPath := filepath.Join(dir, "vault.salt")
	if hash, err := fileSHA256(saltPath); err == nil {
		sentinel.Register(saltPath, hash, true)
	}
	_ = sentinel.Verify()

	// 5. Retrieve secret
	plain, err := ss.GetString("openai-key", sealed)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if plain != "sk-prod-abc123" {
		t.Errorf("secret mismatch: %q", plain)
	}

	// 6. Emergency wipe
	ew := NewEmergencyWipe(0)
	ew.Register(vault)
	ew.Register(ss)
	ew.Register(mp)
	ew.Execute("panic")

	if vault.IsHealthy() {
		t.Error("vault should be wiped")
	}
}

// ── Concurrency Tests ──────────────────────────────────────────────────────

func TestKeyVault_ConcurrentDerive(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func(n int) {
			_, _ = v.Derive("svc")
			done <- true
		}(i)
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestSecretStore_Concurrent(t *testing.T) {
	dir := t.TempDir()
	v, _ := NewKeyVault(dir)
	ss := NewSecretStore(v)

	sealed, _ := ss.SetString("key", "value")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = ss.GetString("key", sealed)
		}()
	}
	wg.Wait()
}
