package transit

import (
	"bytes"
	"testing"
)

func TestCipherRoundTrip(t *testing.T) {
	c := NewCipher("test-shared-key")
	plain := []byte("hello TSG 4.9.0")
	cipherB64, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if cipherB64 == "" {
		t.Fatal("cipher empty")
	}
	decrypted, err := c.Decrypt(cipherB64)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("decrypted = %s, want %s", decrypted, plain)
	}
}

func TestCipherDifferentKey(t *testing.T) {
	c1 := NewCipher("key-a")
	c2 := NewCipher("key-b")
	plain := []byte("secret")
	cipher, _ := c1.Encrypt(plain)
	_, err := c2.Decrypt(cipher)
	if err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestCipherEmptyPlaintext(t *testing.T) {
	c := NewCipher("key")
	cipher, err := c.Encrypt([]byte(""))
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	decrypted, err := c.Decrypt(cipher)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatal("decrypted empty should be empty")
	}
}

func TestDeriveKey(t *testing.T) {
	k1 := DeriveKey("password")
	k2 := DeriveKey("password")
	if !bytes.Equal(k1, k2) {
		t.Fatal("same password should derive same key")
	}
	k3 := DeriveKey("different")
	if bytes.Equal(k1, k3) {
		t.Fatal("different password should derive different key")
	}
}
