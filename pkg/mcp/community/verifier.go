// verifier.go: SHA256 and signature verification for downloaded packages.
package community

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Verifier checks package integrity.
type Verifier struct{}

// NewVerifier creates a verifier.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifySHA256 checks file against expected hex digest.
func (v *Verifier) VerifySHA256(filePath, expected string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", got, expected)
	}
	return nil
}

// VerifySig checks a base64-encoded detached Ed25519 signature.
// For now this is a stub: returns ok if sig is empty (no signature provided),
// otherwise returns an error because we have no public key infrastructure yet.
func (v *Verifier) VerifySig(filePath, sigB64 string) error {
	if sigB64 == "" {
		return nil // no signature to verify
	}
	// TODO: real Ed25519 signature verification once PKI is established.
	// For v4.17.0 we accept empty signatures and warn on non-empty ones.
	_, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	return fmt.Errorf("signature verification not yet implemented (signature present but unverified)")
}

// ComputeSHA256 returns the hex SHA256 of a file.
func ComputeSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
