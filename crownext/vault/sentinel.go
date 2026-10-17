// sentinel.go — BootSentinel: startup integrity verification.
package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// BootSentinel verifies the integrity of critical files at startup.
type BootSentinel struct {
	mu           sync.RWMutex
	manifestPath string
	root         string
	checks       []IntegrityCheck
}

// IntegrityCheck defines a file to verify.
type IntegrityCheck struct {
	Path     string `json:"path"`
	Expected string `json:"expected"` // hex-encoded SHA-256
	Optional bool   `json:"optional"`
}

// NewBootSentinel creates a sentinel for the given manifest file.
func NewBootSentinel(manifestPath string) *BootSentinel {
	return &BootSentinel{manifestPath: manifestPath}
}

// Register adds an integrity check.
func (s *BootSentinel) Register(path, expectedSHA256 string, optional bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks = append(s.checks, IntegrityCheck{
		Path:     path,
		Expected: expectedSHA256,
		Optional: optional,
	})
}

// Verify checks all registered files.
func (s *BootSentinel) Verify() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.checks {
		path := c.Path
		if s.root != "" && !filepath.IsAbs(path) {
			path = filepath.Join(s.root, path)
		}
		actual, err := fileSHA256(path)
		if err != nil {
			if c.Optional {
				continue
			}
			return fmt.Errorf("sentinel: cannot read %s: %w", path, err)
		}
		if actual != c.Expected {
			return fmt.Errorf("sentinel: integrity fail for %s: expected %s got %s",
				path, c.Expected[:16], actual[:16])
		}
	}
	return nil
}

// GenerateManifest creates a manifest for files under a directory.
func (s *BootSentinel) GenerateManifest(root string, patterns []string) ([]IntegrityCheck, error) {
	var checks []IntegrityCheck
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			hash, err := fileSHA256(m)
			if err != nil {
				continue
			}
			rel, _ := filepath.Rel(root, m)
			checks = append(checks, IntegrityCheck{Path: rel, Expected: hash})
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root = root
	s.checks = checks
	return checks, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
