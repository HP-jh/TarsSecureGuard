// sources_test.go: tests for community marketplace.
package community

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryDefaults(t *testing.T) {
	dir := t.TempDir()
	r := NewRegistry(dir)
	list := r.List()
	if len(list) == 0 {
		t.Fatal("expected default sources")
	}
	found := false
	for _, s := range list {
		if s.ID == "official-github" {
			found = true
			if s.TrustLevel != "official" {
				t.Fatalf("expected official trust level, got %s", s.TrustLevel)
			}
		}
	}
	if !found {
		t.Fatal("expected official-github default source")
	}
}

func TestRegistryCRUD(t *testing.T) {
	dir := t.TempDir()
	r := NewRegistry(dir)

	s := &MCPSource{ID: "test-src", Name: "Test", Type: "http", URL: "http://example.com/reg.json", TrustLevel: "community"}
	if err := r.Add(s); err != nil {
		t.Fatal(err)
	}

	got, ok := r.Get("test-src")
	if !ok || got.Name != "Test" {
		t.Fatal("get failed")
	}

	if err := r.UpdateEnabled("test-src", false); err != nil {
		t.Fatal(err)
	}
	got, _ = r.Get("test-src")
	if got.Enabled {
		t.Fatal("expected disabled")
	}

	if err := r.Remove("test-src"); err != nil {
		t.Fatal(err)
	}
	_, ok = r.Get("test-src")
	if ok {
		t.Fatal("expected removed")
	}
}

func TestVerifierSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte("hello mcp community")
	_ = os.WriteFile(path, data, 0644)

	v := NewVerifier()
	// Wrong digest should fail.
	if err := v.VerifySHA256(path, "0000"); err == nil {
		t.Fatal("expected sha256 mismatch")
	}
	// Compute correct digest and verify.
	got, err := ComputeSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifySHA256(path, got); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestTrustBadge(t *testing.T) {
	if TrustBadge("official") != "Official" {
		t.Fatal("official badge mismatch")
	}
	if TrustBadge("personal") != "Personal" {
		t.Fatal("personal badge mismatch")
	}
	if TrustBadge("unknown") != "Unknown" {
		t.Fatal("unknown badge mismatch")
	}
}
