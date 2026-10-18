package main

import (
	"regexp"
	"testing"
)

// TestV4202VersionSync verifies version string is non-empty and well-formed
func TestV4202VersionSync(t *testing.T) {
	if version == "" {
		t.Fatal("version variable is empty")
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		t.Fatalf("version %q does not match x.y.z format", version)
	}
}
