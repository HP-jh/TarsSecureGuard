package mcp

import (
	"strings"
	"testing"
)

func TestFind(t *testing.T) {
	in, idx := Find("Bifrost")
	if in == nil || idx < 0 {
		t.Fatal("expected Bifrost")
	}
	if in.Repo != "HP-jh/TarsBifrost" {
		t.Fatalf("repo mismatch: %s", in.Repo)
	}
	in2, _ := Find("bifrost")
	if in2 == nil {
		t.Fatal("case-insensitive find failed")
	}
	in3, _ := Find("NonExistent")
	if in3 != nil {
		t.Fatal("expected nil")
	}
}

func TestRegistryLength(t *testing.T) {
	if len(Registry) != 15 {
		t.Fatalf("expected 15 integrations, got %d", len(Registry))
	}
}

func TestAssetName(t *testing.T) {
	in, _ := Find("Bifrost")
	name := in.AssetName("v0.1.0")
	if !contains(name, "tars-bifrost") {
		t.Fatalf("unexpected asset name: %s", name)
	}
}

func TestAllNames(t *testing.T) {
	names := AllNames()
	if len(names) != 15 {
		t.Fatalf("expected 15 names, got %d", len(names))
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
