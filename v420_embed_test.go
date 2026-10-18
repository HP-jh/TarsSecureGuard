package main

import (
	"io/fs"
	"testing"
)

// TestV420EmbedCompleteness verifies frontend files are embedded
func TestV420EmbedCompleteness(t *testing.T) {
	expected := []string{
		"frontend/index.html",
		"frontend/i18n.js",
	}
	for _, path := range expected {
		data, err := fs.ReadFile(frontendFS, path)
		if err != nil {
			t.Fatalf("embed file %%s missing: %%v", path, err)
		}
		if len(data) == 0 {
			t.Fatalf("embed file %%s empty", path)
		}
	}
}

// TestV420I18nJSNonEmpty verifies i18n.js content is readable
func TestV420I18nJSNonEmpty(t *testing.T) {
	data, err := fs.ReadFile(frontendFS, "frontend/i18n.js")
	if err != nil {
		t.Fatalf("i18n.js embed read failed: %%v", err)
	}
	if len(data) < 100 {
		t.Fatalf("i18n.js too short: %%d bytes", len(data))
	}
}
