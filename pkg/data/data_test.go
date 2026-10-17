package data

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRoot(t *testing.T) {
	r := DefaultRoot()
	if r == "" {
		t.Fatal("empty default root")
	}
}

func TestEnsureAll(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	if err := m.EnsureAll(); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"config", "logs", "cache", "state", "custom", "backup"} {
		p := filepath.Join(tmp, sub)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing subdir %s", sub)
		}
	}
}

func TestSubPaths(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	if m.ConfigPath("x.json") != filepath.Join(tmp, "config", "x.json") {
		t.Fatal("config path wrong")
	}
	if m.LogPath("app.log") != filepath.Join(tmp, "logs", "app.log") {
		t.Fatal("log path wrong")
	}
}

func TestInstallHistory(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	_ = m.EnsureAll()
	if err := m.AppendInstallHistory(InstallHistory{Version: "4.15.1", Action: "install", Channel: "stable"}); err != nil {
		t.Fatal(err)
	}
	hist, err := m.ReadInstallHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Version != "4.15.1" {
		t.Fatalf("history mismatch: %+v", hist)
	}
}

func TestMigrateCreatesUpdateConfig(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	if err := m.Migrate(); err != nil {
		t.Fatal(err)
	}
	p := m.ConfigPath("update.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatal("update.json not created")
	}
}

func TestBackupAndPrune(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	_ = m.EnsureAll()
	_ = os.WriteFile(m.ConfigPath("config.json"), []byte("{}"), 0644)
	for i := 0; i < 5; i++ {
		_ = m.BackupConfig()
	}
	entries, _ := os.ReadDir(m.Sub("backup"))
	if len(entries) != 5 {
		t.Fatalf("expected 5 backups, got %d", len(entries))
	}
	_ = m.PruneBackups(2)
	entries, _ = os.ReadDir(m.Sub("backup"))
	if len(entries) != 2 {
		t.Fatalf("expected 2 backups after prune, got %d", len(entries))
	}
}
