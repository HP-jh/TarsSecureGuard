package install

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultRoot(t *testing.T) {
	r := DefaultRoot()
	if r == "" {
		t.Fatal("empty default root")
	}
	if runtime.GOOS == "linux" {
		if !contains(r, ".tars/install") {
			t.Fatalf("unexpected linux root: %s", r)
		}
	}
}

func TestManagerPaths(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	vd := m.VersionDir("4.15.1")
	if filepath.Base(vd) != "4.15.1" {
		t.Fatalf("version dir base wrong: %s", vd)
	}
	if m.CurrentPath() != filepath.Join(tmp, "current") {
		t.Fatalf("current path wrong: %s", m.CurrentPath())
	}
}

func TestEnsureAndSetCurrent(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	if err := m.EnsureVersion("4.15.1"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetCurrent("4.15.1"); err != nil {
		t.Fatal(err)
	}
	cur, err := m.ReadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if cur != "4.15.1" {
		t.Fatalf("current mismatch: got %s", cur)
	}
}

func TestListInstalled(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	for _, v := range []string{"4.14.0", "4.15.0", "4.15.1"} {
		if err := m.EnsureVersion(v); err != nil {
			t.Fatal(err)
		}
	}
	list, err := m.ListInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
	if list[0] != "4.15.1" {
		t.Fatalf("expected 4.15.1 first, got %s", list[0])
	}
}

func TestRemoveVersionBlockedIfCurrent(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	_ = m.EnsureVersion("4.15.1")
	_ = m.SetCurrent("4.15.1")
	if err := m.RemoveVersion("4.15.1"); err == nil {
		t.Fatal("expected error removing current version")
	}
}

func TestRemoveVersionOK(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	_ = m.EnsureVersion("4.14.0")
	_ = m.EnsureVersion("4.15.1")
	_ = m.SetCurrent("4.15.1")
	if err := m.RemoveVersion("4.14.0"); err != nil {
		t.Fatal(err)
	}
	list, _ := m.ListInstalled()
	if len(list) != 1 {
		t.Fatalf("expected 1 after remove, got %d", len(list))
	}
}

func TestIsManaged(t *testing.T) {
	tmp := t.TempDir()
	m := New(tmp)
	// executable is the test binary, not inside tmp
	ok, _ := m.IsManaged()
	if ok {
		t.Fatal("expected not managed")
	}
}

func TestCompareVersion(t *testing.T) {
	cases := []struct{ a, b string; want int }{
		{"4.15.1", "4.15.0", 1},
		{"4.14.0", "4.15.0", -1},
		{"4.15.0", "4.15.0", 0},
	}
	for _, c := range cases {
		got := compareVersion(c.a, c.b)
		if got != c.want {
			t.Fatalf("compareVersion(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && s[len(s)-len(sub):] == sub || len(s) > len(sub) && contains(s[:len(s)-1], sub)
}
