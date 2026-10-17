// update_test.go: unit tests for auto-update.
package update

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want Version
	}{
		{"v4.14.0", Version{4, 14, 0, "", ""}},
		{"4.14.0", Version{4, 14, 0, "", ""}},
		{"v4.14.0-alpha.1", Version{4, 14, 0, "alpha.1", ""}},
		{"v4.14.0+build.123", Version{4, 14, 0, "", "build.123"}},
	}
	for _, c := range cases {
		got, err := ParseVersion(c.in)
		if err != nil {
			t.Fatalf("parse %q: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("parse %q = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestVersionGreaterThan(t *testing.T) {
	cases := []struct {
		a, b string
		gt   bool
	}{
		{"v4.14.0", "v4.13.0", true},
		{"v4.13.0", "v4.14.0", false},
		{"v4.14.1", "v4.14.0", true},
		{"v4.14.0", "v4.14.0", false},
		{"v4.14.0", "v4.14.0-alpha", true},
		{"v4.14.0-alpha", "v4.14.0", false},
	}
	for _, c := range cases {
		a, _ := ParseVersion(c.a)
		b, _ := ParseVersion(c.b)
		if a.GreaterThan(b) != c.gt {
			t.Fatalf("%s > %s = %v, want %v", c.a, c.b, a.GreaterThan(b), c.gt)
		}
	}
}

func TestGitHubClientMock(t *testing.T) {
	release := Release{
		TagName: "v4.15.0", Name: "v4.15.0", HTMLURL: "https://example.com/v4.15.0",
		Assets: []Asset{
			{Name: "tsg-v4.15.0-linux-amd64", BrowserDownloadURL: "https://example.com/bin"},
			{Name: "SHA256SUMS-v4.15.0.txt", BrowserDownloadURL: "https://example.com/sums"},
		},
	}
	b, _ := json.Marshal(release)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	defer ts.Close()

	client := NewGitHubClient("owner", "repo")
	client.Client = ts.Client()
	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := client.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("mock status %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		t.Fatal(err)
	}
	if rel.TagName != "v4.15.0" {
		t.Fatalf("tag = %s", rel.TagName)
	}
	bin, sums := FindAsset(&rel, "linux", "amd64")
	if bin == nil || sums == nil {
		t.Fatal("asset not found")
	}
}

func TestStableTableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	u := &Updater{ConfigDir: dir}
	tab := StableTable{
		TarsSecureGuard: "v4.14.0",
		TarsEnterprise:  "v0.3.0",
		LastSync:        time.Now().Format(time.RFC3339),
	}
	if err := u.SaveStableTable(tab); err != nil {
		t.Fatal(err)
	}
	loaded, err := u.LoadStableTable()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TarsSecureGuard != "v4.14.0" {
		t.Fatalf("stable = %s", loaded.TarsSecureGuard)
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	u := &Updater{ConfigDir: dir, HTTPClient: &http.Client{Timeout: 5 * time.Second}}

	binPath := filepath.Join(dir, "testbin")
	if err := os.WriteFile(binPath, []byte("hello update"), 0755); err != nil {
		t.Fatal(err)
	}

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("hello update")))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  testbin\n", hash)
	}))
	defer ts.Close()

	if err := u.verifySHA256(binPath, ts.URL, "v4.14.0"); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(binPath, []byte("tampered"), 0755)
	if err := u.verifySHA256(binPath, ts.URL, "v4.14.0"); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestFallbackStableVersion(t *testing.T) {
	dir := t.TempDir()
	u := &Updater{ConfigDir: dir}
	if v := u.FallbackStableVersion(); v != "" {
		t.Fatalf("empty fallback = %q", v)
	}
	_ = u.SaveStableTable(StableTable{TarsSecureGuard: "v4.14.0"})
	if v := u.FallbackStableVersion(); v != "v4.14.0" {
		t.Fatalf("fallback = %q", v)
	}
}

func TestWriteDefaultStableTable(t *testing.T) {
	dir := t.TempDir()
	if err := WriteDefaultStableTable(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "stable_versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tab StableTable
	if err := json.Unmarshal(b, &tab); err != nil {
		t.Fatal(err)
	}
	if tab.TarsSecureGuard != "v4.14.0" {
		t.Fatalf("default stable = %s", tab.TarsSecureGuard)
	}
}
