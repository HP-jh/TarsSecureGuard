// update.go: core auto-update logic.
package update

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Updater handles version checking, downloading, and applying updates.
type Updater struct {
	CurrentVersion string
	Owner          string
	Repo           string
	GitHub         *GitHubClient
	HTTPClient     *http.Client
	ConfigDir      string // e.g. ~/.tars
}

// NewUpdater creates an updater for the given repo.
func NewUpdater(currentVersion, owner, repo string) *Updater {
	return &Updater{
		CurrentVersion: currentVersion,
		Owner:          owner,
		Repo:           repo,
		GitHub:         NewGitHubClient(owner, repo),
		HTTPClient:     &http.Client{Timeout: 120 * time.Second},
		ConfigDir:      defaultConfigDir(),
	}
}

// CheckResult holds the result of a version check.
type CheckResult struct {
	HasUpdate   bool
	Latest      string
	Current     string
	DownloadURL string
	SumsURL     string
	ReleaseURL  string
	Error       string
}

// Check queries GitHub for a newer version.
func (u *Updater) Check() CheckResult {
	cur, err := ParseVersion(u.CurrentVersion)
	if err != nil {
		return CheckResult{Error: "parse current: " + err.Error()}
	}
	rel, err := u.GitHub.Latest()
	if err != nil {
		return CheckResult{Error: "fetch latest: " + err.Error()}
	}
	latest, err := ParseVersion(rel.TagName)
	if err != nil {
		return CheckResult{Error: "parse latest: " + err.Error()}
	}
	binary, sums := FindAsset(rel, runtime.GOOS, runtime.GOARCH)
	res := CheckResult{Latest: rel.TagName, Current: u.CurrentVersion, ReleaseURL: rel.HTMLURL}
	if binary != nil {
		res.DownloadURL = binary.BrowserDownloadURL
	}
	if sums != nil {
		res.SumsURL = sums.BrowserDownloadURL
	}
	if latest.GreaterThan(cur) {
		res.HasUpdate = true
	}
	return res
}

// StableTable maps repo names to their last known stable version.
type StableTable struct {
	TarsSecureGuard   string `json:"TarsSecureGuard"`
	TarsEnterprise    string `json:"TarsEnterprise"`
	TarsWingGuard     string `json:"TarsWingGuard"`
	TarsOpenClawSandbox string `json:"TarsOpenClawSandbox"`
	TarsVoiceCorrection string `json:"TarsVoiceCorrection"`
	TarsUITarsBridge  string `json:"TarsUITarsBridge"`
	LastSync          string `json:"_last_sync"`
}

// LoadStableTable reads ~/.tars/stable_versions.json.
func (u *Updater) LoadStableTable() (StableTable, error) {
	var t StableTable
	path := filepath.Join(u.ConfigDir, "stable_versions.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return t, err
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return t, err
	}
	return t, nil
}

// SaveStableTable writes ~/.tars/stable_versions.json.
func (u *Updater) SaveStableTable(t StableTable) error {
	if err := os.MkdirAll(u.ConfigDir, 0755); err != nil {
		return err
	}
	t.LastSync = time.Now().Format(time.RFC3339)
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(u.ConfigDir, "stable_versions.json"), b, 0644)
}

// Apply downloads, verifies, and replaces the binary.
func (u *Updater) Apply(check CheckResult) error {
	if !check.HasUpdate || check.DownloadURL == "" {
		return fmt.Errorf("no update available")
	}

	// Download new binary
	tmpBin := filepath.Join(u.ConfigDir, "update.tmp")
	if err := u.downloadFile(check.DownloadURL, tmpBin); err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer os.Remove(tmpBin)

	// Verify SHA256 if sums available
	if check.SumsURL != "" {
		if err := u.verifySHA256(tmpBin, check.SumsURL, check.Latest); err != nil {
			return fmt.Errorf("sha256 verify: %w", err)
		}
	}

	// Backup current binary
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	backup := self + ".backup"
	if err := copyFile(self, backup); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	// Atomic replace
	if err := os.Rename(tmpBin, self+".new"); err != nil {
		return fmt.Errorf("stage new: %w", err)
	}
	if err := os.Rename(self+".new", self); err != nil {
		// rollback
		_ = os.Rename(backup, self)
		return fmt.Errorf("replace: %w", err)
	}

	// Write update log
	u.logUpdate(check.Latest, "success", "")

	// Save stable version
	t, _ := u.LoadStableTable()
	t.TarsSecureGuard = check.Latest
	_ = u.SaveStableTable(t)

	return nil
}

// Rollback restores the backup binary.
func (u *Updater) Rollback() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	backup := self + ".backup"
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("no backup found")
	}
	return os.Rename(backup, self)
}

// fallbackStableVersion returns the locally cached stable version when API fails.
func (u *Updater) FallbackStableVersion() string {
	t, err := u.LoadStableTable()
	if err != nil {
		return ""
	}
	return t.TarsSecureGuard
}

func (u *Updater) downloadFile(url, dst string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	return f.Sync()
}

func (u *Updater) verifySHA256(binPath, sumsURL, tag string) error {
	// Download SHA256SUMS
	tmpSums := filepath.Join(u.ConfigDir, "sums.tmp")
	if err := u.downloadFile(sumsURL, tmpSums); err != nil {
		return err
	}
	defer os.Remove(tmpSums)

	// Compute local hash
	f, err := os.Open(binPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	localHash := hex.EncodeToString(h.Sum(nil))

	// Find expected hash
	var expected string
	sf, err := os.Open(tmpSums)
	if err != nil {
		return err
	}
	defer sf.Close()
	name := filepath.Base(binPath)
	scanner := bufio.NewScanner(sf)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 2 && parts[1] == name {
			expected = parts[0]
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("hash not found in sums")
	}
	if !strings.EqualFold(localHash, expected) {
		return fmt.Errorf("hash mismatch: got %s want %s", localHash, expected)
	}
	return nil
}

func (u *Updater) logUpdate(newVer, status, detail string) {
	path := filepath.Join(u.ConfigDir, "update.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] version=%s status=%s detail=%s\n", time.Now().Format(time.RFC3339), newVer, status, detail)
}

func defaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".tars")
}

func copyFile(src, dst string) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer df.Close()
	if _, err := io.Copy(df, sf); err != nil {
		return err
	}
	return df.Sync()
}

// WriteDefaultStableTable creates the initial stable_versions.json.
func WriteDefaultStableTable(dir string) error {
	t := StableTable{
		TarsSecureGuard:     "v4.14.0",
		TarsEnterprise:      "v0.2.0",
		TarsWingGuard:       "v0.1.0",
		TarsOpenClawSandbox: "v0.1.0",
		TarsVoiceCorrection: "v0.1.0",
		TarsUITarsBridge:    "v0.1.0",
		LastSync:            time.Now().Format(time.RFC3339),
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(t, "", "  ")
	return os.WriteFile(filepath.Join(dir, "stable_versions.json"), b, 0644)
}
