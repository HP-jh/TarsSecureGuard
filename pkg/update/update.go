// update.go: core auto-update logic with unified install path.
// v4.15.1: install/data isolation + channel support.
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

	"github.com/HP-jh/TarsSecureGuard/pkg/data"
	"github.com/HP-jh/TarsSecureGuard/pkg/install"
)

// Updater handles version checking, downloading, and applying updates.
type Updater struct {
	CurrentVersion string
	Owner          string
	Repo           string
	GitHub         *GitHubClient
	HTTPClient     *http.Client
	ConfigDir      string // legacy ~/.tars
	InstallMgr     *install.Manager
	DataMgr        *data.Manager
	Channel        Channel
}

// NewUpdater creates an updater. If installRoot/dataRoot are empty, defaults are used.
func NewUpdater(currentVersion, owner, repo, installRoot, dataRoot string) *Updater {
	u := &Updater{
		CurrentVersion: currentVersion,
		Owner:          owner,
		Repo:           repo,
		GitHub:         NewGitHubClient(owner, repo),
		HTTPClient:     &http.Client{Timeout: 120 * time.Second},
		ConfigDir:      defaultConfigDir(),
		InstallMgr:     install.New(installRoot),
		DataMgr:        data.New(dataRoot),
		Channel:        ChannelStable,
	}
	// Load channel from data config
	if cc, err := LoadChannelConfig(u.DataMgr.Sub("config")); err == nil && cc.Channel != "" {
		u.Channel = ParseChannel(cc.Channel)
	}
	return u
}

// CheckResult holds the result of a version check.
type CheckResult struct {
	HasUpdate   bool     `json:"hasUpdate"`
	Latest      string   `json:"latest"`
	Current     string   `json:"current"`
	DownloadURL string   `json:"downloadURL"`
	SumsURL     string   `json:"sumsURL"`
	ReleaseURL  string   `json:"releaseURL"`
	Channel     string   `json:"channel"`
	Error       string   `json:"error"`
}

// Check queries GitHub for a newer version respecting the channel.
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
	// Channel filtering
	if u.Channel == ChannelStable && !IsStableRelease(u.CurrentVersion, rel.TagName) {
		return CheckResult{Latest: rel.TagName, Current: u.CurrentVersion, Channel: string(u.Channel), Error: "latest is not a stable release"}
	}
	binary, sums := FindAsset(rel, runtime.GOOS, runtime.GOARCH)
	res := CheckResult{Latest: rel.TagName, Current: u.CurrentVersion, ReleaseURL: rel.HTMLURL, Channel: string(u.Channel)}
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

// CheckChannel queries GitHub and returns releases matching the channel.
func (u *Updater) CheckChannel() CheckResult {
	// Reuse Check for single latest; for channel-aware multi-release use ListReleases
	return u.Check()
}

// StableTable maps repo names to their last known stable version.
type StableTable struct {
	TarsSecureGuard     string `json:"TarsSecureGuard"`
	TarsEnterprise      string `json:"TarsEnterprise"`
	TarsWingGuard       string `json:"TarsWingGuard"`
	TarsOpenClawSandbox string `json:"TarsOpenClawSandbox"`
	TarsVoiceCorrection string `json:"TarsVoiceCorrection"`
	TarsUITarsBridge    string `json:"TarsUITarsBridge"`
	LastSync            string `json:"_last_sync"`
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

// Apply downloads, verifies, and installs the new version into the unified path.
// It does NOT modify any existing version directory.
func (u *Updater) Apply(check CheckResult) error {
	if !check.HasUpdate || check.DownloadURL == "" {
		return fmt.Errorf("no update available")
	}
	ver := strings.TrimPrefix(check.Latest, "v")
	verDir := u.InstallMgr.VersionDir(ver)
	if err := os.MkdirAll(verDir, 0755); err != nil {
		return fmt.Errorf("mkdir version dir: %w", err)
	}

	// Determine binary name
	binName := "TarsSecureGuard"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	tmpBin := filepath.Join(verDir, "."+binName+".tmp")

	// Download
	if err := u.downloadFile(check.DownloadURL, tmpBin); err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer os.Remove(tmpBin)

	// Verify
	if check.SumsURL != "" {
		if err := u.verifySHA256(tmpBin, check.SumsURL, check.Latest); err != nil {
			return fmt.Errorf("sha256 verify: %w", err)
		}
	}

	// Move into place
	finalBin := filepath.Join(verDir, binName)
	if err := os.Rename(tmpBin, finalBin); err != nil {
		return fmt.Errorf("stage binary: %w", err)
	}
	_ = os.Chmod(finalBin, 0755)

	// Backup current config before switching
	_ = u.DataMgr.BackupConfig()
	_ = u.DataMgr.PruneBackups(7)

	// Switch current pointer
	if err := u.InstallMgr.SetCurrent(ver); err != nil {
		return fmt.Errorf("set current: %w", err)
	}

	// Record history
	ch := string(u.Channel)
	_ = u.DataMgr.AppendInstallHistory(data.InstallHistory{
		Version:   check.Latest,
		Timestamp: time.Now(),
		Action:    "install",
		Channel:   ch,
	})

	// Log
	u.logUpdate(check.Latest, "success", "")

	// Save stable version
	t, _ := u.LoadStableTable()
	t.TarsSecureGuard = check.Latest
	_ = u.SaveStableTable(t)

	return nil
}

// Rollback restores the previous version from install history.
func (u *Updater) Rollback() error {
	hist, err := u.DataMgr.ReadInstallHistory()
	if err != nil || len(hist) < 2 {
		// Fallback to backup binary
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
	// Roll back to the version before last
	prev := hist[len(hist)-2].Version
	prev = strings.TrimPrefix(prev, "v")
	if err := u.InstallMgr.SetCurrent(prev); err != nil {
		return fmt.Errorf("rollback to %s: %w", prev, err)
	}
	_ = u.DataMgr.AppendInstallHistory(data.InstallHistory{
		Version:   prev,
		Timestamp: time.Now(),
		Action:    "rollback",
		Channel:   string(u.Channel),
	})
	return nil
}

// FallbackStableVersion returns the locally cached stable version when API fails.
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
	tmpSums := filepath.Join(u.ConfigDir, "sums.tmp")
	if err := u.downloadFile(sumsURL, tmpSums); err != nil {
		return err
	}
	defer os.Remove(tmpSums)
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
	path := u.DataMgr.LogPath("update.log")
	_ = os.MkdirAll(filepath.Dir(path), 0755)
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

// WriteDefaultStableTable creates the initial stable_versions.json.
func WriteDefaultStableTable(dir string) error {
	t := StableTable{
		TarsSecureGuard:     "v4.15.0",
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
