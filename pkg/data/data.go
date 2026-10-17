// Package data manages persistent data directories independent of install paths.
// v4.15.1: config/logs/cache/state/custom/backup subdirs, never touched on upgrade.
package data

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Manager handles data-root and subdirectories.
type Manager struct {
	Root string
}

// DefaultRoot returns the platform-specific default data root.
func DefaultRoot() string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "tars", "data")
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local, _ = os.UserHomeDir()
		}
		return filepath.Join(local, "tars", "data")
	case "android":
		return "/data/data/com.tarssecureguard/files/tars/data"
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".tars", "data")
	}
}

// New creates a Manager. Empty root uses default.
func New(root string) *Manager {
	if root == "" {
		root = DefaultRoot()
	}
	return &Manager{Root: root}
}

// EnsureAll creates all standard subdirectories.
func (m *Manager) EnsureAll() error {
	for _, sub := range []string{"config", "logs", "cache", "state", "custom", "backup"} {
		if err := os.MkdirAll(filepath.Join(m.Root, sub), 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", sub, err)
		}
	}
	return nil
}

// Sub returns the path to a named subdirectory.
func (m *Manager) Sub(name string) string {
	return filepath.Join(m.Root, name)
}

// ConfigPath returns data/config/<name>.
func (m *Manager) ConfigPath(name string) string {
	return filepath.Join(m.Root, "config", name)
}

// LogPath returns data/logs/<name>.
func (m *Manager) LogPath(name string) string {
	return filepath.Join(m.Root, "logs", name)
}

// CachePath returns data/cache/<name>.
func (m *Manager) CachePath(name string) string {
	return filepath.Join(m.Root, "cache", name)
	}

// StatePath returns data/state/<name>.
func (m *Manager) StatePath(name string) string {
	return filepath.Join(m.Root, "state", name)
}

// CustomPath returns data/custom/<name>.
func (m *Manager) CustomPath(name string) string {
	return filepath.Join(m.Root, "custom", name)
}

// BackupPath returns data/backup/<name>.
func (m *Manager) BackupPath(name string) string {
	return filepath.Join(m.Root, "backup", name)
}

// InstallHistory records an upgrade event.
type InstallHistory struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // install | switch | rollback
	Channel   string    `json:"channel"` // stable | beta
}

// AppendInstallHistory appends an entry to state/install_history.json.
func (m *Manager) AppendInstallHistory(h InstallHistory) error {
	path := m.StatePath("install_history.json")
	var hist []InstallHistory
	b, _ := os.ReadFile(path)
	_ = json.Unmarshal(b, &hist)
	hist = append(hist, h)
	b, err := json.MarshalIndent(hist, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

// ReadInstallHistory reads the full install history.
func (m *Manager) ReadInstallHistory() ([]InstallHistory, error) {
	path := m.StatePath("install_history.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var hist []InstallHistory
	if err := json.Unmarshal(b, &hist); err != nil {
		return nil, err
	}
	return hist, nil
}

// Migrate ensures any missing files/fields are present without deleting existing data.
// It is called on every startup by the new version.
func (m *Manager) Migrate() error {
	_ = m.EnsureAll()
	// Ensure update channel config exists
	upPath := m.ConfigPath("update.json")
	if _, err := os.Stat(upPath); os.IsNotExist(err) {
		def := map[string]interface{}{
			"channel":      "stable",
			"last_check":   time.Now().Format(time.RFC3339),
			"auto_prompt":  true,
		}
		b, _ := json.MarshalIndent(def, "", "  ")
		_ = os.WriteFile(upPath, b, 0644)
	}
	return nil
}

// BackupConfig copies the current config.json into backup/ with a timestamp.
func (m *Manager) BackupConfig() error {
	src := m.ConfigPath("config.json")
	if _, err := os.Stat(src); err != nil {
		return nil // nothing to backup
	}
	ts := time.Now().Format("20060102-150405.000000000")
	dst := m.BackupPath(fmt.Sprintf("config-%s.json", ts))
	_ = os.MkdirAll(filepath.Dir(dst), 0755)
	return copyFile(src, dst)
}

// PruneBackups keeps only the last N backups.
func (m *Manager) PruneBackups(keep int) error {
	dir := m.Sub("backup")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e)
		}
	}
	if len(files) <= keep {
		return nil
	}
	// Sort by name (timestamp prefix) descending
	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[i].Name() < files[j].Name() {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	for _, f := range files[keep:] {
		_ = os.Remove(filepath.Join(dir, f.Name()))
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(dst), 0755)
	return os.WriteFile(dst, b, 0644)
}
