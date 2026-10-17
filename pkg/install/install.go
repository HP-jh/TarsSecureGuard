// Package install manages unified install paths and version coexistence.
// v4.15.1
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Manager handles install-root, version directories, and current symlink.
type Manager struct {
	Root string // e.g. ~/.tars/install
}

// DefaultRoot returns the platform-specific default install root.
func DefaultRoot() string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "tars", "install")
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local, _ = os.UserHomeDir()
		}
		return filepath.Join(local, "tars", "install")
	case "android":
		// Android apps write to /data/data/<pkg>/files
		return "/data/data/com.tarssecureguard/files/tars/install"
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".tars", "install")
	}
}

// New creates a Manager with the given root (empty = default).
func New(root string) *Manager {
	if root == "" {
		root = DefaultRoot()
	}
	return &Manager{Root: root}
}

// VersionDir returns the directory for a specific version.
func (m *Manager) VersionDir(ver string) string {
	ver = strings.TrimPrefix(ver, "v")
	return filepath.Join(m.Root, ver)
}

// CurrentPath returns the path of the current symlink/shortcut.
func (m *Manager) CurrentPath() string {
	return filepath.Join(m.Root, "current")
}

// BinaryPath returns the path to the binary inside a version dir.
func (m *Manager) BinaryPath(ver string) string {
	name := "TarsSecureGuard"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(m.VersionDir(ver), name)
}

// CurrentBinary returns the path to the currently active binary.
func (m *Manager) CurrentBinary() string {
	name := "TarsSecureGuard"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(m.CurrentPath(), name)
}

// EnsureVersion creates the version directory if missing.
func (m *Manager) EnsureVersion(ver string) error {
	return os.MkdirAll(m.VersionDir(ver), 0755)
}

// SetCurrent switches the current pointer to the given version.
// On Windows it uses a junction; elsewhere a symlink.
func (m *Manager) SetCurrent(ver string) error {
	cur := m.CurrentPath()
	target := m.VersionDir(ver)
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("version dir not found: %s", target)
	}
	// Remove old pointer
	_ = os.Remove(cur)
	if runtime.GOOS == "windows" {
		return m.setCurrentWindows(cur, target)
	}
	return os.Symlink(target, cur)
}

func (m *Manager) setCurrentWindows(link, target string) error {
	// Use mklink /J junction for directories on Windows
	cmd := osExec("cmd", "/c", "mklink", "/J", link, target)
	return cmd.Run()
}

// osExec helper for Windows junction
var osExec = func(name string, arg ...string) *osExecCmd {
	return &osExecCmd{Cmd: name, Args: arg}
}

type osExecCmd struct {
	Cmd  string
	Args []string
}

// init fixes osExec on Windows by using os/exec in _windows file
// The actual implementation is in install_windows.go / install_other.go

// ReadCurrent returns the version pointed to by current.
func (m *Manager) ReadCurrent() (string, error) {
	cur := m.CurrentPath()
	fi, err := os.Lstat(cur)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(cur)
		if err != nil {
			return "", err
		}
		return filepath.Base(target), nil
	}
	// Windows junction or regular dir
	abs, err := filepath.Abs(cur)
	if err != nil {
		return "", err
	}
	return filepath.Base(abs), nil
}

// ListInstalled returns all installed version strings, sorted descending.
func (m *Manager) ListInstalled() ([]string, error) {
	entries, err := os.ReadDir(m.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "current" {
			continue
		}
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		return compareVersion(out[i], out[j]) > 0
	})
	return out, nil
}

// RemoveVersion deletes a version directory (fails if it is current).
func (m *Manager) RemoveVersion(ver string) error {
	cur, _ := m.ReadCurrent()
	if cur == ver {
		return fmt.Errorf("cannot remove currently active version %s", ver)
	}
	return os.RemoveAll(m.VersionDir(ver))
}

// IsManaged returns true if the executable lives inside the install root.
func (m *Manager) IsManaged() (bool, error) {
	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	absRoot, err := filepath.Abs(m.Root)
	if err != nil {
		return false, err
	}
	absSelf, err := filepath.Abs(self)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(absSelf, absRoot+string(filepath.Separator)), nil
}

// compareVersion does simple numeric semver comparison for sorting.
func compareVersion(a, b string) int {
	pa := parseVersionParts(a)
	pb := parseVersionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] - pb[i]
		}
	}
	return 0
}

func parseVersionParts(s string) [3]int {
	s = strings.TrimPrefix(s, "v")
	var out [3]int
	for i, p := range strings.SplitN(s, ".", 3) {
		if i >= 3 {
			break
		}
		fmt.Sscanf(p, "%d", &out[i])
	}
	return out
}
