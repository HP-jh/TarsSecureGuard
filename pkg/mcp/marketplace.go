// marketplace.go: HTTP API for MCP Marketplace.
package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/HP-jh/TarsSecureGuard/pkg/data"
	"github.com/HP-jh/TarsSecureGuard/pkg/install"
	"github.com/HP-jh/TarsSecureGuard/pkg/update"
)

// Marketplace handles marketplace HTTP endpoints.
type Marketplace struct {
	mu      sync.RWMutex
	install *install.Manager
	data    *data.Manager
	mgr     *Manager
}

// NewMarketplace creates a marketplace bound to install/data roots.
func NewMarketplace(installRoot, dataRoot string) *Marketplace {
	return &Marketplace{
		install: install.New(installRoot),
		data:    data.New(dataRoot),
		mgr:     NewManager(dataRoot),
	}
}

// ScanOnBoot delegates to manager.
func (mp *Marketplace) ScanOnBoot() error {
	return mp.mgr.ScanOnBoot()
}

// integrationStatus reflects the runtime state of one integration.
type integrationStatus struct {
	Integration
	Version   string `json:"version"`
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	PID       int    `json:"pid"`
	HasUpdate bool   `json:"hasUpdate"`
}

// HandleList returns the full marketplace list with statuses.
func (mp *Marketplace) HandleList(w http.ResponseWriter, r *http.Request) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	var out []integrationStatus
	for _, in := range Registry {
		st := mp.statusOf(&in)
		out = append(out, st)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// HandleStatus returns status for a single integration.
func (mp *Marketplace) HandleStatus(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	in, _ := Find(name)
	if in == nil {
		http.Error(w, `{"error":"unknown integration"}`, http.StatusNotFound)
		return
	}
	st := mp.statusOf(in)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

// HandleDownload fetches the latest release binary from GitHub.
func (mp *Marketplace) HandleDownload(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	in, _ := Find(name)
	if in == nil {
		http.Error(w, `{"error":"unknown"}`, http.StatusNotFound)
		return
	}
	ver, err := mp.downloadLatest(in)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "downloaded", "version": ver})
}

// HandleEnable registers the integration and spawns the subprocess.
func (mp *Marketplace) HandleEnable(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	in, _ := Find(name)
	if in == nil {
		http.Error(w, `{"error":"unknown"}`, http.StatusNotFound)
		return
	}
	cfg := mp.readConfig(in.Name)
	if cfg.Version == "" {
		http.Error(w, `{"error":"not downloaded"}`, http.StatusBadRequest)
		return
	}
	cfg.Enabled = true
	if err := mp.writeConfig(in.Name, cfg); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if err := mp.mgr.Start(in, cfg); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "enabled"})
}

// HandleDisable stops the subprocess and marks disabled.
func (mp *Marketplace) HandleDisable(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	in, _ := Find(name)
	if in == nil {
		http.Error(w, `{"error":"unknown"}`, http.StatusNotFound)
		return
	}
	_ = mp.mgr.Stop(in.Name)
	cfg := mp.readConfig(in.Name)
	cfg.Enabled = false
	_ = mp.writeConfig(in.Name, cfg)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "disabled"})
}

// HandleUpdate checks for newer release and upgrades if available.
func (mp *Marketplace) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	in, _ := Find(name)
	if in == nil {
		http.Error(w, `{"error":"unknown"}`, http.StatusNotFound)
		return
	}
	cfg := mp.readConfig(in.Name)
	u := update.NewUpdater("v"+cfg.Version, strings.Split(in.Repo, "/")[0], strings.Split(in.Repo, "/")[1], mp.install.Root, mp.data.Root)
	res := u.Check()
	if res.Error != "" {
		http.Error(w, fmt.Sprintf(`{"error":"check failed: %s"}`, res.Error), http.StatusInternalServerError)
		return
	}
	if !res.HasUpdate {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "up-to-date", "version": cfg.Version})
		return
	}
	// Download new version
	ver, err := mp.downloadLatest(in)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"download: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	// Restart if enabled
	if cfg.Enabled {
		_ = mp.mgr.Stop(in.Name)
		cfg.Version = ver
		_ = mp.writeConfig(in.Name, cfg)
		_ = mp.mgr.Start(in, cfg)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated", "version": ver})
}

// HandleCheckAll checks all integrations for updates.
func (mp *Marketplace) HandleCheckAll(w http.ResponseWriter, r *http.Request) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	var results []map[string]string
	for _, in := range Registry {
		cfg := mp.readConfig(in.Name)
		if cfg.Version == "" {
			continue
		}
		parts := strings.Split(in.Repo, "/")
		u := update.NewUpdater("v"+cfg.Version, parts[0], parts[1], mp.install.Root, mp.data.Root)
		res := u.Check()
		results = append(results, map[string]string{
			"name":    in.Name,
			"current": cfg.Version,
			"latest":  res.Latest,
			"hasUpdate": fmt.Sprintf("%v", res.HasUpdate),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// HandleDispatch routes per-integration requests under /api/v1/mcp/marketplace/:name/:action.
func (mp *Marketplace) HandleDispatch(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/mcp/marketplace")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	name := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	in, _ := Find(name)
	if in == nil {
		http.Error(w, `{"error":"unknown integration"}`, http.StatusNotFound)
		return
	}
	// Rewrite URL path so individual handlers can use filepath.Base to extract name.
	r.URL.Path = name
	switch action {
	case "":
		mp.HandleStatus(w, r)
	case "download":
		mp.HandleDownload(w, r)
	case "enable":
		mp.HandleEnable(w, r)
	case "disable":
		mp.HandleDisable(w, r)
	case "update":
		mp.HandleUpdate(w, r)
	default:
		http.Error(w, `{"error":"unknown action"}`, http.StatusNotFound)
	}
}

// ---- helpers ----

func (mp *Marketplace) statusOf(in *Integration) integrationStatus {
	cfg := mp.readConfig(in.Name)
	st := integrationStatus{Integration: *in, Version: cfg.Version, Installed: cfg.Version != "", Enabled: cfg.Enabled}
	if proc := mp.mgr.Get(in.Name); proc != nil {
		st.Running = proc.Running()
		st.PID = proc.PID()
	}
	return st
}

func (mp *Marketplace) readConfig(name string) mcpConfig {
	path := filepath.Join(mp.data.Sub("config"), "mcp", name+".json")
	var cfg mcpConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(b, &cfg)
	return cfg
}

func (mp *Marketplace) writeConfig(name string, cfg mcpConfig) error {
	dir := filepath.Join(mp.data.Sub("config"), "mcp")
	_ = os.MkdirAll(dir, 0755)
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(filepath.Join(dir, name+".json"), b, 0644)
}

func (mp *Marketplace) downloadLatest(in *Integration) (string, error) {
	parts := strings.Split(in.Repo, "/")
	u := update.NewUpdater("v0.0.0", parts[0], parts[1], mp.install.Root, mp.data.Root)
	res := u.Check()
	if res.Error != "" {
		return "", fmt.Errorf("check: %s", res.Error)
	}
	if !res.HasUpdate && res.Latest == "" {
		return "", fmt.Errorf("no release found")
	}
	ver := strings.TrimPrefix(res.Latest, "v")
	verDir := mp.install.VersionDir(in.Name + "-" + ver)
	_ = os.MkdirAll(verDir, 0755)

	binName := in.BinaryName
	if res.DownloadURL == "" {
		return "", fmt.Errorf("no asset for this platform")
	}
	// Download via generic HTTP client
	if err := downloadFile(res.DownloadURL, filepath.Join(verDir, binName)); err != nil {
		return "", err
	}
	_ = os.Chmod(filepath.Join(verDir, binName), 0755)
	// Record config
	cfg := mp.readConfig(in.Name)
	cfg.Version = ver
	_ = mp.writeConfig(in.Name, cfg)
	return ver, nil
}

func downloadFile(url, dst string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
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
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Sync()
}
