// manager.go: subprocess lifecycle for MCP integrations.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HP-jh/TarsSecureGuard/pkg/data"
	"github.com/HP-jh/TarsSecureGuard/pkg/install"
)

// mcpConfig persisted per integration.
type mcpConfig struct {
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
	APIKey  string `json:"apiKey,omitempty"`
	PID     int    `json:"pid"`
}

// Manager tracks running MCP subprocesses.
type Manager struct {
	mu    sync.RWMutex
	procs map[string]*mcpProc
	data  *data.Manager // from pkg/data
}

// NewManager creates a manager.
func NewManager(dataRoot string) *Manager {
	return &Manager{
		procs: make(map[string]*mcpProc),
		data:  data.New(dataRoot),
	}
}

// mcpProc wraps an os.Process with health/restart state.
type mcpProc struct {
	name       string
	cmd        *exec.Cmd
	enabled    bool
	restartCnt int
	lastStart  time.Time
	mu         sync.Mutex
}

// Running reports whether the process is alive.
func (p *mcpProc) Running() bool {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return false
	}
	return p.cmd.Process.Signal(syscall.Signal(0)) == nil
}

// PID returns the process ID.
func (p *mcpProc) PID() int {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Start spawns the subprocess for an integration.
func (m *Manager) Start(in *Integration, cfg mcpConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.procs[in.Name]; ok && p.Running() {
		return nil
	}
	bin := filepath.Join(install.New("").VersionDir(in.Name+"-"+cfg.Version), in.BinaryName)
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("binary not found: %s", bin)
	}
	logPath := filepath.Join(m.data.LogPath("mcp"), in.Name+".log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0755)
	logFile, _ := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "--stdio")
	cmd.Env = append(os.Environ(), "TARS_MCP_MODE=stdio")
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start failed: %w", err)
	}
	p := &mcpProc{name: in.Name, cmd: cmd, enabled: true, lastStart: time.Now()}
	m.procs[in.Name] = p
	// Update config PID
	cfg.PID = cmd.Process.Pid
	_ = m.writeConfig(in.Name, cfg)
	// Watchdog
	go m.watchdog(ctx, cancel, p, in, cfg)
	return nil
}

// Stop terminates a subprocess gracefully then forcefully.
func (m *Manager) Stop(name string) error {
	m.mu.Lock()
	p, ok := m.procs[name]
	delete(m.procs, name)
	m.mu.Unlock()
	if !ok || p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = p.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
		return nil
	}
}

// Get returns a process handle (read-only).
func (m *Manager) Get(name string) *mcpProc {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.procs[name]
}

// ScanOnBoot reads ~/.tars/data/config/mcp/*.json and starts enabled ones.
func (m *Manager) ScanOnBoot() error {
	dir := filepath.Join(m.data.Sub("config"), "mcp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		cfg := m.readConfig(name)
		if !cfg.Enabled {
			continue
		}
		in, _ := Find(name)
		if in == nil {
			continue
		}
		if err := m.Start(in, cfg); err != nil {
			// Log but don't fail boot
			fmt.Fprintf(os.Stderr, "[MCP] failed to start %s: %v\n", name, err)
		}
	}
	return nil
}

// HealthCheckAll pings each running process.
func (m *Manager) HealthCheckAll() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]bool)
	for name, p := range m.procs {
		out[name] = p.Running()
	}
	return out
}

func (m *Manager) watchdog(ctx context.Context, cancel context.CancelFunc, p *mcpProc, in *Integration, cfg mcpConfig) {
	defer cancel()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !p.Running() {
				p.mu.Lock()
				// Rate limit restarts: max 3/hour
				if p.restartCnt >= 3 && time.Since(p.lastStart) < time.Hour {
					p.mu.Unlock()
					continue
				}
				p.restartCnt++
				p.lastStart = time.Now()
				p.mu.Unlock()
				_ = m.Stop(in.Name)
				_ = m.Start(in, cfg)
			} else {
				// Optional HTTP health ping (if the child exposes HTTP alongside stdio)
				go func() {
					client := &http.Client{Timeout: 2 * time.Second}
					_, _ = client.Get("http://127.0.0.1:0/health") // placeholder; real child may not have HTTP port
				}()
			}
		}
	}
}

func (m *Manager) readConfig(name string) mcpConfig {
	path := filepath.Join(m.data.Sub("config"), "mcp", name+".json")
	var cfg mcpConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(b, &cfg)
	return cfg
}

func (m *Manager) writeConfig(name string, cfg mcpConfig) error {
	dir := filepath.Join(m.data.Sub("config"), "mcp")
	_ = os.MkdirAll(dir, 0755)
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(filepath.Join(dir, name+".json"), b, 0644)
}
