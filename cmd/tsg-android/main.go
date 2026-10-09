// tsg-android is the TSG gateway service for Android.
// It runs as a background process and exposes an HTTP control API on localhost.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"tarssecureguard-v41/crownext/agentmesh"
	"tarssecureguard-v41/crownext/mcpclient"
	"tarssecureguard-v41/crownext/skylink"
	"tarssecureguard-v41/crownext/threatmodel"
)

// Config holds the Android service configuration.
type Config struct {
	ListenAddr     string            `json:"listen_addr"`
	GatewayEnabled bool              `json:"gateway_enabled"`
	BootAutoStart  bool              `json:"boot_auto_start"`
	MaxLogSizeMB   int               `json:"max_log_size_mb"`
	Providers      map[string]string `json:"providers,omitempty"`
}

func defaultConfig(dataDir string) *Config {
	return &Config{
		ListenAddr:     "127.0.0.1:18080",
		GatewayEnabled: true,
		BootAutoStart:  false,
		MaxLogSizeMB:   10,
		Providers:      map[string]string{},
	}
}

func configPath(dataDir string) string {
	if p := os.Getenv("TSG_CONFIG_PATH"); p != "" {
		return p
	}
	return filepath.Join(dataDir, "config.json")
}

func logDir(dataDir string) string {
	if p := os.Getenv("TSG_LOG_DIR"); p != "" {
		return p
	}
	return filepath.Join(dataDir, "logs")
}

func loadConfig(dataDir string) (*Config, error) {
	path := configPath(dataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := defaultConfig(dataDir)
			_ = saveConfig(dataDir, cfg)
			return cfg, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveConfig(dataDir string, cfg *Config) error {
	path := configPath(dataDir)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

type Service struct {
	dataDir   string
	config    *Config
	server    *http.Server
	gateway   *Gateway
	startTime time.Time
}

type Gateway struct {
	running bool
	mesh    *agentmesh.Registry
	mcp     *mcpclient.Registry
	sky     *skylink.Discovery
	auth    *threatmodel.DeviceAuthManager
	isol    *threatmodel.Isolator
}

func newGateway() *Gateway {
	return &Gateway{
		mesh: agentmesh.NewRegistry(),
		mcp:  mcpclient.NewRegistry(),
		sky:  skylink.NewDiscovery(),
		isol: threatmodel.NewIsolator(time.Hour, 5),
	}
}

func (g *Gateway) Start() error {
	g.running = true
	return nil
}

func (g *Gateway) Stop() error {
	g.running = false
	return nil
}

func (g *Gateway) Status() map[string]interface{} {
	return map[string]interface{}{
		"running":        g.running,
		"agents":         g.mesh.Count(),
		"devices":        g.sky.Count(),
		"trustedDevices": g.sky.CountTrusted(),
		"quarantined":    len(g.isol.List()),
	}
}

func NewService(dataDir string) (*Service, error) {
	cfg, err := loadConfig(dataDir)
	if err != nil {
		return nil, err
	}
	return &Service{
		dataDir: dataDir,
		config:  cfg,
		gateway: newGateway(),
	}, nil
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"running":      s.gateway != nil && s.gateway.running,
		"uptime":       time.Since(s.startTime).Seconds(),
		"gateway":      s.gateway.Status(),
		"listenAddr":   s.config.ListenAddr,
		"autoStart":    s.config.BootAutoStart,
		"goVersion":    runtime.Version(),
		"goOS":         runtime.GOOS,
		"goArch":       runtime.GOARCH,
		"dataDir":      s.dataDir,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Service) handleStart(w http.ResponseWriter, r *http.Request) {
	if s.gateway.running {
		http.Error(w, `{"error":"already running"}`, http.StatusConflict)
		return
	}
	if err := s.gateway.Start(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	s.startTime = time.Now()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Service) handleStop(w http.ResponseWriter, r *http.Request) {
	if !s.gateway.running {
		http.Error(w, `{"error":"not running"}`, http.StatusConflict)
		return
	}
	if err := s.gateway.Stop(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.config)
}

func (s *Service) handlePostConfig(w http.ResponseWriter, r *http.Request) {
	var newCfg Config
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	s.config = &newCfg
	if err := saveConfig(s.dataDir, s.config); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func (s *Service) handleLogs(w http.ResponseWriter, r *http.Request) {
	ldir := logDir(s.dataDir)
	entries, err := os.ReadDir(ldir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}
	var logs []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		logs = append(logs, map[string]interface{}{
			"name":    e.Name(),
			"size":    info.Size(),
			"modTime": info.ModTime().Format(time.RFC3339),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

func (s *Service) handleLogDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, `{"error":"missing name"}`, http.StatusBadRequest)
		return
	}
	path := filepath.Join(logDir(s.dataDir), filepath.Clean(name))
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", name))
	w.Write(data)
}

func (s *Service) handleAssistantHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Service) setupRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/start", s.handleStart)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			s.handlePostConfig(w, r)
		} else {
			s.handleGetConfig(w, r)
		}
	})
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/logs/download", s.handleLogDownload)
	mux.HandleFunc("/api/assistant/health", s.handleAssistantHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"service": "tsg-android", "version": "4.4.0"})
	})
	return mux
}

func (s *Service) Run(ctx context.Context) error {
	// Ensure directories exist
	_ = os.MkdirAll(s.dataDir, 0755)
	_ = os.MkdirAll(logDir(s.dataDir), 0755)

	// Setup HTTP server
	s.server = &http.Server{Addr: s.config.ListenAddr, Handler: s.setupRoutes()}

	// Auto-start gateway if configured
	if s.config.GatewayEnabled {
		_ = s.gateway.Start()
		s.startTime = time.Now()
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	log.Printf("TSG Android service listening on %s", s.config.ListenAddr)
	return s.server.ListenAndServe()
}

func main() {
	dataDir := "/data/data/com.tarssecureguard.android/files"
	if d := os.Getenv("TSG_DATA_DIR"); d != "" {
		dataDir = d
	}

	svc, err := NewService(dataDir)
	if err != nil {
		log.Fatalf("Failed to create service: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if err := svc.Run(ctx); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Service error: %v", err)
	}
}
