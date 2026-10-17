// handlers.go: HTTP API for the Community Marketplace.
package community

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

	"github.com/HP-jh/TarsSecureGuard/pkg/install"
)

// CommunityMarketplace is the HTTP handler bundle.
type CommunityMarketplace struct {
	mu         sync.RWMutex
	registry   *Registry
	aggregator *Aggregator
	install    *install.Manager
	cache      []MCPPackage
	cacheTime  time.Time
	dataRoot   string
}

// NewCommunityMarketplace creates the handler bundle.
func NewCommunityMarketplace(dataRoot, installRoot string) *CommunityMarketplace {
	reg := NewRegistry(dataRoot)
	return &CommunityMarketplace{
		registry:   reg,
		aggregator: NewAggregator(reg),
		install:    install.New(installRoot),
		dataRoot:   dataRoot,
	}
}

// --- sources ---

// HandleSourcesList GET /api/v1/mcp/community/sources
func (cm *CommunityMarketplace) HandleSourcesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	list := cm.registry.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// HandleSourcesCreate POST /api/v1/mcp/community/sources
func (cm *CommunityMarketplace) HandleSourcesCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var s MCPSource
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	if err := cm.registry.Add(&s); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

// HandleSourcesDelete DELETE /api/v1/mcp/community/sources/:id
func (cm *CommunityMarketplace) HandleSourcesDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := filepath.Base(r.URL.Path)
	if err := cm.registry.Remove(id); err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleSourceRefresh POST /api/v1/mcp/community/sources/:id/refresh
func (cm *CommunityMarketplace) HandleSourceRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		http.Error(w, `{"error":"missing id"}`, http.StatusBadRequest)
		return
	}
	id := parts[len(parts)-2]
	pkgs, err := cm.aggregator.RefreshOne(id)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	cm.mu.Lock()
	cm.mergeIntoCache(pkgs)
	cm.cacheTime = time.Now()
	cm.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"refreshed": id, "packages": len(pkgs)})
}

// HandleRefreshAll POST /api/v1/mcp/community/refresh-all
func (cm *CommunityMarketplace) HandleRefreshAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	pkgs, err := cm.aggregator.RefreshAll()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	cm.mu.Lock()
	cm.cache = pkgs
	cm.cacheTime = time.Now()
	cm.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"packages": len(pkgs)})
}

// --- packages ---

// HandlePackagesList GET /api/v1/mcp/community/packages?q=foo&source=bar
func (cm *CommunityMarketplace) HandlePackagesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	cm.mu.RLock()
	pkgs := make([]MCPPackage, len(cm.cache))
	copy(pkgs, cm.cache)
	cm.mu.RUnlock()

	q := strings.ToLower(r.URL.Query().Get("q"))
	srcFilter := r.URL.Query().Get("source")
	var out []MCPPackage
	for _, p := range pkgs {
		if srcFilter != "" && p.SourceID != srcFilter {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(p.Name), q) && !strings.Contains(strings.ToLower(p.Description), q) {
			continue
		}
		out = append(out, p)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// HandlePackageDetail GET /api/v1/mcp/community/packages/:id
func (cm *CommunityMarketplace) HandlePackageDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := filepath.Base(r.URL.Path)
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for _, p := range cm.cache {
		if p.Name == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(p)
			return
		}
	}
	http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
}

// HandlePackageDownload POST /api/v1/mcp/community/packages/:id/download
func (cm *CommunityMarketplace) HandlePackageDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := filepath.Base(r.URL.Path)
	cm.mu.RLock()
	var pkg *MCPPackage
	for i := range cm.cache {
		if cm.cache[i].Name == id {
			pkg = &cm.cache[i]
			break
		}
	}
	cm.mu.RUnlock()
	if pkg == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	src, _ := cm.registry.Get(pkg.SourceID)
	if src != nil && src.TrustLevel == "personal" {
		// Personal packages require explicit opt-in; frontend should confirm first.
		// Here we just warn in the response.
		w.Header().Set("X-Personal-Package", "true")
	}

	// Download.
	tmpPath, err := cm.download(pkg.DownloadURL)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"download failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpPath)

	// Verify SHA256 if provided.
	if pkg.SHA256 != "" {
		v := NewVerifier()
		if err := v.VerifySHA256(tmpPath, pkg.SHA256); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"verify failed: %s"}`, err.Error()), http.StatusBadRequest)
			return
		}
	}

	// Move to install dir.
	name := filepath.Base(pkg.DownloadURL)
	dst := filepath.Join(cm.install.Root, name)
	_ = os.MkdirAll(cm.install.Root, 0755)
	b, _ := os.ReadFile(tmpPath)
	if err := os.WriteFile(dst, b, 0755); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"install failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Audit log.
	_ = cm.audit("download", pkg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "path": dst})
}

// HandlePackageVerify POST /api/v1/mcp/community/packages/:id/verify
func (cm *CommunityMarketplace) HandlePackageVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := filepath.Base(r.URL.Path)
	cm.mu.RLock()
	var pkg *MCPPackage
	for i := range cm.cache {
		if cm.cache[i].Name == id {
			pkg = &cm.cache[i]
			break
		}
	}
	cm.mu.RUnlock()
	if pkg == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	tmpPath, err := cm.download(pkg.DownloadURL)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"download failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpPath)

	v := NewVerifier()
	var result []string
	if pkg.SHA256 != "" {
		if err := v.VerifySHA256(tmpPath, pkg.SHA256); err != nil {
			result = append(result, "sha256: FAIL - "+err.Error())
		} else {
			result = append(result, "sha256: OK")
		}
	} else {
		result = append(result, "sha256: skipped (no digest)")
	}
	if pkg.Sig != "" {
		if err := v.VerifySig(tmpPath, pkg.Sig); err != nil {
			result = append(result, "sig: FAIL - "+err.Error())
		} else {
			result = append(result, "sig: OK")
		}
	} else {
		result = append(result, "sig: skipped (no signature)")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"package": pkg.Name, "results": result})
}

func (cm *CommunityMarketplace) download(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	// Limit to 100MB.
	if resp.ContentLength > 100*1024*1024 {
		return "", fmt.Errorf("package too large (>100MB)")
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("tars-mcp-%d", time.Now().UnixNano()))
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = io.Copy(f, io.LimitReader(resp.Body, 100*1024*1024))
	if err != nil {
		return "", err
	}
	return tmp, nil
}

func (cm *CommunityMarketplace) mergeIntoCache(pkgs []MCPPackage) {
	byName := make(map[string]int)
	for i, p := range cm.cache {
		byName[p.Name] = i
	}
	for _, p := range pkgs {
		if idx, ok := byName[p.Name]; ok {
			cm.cache[idx] = p
		} else {
			cm.cache = append(cm.cache, p)
			byName[p.Name] = len(cm.cache) - 1
		}
	}
}

func (cm *CommunityMarketplace) audit(action string, pkg *MCPPackage) error {
	logDir := filepath.Join(cm.dataRoot, "logs")
	_ = os.MkdirAll(logDir, 0755)
	path := filepath.Join(logDir, "mcp-community.log")
	entry := fmt.Sprintf("%s | action=%s package=%s version=%s source=%s\n",
		time.Now().Format(time.RFC3339), action, pkg.Name, pkg.Version, pkg.SourceID)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
}
