// sources.go: in-memory + persisted registry of MCP sources.
package community

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Registry manages MCP sources.
type Registry struct {
	mu      sync.RWMutex
	sources map[string]*MCPSource
	path    string
}

// NewRegistry creates a registry persisted at dataRoot.
func NewRegistry(dataRoot string) *Registry {
	path := filepath.Join(dataRoot, "config", "mcp-community-sources.json")
	r := &Registry{
		sources: make(map[string]*MCPSource),
		path:    path,
	}
	_ = r.load()
	// Ensure default official sources if empty.
	if len(r.sources) == 0 {
		r.initDefaults()
		_ = r.save()
	}
	return r
}

func (r *Registry) initDefaults() {
	r.sources["official-github"] = &MCPSource{
		ID: "official-github", Name: "TSG Official GitHub",
		Type: "github", URL: "HP-jh/TarsSecureGuard",
		TrustLevel: "official", Enabled: true, LastSync: time.Time{},
	}
	r.sources["official-registry"] = &MCPSource{
		ID: "official-registry", Name: "TSG Official Registry",
		Type: "http", URL: "https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/docs/mcp-registry.json",
		TrustLevel: "official", Enabled: true, LastSync: time.Time{},
	}
}

// load reads persisted sources.
func (r *Registry) load() error {
	b, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []*MCPSource
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, s := range list {
		r.sources[s.ID] = s
	}
	return nil
}

// save persists sources.
func (r *Registry) save() error {
	_ = os.MkdirAll(filepath.Dir(r.path), 0755)
	r.mu.RLock()
	list := make([]*MCPSource, 0, len(r.sources))
	for _, s := range r.sources {
		list = append(list, s)
	}
	r.mu.RUnlock()
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, b, 0644)
}

// List returns all sources.
func (r *Registry) List() []*MCPSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*MCPSource, 0, len(r.sources))
	for _, s := range r.sources {
		out = append(out, s)
	}
	return out
}

// Get returns one source by ID.
func (r *Registry) Get(id string) (*MCPSource, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sources[id]
	if !ok {
		return nil, false
	}
	cp := *s
	return &cp, true
}

// Add adds a new source.
func (r *Registry) Add(s *MCPSource) error {
	if s.ID == "" {
		return fmt.Errorf("source id required")
	}
	if s.Type == "" {
		return fmt.Errorf("source type required")
	}
	if s.URL == "" {
		return fmt.Errorf("source url required")
	}
	if s.TrustLevel == "" {
		s.TrustLevel = "community"
	}
	s.LastSync = time.Time{}
	s.PackageCount = 0
	r.mu.Lock()
	r.sources[s.ID] = s
	r.mu.Unlock()
	return r.save()
}

// Remove deletes a source.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	delete(r.sources, id)
	r.mu.Unlock()
	return r.save()
}

// UpdateEnabled toggles a source.
func (r *Registry) UpdateEnabled(id string, enabled bool) error {
	r.mu.Lock()
	s, ok := r.sources[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("source not found")
	}
	s.Enabled = enabled
	r.mu.Unlock()
	return r.save()
}

// SetPackageCount updates the cached package count after sync.
func (r *Registry) SetPackageCount(id string, n int, t time.Time) error {
	r.mu.Lock()
	s, ok := r.sources[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("source not found")
	}
	s.PackageCount = n
	s.LastSync = t
	r.mu.Unlock()
	return r.save()
}
