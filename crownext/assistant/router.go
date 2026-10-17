package assistant

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"
)

// ProviderConfig describes an LLM endpoint.
type ProviderConfig struct {
	Name        string            `json:"name"`
	BaseURL     string            `json:"base_url"`
	APIKey      string            `json:"api_key"`
	Model       string            `json:"model"`
	Weight      float64           `json:"weight"`      // routing weight
	MaxRPM      int               `json:"max_rpm"`     // max requests per minute
	Capabilities []string         `json:"capabilities"` // e.g. "chat", "vision", "tool_use"
	Healthy     bool              `json:"-"`
	LastLatency time.Duration     `json:"-"`
	LastCheck   time.Time         `json:"-"`
	ErrCount    int               `json:"-"`
}

// ScoreWeights configures the routing scorer.
type ScoreWeights struct {
	LatencyWeight     float64 `json:"latency_weight"`
	QuotaWeight       float64 `json:"quota_weight"`
	CapabilityWeight  float64 `json:"capability_weight"`
	WeightBias        float64 `json:"weight_bias"`
}

// DefaultScoreWeights returns balanced weights.
func DefaultScoreWeights() ScoreWeights {
	return ScoreWeights{
		LatencyWeight:    0.35,
		QuotaWeight:      0.25,
		CapabilityWeight: 0.25,
		WeightBias:       0.15,
	}
}

// ModelRouter selects the best provider for each request.
type ModelRouter struct {
	mu        sync.RWMutex
	providers map[string]*ProviderConfig
	weights   ScoreWeights
	healthTTL time.Duration
}

// NewModelRouter creates a router with default weights.
func NewModelRouter(healthTTL time.Duration) *ModelRouter {
	return &ModelRouter{
		providers: make(map[string]*ProviderConfig),
		weights:   DefaultScoreWeights(),
		healthTTL: healthTTL,
	}
}

// Register adds a provider.
func (r *ModelRouter) Register(p *ProviderConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name] = p
}

// Unregister removes a provider.
func (r *ModelRouter) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, name)
}

// List returns all registered providers.
func (r *ModelRouter) List() []*ProviderConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ProviderConfig, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	return out
}

// HealthCheck probes all providers and updates health status.
func (r *ModelRouter) HealthCheck(ctx context.Context) {
	r.mu.RLock()
	providers := make([]*ProviderConfig, 0, len(r.providers))
	for _, p := range r.providers {
		providers = append(providers, p)
	}
	r.mu.RUnlock()

	var wg sync.WaitGroup
	for _, p := range providers {
		wg.Add(1)
		go func(pr *ProviderConfig) {
			defer wg.Done()
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, "GET", pr.BaseURL, nil)
			req.Header.Set("Authorization", "Bearer "+pr.APIKey)
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			latency := time.Since(start)
			if err != nil {
				pr.Healthy = false
				pr.ErrCount++
				return
			}
			resp.Body.Close()
			pr.Healthy = resp.StatusCode < 500
			pr.LastLatency = latency
			pr.LastCheck = time.Now()
			if pr.Healthy {
				pr.ErrCount = 0
			}
		}(p)
	}
	wg.Wait()
}

// Score computes a fitness score for a provider (higher = better).
func (r *ModelRouter) Score(p *ProviderConfig, requiredCaps []string) float64 {
	if !p.Healthy {
		return -1
	}
	w := r.weights

	// Latency score: lower latency = higher score, exponential decay
	latencyScore := math.Exp(-float64(p.LastLatency.Milliseconds()) / 1000.0)

	// Quota score: based on remaining RPM capacity (simplified)
	quotaScore := 1.0
	if p.MaxRPM > 0 {
		quotaScore = 1.0 // simplified; real impl would track actual usage
	}

	// Capability score: fraction of required capabilities matched
	capScore := 1.0
	if len(requiredCaps) > 0 {
		matched := 0
		capSet := make(map[string]bool)
		for _, c := range p.Capabilities {
			capSet[c] = true
		}
		for _, rc := range requiredCaps {
			if capSet[rc] {
				matched++
			}
		}
		capScore = float64(matched) / float64(len(requiredCaps))
	}

	return w.LatencyWeight*latencyScore +
		w.QuotaWeight*quotaScore +
		w.CapabilityWeight*capScore +
		w.WeightBias*p.Weight
}

// SelectAuto picks the best provider automatically.
func (r *ModelRouter) SelectAuto(requiredCaps []string) (*ProviderConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var best *ProviderConfig
	bestScore := -1.0
	for _, p := range r.providers {
		// Skip stale health data
		if time.Since(p.LastCheck) > r.healthTTL*2 {
			continue
		}
		s := r.Score(p, requiredCaps)
		if s > bestScore {
			bestScore = s
			best = p
		}
	}
	if best == nil {
		return nil, fmt.Errorf("assistant: no healthy provider available")
	}
	return best, nil
}

// SelectManual returns a provider by name.
func (r *ModelRouter) SelectManual(name string) (*ProviderConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("assistant: provider %s not found", name)
	}
	return p, nil
}

// SelectionMode is auto or manual.
type SelectionMode string

const (
	ModeAuto   SelectionMode = "auto"
	ModeManual SelectionMode = "manual"
)

// SelectionRecord logs each model selection decision.
type SelectionRecord struct {
	Timestamp   time.Time       `json:"timestamp"`
	Mode        SelectionMode   `json:"mode"`
	Provider    string          `json:"provider"`
	Model       string          `json:"model"`
	Score       float64         `json:"score,omitempty"`
	Reason      string          `json:"reason"`
	SessionID   string          `json:"session_id"`
	RequiredCaps []string       `json:"required_caps,omitempty"`
}

// SelectionAudit logs selection decisions (capped).
type SelectionAudit struct {
	mu      sync.RWMutex
	records []SelectionRecord
	cap     int
}

// NewSelectionAudit creates an audit log with capacity limit.
func NewSelectionAudit(cap int) *SelectionAudit {
	return &SelectionAudit{records: make([]SelectionRecord, 0, cap), cap: cap}
}

// Record appends a selection record.
func (a *SelectionAudit) Record(r SelectionRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, r)
	if len(a.records) > a.cap {
		a.records = a.records[len(a.records)-a.cap:]
	}
}

// List returns recent records (newest first).
func (a *SelectionAudit) List(limit int) []SelectionRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if limit <= 0 || limit > len(a.records) {
		limit = len(a.records)
	}
	out := make([]SelectionRecord, limit)
	for i := 0; i < limit; i++ {
		out[i] = a.records[len(a.records)-1-i]
	}
	return out
}

// ComputeAuditHash returns a SHA-256 hash of a selection record for chain integrity.
func ComputeAuditHash(prevHash string, r SelectionRecord) string {
	data, _ := json.Marshal(r)
	h := sha256.Sum256([]byte(prevHash + string(data)))
	return fmt.Sprintf("%x", h[:])
}
