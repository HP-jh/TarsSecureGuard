// aggregator.go: fetch and aggregate packages from all enabled sources.
package community

import (
	"sync"
	"time"
)

// Aggregator collects packages from sources.
type Aggregator struct {
	registry *Registry
}

// NewAggregator creates an aggregator.
func NewAggregator(r *Registry) *Aggregator {
	return &Aggregator{registry: r}
}

// RefreshAll fetches packages from all enabled sources and returns the aggregate.
func (a *Aggregator) RefreshAll() ([]MCPPackage, error) {
	sources := a.registry.List()
	var mu sync.Mutex
	var all []MCPPackage
	var wg sync.WaitGroup

	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		wg.Add(1)
		go func(s *MCPSource) {
			defer wg.Done()
			pkgs, err := a.fetchFrom(s)
			if err != nil {
				return
			}
			// Tag each package with its source.
			for i := range pkgs {
				pkgs[i].SourceID = s.ID
			}
			_ = a.registry.SetPackageCount(s.ID, len(pkgs), time.Now())
			mu.Lock()
			all = append(all, pkgs...)
			mu.Unlock()
		}(src)
	}
	wg.Wait()
	return all, nil
}

// RefreshOne fetches from a single source.
func (a *Aggregator) RefreshOne(sourceID string) ([]MCPPackage, error) {
	src, ok := a.registry.Get(sourceID)
	if !ok {
		return nil, nil
	}
	if !src.Enabled {
		return nil, nil
	}
	pkgs, err := a.fetchFrom(src)
	if err != nil {
		return nil, err
	}
	for i := range pkgs {
		pkgs[i].SourceID = src.ID
	}
	_ = a.registry.SetPackageCount(src.ID, len(pkgs), time.Now())
	return pkgs, nil
}

func (a *Aggregator) fetchFrom(s *MCPSource) ([]MCPPackage, error) {
	switch s.Type {
	case "github":
		return NewGitHubFetcher().Fetch(s.URL)
	case "http", "registry":
		return NewHTTPFetcher().Fetch(s.URL)
	case "local":
		return NewLocalFetcher().Fetch(s.URL)
	default:
		return nil, nil
	}
}
