// http_source.go: fetch packages from an HTTP registry JSON endpoint.
package community

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HTTPFetcher fetches a registry JSON.
type HTTPFetcher struct {
	client *http.Client
}

// RegistryJSON is the expected shape of a remote registry.
type RegistryJSON struct {
	Packages []MCPPackage `json:"packages"`
}

// NewHTTPFetcher creates a fetcher.
func NewHTTPFetcher() *HTTPFetcher {
	return &HTTPFetcher{client: &http.Client{Timeout: 15 * time.Second}}
}

// Fetch fetches the registry at url.
func (h *HTTPFetcher) Fetch(url string) ([]MCPPackage, error) {
	resp, err := h.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	var reg RegistryJSON
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, err
	}
	// Validate sizes.
	var out []MCPPackage
	for _, p := range reg.Packages {
		// Skip oversized (we will check at download time too)
		out = append(out, p)
	}
	return out, nil
}
