// local_source.go: fetch packages from a local manifest JSON file.
package community

import (
	"encoding/json"
	"fmt"
	"os"
)

// LocalFetcher reads a local manifest.
type LocalFetcher struct{}

// NewLocalFetcher creates a fetcher.
func NewLocalFetcher() *LocalFetcher {
	return &LocalFetcher{}
}

// Fetch reads the file at path.
func (l *LocalFetcher) Fetch(path string) ([]MCPPackage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read local manifest: %w", err)
	}
	var reg RegistryJSON
	if err := json.Unmarshal(b, &reg); err != nil {
		return nil, fmt.Errorf("parse local manifest: %w", err)
	}
	return reg.Packages, nil
}
