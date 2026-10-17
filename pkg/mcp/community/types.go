// Package community provides the Community Marketplace for arbitrary MCP sources.
// v4.17.0
package community

import "time"

// MCPSource describes a remote or local source of MCP packages.
type MCPSource struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`         // "github" | "http" | "local" | "registry"
	URL          string    `json:"url"`
	TrustLevel   string    `json:"trustLevel"`   // "official" | "community" | "personal"
	Enabled      bool      `json:"enabled"`
	LastSync     time.Time `json:"lastSync"`
	PackageCount int       `json:"packageCount"`
}

// MCPPackage is a single package discovered from a source.
type MCPPackage struct {
	SourceID    string      `json:"sourceId"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Description string      `json:"description"`
	Author      string      `json:"author"`
	Manifest    MCPManifest `json:"manifest"`
	DownloadURL string      `json:"downloadUrl"`
	SHA256      string      `json:"sha256"`
	Sig         string      `json:"sig,omitempty"` // detached signature (base64)
	Stars       int         `json:"stars"`
}

// MCPManifest describes tools, permissions and resource usage.
type MCPManifest struct {
	Tools      []string          `json:"tools"`
	Permissions []string         `json:"permissions"`
	Resources  map[string]string `json:"resources"` // e.g. {"memory":"512MB"}
}

// TrustBadge returns a short badge for UI.
func TrustBadge(tl string) string {
	switch tl {
	case "official":
		return "Official"
	case "community":
		return "Community"
	case "personal":
		return "Personal"
	default:
		return "Unknown"
	}
}

// TrustEmoji returns an emoji badge for UI.
func TrustEmoji(tl string) string {
	switch tl {
	case "official":
		return "Official"
	case "community":
		return "Community"
	case "personal":
		return "Personal"
	default:
		return "Unknown"
	}
}
