// github_source.go: fetch packages from a GitHub repository releases.
package community

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GitHubFetcher parses GitHub releases API.
type GitHubFetcher struct {
	client *http.Client
}

// NewGitHubFetcher creates a fetcher.
func NewGitHubFetcher() *GitHubFetcher {
	return &GitHubFetcher{client: &http.Client{Timeout: 15 * time.Second}}
}

// Fetch returns packages from a GitHub repo like "owner/repo".
func (g *GitHubFetcher) Fetch(repo string) ([]MCPPackage, error) {
	repo = strings.TrimSpace(repo)
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimSuffix(repo, "/")
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github api %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int    `json:"size"`
		} `json:"assets"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}

	var pkgs []MCPPackage
	for _, a := range rel.Assets {
		if a.Size > 100*1024*1024 {
			continue // skip > 100MB
		}
		name := strings.TrimSuffix(a.Name, ".exe")
		name = strings.TrimSuffix(name, "-linux-amd64")
		name = strings.TrimSuffix(name, "-linux-arm64")
		name = strings.TrimSuffix(name, "-darwin-amd64")
		name = strings.TrimSuffix(name, "-darwin-arm64")
		name = strings.TrimSuffix(name, "-windows-amd64")
		name = strings.TrimSuffix(name, "-windows-arm64")
		name = strings.TrimSuffix(name, "-android-arm64")
		pkgs = append(pkgs, MCPPackage{
			Name:        name,
			Version:     strings.TrimPrefix(rel.TagName, "v"),
			Description: rel.Body,
			DownloadURL: a.BrowserDownloadURL,
		})
	}
	return pkgs, nil
}
