// github.go: GitHub Release API client.
package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const githubAPI = "https://api.github.com"

// Release represents a GitHub release.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Prerelease  bool      `json:"prerelease"`
	CreatedAt   time.Time `json:"created_at"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
	HTMLURL     string    `json:"html_url"`
}

// Asset represents a release asset.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int    `json:"size"`
}

// GitHubClient fetches release info from GitHub API.
type GitHubClient struct {
	Owner  string
	Repo   string
	Client *http.Client
}

// NewGitHubClient creates a client for the given owner/repo.
func NewGitHubClient(owner, repo string) *GitHubClient {
	return &GitHubClient{
		Owner:  owner,
		Repo:   repo,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Latest fetches the latest release.
func (c *GitHubClient) Latest() (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPI, c.Owner, c.Repo)
	return c.fetchRelease(url)
}

// ListReleases fetches the last N releases.
func (c *GitHubClient) ListReleases(perPage int) ([]Release, error) {
	if perPage <= 0 {
		perPage = 10
	}
	url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=%d", githubAPI, c.Owner, c.Repo, perPage)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github list releases %d", resp.StatusCode)
	}
	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}
	return releases, nil
}

func (c *GitHubClient) fetchRelease(url string) (*Release, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// FindAsset selects the platform-specific asset from a release.
func FindAsset(rel *Release, goos, goarch string) (*Asset, *Asset) {
	var binaryName, sumsName string
	switch goos {
	case "windows":
		binaryName = fmt.Sprintf("tsg-%s-%s-%s.exe", rel.TagName, goos, goarch)
	default:
		binaryName = fmt.Sprintf("tsg-%s-%s-%s", rel.TagName, goos, goarch)
	}
	sumsName = "SHA256SUMS-" + rel.TagName + ".txt"

	var binary, sums *Asset
	for i := range rel.Assets {
		a := &rel.Assets[i]
		if a.Name == binaryName {
			binary = a
		}
		if a.Name == sumsName {
			sums = a
		}
	}
	return binary, sums
}
