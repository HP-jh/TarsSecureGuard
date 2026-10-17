// Package update channel detection (stable vs beta).
// v4.15.1
package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Channel type.
type Channel string

const (
	ChannelStable Channel = "stable"
	ChannelBeta   Channel = "beta"
)

// ChannelConfig persisted in data/config/update.json.
type ChannelConfig struct {
	Channel    string `json:"channel"`
	LastCheck  string `json:"last_check"`
	AutoPrompt bool   `json:"auto_prompt"`
}

// LoadChannelConfig reads data/config/update.json.
func LoadChannelConfig(dataDir string) (ChannelConfig, error) {
	var c ChannelConfig
	path := filepath.Join(dataDir, "config", "update.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ChannelConfig{Channel: "stable", AutoPrompt: true}, nil
		}
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Channel == "" {
		c.Channel = "stable"
	}
	return c, nil
}

// SaveChannelConfig writes data/config/update.json.
func SaveChannelConfig(dataDir string, c ChannelConfig) error {
	path := filepath.Join(dataDir, "config", "update.json")
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

// IsMajorBump returns true if the release is a major version change.
func IsMajorBump(current, release string) bool {
	cv, err := ParseVersion(current)
	if err != nil {
		return false
	}
	rv, err := ParseVersion(release)
	if err != nil {
		return false
	}
	return rv.Major != cv.Major
}

// IsStableRelease returns true if the release should be offered on the stable channel.
// Criteria: major bump OR the release has no prerelease suffix AND minor bump with patch==0.
func IsStableRelease(current, release string) bool {
	cv, err := ParseVersion(current)
	if err != nil {
		return false
	}
	rv, err := ParseVersion(release)
	if err != nil {
		return false
	}
	// Major bump always stable
	if rv.Major != cv.Major {
		return true
	}
	// Has prerelease -> beta
	if rv.Prerelease != "" {
		return false
	}
	// Minor bump with patch==0 is stable (e.g. 4.15.0, 4.16.0)
	if rv.Minor != cv.Minor && rv.Patch == 0 {
		return true
	}
	// Patch bumps are beta unless explicitly tagged stable
	return false
}

// FilterByChannel filters releases for the given channel.
func FilterByChannel(current string, releases []Release, channel Channel) []Release {
	var out []Release
	for _, r := range releases {
		if channel == ChannelStable {
			if IsStableRelease(current, r.TagName) {
				out = append(out, r)
			}
		} else {
			// Beta: all releases except those already older than current
			cv, _ := ParseVersion(current)
			rv, _ := ParseVersion(r.TagName)
			if rv.GreaterThan(cv) || (rv.Equal(cv) && strings.Contains(r.TagName, "beta")) {
				out = append(out, r)
			}
		}
	}
	return out
}

// ParseChannel parses a string channel.
func ParseChannel(s string) Channel {
	s = strings.ToLower(s)
	if s == "beta" {
		return ChannelBeta
	}
	return ChannelStable
}
