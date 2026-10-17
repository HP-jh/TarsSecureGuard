// Package update provides auto-update capability for TarsSecureGuard.
// v4.14.0: semver parsing and comparison.
package update

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a semantic version.
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Metadata   string
}

// ParseVersion parses a semver string like "v4.14.0" or "4.14.0-alpha.1".
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(s, "v")
	var v Version
	// metadata
	if i := strings.Index(s, "+"); i >= 0 {
		v.Metadata = s[i+1:]
		s = s[:i]
	}
	// prerelease
	if i := strings.Index(s, "-"); i >= 0 {
		v.Prerelease = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return v, fmt.Errorf("invalid semver: %s", s)
	}
	var err error
	v.Major, err = strconv.Atoi(parts[0])
	if err != nil {
		return v, fmt.Errorf("invalid major: %w", err)
	}
	v.Minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return v, fmt.Errorf("invalid minor: %w", err)
	}
	if len(parts) >= 3 {
		v.Patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return v, fmt.Errorf("invalid patch: %w", err)
		}
	}
	return v, nil
}

// String returns the version string with "v" prefix.
func (v Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	if v.Metadata != "" {
		s += "+" + v.Metadata
	}
	return s
}

// GreaterThan returns true if v > other.
func (v Version) GreaterThan(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	if v.Patch != other.Patch {
		return v.Patch > other.Patch
	}
	// A version without prerelease has higher precedence
	if v.Prerelease == "" && other.Prerelease != "" {
		return true
	}
	if v.Prerelease != "" && other.Prerelease == "" {
		return false
	}
	if v.Prerelease != other.Prerelease {
		return v.Prerelease > other.Prerelease
	}
	return false
}

// Equal returns true if v == other.
func (v Version) Equal(other Version) bool {
	return v.Major == other.Major && v.Minor == other.Minor && v.Patch == other.Patch && v.Prerelease == other.Prerelease
}
