//go:build darwin

package main

import (
	"strconv"
	"strings"
)

// physicalMemoryGB macOS：sysctl hw.memsize（字节）
func physicalMemoryGB() float64 {
	if out, err := runCmd("sysctl", "-n", "hw.memsize"); err == nil {
		if b, err := strconv.ParseFloat(strings.TrimSpace(out), 64); err == nil {
			return b / 1024 / 1024 / 1024
		}
	}
	return 0
}
