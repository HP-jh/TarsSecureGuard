//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// physicalMemoryGB Linux：/proc/meminfo MemTotal（kB）
func physicalMemoryGB() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseFloat(fields[1], 64); err == nil {
					return kb / 1024 / 1024
				}
			}
		}
	}
	return 0
}
