//go:build !windows

package main

import (
	"syscall"
)

// getDiskUsage 非 Windows 平台实现（Linux / macOS / FreeBSD）
func getDiskUsage(path string) (diskUsage, error) {
	var du diskUsage
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return du, err
	}
	// Blocks / Bavail 在不同 Unix 上类型不同，统一转 uint64
	du.Total = uint64(stat.Blocks) * uint64(stat.Bsize)
	du.Free = uint64(stat.Bavail) * uint64(stat.Bsize)
	return du, nil
}
