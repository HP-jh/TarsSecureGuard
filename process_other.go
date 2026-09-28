//go:build !windows

package main

import "os/exec"

// applyHiddenWindow 在非 Windows 平台上为无操作（HideWindow 仅 Windows 支持）
func applyHiddenWindow(cmd *exec.Cmd) {
	// no-op
}
