//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// applyHiddenWindow 在 Windows 上为子进程设置 HideWindow，避免弹出控制台窗口
func applyHiddenWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}
