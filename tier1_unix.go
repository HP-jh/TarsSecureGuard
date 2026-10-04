//go:build !windows

package main

// v3.0.1 Tier 1 Unix 平台执行器（[TIER1_PROC_TIMEOUT] 进程树清理）：
// 子进程自建进程组（Setpgid），超时后 kill(-pgid, SIGKILL) 清理整棵进程树，
// 防止被调用命令再 spawn 的孙进程残留。

import (
	"os/exec"
	"syscall"
	"time"
)

// tier1ExecCmd 启动命令并以 deadline 看护：到期 kill 整个进程组。
// 返回 timedOut 表示是否因超时被强制清理。
func tier1ExecCmd(cmd *exec.Cmd, timeout time.Duration) (timedOut bool, err error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = cmd.Start(); err != nil {
		return false, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
		return false, err
	case <-time.After(timeout):
		// 进程组负 pid = 组内全部进程；失败则对主进程直接兜底
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return true, nil
	}
}
