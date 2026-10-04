//go:build !windows

package main

// sidecarHub 平台层（Linux / macOS）：
//   - sidecarPrepareOS：manifest.User 指定时按低权限用户拉起（root 网关下生效；
//     非 root 环境保持当前权限并审计说明——绝不提权）
//   - sidecarAttachOS：进程树隔离（Setpgid）+ 超时/强杀用 kill -pgid 清整组

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"
)

// sidecarPrepareOS 在 cmd.Start 前设置进程属性：降权 + 进程组隔离。
func sidecarPrepareOS(cmd *exec.Cmd, m *sidecarModule) error {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if m.User != "" {
		u, err := user.Lookup(m.User)
		if err != nil {
			return fmt.Errorf("manifest user %q 不存在: %v", m.User, err)
		}
		uid, err1 := strconv.Atoi(u.Uid)
		gid, err2 := strconv.Atoi(u.Gid)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("manifest user %q uid/gid 非数值", m.User)
		}
		if os.Geteuid() == 0 {
			attr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		} else {
			// 非 root：保持当前权限（无法降到别的用户），审计说明即可，不算失败
			auditLog("SIDECAR_PRIVILEGE_KEEP", "sidecarHub", fmt.Sprintf(
				"模块 %s 要求降权到用户 %s，但网关非 root（euid=%d），按当前权限运行",
				m.ID, m.User, os.Geteuid()))
		}
	}
	cmd.SysProcAttr = attr
	return nil
}

// sidecarAttachOS 在 cmd.Start 成功后返回进程组强杀函数（幂等）。
func sidecarAttachOS(cmd *exec.Cmd, m *sidecarModule) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			if cmd.Process == nil {
				return
			}
			// 杀整组（supervisor 自身不在该组：Setpgid 已把子进程放进独立组）
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
		})
	}
}
