//go:build windows

package main

// sidecarHub 平台层（Windows）：
//   - sidecarPrepareOS：隐藏窗口；manifest.User 在 Windows 上无对应降权机制
//     （无 setuid），审计说明后按当前权限运行——绝不提权
//   - sidecarAttachOS：绑定 Job Object（KILL_ON_JOB_CLOSE），强杀用
//     TerminateJobObject 清整棵进程树；宿主崩溃时 Job 句柄关闭同样兜底清场

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

// sidecarPrepareOS 在 cmd.Start 前设置进程属性。
func sidecarPrepareOS(cmd *exec.Cmd, m *sidecarModule) error {
	applyHiddenWindow(cmd)
	if m.User != "" {
		auditLog("SIDECAR_PRIVILEGE_KEEP", "sidecarHub", fmt.Sprintf(
			"模块 %s manifest 指定 user=%q：Windows 无 setuid 机制，按当前用户运行（传输层 token 鉴权不受影响）",
			m.ID, m.User))
	}
	return nil
}

// sidecarAttachOS 在 cmd.Start 成功后返回进程树强杀函数（幂等）。
// Job 创建/绑定失败时降级为单进程 Kill（tier1_windows.go 同款策略）。
func sidecarAttachOS(cmd *exec.Cmd, m *sidecarModule) func() {
	var once sync.Once
	job := syscall.Handle(0)
	if h, _, _ := procCreateJobObjectW.Call(0, 0); h != 0 {
		job = syscall.Handle(h)
		info := jobObjectExtendedLimitInfo{}
		info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
		procSetInformationJobObj.Call(
			uintptr(job), jobObjectExtendedLimitInfoClass,
			uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
		if cmd.Process != nil {
			hProc, _, _ := procOpenProcess.Call(
				processSetQuota|processTerminate, 0, uintptr(cmd.Process.Pid))
			if hProc != 0 {
				if r, _, _ := procAssignProcessToJobObj.Call(uintptr(job), hProc); r == 0 {
					procCloseHandle.Call(uintptr(job))
					job = 0
				}
				procCloseHandle.Call(hProc)
			} else {
				procCloseHandle.Call(uintptr(job))
				job = 0
			}
		} else {
			procCloseHandle.Call(uintptr(job))
			job = 0
		}
	}
	return func() {
		once.Do(func() {
			if job != 0 {
				procTerminateJobObject.Call(uintptr(job), 1)
				procCloseHandle.Call(uintptr(job))
			} else if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		})
	}
}
