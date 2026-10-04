//go:build windows

package main

// v3.0.1 Tier 1 Windows 平台执行器（[TIER1_PROC_TIMEOUT] 进程树清理）：
// 子进程绑定 Job Object（JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE），超时时
// TerminateJobObject 清理整棵进程树；宿主意外退出时 Job 句柄关闭同样兜底清场。
// Job Object 创建/绑定失败（如父进程已在不允许嵌套的 Job 中）时降级为
// 单进程 Kill，功能不缺失、只弱化孙进程清理。

import (
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW      = modkernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObj  = modkernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObj = modkernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject    = modkernel32.NewProc("TerminateJobObject")
	procCloseHandle           = modkernel32.NewProc("CloseHandle")
	procOpenProcess           = modkernel32.NewProc("OpenProcess")
)

const (
	jobObjectExtendedLimitInfoClass = 9
	jobObjectLimitKillOnJobClose    = 0x00002000
	processSetQuota                 = 0x0100
	processTerminate                = 0x0001
)

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount,
	ReadTransferCount, WriteTransferCount, OtherTransferCount uint64
}

type jobObjectBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInfo
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// tier1ExecCmd 启动命令并以 deadline 看护：超时清理整棵进程树。
// 返回 timedOut 表示是否因超时被强制清理。
func tier1ExecCmd(cmd *exec.Cmd, timeout time.Duration) (timedOut bool, err error) {
	applyHiddenWindow(cmd)

	var job syscall.Handle
	if h, _, _ := procCreateJobObjectW.Call(0, 0); h != 0 {
		job = syscall.Handle(h)
		info := jobObjectExtendedLimitInfo{}
		info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
		procSetInformationJobObj.Call(
			uintptr(job), jobObjectExtendedLimitInfoClass,
			uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	}

	if err = cmd.Start(); err != nil {
		if job != 0 {
			procCloseHandle.Call(uintptr(job))
		}
		return false, err
	}

	if job != 0 {
		// os.Process 无公开句柄：按 pid 用 PROCESS_SET_QUOTA|PROCESS_TERMINATE 重开
		hProc, _, _ := procOpenProcess.Call(
			processSetQuota|processTerminate, 0, uintptr(cmd.Process.Pid))
		if hProc != 0 {
			if r, _, _ := procAssignProcessToJobObj.Call(uintptr(job), hProc); r == 0 {
				// 绑定失败：Job 无用，降级为单进程 Kill
				procCloseHandle.Call(uintptr(job))
				job = 0
			}
			procCloseHandle.Call(hProc)
		} else {
			procCloseHandle.Call(uintptr(job))
			job = 0
		}
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
		if job != 0 {
			procCloseHandle.Call(uintptr(job))
		}
		return false, err
	case <-time.After(timeout):
		if job != 0 {
			procTerminateJobObject.Call(uintptr(job), 1)
			procCloseHandle.Call(uintptr(job))
		} else {
			_ = cmd.Process.Kill()
		}
		<-done
		return true, nil
	}
}
