//go:build windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

var (
	modkernel32_sp         = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentProcess = modkernel32_sp.NewProc("GetCurrentProcess")
	procOpenProcessToken  = modkernel32_sp.NewProc("OpenProcessToken")
	procGetTokenInformation = modkernel32_sp.NewProc("GetTokenInformation")
	modadvapi32         = syscall.NewLazyDLL("advapi32.dll")
	procCheckTokenMembership = modadvapi32.NewProc("CheckTokenMembership")
)

const tokenElevationType = 18
const tokenLinkedToken = 19

type tokenElevationTypeAndLinkedToken struct {
	elevationType uint32
	linkedToken   syscall.Handle
}

func detectAdminPrivilegesPlatform() bool {
	// 方法：尝试打开当前进程的 TOKEN_QUERY 令牌，查询 TokenElevationType
	// 如果 elevationType == 2 (TokenElevationTypeFull) 则表示已提升（管理员）
	hProc, _, _ := procGetCurrentProcess.Call()
	var hToken syscall.Handle
	ok, _, _ := procOpenProcessToken.Call(hProc, 0x0008, uintptr(unsafe.Pointer(&hToken))) // TOKEN_QUERY = 0x0008
	if ok == 0 {
		return false
	}
	defer syscall.CloseHandle(hToken)

	var elev tokenElevationTypeAndLinkedToken
	var retLen uint32
	ok, _, _ = procGetTokenInformation.Call(
		uintptr(hToken),
		uintptr(tokenElevationType),
		uintptr(unsafe.Pointer(&elev)),
		uintptr(unsafe.Sizeof(elev)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if ok == 0 {
		// 回退：老系统没有 UAC，尝试 CheckTokenMembership 看是否在 Administrators 组
		var adminSID *syscall.SID
		sidStr, _ := syscall.UTF16PtrFromString("S-1-5-32-544")
		_ = syscall.ConvertStringSidToSid(sidStr, &adminSID)
		if adminSID == nil {
			return false
		}
		defer syscall.LocalFree((syscall.Handle)(unsafe.Pointer(adminSID)))
		var isAdmin bool
		ok2, _, _ := procCheckTokenMembership.Call(0, uintptr(unsafe.Pointer(adminSID)), uintptr(unsafe.Pointer(&isAdmin)))
		return ok2 != 0 && isAdmin
	}
	// elevationType: 1=Default, 2=Full, 3=Limited
	return elev.elevationType == 2
}

func registerShutdownInterceptor() {
	// Windows：同时处理 os.Signal 和 console control events
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range ch {
			if isShutdownRequested() {
				gracefulShutdown("signal " + sig.String() + " after frontend request")
				return
			}
			if shouldBlockSignal() {
				logMsg("[selfprotect] 拦截 Windows 信号 " + sig.String())
				auditLog("SELFPROTECT_SIGNAL_BLOCKED", "system", "signal="+sig.String())
				syslogAuto(SyslogWarn, "SELFPROTECT", "Signal blocked: "+sig.String())
			} else {
				gracefulShutdown("signal " + sig.String())
				return
			}
		}
	}()

	// 注册 console control handler（拦截 CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT）
	// 这是 Windows 特有的：用户点击控制台窗口 X 按钮、注销、关机时会触发
	go registerConsoleCtrlHandler()
}

var (
	modkernel32_setConsoleCtrlHandler = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleCtrlHandler       = modkernel32_setConsoleCtrlHandler.NewProc("SetConsoleCtrlHandler")
)

func registerConsoleCtrlHandler() {
	// 使用 syscall.NewCallback 创建回调
	cb := syscall.NewCallback(func(ctrlType uint32) uintptr {
		switch ctrlType {
		case 0, 2, 5: // CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_SHUTDOWN_EVENT
			if isShutdownRequested() {
				gracefulShutdown(fmt.Sprintf("console ctrl event %d after frontend request", ctrlType))
				return 0
			}
			if shouldBlockSignal() {
				logMsg(fmt.Sprintf("[selfprotect] 拦截控制台事件 %d（防自关保护）", ctrlType))
				auditLog("SELFPROTECT_CONSOLE_BLOCKED", "system", fmt.Sprintf("ctrlType=%d", ctrlType))
				syslogAuto(SyslogWarn, "SELFPROTECT", fmt.Sprintf("Console event blocked: %d", ctrlType))
				return 1 // 返回 1 表示已处理，不关闭进程
			}
		}
		return 0 // 返回 0 表示未处理，交给默认行为
	})
	procSetConsoleCtrlHandler.Call(cb, 1)
}
