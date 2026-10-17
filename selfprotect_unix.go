//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func detectAdminPrivilegesPlatform() bool {
	return os.Getuid() == 0
}

func registerShutdownInterceptor() {
	// Unix：拦截 SIGINT / SIGTERM
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range ch {
			if isShutdownRequested() {
				// 已收到合法关闭请求，放行
				gracefulShutdown("signal " + sig.String() + " after frontend shutdown request")
				return
			}
			if shouldBlockSignal() {
				logMsg("[selfprotect] 拦截信号 " + sig.String() + "（防自关保护）")
				auditLog("SELFPROTECT_SIGNAL_BLOCKED", "system", "signal="+sig.String())
				syslogAuto(SyslogWarn, "SELFPROTECT", "Signal blocked: "+sig.String())
				// 继续循环，不退出
			} else {
				// 管理员运行，放行
				gracefulShutdown("signal " + sig.String())
				return
			}
		}
	}()
}
