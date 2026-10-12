package main

// ===================== v4.7.0 系统日志（跨平台）=====================
//
// 目标：加深与系统的交互，关键事件写入系统级日志。
// 策略：平台抽象接口 + 各平台具体实现；失败静默跳过，不影响主流程。

import (
	"fmt"
	"sync"
)

// SyslogLevel 日志级别
type SyslogLevel int

const (
	SyslogInfo SyslogLevel = iota
	SyslogWarn
	SyslogError
	SyslogAudit
)

var (
	syslogMu     sync.Mutex
	syslogEnabled = true
)

// syslogInit 初始化系统日志（各平台实现）
func syslogInit() {
	syslogMu.Lock()
	defer syslogMu.Unlock()
	syslogInitPlatform()
}

// syslogWrite 写一条系统日志（各平台实现）
func syslogWrite(level SyslogLevel, msg string) {
	if !syslogEnabled {
		return
	}
	syslogMu.Lock()
	defer syslogMu.Unlock()
	syslogWritePlatform(level, msg)
}

// syslogClose 关闭系统日志句柄（各平台实现）
func syslogClose() {
	syslogMu.Lock()
	defer syslogMu.Unlock()
	syslogClosePlatform()
}

// syslogAuto 在关键事件点自动写系统日志 + 文件日志 + 审计日志
func syslogAuto(level SyslogLevel, event, detail string) {
	line := fmt.Sprintf("[%s] %s", event, detail)
	// 1) 系统日志
	syslogWrite(level, line)
	// 2) 本地文件日志（已有）
	prefix := "tars"
	if level == SyslogAudit {
		prefix = "audit"
	}
	fileLog(prefix, line)
	// 3) 内存日志（已有）
	logMsg(line)
}

// syslogWrapStartup 启动时统一写系统日志
func syslogWrapStartup() {
	syslogAuto(SyslogInfo, "STARTUP", fmt.Sprintf("TarsSecureGuard v%s starting", version))
}

// syslogWrapShutdown 关闭时统一写系统日志
func syslogWrapShutdown(reason string) {
	syslogAuto(SyslogInfo, "SHUTDOWN", fmt.Sprintf("TarsSecureGuard shutting down: %s", reason))
}

// syslogWrapWAF WAF 拦截时写系统日志
func syslogWrapWAF(ip, reason string) {
	syslogAuto(SyslogWarn, "WAF_BLOCK", fmt.Sprintf("IP=%s reason=%s", ip, reason))
}

// syslogWrapAudit 审计事件写系统日志
func syslogWrapAudit(event, actor, detail string) {
	syslogAuto(SyslogAudit, event, fmt.Sprintf("actor=%s %s", actor, detail))
}
