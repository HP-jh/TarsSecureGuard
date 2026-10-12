//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// Windows 使用 eventcreate.exe（系统自带）写事件日志。
// 若 eventcreate 不可用（如精简系统），退回到静默跳过。

var eventSourceName = "TarsSecureGuard"

func syslogInitPlatform() {
	// eventcreate 不需要预先注册 source，首次写入即自动创建
	// 这里只做可用性探测
	cmd := exec.Command("eventcreate", "/T", "INFORMATION", "/ID", "1", "/SO", eventSourceName, "/D", "syslog init test")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		// 精简版 Windows 可能没有 eventcreate；静默禁用
		syslogEnabled = false
	}
}

func syslogWritePlatform(level SyslogLevel, msg string) {
	var typ string
	switch level {
	case SyslogWarn:
		typ = "WARNING"
	case SyslogError:
		typ = "ERROR"
	case SyslogAudit:
		typ = "SUCCESSAUDIT"
	default:
		typ = "INFORMATION"
	}
	// eventcreate 限制：/D 最长 2048 字符
	if len(msg) > 2048 {
		msg = msg[:2048]
	}
	// 转义引号
	msg = strings.ReplaceAll(msg, `"`, `'`)
	cmd := exec.Command("eventcreate", "/T", typ, "/ID", "1001", "/SO", eventSourceName, "/D", msg)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run() // 静默忽略失败
}

func syslogClosePlatform() {
	// Windows Event Log 无需显式关闭句柄
}
