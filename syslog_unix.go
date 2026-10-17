//go:build !windows

package main

import (
	"log/syslog"
)

var syslogWriter *syslog.Writer

func syslogInitPlatform() {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "TarsSecureGuard")
	if err != nil {
		syslogEnabled = false
		return
	}
	syslogWriter = w
}

func syslogWritePlatform(level SyslogLevel, msg string) {
	if syslogWriter == nil {
		return
	}
	switch level {
	case SyslogWarn:
		_ = syslogWriter.Warning(msg)
	case SyslogError:
		_ = syslogWriter.Err(msg)
	case SyslogAudit:
		_ = syslogWriter.Notice(msg)
	default:
		_ = syslogWriter.Info(msg)
	}
}

func syslogClosePlatform() {
	if syslogWriter != nil {
		_ = syslogWriter.Close()
		syslogWriter = nil
	}
}
