package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ===================== 日志文件持久化（新增：v1.0.2 功能强化） =====================
//
// 运行日志写入 logs/tars-YYYY-MM-DD.log，审计日志写入 logs/audit-YYYY-MM-DD.log。
// 采用「打开-追加-关闭」的同步写入模型：每条日志写盘后立即关闭文件，
// 即使进程异常退出也不会丢日志，也不长期占用文件句柄。

var (
	logFileOnce sync.Once
	logFileDir  string
)

// initFileLogging 初始化日志目录（默认 exe 同级 logs/，失败不影响服务运行）
func initFileLogging() {
	logFileOnce.Do(func() {
		dir := filepath.Join(appDir(), "logs")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return // 目录创建失败时静默降级为仅内存日志
		}
		logFileDir = dir
	})
}

// fileLog 同步追加一行日志到指定日志文件（tars=运行日志，audit=审计日志）。
// 每次调用独立打开文件并关闭，保证异常退出不丢日志。
func fileLog(kind, line string) {
	if logFileDir == "" {
		return
	}
	name := fmt.Sprintf("%s-%s.log", kind, time.Now().Format("2006-01-02"))
	path := filepath.Join(logFileDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, strings.TrimRight(line, "\r\n"))
}
