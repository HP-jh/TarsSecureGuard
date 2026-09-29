package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ===================== 日志文件持久化 =====================
//
// 现有日志仅存内存（logs / wafLogs 切片，上限 500 条供 API 查询）。
// 本模块在内存日志之外，把日志同步写入文件并按天轮转：
//   - 运行日志：logs/tars-YYYY-MM-DD.log
//   - WAF 日志：logs/waf-YYYY-MM-DD.log
// 跨天后写入新文件即完成轮转，旧文件保留在 logs/ 目录中供追溯。

var (
	logFileMu  sync.Mutex
	logFileDir string // 日志根目录；为空表示文件日志不可用（仅内存日志）
)

// initFileLogging 初始化日志目录（默认 exe 同目录下的 logs/）。
// 目录创建失败不中断服务，仅放弃文件落盘。
func initFileLogging() {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	logFileDir = filepath.Join(appDir(), "logs")
	if err := os.MkdirAll(logFileDir, 0755); err != nil {
		logFileDir = ""
		log.Printf("[LOG] 无法创建日志目录，文件日志已禁用: %v", err)
	}
}

// fileLog 把一行日志追加写入指定前缀（tars / waf）的当日日志文件。
// 按天轮转：文件名内嵌当天日期，跨天自然切换到新文件。
func fileLog(prefix, line string) {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFileDir == "" {
		return // 目录不可用时静默跳过（内存日志仍生效）
	}
	name := filepath.Join(logFileDir, fmt.Sprintf("%s-%s.log", prefix, time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return // 写盘失败不影响主流程
	}
	defer f.Close()
	f.WriteString(line + "\n")
}
