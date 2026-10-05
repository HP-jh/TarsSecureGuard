package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ===================== 日志文件持久化（v3.2.2 性能升级 v1：常开句柄管线）=====================
//
// 现有日志仅存内存（logs / wafLogs 切片，上限 500 条供 API 查询）。
// 本模块在内存日志之外，把日志同步写入文件并按天轮转：
//   - 运行日志：logs/tars-YYYY-MM-DD.log
//   - WAF 日志：logs/waf-YYYY-MM-DD.log
//   - 审计日志：logs/audit-YYYY-MM-DD.log
//
// v3.2.2 前的实现：每写一行都 open→write→close 同一日志文件（全局互斥）。
// 一次审计事件在请求路径上要触发 2 次 fileLog（audit + tars）+ 1 次 auditV2Write，
// 即每请求多付 4 个 syscall（2 open + 2 close）与路径拼接/时间格式化。
// 现改为：**每个前缀常开一个句柄**，跨天首写时关闭旧句柄、打开新文件（自然轮转）；
// 写入仍是同步 write（不引入丢行风险的异步化），但每行只剩 1 次 write syscall。
//
// 失败语义不变：任何文件操作失败只静默跳过，绝不影响主流程。

var (
	logFileMu  sync.Mutex
	logFileDir string // 日志根目录；为空表示文件日志不可用（仅内存日志）

	// 常开句柄表：prefix -> 当日句柄（v3.2.2；logFileMu 保护）
	logHandles = map[string]*logHandle{}
)

// logHandle 一个前缀的当日日志句柄
type logHandle struct {
	day string // 句柄对应的日期（YYYY-MM-DD）
	f   *os.File
}

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

// logDayFunc 当日日期（可注入，测试模拟跨天轮转用）
var logDayFunc = func() string { return time.Now().Format("2006-01-02") }

// fileLog 把一行日志追加写入指定前缀（tars / waf / audit）的当日日志文件。
// 按天轮转：文件名内嵌当天日期，跨天首写时关闭旧句柄并切换新文件。
// v3.2.2：句柄常开（每行仅 1 次 write syscall），旧实现每行 open+close。
func fileLog(prefix, line string) {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFileDir == "" {
		return // 目录不可用时静默跳过（内存日志仍生效）
	}
	day := logDayFunc()
	h, ok := logHandles[prefix]
	if ok && h.day != day {
		// 跨天轮转：关闭昨日句柄，强制重开
		h.f.Close()
		delete(logHandles, prefix)
		ok = false
	}
	if !ok {
		name := filepath.Join(logFileDir, fmt.Sprintf("%s-%s.log", prefix, day))
		f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return // 写盘失败不影响主流程
		}
		h = &logHandle{day: day, f: f}
		logHandles[prefix] = h
	}
	if _, err := h.f.WriteString(line + "\n"); err != nil {
		// 句柄失效（如磁盘被拔）：关闭并丢弃，下一行重试打开
		h.f.Close()
		delete(logHandles, prefix)
	}
}

// closeLogFileHandles 关闭全部常开日志句柄（优雅退出 / 测试重置用）
func closeLogFileHandles() {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	for p, h := range logHandles {
		h.f.Close()
		delete(logHandles, p)
	}
}
