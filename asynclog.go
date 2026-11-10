package main

// v5.1 §3.4 日志/审计 ring buffer + 批量落盘
//
// 现状：fileLog 每行同步写盘（已优化为常开句柄，但仍在调用者线程上同步 write）。
// 目标：请求路径只入队（channel），单写 goroutine 批量落盘 + 定期 fsync。
// 队列满则丢弃并计数（fail-close 语义不变：请求仍被拒绝/审计，只是日志行丢失）。
//
// 参考：腾讯 MT 架构的日志管线——数据面只入队不落盘，控制面异步刷盘。
// 参考来源：Envoy threading model，main thread 管日志/统计，worker 不碰 IO。
// 参考来源：SEDA (SOSP 2001) 有界队列 + 自适应降载。

import (
	"sync/atomic"
	"time"
)

// logQueue 日志写入队列（ring buffer 语义）
// 有界 channel，满则丢弃并计数
var (
	logQueue    = make(chan logEntry, 4096)
	logDropped  atomic.Int64 // 因队列满而丢弃的日志行数
	logStopCh   = make(chan struct{})
)

// logEntry 一条待写日志
type logEntry struct {
	prefix string
	line   string
}

// startLogWorker 启动日志写入 goroutine（控制面，不在请求路径上）
// 从 logQueue 取行，批量写入对应前缀的文件，定期 fsync
func startLogWorker() {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		// 批量缓冲：同前缀的行攒一批一起写
		batch := make(map[string][]string)
		for {
			select {
			case entry := <-logQueue:
				batch[entry.prefix] = append(batch[entry.prefix], entry.line)
				// 非阻塞地取完当前 channel 中的积压
				for {
					select {
					case e := <-logQueue:
						batch[e.prefix] = append(batch[e.prefix], e.line)
					default:
						goto flush
					}
				}
			flush:
				// 批量写盘
				for prefix, lines := range batch {
					for _, line := range lines {
						fileLog(prefix, line)
					}
				}
				batch = make(map[string][]string)
			case <-ticker.C:
				// 定期 flush（即使无新日志也触发，确保 fsync）
				for prefix, lines := range batch {
					for _, line := range lines {
						fileLog(prefix, line)
					}
				}
				batch = make(map[string][]string)
			case <-logStopCh:
				// 退出前 flush 剩余
				for prefix, lines := range batch {
					for _, line := range lines {
						fileLog(prefix, line)
					}
				}
				// 排空 channel
				for {
					select {
					case e := <-logQueue:
						fileLog(e.prefix, e.line)
					default:
						return
					}
				}
			}
		}
	}()
}

// asyncLog 异步入队日志（请求路径调用，不阻塞）
// 队列满则丢弃并计数（不影响请求处理）
func asyncLog(prefix, line string) {
	select {
	case logQueue <- logEntry{prefix: prefix, line: line}:
	default:
		logDropped.Add(1)
	}
}

// stopLogWorker 停止日志 goroutine（优雅退出时调用）
func stopLogWorker() {
	close(logStopCh)
}
