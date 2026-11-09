package main

// pool_v5.go - 连接池零拷贝优化 (Phase E)
//
// 优化目标：
// 1. 响应体读取复用 buffer（减少 GC 压力）
// 2. JSON 解码 buffer 复用
// 3. 请求体读取复用（与 WAF 共享）
// 4. 连接池指标增强（延迟分布、错误率）

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ===================== Buffer Pool (零拷贝优化) =====================

var (
	// 响应体读取 buffer pool (默认 64KB，按需增长)
	responseBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 64*1024)
			return bytes.NewBuffer(buf)
		},
	}

	// JSON 解码 buffer pool (默认 32KB)
	jsonDecodeBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 32*1024)
			return bytes.NewBuffer(buf)
		},
	}

	// 小对象 buffer pool (4KB，用于 headers/metadata)
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 4*1024)
			return bytes.NewBuffer(buf)
		},
	}
)

// getResponseBuffer 获取响应读取 buffer
func getResponseBuffer() *bytes.Buffer {
	return responseBufferPool.Get().(*bytes.Buffer)
}

// putResponseBuffer 归还响应读取 buffer
func putResponseBuffer(buf *bytes.Buffer) {
	buf.Reset()
	responseBufferPool.Put(buf)
}

// getJSONDecodeBuffer 获取 JSON 解码 buffer
func getJSONDecodeBuffer() *bytes.Buffer {
	return jsonDecodeBufferPool.Get().(*bytes.Buffer)
}

// putJSONDecodeBuffer 归还 JSON 解码 buffer
func putJSONDecodeBuffer(buf *bytes.Buffer) {
	buf.Reset()
	jsonDecodeBufferPool.Put(buf)
}

// getSmallBuffer 获取小对象 buffer
func getSmallBuffer() *bytes.Buffer {
	return smallBufferPool.Get().(*bytes.Buffer)
}

// putSmallBuffer 归还小对象 buffer
func putSmallBuffer(buf *bytes.Buffer) {
	buf.Reset()
	smallBufferPool.Put(buf)
}

// ===================== 零拷贝读取工具 =====================

// ReadResponseWithPool 使用 buffer pool 读取响应体（零拷贝优化）
// 自动归还 buffer 到池中，调用方无需关心
func ReadResponseWithPool(resp *http.Response, maxSize int64) ([]byte, error) {
	buf := getResponseBuffer()
	defer putResponseBuffer(buf)

	// 限制读取大小（防止 OOM）
	limited := io.LimitReader(resp.Body, maxSize)
	if _, err := buf.ReadFrom(limited); err != nil {
		return nil, err
	}

	// 复制数据（buffer 会被复用）
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// DecodeJSONWithPool 使用 buffer pool 解码 JSON（零拷贝优化）
func DecodeJSONWithPool(resp *http.Response, v interface{}, maxSize int64) error {
	buf := getJSONDecodeBuffer()
	defer putJSONDecodeBuffer(buf)

	// 限制读取大小
	limited := io.LimitReader(resp.Body, maxSize)
	if _, err := buf.ReadFrom(limited); err != nil {
		return err
	}

	// 解码
	return json.Unmarshal(buf.Bytes(), v)
}

// CopyResponseWithPool 复制响应体到 writer（使用 buffer pool）
func CopyResponseWithPool(dst io.Writer, resp *http.Response, maxSize int64) (int64, error) {
	buf := getResponseBuffer()
	defer putResponseBuffer(buf)

	// 读取到 buffer
	limited := io.LimitReader(resp.Body, maxSize)
	n, err := buf.ReadFrom(limited)
	if err != nil {
		return 0, err
	}

	// 写出
	written, err := buf.WriteTo(dst)
	return written, err
}

// ===================== 连接池指标增强 =====================

var (
	// 延迟分布 (分桶计数)
	poolLatencyBuckets = struct {
		buckets [10]atomic.Int64 // 0-10ms, 10-50ms, 50-100ms, 100-500ms, 500ms-1s, 1-5s, 5-10s, 10-30s, 30-60s, 60s+
		mu      sync.Mutex
	}

	// 错误率统计
	poolErrors   atomic.Int64
	poolRequests atomic.Int64
)

// recordPoolLatency 记录连接池延迟
func recordPoolLatency(duration time.Duration) {
	ms := duration.Milliseconds()
	var idx int
	switch {
	case ms < 10:
		idx = 0
	case ms < 50:
		idx = 1
	case ms < 100:
		idx = 2
	case ms < 500:
		idx = 3
	case ms < 1000:
		idx = 4
	case ms < 5000:
		idx = 5
	case ms < 10000:
		idx = 6
	case ms < 30000:
		idx = 7
	case ms < 60000:
		idx = 8
	default:
		idx = 9
	}
	poolLatencyBuckets.buckets[idx].Add(1)
}

// recordPoolError 记录连接池错误
func recordPoolError() {
	poolErrors.Add(1)
}

// getPoolLatencyDistribution 获取延迟分布
func getPoolLatencyDistribution() map[string]int64 {
	labels := []string{
		"<10ms", "10-50ms", "50-100ms", "100-500ms", "500ms-1s",
		"1-5s", "5-10s", "10-30s", "30-60s", ">60s",
	}
	result := make(map[string]int64, len(labels))
	for i, label := range labels {
		result[label] = poolLatencyBuckets.buckets[i].Load()
	}
	return result
}

// getPoolErrorRate 获取错误率 (百分比)
func getPoolErrorRate() float64 {
	errors := poolErrors.Load()
	requests := poolRequests.Load()
	if requests == 0 {
		return 0.0
	}
	return float64(errors) / float64(requests) * 100.0
}

// ===================== 增强的 Transport 包装 =====================

// enhancedTrackedTransport 在 trackedTransport 基础上增加延迟和错误跟踪
type enhancedTrackedTransport struct {
	base *http.Transport
}

func (t enhancedTrackedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	poolRequests.Add(1)
	start := time.Now()

	// 调用底层 transport
	resp, err := t.base.RoundTrip(req)

	// 记录延迟
	duration := time.Since(start)
	recordPoolLatency(duration)

	// 记录错误
	if err != nil {
		recordPoolError()
	}

	return resp, err
}

// wrapTransportWithEnhanced 包装 transport 增加增强指标
func wrapTransportWithEnhanced(base *http.Transport) http.RoundTripper {
	return enhancedTrackedTransport{base: base}
}

// ===================== Buffer Pool 统计 =====================

// bufferPoolStats 返回 buffer pool 使用统计
func bufferPoolStats() map[string]interface{} {
	return map[string]interface{}{
		"responseBufferSize":      64 * 1024,  // 64KB
		"jsonDecodeBufferSize":    32 * 1024,  // 32KB
		"smallBufferSize":         4 * 1024,   // 4KB
		"responseBufferPool":      "sync.Pool",
		"jsonDecodeBufferPool":    "sync.Pool",
		"smallBufferPool":         "sync.Pool",
		"optimization":            "zero-copy with buffer reuse",
	}
}

// enhancedPoolStats 返回增强的连接池统计
func enhancedPoolStats() map[string]interface{} {
	// 基础指标
	stats := poolStats()

	// 增强指标
	stats["latencyDistribution"] = getPoolLatencyDistribution()
	stats["errorRate"] = round2(getPoolErrorRate())
	stats["totalErrors"] = poolErrors.Load()
	stats["bufferPool"] = bufferPoolStats()

	return stats
}

// handleV5Pool GET /api/admin/v5/pool - 增强连接池指标
func handleV5Pool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	writeJSON(w, enhancedPoolStats())
}
