package main

// ===================== v3.2.0 连接池（Connection Pool）=====================
//
// 目标：全出站流量共享一个调优过的 http.Transport（连接复用 / HTTP2 /
// TLS 会话复用），替代逐请求隐式建连；并用 httptrace 精确计量「连接复用率」。
//
// 复用率 = reused / (reused + new)：同一 host 的第二次请求应命中空闲连接。
// 默认参数（可经 config.json v32.pool.maxIdleConnsPerHost 覆盖）：
//   MaxIdleConns=256 / MaxIdleConnsPerHost=32 / IdleConnTimeout=90s /
//   TLSHandshakeTimeout=10s / ForceAttemptHTTP2=true
//
// 安全不变量：只改传输层，不改任何安全判定；本池服务所有出站
// （云端 provider / 本地运行时 / web fetch），超时仍由各 client 控制。

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

var (
	sharedTransport *http.Transport
	poolOnce        sync.Once

	// 连接复用计量（atomic 计数，admin 端点只读快照）
	poolConnNew    atomic.Int64
	poolConnReused atomic.Int64
	poolRequests   atomic.Int64
)

// initPooledClients 幂等初始化：构建共享 Transport 并把 httpClientShort/Long
// 切到该 Transport 上（超时语义与 v3.0.5 完全一致：30s / 300s）。
// maxIdlePerHost <= 0 时取默认 32。
func initPooledClients(maxIdlePerHost int) {
	poolOnce.Do(func() {
		if maxIdlePerHost <= 0 {
			maxIdlePerHost = 32
		}
		sharedTransport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          256,
			MaxIdleConnsPerHost:   maxIdlePerHost,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		}
		httpClientShort = &http.Client{Transport: trackedTransport{sharedTransport}, Timeout: 30 * time.Second}
		httpClientLong = &http.Client{Transport: trackedTransport{sharedTransport}, Timeout: 300 * time.Second}
	})
}

// trackedTransport 包装共享 Transport：经 httptrace 计量每个请求的
// 连接复用情况（GotConnInfo.Reused），纯观测零改写。
type trackedTransport struct{ base *http.Transport }

func (t trackedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	poolRequests.Add(1)
	ctx := req.Context()
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				poolConnReused.Add(1)
			} else {
				poolConnNew.Add(1)
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	return t.base.RoundTrip(req)
}

// poolStats 连接池快照（admin 端点 / benchmark 用）
func poolStats() map[string]interface{} {
	total := poolConnNew.Load() + poolConnReused.Load()
	reuseRate := 0.0
	if total > 0 {
		reuseRate = float64(poolConnReused.Load()) / float64(total) * 100
	}
	// Transport 未暴露空闲/活跃连接计数 API（IdleConnCount 不存在于标准库），
	// 连接级指标以 trackedTransport 实测的 connNew/connReused 为准。
	return map[string]interface{}{
		"requests":        poolRequests.Load(),
		"connNew":         poolConnNew.Load(),
		"connReused":      poolConnReused.Load(),
		"reuseRatePct":    round2(reuseRate),
		"maxIdlePerHost":  32,
		"idleConnTimeout": "90s",
		"http2":           true,
	}
}

// poolReuseRatePct 供 benchmark 与测试直接取复用率
func poolReuseRatePct() float64 {
	total := poolConnNew.Load() + poolConnReused.Load()
	if total == 0 {
		return 0
	}
	return float64(poolConnReused.Load()) / float64(total) * 100
}

// handleV32Pool GET /api/admin/v32/pool —— 连接池指标（admin.read）
func handleV32Pool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	writeJSON(w, poolStats())
}
