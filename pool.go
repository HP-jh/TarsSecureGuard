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
// v4.25.0 新增：基于 QPS 的自适应扩缩容（5~200 区间），每 5 秒评估一次，
// 扩容激进、缩容保守，避免连接数抖动。
//
// 安全不变量：只改传输层，不改任何安全判定；本池服务所有出站
// （云端 provider / 本地运行时 / web fetch），超时仍由各 client 控制。

import (
	"crypto/tls"
	"fmt"
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

	// v4.25.0 自适应连接池状态
	poolAdaptiveEnabled atomic.Bool // 默认 true，可经 config 关闭
	poolCurrentMaxIdle  atomic.Int32 // 当前生效的 MaxIdleConnsPerHost
	poolAdaptiveStop    chan struct{} // 停止自适应 goroutine
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
			// v4.6.3 SSRF 统一防线：连接时对实际解析 IP 校验（防 DNS 重绑定）。
			// 本池目标主机均由内置常量/运维配置决定（云端 provider 固定域名、
			// 本机/局域网 ollama/lmstudio），不接受模型/请求体注入 URL——故放行
			// 回环+RFC1918（官方支持的局域网推理部署场景）；链路本地/云元数据
			// (169.254.169.254)/组播/未指定地址仍然一律拒绝。用户/模型可控 URL
			// 的出站走 fetchClient/downloadClient（严格模式，不开例外）。
			DialContext:           ssrfSafeDialContext(true, true),
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
		poolCurrentMaxIdle.Store(int32(maxIdlePerHost))
		poolAdaptiveEnabled.Store(true)
		poolAdaptiveStop = make(chan struct{})
		go poolAdaptiveLoop()
	})
}

// poolAdaptiveLoop v4.25.0 自适应扩缩容主循环：每 5 秒评估 QPS 并调整连接数。
// 扩容阈值低（QPS 上升即扩），缩容阈值高（QPS 持续下降才缩），避免抖动。
func poolAdaptiveLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastRequests int64
	var lastTime time.Time
	first := true

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			currentReq := poolRequests.Load()
			if first {
				lastRequests = currentReq
				lastTime = now
				first = false
				continue
			}

			deltaReq := currentReq - lastRequests
			deltaSec := now.Sub(lastTime).Seconds()
			if deltaSec <= 0 {
				continue
			}
			qps := float64(deltaReq) / deltaSec
			lastRequests = currentReq
			lastTime = now

			if !poolAdaptiveEnabled.Load() {
				continue
			}

			current := int(poolCurrentMaxIdle.Load())
			target := poolTargetConns(qps)

			// 扩容：目标 >= 当前 * 1.2（激进）
			// 缩容：目标 <= 当前 * 0.5（保守，避免频繁缩）
			shouldScale := false
			newVal := current
			if target >= int(float64(current)*1.2) {
				shouldScale = true
				newVal = target
			} else if target <= int(float64(current)*0.5) {
				shouldScale = true
				newVal = target
			}

			if shouldScale && newVal != current && sharedTransport != nil {
				sharedTransport.MaxIdleConnsPerHost = newVal
				poolCurrentMaxIdle.Store(int32(newVal))
				auditLog("POOL_ADAPTIVE", "system", fmt.Sprintf("qps=%.1f old=%d new=%d", qps, current, newVal))
			}
		case <-poolAdaptiveStop:
			return
		}
	}
}

// poolTargetConns 根据 QPS 计算目标连接数：每个连接约服务 2~4 QPS，
// 结果 clamp 到 [5, 200] 区间。
func poolTargetConns(qps float64) int {
	// 经验公式：目标连接数 = QPS / 3（每个连接约 3 QPS）
	target := int(qps / 3.0)
	if target < 5 {
		return 5
	}
	if target > 200 {
		return 200
	}
	return target
}

// poolSetAdaptiveEnabled 动态启停自适应（admin API / 测试用）
func poolSetAdaptiveEnabled(enabled bool) {
	poolAdaptiveEnabled.Store(enabled)
}

// poolSetMaxIdleConnsPerHost 手动设置连接数（覆盖自适应值）
func poolSetMaxIdleConnsPerHost(n int) {
	poolCurrentMaxIdle.Store(int32(n))
	if sharedTransport != nil {
		sharedTransport.MaxIdleConnsPerHost = n
	}
}

// pooledHTTPClient 返回走共享连接池的按需超时客户端（v3.2.2 性能升级 v1：
// 补全池覆盖——doctor / 探测等「按超时新建 client」的路径不再旁路共享池，
// 每次调用复用同一 Transport 的空闲连接而不是重新握手）。
func pooledHTTPClient(timeout time.Duration) *http.Client {
	if sharedTransport == nil {
		initPooledClients(0)
	}
	return &http.Client{Transport: trackedTransport{sharedTransport}, Timeout: timeout}
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
	currentMaxIdle := int(poolCurrentMaxIdle.Load())
	if currentMaxIdle == 0 {
		currentMaxIdle = 32
	}
	// Transport 未暴露空闲/活跃连接计数 API（IdleConnCount 不存在于标准库），
	// 连接级指标以 trackedTransport 实测的 connNew/connReused 为准。
	return map[string]interface{}{
		"requests":          poolRequests.Load(),
		"connNew":           poolConnNew.Load(),
		"connReused":        poolConnReused.Load(),
		"reuseRatePct":      round2(reuseRate),
		"maxIdlePerHost":    currentMaxIdle,
		"idleConnTimeout":   "90s",
		"http2":             true,
		"adaptiveEnabled":   poolAdaptiveEnabled.Load(),
		"adaptiveRange":     "5~200",
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
