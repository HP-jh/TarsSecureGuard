package main

// M1 集成测试（httptest）：验证 gatewayMiddleware 全链路 ——
// panic recovery、鉴权、三维限流 429、404 扫描信誉扣分、guard status 面板。
// 沙箱不支持常驻后台进程，以 httptest 替代真进程冒烟（更可靠且可重复）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// resetIPRep 清空信誉表与限流桶，保证测试间状态隔离
func resetIPRep() {
	ipRepMu.Lock()
	ipRepTable = map[string]*ipRepEntry{}
	ipRepMu.Unlock()
	rlBucketMu.Lock()
	rlBuckets = map[bucketKey]*tokenBucket{}
	rlBucketMu.Unlock()
}

// newTestGateway 构造带测试后端的中间件链
func newTestGateway(next http.Handler) http.Handler {
	return gatewayMiddleware(next)
}

// authedReq 构造带 API Key 的请求，RemoteAddr 模拟外部 IP
func authedReq(method, path, key string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "203.0.113.10:12345"
	if key != "" {
		r.Header.Set("X-API-Key", key)
	}
	return r
}

var onceSink sync.Mutex // 防止 -race 下并发测试互扰（go test 默认串行，保险起见）

func TestMiddlewarePanicRecovery(t *testing.T) {
	onceSink.Lock()
	defer onceSink.Unlock()
	resetIPRep()
	boom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom-in-backend")
	})
	h := newTestGateway(boom)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authedReq("GET", "/api/chat/x", apiKeyDefault))
	if w.Code != 500 {
		t.Fatalf("后端 panic 应被恢复并返回 500，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "internal error") {
		t.Errorf("panic 恢复响应体应包含 internal error，实际: %s", w.Body.String())
	}
}

func TestMiddlewareUnauthorized(t *testing.T) {
	onceSink.Lock()
	defer onceSink.Unlock()
	resetIPRep()
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := newTestGateway(ok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authedReq("GET", "/api/admin/modules", "wrong-key"))
	if w.Code != 401 {
		t.Fatalf("错误 API Key 应返回 401，实际 %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, authedReq("GET", "/api/admin/modules", ""))
	if w.Code != 401 {
		t.Fatalf("缺失 API Key 应返回 401，实际 %d", w.Code)
	}
}

func TestMiddlewareRateLimit429(t *testing.T) {
	onceSink.Lock()
	defer onceSink.Unlock()
	resetIPRep()
	resetGuard()
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := newTestGateway(ok)
	// /api/admin/modules 端点类=admin，默认额度 10/分钟
	for i := 1; i <= 10; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, authedReq("GET", "/api/admin/modules", apiKeyDefault))
		if w.Code != 200 {
			t.Fatalf("第 %d 个请求（额度内）应为 200，实际 %d", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authedReq("GET", "/api/admin/modules", apiKeyDefault))
	if w.Code != 429 {
		t.Fatalf("第 11 个请求应触发限流 429，实际 %d", w.Code)
	}
	// 限流违规联动信誉扣分 -15
	if s := ipRepScore("203.0.113.10"); s != 85 {
		t.Errorf("限流违规应扣 15 分至 85，实际 %f", s)
	}
}

func TestMiddlewareScan404Penalty(t *testing.T) {
	onceSink.Lock()
	defer onceSink.Unlock()
	resetIPRep()
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	h := newTestGateway(notFound)
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, authedReq("GET", "/api/nonexistent"+string(rune('a'+i)), apiKeyDefault))
		if w.Code != 404 {
			t.Fatalf("未注册路径应为 404，实际 %d", w.Code)
		}
	}
	// 三次 404 在同一分钟窗口内：只扣一次 10 分
	if s := ipRepScore("203.0.113.10"); s != 90 {
		t.Fatalf("404 扫描应扣 10 分（窗口内去重），实际 %f", s)
	}
}

func TestGuardStatusHandler(t *testing.T) {
	resetGuard()
	w := httptest.NewRecorder()
	handleGuardStatus(w, httptest.NewRequest("GET", "/api/admin/guard/status", nil))
	if w.Code != 200 {
		t.Fatalf("guard status 应返回 200，实际 %d", w.Code)
	}
	body := w.Body.String()
	for _, kw := range []string{`"tier"`, `"rssMB"`, `"memLimitMB"`, `"goroutines"`, `"tierLevel"`} {
		if !strings.Contains(body, kw) {
			t.Errorf("guard status 响应缺少字段 %s，实际 body: %s", kw, body)
		}
	}
}
