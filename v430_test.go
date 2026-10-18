package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ===================== 测试辅助：隔离 auth 状态 =====================

func v430SetupAuth(t *testing.T) (cleanup func()) {
	cfgMu.Lock()
	savedUsers := cfg.Users
	savedKey := cfg.Security.APIKey
	cfg.Users = nil
	cfg.Security.APIKey = "test-api-key-v430"
	cfgMu.Unlock()
	return func() {
		cfgMu.Lock()
		cfg.Users = savedUsers
		cfg.Security.APIKey = savedKey
		cfgMu.Unlock()
	}
}

// ===================== 版本号校验 =====================

func TestV430VersionBumped(t *testing.T) {
	if version != "4.30.0" {
		t.Fatalf("version = %q, want 4.30.0", version)
	}
}

// ===================== SSE 端点基础行为 =====================

func TestV430AuditStreamUnauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/v4/audit/stream", nil)
	rec := httptest.NewRecorder()
	handleAuditStream(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未鉴权应返回 401，实际 %d", rec.Code)
	}
}

func TestV430AuditStreamMethodNotAllowed(t *testing.T) {
	cleanup := v430SetupAuth(t)
	defer cleanup()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/v4/audit/stream", nil)
	req.Header.Set("X-API-Key", "test-api-key-v430")
	rec := httptest.NewRecorder()
	handleAuditStream(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST 应返回 405，实际 %d", rec.Code)
	}
}

func TestV430AuditStreamSSEHeaders(t *testing.T) {
	cleanup := v430SetupAuth(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/v4/audit/stream", nil).WithContext(ctx)
	req.Header.Set("X-API-Key", "test-api-key-v430")
	rec := httptest.NewRecorder()

	// SSE 是长连接，用 goroutine 运行并在超时后通过取消 context 结束
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleAuditStream(rec, req)
	}()

	// 给 handler 一点时间写入响应头
	time.Sleep(100 * time.Millisecond)

	// 取消请求以结束 handler
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler 未在预期时间内结束")
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("Content-Type 应为 text/event-stream，实际 %q", ct)
	}
	if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("Cache-Control 应为 no-cache")
	}
}

// ===================== 广播与过滤 =====================

func TestV430AuditStreamBroadcast(t *testing.T) {
	// 注册一个测试客户端
	ch := make(chan AuditStreamEvent, 4)
	client := &streamClient{
		ch:     ch,
		filter: func(e AuditStreamEvent) bool { return true },
	}
	auditStreamMu.Lock()
	auditStreamClients = append(auditStreamClients, client)
	auditStreamMu.Unlock()
	defer func() {
		auditStreamMu.Lock()
		for i, c := range auditStreamClients {
			if c == client {
				auditStreamClients = append(auditStreamClients[:i], auditStreamClients[i+1:]...)
				break
			}
		}
		auditStreamMu.Unlock()
		close(ch)
	}()

	// 广播一条事件
	entry := AuditV2Entry{
		Seq: 1, Ts: time.Now().Format(time.RFC3339Nano),
		Action: "TEST_ACTION", Tenant: "default",
		User: "admin", Detail: "test detail",
	}
	auditStreamBroadcast(entry)

	select {
	case evt := <-ch:
		if evt.Action != "TEST_ACTION" {
			t.Fatalf("Action 不匹配: got %q", evt.Action)
		}
		if evt.User != "admin" {
			t.Fatalf("User 不匹配: got %q", evt.User)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到广播事件")
	}
}

func TestV430AuditStreamFilterAction(t *testing.T) {
	ch := make(chan AuditStreamEvent, 4)
	client := &streamClient{
		ch: ch,
		filter: func(e AuditStreamEvent) bool {
			return e.Action == "WANTED"
		},
	}
	auditStreamMu.Lock()
	auditStreamClients = append(auditStreamClients, client)
	auditStreamMu.Unlock()
	defer func() {
		auditStreamMu.Lock()
		for i, c := range auditStreamClients {
			if c == client {
				auditStreamClients = append(auditStreamClients[:i], auditStreamClients[i+1:]...)
				break
			}
		}
		auditStreamMu.Unlock()
		close(ch)
	}()

	// 发送不匹配的事件
	auditStreamBroadcast(AuditV2Entry{Action: "UNWANTED", Tenant: "default", User: "u"})
	// 发送匹配的事件
	auditStreamBroadcast(AuditV2Entry{Action: "WANTED", Tenant: "default", User: "u"})

	// 只应收到 WANTED
	select {
	case evt := <-ch:
		if evt.Action != "WANTED" {
			t.Fatalf("应只收到 WANTED，实际 %q", evt.Action)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到匹配事件")
	}

	// 不应再有第二条
	select {
	case <-ch:
		t.Fatal("不应收到过滤掉的事件")
	case <-time.After(200 * time.Millisecond):
		// 正确
	}
}

func TestV430AuditStreamTenantIsolation(t *testing.T) {
	// 模拟租户 t1 的客户端
	ch := make(chan AuditStreamEvent, 4)
	client := &streamClient{
		ch: ch,
		filter: func(e AuditStreamEvent) bool {
			// 非 global 角色只能看本租户
			return e.Tenant == "t1" || e.Tenant == "*"
		},
	}
	auditStreamMu.Lock()
	auditStreamClients = append(auditStreamClients, client)
	auditStreamMu.Unlock()
	defer func() {
		auditStreamMu.Lock()
		for i, c := range auditStreamClients {
			if c == client {
				auditStreamClients = append(auditStreamClients[:i], auditStreamClients[i+1:]...)
				break
			}
		}
		auditStreamMu.Unlock()
		close(ch)
	}()

	// 发送跨租户事件
	auditStreamBroadcast(AuditV2Entry{Action: "A", Tenant: "t2", User: "u"})
	// 发送本租户事件
	auditStreamBroadcast(AuditV2Entry{Action: "B", Tenant: "t1", User: "u"})

	select {
	case evt := <-ch:
		if evt.Action != "B" {
			t.Fatalf("租户隔离失败：收到 %q（tenant=%q）", evt.Action, evt.Tenant)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到本租户事件")
	}

	select {
	case <-ch:
		t.Fatal("不应收到跨租户事件")
	case <-time.After(200 * time.Millisecond):
		// 正确
	}
}

// ===================== SSE 响应体格式校验 =====================

func TestV430AuditStreamResponseFormat(t *testing.T) {
	cleanup := v430SetupAuth(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/v4/audit/stream", nil).WithContext(ctx)
	req.Header.Set("X-API-Key", "test-api-key-v430")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleAuditStream(rec, req)
	}()

	// 等待一点输出
	time.Sleep(150 * time.Millisecond)

	// 取消请求结束 handler
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler 未在预期时间内结束")
	}

	// 检查 body 是否以 SSE 格式开头（: connected）
	body := rec.Body.String()
	if !strings.Contains(body, ": connected") {
		t.Fatalf("SSE 响应体应包含 ': connected'，实际：%q", body)
	}
}

// ===================== 历史回放 =====================

func TestV430AuditStreamRecentEventsHelper(t *testing.T) {
	// 该辅助函数依赖当日审计文件存在，在无文件时应返回 nil
	events := auditStreamRecentEvents(10, func(e AuditStreamEvent) bool { return true })
	// 测试环境可能没有审计文件，允许 nil 或空切片
	if events != nil && len(events) > 0 {
		// 如果有数据，验证结构
		for _, e := range events {
			if e.Action == "" {
				t.Fatal("历史事件 Action 不应为空")
			}
		}
	}
}

// ===================== 集成：端到端 SSE 连接 + 事件推送 =====================

func TestV430AuditStreamEndToEnd(t *testing.T) {
	cleanup := v430SetupAuth(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/v4/audit/stream", nil).WithContext(ctx)
	req.Header.Set("X-API-Key", "test-api-key-v430")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleAuditStream(rec, req)
	}()

	// 等待连接建立
	time.Sleep(100 * time.Millisecond)

	// 模拟审计写入触发广播
	go auditV2Write("E2E_TEST", "default", "", "tester", "127.0.0.1", "end-to-end streaming test", "trace-430")

	// 给广播和写入一点时间
	time.Sleep(200 * time.Millisecond)

	// 取消请求结束 handler
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler 未在预期时间内结束")
	}

	body := rec.Body.String()

	// 解析 SSE 事件行
	var found bool
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			var evt AuditStreamEvent
			if err := json.Unmarshal([]byte(line[6:]), &evt); err == nil {
				if evt.Action == "E2E_TEST" {
					found = true
					if evt.Detail != "end-to-end streaming test" {
						t.Fatalf("Detail 不匹配: %q", evt.Detail)
					}
					break
				}
			}
		}
	}

	if !found {
		t.Fatalf("端到端未收到 E2E_TEST 事件，响应体：%q", body)
	}
}
