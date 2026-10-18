package main

// v4.30.0 审计日志实时流式导出（SSE）
//
// 设计目标：
//   - 零外部依赖：纯标准库 SSE（text/event-stream），不引入 WebSocket 库
//   - 实时推送：auditV2Write 落盘后同步广播到所有匹配客户端
//   - 租户硬隔离：非 global 角色只能收到本租户事件（同 [MT_AUDIT_ISOLATION]）
//   - 可过滤：支持按 action / user / tenant / since 过滤
//   - 历史回放：新连接可指定 ?history=N 推送最近 N 条（默认 0）
//   - 心跳保活：30 秒一次注释行 keepalive，防 CDN/代理断开
//
// 端点：GET /api/admin/v4/audit/stream
//   Query:
//     action   — 仅推送指定事件类型（如 ACCESS_DENIED）
//     user     — 仅推送指定用户
//     tenant   — 仅推送指定租户（global 角色可用）
//     since    — RFC3339，仅推送该时间之后的事件
//     history  — 连接建立时先推送最近 N 条（1~1000，默认 0）

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ===================== 事件与客户端 =====================

// AuditStreamEvent 流式推送的审计事件（AuditV2Entry 子集，省带宽）
type AuditStreamEvent struct {
	Seq    int    `json:"seq"`
	Ts     string `json:"ts"`
	Action string `json:"action"`
	Tenant string `json:"tenant"`
	Group  string `json:"group,omitempty"`
	User   string `json:"user"`
	IP     string `json:"ip,omitempty"`
	Detail string `json:"detail"`
	Trace  string `json:"trace,omitempty"`
}

type streamClient struct {
	ch     chan AuditStreamEvent
	filter func(AuditStreamEvent) bool
}

var (
	auditStreamMu      sync.RWMutex
	auditStreamClients []*streamClient
)

// ===================== 广播（由 auditV2Write 调用） =====================

// auditStreamBroadcast 将新审计事件广播给所有匹配的 SSE 客户端
func auditStreamBroadcast(e AuditV2Entry) {
	evt := AuditStreamEvent{
		Seq: e.Seq, Ts: e.Ts, Action: e.Action,
		Tenant: e.Tenant, Group: e.Group, User: e.User,
		IP: e.IP, Detail: e.Detail, Trace: e.Trace,
	}
	auditStreamMu.RLock()
	clients := make([]*streamClient, len(auditStreamClients))
	copy(clients, auditStreamClients)
	auditStreamMu.RUnlock()

	for _, c := range clients {
		if c.filter(evt) {
			select {
			case c.ch <- evt:
			default:
				// 通道满则丢弃（背压保护，避免慢客户端拖垮系统）
			}
		}
	}
}

// ===================== SSE 端点 =====================

// handleAuditStream GET /api/admin/v4/audit/stream
func handleAuditStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// 解析过滤参数
	qAction := r.URL.Query().Get("action")
	qUser := r.URL.Query().Get("user")
	qTenant := r.URL.Query().Get("tenant")
	qSince := r.URL.Query().Get("since")
	qHistory := r.URL.Query().Get("history")

	historyN := 0
	if qHistory != "" {
		if n, err := strconv.Atoi(qHistory); err == nil && n > 0 && n <= 1000 {
			historyN = n
		}
	}

	// SSE 响应头
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // 禁用 Nginx 缓冲
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
		return
	}

	// 发送初始注释建立连接
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	// 组装过滤函数（闭包捕获查询参数 + 身份）
	filter := func(e AuditStreamEvent) bool {
		// [MT_AUDIT_ISOLATION] 租户硬隔离
		if !id.Global && e.Tenant != id.Tenant && e.Tenant != "*" {
			return false
		}
		if qAction != "" && e.Action != qAction {
			return false
		}
		if qUser != "" && e.User != qUser {
			return false
		}
		if qTenant != "" && e.Tenant != qTenant {
			return false
		}
		if qSince != "" {
			if since, err := time.Parse(time.RFC3339, qSince); err == nil {
				if evtTs, err := time.Parse(time.RFC3339Nano, e.Ts); err == nil && evtTs.Before(since) {
					return false
				}
			}
		}
		return true
	}

	// 可选：历史回放
	if historyN > 0 {
		events := auditStreamRecentEvents(historyN, filter)
		for _, e := range events {
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		flusher.Flush()
	}

	// 订阅
	ch := make(chan AuditStreamEvent, 64)
	client := &streamClient{ch: ch, filter: filter}
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

	// 心跳 + 事件循环
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(evt)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive %d\n\n", time.Now().Unix())
			flusher.Flush()
		}
	}
}

// ===================== 历史回放辅助 =====================

// auditStreamRecentEvents 读取当日审计文件，返回匹配过滤条件的最近 N 条
func auditStreamRecentEvents(n int, filter func(AuditStreamEvent) bool) []AuditStreamEvent {
	day := time.Now().Format("2006-01-02")
	f, err := os.Open(auditV2FilePath(day))
	if err != nil {
		return nil
	}
	defer f.Close()

	var all []AuditStreamEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditV2Entry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		evt := AuditStreamEvent{
			Seq: e.Seq, Ts: e.Ts, Action: e.Action,
			Tenant: e.Tenant, Group: e.Group, User: e.User,
			IP: e.IP, Detail: e.Detail, Trace: e.Trace,
		}
		if filter(evt) {
			all = append(all, evt)
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}
