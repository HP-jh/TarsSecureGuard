package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// v4.11.0 SSE 实时事件流：供桌面客户端订阅拦截/审计事件
// 采用标准 HTTP SSE（text/event-stream），零外部依赖，浏览器原生 EventSource 支持

var (
	sseClients   = make(map[chan sseEvent]bool)
	sseClientsMu sync.RWMutex
	sseEventID   int64
	sseEventIDMu sync.Mutex
)

// sseEvent 统一事件载荷
type sseEvent struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`      // "intercept" | "audit" | "waf" | "system"
	Timestamp int64  `json:"timestamp"` // Unix ms
	Severity  string `json:"severity"`  // "info" | "warn" | "block"
	Title     string `json:"title"`     // 人话标题
	Detail    string `json:"detail"`    // 详情
	IP        string `json:"ip"`        // 来源 IP（如有）
	Route     string `json:"route"`     // 命中路由（如有）
}

// handleWSEvents SSE 端点：/ws/events（保留路径名，实际协议为 SSE）
func handleWSEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan sseEvent, 64)
	sseClientsMu.Lock()
	sseClients[ch] = true
	sseClientsMu.Unlock()

	defer func() {
		sseClientsMu.Lock()
		delete(sseClients, ch)
		sseClientsMu.Unlock()
		close(ch)
	}()

	// 发送就绪事件
	sseWrite(w, flusher, sseEvent{
		Type:      "system",
		Timestamp: time.Now().UnixMilli(),
		Severity:  "info",
		Title:     "事件流已连接",
		Detail:    "TarsSecureGuard v" + version + " 实时事件流",
	})

	// 保持连接：心跳每 30 秒（防中间件/代理断开）
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !sseWrite(w, flusher, ev) {
				return
			}
		case <-ticker.C:
			if !sseWrite(w, flusher, sseEvent{Type: "ping", Timestamp: time.Now().UnixMilli()}) {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

func sseWrite(w http.ResponseWriter, flusher http.Flusher, ev sseEvent) bool {
	sseEventIDMu.Lock()
	sseEventID++
	ev.ID = sseEventID
	sseEventIDMu.Unlock()

	data, err := json.Marshal(ev)
	if err != nil {
		return true // 静默丢弃格式错误事件，不断开连接
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", ev.ID, data)
	if err != nil {
		return false
	}
	flusher.Flush()
	return true
}

// sseBroadcast 向所有已连接客户端广播事件（非阻塞，通道满则丢弃）
func sseBroadcast(ev sseEvent) {
	sseClientsMu.RLock()
	clients := make([]chan sseEvent, 0, len(sseClients))
	for c := range sseClients {
		clients = append(clients, c)
	}
	sseClientsMu.RUnlock()

	for _, c := range clients {
		select {
		case c <- ev:
		default:
			// 通道满 → 静默丢弃（避免阻塞广播方）
		}
	}
}

// sseEmitIntercept 封装拦截事件广播（供 WAF/网关中间件调用）
func sseEmitIntercept(severity, title, detail, ip, route string) {
	sseBroadcast(sseEvent{
		Type:      "intercept",
		Timestamp: time.Now().UnixMilli(),
		Severity:  severity,
		Title:     title,
		Detail:    detail,
		IP:        ip,
		Route:     route,
	})
}

// sseEmitAudit 封装审计事件广播
func sseEmitAudit(action, user, detail string) {
	sseBroadcast(sseEvent{
		Type:      "audit",
		Timestamp: time.Now().UnixMilli(),
		Severity:  "info",
		Title:     action,
		Detail:    detail,
		IP:        "-",
	})
}
