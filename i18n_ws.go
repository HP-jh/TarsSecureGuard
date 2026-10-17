package main

// ===================== i18n SSE 实时推送 =====================
// 翻译包更新后秒级推送到所有连接的浏览器客户端
// 使用 SSE (Server-Sent Events) —— 纯 HTTP，零外部依赖

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type i18nSSEHub struct {
	mu      sync.RWMutex
	clients map[chan i18nSSEEvent]bool
}

type i18nSSEEvent struct {
	Type    string `json:"type"`    // "update" | "reload"
	Lang    string `json:"lang"`    // "*" 表示全部
	Version string `json:"version"`
	TS      int64  `json:"ts"`
}

var globalSSEHub = &i18nSSEHub{clients: make(map[chan i18nSSEEvent]bool)}

func newI18nSSEHub() *i18nSSEHub {
	return globalSSEHub
}

func (h *i18nSSEHub) broadcast(lang, version string) {
	ev := i18nSSEEvent{Type: "update", Lang: lang, Version: version, TS: time.Now().Unix()}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- ev:
		default:
		}
	}
}

func handleI18nSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// 发送初始连接事件
	fmt.Fprintf(w, "event: connected\ndata: %s\n\n", `{"type":"connected","ts":`+fmt.Sprint(time.Now().Unix())+`}`)
	flusher.Flush()

	ch := make(chan i18nSSEEvent, 4)
	globalSSEHub.mu.Lock()
	globalSSEHub.clients[ch] = true
	globalSSEHub.mu.Unlock()

	defer func() {
		globalSSEHub.mu.Lock()
		delete(globalSSEHub.clients, ch)
		globalSSEHub.mu.Unlock()
		close(ch)
	}()

	// 心跳 + 事件推送
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: update\ndata: %s\n\n", string(b))
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, "event: ping\ndata: %s\n\n", `{"type":"ping","ts":`+fmt.Sprint(time.Now().Unix())+`}`)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handleI18nWS 保留原函数名但走 SSE（兼容前端注册路径）
func handleI18nWS(w http.ResponseWriter, r *http.Request) {
	handleI18nSSE(w, r)
}
