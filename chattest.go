// chattest.go — v4.12.0 AI Chat API 测试面板
package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type ChatTestRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Search bool   `json:"search"`
	Agent  bool   `json:"agent"`
}

type ChatTestResult struct {
	Content   string        `json:"content"`
	Backend   string        `json:"backend"`
	Usage     Usage         `json:"usage"`
	LatencyMs int64         `json:"latencyMs"`
	Status    string        `json:"status"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

func handleChatTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req ChatTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Prompt == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "prompt required"})
		return
	}

	start := time.Now()
	result := ChatTestResult{
		Timestamp: time.Now(),
		Status:    "ok",
	}

	// 构建单轮对话请求
	chatReq := ChatRequest{
		Messages: []Message{
			{Role: "user", Content: req.Prompt},
		},
		Model:  req.Model,
		Search: req.Search,
		Agent:  req.Agent,
	}

	chatResult, err := routeChatEx(chatReq.Model, chatReq.Messages, ChatOpts{}, "test")
	result.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		recordChatTest(result)
		writeJSON(w, result)
		return
	}

	result.Content = chatResult.Content
	result.Backend = chatResult.Backend
	result.Usage = chatResult.Usage
	recordChatTest(result)
	writeJSON(w, result)
}

func handleChatTestHistory(w http.ResponseWriter, r *http.Request) {
	chatTestMu.RLock()
	hist := make([]ChatTestResult, len(chatTestHistory))
	copy(hist, chatTestHistory)
	chatTestMu.RUnlock()
	writeJSON(w, map[string]interface{}{"history": hist, "total": len(hist)})
}

var (
	chatTestMu      sync.RWMutex
	chatTestHistory []ChatTestResult
)

func recordChatTest(r ChatTestResult) {
	chatTestMu.Lock()
	chatTestHistory = append(chatTestHistory, r)
	if len(chatTestHistory) > 50 {
		chatTestHistory = chatTestHistory[len(chatTestHistory)-50:]
	}
	chatTestMu.Unlock()
}
