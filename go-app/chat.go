package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ChatRequest struct {
	Messages []Message `json:"messages"`
	Model    string    `json:"model"`
	Search   bool      `json:"search"`
	Agent    bool      `json:"agent"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Choices []Choice `json:"choices"`
	Model   string   `json:"model"`
}

type Choice struct {
	Message Message `json:"message"`
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}
	if len(req.Messages) == 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "No messages"})
		return
	}
	content, backend, err := routeChat(req.Model, req.Messages)
	reply := content
	if err != nil {
		reply = fmt.Sprintf("[%s 后端不可用] %s\n\n最后消息: %s", backend, err.Error(), req.Messages[len(req.Messages)-1].Content)
	}
	if req.Search {
		reply += "\n\n[Web search enabled]"
	}
	if req.Agent {
		reply += "\n\n[Agent boost enabled]"
	}
	mu.Lock()
	successReq++
	mu.Unlock()
	writeJSON(w, ChatResponse{
		Choices: []Choice{{Message: Message{Role: "assistant", Content: reply}}},
		Model:   req.Model,
	})
}

func handleUrgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}
	prompt := body["prompt"]
	msgs := []Message{{Role: "user", Content: prompt}}
	content, backend, err := routeChat("qwen2.5-3b", msgs)
	if err != nil {
		content = "Urgent: " + err.Error()
	}
	writeJSON(w, map[string]interface{}{"success": true, "response": content, "agent": "urgent-responder", "backend": backend})
}

func handleAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	agentID := ""
	if len(parts) >= 5 {
		agentID = parts[4]
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}
	prompt := body["prompt"]
	sysPrompt := getAgentPrompt(agentID)
	msgs := []Message{{Role: "system", Content: sysPrompt}, {Role: "user", Content: prompt}}
	content, backend, err := routeChat("", msgs)
	if err != nil {
		content = fmt.Sprintf("Agent [%s]: %s", agentID, err.Error())
	}
	writeJSON(w, map[string]interface{}{"success": true, "agent": agentID, "backend": backend, "response": content})
}

func getAgentPrompt(id string) string {
	switch id {
	case "code-assistant":
		return "你是代码助手，擅长编程、代码审查与调试，用简洁的中文回答。"
	case "writing-assistant":
		return "你是写作助手，擅长写作、润色与翻译，输出高质量中文。"
	case "urgent-responder":
		return "你是紧急响应助手，回答简洁快速，直接给出结论。"
	case "security-analyst":
		return "你是安全分析助手，专注安全审计与威胁分析。"
	case "translator":
		return "你是翻译助手，准确进行中英互译。"
	case "summarizer":
		return "你是摘要助手，提取要点并总结。"
	case "data-analyst":
		return "你是数据分析助手，分析数据并提供洞察。"
	default:
		return "你是乐于助人的助手。"
	}
}

func routeChat(model string, msgs []Message) (string, string, error) {
	backend := "llama"
	target := model
	if strings.HasPrefix(model, "lmstudio/") {
		backend = "lmstudio"
		target = strings.TrimPrefix(model, "lmstudio/")
	} else if strings.HasPrefix(model, "ollama/") {
		backend = "ollama"
		target = strings.TrimPrefix(model, "ollama/")
	} else if model == "" || model == "auto" || model == "local" || model == "cloud-default" {
		running, cur := modelState()
		if running {
			backend = "llama"
			target = cur
		} else if lmsReachable() {
			backend = "lmstudio"
			target = ""
		} else if ollamaReachable() {
			backend = "ollama"
			target = ""
		} else {
			return "", backend, fmt.Errorf("无可用后端：请先启动本地模型，或启动 LM Studio / Ollama")
		}
	} else {
		if findGGUFFile(model) != "" {
			backend = "llama"
			target = model
		} else if isCloudModel(model) {
			backend = "cloud"
			target = model
		} else if lmsReachable() {
			backend = "lmstudio"
			target = model
		} else if ollamaReachable() {
			backend = "ollama"
			target = model
		} else if _, cur := modelState(); findGGUFFile(cur) != "" {
			backend = "llama"
			target = cur
		} else {
			return "", backend, fmt.Errorf("未知模型 %s", model)
		}
	}

	switch backend {
	case "llama":
		if running, _ := modelState(); !running {
			if err := startLocalModel(target); err != nil {
				return "", backend, err
			}
		}
		return callOpenAICompatible(fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", modelPort), target, msgs)
	case "lmstudio":
		return callOpenAICompatible(lmStudioBase+"/v1/chat/completions", target, msgs)
	case "ollama":
		return callOllamaChat(target, msgs)
	case "cloud":
		return callCloudChat(target, msgs)
	default:
		for _, cc := range allCloudCfgs() {
			for _, mdl := range cc.Models {
				if mdl == target {
					return callOpenAICompatibleWithKey(strings.TrimSuffix(cc.BaseURL, "/")+"/chat/completions", cc.APIKey, mdl, msgs)
				}
			}
		}
		return "", backend, fmt.Errorf("无可用云端后端")
	}
}

func isCloudModel(model string) bool {
	for _, cc := range allCloudCfgs() {
		for _, mdl := range cc.Models {
			if mdl == model {
				return true
			}
		}
	}
	return false
}

func callOpenAICompatible(endpoint, model string, msgs []Message) (string, string, error) {
	return callOpenAICompatibleWithKey(endpoint, "", model, msgs)
}

func callOpenAICompatibleWithKey(endpoint, apiKey, model string, msgs []Message) (string, string, error) {
	body := map[string]interface{}{
		"model":      model,
		"messages":   msgs,
		"max_tokens": 2048,
		"stream":     false,
	}
	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := httpClientLong.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("上游 %s", strings.TrimSpace(string(data)))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return string(data), "", nil
	}
	if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if msg, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := msg["content"].(string); ok {
					return content, "", nil
				}
			}
		}
	}
	return string(data), "", nil
}

func callOllamaChat(model string, msgs []Message) (string, string, error) {
	var om []map[string]string
	for _, m := range msgs {
		om = append(om, map[string]string{"role": m.Role, "content": m.Content})
	}
	body := map[string]interface{}{
		"model":    model,
		"messages": om,
		"stream":   false,
	}
	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", ollamaBase+"/api/chat", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClientShort.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("ollama %s", strings.TrimSpace(string(data)))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return string(data), "", nil
	}
	if msg, ok := result["message"].(map[string]interface{}); ok {
		if content, ok := msg["content"].(string); ok {
			return content, "", nil
		}
	}
	return string(data), "", nil
}

func callCloudChat(model string, msgs []Message) (string, string, error) {
	for _, cc := range allCloudCfgs() {
		for _, mdl := range cc.Models {
			if mdl == model {
				return callOpenAICompatibleWithKey(strings.TrimSuffix(cc.BaseURL, "/")+"/chat/completions", cc.APIKey, mdl, msgs)
			}
		}
	}
	return "", "cloud", fmt.Errorf("云端模型 %s 未配置", model)
}

func handleV1(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.HasPrefix(path, "/v1") && strings.HasSuffix(path, "/models") {
		if r.Method != http.MethodGet {
			writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": map[string]string{"message": "Method not allowed"}})
			return
		}
		ms := getModels()
		data := make([]map[string]interface{}, 0, len(ms))
		for _, m := range ms {
			data = append(data, map[string]interface{}{
				"id":       m.ID,
				"object":   "model",
				"created":  startTime.Unix(),
				"owned_by": m.Backend,
			})
		}
		writeJSON(w, map[string]interface{}{"object": "list", "data": data})
		return
	}

	if strings.HasPrefix(path, "/v1") && strings.HasSuffix(path, "/chat/completions") {
		if r.Method != http.MethodPost {
			writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": map[string]string{"message": "Method not allowed"}})
			return
		}
		var req ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]interface{}{"error": map[string]string{"message": "Invalid request"}})
			return
		}
		if len(req.Messages) == 0 {
			writeJSONStatus(w, http.StatusBadRequest, map[string]interface{}{"error": map[string]string{"message": "No messages"}})
			return
		}
		content, backend, err := routeChat(req.Model, req.Messages)
		if err != nil {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{"error": map[string]interface{}{"message": err.Error(), "backend": backend}})
			return
		}
		mu.Lock()
		successReq++
		mu.Unlock()
		writeJSON(w, map[string]interface{}{
			"id":      "chatcmpl-tars-" + strconv.FormatInt(time.Now().Unix(), 10),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   req.Model,
			"backend": backend,
			"choices": []map[string]interface{}{
				{
					"index":         0,
					"message":       map[string]interface{}{"role": "assistant", "content": content},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
		})
		return
	}

	writeJSONStatus(w, http.StatusNotFound, map[string]interface{}{"error": map[string]interface{}{"message": "Not found: " + path}})
}

func handleV1Root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1" || r.URL.Path == "/v1/" {
		writeJSON(w, map[string]interface{}{
			"name":      "TarsSecureGuard",
			"version":   version,
			"endpoints": []string{"/v1/models", "/v1/chat/completions"},
		})
		return
	}
	handleV1(w, r)
}
