package main

// v4.10.1 Protocol Translator — Multi-Protocol Passthrough
// Kingdom 7 层归位：界·Domain = gateway / 门·Phylum = routing / 纲·Class = protocol-translator
//
// 借鉴 LLMux routes/v1/{anthropic,gemini,openai}.rs 思路（AGPL-3.0 隔离，Go 自研实现）：
// - 原生支持 OpenAI / Anthropic / Gemini 三种协议透传
// - 现有 /v1/chat/completions = OpenAI 兼容（保持不变）
// - 新增 /v1/messages = Anthropic Messages API
// - 新增 /v1beta/models/{model}:generateContent = Gemini GenerateContent API
// - 透传设计：body 原样转发，只改 auth header 和 model 字段

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ===================== Anthropic Protocol =====================

// AnthropicMessageRequest Anthropic Messages API 请求体（透传子集）
type AnthropicMessageRequest struct {
	Model       string          `json:"model"`
	Messages    []AnthropicMsg  `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	System      string          `json:"system,omitempty"`
	Stream      bool            `json:"stream,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
	Tools       json.RawMessage `json:"tools,omitempty"`
	ToolChoice  json.RawMessage `json:"tool_choice,omitempty"`
}

type AnthropicMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AnthropicMessageResponse 简化响应（只取 content）
type AnthropicMessageResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens              int64 `json:"input_tokens"`
		OutputTokens             int64 `json:"output_tokens"`
		CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	} `json:"usage"`
	StopReason string `json:"stop_reason"`
}

// handleV1AnthropicMessages POST /v1/messages — Anthropic 原生协议透传
func handleV1AnthropicMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": map[string]string{"message": "Method not allowed"}})
		return
	}
	var req AnthropicMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]interface{}{"error": map[string]string{"message": "Invalid request"}})
		return
	}
	if req.Model == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]interface{}{"error": map[string]string{"message": "model required"}})
		return
	}

	// 别名展开
	model, forcedPID, _ := expandModelAlias(req.Model)
	req.Model = model

	// 路由到 anthropic provider（或强制 provider）
	var spec ProviderSpec
	var ok bool
	if forcedPID != "" {
		spec, ok = providerSpec(forcedPID)
	} else {
		spec, ok = providerSpec("anthropic")
		if !ok {
			spec, ok = findProviderByProtocol("anthropic")
		}
	}
	if !ok {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{"error": map[string]string{"message": "Anthropic provider not configured"}})
		return
	}

	result, err := callAnthropicPassthrough(spec, req, r)
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{"error": map[string]string{"message": err.Error()}})
		return
	}
	writeJSON(w, result)
}

// callAnthropicPassthrough 向 Anthropic 兼容端点透传 Messages 请求
func callAnthropicPassthrough(spec ProviderSpec, req AnthropicMessageRequest, r *http.Request) (map[string]interface{}, error) {
	base, _ := providerEffectiveURL(spec)
	base = strings.TrimSuffix(base, "/")
	if !strings.HasSuffix(base, "/v1") {
		base += "/v1"
	}
	endpoint := base + "/messages"

	body, _ := json.Marshal(req)
	hreq, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("anthropic-version", "2023-06-01")

	apiKey, _ := providerAPIKey(spec)
	if apiKey != "" {
		hreq.Header.Set("x-api-key", apiKey)
	}
	traceHeaderForward(hreq, traceFromReq(r))

	obsStart := time.Now()
	resp, err := httpClientLong.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	obsRecordBackend(traceFromReq(r), backendNameFromURL(endpoint), resp.StatusCode == 200, time.Since(obsStart).Milliseconds(), resp.StatusCode)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upstream %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var anthResp AnthropicMessageResponse
	if err := json.Unmarshal(data, &anthResp); err != nil {
		// 非标准结构：原样回传
		var raw map[string]interface{}
		json.Unmarshal(data, &raw)
		return raw, nil
	}

	// 构造 OpenAI 兼容形态回传（便于客户端统一消费）
	content := ""
	for _, c := range anthResp.Content {
		if c.Type == "text" {
			content += c.Text
		}
	}
	return map[string]interface{}{
		"id":      "msg_" + strconv.FormatInt(time.Now().Unix(), 10),
		"type":    "message",
		"role":    "assistant",
		"model":   req.Model,
		"content": content,
		"usage": map[string]interface{}{
			"input_tokens":               anthResp.Usage.InputTokens,
			"output_tokens":              anthResp.Usage.OutputTokens,
			"cache_read_input_tokens":    anthResp.Usage.CacheReadInputTokens,
			"cache_creation_input_tokens": anthResp.Usage.CacheCreationInputTokens,
		},
		"stop_reason": anthResp.StopReason,
	}, nil
}

// ===================== Gemini Protocol =====================

// GeminiGenerateRequest Gemini generateContent 请求体
type GeminiGenerateRequest struct {
	Contents []GeminiContent `json:"contents"`
	// 保留其他字段透传
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text,omitempty"`
}

// handleV1BetaGeminiGenerate POST /v1beta/models/{model}:generateContent
func handleV1BetaGeminiGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": map[string]string{"message": "Method not allowed"}})
		return
	}
	// 从路径提取模型名：/v1beta/models/{model}:generateContent
	path := r.URL.Path
	model := extractGeminiModelFromPath(path)
	if model == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]interface{}{"error": map[string]string{"message": "model not found in path"}})
		return
	}

	bodyBytes, _ := io.ReadAll(r.Body)
	var req GeminiGenerateRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		// 无法解析也继续透传原 body
		req = GeminiGenerateRequest{}
	}

	// 别名展开
	model, forcedPID, _ := expandModelAlias(model)

	var spec ProviderSpec
	var ok bool
	if forcedPID != "" {
		spec, ok = providerSpec(forcedPID)
	} else {
		spec, ok = providerSpec("google-gemini")
		if !ok {
			spec, ok = findProviderByProtocol("gemini")
		}
	}
	if !ok {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{"error": map[string]string{"message": "Gemini provider not configured"}})
		return
	}

	result, err := callGeminiPassthrough(spec, model, bodyBytes, r)
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{"error": map[string]string{"message": err.Error()}})
		return
	}
	writeJSON(w, result)
}

// callGeminiPassthrough 向 Gemini 端点透传 generateContent
func callGeminiPassthrough(spec ProviderSpec, model string, body []byte, r *http.Request) (map[string]interface{}, error) {
	base, _ := providerEffectiveURL(spec)
	base = strings.TrimSuffix(base, "/")
	endpoint := base + "/v1beta/models/" + model + ":generateContent"

	hreq, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")

	apiKey, _ := providerAPIKey(spec)
	if apiKey != "" {
		// Gemini 官方用 query param key=；自定义代理可能用 Bearer
		if strings.Contains(base, "generativelanguage.googleapis.com") {
			q := hreq.URL.Query()
			q.Set("key", apiKey)
			hreq.URL.RawQuery = q.Encode()
		} else {
			hreq.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	traceHeaderForward(hreq, traceFromReq(r))

	obsStart := time.Now()
	resp, err := httpClientLong.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	obsRecordBackend(traceFromReq(r), backendNameFromURL(endpoint), resp.StatusCode == 200, time.Since(obsStart).Milliseconds(), resp.StatusCode)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upstream %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return map[string]interface{}{"raw": string(data)}, nil
	}
	return raw, nil
}

// ===================== Helpers =====================

func extractGeminiModelFromPath(path string) string {
	// /v1beta/models/{model}:generateContent
	prefix := "/v1beta/models/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	idx := strings.Index(rest, ":")
	if idx > 0 {
		return rest[:idx]
	}
	return rest
}

// findProviderByProtocol 按协议类型查找第一个启用的 provider
func findProviderByProtocol(protocol string) (ProviderSpec, bool) {
	preg.mu.RLock()
	defer preg.mu.RUnlock()
	for _, id := range preg.order {
		s := preg.specs[id]
		if !providerEnabled(s) {
			continue
		}
		if s.Protocol == protocol {
			return s, true
		}
	}
	return ProviderSpec{}, false
}

// traceFromReq 从请求提取 trace_id
func traceFromReq(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get("X-Trace-Id")
}
