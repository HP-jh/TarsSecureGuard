package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ===================== 聊天 API =====================
type ChatRequest struct {
	Messages []Message `json:"messages"`
	Model    string    `json:"model"`
	Search   bool      `json:"search"`
	Agent    bool      `json:"agent"`
	// v3.2.2 上下文拓展：请求体可选 context 段——服务端按租户隔离策略把共享信息 /
	// 共享记忆组装为 system 前缀注入（注入内容来自已过隔离的存储，随后照常过
	// PII 脱敏与语义分级分流，不引入新旁路）。缺省不注入，行为与旧版一致。
	Context *ChatContextOpts `json:"context,omitempty"`
}

// ChatContextOpts chat 请求的上下文注入选项
type ChatContextOpts struct {
	SharedMemory bool   `json:"sharedMemory"`
	SharedInfo   bool   `json:"sharedInfo"`
	MaxChars     int    `json:"maxChars"`
	Topic        string `json:"topic"`
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
	// v3.2.2 上下文拓展：context 段存在且开启任一来源时，组装上下文包注入为
	// 首条 system 消息（在 PII 脱敏/语义分流之前注入——注入文本同样过安全链）
	if req.Context != nil && (req.Context.SharedMemory || req.Context.SharedInfo) {
		if id, ok := identityFromRequest(r); ok {
			pack := buildContextPack(id, ContextBuildOpts{
				IncludeSharedInfo:   req.Context.SharedInfo,
				IncludeSharedMemory: req.Context.SharedMemory,
				MaxChars:            req.Context.MaxChars,
				Topic:               req.Context.Topic,
			})
			req.Messages = append([]Message{{Role: "system", Content: pack.Text}}, req.Messages...)
		}
	}
	// PII 脱敏：在路由到后端前对消息内容脱敏
	req.Messages = maskPIIInMessages(req.Messages)
	// v3.0.0 B 线：语义分级分流（静态 deny / 灰区送本地小模型 / fail-close）
	if !semanticGuardChat(w, r, &req) {
		return
	}
	// v3.0.0 C 线：两阶段路由（静态优先 + bandit 优化自动分支）
	// v3.0.4 [MT_ROUTER]：叠加租户/组路由偏好（Rule A 无值取全集；组优先于租户）
	// v3.0.5：透传 trace_id（纯观测；X-Trace-Id 响应头 + 后端出站头 + 路由/后端 span）
	id, _ := identityFromRequest(r)
	pref := tenantPreferredBackends(id.Tenant, id.Groups)
	content, backend, _, err := routeChatSmartT(req.Model, req.Messages, id.Role, pref, traceFromReq(r))
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
	// v3.0.4 [MT_QUOTA]：成功完成的请求记入日配额（tokens 按字符数/4 估算）
	if err == nil {
		inTok := int64(0)
		for _, m := range req.Messages {
			inTok += estimateTokens(m.Content)
		}
		quotaRecord(id.Tenant, id.Name, id.Groups, inTok+estimateTokens(reply))
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
	// v2.0.0：自定义 agent 角色（customAgents 模块开启时可用，默认系统提示词兜底）
	if moduleEnabledByID("customAgents") {
		if a, ok := findCustomAgentPrompt(id); ok {
			return a.Prompt
		}
	}
	switch id {
	case "code-assistant":
		// v3.2.0 提示词打磨：明确能力边界与不确定性表述（accuracy），结构扁平便于 i18n
		return "你是代码助手，擅长编程、代码审查与调试。要求：用简洁的中文回答；给出可运行的示例；不确定时明确说明，不要猜测 API 或库的行为。"
	case "writing-assistant":
		return "你是写作助手，擅长写作、润色与翻译。要求：输出高质量中文；保持原文含义不变；改写时说明主要改动。"
	case "urgent-responder":
		return "你是紧急响应助手。要求：先给结论，再给依据；回答不超过三句话；信息不足时直接说明缺什么。"
	case "security-analyst":
		return "你是安全分析助手，专注安全审计与威胁分析。要求：区分「已确认事实」与「推测」；给出可执行的加固建议；不提供攻击利用细节。"
	case "translator":
		return "你是翻译助手，进行中英互译。要求：忠实原文，不增删含义；专业术语保留英文并附中文注释；不确定的术语标注说明。"
	case "summarizer":
		return "你是摘要助手，提取要点并总结。要求：只基于原文内容，不添加原文没有的信息；按要点列出，标注每条要点对应的依据。"
	case "data-analyst":
		return "你是数据分析助手，分析数据并提供洞察。要求：结论必须基于给定数据；区分数据支持的结论与你的推断；数据不足时明确指出。"
	default:
		return "你是乐于助人的助手。要求：回答准确、简洁；不确定时明确说明；不编造事实、引用或数据。"
	}
}

// ===================== 模型路由 =====================
// routeChat 静态路由。v3.0.5：可选 trace 变长参数（纯观测）——透传至出站
// 后端请求（X-Trace-Id 头）与后端 span；省略时行为与 v3.0.4 完全一致。
func routeChat(model string, msgs []Message, trace ...string) (string, string, error) {
	obsTr := ""
	if len(trace) > 0 {
		obsTr = trace[0]
	}
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
	} else if pid, rest, ok := splitProviderModel(model); ok {
		// v3.2.0 provider-registry 显式路由："anthropic/claude-sonnet-4-5" 这类
		// "providerId/model" 形式优先于既有本地/云端判定
		spec, _ := providerSpec(pid)
		if !moduleEnabledByID("cloudModels") && spec.Kind == "cloud" {
			return "", pid, fmt.Errorf("云端模型模块已关闭（modules.cloudModels=false）")
		}
		content, err := callProviderChat(spec, rest, msgs, "", obsTr)
		return content, pid, err
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
		if !moduleEnabledByID("localModels") {
			return "", backend, fmt.Errorf("本地模型模块已关闭（modules.localModels=false）")
		}
		if running, _ := modelState(); !running {
			if err := startLocalModel(target); err != nil {
				return "", backend, err
			}
		}
		// v2.0.0 直连层切换点：direct.transport = native | grpc-sidecar（边车不可用自动回落 native）
		ep, err := directChatEndpoint()
		if err != nil {
			return "", backend, err
		}
		return callOpenAICompatible(ep, target, msgs, obsTr)
	case "lmstudio", "ollama":
		if !moduleEnabledByID("localModels") {
			return "", backend, fmt.Errorf("本地模型模块已关闭（modules.localModels=false）")
		}
		if backend == "lmstudio" {
			return callOpenAICompatible(lmStudioBase+"/v1/chat/completions", target, msgs, obsTr)
		}
		return callOllamaChat(target, msgs, obsTr)
	case "cloud":
		if !moduleEnabledByID("cloudModels") {
			return "", backend, fmt.Errorf("云端模型模块已关闭（modules.cloudModels=false）")
		}
		// v3.2.0：注册表 provider 的裸模型名（无 providerId 前缀）在此接管；
		// 未命中再回落 v3.0.x 的 legacy cloud 配置（config.json cloud 段）
		if spec, ok := findCloudProviderByModel(target); ok {
			content, err := callProviderChat(spec, target, msgs, "", obsTr)
			return content, spec.ID, err
		}
		return callCloudChat(target, msgs, obsTr)
	default:
		for _, cc := range allCloudCfgs() {
			for _, mdl := range cc.Models {
				if mdl == target {
					return callOpenAICompatibleWithKey(strings.TrimSuffix(cc.BaseURL, "/")+"/chat/completions", cc.APIKey, mdl, msgs, obsTr)
				}
			}
		}
		return "", backend, fmt.Errorf("无可用云端后端")
	}
}

// backendNameFromURL 从出站 URL 提取低基数后端标签（仅用于观测指标/span，
// 枚举值：llama/lmstudio/ollama/cloud/local/unknown——不含任何路径或密钥）
func backendNameFromURL(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "unknown"
	}
	host, portNo := u.Hostname(), u.Port()
	switch {
	case host == "lmstudio" || portNo == "1234": // LM Studio 默认端口
		return "lmstudio"
	case portNo == "1235": // llama-server 直连层默认端口
		return "llama"
	case host == "ollama" || portNo == "11434": // Ollama 默认端口
		return "ollama"
	case host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1":
		return "local"
	default:
		return "cloud"
	}
}

func isCloudModel(model string) bool {
	// v3.2.0：注册表云端 provider 的裸模型名也算「云端」——
	// 使 provider-registry 模型无需前缀即可路由（真正的「只写配置不改核心」）
	if _, ok := findCloudProviderByModel(model); ok {
		return true
	}
	for _, cc := range allCloudCfgs() {
		for _, mdl := range cc.Models {
			if mdl == model {
				return true
			}
		}
	}
	return false
}

// callOpenAICompatible v3.0.5：可选 trace 变长参数（纯观测：出站请求带 X-Trace-Id 头）。
func callOpenAICompatible(endpoint, model string, msgs []Message, trace ...string) (string, string, error) {
	var tr string
	if len(trace) > 0 {
		tr = trace[0]
	}
	return callOpenAICompatibleWithKey(endpoint, "", model, msgs, tr)
}

func callOpenAICompatibleWithKey(endpoint, apiKey, model string, msgs []Message, trace ...string) (string, string, error) {
	var tr string
	if len(trace) > 0 {
		tr = trace[0]
	}
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
	traceHeaderForward(req, tr) // v3.0.5：trace_id 透传至后端（空值 no-op）
	obsStart := time.Now()
	resp, err := httpClientLong.Do(req)
	if err != nil {
		obsRecordBackend(tr, backendNameFromURL(endpoint), false, time.Since(obsStart).Milliseconds(), 0)
		return "", "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	obsRecordBackend(tr, backendNameFromURL(endpoint), resp.StatusCode == 200, time.Since(obsStart).Milliseconds(), resp.StatusCode)
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

func callOllamaChat(model string, msgs []Message, trace ...string) (string, string, error) {
	var tr string
	if len(trace) > 0 {
		tr = trace[0]
	}
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
	traceHeaderForward(req, tr) // v3.0.5：trace_id 透传至后端（空值 no-op）
	obsStart := time.Now()
	resp, err := httpClientShort.Do(req)
	if err != nil {
		obsRecordBackend(tr, "ollama", false, time.Since(obsStart).Milliseconds(), 0)
		return "", "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	obsRecordBackend(tr, "ollama", resp.StatusCode == 200, time.Since(obsStart).Milliseconds(), resp.StatusCode)
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

func callCloudChat(model string, msgs []Message, trace ...string) (string, string, error) {
	var tr string
	if len(trace) > 0 {
		tr = trace[0]
	}
	for _, cc := range allCloudCfgs() {
		for _, mdl := range cc.Models {
			if mdl == model {
				return callOpenAICompatibleWithKey(strings.TrimSuffix(cc.BaseURL, "/")+"/chat/completions", cc.APIKey, mdl, msgs, tr)
			}
		}
	}
	return "", "cloud", fmt.Errorf("云端模型 %s 未配置", model)
}

// ===================== OpenAI 兼容 /v1 =====================
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
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{"error": map[string]string{"message": err.Error(), "backend": backend}})
			return
		}
		// v3.0.4 [MT_QUOTA]：OpenAI 兼容端点成功请求同样记入日配额
		if vid, ok := identityFromRequest(r); ok {
			inTok := int64(0)
			for _, m := range req.Messages {
				inTok += estimateTokens(m.Content)
			}
			quotaRecord(vid.Tenant, vid.Name, vid.Groups, inTok+estimateTokens(content))
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

	writeJSONStatus(w, http.StatusNotFound, map[string]interface{}{"error": map[string]string{"message": "Not found: " + path}})
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
