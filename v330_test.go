package main

// ===================== v3.3.0 转换中枢与模型库测试 =====================
//
// 覆盖：能力推断 / 三层数据（override > registry > inferred）/ 能力需求推导 /
// 能力感知改道 / custom 协议适配器端到端 / 多模态消息解析与出站重建 /
// parseOpenAIFull 富解析 / extractJSONPath。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- 1. 能力推断与规范化 ----------

func TestV330InferCaps(t *testing.T) {
	cases := []struct {
		model string
		want  []string
	}{
		{"qwen2-vl-7b", []string{"vision", "tools", "longContext"}},
		{"gpt-4o", []string{"vision", "tools"}},
		{"deepseek-reasoner", []string{"tools", "longContext", "reasoning"}},
		{"llama-3.1-8b", []string{"tools"}},
		{"llava-13b", []string{"vision"}},
		{"qwen2.5-128k", []string{"tools", "longContext"}},
		{"some-json-model", []string{"json"}},
		{"tiny-unknown", nil},
	}
	for _, c := range cases {
		got := inferModelCapabilities(c.model)
		if !capsContain(got, c.want) || !capsContain(c.want, got) {
			t.Errorf("inferModelCapabilities(%q) = %v, want %v", c.model, got, c.want)
		}
	}
}

func TestV330NormalizeCaps(t *testing.T) {
	got := normalizeCaps([]string{"tools", "Tools", " vision ", "bogus", "tools"})
	if len(got) != 2 || got[0] != "tools" || got[1] != "vision" {
		t.Errorf("normalizeCaps 去重/过滤/排序失败: %v", got)
	}
}

// ---------- 2. 三层数据优先级 ----------

func TestV330ModelCapabilitiesFor(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	cfgMu.Lock()
	orig := cfg.V33Config.ModelCaps
	cfg.V33Config.ModelCaps = map[string][]string{"openai/gpt-4o": {"tools"}, "bare-model": {"vision"}}
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg.V33Config.ModelCaps = orig
		cfgMu.Unlock()
	}()

	// override（provider/model 全名）
	caps, src := modelCapabilitiesFor("openai", "gpt-4o")
	if src != "override" || len(caps) != 1 || caps[0] != "tools" {
		t.Errorf("override 层未生效: caps=%v src=%s", caps, src)
	}
	// override（裸模型名）
	caps, src = modelCapabilitiesFor("", "bare-model")
	if src != "override" || len(caps) != 1 || caps[0] != "vision" {
		t.Errorf("裸模型名 override 未生效: caps=%v src=%s", caps, src)
	}
	// registry（openai.json modelCaps.gpt-4o: vision/tools/json/longContext）
	caps, src = modelCapabilitiesFor("openai", "gpt-4o-mini")
	if src != "registry" || !capsContain(caps, []string{"vision", "tools", "json"}) {
		t.Errorf("registry modelCaps 未生效: caps=%v src=%s", caps, src)
	}
	// registry defaultCaps（anthropic）
	caps, src = modelCapabilitiesFor("anthropic", "claude-some-new")
	if src != "registry" || !capsContain(caps, []string{"vision", "tools"}) {
		t.Errorf("registry defaultCaps 未生效: caps=%v src=%s", caps, src)
	}
	// inferred 兜底
	_, src = modelCapabilitiesFor("nonexistent-provider", "llava-x")
	if src != "inferred" {
		t.Errorf("未知 provider 应走 inferred，实际 %s", src)
	}
}

// ---------- 3. 能力需求推导 ----------

func TestV330CapabilityNeeds(t *testing.T) {
	// 图片 → vision
	needs := capabilityNeeds([]Message{{Role: "user", Content: "看图", Images: []string{"data:image/png;base64,AAAA"}}}, nil)
	if !capsContain(needs, []string{capVision}) || len(needs) != 1 {
		t.Errorf("带图消息应推导 vision: %v", needs)
	}
	// tools → tools
	needs = capabilityNeeds([]Message{{Role: "user", Content: "hi"}}, json.RawMessage(`[{"type":"function","function":{"name":"f"}}]`))
	if !capsContain(needs, []string{capTools}) {
		t.Errorf("带 tools 应推导 tools: %v", needs)
	}
	// null tools 不算
	needs = capabilityNeeds([]Message{{Role: "user", Content: "hi"}}, json.RawMessage(`null`))
	if len(needs) != 0 {
		t.Errorf("null tools 不应推导能力: %v", needs)
	}
	// > 32k 估算 tokens → longContext
	long := strings.Repeat("a", 200*1024)
	needs = capabilityNeeds([]Message{{Role: "user", Content: long}}, nil)
	if !capsContain(needs, []string{capLongContext}) {
		t.Errorf("超长输入应推导 longContext: %v", needs)
	}
}

// ---------- 4. 能力感知改道 ----------

func TestV330CapabilityRoute(t *testing.T) {
	// capabilityHub 模块默认开；确保默认态
	initModuleDefaults()
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	// 无需求：原样放行
	m, routed, _ := capabilityRoute("openai/gpt-4o-mini", nil)
	if routed || m != "openai/gpt-4o-mini" {
		t.Errorf("无能力需求不应改道: %s %v", m, routed)
	}
	// 模型已具备能力：原样放行
	m, routed, _ = capabilityRoute("openai/gpt-4o", []string{capVision})
	if routed || m != "openai/gpt-4o" {
		t.Errorf("模型具备能力不应改道: %s %v", m, routed)
	}
	// 模型缺能力：要么放行（无已就绪候选），要么改道到具备能力的模型
	m, routed, _ = capabilityRoute("nonexistent/tiny", []string{capVision})
	if routed {
		pid, rest, ok := splitProviderModel(m)
		if !ok {
			t.Fatalf("改道目标应为 provider/model 形态: %q", m)
		}
		caps, _ := modelCapabilitiesFor(pid, rest)
		if !capsContain(caps, []string{capVision}) {
			t.Errorf("改道目标 %s 不具备 vision 能力: %v", m, caps)
		}
	} else if m != "nonexistent/tiny" {
		t.Errorf("未改道时应原样放行: %q", m)
	}
}

// ---------- 5. custom 协议适配器端到端 ----------

func TestV330CustomProviderEndToEnd(t *testing.T) {
	var gotBody map[string]interface{}
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/chat" {
			t.Errorf("custom path 不符: %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte(`{"result":{"answer":{"text":"你好，来自自定义后端"}},"usage":{"total":9}}`))
	}))
	defer ts.Close()

	spec := ProviderSpec{
		ID: "custom-test", Name: "Custom Test", Kind: "cloud", Protocol: "custom",
		BaseURL: ts.URL, ChatPath: "/v3/chat",
		Custom: &CustomAdapterSpec{
			Method: "POST", Path: "/v3/chat",
			Headers: map[string]string{"Authorization": "Bearer {{.Key}}"},
			Body: map[string]interface{}{
				"model":  "{{.Model}}",
				"prompt": "{{.User}}",
				"system": "{{.System}}",
				"all":    "{{.MessagesJSON}}",
			},
			ResponsePath: "result.answer.text",
		},
	}
	msgs := []Message{
		{Role: "system", Content: "你是助手"},
		{Role: "user", Content: "打个招呼"},
	}
	content, _, err := callCustomProvider(spec, "my-model", msgs, "sk-test-key", "")
	if err != nil {
		t.Fatalf("custom 协议调用失败: %v", err)
	}
	if content != "你好，来自自定义后端" {
		t.Errorf("responsePath 取值错误: %q", content)
	}
	if gotAuth != "Bearer sk-test-key" {
		t.Errorf("模板化 Header 失败: %q", gotAuth)
	}
	if gotBody["model"] != "my-model" || gotBody["prompt"] != "打个招呼" || gotBody["system"] != "你是助手" {
		t.Errorf("请求体模板展开错误: %v", gotBody)
	}
	if _, ok := gotBody["all"].(string); !ok || !strings.Contains(gotBody["all"].(string), "打个招呼") {
		t.Errorf("MessagesJSON 展开错误: %v", gotBody["all"])
	}
}

func TestV330CustomProviderBadPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"foo": "bar"}`))
	}))
	defer ts.Close()
	spec := ProviderSpec{ID: "c", Protocol: "custom", BaseURL: ts.URL,
		Custom: &CustomAdapterSpec{Path: "/", Body: map[string]interface{}{"q": "{{.User}}"}, ResponsePath: "a.b.c"}}
	_, _, err := callCustomProvider(spec, "m", []Message{{Role: "user", Content: "x"}}, "", "")
	if err == nil || !strings.Contains(err.Error(), "responsePath") {
		t.Errorf("未命中 responsePath 应报错，实际: %v", err)
	}
}

// ---------- 6. 多模态消息解析 ----------

func TestV330MessageUnmarshalMultimodal(t *testing.T) {
	raw := `{"role":"user","content":[
		{"type":"text","text":"这是什么"},
		{"type":"image_url","image_url":{"url":"data:image/png;base64,QUJD"}},
		{"type":"file","file":{"data":"data:application/pdf;base64,AA"}}
	]}`
	var m Message
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("多模态 content 解析失败: %v", err)
	}
	if m.Role != "user" || m.Content != "这是什么" {
		t.Errorf("文本合并错误: %+v", m)
	}
	if len(m.Images) != 2 {
		t.Fatalf("应提取 2 个多模态附件（image + file），实际 %d", len(m.Images))
	}
	if m.Images[0] != "data:image/png;base64,QUJD" || m.Images[1] != "data:application/pdf;base64,AA" {
		t.Errorf("附件 URL 提取错误: %v", m.Images)
	}
	// OpenAI 兼容 file_data 形态
	var m3 Message
	if err := json.Unmarshal([]byte(`{"role":"user","content":[{"type":"text","text":"f"},{"type":"file","file":{"file_data":"data:text/csv;base64,QQ=="}}]}`), &m3); err != nil || len(m3.Images) != 1 || m3.Images[0] != "data:text/csv;base64,QQ==" {
		t.Errorf("file_data 形态解析失败: %+v err=%v", m3, err)
	}
	// 字符串 content 兼容
	var m2 Message
	if err := json.Unmarshal([]byte(`{"role":"user","content":"纯文本"}`), &m2); err != nil || m2.Content != "纯文本" {
		t.Errorf("字符串 content 兼容失败: %+v err=%v", m2, err)
	}
}

func TestV330OpenAIMessagesMultimodal(t *testing.T) {
	// 纯文本：字节级保持 {"role","content"} 字符串形态
	plain := openAIMessages([]Message{{Role: "user", Content: "hi"}})
	pm, _ := plain[0].(map[string]interface{})
	if _, ok := pm["content"].(string); !ok {
		t.Errorf("纯文本消息 content 应保持字符串: %v", plain[0])
	}
	// 带图：展开 content 数组
	img := []Message{{Role: "user", Content: "看图", Images: []string{"data:image/png;base64,QUJD"}}}
	mm := openAIMessages(img)
	um, _ := mm[0].(map[string]interface{})
	parts, ok := um["content"].([]map[string]interface{})
	if !ok {
		parts2, ok2 := um["content"].([]interface{})
		if !ok2 {
			t.Fatalf("带图消息应展开为 content 数组: %v", um["content"])
		}
		_ = parts2
		return
	}
	if len(parts) != 2 || parts[0]["type"] != "text" || parts[1]["type"] != "image_url" {
		t.Errorf("content 数组结构错误: %v", parts)
	}
}

func TestV330AnthropicGeminiMultimodal(t *testing.T) {
	img := []Message{{Role: "user", Content: "看图", Images: []string{"data:image/png;base64,QUJD"}}}
	ab, err := buildAnthropicBody("claude-x", img)
	if err != nil {
		t.Fatalf("anthropic 多模态构建失败: %v", err)
	}
	if !strings.Contains(string(ab), `"source"`) || !strings.Contains(string(ab), `"base64"`) || !strings.Contains(string(ab), "QUJD") {
		t.Errorf("anthropic body 缺 base64 图片块: %s", ab)
	}
	gb, err := buildGeminiBody("gemini-x", img)
	if err != nil {
		t.Fatalf("gemini 多模态构建失败: %v", err)
	}
	if !strings.Contains(string(gb), `"inline_data"`) || !strings.Contains(string(gb), "QUJD") {
		t.Errorf("gemini body 缺 inline_data 块: %s", gb)
	}
}

// ---------- 7. parseOpenAIFull / extractJSONPath ----------

func TestV330ParseOpenAIFull(t *testing.T) {
	data := []byte(`{"choices":[{"message":{"content":"答案","tool_calls":[
		{"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"北京\"}"}}]}}],
		"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
	content, usage, tools := parseOpenAIFull(data)
	if content != "答案" {
		t.Errorf("content 解析错误: %q", content)
	}
	if usage.PromptTokens != 10 || usage.CompletionTokens != 5 || usage.TotalTokens != 15 {
		t.Errorf("usage 解析错误: %+v", usage)
	}
	if len(tools) != 1 || tools[0].Function.Name != "get_weather" || tools[0].ID != "c1" {
		t.Errorf("tool_calls 解析错误: %+v", tools)
	}
	// type 缺省补 function
	data2 := []byte(`{"choices":[{"message":{"content":"x","tool_calls":[{"id":"c2","function":{"name":"f"}}]}}]}`)
	_, _, tools2 := parseOpenAIFull(data2)
	if len(tools2) != 1 || tools2[0].Type != "function" {
		t.Errorf("tool_calls type 缺省未补: %+v", tools2)
	}
	// 非 openai JSON：整包文本兜底
	data3 := []byte(`{"error":"boom"}`)
	c3, _, _ := parseOpenAIFull(data3)
	if c3 != string(data3) {
		t.Errorf("非 openai JSON 应整包兜底: %q", c3)
	}
}

func TestV330ExtractJSONPath(t *testing.T) {
	data := []byte(`{"a":{"b":[{"c":"hit"},{"c":"miss"}]},"n":42,"s":"str"}`)
	if v, ok := extractJSONPath(data, "a.b.0.c"); !ok || v != "hit" {
		t.Errorf("嵌套数组路径取值错误: %q %v", v, ok)
	}
	if v, ok := extractJSONPath(data, "s"); !ok || v != "str" {
		t.Errorf("根字符串路径取值错误: %q %v", v, ok)
	}
	if v, ok := extractJSONPath(data, "n"); !ok || v != "42" {
		t.Errorf("数值叶子应 JSON 序列化: %q %v", v, ok)
	}
	if _, ok := extractJSONPath(data, "a.b.9.c"); ok {
		t.Errorf("越界索引应失败")
	}
	if _, ok := extractJSONPath(data, ""); ok {
		t.Errorf("空路径应失败")
	}
	if _, ok := extractJSONPath(data, "x.y"); ok {
		t.Errorf("未知键应失败")
	}
}

// ---------- 8. 模块注册与纯文本路径回归 ----------

func TestV330CapabilityHubModule(t *testing.T) {
	initModuleDefaults()
	found := false
	for _, m := range moduleRegistry {
		if m.ID == "capabilityHub" {
			found = true
			if !m.Default {
				t.Errorf("capabilityHub 应默认开启")
			}
			if !containsStr(m.Deps, "chatApi") {
				t.Errorf("capabilityHub 应依赖 chatApi")
			}
		}
	}
	if !found {
		t.Fatalf("capabilityHub 未注册进 moduleRegistry")
	}
	if !moduleEnabledByID("capabilityHub") {
		t.Errorf("capabilityHub 默认态应为开启")
	}
}

func TestV330PlainTextBodyUnchanged(t *testing.T) {
	// 纯文本路径字节级回归：与 v3.2.x 完全一致的请求体（无 tools、无图）
	body, err := buildOpenAIBody("m", []Message{
		{Role: "system", Content: "s"},
		{Role: "user", Content: "u"},
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	var m map[string]interface{}
	json.Unmarshal(body, &m)
	msgs := m["messages"].([]interface{})
	m0 := msgs[0].(map[string]interface{})
	if _, ok := m0["content"].(string); !ok {
		t.Errorf("纯文本 system 消息 content 应为字符串: %v", m0)
	}
	if _, present := m["tools"]; present {
		t.Errorf("无 tools 请求不应携带 tools 字段")
	}
}

// ---------- 9. provider 注册表 v3.3.0 字段 ----------

func TestV330ProviderApplyURL(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	cloud, _ := providerCount()
	if cloud < 20 {
		t.Errorf("云端 provider 数量异常: %d", cloud)
	}
	withApply := 0
	for _, id := range pregOrderList() {
		s, ok := providerSpec(id)
		if !ok || s.Kind != "cloud" {
			continue
		}
		if s.ApplyURL != "" {
			withApply++
		}
		if s.Custom != nil && s.Protocol != "custom" {
			t.Errorf("provider %s：携带 Custom 配置但协议非 custom", id)
		}
	}
	if withApply < 20 {
		t.Errorf("带 applyUrl 的云端 provider 应 ≥20，实际 %d", withApply)
	}
	// openai 能力三层来源：registry 层应有 modelCaps
	caps, src := modelCapabilitiesFor("openai", "gpt-4o")
	if src != "override" && src != "registry" {
		t.Errorf("openai/gpt-4o 应有 registry 层数据，实际 %s (%v)", src, caps)
	}
}

// pregOrderList 测试辅助：注册表顺序快照
func pregOrderList() []string {
	preg.mu.RLock()
	defer preg.mu.RUnlock()
	out := make([]string, 0, len(preg.order))
	out = append(out, preg.order...)
	return out
}
