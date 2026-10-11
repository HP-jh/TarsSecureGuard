package main

// v3.7.0 扩展器 / 一键配置器专项测试

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- 1. 目标注册表完整性 ----------

func TestV370TargetsRegistry(t *testing.T) {
	targets := extenderTargets()
	if len(targets) < 6 {
		t.Fatalf("目标数应 >= 6, got %d", len(targets))
	}
	ids := map[string]bool{}
	for _, tgt := range targets {
		if tgt.ID == "" || tgt.Name == "" || tgt.Homepage == "" {
			t.Errorf("目标 %+v 缺少基础字段", tgt.ID)
		}
		// license 矩阵红线：绝不出现 GPL 系
		lic := strings.ToUpper(tgt.License)
		if strings.Contains(lic, "GPL") {
			t.Errorf("目标 %s license 触红线: %s", tgt.ID, tgt.License)
		}
		// 每个目标必须能生成片段（不 panic、非空）
		sn := tgt.snippet(extenderBaseURL(), extenderDefaultKeySnippet, extenderDefaultModel)
		if sn.Code == "" || sn.Steps == "" {
			t.Errorf("目标 %s 片段不完整: %+v", tgt.ID, sn)
		}
		// 片段必须指向 TSG 端点
		if !strings.Contains(sn.Code, extenderBaseURL()) {
			t.Errorf("目标 %s 片段未包含 TSG 端点 %s", tgt.ID, extenderBaseURL())
		}
		// 探测函数可安全调用（不 panic）
		tgt.detect()
		ids[tgt.ID] = true
	}
	// 关键目标必须在册
	for _, want := range []string{"openclaw", "continue", "aider", "cline", "zoocode", "codex"} {
		if !ids[want] {
			t.Errorf("缺少关键目标 %s", want)
		}
	}
	// Roo Code 停摆警示
	for _, tgt := range targets {
		if tgt.ID == "roocode" {
			if tgt.Status != "warn" || tgt.Note == "" {
				t.Errorf("Roo Code 应标记 warn + 停摆提示")
			}
		}
	}
}

// ---------- 2. 片段内容正确性 ----------

func TestV370SnippetContent(t *testing.T) {
	base := extenderBaseURL()
	for _, tgt := range extenderTargets() {
		sn := tgt.snippet(base, extenderDefaultKeySnippet, extenderDefaultModel)
		// 默认密钥为占位符，不得内嵌真实密钥（密钥可能出现在 Code 或 Steps——如 codex 走环境变量）
		if !strings.Contains(sn.Code+sn.Steps, extenderDefaultKeySnippet) {
			t.Errorf("目标 %s 默认片段应使用占位密钥", tgt.ID)
		}
	}
	// 各家协议关键字抽查
	byID := func(id string) *extenderTarget {
		for _, x := range extenderTargets() {
			if x.ID == id {
				return x
			}
		}
		return nil
	}
	if sn := byID("openclaw").snippet(base, "K", "m1"); !strings.Contains(sn.Code, "providers") || !strings.Contains(sn.Code, "@ai-sdk/openai-compatible") {
		t.Errorf("OpenClaw 片段缺 provider 结构")
	}
	if sn := byID("continue").snippet(base, "K", "m1"); !strings.Contains(sn.Code, "apiBase") {
		t.Errorf("Continue 片段缺 apiBase")
	}
	if sn := byID("aider").snippet(base, "K", "m1"); !strings.Contains(sn.Code, "openai-api-base") {
		t.Errorf("Aider 片段缺 openai-api-base")
	}
	if sn := byID("codex").snippet(base, "K", "m1"); !strings.Contains(sn.Code, "model_providers") {
		t.Errorf("Codex 片段缺 model_providers")
	}
	// 自定义模型名透传
	if sn := byID("continue").snippet(base, "K", "glm-4-plus"); !strings.Contains(sn.Code, "glm-4-plus") {
		t.Errorf("自定义模型名未透传到片段")
	}
}

// ---------- 3. handler：GET 探测 ----------

func TestV370ExtenderGet(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/admin/v37/extender", nil)
	rec := httptest.NewRecorder()
	handleV37Extender(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET 应 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Version   string                   `json:"version"`
		BaseURL   string                   `json:"baseUrl"`
		ChatAPIOn bool                     `json:"chatApiOn"`
		Targets   []map[string]interface{} `json:"targets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Version != "4.6.0" {
		t.Errorf("version = %q, want 3.9.0", resp.Version)
	}
	if resp.BaseURL != extenderBaseURL() {
		t.Errorf("baseUrl = %q", resp.BaseURL)
	}
	if len(resp.Targets) != len(extenderTargets()) {
		t.Errorf("targets 数不符: %d", len(resp.Targets))
	}
	for _, t2 := range resp.Targets {
		if _, ok := t2["installed"]; !ok {
			t.Errorf("target %v 缺 installed 字段", t2["id"])
		}
		if _, ok := t2["license"]; !ok {
			t.Errorf("target %v 缺 license 字段", t2["id"])
		}
	}
	// 响应体不得出现真实网关密钥（GET 只探测，不嵌密钥）
	if body := rec.Body.String(); strings.Contains(body, gatewayAPIKey()) && gatewayAPIKey() != "" {
		t.Errorf("GET 响应泄露真实密钥")
	}
}

// ---------- 4. handler：POST 生成片段 ----------

func TestV370ExtenderPost(t *testing.T) {
	// 合法目标，占位密钥
	req := httptest.NewRequest("POST", "/api/admin/v37/extender", strings.NewReader(`{"target":"openclaw"}`))
	rec := httptest.NewRecorder()
	handleV37Extender(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST 应 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Target      string          `json:"target"`
		Snippet     extenderSnippet `json:"snippet"`
		KeyEmbedded bool            `json:"keyEmbedded"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Target != "openclaw" || resp.Snippet.Code == "" {
		t.Errorf("片段响应异常: %+v", resp)
	}
	if resp.KeyEmbedded {
		t.Errorf("未请求 includeKey 不应内嵌密钥")
	}
	if !strings.Contains(resp.Snippet.Code, extenderDefaultKeySnippet) {
		t.Errorf("默认片段应使用占位密钥")
	}
	// includeKey=true：内嵌真实密钥
	req = httptest.NewRequest("POST", "/api/admin/v37/extender", strings.NewReader(`{"target":"continue","includeKey":true}`))
	rec = httptest.NewRecorder()
	handleV37Extender(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("includeKey POST 应 200, got %d", rec.Code)
	}
	var resp2 struct {
		Snippet     extenderSnippet `json:"snippet"`
		KeyEmbedded bool            `json:"keyEmbedded"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if !resp2.KeyEmbedded || !strings.Contains(resp2.Snippet.Code, gatewayAPIKey()) {
		t.Errorf("includeKey=true 应内嵌真实密钥")
	}
	// 未知目标 → 400
	req = httptest.NewRequest("POST", "/api/admin/v37/extender", strings.NewReader(`{"target":"nope"}`))
	rec = httptest.NewRecorder()
	handleV37Extender(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("未知目标应 400, got %d", rec.Code)
	}
	// 空 body → 400
	req = httptest.NewRequest("POST", "/api/admin/v37/extender", nil)
	rec = httptest.NewRecorder()
	handleV37Extender(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("空 body 应 400, got %d", rec.Code)
	}
	// 其他方法 → 405
	req = httptest.NewRequest("DELETE", "/api/admin/v37/extender", nil)
	rec = httptest.NewRecorder()
	handleV37Extender(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE 应 405, got %d", rec.Code)
	}
}

// ---------- 5. 模块注册与裁剪档案 ----------

func TestV370ModuleRegistered(t *testing.T) {
	initModuleDefaults()
	found := false
	for _, m := range moduleRegistry {
		if m.ID == "extender" {
			found = true
			if !m.Default {
				t.Errorf("extender 应默认开启")
			}
		}
	}
	if !found {
		t.Fatalf("moduleRegistry 缺 extender")
	}
	// 标准档应包含 extender
	states := profileStates(1) // standard
	if !states["extender"] {
		t.Errorf("标准档应开启 extender")
	}
	// 极简/纯本地/低配档不含（与 connectors 同侧，不背包袱），但关闭态下路由应返回 503
	for _, idx := range []int{0, 3, 4} {
		if profileStates(idx)["extender"] {
			t.Errorf("裁剪档 %d 不应默认开启 extender", idx)
		}
	}
}

// ---------- 6. 汇总函数 ----------

func TestV370Summary(t *testing.T) {
	s := extenderInstalledSummary() // 只要不 panic 即可（沙箱内装了什么都不影响）
	if s == "" {
		// 沙箱未装任何目标工具时为空是合法的
		t.Log("本机未探测到任何目标工具（合法）")
	}
}
