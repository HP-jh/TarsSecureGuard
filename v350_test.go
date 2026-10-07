package main

// ===================== v3.5.0 极致模块化与自适应 专项测试 =====================

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- 1. 模块使用埋点 ----------

func TestV350ModuleUsageTracking(t *testing.T) {
	usageMu.Lock()
	moduleUsage = map[string]*moduleUsageStat{}
	usageMu.Unlock()
	called := false
	h := moduleRoute("chatApi", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	// chatApi 默认开（无 config 时回退注册表 Default）
	req := httptest.NewRequest("GET", "/api/chat/completions", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatalf("handler 未被调用")
	}
	usageMu.Lock()
	s, ok := moduleUsage["chatApi"]
	usageMu.Unlock()
	if !ok || s.Calls != 1 {
		t.Errorf("chatApi 使用埋点应记 1 次, got %v", moduleUsage["chatApi"])
	}
	// 关闭态不埋点
	modMu.Lock()
	modStates["chatApi"] = false
	modMu.Unlock()
	h.ServeHTTP(httptest.NewRecorder(), req)
	usageMu.Lock()
	calls := moduleUsage["chatApi"].Calls
	usageMu.Unlock()
	if calls != 1 {
		t.Errorf("模块关闭时不应埋点, calls=%d", calls)
	}
	modMu.Lock()
	modStates["chatApi"] = true
	modMu.Unlock()
}

// ---------- 2. 内置档案合法性 ----------

func TestV350BuiltinProfilesValid(t *testing.T) {
	for i, p := range builtinProfiles {
		states := profileStates(i)
		if len(states) != len(moduleRegistry) {
			t.Errorf("档案 %s 展开应覆盖全部注册模块", p.ID)
		}
		for id := range states {
			if _, ok := registryLookup(id); !ok {
				t.Errorf("档案 %s 含未知模块 %s", p.ID, id)
			}
		}
		if p.ID == "minimal" {
			// 极简档核心链路必须在
			for _, must := range []string{"chatApi", "memory", "builtinTools"} {
				if !states[must] {
					t.Errorf("minimal 档必须保留 %s", must)
				}
			}
			if states["webSearch"] || states["connectors"] || states["mcpExternal"] {
				t.Errorf("minimal 档不应开启外联工具模块")
			}
		}
		if p.ID == "privacy" {
			// 纯本地档零外联
			for _, banned := range []string{"cloudModels", "webSearch", "webFetch", "openapiTools", "mcpExternal", "connectors", "sidecarHub", "customTools"} {
				if states[banned] {
					t.Errorf("privacy 档不应开启外联模块 %s", banned)
				}
			}
			if !states["chatApi"] || !states["localModels"] {
				t.Errorf("privacy 档必须保留本地对话链路")
			}
		}
		// 档案管理控制面（adaptive）必须在所有裁剪档保留，否则应用后无法再切换档案
		if !states["adaptive"] {
			t.Errorf("%s 档必须保留 adaptive（档案管理控制面）", p.ID)
		}
		if p.ID == "lowspec" {
			if !states["resourceGuardian"] || !states["semanticGuard"] {
				t.Errorf("lowspec 档必须保留资源守护器与语义分级（省资源不降安全）")
			}
			if states["autoDiscovery"] || states["scoreBoard"] {
				t.Errorf("lowspec 档应关闭非必要开销模块")
			}
		}
	}
}

// ---------- 3. 档案应用：依赖闭合 + dryRun ----------

func TestV350ProfileApplyClosure(t *testing.T) {
	initModuleDefaults()
	// privacy 档把 localModels 之外的东西关掉，但 privacy 开 localModels 本身
	target, ok := profileTargetStates("privacy")
	if !ok {
		t.Fatalf("privacy 档应存在")
	}
	closed := closeDeps(target)
	// contextGov 依赖 builtinTools，privacy 档 builtinTools 开 → 依赖无违例
	if !closed["builtinTools"] {
		t.Errorf("closure 后 builtinTools 应保持开启")
	}
	// 档案闭包语义：显式开启 modelDownload（其依赖 localModels 未声明）→ 传递补全 localModels
	bad := map[string]bool{}
	for _, m := range moduleRegistry {
		bad[m.ID] = false
	}
	bad["modelDownload"] = true
	fixed := closeDeps(bad)
	if !fixed["localModels"] {
		t.Errorf("modelDownload 依赖 localModels，closure 应连带开启")
	}
	if fixed["webSearch"] || fixed["stats"] {
		t.Errorf("未声明的无关模块应保持关闭")
	}
	// 反向：显式关闭 localModels 且不开任何依赖它的模块 → 依赖者保持关闭、localModels 不被复活
	bad2 := map[string]bool{}
	for _, m := range moduleRegistry {
		bad2[m.ID] = m.Default
	}
	bad2["localModels"] = false
	bad2["modelDownload"] = false
	bad2["autoDiscovery"] = false
	bad2["autoStartModel"] = false
	bad2["modelDownload"] = false
	fixed2 := closeDeps(bad2)
	if fixed2["localModels"] {
		t.Errorf("显式关闭且无依赖者时 localModels 不应被复活")
	}
	if fixed2["modelDownload"] || fixed2["autoDiscovery"] || fixed2["autoStartModel"] {
		t.Errorf("依赖 localModels 的模块应保持关闭")
	}
	// 顺序无关性：开启集相同但表构造顺序不同 → 结果一致
	a := map[string]bool{"builtinTools": true, "contextGov": true, "chatApi": true}
	b := map[string]bool{"chatApi": true, "contextGov": true, "builtinTools": true}
	fa, fb := closeDeps(a), closeDeps(b)
	for _, m := range moduleRegistry {
		if fa[m.ID] != fb[m.ID] {
			t.Errorf("闭包应与构造顺序无关: %s 不一致 (%v vs %v)", m.ID, fa[m.ID], fb[m.ID])
		}
	}
}

func TestV350ProfileDryRun(t *testing.T) {
	initModuleDefaults()
	target, _ := profileTargetStates("minimal")
	changes := profileChanges(target)
	if len(changes) == 0 {
		t.Errorf("minimal 档与默认态应有差异")
	}
	for _, c := range changes {
		id := c["id"].(string)
		if id == "chatApi" && c["to"] == false {
			t.Errorf("minimal 档不应关闭 chatApi")
		}
	}
}

// ---------- 4. 自定义档案 save / apply / delete ----------

func TestV350CustomProfileLifecycle(t *testing.T) {
	cfg = Config{}
	initModuleDefaults()
	cfg.V35Config.ModuleProfiles = map[string]map[string]bool{}
	// save：名字清洗
	if sanitizeProfileName("我的档案") != "" {
		t.Errorf("中文档案名应被拒绝")
	}
	if sanitizeProfileName("work-lite 2") != "work-lite2" {
		t.Errorf("档案名应剔除非法字符, got %q", sanitizeProfileName("work-lite 2"))
	}
	if sanitizeProfileName(strings.Repeat("a", 40)) != "" {
		t.Errorf("超长档案名应被拒绝")
	}
	if isBuiltinProfile("minimal") != true || isBuiltinProfile("myown") != false {
		t.Errorf("内置档案判定错误")
	}
	// 存一个自定义档案并取回
	snap := map[string]bool{}
	for _, m := range moduleRegistry {
		snap[m.ID] = m.Default
	}
	snap["customTools"] = true
	cfg.V35Config.ModuleProfiles["night"] = snap
	got, ok := profileTargetStates("night")
	if !ok || !got["customTools"] {
		t.Errorf("自定义档案取回应保留 customTools=true")
	}
	// 未知档案
	if _, ok := profileTargetStates("nope"); ok {
		t.Errorf("未知档案应返回 false")
	}
}

// ---------- 5. 自适应建议引擎 ----------

func TestV350AdaptiveSuggestions(t *testing.T) {
	cfg = Config{}
	initModuleDefaults()
	usageMu.Lock()
	moduleUsage = map[string]*moduleUsageStat{}
	usageMu.Unlock()
	sugg := adaptiveSuggestions()
	// 无硬件 / 无本地模型 / uptime 短 → 允许为空，但结构必须是切片
	if sugg == nil {
		t.Errorf("建议列表不应为 nil")
	}
	// R2：把 uptime 判定绕不开（真实 startTime），但可验证开启且 0 调用的模块不panic、
	// 且建议中 module-off 类的目标模块确实开启且无依赖方
	for _, s := range sugg {
		if s.Kind == "module-off" {
			if !moduleEnabledByID(s.ModuleID) {
				t.Errorf("module-off 建议 %s 目标模块未开启", s.ModuleID)
			}
		}
	}
	// apply 未知建议 → 报错
	if _, err := applyAdaptiveSuggestion("no-such"); err == nil {
		t.Errorf("未知建议应报错")
	}
	// info 类不可应用
	cfg = Config{}
	initModuleDefaults()
}

// ---------- 6. UI 模式 ----------

func TestV350UIMode(t *testing.T) {
	cfg = Config{}
	if m := uiMode(); m != "advanced" {
		t.Errorf("默认 UI 模式应为 advanced, got %s", m)
	}
	cfg.V35Config.UI.Mode = "beginner"
	if m := uiMode(); m != "beginner" {
		t.Errorf("beginner 模式读取错误, got %s", m)
	}
	cfg.V35Config.UI.Mode = "garbage"
	if m := uiMode(); m != "advanced" {
		t.Errorf("非法模式应回退 advanced, got %s", m)
	}
}

// ---------- 7. API handler：ui-mode 切换与 profile dryRun ----------

func TestV350APIHandlers(t *testing.T) {
	cfg = Config{}
	initModuleDefaults()
	// ui-mode POST 非法值
	req := httptest.NewRequest("POST", "/api/admin/v35/ui-mode", strings.NewReader(`{"mode":"hacker"}`))
	rec := httptest.NewRecorder()
	handleV35UIMode(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("非法 mode 应 400, got %d", rec.Code)
	}
	// ui-mode POST 合法值
	req = httptest.NewRequest("POST", "/api/admin/v35/ui-mode", strings.NewReader(`{"mode":"beginner"}`))
	rec = httptest.NewRecorder()
	handleV35UIMode(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("合法 mode 应 200, got %d", rec.Code)
	}
	if uiMode() != "beginner" {
		t.Errorf("切换后应为 beginner")
	}
	// profile POST dryRun
	req = httptest.NewRequest("POST", "/api/admin/v35/profile", strings.NewReader(`{"action":"apply","profile":"minimal","dryRun":true}`))
	rec = httptest.NewRecorder()
	handleV35Profile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dryRun 应 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		DryRun  bool                   `json:"dryRun"`
		Changes []map[string]interface{} `json:"changes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if !resp.DryRun || len(resp.Changes) == 0 {
		t.Errorf("dryRun 响应应带 changes, got %+v", resp)
	}
	// dryRun 不应真正应用
	if !moduleEnabledByID("webSearch") {
		t.Errorf("dryRun 不应真正应用（webSearch 应保持默认开）")
	}
	// profile POST 未知档案
	req = httptest.NewRequest("POST", "/api/admin/v35/profile", strings.NewReader(`{"action":"apply","profile":"nope"}`))
	rec = httptest.NewRecorder()
	handleV35Profile(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("未知档案应 404, got %d", rec.Code)
	}
	// profile POST 非法 action
	req = httptest.NewRequest("POST", "/api/admin/v35/profile", strings.NewReader(`{"action":"nuke","profile":"minimal"}`))
	rec = httptest.NewRecorder()
	handleV35Profile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("非法 action 应 400, got %d", rec.Code)
	}
}

// ---------- 8. adaptive 模块注册 ----------

func TestV350Modules(t *testing.T) {
	initModuleDefaults()
	found := false
	for _, m := range moduleRegistry {
		if m.ID == "adaptive" {
			found = true
			if !m.Default {
				t.Errorf("adaptive 应默认开启")
			}
			if m.Category != "ops" {
				t.Errorf("adaptive 应归 ops 类")
			}
		}
	}
	if !found {
		t.Errorf("adaptive 模块未注册")
	}
	if !moduleEnabledByID("adaptive") {
		t.Errorf("adaptive 默认态应为开")
	}
}
