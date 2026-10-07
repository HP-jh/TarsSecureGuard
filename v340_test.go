package main

// ===================== v3.4.0 测量器 / 工具降耗 / 连接器测试 =====================

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- 1. 计量记录与聚合 ----------

func TestV340MeterRecordAndAgg(t *testing.T) {
	// 清零
	meterMu.Lock()
	meterRing = meterRing[:0]
	meterStats = map[string]*meterAgg{}
	meterByModel = map[string]*meterAgg{}
	meterMu.Unlock()

	meterRecord(MeterEntry{Model: "openai/gpt-4o", Backend: "openai", Prompt: 100, Complete: 50, Total: 150, CostUSD: 0.001, Priced: true})
	meterRecord(MeterEntry{Model: "openai/gpt-4o", Backend: "openai", Prompt: 10, Complete: 5, Total: 15, Error: true})
	meterRecord(MeterEntry{Model: "llama-3", Backend: "llama", Prompt: 200, Complete: 100, Total: 300})

	meterMu.Lock()
	if len(meterRing) != 3 {
		t.Fatalf("ring 应有 3 条，实际 %d", len(meterRing))
	}
	agg := meterByModel["openai/gpt-4o"]
	if agg == nil || agg.Calls != 2 || agg.Errors != 1 || agg.Total != 165 || agg.CostUSD < 0.001-1e-9 {
		t.Errorf("模型聚和错误: %+v", agg)
	}
	if len(meterStats) != 1 {
		t.Errorf("应只有今天一天聚合: %v", meterStats)
	}
	meterMu.Unlock()
}

// ---------- 2. 定价三层 ----------

func TestV340PricingFor(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	// registry pricing（openai 有 provider 级定价）
	p, ok := pricingFor("openai", "gpt-4o")
	if !ok || p.Input <= 0 || p.Output <= 0 {
		t.Errorf("registry pricing 未命中: %+v %v", p, ok)
	}
	// registry modelPricing 精确覆盖（gpt-4o-mini 0.15/0.60）
	p, ok = pricingFor("openai", "gpt-4o-mini")
	if !ok || p.Input != 0.15 || p.Output != 0.60 {
		t.Errorf("registry modelPricing 未命中: %+v %v", p, ok)
	}
	// override 层优先
	cfgMu.Lock()
	orig := cfg.V34Config.Pricing.Overrides
	cfg.V34Config.Pricing.Overrides = map[string]*Pricing{
		"openai/gpt-4o": {Input: 1, Output: 2},
		"bare-model":    {Input: 9, Output: 9},
	}
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg.V34Config.Pricing.Overrides = orig
		cfgMu.Unlock()
	}()
	p, ok = pricingFor("openai", "gpt-4o")
	if !ok || p.Input != 1 || p.Output != 2 {
		t.Errorf("override pricing 未生效: %+v %v", p, ok)
	}
	p, ok = pricingFor("", "bare-model")
	if !ok || p.Input != 9 {
		t.Errorf("裸模型 override 未生效: %+v %v", p, ok)
	}
	// 无定价 provider（huggingface 未配 pricing）
	if _, ok := pricingFor("huggingface", "some-model"); ok {
		t.Errorf("未配置定价的 provider 不应命中")
	}
}

func TestV340MeterCost(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	// 本地后端免费
	if cost, priced := meterCost("llama", "m", Usage{PromptTokens: 1000, CompletionTokens: 1000}); priced || cost != 0 {
		t.Errorf("本地后端应免费: %v %v", cost, priced)
	}
	if _, priced := meterCost("", "m", Usage{}); priced {
		t.Errorf("无 provider 应免费")
	}
	// 云端有定价：openai 2.50/10.00 → 1M in + 1M out = 12.5 USD
	cost, priced := meterCost("openai", "gpt-4o", Usage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000})
	if !priced || cost < 12.5-1e-9 || cost > 12.5+1e-9 {
		t.Errorf("成本折算错误: %v %v", cost, priced)
	}
	// 未登记定价的云端模型：只记 token 不计金额
	if _, priced := meterCost("huggingface", "x", Usage{}); priced {
		t.Errorf("无定价云端模型不应计价")
	}
}

// ---------- 3. meterHook 埋点（routeChatEx 出口） ----------

func TestV340MeterHook(t *testing.T) {
	initModuleDefaults()
	meterMu.Lock()
	meterRing = meterRing[:0]
	meterByModel = map[string]*meterAgg{}
	meterMu.Unlock()
	// 失败路径也记账（无后端可用）
	_, _ = routeChatEx("auto-no-backend-xyz", []Message{{Role: "user", Content: "hi"}}, ChatOpts{})
	meterMu.Lock()
	n := len(meterRing)
	meterMu.Unlock()
	if n == 0 {
		t.Fatalf("routeChatEx 失败路径也应记计量（defer 出口埋点）")
	}
	meterMu.Lock()
	last := meterRing[n-1]
	meterMu.Unlock()
	if !last.Error || last.Model != "auto-no-backend-xyz" {
		t.Errorf("失败计量字段错误: %+v", last)
	}
}

// ---------- 4. tools schema 瘦身 ----------

func TestV340SlimToolsSchema(t *testing.T) {
	tools := json.RawMessage(`[{"type":"function","function":{"name":"f","description":"d","strict":false,"parameters":{"type":"object","properties":{"a":{"type":"string","additionalProperties":false}},"required":[],"additionalProperties":false}}}]`)
	out := slimToolsSchema(tools)
	s := string(out)
	if strings.Contains(s, `"strict":false`) {
		t.Errorf("strict:false 应被剔除: %s", s)
	}
	if strings.Contains(s, `"additionalProperties":false`) {
		t.Errorf("additionalProperties:false 应被剔除: %s", s)
	}
	if strings.Contains(s, `"required":[]`) {
		t.Errorf("空 required 数组应被剔除: %s", s)
	}
	if !strings.Contains(s, `"name":"f"`) || !strings.Contains(s, `"type":"string"`) {
		t.Errorf("语义字段不应被剔除: %s", s)
	}
	// strict:true 保留（非默认值）
	tools2 := json.RawMessage(`[{"type":"function","function":{"name":"f","strict":true}}]`)
	out2 := slimToolsSchema(tools2)
	if !strings.Contains(string(out2), `"strict":true`) {
		t.Errorf("strict:true 不应被剔除: %s", out2)
	}
	// 已紧凑的定义：原样返回
	tools3 := json.RawMessage(`[{"type":"function","function":{"name":"f"}}]`)
	out3 := slimToolsSchema(tools3)
	if string(out3) != string(tools3) {
		t.Errorf("紧凑定义应原样返回: %s", out3)
	}
}

func TestV340SlimToolsCounters(t *testing.T) {
	toolSlimMu.Lock()
	toolSlimSaved, toolSlimCalls = 0, 0
	toolSlimMu.Unlock()
	tools := json.RawMessage(`[{"type":"function","function":{"name":"f","description":"d","strict":false,"parameters":{"type":"object","properties":{},"additionalProperties":false}}}]`)
	slimToolsSchema(tools)
	toolSlimMu.Lock()
	saved, calls := toolSlimSaved, toolSlimCalls
	toolSlimMu.Unlock()
	if calls != 1 || saved <= 0 {
		t.Errorf("瘦身收益应累计: saved=%d calls=%d", saved, calls)
	}
}

// ---------- 5. 连接器 ----------

func TestV340ConnectorTemplates(t *testing.T) {
	tm := connectorTemplatesMap()
	if len(tm) < 8 {
		t.Errorf("内置连接器模板应 ≥8，实际 %d", len(tm))
	}
	for _, id := range []string{"github_repo", "github_issues", "webhook_notify", "wikipedia_search", "weather", "ip_info", "hn_top", "hn_item"} {
		if _, ok := tm[id]; !ok {
			t.Errorf("缺少模板 %s", id)
		}
	}
	// 全部模板 endpoint 为公网 https
	for _, tpl := range builtinConnectorTemplates {
		if !strings.HasPrefix(tpl.Endpoint, "https://") && !strings.HasPrefix(tpl.Endpoint, "{{.url}}") {
			t.Errorf("模板 %s endpoint 应为 https: %s", tpl.ID, tpl.Endpoint)
		}
	}
}

func TestV340ExpandConnectorParams(t *testing.T) {
	tpl := connectorTemplatesMap()["github_issues"]
	inst := map[string]string{"owner": "HP-jh", "repo": "TarsSecureGuard"}
	// 实例静态参数 + 默认值
	out, err := expandConnectorParams(tpl.Endpoint, tpl, inst, nil)
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if !strings.Contains(out, "repos/HP-jh/TarsSecureGuard/issues") || !strings.Contains(out, "state=open") || !strings.Contains(out, "per_page=10") {
		t.Errorf("静态参数/默认值展开错误: %s", out)
	}
	// 调用参数动态覆盖
	out, err = expandConnectorParams(tpl.Endpoint, tpl, inst, map[string]string{"state": "closed", "limit": "5"})
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if !strings.Contains(out, "state=closed") || !strings.Contains(out, "per_page=5") {
		t.Errorf("动态参数覆盖失败: %s", out)
	}
	// 必填缺失报错
	_, err = expandConnectorParams(tpl.Endpoint, tpl, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Errorf("必填缺失应报错: %v", err)
	}
}

func TestV340ConnectorExecuteNotEnabled(t *testing.T) {
	cfgMu.Lock()
	orig := cfg.V34Config.Connectors
	cfg.V34Config.Connectors = nil
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg.V34Config.Connectors = orig
		cfgMu.Unlock()
	}()
	if _, err := executeConnector("github_repo", map[string]interface{}{"owner": "a", "repo": "b"}); err == nil {
		t.Errorf("未启用连接器应报错")
	}
	// 启用但缺参数（实例 params 空）
	cfgMu.Lock()
	cfg.V34Config.Connectors = []ConnectorInstance{{Template: "github_repo", Enabled: true}}
	cfgMu.Unlock()
	if _, err := executeConnector("github_repo", map[string]interface{}{}); err == nil || !strings.Contains(err.Error(), "必填") {
		t.Errorf("缺必填参数应报错: %v", err)
	}
}

func TestV340ConnectorEnabledList(t *testing.T) {
	cfgMu.Lock()
	orig := cfg.V34Config.Connectors
	cfg.V34Config.Connectors = []ConnectorInstance{
		{Template: "github_repo", Enabled: true, Params: map[string]string{"owner": "a", "repo": "b"}},
		{Template: "weather", Enabled: false},
	}
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg.V34Config.Connectors = orig
		cfgMu.Unlock()
	}()
	live := enabledConnectors()
	if len(live) != 1 || live[0].Inst.Template != "github_repo" {
		t.Fatalf("enabledConnectors 过滤错误: %+v", live)
	}
	names := toolNames()
	found := false
	for _, n := range names {
		if n == "conn_github_repo" {
			found = true
		}
	}
	if !found {
		t.Errorf("启用连接器应出现在工具列表: %v", names)
	}
}

// ---------- 6. SSRF 红线（executeForwardedRequest 拒回环地址） ----------

func TestV340ForwardedRequestSSRF(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should not reach"))
	}))
	defer ts.Close()
	// httptest 监听 127.0.0.1——SSRF 拨号层应拒绝（红线 1：非公网地址）
	_, err := executeForwardedRequest(http.MethodGet, ts.URL, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("回环地址应被 SSRF 防护拒绝: %v", err)
	}
	// 非 http 协议拒绝
	if _, err := executeForwardedRequest("GET", "ftp://example.com", nil, nil, nil); err == nil {
		t.Errorf("非 http 协议应拒绝")
	}
	// 非 GET/POST 拒绝
	if _, err := executeForwardedRequest("DELETE", "https://example.com", nil, nil, nil); err == nil {
		t.Errorf("DELETE 应拒绝")
	}
}

// ---------- 7. 模块注册 ----------

func TestV340Modules(t *testing.T) {
	initModuleDefaults()
	for _, id := range []string{"tokenMeter", "connectors"} {
		found := false
		for _, m := range moduleRegistry {
			if m.ID == id {
				found = true
				if !m.Default {
					t.Errorf("%s 应默认开启", id)
				}
			}
		}
		if !found {
			t.Errorf("%s 未注册", id)
		}
		if !moduleEnabledByID(id) {
			t.Errorf("%s 默认态应为开", id)
		}
	}
}

// ---------- 8. 定价落进注册表文件 ----------

func TestV340ProviderPricingInRegistry(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	spec, ok := providerSpec("openai")
	if !ok || spec.Pricing == nil || spec.Pricing.Input <= 0 {
		t.Errorf("openai 应有 provider 级定价: %+v", spec.Pricing)
	}
	if spec.ModelPricing == nil || spec.ModelPricing["gpt-4o-mini"] == nil {
		t.Errorf("openai 应有模型级定价")
	}
	spec2, _ := providerSpec("deepseek")
	if spec2.Pricing == nil {
		t.Errorf("deepseek 应有定价")
	}
}

// ---------- 9. 连接器参数过滤（保留键不泄漏 / 已消费参数不重复透传） ----------

func TestV340ConnectorPassArgs(t *testing.T) {
	tpl := ConnectorTemplate{
		ID:       "test_tpl",
		Endpoint: "https://api.example.com/search?q={{.query}}&limit={{.limit}}",
		Params: []ConnectorParam{
			{Name: "query", Required: true},
			{Name: "limit", Default: "5"},
		},
	}
	args := map[string]interface{}{
		"query":         "hello",
		"limit":         "5",
		"_tsgIdentity":  map[string]interface{}{"Name": "admin", "Role": "global_admin"},
		"confirm_token": "secret-token",
		"extra":         "keep-me",
	}
	pass := connectorPassArgs(tpl, args)
	if _, ok := pass["_tsgIdentity"]; ok {
		t.Errorf("保留键 _tsgIdentity 不应透传给上游")
	}
	if _, ok := pass["confirm_token"]; ok {
		t.Errorf("保留键 confirm_token 不应透传给上游")
	}
	if _, ok := pass["query"]; ok {
		t.Errorf("已被端点模板消费的参数 query 不应重复透传")
	}
	if _, ok := pass["limit"]; ok {
		t.Errorf("已被端点模板消费的参数 limit 不应重复透传")
	}
	if pass["extra"] != "keep-me" {
		t.Errorf("未消费的额外参数应保留，got %v", pass)
	}
	if len(pass) != 1 {
		t.Errorf("过滤后应只剩 extra，got %v", pass)
	}
}

// ---------- 10. 查询串拼接分隔符（URL 已含 ? 时用 &） ----------

func TestV340ForwardedRequestQuerySeparator(t *testing.T) {
	// URL 已带查询串：应追加 & 而非再拼一个 ?（双 ? 会把后续参数并入首个参数的值）
	got := appendQueryParams("https://api.example.com/search?q=go&limit=5", map[string]interface{}{"tag": "x"})
	if got != "https://api.example.com/search?q=go&limit=5&tag=x" {
		t.Errorf("已含 ? 的 URL 拼接错误: %s", got)
	}
	// URL 不带查询串：拼 ?
	got = appendQueryParams("https://api.example.com/search", map[string]interface{}{"tag": "x"})
	if got != "https://api.example.com/search?tag=x" {
		t.Errorf("不含 ? 的 URL 拼接错误: %s", got)
	}
}
