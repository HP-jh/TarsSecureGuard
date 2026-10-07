package main

// ===================== v3.2.0 连接性测试 ====================
//
// 覆盖（对应交付物验收项）：
//  1. provider-registry：≥20 云端 + ≥8 本地运行时、字段合法性
//  2. 注册表文件静态扫描：不含密钥/敏感字样（Tier 1 精神）
//  3. splitProviderModel 解析 / findCloudProviderByModel 裸模型名路由
//  4. 熔断器状态机：closed → open → half-open → closed
//  5. 协议适配：openai / anthropic（system 提升）/ gemini（role=model + systemInstruction）
//  6. 响应缓存：租户隔离、TTL、主动失效
//  7. callProviderChat 集成测试：httptest 模拟 openai-compat 上游（鉴权头/模型透传/缓存命中）
//  8. routeChat 显式前缀路由端到端（"openai/gpt-4o"）
//  9. 连接池复用：同一上游连续请求后 connReused > 0
// 10. handleV32Providers 永不回显密钥

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- 测试辅助：保存/恢复 v32 配置段，避免污染其他测试 ----

func v32SaveProviders() map[string]ProviderOverride {
	saved := cfg.V32Config.Providers
	if saved == nil {
		saved = map[string]ProviderOverride{}
	}
	return saved
}

func v32RestoreProviders(saved map[string]ProviderOverride) {
	cfg.V32Config.Providers = saved
	v32CacheInvalidate("test_restore")
}

// ===================== 1. 注册表加载与形状 =====================

func TestV32RegistryLoadAndShape(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	cloud, local := providerCount()
	if cloud < 20 {
		t.Errorf("云端 provider %d 个，低于承诺的 20 个", cloud)
	}
	if local < 8 {
		t.Errorf("本地运行时 provider %d 个，低于承诺的 8 个", local)
	}
	validProto := map[string]bool{"openai-compat": true, "anthropic": true, "gemini": true, "ollama": true}
	validKind := map[string]bool{"cloud": true, "local": true}
	for _, id := range registryIDsForTest() {
		s, ok := providerSpec(id)
		if !ok {
			t.Fatalf("providerSpec(%s) 未找到", id)
		}
		if s.ID != id || s.Name == "" || s.BaseURL == "" || s.ChatPath == "" {
			t.Errorf("provider %s 字段不完整（name/baseURL/chatPath）", id)
		}
		if !validProto[s.Protocol] {
			t.Errorf("provider %s 非法 protocol %q", id, s.Protocol)
		}
		if !validKind[s.Kind] {
			t.Errorf("provider %s 非法 kind %q", id, s.Kind)
		}
		if s.Kind == "cloud" && s.KeyEnv == "" {
			t.Errorf("云端 provider %s 缺 keyEnv（密钥环境变量名）", id)
		}
	}
}

func registryIDsForTest() []string {
	preg.mu.RLock()
	defer preg.mu.RUnlock()
	ids := make([]string, 0, len(preg.order))
	ids = append(ids, preg.order...)
	return ids
}

// ===================== 2. 注册表无敏感信息 =====================

func TestV32RegistryNoSecrets(t *testing.T) {
	entries, err := providerFS.ReadDir("providers")
	if err != nil {
		t.Fatalf("ReadDir providers: %v", err)
	}
	if len(entries) < 28 {
		t.Errorf("注册表文件 %d 个，低于 32 个预期（24 云端 + 8 本地）的最小集", len(entries))
	}
	for _, e := range entries {
		data, err := providerFS.ReadFile("providers/" + e.Name())
		if err != nil {
			t.Fatalf("ReadFile %s: %v", e.Name(), err)
		}
		low := strings.ToLower(string(data))
		for _, bad := range []string{"apikey", "sk-", "bearer ", "secret", "token_"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s 含敏感字样 %q（注册表文件不得携带密钥）", e.Name(), bad)
			}
		}
	}
}

// ===================== 3. 模型名路由解析 =====================

func TestV32SplitProviderModel(t *testing.T) {
	if pid, rest, ok := splitProviderModel("anthropic/claude-sonnet-4-5"); !ok || pid != "anthropic" || rest != "claude-sonnet-4-5" {
		t.Errorf("合法前缀解析失败: %q %q %v", pid, rest, ok)
	}
	if _, _, ok := splitProviderModel("gpt-4o"); ok {
		t.Error("无斜杠不应命中")
	}
	if _, _, ok := splitProviderModel("/leading"); ok {
		t.Error("空前缀不应命中")
	}
	if _, _, ok := splitProviderModel("trailing/"); ok {
		t.Error("空模型名不应命中")
	}
	if _, _, ok := splitProviderModel("no-such-provider/model-x"); ok {
		t.Error("注册表外 providerId 不应命中")
	}
}

func TestV32FindCloudProviderByModel(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	if _, ok := findCloudProviderByModel("gpt-4o"); !ok {
		t.Error("注册表内云端模型 gpt-4o 应命中 openai")
	}
	if _, ok := findCloudProviderByModel("totally-unknown-model-xyz"); ok {
		t.Error("未知模型不应命中")
	}
	// 云端反查不得劫持本地运行时
	if _, ok := findCloudProviderByModel("qwen2.5:3b"); ok {
		t.Error("本地运行时模型不应被云端反查命中（本地链路由前缀/可达性路由）")
	}
}

// ===================== 4. 熔断器状态机 =====================

func TestV32BreakerStateMachine(t *testing.T) {
	const pid = "test-breaker-prov"
	defer func() {
		cbMu.Lock()
		delete(cbTable, pid)
		cbMu.Unlock()
	}()

	savedCircuit := cfg.V32Config.Circuit
	cfg.V32Config.Circuit.FailureThreshold = 3
	cfg.V32Config.Circuit.OpenSeconds = 30
	defer func() { cfg.V32Config.Circuit = savedCircuit }()

	for i := 0; i < 3; i++ {
		cbRecord(pid, false)
	}
	if st := cbStates()[pid]; st != "open" {
		t.Fatalf("连续 3 次失败后应为 open，实际 %s", st)
	}
	if cbAllow(pid) {
		t.Error("open 态应拒绝出站")
	}
	// 冷却期满 → half-open，放一个探测
	cbMu.Lock()
	b := cbTable[pid]
	b.openedAt = time.Now().Add(-time.Minute)
	cbMu.Unlock()
	if !cbAllow(pid) {
		t.Error("冷却期满应转 half-open 并放行一个探测")
	}
	if cbAllow(pid) {
		t.Error("half-open 探测在途时其余请求应拒绝")
	}
	// 探测失败 → 回到 open
	cbRecord(pid, false)
	if st := cbStates()[pid]; st != "open" {
		t.Fatalf("half-open 探测失败应回 open，实际 %s", st)
	}
	// 再次冷却 → half-open → 探测成功 → closed
	cbMu.Lock()
	b = cbTable[pid]
	b.openedAt = time.Now().Add(-time.Minute)
	cbMu.Unlock()
	if !cbAllow(pid) {
		t.Fatal("第二次冷却期满应放行探测")
	}
	cbRecord(pid, true)
	if st := cbStates()[pid]; st != "closed" {
		t.Fatalf("探测成功应回 closed，实际 %s", st)
	}
	if !cbAllow(pid) {
		t.Error("closed 态应正常放行")
	}
}

// ===================== 5. 协议适配 body 构建 =====================

func TestV32AdapterBodies(t *testing.T) {
	msgs := []Message{
		{Role: "system", Content: "you are safe"},
		{Role: "user", Content: "hi"},
		{Role: "assistant", Content: "hello"},
		{Role: "user", Content: "bye"},
	}

	// openai-compat：消息原样透传（含 system role）
	ob, err := buildOpenAIBody("gpt-4o", msgs)
	if err != nil {
		t.Fatal(err)
	}
	var om map[string]interface{}
	if err := json.Unmarshal(ob, &om); err != nil {
		t.Fatal(err)
	}
	if om["model"] != "gpt-4o" {
		t.Errorf("openai body model 透传失败: %v", om["model"])
	}
	if _, ok := om["messages"]; !ok {
		t.Error("openai body 缺 messages")
	}

	// anthropic：system 提升为顶层字段，messages 只剩 user/assistant
	ab, err := buildAnthropicBody("claude-sonnet-4-5", msgs)
	if err != nil {
		t.Fatal(err)
	}
	var am struct {
		Model   string `json:"model"`
		System  string `json:"system"`
		Content []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(ab, &am); err != nil {
		t.Fatal(err)
	}
	if am.System != "you are safe" {
		t.Errorf("anthropic system 未提升到顶层: %q", am.System)
	}
	for _, m := range am.Content {
		if m.Role != "user" && m.Role != "assistant" {
			t.Errorf("anthropic messages 含非法 role %q", m.Role)
		}
	}

	// gemini：role=model + systemInstruction
	gb, err := buildGeminiBody("gemini-2.0-flash", msgs)
	if err != nil {
		t.Fatal(err)
	}
	var gm struct {
		SystemInstruction *struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"systemInstruction"`
		Contents []struct {
			Role  string `json:"role"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(gb, &gm); err != nil {
		t.Fatal(err)
	}
	if gm.SystemInstruction == nil || len(gm.SystemInstruction.Parts) == 0 || gm.SystemInstruction.Parts[0].Text != "you are safe" {
		t.Error("gemini systemInstruction 缺失或内容错误")
	}
	for _, c := range gm.Contents {
		if c.Role != "model" && c.Role != "user" {
			t.Errorf("gemini contents 含非法 role %q（assistant 应映射为 model）", c.Role)
		}
	}
}

// ===================== 6. 响应缓存：租户隔离 / TTL / 失效 =====================

func TestV32RespCacheTenantIsolation(t *testing.T) {
	v32CacheInvalidate("test_setup")
	defer v32CacheInvalidate("test_teardown")

	msgs := []Message{{Role: "user", Content: "cache-me"}}
	k1 := respCacheKey("tenant-a", "openai", "gpt-4o", msgs)
	k2 := respCacheKey("tenant-b", "openai", "gpt-4o", msgs)
	if k1 == k2 {
		t.Error("不同租户的缓存键必须不同（租户隔离红线）")
	}

	respCachePut(k1, "answer-a")
	if v, ok := respCacheGet(k1); !ok || v != "answer-a" {
		t.Error("缓存写入后应可命中")
	}
	if _, ok := respCacheGet(k2); ok {
		t.Error("租户 B 不应命中租户 A 的缓存")
	}

	v32CacheInvalidate("test_invalidate")
	if _, ok := respCacheGet(k1); ok {
		t.Error("主动失效后缓存应清空")
	}
}

func TestV32RespCacheTTLExpiry(t *testing.T) {
	savedTTL := cfg.V32Config.ResponseCache.TTLSec
	cfg.V32Config.ResponseCache.TTLSec = 1
	defer func() { cfg.V32Config.ResponseCache.TTLSec = savedTTL }()

	v32CacheInvalidate("test_ttl_setup")
	defer v32CacheInvalidate("test_ttl_teardown")

	msgs := []Message{{Role: "user", Content: "ttl-me"}}
	k := respCacheKey("ttl-tenant", "openai", "gpt-4o", msgs)
	respCachePut(k, "stale-answer")
	time.Sleep(1100 * time.Millisecond)
	if _, ok := respCacheGet(k); ok {
		t.Error("超过 TTL 的缓存条目不应命中")
	}
}

// ===================== 7. callProviderChat 集成（httptest 模拟上游） =====================

func TestV32CallProviderChatOpenAICompat(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/chat/completions" {
			t.Errorf("上游路径不符: %s（openai baseURL 默认含 /v1，chatPath 为 /chat/completions）", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tsg-test-key-xyz" {
			t.Errorf("鉴权头不符: %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(body, &m)
		if m["model"] != "gpt-4o" {
			t.Errorf("模型未透传: %v", m["model"])
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"gateway says hi"}}]}`))
	}))
	defer srv.Close()

	saved := v32SaveProviders()
	cfg.V32Config.Providers = map[string]ProviderOverride{
		"openai": {APIKey: "tsg-test-key-xyz", BaseURL: srv.URL},
	}
	v32CacheInvalidate("test_call_setup")
	defer v32RestoreProviders(saved)

	spec, ok := providerSpec("openai")
	if !ok {
		t.Fatal("openai spec 缺失")
	}
	msgs := []Message{{Role: "user", Content: "hello"}}
	content, err := callProviderChat(spec, "gpt-4o", msgs, "tenant-test", "")
	if err != nil {
		t.Fatalf("callProviderChat: %v", err)
	}
	if content != "gateway says hi" {
		t.Errorf("上游回复解析不符: %q", content)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("首次调用应命中上游 1 次，实际 %d", n)
	}
	// 第二次同参调用：命中响应缓存，不再出站
	content2, err := callProviderChat(spec, "gpt-4o", msgs, "tenant-test", "")
	if err != nil || content2 != "gateway says hi" {
		t.Fatalf("缓存命中调用失败: %v / %q", err, content2)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("响应缓存未生效：上游命中 %d 次（应为 1）", n)
	}
	// 换租户：缓存隔离，必须重新出站
	if _, err := callProviderChat(spec, "gpt-4o", msgs, "tenant-other", ""); err != nil {
		t.Fatalf("跨租户调用失败: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Errorf("租户隔离失效：上游命中 %d 次（应为 2）", n)
	}
}

// ===================== 8. routeChat 显式前缀路由端到端 =====================

func TestV32RouteChatExplicitPrefix(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"via-routechat"}}]}`))
	}))
	defer srv.Close()

	saved := v32SaveProviders()
	cfg.V32Config.Providers = map[string]ProviderOverride{
		"openai": {APIKey: "tsg-test-key-xyz", BaseURL: srv.URL},
	}
	v32CacheInvalidate("test_route_setup")
	defer v32RestoreProviders(saved)

	content, backend, err := routeChat("openai/gpt-4o", []Message{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("routeChat 显式前缀路由失败: %v", err)
	}
	if backend != "openai" {
		t.Errorf("backend 应为 providerId，实际 %q", backend)
	}
	if content != "via-routechat" {
		t.Errorf("路由内容不符: %q", content)
	}
}

// ===================== 9. 连接池复用 =====================

func TestV32PoolReuse(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	// 显式初始化连接池（sync.Once 幂等；测试进程默认不经过 main 启动链）
	initPooledClients(32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"pool"}}]}`))
	}))
	defer srv.Close()

	saved := v32SaveProviders()
	cfg.V32Config.Providers = map[string]ProviderOverride{
		"openai": {APIKey: "tsg-test-key-xyz", BaseURL: srv.URL},
	}
	v32CacheInvalidate("test_pool_setup")
	defer v32RestoreProviders(saved)

	spec, _ := providerSpec("openai")
	beforeNew := poolConnNew.Load()
	beforeReused := poolConnReused.Load()

	// 顺序 10 次不同内容请求（避开响应缓存），观察连接复用
	for i := 0; i < 10; i++ {
		msgs := []Message{{Role: "user", Content: "pool-probe-" + strings.Repeat("x", i+1)}}
		if _, err := callProviderChat(spec, "gpt-4o", msgs, "pool-tenant", ""); err != nil {
			t.Fatalf("第 %d 次调用失败: %v", i+1, err)
		}
	}
	newConns := poolConnNew.Load() - beforeNew
	reusedConns := poolConnReused.Load() - beforeReused
	if reusedConns == 0 {
		t.Errorf("连接池复用未生效：10 次请求新建 %d / 复用 %d", newConns, reusedConns)
	}
	if r := poolReuseRatePct(); r <= 0 {
		t.Errorf("复用率应为正，实际 %.2f%%", r)
	}
}

// ===================== 10. handleV32Providers 永不回显密钥 =====================

func TestV32ProvidersHandlerKeySafety(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	saved := v32SaveProviders()
	cfg.V32Config.Providers = map[string]ProviderOverride{
		"openai": {APIKey: "tsg-leakcheck-key-9f8e7d"},
	}
	defer v32RestoreProviders(saved)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/v32/providers", nil)
	handleV32Providers(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "tsg-leakcheck-key-9f8e7d") {
		t.Error("providers 端点泄漏了密钥本体（只允许 keySet 布尔）")
	}
	if !strings.Contains(body, `"keySet":true`) {
		t.Error("配置密钥后 keySet 应为 true")
	}
	if !strings.Contains(body, `"providers"`) {
		t.Error("响应缺 providers 列表")
	}
}
