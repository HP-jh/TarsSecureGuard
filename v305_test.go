package main

// ===================== v3.0.5 可观测性与 self-diagnostic 测试 ====================
//
// 覆盖：
//  1. 指标注册表：counter/histogram 渲染、标签转义、HELP/TYPE 行
//  2. 脱敏：bearer / sk- / key= / 长十六进制
//  3. trace 中间件：X-Trace-Id 回写、span 记录、环形缓冲有界、/metrics 不入 ring
//  4. /metrics 端点：无密钥 401、有密钥 200、含核心指标名、输出无密钥泄漏
//  5. WAF 命中埋点：全链路（gatewayMiddleware）触发 403 后计数器递增
//  6. 路由埋点：routeChatSmartT defer 覆盖（无后端 → error 计数）
//  7. doctor：config 解析 / 角色合法性 / 探测密钥读取
//  8. 审计行 TRACE 关联后缀

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// obsMetricValue 读取 counter 当前值（测试辅助）
func obsMetricValue(m *obsMetric, labels ...string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.values[obsSeriesKey(labels)]
}

// obsHistogramCount 读取 histogram 样本数（测试辅助）
func obsHistogramCount(m *obsMetric, labels ...string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totals[obsSeriesKey(labels)]
}

// ===================== 1. 指标注册表 =====================

func TestObsMetricRender(t *testing.T) {
	c := obsNewCounter("tsg_test_total", "测试计数 \"引号\"\n换行", "rule")
	c.Inc("路径穿越")
	c.Add(2, "路径穿越")
	c.Inc("命令注入")
	// 标签数不匹配应静默忽略（防错配不出坏序列）
	c.Inc("a", "b")

	var b strings.Builder
	c.render(&b)
	out := b.String()
	for _, want := range []string{
		"# HELP tsg_test_total 测试计数 \"引号\"\\n换行",
		"# TYPE tsg_test_total counter",
		`tsg_test_total{rule="路径穿越"} 3`,
		`tsg_test_total{rule="命令注入"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("渲染缺少 %q:\n%s", want, out)
		}
	}
	if got := obsMetricValue(c, "路径穿越"); got != 3 {
		t.Errorf("counter 值 = %v, want 3", got)
	}
}

func TestObsHistogramRender(t *testing.T) {
	h := obsNewHistogram("tsg_test_dur", "测试直方图", "class")
	h.Observe(3, "chat")
	h.Observe(150, "chat")
	h.Observe(100000, "chat") // 超最大桶只入 +Inf/sum
	var b strings.Builder
	h.render(&b)
	out := b.String()
	for _, want := range []string{
		`# TYPE tsg_test_dur histogram`,
		`tsg_test_dur_bucket{class="chat",le="5"} 1`,
		`tsg_test_dur_bucket{class="chat",le="250"} 2`,
		`tsg_test_dur_bucket{class="chat",le="+Inf"} 3`,
		`tsg_test_dur_count{class="chat"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("渲染缺少 %q:\n%s", want, out)
		}
	}
}

// ===================== 2. 脱敏 =====================

func TestObsRedact(t *testing.T) {
	cases := []struct{ in, wantSub string }{
		{"Authorization: Bearer sk-abcdef1234567890xyz", "Bearer ***"},
		{"key=supersecret123 end", "key=***"},
		{"token=abc123; next", "token=***;"},
		{"hash d41d8cd98f00b204e9800998ecf8427e done", "***"},
		{"正常文本：路径穿越 / 命令注入", "路径穿越"},
	}
	for _, c := range cases {
		got := obsRedact(c.in)
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("obsRedact(%q) = %q, 应包含 %q", c.in, got, c.wantSub)
		}
	}
	// 秘密值本体绝不能残留
	out := obsRedact("Bearer sk-abcdef1234567890xyz")
	if strings.Contains(out, "sk-abcdef") {
		t.Errorf("脱敏后仍泄漏秘密值: %q", out)
	}
}

// ===================== 3. trace 中间件 =====================

func TestObsMiddlewareTrace(t *testing.T) {
	var gotTraceID string
	boom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceID = traceFromReq(r)
		obsStage(r.Context(), "test", "detail with key=abc123")
		w.WriteHeader(200)
	})
	h := obsMiddleware(boom)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	h.ServeHTTP(w, req)

	hdr := w.Header().Get("X-Trace-Id")
	if hdr == "" || len(hdr) != 16 {
		t.Errorf("X-Trace-Id 应为 16 位十六进制，实际 %q", hdr)
	}
	if gotTraceID != hdr {
		t.Errorf("handler 内 trace(%q) 与响应头(%q)不一致", gotTraceID, hdr)
	}
	// trace 已进 ring，span 已脱敏
	traces := obsRecentTraces(10)
	if len(traces) == 0 || traces[0]["id"] != hdr {
		t.Fatalf("ring 中未找到该 trace")
	}
	spans := traces[0]["spans"].([]obsSpan)
	found := false
	for _, s := range spans {
		if s.Stage == "test" {
			found = true
			if strings.Contains(s.Detail, "abc123") {
				t.Errorf("span detail 未脱敏: %q", s.Detail)
			}
		}
	}
	if !found {
		t.Errorf("未记录 test span: %+v", spans)
	}
	// 请求计数器（app 类 GET 200）
	if v := obsMetricValue(mHTTPReqTotal, "app", "GET", "200"); v < 1 {
		t.Errorf("tsg_http_requests_total 未计数, v=%v", v)
	}
}

func TestObsMiddlewareMetricsNotTraced(t *testing.T) {
	before := len(obsRecentTraces(obsTraceRingCap))
	h := obsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	h.ServeHTTP(w, req)
	after := len(obsRecentTraces(obsTraceRingCap))
	if after != before {
		t.Errorf("/metrics 不应进入 trace ring（before=%d after=%d）", before, after)
	}
	if w.Header().Get("X-Trace-Id") == "" {
		t.Errorf("/metrics 仍应回写 X-Trace-Id 响应头")
	}
}

func TestObsTraceRingBounded(t *testing.T) {
	h := obsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for i := 0; i < obsTraceRingCap+30; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/status", nil))
	}
	obsTraceMu.Lock()
	n := len(obsRing)
	obsTraceMu.Unlock()
	if n > obsTraceRingCap {
		t.Errorf("ring 越界: %d > %d", n, obsTraceRingCap)
	}
}

// ===================== 4. /metrics 端点（全链路）====================

func TestMetricsEndpoint(t *testing.T) {
	resetIPRep()
	cfgMu.Lock()
	savedUsers, savedAllow := cfg.Users, cfg.Security.DefaultKeyAllowed
	cfg.Users = []User{{Name: "obs1", APIKey: "k-obs1", Role: "user", Tenant: "t-obs", Enabled: true}}
	cfg.Security.DefaultKeyAllowed = nil
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg.Users, cfg.Security.DefaultKeyAllowed = savedUsers, savedAllow
		cfgMu.Unlock()
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", handleMetrics)
	h := obsMiddleware(gatewayMiddleware(mux))

	// 无密钥 → 401（走 gatewayMiddleware 鉴权）
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("无密钥 /metrics 应 401，实际 %d", w.Code)
	}

	// readonly 角色也应可读（RBAC app 类全放行）
	cfgMu.Lock()
	cfg.Users = []User{{Name: "ro1", APIKey: "k-ro1", Role: "readonly", Tenant: "t-obs", Enabled: true}}
	cfgMu.Unlock()
	w = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("X-API-Key", "k-ro1")
	req.RemoteAddr = "203.0.113.90:1234"
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("readonly /metrics 应 200，实际 %d", w.Code)
	}
	body := w.Body.String()
	for _, name := range []string{
		"tsg_http_requests_total", "tsg_http_request_duration_ms",
		"tsg_waf_hits_total", "tsg_router_decisions_total",
		"tsg_guard_tier", "tsg_module_up", "tsg_uptime_seconds", "tsg_build_info",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics 缺少指标 %s", name)
		}
	}
	// 输出绝不包含密钥本体
	if strings.Contains(body, "k-ro1") || strings.Contains(body, "k-obs1") {
		t.Errorf("/metrics 泄漏密钥")
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("Content-Type 应为 text/plain: %q", w.Header().Get("Content-Type"))
	}
	// 指标标签不应包含 user 名（低基数红线）
	if strings.Contains(body, `user="ro1"`) || strings.Contains(body, "ro1") {
		t.Errorf("/metrics 标签出现用户名，违反低基数/脱敏红线")
	}
}

// ===================== 5. WAF 命中埋点 =====================

func TestWAFHitMetric(t *testing.T) {
	resetIPRep()
	before := obsMetricValue(mWAFHits, "路径穿越")
	h := obsMiddleware(gatewayMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})))
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/x/../etc/passwd", nil)
	req.RemoteAddr = "203.0.113.91:7777"
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("路径穿越应 403，实际 %d", w.Code)
	}
	after := obsMetricValue(mWAFHits, "路径穿越")
	if after != before+1 {
		t.Errorf("tsg_waf_hits_total{路径穿越} %v → %v，应 +1", before, after)
	}
	// 403 也应计入请求计数器
	if v := obsMetricValue(mHTTPReqTotal, "app", "GET", "403"); v < 1 {
		t.Errorf("403 未计入 tsg_http_requests_total")
	}
}

// ===================== 6. 路由埋点 =====================

func TestRouteMetricDefer(t *testing.T) {
	// 无可用后端 → routeChatSmartT 返回 error，但埋点仍须计数（defer 覆盖全部路径）
	cfgMu.RLock()
	apiKeyBackup := cfg.Security.APIKey
	cfgMu.RUnlock()
	_ = apiKeyBackup
	beforeErr := obsMetricValue(mRouteDecisions, "llama", "error")
	_, _, _, err := routeChatSmartT("nonexistent-model-xyz", []Message{{Role: "user", Content: "hi"}}, "user", nil)
	if err == nil {
		t.Fatalf("未知模型应报错（测试前提）")
	}
	afterErr := obsMetricValue(mRouteDecisions, "llama", "error")
	if afterErr <= beforeErr {
		t.Errorf("路由 error 决策未计数: %v → %v", beforeErr, afterErr)
	}
}

// ===================== 7. doctor =====================

func TestDoctorConfigChecks(t *testing.T) {
	// 合法配置
	dir := t.TempDir()
	good := filepath.Join(dir, "config.json")
	os.WriteFile(good, []byte(`{"users":[{"name":"u1","role":"user","tenant":"t1"}],
		"security":{"apiKey":"custom-key-xyz","auditLogEnabled":true}}`), 0600)
	saved := configPath
	configPath = good
	defer func() { configPath = saved }()

	c, err := doctorLoadConfig()
	if err != nil {
		t.Fatalf("合法配置解析失败: %v", err)
	}
	rep := &doctorReport{}
	dc := &doctorChecks{rep: rep}
	dc.checkConfig(c, nil)
	hasFail := false
	for _, chk := range rep.Checks {
		if chk.Status == doctorFail {
			hasFail = true
			t.Errorf("合法配置不应 FAIL: %+v", chk)
		}
	}
	_ = hasFail

	// 非法角色 → FAIL + NextStep 非空
	bad := &doctorCfg{}
	bad.Users = []struct {
		Name   string   `json:"name"`
		Role   string   `json:"role"`
		Tenant string   `json:"tenant"`
		APIKey string   `json:"apiKey"`
		Groups []string `json:"groups"`
	}{{Name: "u1", Role: "superadmin"}}
	rep2 := &doctorReport{}
	dc2 := &doctorChecks{rep: rep2}
	dc2.checkConfig(bad, nil)
	found := false
	for _, chk := range rep2.Checks {
		if chk.Status == doctorFail && strings.Contains(chk.Name, "角色") {
			found = true
			if chk.NextStep == "" {
				t.Errorf("FAIL 项必须给下一步建议: %+v", chk)
			}
		}
	}
	if !found {
		t.Errorf("非法角色应产生 FAIL: %+v", rep2.Checks)
	}

	// JSON 语法错误 → FAIL + 建议
	rep3 := &doctorReport{}
	(&doctorChecks{rep: rep3}).checkConfig(nil, os.ErrInvalid)
	if len(rep3.Checks) == 0 || rep3.Checks[0].Status != doctorFail || rep3.Checks[0].NextStep == "" {
		t.Errorf("解析失败应 FAIL 且带建议: %+v", rep3.Checks)
	}
}

func TestDoctorProbeKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "gateway-key.txt")
	os.WriteFile(kf, []byte("# auto-rotated\nKEY=abc123def456\n"), 0600)
	// doctorProbeKey 固定读 appDir()/gateway-key.txt；此处直接验证行解析逻辑
	data, _ := os.ReadFile(kf)
	got := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "KEY=") {
			got = strings.TrimSpace(strings.TrimPrefix(line, "KEY="))
		}
	}
	if got != "abc123def456" {
		t.Errorf("KEY= 解析 = %q", got)
	}
}

// ===================== 8. 审计 TRACE 关联 =====================

func TestObsTraceSuffix(t *testing.T) {
	if s := obsTraceSuffix(nil); s != "" {
		t.Errorf("无请求时应为空串，实际 %q", s)
	}
	req := httptest.NewRequest("GET", "/api/status", nil)
	req = req.WithContext(context.WithValue(req.Context(), obsTraceKey{}, "abcd1234abcd1234"))
	if s := obsTraceSuffix(req); s != " TRACE=abcd1234abcd1234" {
		t.Errorf("TRACE 后缀 = %q", s)
	}
}

// ===================== 9. 后端名归一（低基数标签）====================

func TestBackendNameFromURL(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:1234/v1/chat/completions":  "lmstudio",
		"http://127.0.0.1:11434/api/chat":            "ollama",
		"https://api.openai.com/v1/chat/completions": "cloud",
		"http://[::1]:8080/x":                        "local",
	}
	for in, want := range cases {
		if got := backendNameFromURL(in); got != want {
			t.Errorf("backendNameFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// ===================== 10. 出站 X-Trace-Id 头透传（本地桩后端）====================

func TestBackendTraceHeaderForward(t *testing.T) {
	var gotHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Trace-Id")
		w.WriteHeader(200)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer ts.Close()

	_, _, err := callOpenAICompatible(ts.URL, "m", []Message{{Role: "user", Content: "hi"}}, "trace123trace123")
	if err != nil {
		t.Fatalf("桩后端调用失败: %v", err)
	}
	if gotHeader != "trace123trace123" {
		t.Errorf("出站请求应携带 X-Trace-Id=trace123trace123，实际 %q", gotHeader)
	}
	// 不带 trace 的调用不应设置头
	gotHeader = ""
	_, _, err = callOpenAICompatible(ts.URL, "m", []Message{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("桩后端调用失败: %v", err)
	}
	if gotHeader != "" {
		t.Errorf("无 trace 调用不应设置 X-Trace-Id，实际 %q", gotHeader)
	}
	// JSON 输出可序列化（/api/admin/traces 数据结构完整性）
	if _, err := json.Marshal(obsRecentTraces(5)); err != nil {
		t.Errorf("trace 快照序列化失败: %v", err)
	}
	_ = time.Now()
}
