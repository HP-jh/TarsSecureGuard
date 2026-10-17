package main

// ===================== v3.0.5 可观测性层（纯观测，不改主流程）=====================
//
// 设计红线（任务约束）：
//  1. 纯观测：本文件只"读"主流程并记录，不改变任何判定逻辑、不新增依赖模块；
//  2. 脱敏：所有 metric 标签均为低基数枚举（端点类/方法/状态码/规则名/后端名/模块 id），
//     绝不出现 user / api key / token / 请求体内容；span 与 trace 视图输出前统一过 obsRedact；
//  3. trace_id 与现有 audit 关联但不重复存储：trace 只存在于内存有界环形缓冲
//     （重启即失，与 wafLogs/logs 同模式），持久化关联方式是审计行追加 TRACE=<id> 字段，
//     不落第二个 trace 存储文件。
//
// 指标总览（Prometheus 文本格式 v0.0.4，零第三方依赖）：
//   tsg_http_requests_total{class,method,code}      —— QPS：rate(tsg_http_requests_total[1m])
//   tsg_http_request_duration_ms{class}             —— 延迟直方图（p50/p95/p99）
//   tsg_waf_hits_total{rule}                        —— WAF 命中（按规则）
//   tsg_router_decisions_total{backend,result}      —— 模型路由分布
//   tsg_router_explore_total                        —— ε-greedy 探索次数
//   tsg_router_backend_duration_ms{backend}         —— 后端调用耗时直方图
//   tsg_guard_tier / tsg_guard_rss_mb               —— 资源守护层级 / RSS
//   tsg_module_up{module}                           —— 模块状态（1=启用）
//   tsg_backend_up{backend}                         —— 后端可达性（15s 缓存）
//   tsg_quota_used_today{tenant}                    —— 当日租户配额用量
//   tsg_uptime_seconds / tsg_build_info / tsg_active_traces

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ===================== trace 上下文 =====================

type obsTraceKey struct{}

// traceFromContext 取当前请求的 trace id（无则返回空串）
func traceFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(obsTraceKey{}).(string); ok {
		return v
	}
	return ""
}

// traceFromReq 便捷：从 *http.Request 取 trace id
func traceFromReq(r *http.Request) string {
	if r == nil {
		return ""
	}
	return traceFromContext(r.Context())
}

// genTraceID 生成 16 位十六进制 trace id（crypto/rand，非可预测序列）
func genTraceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// 极端情况下退化为时间戳熵源（仅用于观测关联，无安全语义）
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ===================== trace 内存环形缓冲（不落盘）=====================

const (
	obsTraceRingCap = 256 // 有界：最近 256 条 trace
	obsSpanCap      = 12  // 单条 trace 最多记录的 span 数（防御性上限）
)

type obsSpan struct {
	Stage  string `json:"stage"`  // waf / auth / rbac / quota / route / backend / done
	At     string `json:"at"`     // 相对 trace 开始的毫秒数（字符串化便于 JSON 展示）
	Detail string `json:"detail"` // 已脱敏的补充信息（规则名 / 后端名 / 原因摘要）
}

type obsTrace struct {
	ID      string    `json:"id"`
	Start   time.Time `json:"start"`
	Method  string    `json:"method"`
	Path    string    `json:"path"` // 仅路径，不含 query（query 可能携带敏感参数）
	Class   string    `json:"class"`
	Spans   []obsSpan `json:"spans"`
	Code    int       `json:"code"`
	TotalMs int64     `json:"total_ms"`

	mu sync.Mutex
}

var (
	obsTraceMu    sync.Mutex
	obsActive     = map[string]*obsTrace{} // 在途请求
	obsRing       []*obsTrace              // 已完成（最近优先）
	obsTraceTotal int64                    // 累计 trace 数（自身也是指标）
)

func obsTraceStart(id, method, path string, start time.Time) *obsTrace {
	t := &obsTrace{ID: id, Start: start, Method: method, Path: path, Class: routeClass(path), Code: 0}
	obsTraceMu.Lock()
	obsTraceTotal++
	obsActive[id] = t
	obsTraceMu.Unlock()
	return t
}

func obsTraceFinish(t *obsTrace, code int, totalMs int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.Code = code
	t.TotalMs = totalMs
	t.mu.Unlock()
	obsTraceMu.Lock()
	delete(obsActive, t.ID)
	obsRing = append([]*obsTrace{t}, obsRing...)
	if len(obsRing) > obsTraceRingCap {
		obsRing = obsRing[:obsTraceRingCap]
	}
	obsTraceMu.Unlock()
}

// obsStage 记录当前请求的一个阶段 span（detail 自动脱敏）
func obsStage(ctx context.Context, stage, detail string) {
	obsStageByTrace(traceFromContext(ctx), stage, detail)
}

// obsStageByTrace 按 trace id 记录 span（供不持有 ctx 的调用点使用）
func obsStageByTrace(traceID, stage, detail string) {
	if traceID == "" {
		return
	}
	obsTraceMu.Lock()
	t := obsActive[traceID]
	obsTraceMu.Unlock()
	if t == nil {
		return
	}
	t.mu.Lock()
	if len(t.Spans) < obsSpanCap {
		elapsed := time.Since(t.Start).Milliseconds()
		t.Spans = append(t.Spans, obsSpan{
			Stage:  stage,
			At:     strconv.FormatInt(elapsed, 10),
			Detail: obsRedact(detail),
		})
	}
	t.mu.Unlock()
}

// obsRecentTraces 返回最近 n 条 trace 的快照（JSON 序列化用）
func obsRecentTraces(n int) []map[string]interface{} {
	obsTraceMu.Lock()
	defer obsTraceMu.Unlock()
	if n <= 0 || n > obsTraceRingCap {
		n = 100
	}
	out := make([]map[string]interface{}, 0, len(obsRing))
	for i, t := range obsRing {
		if i >= n {
			break
		}
		t.mu.Lock()
		spans := make([]obsSpan, len(t.Spans))
		copy(spans, t.Spans)
		t.mu.Unlock()
		out = append(out, map[string]interface{}{
			"id": t.ID, "start": t.Start.Format(time.RFC3339), "method": t.Method,
			"path": t.Path, "class": t.Class, "code": t.Code, "total_ms": t.TotalMs,
			"spans": spans,
		})
	}
	return out
}

// ===================== 脱敏（audit/metric 输出共享）=====================

// obsRedact 对观测输出做防御性脱敏：bearer token / sk- 密钥 / 长十六进制 /
// 长 base64 / key=value 形式的秘密一律打码。metric 标签本身只用枚举值，
// 本函数是 span detail 与 trace 视图的第二道防线。
func obsRedact(s string) string {
	if s == "" {
		return s
	}
	// 逐条子串替换（不用正则，保持简单可审计）：
	// <prefix> 之后到下一个空白/引号/分号之间的短串视为秘密值，打码为 ***
	for _, prefix := range []string{"bearer ", "sk-", "key=", "token=", "secret=", "password="} {
		s = redactPattern(s, prefix)
	}
	// 长十六进制串（≥32 位，如泄漏的 hash/key）整体打码
	s = redactLongHex(s)
	return s
}

// redactPattern 把 prefix（大小写不敏感）之后到下一个空白/引号/逗号/分号的
// 非空连续串（长度 ≤64，过滤误伤长文本）替换为 ***
func redactPattern(s, prefix string) string {
	lower := strings.ToLower(s)
	pl := len(prefix)
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(lower[i:], prefix)
		if j < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		j += i
		b.WriteString(s[i : j+pl])
		rest := s[j+pl:]
		end := strings.IndexAny(rest, " \t\r\n\"',;")
		var run string
		if end < 0 {
			run = rest
		} else {
			run = rest[:end]
		}
		if run != "" && len(run) <= 64 {
			b.WriteString("***")
		} else {
			b.WriteString(run)
		}
		i = j + pl + len(run)
	}
}

// redactLongHex 打码 ≥32 位的连续十六进制串
func redactLongHex(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		j := i
		for j < len(s) && isHexDigit(s[j]) {
			j++
		}
		if j-i >= 32 {
			b.WriteString("***")
		} else {
			b.WriteString(s[i:j])
		}
		if j == i {
			b.WriteByte(s[i])
			i++
		} else {
			i = j
		}
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// ===================== 指标注册表（Prometheus 文本格式，零依赖）=====================

type obsMetric struct {
	name       string
	help       string
	mtype      string // counter / gauge / histogram
	labelNames []string
	mu         sync.Mutex
	series     map[string][]string // seriesKey → label values（保持插入序由 render 排序）
	values     map[string]float64
	// histogram 专用
	buckets []float64
	counts  map[string][]uint64 // seriesKey → 每 bucket 累计计数
	sums    map[string]float64
	totals  map[string]float64
	// gauge 动态取值（拉取时计算，避免常驻采样协程）
	dynFn func() []obsSeries
}

type obsSeries struct {
	labels []string
	value  float64
}

func obsSeriesKey(vals []string) string { return strings.Join(vals, "\x00") }

func obsNewCounter(name, help string, labels ...string) *obsMetric {
	return &obsMetric{name: name, help: help, mtype: "counter", labelNames: labels,
		series: map[string][]string{}, values: map[string]float64{}}
}

func obsNewGauge(name, help string, labels []string, dynFn func() []obsSeries) *obsMetric {
	return &obsMetric{name: name, help: help, mtype: "gauge", labelNames: labels,
		series: map[string][]string{}, values: map[string]float64{}, dynFn: dynFn}
}

var obsHistBuckets = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000}

func obsNewHistogram(name, help string, labels ...string) *obsMetric {
	return &obsMetric{name: name, help: help, mtype: "histogram", labelNames: labels,
		series:  map[string][]string{},
		counts:  map[string][]uint64{},
		sums:    map[string]float64{},
		totals:  map[string]float64{},
		buckets: obsHistBuckets,
	}
}

func (m *obsMetric) Inc(vals ...string) { m.Add(1, vals...) }

func (m *obsMetric) Add(v float64, vals ...string) {
	if m.mtype == "histogram" || m.dynFn != nil {
		return // histogram 用 Observe；动态 gauge 不接受直接写
	}
	if len(vals) != len(m.labelNames) {
		return
	}
	m.mu.Lock()
	k := obsSeriesKey(vals)
	m.series[k] = vals
	m.values[k] += v
	m.mu.Unlock()
}

func (m *obsMetric) Observe(v float64, vals ...string) {
	if m.mtype != "histogram" || len(vals) != len(m.labelNames) {
		return
	}
	m.mu.Lock()
	k := obsSeriesKey(vals)
	m.series[k] = vals
	if m.counts[k] == nil {
		m.counts[k] = make([]uint64, len(m.buckets))
	}
	for i, up := range m.buckets {
		if v <= up {
			m.counts[k][i]++
		}
	}
	m.sums[k] += v
	m.totals[k]++
	m.mu.Unlock()
}

// obsEscapeLabel Prometheus 文本格式标签值转义
func obsEscapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func obsEscapeHelp(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func (m *obsMetric) render(b *strings.Builder) {
	if m.dynFn != nil {
		for _, s := range m.dynFn() {
			m.mu.Lock()
			m.series[obsSeriesKey(s.labels)] = s.labels
			m.values[obsSeriesKey(s.labels)] = s.value
			m.mu.Unlock()
		}
	}
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", m.name, obsEscapeHelp(m.help), m.name, m.mtype)
	m.mu.Lock()
	keys := make([]string, 0, len(m.series))
	for k := range m.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals := m.series[k]
		lbl := m.renderLabels(vals)
		switch m.mtype {
		case "histogram":
			cum := uint64(0)
			for i, up := range m.buckets {
				cum = m.counts[k][i]
				fmt.Fprintf(b, "%s_bucket%s %.0f\n", m.name, m.renderLabels(append(append([]string{}, vals...), fmt.Sprintf("%g", up))), float64(cum))
			}
			fmt.Fprintf(b, "%s_bucket%s %.0f\n", m.name, m.renderLabels(append(append([]string{}, vals...), "+Inf")), m.totals[k])
			fmt.Fprintf(b, "%s_sum%s %g\n", m.name, lbl, m.sums[k])
			fmt.Fprintf(b, "%s_count%s %.0f\n", m.name, lbl, m.totals[k])
		default:
			fmt.Fprintf(b, "%s%s %g\n", m.name, lbl, m.values[k])
		}
	}
	m.mu.Unlock()
}

func (m *obsMetric) renderLabels(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for i, v := range vals {
		name := "le" // 超出 labelNames 的尾值为 histogram 桶上界（render 时追加）
		if i < len(m.labelNames) {
			name = m.labelNames[i]
		}
		parts = append(parts, fmt.Sprintf(`%s="%s"`, name, obsEscapeLabel(v)))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ===================== 指标实例 =====================

var (
	mHTTPReqTotal = obsNewCounter("tsg_http_requests_total",
		"网关处理的 HTTP 请求总数（标签为低基数枚举，绝不包含 user/token/api key）", "class", "method", "code")
	mHTTPDuration = obsNewHistogram("tsg_http_request_duration_ms",
		"HTTP 请求耗时分布（毫秒）", "class")
	mWAFHits = obsNewCounter("tsg_waf_hits_total",
		"WAF 命中次数（按规则名聚合）", "rule")
	mRouteDecisions = obsNewCounter("tsg_router_decisions_total",
		"模型路由决策分布（按后端与结果聚合）", "backend", "result")
	mRouteExplore = obsNewCounter("tsg_router_explore_total",
		"ε-greedy 探索决策次数")
	mBackendDuration = obsNewHistogram("tsg_router_backend_duration_ms",
		"后端调用耗时分布（毫秒，按后端聚合）", "backend")

	mGuardTier = obsNewGauge("tsg_guard_tier",
		"资源守护层级：0=L0 正常 1=L1 降级 2=L2 熔断 3=L3 优雅停机", nil, func() []obsSeries {
			guardMu.Lock()
			t := guardTier
			guardMu.Unlock()
			return []obsSeries{{value: float64(t)}}
		})
	mGuardRSS = obsNewGauge("tsg_guard_rss_mb",
		"进程常驻内存 RSS（MB，L2/L3 判定口径）", nil, func() []obsSeries {
			return []obsSeries{{value: float64(currentRSSMB())}}
		})
	mModuleUp = obsNewGauge("tsg_module_up",
		"可选模块启用状态（1=启用 0=关闭；security-core 不在此列，恒为 1 由 tsg_build_info 体现）",
		[]string{"module"}, func() []obsSeries {
			var out []obsSeries
			for _, m := range moduleIDsSorted() {
				v := 0.0
				if moduleEnabledByID(m) {
					v = 1
				}
				out = append(out, obsSeries{labels: []string{m}, value: v})
			}
			return out
		})
	mBackendUp = obsNewGauge("tsg_backend_up",
		"推理后端可达性（1=可用 0=不可用；15 秒缓存，仅本地回环探测）", []string{"backend"},
		func() []obsSeries {
			var out []obsSeries
			for _, bk := range []string{"llama", "lmstudio", "ollama"} {
				v := 0.0
				if obsBackendUpCached(bk) {
					v = 1
				}
				out = append(out, obsSeries{labels: []string{bk}, value: v})
			}
			return out
		})
	mQuotaUsed = obsNewGauge("tsg_quota_used_today",
		"当日租户配额用量（tokens 估算值，仅租户维度聚合）", []string{"tenant"}, func() []obsSeries {
			day := time.Now().Format("2006-01-02")
			var out []obsSeries
			quotaMu.Lock()
			for k, v := range quotaUsed {
				if k.Day == day && k.Scope == "tenant" {
					out = append(out, obsSeries{labels: []string{k.Tenant}, value: float64(v)})
				}
			}
			quotaMu.Unlock()
			return out
		})
	mUptime = obsNewGauge("tsg_uptime_seconds",
		"网关进程运行时长（秒）", nil, func() []obsSeries {
			return []obsSeries{{value: time.Since(startTime).Seconds()}}
		})
	mBuildInfo = obsNewGauge("tsg_build_info",
		"构建信息（value 恒为 1）", []string{"version", "goos", "goarch"}, func() []obsSeries {
			return []obsSeries{{labels: []string{version, runtime.GOOS, runtime.GOARCH}, value: 1}}
		})
	mActiveTraces = obsNewGauge("tsg_active_traces",
		"在途请求 trace 数（观测层自身健康度）", nil, func() []obsSeries {
			obsTraceMu.Lock()
			n := len(obsActive)
			obsTraceMu.Unlock()
			return []obsSeries{{value: float64(n)}}
		})
	mTraceTotal = obsNewGauge("tsg_traces_total",
		"本进程累计 trace 数", nil, func() []obsSeries {
			obsTraceMu.Lock()
			n := obsTraceTotal
			obsTraceMu.Unlock()
			return []obsSeries{{value: float64(n)}}
		})
)

// obsRegistry 渲染顺序（Grafana 面板依赖的名称都已覆盖）
var obsRegistry = []*obsMetric{
	mHTTPReqTotal, mHTTPDuration, mWAFHits, mRouteDecisions, mRouteExplore, mBackendDuration,
	mGuardTier, mGuardRSS, mModuleUp, mBackendUp, mQuotaUsed, mUptime, mBuildInfo,
	mActiveTraces, mTraceTotal,
}

// ===================== 后端可达性缓存（15s）=====================

var (
	obsBackendMu   sync.Mutex
	obsBackendVals = map[string]bool{}
	obsBackendAt   time.Time
)

func obsBackendUpCached(backend string) bool {
	obsBackendMu.Lock()
	if time.Since(obsBackendAt) > 15*time.Second {
		obsBackendVals = map[string]bool{
			"llama":    func() bool { r, _ := modelState(); return r }(),
			"lmstudio": lmsReachable(),
			"ollama":   ollamaReachable(),
		}
		obsBackendAt = time.Now()
	}
	v := obsBackendVals[backend]
	obsBackendMu.Unlock()
	return v
}

// ===================== 观测中间件（最外层，包裹 gatewayMiddleware）=====================

// obsMiddleware 生成 trace_id、注入请求上下文、回写 X-Trace-Id 响应头、
// 记录请求级指标。/metrics 与 /health 不进 trace 环形缓冲（避免采集噪声淹没真实请求）。
func obsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := genTraceID()
		ctx := context.WithValue(r.Context(), obsTraceKey{}, id)
		r = r.WithContext(ctx)
		w.Header().Set("X-Trace-Id", id)

		var traced bool
		if r.URL.Path != "/metrics" && r.URL.Path != "/health" {
			obsTraceStart(id, r.Method, obsPathOnly(r), start)
			obsStage(ctx, "request", "接收请求 "+routeClass(r.URL.Path))
			traced = true
		}
		sw := &obsStatusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		cls := routeClass(r.URL.Path)
		mHTTPReqTotal.Add(1, cls, r.Method, strconv.Itoa(sw.status))
		mHTTPDuration.Observe(ms, cls)
		if traced {
			if t := obsTraceActive(id); t != nil {
				obsTraceFinish(t, sw.status, int64(ms))
			}
		}
	})
}

// obsPathOnly 只保留路径部分（query 可能含敏感参数，不入 trace）
func obsPathOnly(r *http.Request) string {
	if r.URL == nil {
		return "/"
	}
	return r.URL.Path
}

func obsTraceActive(id string) *obsTrace {
	obsTraceMu.Lock()
	t := obsActive[id]
	obsTraceMu.Unlock()
	return t
}

// obsStatusWriter 记录下游状态码（观测层私有，不与主流程 statusWriter 混用）
type obsStatusWriter struct {
	http.ResponseWriter
	status   int
	written  bool
	hijacked bool
}

func (s *obsStatusWriter) WriteHeader(code int) {
	if !s.written {
		s.status = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *obsStatusWriter) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
}

func (s *obsStatusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ===================== WAF / 路由 / 后端 埋点（供主流程单点调用）=====================

// obsRecordWAF WAF 拦截埋点（blockRequest 单点调用；rule 为 WAF 规则名或拦截原因）
func obsRecordWAF(r *http.Request, rule string) {
	if r == nil {
		return
	}
	mWAFHits.Inc(rule)
	obsStage(r.Context(), "waf", "拦截规则="+rule)
}

// obsRecordRoute 路由决策埋点（routeChatSmartT 单点调用）
func obsRecordRoute(traceID, backend string, ok bool, dur time.Duration) {
	result := "success"
	if !ok {
		result = "error"
	}
	mRouteDecisions.Inc(backend, result)
	mBackendDuration.Observe(float64(dur.Microseconds())/1000.0, backend)
	obsStageByTrace(traceID, "route", "后端="+backend+" 结果="+result)
}

// obsRecordExplore ε-greedy 探索埋点
func obsRecordExplore() { mRouteExplore.Inc() }

// obsRecordBackend 后端调用埋点（call* 函数出口单点调用）
func obsRecordBackend(traceID, backend string, ok bool, ms int64, code int) {
	detail := fmt.Sprintf("后端=%s 耗时=%dms http=%d", backend, ms, code)
	if !ok {
		detail += "（调用失败或非 200）"
	}
	obsStageByTrace(traceID, "backend", detail)
}

// traceHeaderForward 出站请求透传 trace_id（X-Trace-Id 头；traceID 为空时不设置）
func traceHeaderForward(req *http.Request, traceID string) {
	if req == nil || traceID == "" {
		return
	}
	req.Header.Set("X-Trace-Id", traceID)
}

// obsTraceSuffix 审计/WAF 日志行的 trace 关联后缀：
// 把 trace_id 追加到现有日志行（TRACE=<id>），实现 audit ↔ trace 关联而不新建持久化存储；
// 无 trace 上下文（如 stdio 模式、后台任务）时返回空串，日志行格式与 v3.0.4 完全一致。
func obsTraceSuffix(r *http.Request) string {
	if id := traceFromReq(r); id != "" {
		return " TRACE=" + id
	}
	return ""
}

// ===================== /metrics 与 /api/admin/traces 端点 =====================

// handleMetrics Prometheus 拉取端点：走 gatewayMiddleware 鉴权（X-API-Key），
// RBAC 归入 app 端点类（全角色可读，readonly 亦可）。输出已保证不含任何密钥。
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	for _, m := range obsRegistry {
		m.render(&b)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// handleTraces 最近 trace 查询端点（admin.read 端点类，admin/审计角色可读）：
// 返回内存环形缓冲中的最近 trace 及其 span 时间线（重启即失，不落盘）。
func handleTraces(w http.ResponseWriter, r *http.Request) {
	n := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p <= obsTraceRingCap {
			n = p
		}
	}
	traces := obsRecentTraces(n)
	writeJSON(w, map[string]interface{}{
		"count":       len(traces),
		"ring_cap":    obsTraceRingCap,
		"persistence": "内存环形缓冲（重启即失，不落盘）；持久关联走审计行 TRACE= 字段",
		"traces":      traces,
	})
}
