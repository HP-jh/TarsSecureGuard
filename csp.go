package main

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ===================== CSP 策略自动生成（v4.34.0）=====================
//
// 目标：把 v4.6.4 的静态 CSP 升级为「基于响应体实际资源」动态生成的最小化策略。
// 只对 HTML 响应生效（Content-Type 含 text/html）；API/JSON 保持静态兜底策略。
//
// 能力：
//   - 解析响应 HTML，提取 <script src="..."> / <link href="..."> / <img src="..."> 等
//   - 按资源协议+主机分组，生成精确 allowlist（避免 'self' 过度宽松）
//   - report-only 模式：只发 CSP-Report-Only 头，不阻断（供管理员观察误报）
//   - enforce 模式：发 Content-Security-Policy 头，浏览器强制执行

// CSPConfig 配置段（嵌在 Config.Security 下，JSON 键：csp）
type CSPConfig struct {
	Enabled    bool   `json:"enabled"`    // 默认 true
	Mode       string `json:"mode"`       // "enforce" | "report-only"（默认 enforce）
	ReportURI  string `json:"reportURI"`  // 违规报告接收端点（可选）
	StaticOnly bool   `json:"staticOnly"` // true=关闭动态解析，只用静态策略（降级开关）
}

// cspDirective 单条 CSP 指令（如 script-src 'self' https://cdn.example.com）
type cspDirective struct {
	name   string
	values []string
}

// String 序列化为 "name v1 v2 v3"
func (d cspDirective) String() string {
	if len(d.values) == 0 {
		return d.name + " 'none'"
	}
	return d.name + " " + strings.Join(d.values, " ")
}

// cspPolicy 完整策略（多指令）
type cspPolicy struct {
	directives []cspDirective
}

func (p cspPolicy) String() string {
	var parts []string
	for _, d := range p.directives {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, "; ")
}

// resourceRef 提取到的单个资源引用
type resourceRef struct {
	directive string // script-src / style-src / img-src 等
	value     string // 'self' / https://cdn.com / data: 等
}

// -------------------- 响应拦截器（捕获 HTML 响应体）--------------------

// cspInterceptWriter 包装 http.ResponseWriter，在 Write 时缓冲前 N 字节用于 HTML 解析
// 只在 Content-Type 为 text/html 时启用；非 HTML 直接透传。
type cspInterceptWriter struct {
	http.ResponseWriter
	isHTML      bool
	buf         *bytes.Buffer
	wroteHeader bool
	maxBuf      int
}

func newCSPInterceptWriter(w http.ResponseWriter) *cspInterceptWriter {
	return &cspInterceptWriter{
		ResponseWriter: w,
		buf:            &bytes.Buffer{},
		maxBuf:         256 << 10, // 最多缓冲 256KB（前端单文件 HTML 通常 <100KB）
	}
}

func (ci *cspInterceptWriter) WriteHeader(code int) {
	if ci.wroteHeader {
		return
	}
	ci.wroteHeader = true
	ct := ci.ResponseWriter.Header().Get("Content-Type")
	ci.isHTML = strings.Contains(ct, "text/html")
	ci.ResponseWriter.WriteHeader(code)
}

func (ci *cspInterceptWriter) Write(p []byte) (int, error) {
	if !ci.wroteHeader {
		ci.WriteHeader(http.StatusOK)
	}
	if ci.isHTML && ci.buf != nil {
		if ci.buf.Len() < ci.maxBuf {
			remaining := ci.maxBuf - ci.buf.Len()
			if len(p) > remaining {
				ci.buf.Write(p[:remaining])
			} else {
				ci.buf.Write(p)
			}
		}
		// 同时继续写入底层 ResponseWriter，不阻塞响应
	}
	return ci.ResponseWriter.Write(p)
}

// htmlBody 返回已缓冲的 HTML 内容（用于 CSP 分析）
func (ci *cspInterceptWriter) htmlBody() []byte {
	if !ci.isHTML || ci.buf == nil {
		return nil
	}
	return ci.buf.Bytes()
}

// -------------------- HTML 资源提取 --------------------

// 正则：提取标签属性（不依赖外部 HTML 解析库，零新增依赖）
var (
	// <script src="..."> 或 <script>（内联脚本）
	reScriptSrc = regexp.MustCompile(`(?i)<script\s+[^>]*src\s*=\s*["']([^"']+)["']`)
	// <link rel="stylesheet" href="...">
	reLinkHref = regexp.MustCompile(`(?i)<link\s+[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["']([^"']+)["']`)
	reLinkHref2 = regexp.MustCompile(`(?i)<link\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["']stylesheet["']`)
	// <img src="...">
	reImgSrc = regexp.MustCompile(`(?i)<img\s+[^>]*src\s*=\s*["']([^"']+)["']`)
	// <iframe src="...">
	reIframeSrc = regexp.MustCompile(`(?i)<iframe\s+[^>]*src\s*=\s*["']([^"']+)["']`)
	// <object data="...">
	reObjectData = regexp.MustCompile(`(?i)<object\s+[^>]*data\s*=\s*["']([^"']+)["']`)
	// <embed src="...">
	reEmbedSrc = regexp.MustCompile(`(?i)<embed\s+[^>]*src\s*=\s*["']([^"']+)["']`)
	// <form action="...">
	reFormAction = regexp.MustCompile(`(?i)<form\s+[^>]*action\s*=\s*["']([^"']+)["']`)
	// <base href="...">
	reBaseHref = regexp.MustCompile(`(?i)<base\s+[^>]*href\s*=\s*["']([^"']+)["']`)
	// <audio src="..."> / <video src="...">
	reMediaSrc = regexp.MustCompile(`(?i)<(?:audio|video)\s+[^>]*src\s*=\s*["']([^"']+)["']`)
	// <source src="...">
	reSourceSrc = regexp.MustCompile(`(?i)<source\s+[^>]*src\s*=\s*["']([^"']+)["']`)
	// <link rel="icon" href="...">
	reIconHref = regexp.MustCompile(`(?i)<link\s+[^>]*(?:rel\s*=\s*["'](?:icon|shortcut icon)["'])[^>]*href\s*=\s*["']([^"']+)["']`)
	reIconHref2 = regexp.MustCompile(`(?i)<link\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*(?:rel\s*=\s*["'](?:icon|shortcut icon)["'])`)
	// 内联 <script>（无 src 属性）
	reInlineScript = regexp.MustCompile(`(?i)<script[\s>][^<]*(?:<\/script>)?`)
	// 内联 on* 事件处理（onerror, onload 等）
	reInlineEvent = regexp.MustCompile(`(?i)\s(on\w+)\s*=\s*["']`)
	// style 属性
	reInlineStyle = regexp.MustCompile(`(?i)\sstyle\s*=\s*["']`)
)

// extractResources 从 HTML 中提取所有资源引用
func extractResources(html []byte) []resourceRef {
	var refs []resourceRef
	s := string(html)

	// script src
	for _, m := range reScriptSrc.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"script-src", normalizeSrc(m[1])})
	}
	// link stylesheet href
	for _, m := range reLinkHref.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"style-src", normalizeSrc(m[1])})
	}
	for _, m := range reLinkHref2.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"style-src", normalizeSrc(m[1])})
	}
	// img src
	for _, m := range reImgSrc.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"img-src", normalizeSrc(m[1])})
	}
	// iframe src
	for _, m := range reIframeSrc.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"frame-src", normalizeSrc(m[1])})
	}
	// object data
	for _, m := range reObjectData.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"object-src", normalizeSrc(m[1])})
	}
	// embed src
	for _, m := range reEmbedSrc.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"frame-src", normalizeSrc(m[1])})
	}
	// form action
	for _, m := range reFormAction.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"form-action", normalizeSrc(m[1])})
	}
	// base href（影响所有相对 URL 的解析基准）
	for _, m := range reBaseHref.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"base-uri", normalizeSrc(m[1])})
	}
	// audio/video src
	for _, m := range reMediaSrc.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"media-src", normalizeSrc(m[1])})
	}
	// source src
	for _, m := range reSourceSrc.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"media-src", normalizeSrc(m[1])})
	}
	// icon href
	for _, m := range reIconHref.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"img-src", normalizeSrc(m[1])})
	}
	for _, m := range reIconHref2.FindAllStringSubmatch(s, -1) {
		refs = append(refs, resourceRef{"img-src", normalizeSrc(m[1])})
	}

	// 内联脚本检测：只要存在 <script> 无 src，就需要 'unsafe-inline'
	if hasInlineScript(s) {
		refs = append(refs, resourceRef{"script-src", "'unsafe-inline'"})
	}
	// 内联事件处理检测
	if reInlineEvent.MatchString(s) {
		refs = append(refs, resourceRef{"script-src", "'unsafe-inline'"})
	}
	// 内联 style 检测
	if reInlineStyle.MatchString(s) {
		refs = append(refs, resourceRef{"style-src", "'unsafe-inline'"})
	}
	// <style> 标签检测
	if strings.Contains(strings.ToLower(s), "<style") {
		refs = append(refs, resourceRef{"style-src", "'unsafe-inline'"})
	}

	return refs
}

// hasInlineScript 检测是否存在无 src 属性的内联 <script> 标签
func hasInlineScript(s string) bool {
	// 简单检测：找到 <script 后，如果在同一标签闭合前没有 src=，则为内联
	lower := strings.ToLower(s)
	idx := 0
	for {
		i := strings.Index(lower[idx:], "<script")
		if i < 0 {
			break
		}
		i += idx
		// 找到该标签的结束位置 (> 或 />)
		end := strings.IndexAny(lower[i:], ">/")
		if end < 0 {
			break
		}
		tag := lower[i : i+end]
		if !strings.Contains(tag, "src=") {
			return true
		}
		idx = i + end + 1
	}
	return false
}

// normalizeSrc 将 URL 归一化为 CSP allowlist 值
// 相对路径 → 'self'；data: / blob: → 保留；绝对 URL → 保留 scheme+host；
// javascript: / vbscript: → 丢弃（XSS 向量，不应出现在合法策略中）
func normalizeSrc(src string) string {
	src = strings.TrimSpace(src)
	if src == "" {
		return "'self'"
	}
	// 协议相对 URL（//cdn.com/js.js）→ 补全 scheme 并去掉路径
	if strings.HasPrefix(src, "//") {
		src = "https:" + src
		rest := src[8:] // 去掉 https://
		if slash := strings.Index(rest, "/"); slash >= 0 {
			rest = rest[:slash]
		}
		return "https://" + rest
	}
	// data: / blob: / filesystem: 等保留 scheme 即可（CSP allowlist 只认 scheme）
	if strings.HasPrefix(src, "data:") {
		return "data:"
	}
	if strings.HasPrefix(src, "blob:") {
		return "blob:"
	}
	if strings.HasPrefix(src, "filesystem:") {
		return "filesystem:"
	}
	// 危险协议直接丢弃（返回空，调用方过滤）
	lower := strings.ToLower(src)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "vbscript:") || strings.HasPrefix(lower, "data:") && strings.Contains(lower, "javascript") {
		return ""
	}
	// 相对路径（不以协议开头）
	if !strings.Contains(src, "://") {
		return "'self'"
	}
	// 绝对 URL：只保留 scheme + host（去掉路径、查询、片段）
	// 例如 https://cdn.example.com/path/file.js → https://cdn.example.com
	// 但为了最小化，保留完整 origin（scheme+host+port）
	if idx := strings.Index(src, "://"); idx > 0 {
		rest := src[idx+3:]
		// 去掉路径部分
		if slash := strings.Index(rest, "/"); slash >= 0 {
			rest = rest[:slash]
		}
		return src[:idx+3] + rest
	}
	return src
}

// -------------------- 策略生成 --------------------

// buildCSPPolicy 基于提取的资源引用生成最小化 CSP 策略
func buildCSPPolicy(refs []resourceRef, cfg CSPConfig) cspPolicy {
	// 按指令分组去重
	groups := map[string]map[string]bool{}
	for _, r := range refs {
		if r.value == "" {
			continue
		}
		if groups[r.directive] == nil {
			groups[r.directive] = map[string]bool{}
		}
		groups[r.directive][r.value] = true
	}

	// 指令排序（保证输出稳定，便于测试）
	order := []string{
		"default-src", "script-src", "style-src", "img-src",
		"connect-src", "font-src", "frame-src", "object-src",
		"media-src", "form-action", "base-uri", "frame-ancestors",
	}

	var directives []cspDirective
	for _, name := range order {
		vals, ok := groups[name]
		if !ok {
			continue
		}
		// 去重并排序
		var uniq []string
		for v := range vals {
			uniq = append(uniq, v)
		}
		sort.Strings(uniq)
		directives = append(directives, cspDirective{name: name, values: uniq})
	}

	// 兜底：如果没提取到任何指令，保持基础策略
	if len(directives) == 0 {
		directives = []cspDirective{
			{name: "default-src", values: []string{"'self'"}},
			{name: "script-src", values: []string{"'self'", "'unsafe-inline'"}},
			{name: "style-src", values: []string{"'self'", "'unsafe-inline'"}},
			{name: "img-src", values: []string{"'self'", "data:"}},
			{name: "connect-src", values: []string{"'self'", "http://127.0.0.1:*"}},
			{name: "font-src", values: []string{"'self'", "data:"}},
			{name: "object-src", values: []string{"'none'"}},
			{name: "base-uri", values: []string{"'self'"}},
			{name: "form-action", values: []string{"'self'"}},
			{name: "frame-ancestors", values: []string{"'none'"}},
		}
	}

	// script-src 必须包含 'self'（SPA 路由切换用）
	if vals, ok := groups["script-src"]; ok {
		vals["'self'"] = true
	}
	// style-src 必须包含 'self'
	if vals, ok := groups["style-src"]; ok {
		vals["'self'"] = true
	}
	// img-src 必须包含 data:（前端常见内联图标）
	if vals, ok := groups["img-src"]; ok {
		vals["data:"] = true
		vals["'self'"] = true
	}
	// connect-src 必须包含 'self' 和本机回环（Tauri 桌面端需要）
	if vals, ok := groups["connect-src"]; ok {
		vals["'self'"] = true
		vals["http://127.0.0.1:*"] = true
	}

	// 如果配置了 report-uri，追加 report-to / report-uri
	if cfg.ReportURI != "" {
		directives = append(directives, cspDirective{name: "report-uri", values: []string{cfg.ReportURI}})
	}

	return cspPolicy{directives: directives}
}

// -------------------- 配置读取 --------------------

func cspConfig() CSPConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.Security.CSP
}

func cspEnabled() bool {
	c := cspConfig()
	// 默认启用（nil/零值视为开启，与 WAF 一致）
	return !c.StaticOnly
}

func cspReportOnly() bool {
	return cspConfig().Mode == "report-only"
}

// -------------------- 中间件集成 --------------------

// setDynamicCSP 在 setSecurityHeaders 中调用。
// 对 HTML 响应启用动态 CSP；非 HTML / 降级模式回退静态策略。
// 返回一个包装过的 ResponseWriter，供后续 handler 使用。
func setDynamicCSP(w http.ResponseWriter, r *http.Request) http.ResponseWriter {
	if !cspEnabled() {
		// 降级：静态策略（v4.6.4 行为）
		setStaticCSP(w)
		return w
	}

	// 非 HTML 请求直接发静态策略（API/JSON 不需要动态解析）
	// 但 Content-Type 此时可能还没设置（handler 在 Write 时才设），
	// 所以用拦截器延后决策。
	ci := newCSPInterceptWriter(w)
	return ci
}

// setStaticCSP v4.6.4 静态兜底策略
func setStaticCSP(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
		"img-src 'self' data:; connect-src 'self' http://127.0.0.1:*; font-src 'self' data:; "+
		"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
}

// flushCSP 在 handler 完成后调用，基于实际响应体生成并注入 CSP
func flushCSP(ci *cspInterceptWriter, w http.ResponseWriter) {
	if ci == nil {
		return
	}
	body := ci.htmlBody()
	if len(body) == 0 {
		// 未捕获到 HTML 内容，保持静态策略
		setStaticCSP(w)
		return
	}

	refs := extractResources(body)
	policy := buildCSPPolicy(refs, cspConfig())
	policyStr := policy.String()

	// report-only 模式：发 CSP-Report-Only；enforce 模式：发 Content-Security-Policy
	if cspReportOnly() {
		w.Header().Set("Content-Security-Policy-Report-Only", policyStr)
	} else {
		w.Header().Set("Content-Security-Policy", policyStr)
	}

	// 审计：生成动态 CSP 事件（仅当策略与静态兜底明显不同时记录，避免噪声）
	if !strings.Contains(policyStr, "script-src 'self' 'unsafe-inline'") || len(refs) > 5 {
		auditLog("CSP_GENERATED", "system", fmt.Sprintf("动态 CSP: %s", truncateCSP(policyStr, 200)))
	}
}

func truncateCSP(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// -------------------- 缓存（避免重复解析相同响应）--------------------

// cspCache HTML→策略 的短期缓存（按响应体 SHA256 键控），减少重复解析开销
var (
	cspCacheMu sync.RWMutex
	cspCache   = map[string]string{} // body hash → policy string
	cspCacheCap = 64
)

func cachedCSP(body []byte) (string, bool) {
	h := quickHash(body)
	cspCacheMu.RLock()
	v, ok := cspCache[h]
	cspCacheMu.RUnlock()
	return v, ok
}

func storeCSP(body []byte, policy string) {
	cspCacheMu.Lock()
	defer cspCacheMu.Unlock()
	if len(cspCache) >= cspCacheCap {
		// 简单淘汰：清空（策略生成成本很低，缓存只是锦上添花）
		cspCache = map[string]string{}
	}
	cspCache[quickHash(body)] = policy
}

// quickHash 简单 64-bit FNV-1a（足够做缓存键）
func quickHash(b []byte) string {
	var h uint64 = 0xcbf29ce484222325
	for _, c := range b {
		h ^= uint64(c)
		h *= 0x100000001b3
	}
	return fmt.Sprintf("%016x", h)
}

// -------------------- 辅助：为 gatewayMiddleware 提供的一站式调用 --------------------
//
// gatewayMiddleware 中已调用 setSecurityHeaders(w, r)。
// 为最小化改动，把 setSecurityHeaders 改为：
//   1) 发其他安全头（X-Frame-Options 等）
//   2) 返回一个可能包装过的 ResponseWriter
//   3) 在请求结束时 flushCSP
//
// 由于 gatewayMiddleware 内部结构固定，实际做法是在调用链末尾 flush。
// 这里提供 cspWrapHandler 供需要精确控制的场景使用。

// cspWrapHandler 包装 http.Handler，在 ServeHTTP 结束后对 HTML 响应注入动态 CSP。
// 用于 gatewayMiddleware 中对 "public route" 路径（前端页面）做动态 CSP。
func cspWrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cspEnabled() {
			setStaticCSP(w)
			next.ServeHTTP(w, r)
			return
		}
		ci := newCSPInterceptWriter(w)
		next.ServeHTTP(ci, r)
		flushCSP(ci, w)
	})
}
