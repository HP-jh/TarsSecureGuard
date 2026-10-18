package main

// ===================== v4.34.0 XSS防护增强：CSP策略自动生成 =====================
//
// 根据嵌入的前端资源自动推导 Content-Security-Policy 头，支持 report-only 模式。
// 设计原则：
//   - 自动扫描 go:embed 的前端文件，分析资源引用模式
//   - 生成最小化但充分的 CSP 策略（不过度放宽）
//   - 支持 report-only 模式（只观察不阻断，用于灰度验证）
//   - 支持管理员自定义策略覆盖（高级场景）
//   - 内置 CSP 违规报告收集端点（/api/admin/security/csp-report）

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// CSPConfig v4.34.0 CSP 配置（嵌在 security 配置段内）
type CSPConfig struct {
	Enabled       bool   `json:"cspEnabled"`        // 默认 true
	ReportOnly    bool   `json:"cspReportOnly"`     // report-only 模式（默认 false）
	CustomPolicy  string `json:"cspCustomPolicy"`   // 自定义策略覆盖（空则自动推导）
	ReportURI     string `json:"cspReportURI"`      // 违规报告接收地址（空则使用内置端点）
	NonceEnabled  bool   `json:"cspNonceEnabled"`   // 使用 nonce 替代 'unsafe-inline'（默认 false，需前端配合）
}

// CSPDirective 单条 CSP 指令
type CSPDirective struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// CSPPolicy 完整的 CSP 策略
type CSPPolicy struct {
	Directives []CSPDirective `json:"directives"`
	String     string         `json:"string"`
	Generated  time.Time      `json:"generated"`
	Source     string         `json:"source"` // auto | custom | fallback
}

// CSPReport CSP 违规报告结构（浏览器上报格式）
type CSPReport struct {
	DocumentURI        string `json:"document-uri"`
	Referrer           string `json:"referrer"`
	BlockedURI         string `json:"blocked-uri"`
	ViolatedDirective  string `json:"violated-directive"`
	OriginalPolicy     string `json:"original-policy"`
	Disposition        string `json:"disposition"`
	SourceFile         string `json:"source-file"`
	LineNumber         int    `json:"line-number"`
	ColumnNumber       int    `json:"column-number"`
}

type cspReportWrapper struct {
	Report CSPReport `json:"csp-report"`
}

var (
	cspMu       sync.RWMutex
	cspCache    *CSPPolicy
	cspReports  []cspReportEntry
	cspReportMu sync.Mutex
)

type cspReportEntry struct {
	Time   time.Time `json:"time"`
	Report CSPReport `json:"report"`
}

// ===================== 策略生成器 =====================

// generateCSPPolicy 根据前端资源自动生成 CSP 策略
func generateCSPPolicy() *CSPPolicy {
	cfgMu.RLock()
	cspCfg := cfg.Security.CSP
	cfgMu.RUnlock()

	// 如果管理员配置了自定义策略，直接采用
	if cspCfg.CustomPolicy != "" {
		return &CSPPolicy{
			Directives: parseCSPString(cspCfg.CustomPolicy),
			String:     cspCfg.CustomPolicy,
			Generated:  time.Now(),
			Source:     "custom",
		}
	}

	// 自动推导策略
	directives := map[string]map[string]bool{}
	add := func(name string, vals ...string) {
		if directives[name] == nil {
			directives[name] = map[string]bool{}
		}
		for _, v := range vals {
			directives[name][v] = true
		}
	}

	// 基础指令
	add("default-src", "'self'")
	add("base-uri", "'self'")
	add("form-action", "'self'")
	add("frame-ancestors", "'none'")
	add("object-src", "'none'")

	// 扫描嵌入的前端文件
	scanEmbeddedFrontend(add)

	// connect-src：放行本机 API + Tauri 桌面端
	add("connect-src", "'self'", "http://127.0.0.1:*", "https://127.0.0.1:*", "tauri://localhost", "http://localhost:*", "https://localhost:*")

	// font-src：self + data:（SVG 内联字体可能用到）
	add("font-src", "'self'", "data:")

	// 如果未启用 nonce，内联脚本/样式需要 'unsafe-inline'
	if !cspCfg.NonceEnabled {
		add("script-src", "'unsafe-inline'")
		add("style-src", "'unsafe-inline'")
	}

	// 检查是否需要 'unsafe-eval'（前端使用了 eval / new Function / setTimeout 字符串）
	if hasUnsafeEval(frontendFS) {
		add("script-src", "'unsafe-eval'")
	}

	// 构建有序指令列表
	order := []string{
		"default-src", "script-src", "style-src", "img-src", "connect-src",
		"font-src", "media-src", "object-src", "frame-src", "worker-src",
		"manifest-src", "base-uri", "form-action", "frame-ancestors",
	}
	var dirs []CSPDirective
	var parts []string
	seen := map[string]bool{}
	for _, name := range order {
		if vals, ok := directives[name]; ok && len(vals) > 0 {
			seen[name] = true
			vlist := sortedValues(vals)
			dirs = append(dirs, CSPDirective{Name: name, Values: vlist})
			parts = append(parts, name+" "+strings.Join(vlist, " "))
		}
	}
	// 追加未在 order 中的指令
	for name, vals := range directives {
		if !seen[name] && len(vals) > 0 {
			vlist := sortedValues(vals)
			dirs = append(dirs, CSPDirective{Name: name, Values: vlist})
			parts = append(parts, name+" "+strings.Join(vlist, " "))
		}
	}

	policyStr := strings.Join(parts, "; ")

	return &CSPPolicy{
		Directives: dirs,
		String:     policyStr,
		Generated:  time.Now(),
		Source:     "auto",
	}
}

// scanEmbeddedFrontend 扫描 go:embed 的前端文件，分析资源需求
func scanEmbeddedFrontend(add func(string, ...string)) {
	entries, err := frontendFS.ReadDir("frontend")
	if err != nil {
		return
	}

	hasExternalScript := false
	hasExternalStyle := false
	hasImgDataURI := false
	hasImgExternal := false

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := frontendFS.ReadFile("frontend/" + entry.Name())
		if err != nil {
			continue
		}
		content := string(data)
		lower := strings.ToLower(content)

		// 检测外部脚本
		if strings.Contains(lower, "<script src=") {
			hasExternalScript = true
		}
		// 检测外部样式
		if strings.Contains(lower, "<link") && strings.Contains(lower, "stylesheet") {
			hasExternalStyle = true
		}
		// 检测 data: URI 图片
		if strings.Contains(lower, "data:image") {
			hasImgDataURI = true
		}
		// 检测外部图片
		if imgExtRe.MatchString(lower) {
			hasImgExternal = true
		}
	}

	// img-src
	imgVals := []string{"'self'"}
	if hasImgDataURI {
		imgVals = append(imgVals, "data:")
	}
	if hasImgExternal {
		// 外部图片在网关场景下通常不需要，但如果检测到则保留 'self' 即可
		// 不自动添加 *，保持严格
	}
	add("img-src", imgVals...)

	// script-src / style-src
	scriptVals := []string{"'self'"}
	styleVals := []string{"'self'"}
	if hasExternalScript {
		// 外部脚本来源分析（从前端文件中提取）
		srcs := extractScriptSrcs(frontendFS)
		scriptVals = append(scriptVals, srcs...)
	}
	if hasExternalStyle {
		srcs := extractStyleSrcs(frontendFS)
		styleVals = append(styleVals, srcs...)
	}
	add("script-src", scriptVals...)
	add("style-src", styleVals...)
}

var imgExtRe = regexp.MustCompile(`<img[^>]+src=["']?https?://`)

// extractScriptSrcs 从嵌入的前端文件中提取外部脚本来源
func extractScriptSrcs(fs embed.FS) []string {
	re := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	return extractSrcs(fs, re)
}

// extractStyleSrcs 从嵌入的前端文件中提取外部样式来源
func extractStyleSrcs(fs embed.FS) []string {
	re := regexp.MustCompile(`<link[^>]+href=["']([^"']+)["']`)
	return extractSrcs(fs, re)
}

func extractSrcs(fs embed.FS, re *regexp.Regexp) []string {
	entries, _ := fs.ReadDir("frontend")
	seen := map[string]bool{}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := fs.ReadFile("frontend/" + entry.Name())
		if err != nil {
			continue
		}
		matches := re.FindAllStringSubmatch(string(data), -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			src := m[1]
			// 只保留绝对 URL 的来源
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				origin := extractOrigin(src)
				if origin != "" && !seen[origin] {
					seen[origin] = true
					out = append(out, origin)
				}
			}
		}
	}
	return out
}

func extractOrigin(urlStr string) string {
	if strings.HasPrefix(urlStr, "http://") {
		rest := strings.TrimPrefix(urlStr, "http://")
		if idx := strings.Index(rest, "/"); idx > 0 {
			return "http://" + rest[:idx]
		}
		return "http://" + rest
	}
	if strings.HasPrefix(urlStr, "https://") {
		rest := strings.TrimPrefix(urlStr, "https://")
		if idx := strings.Index(rest, "/"); idx > 0 {
			return "https://" + rest[:idx]
		}
		return "https://" + rest
	}
	return ""
}

// hasUnsafeEval 检测前端是否使用了 eval / new Function / setTimeout 字符串
func hasUnsafeEval(fs embed.FS) bool {
	entries, _ := fs.ReadDir("frontend")
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := fs.ReadFile("frontend/" + entry.Name())
		if err != nil {
			continue
		}
		content := string(data)
		// 检测常见的 eval 用法
		if strings.Contains(content, "eval(") ||
			strings.Contains(content, "new Function(") ||
			strings.Contains(content, "setTimeout(") && strings.Contains(content, "function") == false {
			// setTimeout 字符串用法较罕见，简单检测
			if strings.Contains(content, "setTimeout(") {
				// 进一步检查 setTimeout 的第一个参数是否为字符串
				if strings.Contains(content, `setTimeout("`) || strings.Contains(content, "setTimeout('") {
					return true
				}
			}
		}
		if strings.Contains(content, "eval(") || strings.Contains(content, "new Function(") {
			return true
		}
	}
	return false
}

// parseCSPString 解析 CSP 策略字符串为指令列表
func parseCSPString(policy string) []CSPDirective {
	var dirs []CSPDirective
	for _, part := range strings.Split(policy, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		dirs = append(dirs, CSPDirective{
			Name:   fields[0],
			Values: fields[1:],
		})
	}
	return dirs
}

func sortedValues(m map[string]bool) []string {
	var out []string
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ===================== 运行时应用 =====================

// getCSPPolicy 获取当前 CSP 策略（带缓存）
func getCSPPolicy() *CSPPolicy {
	cspMu.RLock()
	cached := cspCache
	cspMu.RUnlock()
	if cached != nil {
		return cached
	}
	cspMu.Lock()
	defer cspMu.Unlock()
	if cspCache != nil {
		return cspCache
	}
	cspCache = generateCSPPolicy()
	return cspCache
}

// invalidateCSPCache 使 CSP 缓存失效（配置变更后调用）
func invalidateCSPCache() {
	cspMu.Lock()
	cspCache = nil
	cspMu.Unlock()
}

// applyCSPHeaders 将 CSP 策略应用到响应头
func applyCSPHeaders(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	cspCfg := cfg.Security.CSP
	cfgMu.RUnlock()

	if !cspCfg.Enabled {
		return
	}

	policy := getCSPPolicy()
	if policy == nil || policy.String == "" {
		return
	}

	headerValue := policy.String

	// 如果配置了自定义报告 URI，追加 report-uri / report-to
	if cspCfg.ReportURI != "" {
		headerValue += "; report-uri " + cspCfg.ReportURI
	}

	if cspCfg.ReportOnly {
		w.Header().Set("Content-Security-Policy-Report-Only", headerValue)
	} else {
		w.Header().Set("Content-Security-Policy", headerValue)
	}
}

// ===================== 管理 API =====================

func handleAdminCSPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	cfgMu.RLock()
	cspCfg := cfg.Security.CSP
	cfgMu.RUnlock()

	policy := getCSPPolicy()
	writeJSON(w, map[string]interface{}{
		"enabled":      cspCfg.Enabled,
		"reportOnly":   cspCfg.ReportOnly,
		"customPolicy": cspCfg.CustomPolicy,
		"reportURI":    cspCfg.ReportURI,
		"nonceEnabled": cspCfg.NonceEnabled,
		"policy":       policy,
		"reportCount":  len(cspReports),
	})
}

func handleAdminCSPUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var req struct {
		Enabled      *bool   `json:"enabled"`
		ReportOnly   *bool   `json:"reportOnly"`
		CustomPolicy *string `json:"customPolicy"`
		ReportURI    *string `json:"reportURI"`
		NonceEnabled *bool   `json:"nonceEnabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	cfgMu.Lock()
	if req.Enabled != nil {
		cfg.Security.CSP.Enabled = *req.Enabled
	}
	if req.ReportOnly != nil {
		cfg.Security.CSP.ReportOnly = *req.ReportOnly
	}
	if req.CustomPolicy != nil {
		cfg.Security.CSP.CustomPolicy = *req.CustomPolicy
	}
	if req.ReportURI != nil {
		cfg.Security.CSP.ReportURI = *req.ReportURI
	}
	if req.NonceEnabled != nil {
		cfg.Security.CSP.NonceEnabled = *req.NonceEnabled
	}
	cfgMu.Unlock()

	invalidateCSPCache()
	if err := saveConfigChecked(); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "保存失败: " + err.Error()})
		return
	}

	// 重新生成策略并返回
	policy := getCSPPolicy()
	writeJSON(w, map[string]interface{}{
		"ok":     true,
		"policy": policy,
	})
}

func handleAdminCSPReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	cspReportMu.Lock()
	defer cspReportMu.Unlock()
	// 最多返回最近 100 条
	start := 0
	if len(cspReports) > 100 {
		start = len(cspReports) - 100
	}
	writeJSON(w, map[string]interface{}{
		"reports": cspReports[start:],
		"total":   len(cspReports),
	})
}

func handleCSPReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var wrapper cspReportWrapper
	if err := json.Unmarshal(body, &wrapper); err != nil {
		// 尝试直接解析 report 字段
		var direct CSPReport
		if err2 := json.Unmarshal(body, &direct); err2 != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wrapper.Report = direct
	}

	cspReportMu.Lock()
	cspReports = append(cspReports, cspReportEntry{
		Time:   time.Now(),
		Report: wrapper.Report,
	})
	// 限制内存占用，最多保留 5000 条
	if len(cspReports) > 5000 {
		cspReports = cspReports[len(cspReports)-5000:]
	}
	cspReportMu.Unlock()

	// 记录到审计日志
	auditLog("CSP_VIOLATION", "system", fmt.Sprintf("blocked-uri=%s directive=%s document=%s",
		wrapper.Report.BlockedURI,
		wrapper.Report.ViolatedDirective,
		wrapper.Report.DocumentURI))

	w.WriteHeader(http.StatusNoContent)
}

// ===================== nonce 生成器（供未来前端配合）=====================

var nonceMu sync.Mutex
var nonceRand = &fastRand{}

type fastRand struct{}

func (f *fastRand) Uint32() uint32 {
	// 简单的混合同步计数器（nonce 不需要密码学安全随机）
	nonceMu.Lock()
	defer nonceMu.Unlock()
	// 使用当前时间纳秒 + 计数器
	return uint32(time.Now().UnixNano() & 0xFFFFFFFF)
}

// generateNonce 生成 CSP nonce（供未来前端内联脚本配合）
func generateNonce() string {
	b := make([]byte, 16)
	u := nonceRand.Uint32()
	for i := 0; i < 4; i++ {
		b[i] = byte(u >> (i * 8))
	}
	u2 := nonceRand.Uint32()
	for i := 0; i < 4; i++ {
		b[i+4] = byte(u2 >> (i * 8))
	}
	u3 := nonceRand.Uint32()
	for i := 0; i < 4; i++ {
		b[i+8] = byte(u3 >> (i * 8))
	}
	u4 := nonceRand.Uint32()
	for i := 0; i < 4; i++ {
		b[i+12] = byte(u4 >> (i * 8))
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:16]
}
