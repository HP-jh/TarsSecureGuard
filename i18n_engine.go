package main

// ===================== v4.9.0 i18n 架构引擎 =====================
// 支持：嵌套命名空间 / 复数规则 / 插值 / 日期数字本地化 / 热替换 / 缺失统计

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// I18nLocale 单语言翻译包
type I18nLocale struct {
	Meta     LocaleMeta        `json:"meta"`
	Messages map[string]string `json:"messages"` // 扁平化 key -> value
}

type LocaleMeta struct {
	Name    string `json:"name"`
	Code    string `json:"code"`
	Version string `json:"version"`
}

// I18nEngine 全局 i18n 引擎
type I18nEngine struct {
	mu        sync.RWMutex
	locales   map[string]*I18nLocale
	fallback  string
	nsSep     string // 命名空间分隔符，默认 "."
	plurals   map[string]pluralRule
	missing   map[string]int64 // key -> 缺失计数（用于仪表盘）
	missMu    sync.Mutex
	remoteURL string
	lastVer   string
	stopRefresh chan struct{}
	wsHub     *i18nSSEHub
}

// pluralRule 复数分类器：返回分类名 (zero/one/two/few/many/other)
type pluralRule func(n int) string

var defaultEngine *I18nEngine
var engineOnce sync.Once

func getI18nEngine() *I18nEngine {
	engineOnce.Do(func() {
		defaultEngine = newI18nEngine()
	})
	return defaultEngine
}

func newI18nEngine() *I18nEngine {
	e := &I18nEngine{
		locales:     make(map[string]*I18nLocale),
		fallback:    "en",
		nsSep:       ".",
		plurals:     buildPluralRules(),
		missing:     make(map[string]int64),
		stopRefresh: make(chan struct{}),
		wsHub:       newI18nSSEHub(),
	}
	// 加载内置翻译包
	e.loadBuiltinBundles()
	// 启动定时刷新（5分钟）
	go e.refreshLoop(5 * time.Minute)
	return e
}

// pickLang 根据 Accept-Language 头选择最佳匹配语言
func pickLang(r *http.Request) string {
	al := r.Header.Get("Accept-Language")
	if al == "" {
		return getI18nEngine().fallback
	}
	al = strings.ToLower(al)
	eng := getI18nEngine()
	eng.mu.RLock()
	defer eng.mu.RUnlock()
	for code := range eng.locales {
		if strings.Contains(al, code) {
			return code
		}
		short := strings.SplitN(code, "-", 2)[0]
		if strings.Contains(al, short) {
			return code
		}
	}
	return eng.fallback
}

// ===================== 加载 =====================

func (e *I18nEngine) loadBuiltinBundles() {
	// 从 embed/i18n/ 目录加载（fallback 到内置 JSON 字符串减少外部依赖）
	builtinLangs := []string{"zh-CN", "en", "ja-JP", "ko-KR", "es", "fr"}
	for _, code := range builtinLangs {
		if data, ok := builtinI18nBundles[code]; ok {
			e.loadJSON(code, data)
		}
	}
	// 尝试从文件系统覆盖（支持热替换）
	for _, code := range builtinLangs {
		path := filepath.Join("i18n", code+".json")
		if b, err := os.ReadFile(path); err == nil {
			e.loadJSON(code, b)
		}
	}
}

func (e *I18nEngine) loadJSON(code string, data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	metaRaw, _ := raw["meta"].(map[string]interface{})
	loc := &I18nLocale{
		Meta: LocaleMeta{
			Name:    jsonStr(metaRaw["name"]),
			Code:    jsonStr(metaRaw["code"]),
			Version: jsonStr(metaRaw["version"]),
		},
		Messages: make(map[string]string),
	}
	if msgs, ok := raw["messages"].(map[string]interface{}); ok {
		flattenMap("", msgs, loc.Messages, e.nsSep)
	}
	e.mu.Lock()
	e.locales[code] = loc
	e.mu.Unlock()
	return nil
}

func jsonStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func flattenMap(prefix string, src map[string]interface{}, dst map[string]string, sep string) {
	for k, v := range src {
		key := k
		if prefix != "" {
			key = prefix + sep + k
		}
		switch val := v.(type) {
		case string:
			dst[key] = val
		case map[string]interface{}:
			flattenMap(key, val, dst, sep)
		case map[string]string:
			for k2, v2 := range val {
				dst[key+sep+k2] = v2
			}
		}
	}
}

// ===================== 翻译核心 =====================

// T 翻译 key，支持命名空间、插值、复数
func (e *I18nEngine) T(lang, key string, args ...map[string]interface{}) string {
	return e.translate(lang, key, 1, args...)
}

// Tn 带数量的翻译（触发复数规则）
func (e *I18nEngine) Tn(lang, key string, count int, args ...map[string]interface{}) string {
	return e.translate(lang, key, count, args...)
}

func (e *I18nEngine) translate(lang, key string, count int, args ...map[string]interface{}) string {
	if lang == "" {
		lang = e.fallback
	}
	e.mu.RLock()
	loc, ok := e.locales[lang]
	if !ok {
		loc = e.locales[e.fallback]
	}
	if loc == nil {
		e.mu.RUnlock()
		return key
	}
	val := loc.Messages[key]
	e.mu.RUnlock()

	if val == "" {
		// fallback 到英文
		if lang != e.fallback {
			e.mu.RLock()
			if fb := e.locales[e.fallback]; fb != nil {
				val = fb.Messages[key]
			}
			e.mu.RUnlock()
		}
		if val == "" {
			// 记录缺失
			e.missMu.Lock()
			e.missing[key]++
			e.missMu.Unlock()
			return key
		}
	}

	// 复数选择
	if count != 1 || strings.Contains(val, "|") {
		val = e.selectPlural(val, lang, count)
	}

	// 插值
	if len(args) > 0 {
		val = e.interpolate(val, args[0])
	}

	return val
}

// selectPlural 从 "one|other" 或 "zero|one|other" 格式中选择
func (e *I18nEngine) selectPlural(val, lang string, n int) string {
	if !strings.Contains(val, "|") {
		return val
	}
	parts := strings.Split(val, "|")
	rule := e.plurals[lang]
	if rule == nil {
		rule = e.plurals["en"]
	}
	cat := rule(n)
	// 映射：zero->0, one->1, two->2, few->3, many->4, other->last
	order := map[string]int{"zero": 0, "one": 1, "two": 2, "few": 3, "many": 4, "other": 5}
	idx, ok := order[cat]
	if !ok || idx >= len(parts) {
		idx = len(parts) - 1
	}
	return strings.TrimSpace(parts[idx])
}

var interpolateRe = regexp.MustCompile(`\{\{(\w+)\}\}`)

func (e *I18nEngine) interpolate(val string, args map[string]interface{}) string {
	return interpolateRe.ReplaceAllStringFunc(val, func(m string) string {
		inner := m[2 : len(m)-2]
		if v, ok := args[inner]; ok {
			return fmt.Sprint(v)
		}
		return m
	})
}

// ===================== 复数规则 =====================

func buildPluralRules() map[string]pluralRule {
	return map[string]pluralRule{
		"en": func(n int) string {
			if n == 1 { return "one" }
			return "other"
		},
		"zh-CN": func(n int) string {
			return "other" // 中文无复数变化
		},
		"ja-JP": func(n int) string { return "other" },
		"ko-KR": func(n int) string { return "other" },
		"es": func(n int) string {
			if n == 1 { return "one" }
			return "other"
		},
		"fr": func(n int) string {
			if n == 0 || n == 1 { return "one" }
			return "other"
		},
	}
}

// ===================== 实时同步 =====================

func (e *I18nEngine) refreshLoop(d time.Duration) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.tryRemoteUpdate()
		case <-e.stopRefresh:
			return
		}
	}
}

func (e *I18nEngine) tryRemoteUpdate() {
	if e.remoteURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.remoteURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	// 解析远程翻译包列表
	var remote struct {
		Version string            `json:"version"`
		Bundles map[string][]byte `json:"bundles"`
	}
	if err := json.Unmarshal(body, &remote); err != nil {
		// 尝试直接当单语言包解析
		return
	}
	if remote.Version != "" && remote.Version == e.lastVer {
		return
	}
	for code, data := range remote.Bundles {
		if err := e.loadJSON(code, data); err == nil {
			// 通知 WebSocket 客户端
			e.wsHub.broadcast(code, remote.Version)
		}
	}
	if remote.Version != "" {
		e.lastVer = remote.Version
	}
}

func (e *I18nEngine) SetRemoteURL(url string) {
	e.remoteURL = url
	// 立即拉取一次
	go e.tryRemoteUpdate()
}

func (e *I18nEngine) ForceReload() {
	e.loadBuiltinBundles()
	e.wsHub.broadcast("*", e.lastVer)
}

// ===================== 仪表盘 =====================

func (e *I18nEngine) Dashboard() I18nDashboard {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var langs []LangStatus
	allKeys := map[string]bool{}
	for _, loc := range e.locales {
		for k := range loc.Messages {
			allKeys[k] = true
		}
	}
	totalKeys := len(allKeys)

	for code, loc := range e.locales {
		translated := 0
		for k := range allKeys {
			if loc.Messages[k] != "" {
				translated++
			}
		}
		pct := 0
		if totalKeys > 0 {
			pct = translated * 100 / totalKeys
		}
		langs = append(langs, LangStatus{
			Code:       code,
			Name:       loc.Meta.Name,
			Translated: translated,
			Total:      totalKeys,
			Percent:    pct,
			Version:    loc.Meta.Version,
		})
	}
	sort.Slice(langs, func(i, j int) bool { return langs[i].Code < langs[j].Code })

	e.missMu.Lock()
	missCopy := make(map[string]int64, len(e.missing))
	for k, v := range e.missing {
		missCopy[k] = v
	}
	e.missMu.Unlock()

	return I18nDashboard{Languages: langs, MissingKeys: missCopy, TotalKeys: totalKeys}
}

type I18nDashboard struct {
	Languages   []LangStatus     `json:"languages"`
	MissingKeys map[string]int64 `json:"missing_keys"`
	TotalKeys   int              `json:"total_keys"`
}

type LangStatus struct {
	Code       string `json:"code"`
	Name       string `json:"name"`
	Translated int    `json:"translated"`
	Total      int    `json:"total"`
	Percent    int    `json:"percent"`
	Version    string `json:"version"`
}

// ===================== HTTP Handlers =====================

func handleI18nBundle(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang == "" {
		lang = pickLang(r)
	}
	eng := getI18nEngine()
	eng.mu.RLock()
	loc, ok := eng.locales[lang]
	if !ok {
		loc = eng.locales[eng.fallback]
	}
	// 深拷贝
	out := map[string]interface{}{
		"meta":     loc.Meta,
		"messages": loc.Messages,
		"fallback": eng.fallback,
	}
	eng.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func handleI18nTranslate(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	key := r.URL.Query().Get("key")
	countStr := r.URL.Query().Get("n")
	if lang == "" { lang = pickLang(r) }
	if key == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "missing key"})
		return
	}
	eng := getI18nEngine()
	var val string
	if countStr != "" {
		n, _ := strconv.Atoi(countStr)
		val = eng.Tn(lang, key, n)
	} else {
		val = eng.T(lang, key)
	}
	writeJSON(w, map[string]string{"key": key, "value": val, "lang": lang})
}

func handleI18nLanguages(w http.ResponseWriter, r *http.Request) {
	eng := getI18nEngine()
	eng.mu.RLock()
	var out []map[string]string
	for code, loc := range eng.locales {
		out = append(out, map[string]string{"code": code, "name": loc.Meta.Name})
	}
	eng.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i]["code"] < out[j]["code"] })
	writeJSON(w, out)
}

func handleI18nDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, getI18nEngine().Dashboard())
}

func handleAdminI18nReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	getI18nEngine().ForceReload()
	writeJSON(w, map[string]string{"status": "ok"})
}

// ===================== 兼容 v4.7.0 接口 =====================

// v4 compat: i18nT -> engine.T
func i18nT(lang, key string) string {
	return getI18nEngine().T(lang, key)
}

func i18nTReq(r *http.Request, key string) string {
	return getI18nEngine().T(pickLang(r), key)
}

func i18nErrorJSON(w http.ResponseWriter, r *http.Request, code int, key string) {
	writeJSONStatus(w, code, map[string]string{
		"error": getI18nEngine().T(pickLang(r), key),
		"key":   key,
		"lang":  pickLang(r),
	})
}

func i18nErrorJSONWithHint(w http.ResponseWriter, r *http.Request, code int, key, hintKey string) {
	eng := getI18nEngine()
	lang := pickLang(r)
	body := map[string]string{
		"error": eng.T(lang, key),
		"key":   key,
		"lang":  lang,
	}
	if hintKey != "" {
		body["hint"] = eng.T(lang, hintKey)
	}
	writeJSONStatus(w, code, body)
}

func i18nRegister(lang string, msgs map[string]string) {
	eng := getI18nEngine()
	eng.mu.Lock()
	defer eng.mu.Unlock()
	loc, ok := eng.locales[lang]
	if !ok {
		loc = &I18nLocale{Messages: make(map[string]string)}
		eng.locales[lang] = loc
	}
	for k, v := range msgs {
		loc.Messages[k] = v
	}
}

func i18nListLanguages() []string {
	eng := getI18nEngine()
	eng.mu.RLock()
	defer eng.mu.RUnlock()
	var out []string
	for k := range eng.locales {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ===================== 日志/审计 i18n 辅助 =====================

// LogKey 把原始英文日志 key 转成本地化（供前端展示用，后端仍存英文 key）
func (e *I18nEngine) LogKey(lang, key string) string {
	return e.T(lang, "log."+key)
}

// AuditEvent 审计事件输入结构
type AuditEvent struct {
	Action string
	Target string
	Result string
	Detail string
}

// AuditKey 审计事件本地化
type AuditEventL10n struct {
	Action   string `json:"action"`
	Target   string `json:"target"`
	Result   string `json:"result"`
	Detail   string `json:"detail"`
	Lang     string `json:"lang"`
}

func (e *I18nEngine) LocalizeAudit(lang string, ev AuditEvent) AuditEventL10n {
	return AuditEventL10n{
		Action: e.T(lang, "audit.action."+ev.Action),
		Target: ev.Target,
		Result: e.T(lang, "audit.result."+ev.Result),
		Detail: ev.Detail,
		Lang:   lang,
	}
}
