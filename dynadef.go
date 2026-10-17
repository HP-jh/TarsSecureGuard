package main

// ===================== v3.9.0 动态防护模块（Dynadef）=====================
//
// 四子能力：
//   1. 影子规则流水线 — 在正式 WAF 规则前运行低风险影子规则，收集误报数据
//   2. 蜜令牌陷阱 — 在响应中注入不可见蜜令牌，检测爬虫/镜像站
//   3. 解码扰动池 — 对可疑输入进行多轮解码/规范化，探测编码绕过
//   4. 蜜罐路由 — 为扫描器/攻击者提供虚假端点，延迟+审计
//
// 原则：可配置（config）、可观测（metrics）、可审计（audit）

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DynadefConfig 动态防护配置
type DynadefConfig struct {
	Enabled          bool            `json:"enabled"`
	ShadowRules      []ShadowRule    `json:"shadow_rules"`
	HoneyTokens      HoneyTokenCfg   `json:"honey_tokens"`
	DecodePerturb    DecodePerturbCfg `json:"decode_perturb"`
	HoneypotRoutes   []string        `json:"honeypot_routes"`
	HoneypotDelay    time.Duration   `json:"honeypot_delay"`
}

// ShadowRule 影子规则（只记录不阻断）
type ShadowRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Pattern string `json:"pattern"` // 正则或关键词
	Hits    int64  `json:"hits"`
	FPs     int64  `json:"false_positives"`
	Enabled bool   `json:"enabled"`
}

// HoneyTokenCfg 蜜令牌配置
type HoneyTokenCfg struct {
	Enabled     bool   `json:"enabled"`
	HTMLComment string `json:"html_comment"` // 如 <!-- ht_xxx -->
	CSSHidden   string `json:"css_hidden"`   // 如 .ht-xxx{display:none}
	CookieName  string `json:"cookie_name"`  // 如 __ht_session
}

// DecodePerturbCfg 解码扰动配置
type DecodePerturbCfg struct {
	Enabled      bool     `json:"enabled"`
	MaxRounds    int      `json:"max_rounds"`    // 最大解码轮数
	Techniques   []string `json:"techniques"`    // url, html, base64, hex, unicode
	TriggerScore float64  `json:"trigger_score"` // WAF 分数触发阈值
}

var (
	dyna     *DynadefEngine
	dynaOnce sync.Once
)

// DynadefEngine 动态防护引擎
type DynadefEngine struct {
	cfg DynadefConfig
	mu  sync.RWMutex

	shadowHits      map[string]*int64 // 规则 ID -> 命中计数
	shadowFPs       map[string]*int64
	honeyTokenSet   map[string]bool   // 已发出的蜜令牌
	decodeAttempts  int64
	honeypotHits    int64
}

func initDynadef(cfg DynadefConfig) *DynadefEngine {
	dynaOnce.Do(func() {
		dyna = &DynadefEngine{
			cfg:           cfg,
			shadowHits:    make(map[string]*int64),
			shadowFPs:     make(map[string]*int64),
			honeyTokenSet: make(map[string]bool),
		}
		for i := range cfg.ShadowRules {
			var h, fp int64
			dyna.shadowHits[cfg.ShadowRules[i].ID] = &h
			dyna.shadowFPs[cfg.ShadowRules[i].ID] = &fp
		}
	})
	return dyna
}

// ===================== 1. 影子规则流水线 =====================

func (d *DynadefEngine) runShadowPipeline(r *http.Request) []ShadowHit {
	if !d.cfg.Enabled {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	var hits []ShadowHit
	body := readBodyString(r)
	combined := strings.ReplaceAll(r.URL.RawQuery, "+", " ") + " " + r.UserAgent() + " " + body

	for i := range d.cfg.ShadowRules {
		rule := &d.cfg.ShadowRules[i]
		if !rule.Enabled {
			continue
		}
		if strings.Contains(combined, rule.Pattern) {
			atomic.AddInt64(d.shadowHits[rule.ID], 1)
			hits = append(hits, ShadowHit{
				RuleID:    rule.ID,
				RuleName:  rule.Name,
				Timestamp: time.Now(),
				Path:      r.URL.Path,
				ClientIP:  clientIP(r),
			})
		}
	}
	return hits
}

type ShadowHit struct {
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path"`
	ClientIP  string    `json:"client_ip"`
}

// ===================== 2. 蜜令牌陷阱 =====================

func (d *DynadefEngine) injectHoneyToken(html string) string {
	if !d.cfg.Enabled || !d.cfg.HoneyTokens.Enabled {
		return html
	}
	token := genHoneyToken()
	d.mu.Lock()
	d.honeyTokenSet[token] = true
	d.mu.Unlock()

	// 注入 HTML 注释蜜令牌
	if strings.Contains(html, "</body>") {
		marker := fmt.Sprintf("<!-- %s_%s -->", d.cfg.HoneyTokens.HTMLComment, token)
		html = strings.Replace(html, "</body>", marker+"</body>", 1)
	}
	return html
}

func (d *DynadefEngine) checkHoneyToken(r *http.Request) bool {
	if !d.cfg.Enabled || !d.cfg.HoneyTokens.Enabled {
		return false
	}
	// 检查请求是否携带了蜜令牌（如爬虫抓取了页面并回传）
	cookie, err := r.Cookie(d.cfg.HoneyTokens.CookieName)
	if err == nil && d.isHoneyToken(cookie.Value) {
		atomic.AddInt64(&d.honeypotHits, 1)
		auditLog("DYNADEF_HONEY_TOKEN", clientIP(r), "蜜令牌触发")
		return true
	}
	return false
}

func (d *DynadefEngine) isHoneyToken(v string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.honeyTokenSet[v]
}

func genHoneyToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// ===================== 3. 解码扰动池 =====================

func (d *DynadefEngine) perturbDecode(input string) []PerturbResult {
	if !d.cfg.Enabled || !d.cfg.DecodePerturb.Enabled {
		return nil
	}
	var results []PerturbResult
	current := input
	for round := 0; round < d.cfg.DecodePerturb.MaxRounds; round++ {
		changed := false
		for _, tech := range d.cfg.DecodePerturb.Techniques {
			decoded, ok := tryDecode(current, tech)
			if ok && decoded != current {
				results = append(results, PerturbResult{
					Round:     round + 1,
					Technique: tech,
					Input:     current,
					Output:    decoded,
				})
				current = decoded
				changed = true
				atomic.AddInt64(&d.decodeAttempts, 1)
			}
		}
		if !changed {
			break
		}
	}
	return results
}

type PerturbResult struct {
	Round     int    `json:"round"`
	Technique string `json:"technique"`
	Input     string `json:"input"`
	Output    string `json:"output"`
}

func tryDecode(s, tech string) (string, bool) {
	switch tech {
	case "url":
		if decoded, err := urlQueryUnescape(s); err == nil && decoded != s {
			return decoded, true
		}
	case "base64":
		if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
			return string(decoded), true
		}
	case "hex":
		if len(s) >= 2 && s[:2] == "0x" {
			// 简化：只处理 0x 前缀
			return s, false
		}
	case "html":
		// 简化：只处理常见 HTML 实体
		if strings.Contains(s, "&lt;") || strings.Contains(s, "&gt;") {
			return strings.ReplaceAll(strings.ReplaceAll(s, "&lt;", "<"), "&gt;", ">"), true
		}
	case "unicode":
		// 简化：处理 \\uXXXX 编码
		if strings.Contains(s, "\\u") {
			// 这里简化处理，实际应使用 strconv.Unquote
			return s, false
		}
	}
	return s, false
}

func urlQueryUnescape(s string) (string, error) {
	// 避免循环引用，简单实现
	return strings.ReplaceAll(s, "%20", " "), nil
}

// ===================== 4. 蜜罐路由 =====================

func (d *DynadefEngine) isHoneypotPath(path string) bool {
	if !d.cfg.Enabled {
		return false
	}
	for _, hp := range d.cfg.HoneypotRoutes {
		if path == hp || strings.HasPrefix(path, hp+"/") {
			return true
		}
	}
	return false
}

func (d *DynadefEngine) handleHoneypot(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	atomic.AddInt64(&d.honeypotHits, 1)
	auditLog("DYNADEF_HONEYPOT", ip, r.URL.Path)

	// 延迟响应，消耗攻击者时间
	if d.cfg.HoneypotDelay > 0 {
		time.Sleep(d.cfg.HoneypotDelay)
	}

	// 返回虚假数据
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","data":"%s","timestamp":%d}`, genHoneyToken(), time.Now().Unix())
}

// ===================== 中间件集成 =====================

func dynadefMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dyna == nil || !dyna.cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// 蜜罐路由优先
		if dyna.isHoneypotPath(r.URL.Path) {
			dyna.handleHoneypot(w, r)
			return
		}

		// 影子规则流水线
		hits := dyna.runShadowPipeline(r)
		if len(hits) > 0 {
			// 影子规则只记录不阻断
			for _, h := range hits {
				auditLog("SHADOW_HIT", h.ClientIP, fmt.Sprintf("%s:%s", h.RuleID, h.Path))
			}
		}

		// 解码扰动（对 body 进行）
		body := readBodyString(r)
		if body != "" {
			results := dyna.perturbDecode(body)
			if len(results) > 0 {
				auditLog("PERTURB_DECODE", clientIP(r), fmt.Sprintf("rounds=%d", len(results)))
			}
		}

		next.ServeHTTP(w, r)
	})
}

func readBodyString(r *http.Request) string {
	// 简化：不从 body reader 读取（避免消费），从 URL 和 Header 推断
	return r.URL.RawQuery
}
