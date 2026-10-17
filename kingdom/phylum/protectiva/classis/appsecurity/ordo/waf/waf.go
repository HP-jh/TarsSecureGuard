// waf.go — Web应用防火墙（目：Ordo-WAF）
// 合并正则 + ASCII触发字节预筛（v3.2.3优化成果继承）
package waf

import (
	"net/http"
	"net/url"
	"regexp"
	"sync"
)

// Rule WAF规则
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Level   string `json:"level"` // strict/normal/lenient
	Action  string `json:"action"` // block/log/challenge
}

// Engine WAF引擎
type Engine struct {
	mu       sync.RWMutex
	rules    []Rule
	level    string
	enabled  bool
	asciiPre map[byte]bool // ASCII触发字节预筛表
}

// NewEngine 创建WAF引擎
func NewEngine(rules []Rule, level string) *Engine {
	e := &Engine{
		rules:    rules,
		level:    level,
		enabled:  true,
		asciiPre: make(map[byte]bool),
	}
	// 预编译常见攻击特征的ASCII首字节（如 < " ' ; ( ) . % \ | & ` 等）
	for _, b := range []byte{'<', '"', '\'', ';', '(', ')', '.', '%', '\\', '|', '&', '`'} {
		e.asciiPre[b] = true
	}
	return e
}

// CheckRequest 检查HTTP请求
func (e *Engine) CheckRequest(r *http.Request) (blocked bool, reason string) {
	if !e.enabled {
		return false, ""
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 对RawQuery做URL解码后再检测，使正则与真实payload对齐
	query, _ := url.QueryUnescape(r.URL.RawQuery)
	ua := r.UserAgent()

	// ASCII触发字节预筛：快速排除干净请求
	if !e.hasTriggerByte(query + ua) {
		return false, ""
	}

	for _, rule := range e.rules {
		if rule.Level != e.level && e.level != "strict" {
			continue
		}
		re := regexp.MustCompile(rule.Pattern)
		if re.MatchString(query) || re.MatchString(ua) {
			if rule.Action == "block" {
				return true, rule.Name
			}
		}
	}
	return false, ""
}

func (e *Engine) hasTriggerByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if e.asciiPre[s[i]] {
			return true
		}
	}
	return false
}

// AddRule 动态添加规则
func (e *Engine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// SetLevel 调整防护级别
func (e *Engine) SetLevel(l string) { e.level = l }

// SetEnabled 启停引擎
func (e *Engine) SetEnabled(v bool) { e.enabled = v }

// DefaultRules 返回默认规则集
func DefaultRules() []Rule {
	return []Rule{
		{ID: "W001", Name: "SQL注入", Pattern: `(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table)`, Level: "strict", Action: "block"},
		{ID: "W002", Name: "XSS攻击", Pattern: `(?i)(<script|javascript:|onerror=|onload=)`, Level: "strict", Action: "block"},
		{ID: "W003", Name: "路径遍历", Pattern: `(?i)(\.\./|\.\.\\|%2e%2e)`, Level: "normal", Action: "block"},
		{ID: "W004", Name: "命令注入", Pattern: `(?i)(;\s*cat\s+|\|\s*bash|\` + "`" + `\s*whoami)`, Level: "strict", Action: "block"},
		{ID: "W005", Name: "SSRF探测", Pattern: `(?i)(http://(127|10\.|192\.168|172\.(1[6-9]|2\d|3[01])))`, Level: "normal", Action: "block"},
	}
}
