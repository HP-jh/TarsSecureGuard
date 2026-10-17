// extranet.go — 外网防护（目：Ordo-Extranet）
package extranet

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// Guard 外网防护守卫
type Guard struct {
	mu        sync.RWMutex
	blocklist map[string]bool
	allowlist map[string]bool
	urlRules  []URLRule
	enabled   bool
}

// URLRule URL拦截规则
type URLRule struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
	Reason  string `json:"reason"`
}

// NewGuard 创建外网防护守卫
func NewGuard() *Guard {
	g := &Guard{
		blocklist: map[string]bool{},
		allowlist: map[string]bool{},
		enabled:   true,
		urlRules: []URLRule{
			{ID: "U001", Pattern: `(?i)(malware|phishing|ransomware)`, Action: "block", Reason: "恶意软件域名"},
			{ID: "U002", Pattern: `(?i)(\.onion|tor2web)`, Action: "block", Reason: "暗网代理"},
			{ID: "U003", Pattern: `(?i)(pastebin|ghostbin)`, Action: "log", Reason: "文本托管站"},
			{ID: "U004", Pattern: `(?i)(cryptominer|mining)`, Action: "block", Reason: "加密货币挖矿"},
			{ID: "U005", Pattern: `(?i)(command.*control|c2|botnet)`, Action: "block", Reason: "C2服务器"},
		},
	}
	for _, d := range []string{"malware.example", "phishing.test", "botnet.cc"} {
		g.blocklist[d] = true
	}
	for _, d := range []string{"github.com", "huggingface.co", "openai.com", "anthropic.com"} {
		g.allowlist[d] = true
	}
	return g
}

// CheckRequest 检查HTTP请求是否允许出站
func (g *Guard) CheckRequest(req *http.Request) (bool, string) {
	if !g.enabled {
		return true, ""
	}
	host := req.URL.Hostname()
	if g.allowlist[host] {
		return true, "allowlist"
	}
	if g.blocklist[host] {
		return false, "blocklist: " + host
	}
	url := req.URL.String()
	for _, rule := range g.urlRules {
		re := regexp.MustCompile(rule.Pattern)
		if re.MatchString(url) {
			if rule.Action == "block" {
				return false, "rule:" + rule.ID + " " + rule.Reason
			}
		}
	}
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			if ip.IsPrivate() || ip.IsLoopback() {
				return false, "private IP blocked"
			}
		}
	}
	return true, ""
}

func (g *Guard) AddBlock(domain string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocklist[strings.ToLower(domain)] = true
}

func (g *Guard) AddAllow(domain string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.allowlist[strings.ToLower(domain)] = true
}

func (g *Guard) SetEnabled(v bool) { g.enabled = v }
