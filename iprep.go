package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ===================== IP 信誉表（v3.0.0 新增，模块 ipReputation）=====================
//
// 基于本地行为证据动态评分（初始 100 分）：
//   WAF 命中 -30；分层限流超限 -20；扫描型 404 突发（5 次/分钟）-10；
//   低于 40 分触发动态封禁（联动 firewall，时长为普通封禁的 2 倍）；
//   24 小时无事件自动恢复 +10/小时。
// 状态持久化到 state/iprep.json，重启不丢。

type IPEntry struct {
	Score     int       `json:"score"`
	UpdatedAt time.Time `json:"updatedAt"`
	BannedAt  time.Time `json:"bannedAt,omitempty"`
	Reasons   []string  `json:"reasons,omitempty"`
}

var (
	ipMu   sync.Mutex
	ipTable = map[string]*IPEntry{}
)

func ipRepPath() string { return filepath.Join("state", "iprep.json") }

func ipRepLoad() {
	b, err := os.ReadFile(ipRepPath())
	if err != nil {
		return
	}
	ipMu.Lock()
	defer ipMu.Unlock()
	json.Unmarshal(b, &ipTable)
}

func ipRepSave() {
	_ = os.MkdirAll("state", 0o755)
	ipMu.Lock()
	b, _ := json.MarshalIndent(ipTable, "", "  ")
	ipMu.Unlock()
	os.WriteFile(ipRepPath(), b, 0o600)
}

func ipRepEnabled() bool {
	v := v3Config().IPReputation.Enabled
	return v == nil || *v
}

// ipRepPenalty 扣分（WAF/限流/扫描 404 联动）
func ipRepPenalty(ip string, delta int, reason string) {
	if !ipRepEnabled() || isWhitelistedIP(ip) {
		return
	}
	ipMu.Lock()
	e := ipTable[ip]
	if e == nil {
		e = &IPEntry{Score: 100}
		ipTable[ip] = e
	}
	e.Score -= delta
	if e.Score < 0 {
		e.Score = 0
	}
	e.UpdatedAt = time.Now()
	e.Reasons = append(e.Reasons, fmt.Sprintf("%s -%d @%s", reason, delta, time.Now().Format("15:04:05")))
	if len(e.Reasons) > 20 {
		e.Reasons = e.Reasons[len(e.Reasons)-20:]
	}
	low := e.Score < 40
	firstBan := low && e.BannedAt.IsZero()
	if low && e.BannedAt.IsZero() {
		e.BannedAt = time.Now()
	}
	ipMu.Unlock()
	if firstBan {
		auditLog("IP_REP_BAN", "system", fmt.Sprintf("ip=%s score=%d 触发动态封禁（时长×2）", ip, e.Score))
		firewallBanIPExtra(ip)
	}
	ipRepSave()
}

// markIPBanned 标记封禁时刻（WAF 命中时由中间件调用，供 24h 恢复判定）
func markIPBanned(ip string) {
	if !ipRepEnabled() || isWhitelistedIP(ip) {
		return
	}
	ipMu.Lock()
	e := ipTable[ip]
	if e == nil {
		e = &IPEntry{Score: 100}
		ipTable[ip] = e
	}
	if e.BannedAt.IsZero() {
		e.BannedAt = time.Now()
	}
	ipMu.Unlock()
}

// ipRepRecoverTick 每小时恢复 +10（24h 无事件自动恢复）
func ipRepRecoverTick() {
	ipMu.Lock()
	now := time.Now()
	changed := false
	for ip, e := range ipTable {
		if now.Sub(e.UpdatedAt) >= time.Hour {
			e.Score += 10
			if e.Score > 100 {
				e.Score = 100
			}
			e.UpdatedAt = now
			if e.Score >= 60 && !e.BannedAt.IsZero() {
				e.BannedAt = time.Time{}
				firewallUnbanIP(ip) // 信誉恢复到 60 以上自动解封
			}
			changed = true
		}
	}
	ipMu.Unlock()
	if changed {
		ipRepSave()
	}
}

func isWhitelistedIP(ip string) bool {
	for _, w := range v3Config().IPReputation.Whitelist {
		if w == ip {
			return true
		}
	}
	return false
}

// ===================== IP 信誉 HTTP =====================
func handleIPRepStatus(w http.ResponseWriter, r *http.Request) {
	ipMu.Lock()
	defer ipMu.Unlock()
	out := make([]map[string]interface{}, 0, len(ipTable))
	for ip, e := range ipTable {
		out = append(out, map[string]interface{}{
			"ip": ip, "score": e.Score, "updatedAt": e.UpdatedAt.Unix(),
			"banned": !e.BannedAt.IsZero(), "reasons": e.Reasons,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["score"].(int) < out[j]["score"].(int) })
	writeJSON(w, map[string]interface{}{"enabled": ipRepEnabled(), "entries": out})
}

func handleIPRepUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.IP == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "ip 必填"})
		return
	}
	ipMu.Lock()
	if e, ok := ipTable[body.IP]; ok {
		e.Score = 100
		e.BannedAt = time.Time{}
		e.UpdatedAt = time.Now()
	}
	ipMu.Unlock()
	firewallUnbanIP(body.IP)
	ipRepSave()
	n, _, _ := userFromRequest(r)
	auditLog("IP_REP_UNBAN", n, "手动解封 ip="+body.IP)
	writeJSON(w, map[string]interface{}{"success": true, "ip": body.IP})
}

// 防止未使用导入（net 用于后续 CIDR 段判定）
var _ = net.ParseIP
