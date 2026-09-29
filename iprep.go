package main

// v3.0.0 B 线：IP 信誉（本地行为指纹累积评分，security-core 内置，不可关闭）
//
// 设计依据：架构方案第三节 B 线 + 锦衣卫裁定 6 全项：
//   - 起分 100；WAF 命中 -30、扫描型 404 突发 -10/分钟、限流违规 -15
//   - 每小时回升 +2 封顶 100；低于 40 触发动态封禁（banDuration×2）
//   - ip_reputation.whitelist 白名单不参与评分
//   - 封禁后连续 24 小时无新扣分自动恢复至 60 分并解封
//   - NAT 误伤识别：同 IP 短时间被大量不同来源触发扣分 → IP_REPUTATION_ANOMALY 告警
//   - admin 可解封（API + M3 的 tars_ip_reputation_unban），操作审计
//   - 不接外部信誉服务（离线优先）；CrowdSec 源为 v3.x 可选项，本文件不含
//   - state 持久化（state/iprep.json），重启不丢

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ipRepEntry struct {
	Score        float64   `json:"score"`
	LastPenalty  time.Time `json:"lastPenalty"`
	BannedAt     time.Time `json:"bannedAt"`
	Last404Win   time.Time `json:"last404Win"`   // 404 突发扣分窗口（每分钟至多一次）
	AnomalyMark  time.Time `json:"anomalyMark"`  // NAT 异常标记时间
	distinctSrcs map[string]bool // 触发扣分的来源用户集合（NAT 识别用，不持久化）
}

var (
	ipRepMu    sync.Mutex
	ipRepTable = map[string]*ipRepEntry{}
)

// ipRepEnabled 信誉评分总开关（默认 true）
func ipRepEnabled() bool {
	c := v3Config()
	if c.IPReputation.Enabled != nil {
		return *c.IPReputation.Enabled
	}
	return true
}

// ipRepWhitelisted 白名单判定
func ipRepWhitelisted(ip string) bool {
	c := v3Config()
	for _, w := range c.IPReputation.Whitelist {
		if w == ip {
			return true
		}
	}
	return false
}

// ipRepScore 返回当前分（无记录 = 100）
func ipRepScore(ip string) float64 {
	ipRepMu.Lock()
	defer ipRepMu.Unlock()
	if e, ok := ipRepTable[ip]; ok {
		return e.Score
	}
	return 100
}

// ipRepPenalty 扣分入口（source: waf / scan404 / rate-limit / abuse）
func ipRepPenalty(ip string, delta float64, source string) {
	if !ipRepEnabled() || ipRepWhitelisted(ip) || ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return
	}
	ipRepMu.Lock()
	e, ok := ipRepTable[ip]
	if !ok {
		e = &ipRepEntry{Score: 100, distinctSrcs: map[string]bool{}}
		ipRepTable[ip] = e
	}
	// 404 突发每分钟至多扣一次（防单次扫描事件重复扣分）
	if source == "scan404" {
		if time.Since(e.Last404Win) < time.Minute {
			ipRepMu.Unlock()
			return
		}
		e.Last404Win = time.Now()
	}
	e.Score -= delta
	if e.Score < 0 {
		e.Score = 0
	}
	e.LastPenalty = time.Now()
	e.distinctSrcs[source] = true
	// NAT 异常识别：15 分钟内 ≥3 种不同扣分来源（大量不同用户/事件类型同时命中同 IP）
	if time.Since(e.AnomalyMark) > 15*time.Minute && len(e.distinctSrcs) >= 3 {
		e.AnomalyMark = time.Now()
		auditLog("IP_REPUTATION_ANOMALY", "system", "ip="+ip+" 疑似 NAT/共享出口（多来源扣分集中），请确认是否误伤；白名单可经 config.ipReputation.whitelist 豁免")
	}
	score := e.Score
	ipRepMu.Unlock()

	// 低于 40：触发动态封禁（时长 = banDuration×2），复用既有防火墙档位
	if score < 40 {
		firewallBanIP(ip) // passive 档为 no-op；dynamic-ban/os-link 生效
		firewallBanIPExtra(ip) // 二倍时长（见 firewalldriver 扩展；不支持则等效单次）
		auditLog("IP_REPUTATION_BAN", "system", "ip="+ip+" score<40 已联动防火墙封禁（banDuration×2）")
	}
}

// ipRepTick 后台维护（由守护器 worker 携带驱动，每 5 秒调一次即可）：
//   - 每小时回升 +2 封顶 100（无未过期封禁记录时）
//   - 封禁后 24h 无新扣分 → 恢复 60 分并解封
func ipRepTick() {
	ipRepMu.Lock()
	defer ipRepMu.Unlock()
	now := time.Now()
	for ip, e := range ipRepTable {
		// 24h 自动恢复（针对已被封禁或低分条目）
		if e.Score < 60 && !e.BannedAt.IsZero() && now.Sub(e.LastPenalty) >= 24*time.Hour {
			auditLog("IP_REPUTATION_AUTO_RECOVER", "system", "ip="+ip+" 24h 无新扣分，自动恢复至 60 分")
			e.Score = 60
			e.BannedAt = time.Time{}
			continue
		}
		// 每小时回升 2 分（上次扣分 1 小时后开始）
		if e.Score < 100 && now.Sub(e.LastPenalty) >= time.Hour {
			e.Score += 2
			if e.Score > 100 {
				e.Score = 100
			}
			e.LastPenalty = e.LastPenalty.Add(time.Hour) // 逐小时推进
		}
	}
}

// markIPBanned 由 firewalldriver 封禁回调（记录 BannedAt 供 24h 恢复）
func markIPBanned(ip string) {
	ipRepMu.Lock()
	defer ipRepMu.Unlock()
	if e, ok := ipRepTable[ip]; ok {
		e.BannedAt = time.Now()
	}
}

// ipRepUnban admin 解封（API + M3 MCP 工具共用），操作审计
func ipRepUnban(operator, ip string) bool {
	ipRepMu.Lock()
	if e, ok := ipRepTable[ip]; ok {
		e.Score = 100
		e.BannedAt = time.Time{}
		e.distinctSrcs = map[string]bool{}
	}
	ipRepMu.Unlock()
	firewallUnbanIP(ip)
	auditLog("IP_REPUTATION_UNBAN", operator, "ip="+ip+" 已解封并重置评分")
	return true
}

// ===================== 持久化 =====================

type ipRepPersist struct {
	Score       float64 `json:"score"`
	LastPenalty int64   `json:"lastPenalty"`
	BannedAt    int64   `json:"bannedAt"`
}

func ipRepSave() {
	ipRepMu.Lock()
	out := map[string]ipRepPersist{}
	for ip, e := range ipRepTable {
		out[ip] = ipRepPersist{Score: e.Score, LastPenalty: e.LastPenalty.Unix(), BannedAt: e.BannedAt.Unix()}
	}
	ipRepMu.Unlock()
	b, _ := json.Marshal(out)
	_ = os.MkdirAll("state", 0o755)
	_ = os.WriteFile(filepath.Join("state", "iprep.json"), b, 0o600)
}

func ipRepLoad() {
	b, err := os.ReadFile(filepath.Join("state", "iprep.json"))
	if err != nil {
		return
	}
	var in map[string]ipRepPersist
	if json.Unmarshal(b, &in) != nil {
		return
	}
	ipRepMu.Lock()
	defer ipRepMu.Unlock()
	for ip, p := range in {
		ipRepTable[ip] = &ipRepEntry{
			Score:       p.Score,
			LastPenalty: time.Unix(p.LastPenalty, 0),
			BannedAt:    time.Unix(p.BannedAt, 0),
			distinctSrcs: map[string]bool{},
		}
	}
	logMsg("[IPREP] 信誉表已从 state/iprep.json 恢复（条目数见状态接口）")
}

// handleIPRepStatus admin 查询接口
func handleIPRepStatus(w http.ResponseWriter, r *http.Request) {
	ipRepMu.Lock()
	snapshot := map[string]float64{}
	for ip, e := range ipRepTable {
		snapshot[ip] = e.Score
	}
	ipRepMu.Unlock()
	writeJSON(w, map[string]interface{}{
		"enabled":   ipRepEnabled(),
		"whitelist": v3Config().IPReputation.Whitelist,
		"scores":    snapshot,
	})
}

// handleIPRepUnban admin 解封接口
func handleIPRepUnban(w http.ResponseWriter, r *http.Request) {
	name, role, ok := userFromRequest(r)
	if !ok || role != "admin" {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "需要 admin 角色"})
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.IP == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 body: {\"ip\": \"...\"}"})
		return
	}
	ipRepUnban(name, req.IP)
	writeJSON(w, map[string]string{"status": "unbanned", "ip": req.IP})
}
