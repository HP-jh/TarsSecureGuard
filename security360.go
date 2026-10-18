// security360.go — v4.15.0 360 Safe 风格安全中心
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ========== 数据模型 ==========

type SecurityScanResult struct {
	Score       int              `json:"score"`
	Status      string           `json:"status"` // safe / warning / danger
	ScanTime    time.Time        `json:"scanTime"`
	DurationMs  int64            `json:"durationMs"`
	Categories  []ScanCategory   `json:"categories"`
	Threats     []ThreatItem     `json:"threats"`
	Recommendations []string     `json:"recommendations"`
}

type ScanCategory struct {
	Name     string `json:"name"`
	Score    int    `json:"score"`    // 0-100
	Status   string `json:"status"`   // safe / warning / danger
	Icon     string `json:"icon"`
	Details  string `json:"details"`
}

type ThreatItem struct {
	ID          string    `json:"id"`
	Level       string    `json:"level"`       // high / medium / low
	Category    string    `json:"category"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	FoundAt     time.Time `json:"foundAt"`
	Resolved    bool      `json:"resolved"`
	Quarantined bool      `json:"quarantined"`
}

type QuarantineItem struct {
	ID          string    `json:"id"`
	OriginalPath string   `json:"originalPath"`
	ThreatID    string    `json:"threatId"`
	QuarantinedAt time.Time `json:"quarantinedAt"`
	Size        int64     `json:"size"`
	Hash        string    `json:"hash"`
}

// ========== 内存存储 ==========

var (
	sec360Mu        sync.RWMutex
	lastScanResult  *SecurityScanResult
	threatDB        = map[string]*ThreatItem{}
	quarantineDB    = map[string]*QuarantineItem{}
	scanInProgress  bool
)

// ========== 处理器 ==========

func handleSecurity360Scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeHumanizedJSONStatus(w, r, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	sec360Mu.Lock()
	if scanInProgress {
		sec360Mu.Unlock()
		writeJSON(w, map[string]interface{}{"status": "scanning", "message": "扫描进行中"})
		return
	}
	scanInProgress = true
	sec360Mu.Unlock()

	go func() {
		result := runSecurityScan()
		sec360Mu.Lock()
		lastScanResult = result
		scanInProgress = false
		sec360Mu.Unlock()
	}()

	writeJSON(w, map[string]interface{}{"status": "started", "message": "安全扫描已启动"})
}

func handleSecurity360Status(w http.ResponseWriter, r *http.Request) {
	sec360Mu.RLock()
	result := lastScanResult
	scanning := scanInProgress
	sec360Mu.RUnlock()

	if result == nil && !scanning {
		// 返回默认状态，提示未扫描
		writeJSON(w, map[string]interface{}{
			"scanned":   false,
			"scanning":  false,
			"score":     0,
			"status":    "unknown",
			"message":   "尚未执行安全扫描",
		})
		return
	}

	if scanning {
		writeJSON(w, map[string]interface{}{
			"scanned":   false,
			"scanning":  true,
			"score":     0,
			"status":    "scanning",
			"message":   "安全扫描进行中...",
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"scanned":    true,
		"scanning":   false,
		"score":      result.Score,
		"status":     result.Status,
		"scanTime":   result.ScanTime,
		"durationMs": result.DurationMs,
		"categories": result.Categories,
		"threatCount": len(result.Threats),
		"recommendations": result.Recommendations,
	})
}

func handleSecurity360Threats(w http.ResponseWriter, r *http.Request) {
	sec360Mu.RLock()
	threats := make([]*ThreatItem, 0, len(threatDB))
	for _, t := range threatDB {
		threats = append(threats, t)
	}
	sec360Mu.RUnlock()

	// 过滤参数
	level := r.URL.Query().Get("level")
	resolved := r.URL.Query().Get("resolved")
	filtered := make([]*ThreatItem, 0, len(threats))
	for _, t := range threats {
		if level != "" && t.Level != level {
			continue
		}
		if resolved != "" {
			wantResolved := resolved == "true"
			if t.Resolved != wantResolved {
				continue
			}
		}
		filtered = append(filtered, t)
	}

	writeJSON(w, map[string]interface{}{"threats": filtered, "total": len(filtered)})
}

func handleSecurity360ResolveThreat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeHumanizedJSONStatus(w, r, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeHumanizedJSONStatus(w, r, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	sec360Mu.Lock()
	if t, ok := threatDB[req.ID]; ok {
		t.Resolved = true
	}
	sec360Mu.Unlock()

	writeJSON(w, map[string]interface{}{"ok": true})
}

func handleSecurity360Quarantine(w http.ResponseWriter, r *http.Request) {
	sec360Mu.RLock()
	items := make([]*QuarantineItem, 0, len(quarantineDB))
	for _, q := range quarantineDB {
		items = append(items, q)
	}
	sec360Mu.RUnlock()
	writeJSON(w, map[string]interface{}{"items": items, "total": len(items)})
}

func handleSecurity360QuarantineRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeHumanizedJSONStatus(w, r, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeHumanizedJSONStatus(w, r, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	sec360Mu.Lock()
	if q, ok := quarantineDB[req.ID]; ok {
		delete(quarantineDB, req.ID)
		// 恢复威胁为未隔离
		if t, ok := threatDB[q.ThreatID]; ok {
			t.Quarantined = false
		}
	}
	sec360Mu.Unlock()

	writeJSON(w, map[string]interface{}{"ok": true})
}

// ========== 扫描引擎 ==========

func runSecurityScan() *SecurityScanResult {
	start := time.Now()
	result := &SecurityScanResult{
		ScanTime:   time.Now(),
		Categories: make([]ScanCategory, 0, 6),
		Threats:    make([]ThreatItem, 0),
	}

	// 1. WAF 防护检查
	wafScore, wafThreats := scanWAF()
	result.Categories = append(result.Categories, ScanCategory{
		Name:   "WAF 防护",
		Score:  wafScore,
		Status: statusFromScore(wafScore),
		Icon:   "shield",
		Details: fmt.Sprintf("拦截次数: %d", wafBlocks),
	})
	result.Threats = append(result.Threats, wafThreats...)

	// 2. 防火墙状态
	fwScore, fwThreats := scanFirewall()
	fwStatus := firewallStatus()
	fwPolicy := "unknown"
	if p, ok := fwStatus["policy"].(string); ok {
		fwPolicy = p
	}
	result.Categories = append(result.Categories, ScanCategory{
		Name:   "防火墙",
		Score:  fwScore,
		Status: statusFromScore(fwScore),
		Icon:   "firewall",
		Details: fwPolicy,
	})
	result.Threats = append(result.Threats, fwThreats...)

	// 3. 配置安全检查
	cfgScore, cfgThreats := scanConfigSecurity()
	result.Categories = append(result.Categories, ScanCategory{
		Name:   "配置安全",
		Score:  cfgScore,
		Status: statusFromScore(cfgScore),
		Icon:   "config",
		Details: "检查密钥强度与默认配置",
	})
	result.Threats = append(result.Threats, cfgThreats...)

	// 4. 访问控制
	aclScore, aclThreats := scanACL()
	result.Categories = append(result.Categories, ScanCategory{
		Name:   "访问控制",
		Score:  aclScore,
		Status: statusFromScore(aclScore),
		Icon:   "lock",
		Details: "RBAC / 白名单 / 租户隔离",
	})
	result.Threats = append(result.Threats, aclThreats...)

	// 5. 审计链路
	auditScore, auditThreats := scanAudit()
	result.Categories = append(result.Categories, ScanCategory{
		Name:   "审计链路",
		Score:  auditScore,
		Status: statusFromScore(auditScore),
		Icon:   "audit",
		Details: "日志完整性 hash 链",
	})
	result.Threats = append(result.Threats, auditThreats...)

	// 6. 系统健康
	healthScore, healthThreats := scanSystemHealth()
	result.Categories = append(result.Categories, ScanCategory{
		Name:   "系统健康",
		Score:  healthScore,
		Status: statusFromScore(healthScore),
		Icon:   "health",
		Details: "运行时长与资源状态",
	})
	result.Threats = append(result.Threats, healthThreats...)

	// 7. MCP 安全
	mcpScore, mcpThreats := scanMCPSecurity()
	result.Categories = append(result.Categories, ScanCategory{
		Name:   "MCP 安全",
		Score:  mcpScore,
		Status: statusFromScore(mcpScore),
		Icon:   "mcp",
		Details: "外部 MCP 服务器配置安全检查",
	})
	result.Threats = append(result.Threats, mcpThreats...)

	// 计算总分
	totalScore := 0
	for _, c := range result.Categories {
		totalScore += c.Score
	}
	result.Score = totalScore / len(result.Categories)
	result.Status = statusFromScore(result.Score)
	result.DurationMs = time.Since(start).Milliseconds()

	// 生成建议
	result.Recommendations = generateRecommendations(result)

	// 更新威胁数据库
	sec360Mu.Lock()
	for i := range result.Threats {
		t := &result.Threats[i]
		if _, exists := threatDB[t.ID]; !exists {
			threatDB[t.ID] = t
		}
	}
	sec360Mu.Unlock()

	return result
}

// ========== 各子扫描器 ==========

func scanWAF() (int, []ThreatItem) {
	mu.Lock()
	blocks := wafBlocks
	mu.Unlock()

	score := 100
	var threats []ThreatItem

	if blocks == 0 {
		score = 85 // WAF 运行中但无拦截记录，可能流量不足
		threats = append(threats, ThreatItem{
			ID:          hashThreat("waf-no-blocks"),
			Level:       "low",
			Category:    "WAF 防护",
			Title:       "WAF 尚无拦截记录",
			Description: "WAF 已启用但未检测到攻击流量，建议验证规则有效性",
			FoundAt:     time.Now(),
		})
	} else if blocks > 1000 {
		score = 70
		threats = append(threats, ThreatItem{
			ID:          hashThreat("waf-high-blocks"),
			Level:       "medium",
			Category:    "WAF 防护",
			Title:       "WAF 拦截量异常偏高",
			Description: fmt.Sprintf("近期拦截 %d 次，可能存在持续攻击", blocks),
			FoundAt:     time.Now(),
		})
	}

	cfgMu.RLock()
	enabled := cfg.Security.WAFEnabled
	cfgMu.RUnlock()
	if !enabled {
		score = 20
		threats = append(threats, ThreatItem{
			ID:          hashThreat("waf-disabled"),
			Level:       "high",
			Category:    "WAF 防护",
			Title:       "WAF 已禁用",
			Description: "Web 应用防火墙未启用，网关面临直接攻击风险",
			FoundAt:     time.Now(),
		})
	}

	return score, threats
}

func scanFirewall() (int, []ThreatItem) {
	status := firewallStatus()
	score := 100
	var threats []ThreatItem

	policy := ""
	if p, ok := status["policy"].(string); ok {
		policy = p
	}

	if policy == "passive" || policy == "" {
		score = 60
		threats = append(threats, ThreatItem{
			ID:          hashThreat("fw-passive"),
			Level:       "medium",
			Category:    "防火墙",
			Title:       "防火墙处于被动模式",
			Description: "仅记录不拦截，建议切换为 dynamic-ban 或 os-link 模式",
			FoundAt:     time.Now(),
		})
	}

	return score, threats
}

func scanConfigSecurity() (int, []ThreatItem) {
	score := 100
	var threats []ThreatItem

	cfgMu.RLock()
	key := cfg.Security.APIKey
	mode := cfg.Security.Mode
	users := len(cfg.Users)
	cfgMu.RUnlock()

	if len(key) < 16 {
		score -= 40
		threats = append(threats, ThreatItem{
			ID:          hashThreat("cfg-weak-key"),
			Level:       "high",
			Category:    "配置安全",
			Title:       "API 密钥强度不足",
			Description: fmt.Sprintf("当前密钥长度 %d，建议 ≥32 位随机字符串", len(key)),
			FoundAt:     time.Now(),
		})
	}

	if mode == "permissive" || mode == "" {
		score -= 30
		threats = append(threats, ThreatItem{
			ID:          hashThreat("cfg-permissive"),
			Level:       "medium",
			Category:    "配置安全",
			Title:       "安全模式为宽松",
			Description: "当前安全模式为 permissive，建议切换为 strict",
			FoundAt:     time.Now(),
		})
	}

	if users == 0 {
		score -= 10
		threats = append(threats, ThreatItem{
			ID:          hashThreat("cfg-no-rbac"),
			Level:       "low",
			Category:    "配置安全",
			Title:       "未配置多用户 RBAC",
			Description: "仅使用单管理员模式，建议配置 Users 实现角色分离",
			FoundAt:     time.Now(),
		})
	}

	// 检查配置文件权限
	if configPath != "" {
		info, err := os.Stat(configPath)
		if err == nil {
			mode := info.Mode().Perm()
			if mode&0o077 != 0 {
				score -= 20
				threats = append(threats, ThreatItem{
					ID:          hashThreat("cfg-perm"),
					Level:       "medium",
					Category:    "配置安全",
					Title:       "配置文件权限过宽",
					Description: fmt.Sprintf("config.json 权限 %04o，建议 0600", mode),
					FoundAt:     time.Now(),
				})
			}
		}
	}

	if score < 0 {
		score = 0
	}
	return score, threats
}

func scanACL() (int, []ThreatItem) {
	score := 90
	var threats []ThreatItem

	cfgMu.RLock()
	users := len(cfg.Users)
	cfgMu.RUnlock()

	if users <= 1 {
		score -= 15
		threats = append(threats, ThreatItem{
			ID:          hashThreat("acl-minimal-rbac"),
			Level:       "low",
			Category:    "访问控制",
			Title:       "RBAC 配置极简",
			Description: "用户数量 ≤1，未实现角色分离，建议配置多用户与租户隔离",
			FoundAt:     time.Now(),
		})
	}

	return score, threats
}

func scanAudit() (int, []ThreatItem) {
	score := 95
	var threats []ThreatItem

	// 检查审计目录是否有文件
	dir := auditV2DirPath()
	hasFiles := false
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) > 0 {
			hasFiles = true
		}
	}

	if !hasFiles {
		score = 50
		threats = append(threats, ThreatItem{
			ID:          hashThreat("audit-empty"),
			Level:       "medium",
			Category:    "审计链路",
			Title:       "审计链为空",
			Description: "审计 hash 链尚未建立，无法保证日志不可篡改",
			FoundAt:     time.Now(),
		})
	}

	return score, threats
}

func scanSystemHealth() (int, []ThreatItem) {
	score := 95
	var threats []ThreatItem

	uptime := time.Since(startTime)
	if uptime < time.Minute {
		score -= 10
		threats = append(threats, ThreatItem{
			ID:          hashThreat("health-recent-start"),
			Level:       "low",
			Category:    "系统健康",
			Title:       "服务刚启动",
			Description: "运行时间不足 1 分钟，稳定性观察中",
			FoundAt:     time.Now(),
		})
	}

	return score, threats
}

func scanMCPSecurity() (int, []ThreatItem) {
	score := 100
	var threats []ThreatItem

	cfgMu.RLock()
	servers := cfg.MCP.ExternalServers
	cfgMu.RUnlock()

	if len(servers) == 0 {
		score = 85
		threats = append(threats, ThreatItem{
			ID:          hashThreat("mcp-no-servers"),
			Level:       "low",
			Category:    "MCP 安全",
			Title:       "未配置外部 MCP 服务器",
			Description: "未配置外部 MCP 服务器，功能受限但无额外风险",
			FoundAt:     time.Now(),
		})
		return score, threats
	}

	for _, s := range servers {
		if !s.Enabled {
			continue
		}
		sec := evaluateMCPServer(s)
		if sec.RiskLevel == "danger" {
			score -= 15
			threats = append(threats, ThreatItem{
				ID:          hashThreat("mcp-danger-" + s.Name),
				Level:       "high",
				Category:    "MCP 安全",
				Title:       fmt.Sprintf("MCP 服务器 [%s] 存在高危风险", s.Name),
				Description: strings.Join(sec.Issues, "；"),
				FoundAt:     time.Now(),
			})
		} else if sec.RiskLevel == "warning" {
			score -= 8
			threats = append(threats, ThreatItem{
				ID:          hashThreat("mcp-warning-" + s.Name),
				Level:       "medium",
				Category:    "MCP 安全",
				Title:       fmt.Sprintf("MCP 服务器 [%s] 存在警告", s.Name),
				Description: strings.Join(sec.Issues, "；"),
				FoundAt:     time.Now(),
			})
		}
	}

	if score < 0 {
		score = 0
	}
	return score, threats
}

// ========== 辅助函数 ==========

func statusFromScore(s int) string {
	if s >= 90 {
		return "safe"
	}
	if s >= 60 {
		return "warning"
	}
	return "danger"
}

func hashThreat(s string) string {
	h := sha256.Sum256([]byte(s + time.Now().Format("2006-01-02")))
	return hex.EncodeToString(h[:8])
}

func generateRecommendations(r *SecurityScanResult) []string {
	var recs []string
	for _, c := range r.Categories {
		if c.Score < 60 {
			recs = append(recs, fmt.Sprintf("[%s] %s — 当前评分 %d，建议立即修复", c.Status, c.Name, c.Score))
		} else if c.Score < 85 {
			recs = append(recs, fmt.Sprintf("[%s] %s — 当前评分 %d，建议优化", c.Status, c.Name, c.Score))
		}
	}
	if len(recs) == 0 {
		recs = append(recs, "安全状态良好，继续保持")
	}
	return recs
}

// ========== MCP 安全管理 ==========

type MCPServerSecurity struct {
	Name      string `json:"name"`
	Command   string `json:"command"`
	Enabled   bool   `json:"enabled"`
	Healthy   bool   `json:"healthy"`
	RiskLevel string `json:"riskLevel"` // safe / warning / danger
	Issues    []string `json:"issues"`
}

func handleSecurity360MCPServers(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	servers := cfg.MCP.ExternalServers
	cfgMu.RUnlock()

	var result []MCPServerSecurity
	for _, s := range servers {
		sec := evaluateMCPServer(s)
		result = append(result, sec)
	}
	writeJSON(w, map[string]interface{}{"servers": result, "total": len(result)})
}

func handleSecurity360MCPValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeHumanizedJSONStatus(w, r, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeHumanizedJSONStatus(w, r, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	cfgMu.RLock()
	var target *ExtServer
	for i := range cfg.MCP.ExternalServers {
		if cfg.MCP.ExternalServers[i].Name == req.Name {
			target = &cfg.MCP.ExternalServers[i]
			break
		}
	}
	cfgMu.RUnlock()

	if target == nil {
		writeHumanizedJSONStatus(w, r, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}

	sec := evaluateMCPServer(*target)
	writeJSON(w, map[string]interface{}{"server": sec, "valid": sec.RiskLevel != "danger"})
}

func evaluateMCPServer(s ExtServer) MCPServerSecurity {
	sec := MCPServerSecurity{
		Name:    s.Name,
		Command: s.Command,
		Enabled: s.Enabled,
		Healthy: false,
	}

	if !s.Enabled {
		sec.RiskLevel = "safe"
		sec.Issues = append(sec.Issues, "服务器已禁用")
		return sec
	}

	score := 100
	// 检查命令路径
	if s.Command == "" {
		score -= 50
		sec.Issues = append(sec.Issues, "命令路径为空")
	} else if !filepath.IsAbs(s.Command) {
		score -= 20
		sec.Issues = append(sec.Issues, "命令使用相对路径，建议改为绝对路径")
	}

	// 检查参数中是否有敏感信息
	for _, arg := range s.Args {
		if strings.Contains(strings.ToLower(arg), "password") ||
			strings.Contains(strings.ToLower(arg), "secret") ||
			strings.Contains(strings.ToLower(arg), "token") ||
			strings.Contains(strings.ToLower(arg), "key") {
			score -= 30
			sec.Issues = append(sec.Issues, "参数可能包含敏感信息，建议改用环境变量")
		}
	}

	// 检查是否位于允许路径
	if s.Command != "" && len(allowedRoots) > 0 {
		inAllowed := false
		for _, root := range allowedRoots {
			if strings.HasPrefix(s.Command, root) {
				inAllowed = true
				break
			}
		}
		if !inAllowed {
			score -= 25
			sec.Issues = append(sec.Issues, "命令不在授权路径内")
		}
	}

	if score >= 85 {
		sec.RiskLevel = "safe"
	} else if score >= 60 {
		sec.RiskLevel = "warning"
	} else {
		sec.RiskLevel = "danger"
	}

	sec.Healthy = score >= 60
	return sec
}

// 兼容旧 handleSecurity，增强为 360 格式
func handleSecurity360Summary(w http.ResponseWriter, r *http.Request) {
	sec360Mu.RLock()
	result := lastScanResult
	sec360Mu.RUnlock()

	mu.Lock()
	blocks := wafBlocks
	mu.Unlock()

	cfgMu.RLock()
	mode := cfg.Security.Mode
	wafOn := cfg.Security.WAFEnabled
	cfgMu.RUnlock()

	score := 0
	if result != nil {
		score = result.Score
	}

	writeJSON(w, map[string]interface{}{
		"score":                 score,
		"status":                statusFromScore(score),
		"wafBlockCount":         blocks,
		"threatIntelBlockCount": 0,
		"domainBlockCount":      0,
		"safeModeTriggerCount":  0,
		"mode":                  mode,
		"wafEnabled":            wafOn,
		"firewall":              firewallStatus(),
		"scanned":               result != nil,
		"scanTime":              func() interface{} {
			if result != nil {
				return result.ScanTime
			}
			return nil
		}(),
	})
}

