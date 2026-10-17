// mcpscan.go — MCP工具扫描（目：Ordo-MCPSecurity）
// 静态扫描 + 动态扫描 + 自动分类 + 任务匹配
package mcpscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Scanner MCP扫描器
type Scanner struct {
	staticRules  []StaticRule
	dynamicRules []DynamicRule
}

// StaticRule 静态扫描规则
type StaticRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

// DynamicRule 动态扫描规则
type DynamicRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	RiskScore   int      `json:"risk_score"`
}

// MCPManifest MCP工具清单
type MCPManifest struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Tools       []MCPTool `json:"tools"`
	ServerType  string    `json:"server_type"`
}

// MCPTool 单个工具
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ScanResult 扫描结果
type ScanResult struct {
	Safe       bool        `json:"safe"`
	RiskLevel  string      `json:"risk_level"`
	Categories []string    `json:"categories"`
	Tasks      []string    `json:"tasks"`
	Matches    []RuleMatch `json:"matches"`
	Hash       string      `json:"hash"`
}

// RuleMatch 规则命中
type RuleMatch struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// NewScanner 创建扫描器
func NewScanner() *Scanner {
	return &Scanner{
		staticRules: []StaticRule{
			{ID: "S001", Name: "SSRF检测", Pattern: `(?i)(fetch|curl|wget|http\.request|urllib)`, Severity: "high", Category: "ssrf"},
			{ID: "S002", Name: "文件读取", Pattern: `(?i)(fs\.read|readFile|open\(|\.read\()`, Severity: "medium", Category: "file-access"},
			{ID: "S003", Name: "命令执行", Pattern: `(?i)(exec|spawn|system\(|subprocess)`, Severity: "critical", Category: "exec"},
			{ID: "S004", Name: "网络监听", Pattern: `(?i)(listen|bind|createServer)`, Severity: "high", Category: "network"},
			{ID: "S005", Name: "数据外传", Pattern: `(?i)(post|send|upload|exfil)`, Severity: "high", Category: "data-exfil"},
			{ID: "S006", Name: "环境变量读取", Pattern: `(?i)(process\.env|os\.environ|getenv)`, Severity: "low", Category: "data-exfil"},
			{ID: "S007", Name: "eval执行", Pattern: `(?i)(eval\(|Function\(|new Function)`, Severity: "critical", Category: "exec"},
		},
		dynamicRules: []DynamicRule{
			{ID: "D001", Name: "本地文件系统访问", Permissions: []string{"file.read", "file.write"}, RiskScore: 60},
			{ID: "D002", Name: "网络出站请求", Permissions: []string{"network.outbound"}, RiskScore: 70},
			{ID: "D003", Name: "进程启动", Permissions: []string{"process.spawn"}, RiskScore: 90},
			{ID: "D004", Name: "系统命令", Permissions: []string{"system.exec"}, RiskScore: 95},
			{ID: "D005", Name: "剪贴板访问", Permissions: []string{"clipboard.read", "clipboard.write"}, RiskScore: 50},
		},
	}
}

// Scan 扫描MCP工具
func (s *Scanner) Scan(manifest *MCPManifest) *ScanResult {
	result := &ScanResult{Safe: true, RiskLevel: "low"}
	text := manifestToText(manifest)

	for _, rule := range s.staticRules {
		re := regexp.MustCompile(rule.Pattern)
		if re.MatchString(text) {
			result.Matches = append(result.Matches, RuleMatch{
				RuleID: rule.ID, RuleName: rule.Name, Severity: rule.Severity,
				Detail: fmt.Sprintf("pattern: %s", rule.Pattern),
			})
			result.Categories = appendUnique(result.Categories, rule.Category)
			if severityScore(rule.Severity) > severityScore(result.RiskLevel) {
				result.RiskLevel = rule.Severity
			}
			result.Safe = false
		}
	}

	for _, tool := range manifest.Tools {
		for _, rule := range s.dynamicRules {
			if matchesDynamic(tool, rule) {
				result.Matches = append(result.Matches, RuleMatch{
					RuleID: rule.ID, RuleName: rule.Name, Severity: riskToSeverity(rule.RiskScore),
					Detail: fmt.Sprintf("tool %s matches behavior", tool.Name),
				})
				result.Safe = false
			}
		}
	}

	result.Categories = classifyMCP(manifest, result.Categories)
	result.Tasks = matchTasks(result.Categories)

	h := sha256.Sum256([]byte(text))
	result.Hash = hex.EncodeToString(h[:])[:16]
	return result
}

func classifyMCP(manifest *MCPManifest, detected []string) []string {
	categories := append([]string{}, detected...)
	desc := strings.ToLower(manifest.Description)
	if strings.Contains(desc, "browser") || strings.Contains(desc, "web") {
		categories = appendUnique(categories, "browser-automation")
	}
	if strings.Contains(desc, "file") || strings.Contains(desc, "document") {
		categories = appendUnique(categories, "file-system")
	}
	if strings.Contains(desc, "database") || strings.Contains(desc, "sql") {
		categories = appendUnique(categories, "database")
	}
	if strings.Contains(desc, "shell") || strings.Contains(desc, "terminal") {
		categories = appendUnique(categories, "terminal")
	}
	if strings.Contains(desc, "search") {
		categories = appendUnique(categories, "search")
	}
	return categories
}

func matchTasks(categories []string) []string {
	taskMap := map[string][]string{
		"ssrf":               {"外网信息收集", "API测试"},
		"file-access":        {"本地文件处理", "文档分析"},
		"exec":               {"系统运维", "开发调试"},
		"network":            {"网络诊断", "服务发现"},
		"data-exfil":         {"数据备份", "日志收集"},
		"browser-automation": {"网页抓取", "自动化测试"},
		"file-system":        {"文件管理", "批量处理"},
		"database":           {"数据分析", "报表生成"},
		"terminal":           {"命令行操作", "脚本执行"},
		"search":             {"信息检索", "知识问答"},
	}
	var tasks []string
	seen := map[string]bool{}
	for _, cat := range categories {
		for _, t := range taskMap[cat] {
			if !seen[t] {
				seen[t] = true
				tasks = append(tasks, t)
			}
		}
	}
	return tasks
}

func manifestToText(m *MCPManifest) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func severityScore(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func riskToSeverity(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 50:
		return "medium"
	default:
		return "low"
	}
}

func matchesDynamic(tool MCPTool, rule DynamicRule) bool {
	desc := strings.ToLower(tool.Description)
	for _, perm := range rule.Permissions {
		if strings.Contains(desc, strings.ToLower(perm)) {
			return true
		}
	}
	return false
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
