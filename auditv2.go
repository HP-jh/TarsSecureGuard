package main

// v3.2.2 审计升级（audit v2）：结构化 JSONL + 哈希链防篡改。
//
// 设计目标：
//   - 既有 auditLog / auditLogT 全量无损升级：老文本行（logs/audit-*.log + 内存 500 条）
//     照旧供现有 UI / 检索使用，v2 结构化条目为增量落盘，二者并存零迁移。
//   - 每条 v2 条目携带 prev_hash + 本条 SHA-256 hash 形成「链」：任何对历史行
//     的增/删/改都会使其后所有条目的 hash 校验失败——篡改可检出、可定位。
//   - 按天分文件（audit/audit-YYYY-MM-DD.jsonl），重启续链：当天首次写入前读回
//     末行 seed（seq + prev_hash），链跨重启连续。
//   - 保留期治理：audit.retentionDays > 0 时按天清理过期文件（0=永久保留）。
//   - 验证与导出：
//       GET /api/admin/audit/verify?date=YYYY-MM-DD  —— 重算全链，报告首个断点
//       GET /api/admin/audit/export?date=YYYY-MM-DD  —— JSONL 下载（租户行级过滤）
//   - [MT_AUDIT_ISOLATION] 延续：导出按 tenant 行级过滤；非全局角色只见本租户；
//     verify 需 global 审计视野（链完整性是全局事实，逐租户验证无意义）。
//
// 零依赖：全部标准库（crypto/sha256、encoding/json）。

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ===================== 配置 =====================

// AuditCfg 审计 v2 配置段（config.json 顶层键 audit）
type AuditCfg struct {
	// RetentionDays 审计文件保留天数；0 = 永久保留（默认）
	RetentionDays int `json:"retentionDays"`
}

// ===================== 条目与链状态 =====================

// AuditV2Entry 审计 v2 结构化条目（JSONL 一行一条）
type AuditV2Entry struct {
	Seq      int    `json:"seq"`                // 当日文件内单调递增（从 1 起）
	Ts       string `json:"ts"`                 // RFC3339Nano
	Action   string `json:"action"`             // 事件名（如 ACCESS_DENIED / GATEKEEPER_DENY）
	Tenant   string `json:"tenant"`             // 租户 ID；全局事件为 "*"
	Group    string `json:"group,omitempty"`    // 用户组（可空）
	User     string `json:"user"`               // 操作者；系统事件为 "system"
	IP       string `json:"ip,omitempty"`       // 来源 IP（可空）
	Detail   string `json:"detail"`             // 详情（沿用既有 detail 文本）
	Trace    string `json:"trace,omitempty"`    // 观测 trace id（可空）
	PrevHash string `json:"prevHash"`           // 前一条 hash；当日首条为 64 个 "0"
	Hash     string `json:"hash"`               // 本条 hash = SHA256(prevHash + 规范化JSON)
}

var (
	auditV2Mu       sync.Mutex
	auditV2Dir      string // audit/ 目录；空 = 不可用（降级：只写旧文本日志）
	auditV2Day      string // 当前打开文件对应的日期（YYYY-MM-DD）
	auditV2Seq      int    // 当日已写入的最大 seq
	auditV2PrevHash string // 当日末条 hash（链头）
	auditV2File     *os.File
	auditV2LastSweep time.Time
)

const auditV2Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// auditV2DirPath 审计目录（惰性创建；失败则 v2 落盘禁用，服务不中断）
func auditV2DirPath() string {
	if auditV2Dir != "" {
		return auditV2Dir
	}
	d := filepath.Join(appDir(), "audit")
	if err := os.MkdirAll(d, 0755); err != nil {
		logMsg(fmt.Sprintf("[AUDIT-V2] 无法创建审计目录，v2 落盘禁用: %v", err))
		return ""
	}
	auditV2Dir = d
	return d
}

// auditV2FilePath 指定日期的审计文件路径
func auditV2FilePath(day string) string {
	return filepath.Join(auditV2DirPath(), "audit-"+day+".jsonl")
}

// auditV2SeedFor 当日首次写入前从文件末行恢复链头（seq + prev_hash）
func auditV2SeedFor(day string) (int, string) {
	f, err := os.Open(auditV2FilePath(day))
	if err != nil {
		return 0, auditV2Genesis
	}
	defer f.Close()
	var last string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			last = line
		}
	}
	if last == "" {
		return 0, auditV2Genesis
	}
	var e AuditV2Entry
	if err := json.Unmarshal([]byte(last), &e); err != nil || e.Hash == "" {
		// 末行损坏：不中断写链，从 0 重算会掩盖篡改——改为拒绝续链（fail-close：
		// 新条目继续写，但链头指向损坏行的原始文本 hash，验证器会同时报告）
		h := sha256.Sum256([]byte("corrupted-tail:" + last))
		return 0, hex.EncodeToString(h[:])
	}
	return e.Seq, e.Hash
}

// auditV2Write 写入一条 v2 审计（内部含按天切换 / 续链 / 保留期清理）
func auditV2Write(action, tenant, group, user, ip, detail, trace string) {
	auditV2Mu.Lock()
	defer auditV2Mu.Unlock()
	dir := auditV2DirPath()
	if dir == "" {
		return // 目录不可用：降级为仅旧文本日志（已在调用方写入）
	}
	day := time.Now().Format("2006-01-02")
	if auditV2File == nil || auditV2Day != day {
		if auditV2File != nil {
			auditV2File.Close()
		}
		seq, prev := auditV2SeedFor(day)
		auditV2Seq, auditV2PrevHash = seq, prev
		f, err := os.OpenFile(auditV2FilePath(day), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			logMsg(fmt.Sprintf("[AUDIT-V2] 打开审计文件失败，v2 落盘暂停: %v", err))
			auditV2File = nil
			return
		}
		auditV2File, auditV2Day = f, day
		auditV2SweepLocked()
	}
	if tenant == "" {
		tenant = "*"
	}
	if user == "" {
		user = "system"
	}
	e := AuditV2Entry{
		Seq:      auditV2Seq + 1,
		Ts:       time.Now().Format(time.RFC3339Nano),
		Action:   action,
		Tenant:   tenant,
		Group:    group,
		User:     user,
		IP:       ip,
		Detail:   detail,
		Trace:    trace,
		PrevHash: auditV2PrevHash,
	}
	e.Hash = auditV2EntryHash(e)
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	if _, err := auditV2File.Write(append(line, '\n')); err != nil {
		logMsg(fmt.Sprintf("[AUDIT-V2] 审计写入失败: %v", err))
		return
	}
	auditV2Seq = e.Seq
	auditV2PrevHash = e.Hash
}

// auditV2EntryHash 规范化序列化后与 prevHash 一起取 SHA-256
func auditV2EntryHash(e AuditV2Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// auditV2SweepLocked 保留期清理（调用方持有 auditV2Mu）。每天最多执行一次。
func auditV2SweepLocked() {
	if !auditV2LastSweep.IsZero() && time.Since(auditV2LastSweep) < 24*time.Hour {
		return
	}
	auditV2LastSweep = time.Now()
	cfgMu.RLock()
	retention := cfg.Audit.RetentionDays
	cfgMu.RUnlock()
	if retention <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retention).Format("2006-01-02")
	entries, err := os.ReadDir(auditV2DirPath())
	if err != nil {
		return
	}
	for _, en := range entries {
		name := en.Name()
		if !strings.HasPrefix(name, "audit-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "audit-"), ".jsonl")
		if len(day) == 10 && day < cutoff {
			if err := os.Remove(filepath.Join(auditV2DirPath(), name)); err == nil {
				logMsg(fmt.Sprintf("[AUDIT-V2] 保留期清理：%s（retention=%dd）", name, retention))
			}
		}
	}
}

// ===================== 验证与导出 =====================

// auditV2Verify 重算指定日期全链，返回（总数， 首个断点序号, 错误说明）
func auditV2Verify(day string) (int, int, string) {
	f, err := os.Open(auditV2FilePath(day))
	if err != nil {
		return 0, 0, "审计文件不存在: " + day
	}
	defer f.Close()
	prev := auditV2Genesis
	seq := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditV2Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return seq, e.Seq, fmt.Sprintf("第 %d 行不是合法 JSON", lineNo)
		}
		if e.PrevHash != prev {
			return seq, e.Seq, fmt.Sprintf("第 %d 条 prevHash 断链（期望 %s… 实际 %s…）", e.Seq, prev[:8], e.PrevHash[:8])
		}
		if want := auditV2EntryHash(e); want != e.Hash {
			return seq, e.Seq, fmt.Sprintf("第 %d 条 hash 不匹配（内容被篡改或损坏）", e.Seq)
		}
		prev = e.Hash
		seq = e.Seq
	}
	if seq == 0 {
		return 0, 0, "当日无审计条目"
	}
	return seq, 0, ""
}

// auditV2ListDates 列出已有审计文件日期（升序，供导出/验证参数提示）
func auditV2ListDates() []string {
	entries, err := os.ReadDir(auditV2DirPath())
	if err != nil {
		return nil
	}
	var days []string
	for _, en := range entries {
		name := en.Name()
		if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".jsonl") {
			days = append(days, strings.TrimSuffix(strings.TrimPrefix(name, "audit-"), ".jsonl"))
		}
	}
	sort.Strings(days)
	return days
}

// handleAuditVerify GET /api/admin/audit/verify?date=YYYY-MM-DD
// 链完整性是全局事实：仅 global_admin / global_auditor（含单管理员回退）可验。
func handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	id, ok := identityFromRequest(r)
	if !ok || (!id.Global && id.Role != "global_admin" && id.Role != "global_auditor") {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "审计链验证需要全局审计视野（global_admin / global_auditor）"})
		return
	}
	day := r.URL.Query().Get("date")
	if day == "" {
		day = time.Now().Format("2006-01-02")
	}
	total, broken, msg := auditV2Verify(day)
	resp := map[string]interface{}{
		"date": day, "total": total, "intact": broken == 0 && total > 0,
		"availableDates": auditV2ListDates(),
	}
	if broken != 0 {
		resp["brokenAtSeq"] = broken
		resp["problem"] = msg
	}
	auditLogT("AUDIT_V2_VERIFY", id.Tenant, "", id.Name, fmt.Sprintf("date=%s total=%d intact=%v %s", day, total, broken == 0, msg))
	writeJSON(w, resp)
}

// handleAuditExport GET /api/admin/audit/export?date=YYYY-MM-DD
// [MT_AUDIT_ISOLATION]：非全局角色按 tenant 行级过滤；跨租户访问产生审计事件。
func handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	day := r.URL.Query().Get("date")
	if day == "" {
		day = time.Now().Format("2006-01-02")
	}
	f, err := os.Open(auditV2FilePath(day))
	if err != nil {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "当日无审计文件"})
		return
	}
	defer f.Close()
	var b strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	exported, skipped := 0, 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditV2Entry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if !id.Global && e.Tenant != id.Tenant && e.Tenant != "*" {
			skipped++
			if skipped == 1 {
				auditLogT("AUDIT_CROSS_TENANT_ACCESS", id.Tenant, "", id.Name, "审计导出已按租户过滤（其余行不展示）")
			}
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
		exported++
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=audit-%s-filtered.jsonl", day))
	w.Write([]byte(b.String()))
}
