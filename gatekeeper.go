package main

// v3.2.2 守门人机制（gatekeeper）：工具执行前的统一策略决策点。
//
// 定位：WAF 管「输入」，语义防护管「内容」，守门人管「动作」——高风险工具调用
// 在执行前必须过一道显式策略门，支持人工二次确认（two-phase confirm）。
//
// 决策：allow / deny / confirm（需人工确认）
//   内置规则（代码级，配置只能加严不能放宽——与语义防护「AI 只能加严」同哲学）：
//     [GK-D1] deny   tars_config_set 目标为 security.* / oauth.* / tenants.* /
//                    gatekeeper.* —— 安全关键配置不可经工具通道修改
//     [GK-D2] deny   tars_file_write 目标命中敏感模式（.ssh / id_rsa* /
//                    credentials* / .env* / .git/config）——凭据面零容忍
//     [GK-C1] confirm tars_config_set（其余路径）
//     [GK-C2] confirm tars_model_start / tars_model_stop / tars_model_download
//                      （资源面高影响动作）
//     [GK-C3] confirm tars_file_write 单次写入 > 1MB（大面积覆写保护）
//     [GK-A1] allow   其余工具（含全部只读工具）
//
//   配置规则（config.gatekeeper.rules[]）：{tools:[模式], action, description}
//     - 模式支持尾部 * 通配（如 "tars_file_*"）
//     - 加严方向有效：config deny/confirm 可把内置 allow 升级；
//       config allow 不能把内置 deny/confirm 降级（静默按原级别执行并审计）
//
//   enforce 档位：true（默认，强制拦截）/ false（observe 观察模式：只审计不拦截）
//     —— 观察模式供上线初期试运行；切档本身经配置审计留痕。
//
// Two-phase confirm：
//   首次调用返回 confirmation_required + confirm_token（60s 有效、单次、
//   绑定 用户+工具+参数哈希——换参数/换人不能重放）；客户端带
//   confirm_token 重发即放行本次。
//   防滥用：每用户 pending 上限 10 个、confirm 触发频率 20 次/分钟（超限 deny）。
//
// 审计：GATEKEEPER_DENY / GATEKEEPER_CONFIRM_REQUIRED / GATEKEEPER_CONFIRMED /
//       GATEKEEPER_POLICY_OVERRIDE（配置试图放宽被拒）
// 接入点：executeToolAs（HTTP /api/tools/ 与 /mcp 的统一包装，见 tools.go / mcp.go）。

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ===================== 配置 =====================

// GKRule 单条守门人规则
type GKRule struct {
	Tools       []string `json:"tools"`       // 工具名模式（尾部 * 通配）
	Action      string   `json:"action"`      // allow | deny | confirm
	Description string   `json:"description"`
}

// GatekeeperCfg 守门人配置段（config.json 顶层键 gatekeeper）
type GatekeeperCfg struct {
	Enabled *bool    `json:"enabled"` // 默认 true
	Rules   []GKRule `json:"rules"`   // 配置规则（只能加严）
}

func gatekeeperEnabled() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Gatekeeper.Enabled != nil {
		return *cfg.Gatekeeper.Enabled
	}
	return true
}

func gatekeeperRules() []GKRule {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return append([]GKRule(nil), cfg.Gatekeeper.Rules...)
}

// ===================== 决策 =====================

type gkVerdict int

const (
	gkAllow gkVerdict = iota
	gkConfirm
	gkDeny
)

func (v gkVerdict) String() string {
	switch v {
	case gkAllow:
		return "allow"
	case gkConfirm:
		return "confirm"
	default:
		return "deny"
	}
}

// gkMatchTool 工具名匹配（尾部 * 通配）
func gkMatchTool(pattern, tool string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(tool, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == tool
}

// gkSensitivePath 敏感路径模式（凭据面）
func gkSensitivePath(p string) bool {
	lp := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	patterns := []string{
		"/.ssh/", "id_rsa", "id_ed25519", "id_ecdsa", "credentials",
		"/.env", ".env.", "/.git/config", "authorized_keys", "known_hosts",
		".aws/credentials", ".kube/config", ".netrc", ".npmrc",
	}
	for _, pat := range patterns {
		if strings.Contains(lp, pat) {
			return true
		}
	}
	return false
}

// gkConfigPathProtected 安全关键配置路径前缀
var gkConfigProtectedPrefixes = []string{"security.", "oauth.", "tenants.", "gatekeeper.", "audit."}

func gkConfigPathProtected(p string) bool {
	for _, pre := range gkConfigProtectedPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// gkBuiltin 内置规则判定（最严者胜：deny > confirm > allow）
func gkBuiltin(tool string, args map[string]interface{}) (gkVerdict, string) {
	switch tool {
	case "tars_config_set":
		path, _ := args["path"].(string)
		if gkConfigPathProtected(path) {
			return gkDeny, "安全关键配置路径不可经工具通道修改: " + path
		}
		return gkConfirm, "配置变更需确认（path=" + path + "）"
	case "tars_model_start", "tars_model_stop", "tars_model_download":
		return gkConfirm, "模型资源高影响动作需确认: " + tool
	case "tars_file_write":
		path, _ := args["path"].(string)
		if gkSensitivePath(path) {
			return gkDeny, "敏感路径（凭据/密钥面）禁止经工具写入: " + path
		}
		if c, ok := args["content"].(string); ok && len(c) > 1<<20 {
			return gkConfirm, fmt.Sprintf("单次写入 %d 字节超过 1MB 保护线，需确认", len(c))
		}
		return gkAllow, ""
	default:
		return gkAllow, ""
	}
}

// gkDecide 完整决策：内置 + 配置（配置只能加严）
func gkDecide(tool string, args map[string]interface{}) (gkVerdict, string) {
	v, why := gkBuiltin(tool, args)
	// 配置规则：deny/confirm 可加严；allow 不可放宽（降级尝试审计留痕）
	for _, r := range gatekeeperRules() {
		matched := false
		for _, p := range r.Tools {
			if gkMatchTool(p, tool) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		switch r.Action {
		case "deny":
			if v != gkDeny {
				v = gkDeny
				why = "守门人规则拒绝: " + r.Description
			}
		case "confirm":
			if v == gkAllow {
				v = gkConfirm
				why = "守门人规则要求确认: " + r.Description
			}
		case "allow":
			if v == gkDeny || v == gkConfirm {
				auditLog("GATEKEEPER_POLICY_OVERRIDE", "system",
					fmt.Sprintf("配置规则试图放宽 %s 至 allow（被拒，维持 %s）", tool, v))
			}
		}
	}
	return v, why
}

// ===================== 确认令牌 =====================

type gkPending struct {
	User      string
	Tool      string
	ArgsHash  string
	ExpiresAt time.Time
}

var (
	gkMu        sync.Mutex
	gkPendings  = map[string]gkPending{}
	gkRateWin   = map[string][]time.Time{} // user -> confirm-required 时间窗
)

const gkConfirmTTL = 60 * time.Second
const gkMaxPending = 10
const gkMaxConfirmPerMin = 20

func gkArgsHash(tool string, args map[string]interface{}) string {
	b, _ := json.Marshal(args)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// gkBoundArgsHash 确认令牌的参数绑定哈希：剥离保留键（confirm_token 自身、
// 服务端注入的 _tsgIdentity），只绑业务参数——签发与消费两侧统一用本函数
func gkBoundArgsHash(tool string, args map[string]interface{}) string {
	bound := make(map[string]interface{}, len(args))
	for k, v := range args {
		if k == "confirm_token" || k == "_tsgIdentity" {
			continue
		}
		bound[k] = v
	}
	return gkArgsHash(tool, bound)
}

func gkNewToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "gk_" + hex.EncodeToString(b)
}

// gkRateExceeded 每分钟 confirm 触发频率限制
func gkRateExceeded(user string) bool {
	gkMu.Lock()
	defer gkMu.Unlock()
	now := time.Now()
	win := gkRateWin[user][:0]
	for _, t := range gkRateWin[user] {
		if now.Sub(t) < time.Minute {
			win = append(win, t)
		}
	}
	if len(win) >= gkMaxConfirmPerMin {
		gkRateWin[user] = win
		return true
	}
	win = append(win, now)
	gkRateWin[user] = win
	return false
}

// gkPendingCount 用户 pending 数（含过期清扫）
func gkPendingCount(user string) int {
	gkMu.Lock()
	defer gkMu.Unlock()
	now := time.Now()
	n := 0
	for k, p := range gkPendings {
		if now.After(p.ExpiresAt) {
			delete(gkPendings, k)
			continue
		}
		if p.User == user {
			n++
		}
	}
	return n
}

// gkIssueConfirm 签发确认令牌
func gkIssueConfirm(user, tool, argsHash string) (string, time.Time, error) {
	gkMu.Lock()
	defer gkMu.Unlock()
	now := time.Now()
	for k, p := range gkPendings { // 清扫过期
		if now.After(p.ExpiresAt) {
			delete(gkPendings, k)
		}
	}
	tok := gkNewToken()
	exp := now.Add(gkConfirmTTL)
	gkPendings[tok] = gkPending{User: user, Tool: tool, ArgsHash: argsHash, ExpiresAt: exp}
	return tok, exp, nil
}

// gkConsumeConfirm 消费确认令牌（单次；校验 user/tool/argsHash 绑定）
func gkConsumeConfirm(token, user, tool, argsHash string) error {
	gkMu.Lock()
	defer gkMu.Unlock()
	p, ok := gkPendings[token]
	if !ok {
		return fmt.Errorf("确认令牌无效或已使用")
	}
	delete(gkPendings, token)
	if time.Now().After(p.ExpiresAt) {
		return fmt.Errorf("确认令牌已过期（有效期 %s），请重新发起", gkConfirmTTL)
	}
	if p.User != user || p.Tool != tool || p.ArgsHash != argsHash {
		return fmt.Errorf("确认令牌与本次调用不匹配（令牌绑定 用户/工具/参数，不可跨用）")
	}
	return nil
}

// ===================== 执行包装（接入点）=====================

// gkConfirmationRequired 错误：需要二次确认（HTTP 层据此返回结构化确认要求）
type gkConfirmationRequired struct {
	Tool        string
	Reason      string
	Token       string
	ExpiresAt   time.Time
}

func (e *gkConfirmationRequired) Error() string {
	return fmt.Sprintf("守门人要求确认: %s", e.Reason)
}

// executeToolAs 守门人包装的工具执行入口（身份感知）。
// 身份经保留参数键注入 args（_tsgIdentity），供共享记忆等租户隔离工具读取；
// 注入前先剥离调用方自带的同名字段（防伪造——包装层覆盖优先）。
func executeToolAs(id Identity, name string, args map[string]interface{}) (interface{}, error) {
	if args == nil {
		args = map[string]interface{}{}
	}
	delete(args, "_tsgIdentity") // 防伪造：先剥离调用方注入
	args["_tsgIdentity"] = id
	defer delete(args, "_tsgIdentity")

	enabled := gatekeeperEnabled()
	v, why := gkDecide(name, args)
	if v == gkDeny {
		auditLogT("GATEKEEPER_DENY", id.Tenant, "", id.Name, fmt.Sprintf("tool=%s %s", name, why))
		if enabled {
			return nil, fmt.Errorf("守门人拒绝: %s", why)
		}
		// observe 模式：审计已落，继续执行（试运行期观察）
	}
	if v == gkConfirm && enabled {
		// 已携带有效确认令牌 → 放行本次（哈希口径见 gkBoundArgsHash）
		argsHash := gkBoundArgsHash(name, args)
		if tok, _ := args["confirm_token"].(string); tok != "" {
			if err := gkConsumeConfirm(tok, id.Name, name, argsHash); err != nil {
				auditLogT("GATEKEEPER_DENY", id.Tenant, "", id.Name, fmt.Sprintf("tool=%s confirm 消费失败: %v", name, err))
				return nil, fmt.Errorf("守门人: %v", err)
			}
			auditLogT("GATEKEEPER_CONFIRMED", id.Tenant, "", id.Name, fmt.Sprintf("tool=%s 二次确认通过", name))
			return executeTool(name, args)
		}
		// 签发确认令牌
		if gkRateExceeded(id.Name) {
			auditLogT("GATEKEEPER_DENY", id.Tenant, "", id.Name, fmt.Sprintf("tool=%s confirm 频率超限（%d/min）", name, gkMaxConfirmPerMin))
			return nil, fmt.Errorf("守门人: 确认请求频率超限，请稍后再试")
		}
		if gkPendingCount(id.Name) >= gkMaxPending {
			auditLogT("GATEKEEPER_DENY", id.Tenant, "", id.Name, fmt.Sprintf("tool=%s pending 确认超上限 %d", name, gkMaxPending))
			return nil, fmt.Errorf("守门人: 待确认请求过多（上限 %d），请先完成或等待过期", gkMaxPending)
		}
		tok, exp, _ := gkIssueConfirm(id.Name, name, argsHash)
		auditLogT("GATEKEEPER_CONFIRM_REQUIRED", id.Tenant, "", id.Name, fmt.Sprintf("tool=%s %s", name, why))
		return nil, &gkConfirmationRequired{Tool: name, Reason: why, Token: tok, ExpiresAt: exp}
	}
	if v == gkConfirm && !enabled {
		auditLogT("GATEKEEPER_CONFIRM_REQUIRED", id.Tenant, "", id.Name, fmt.Sprintf("tool=%s %s（observe 模式，已放行）", name, why))
	}
	return executeTool(name, args)
}

// gkWriteConfirmation HTTP 响应：结构化确认要求（两种调用格式共用）
func gkWriteConfirmation(w http.ResponseWriter, req *gkConfirmationRequired, wrapper func(map[string]interface{})) {
	body := map[string]interface{}{
		"confirmation_required": true,
		"tool":                  req.Tool,
		"reason":                req.Reason,
		"confirm_token":         req.Token,
		"expires_in_seconds":    int(time.Until(req.ExpiresAt).Seconds()),
		"hint":                  "请在 60 秒内携带 confirm_token 重发同一请求以完成确认",
	}
	if wrapper != nil {
		wrapper(body)
		return
	}
	writeJSONStatus(w, http.StatusForbidden, body)
}

// identityFromArgs 工具 handler 内读取注入的身份（无身份 = 匿名只读视角）
func identityFromArgs(args map[string]interface{}) (Identity, bool) {
	if args == nil {
		return Identity{}, false
	}
	if id, ok := args["_tsgIdentity"].(Identity); ok {
		return id, true
	}
	return Identity{}, false
}

// handleGatekeeperStatus GET /api/admin/v322/status 的守门人段
func gatekeeperStatusView() map[string]interface{} {
	gkMu.Lock()
	pending := len(gkPendings)
	gkMu.Unlock()
	return map[string]interface{}{
		"enabled": gatekeeperEnabled(), "mode": map[bool]string{true: "enforce", false: "observe"}[gatekeeperEnabled()],
		"pendingConfirms": pending, "configRuleCount": len(gatekeeperRules()),
		"builtinRules": []string{
			"deny: tars_config_set → security./oauth./tenants./gatekeeper./audit.*",
			"deny: tars_file_write → 敏感凭据路径（.ssh/id_rsa/.env/credentials/…）",
			"confirm: tars_config_set（其余）",
			"confirm: tars_model_start / tars_model_stop / tars_model_download",
			"confirm: tars_file_write > 1MB",
		},
	}
}


// handleV322Status GET /api/admin/v322/status —— v3.2.2 治理层总览
// （admin.read：共享记忆/信息规模 + 守门人 + OAuth + 审计 v2 状态，不泄密）
func handleV322Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	sharedMemMu.Lock()
	smNS, smKeys := len(sharedMem), 0
	for _, m := range sharedMem {
		smKeys += len(m)
	}
	sharedMemMu.Unlock()
	sharedInfoMu.Lock()
	siCount := len(sharedInfo)
	sharedInfoMu.Unlock()
	ctxPackMu.Lock()
	cpCount := len(ctxPacks)
	ctxPackMu.Unlock()
	oauthMu.Lock()
	sessions := len(oauthSessions)
	oauthMu.Unlock()
	maxPerNS, maxValue, maxTotal := smLimits()
	writeJSON(w, map[string]interface{}{
		"version": "3.2.2",
		"sharedMemory": map[string]interface{}{
			"namespaces": smNS, "keys": smKeys,
			"limits": map[string]int{"maxKeysPerNamespace": maxPerNS, "maxValueBytes": maxValue, "maxTotalKeys": maxTotal},
		},
		"sharedInfo":    map[string]interface{}{"records": siCount, "limit": siMaxRecords},
		"contextPacks":  cpCount,
		"gatekeeper":    gatekeeperStatusView(),
		"oauth":         map[string]interface{}{"enabled": oauthConfig().Enabled, "ready": oauthReady(), "activeSessions": sessions},
		"auditV2":       map[string]interface{}{"format": "JSONL+hashchain", "retentionDays": cfgAuditRetention(), "availableDates": auditV2ListDates()},
	})
}

// cfgAuditRetention 审计保留天数快照
func cfgAuditRetention() int {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.Audit.RetentionDays
}
