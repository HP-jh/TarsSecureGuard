package main

// v3.0.4 多租户模型与 RBAC 扩展（锦衣卫裁定 TSG-ZT-2026-0929 第二/三/四节）。
//
// 红线落实：
//   [MT_AUDIT_ISOLATION]   审计日志按 tenant_id 行级过滤；查询必带租户；跨租户查询
//                           产生 AUDIT_CROSS_TENANT_ACCESS 事件
//   [MT_RL_ISOLATION]      限流令牌桶按 (tenant_id, endpoint, key_type) 三维隔离
//   [MT_QUOTA_HARD]        配额按租户硬隔离，超配 429；全局上限 = 各租户之和的硬上限
//   [MT_META_ISOLATION]    资源/角色绑定按租户命名空间；跨租户绑定拒绝（RBAC_TENANT_MISMATCH）
//   [MT_ADMIN_SCOPE]       admin 仅本租户；global_admin / global_auditor 独立角色标识
//   [RBAC_TEAM_LEAD]       team_lead 权限天花板由代码层矩阵硬约束，禁止自授权
//   [RBAC_AUDITOR_RO]      auditor 写请求在 handler 入口层（gatewayMiddleware）硬拒
//   [RBAC_NO_INHERIT]      角色零自动继承：矩阵逐格显式授予
//   [CFG_TEAM_SCHEMA]      team 配置 schema 校验（代码层），安全项全局优先不可覆盖
//   [CFG_RULES_ABCD]       冲突解决 A/B/C/D 规则代码层硬编码，禁止合并语义
//   [CFG_ATOMIC_SWAP]      校验通过 → 审计 → 原子替换；失败保持上一版本生效

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ===================== 配置结构 =====================

// TenantsCfg v3.0.4 多租户配置段（config.json 顶层键 tenants）
type TenantsCfg struct {
	GlobalTokenCapPerDay int         `json:"globalTokenCapPerDay"` // 全局 token 硬上限（各租户配额之和不得超过）
	Tenants              []TenantCfg `json:"list"`
}

// TenantCfg 单租户定义（schema 白名单字段集——本结构即 team 配置 schema 的代码层实现，
// 租户段只允许运营项字段；试图添加安全项字段会在未知键校验时被拒，[CFG_TEAM_SCHEMA]）
type TenantCfg struct {
	ID                 string           `json:"id"`
	Name               string           `json:"name"`
	Enabled            *bool            `json:"enabled"` // 默认 true
	Quota              TenantQuota      `json:"quota"`
	Router             TenantRouter     `json:"router"`
	RateLimit          TenantRateLimit  `json:"rateLimit"`
	Groups             []GroupCfg       `json:"groups"`
	AuditRetentionDays int              `json:"auditRetentionDays"` // 运营项：租户审计保留期（天，0=随全局）
}

// TenantQuota 租户配额（tokens 估算口径：字符数/4）
type TenantQuota struct {
	TokensPerDay         int `json:"tokensPerDay"`         // 租户日配额（0=不限）
	TokensPerUserPerDay  int `json:"tokensPerUserPerDay"`  // 单用户日配额
	TokensPerGroupPerDay int `json:"tokensPerGroupPerDay"` // 单组日配额
}

// TenantRouter 模型路由偏好（在全局候选集内的子集，运营项）
type TenantRouter struct {
	PreferredBackends []string `json:"preferredBackends"`
}

// TenantRateLimit 租户级限流阈值（运营项；只允许比全局更严，放宽即校验拒绝）
type TenantRateLimit struct {
	ChatPerMin  int `json:"chatPerMin"`
	AdminPerMin int `json:"adminPerMin"`
	ModelPerMin int `json:"modelPerMin"`
}

// GroupCfg 组定义（user/group/role 三层的 group 层）
type GroupCfg struct {
	ID     string       `json:"id"`
	Name   string       `json:"name"`
	Quota  *TenantQuota `json:"quota,omitempty"`  // 组级配额（Rule C：须 ≤ 租户配额）
	Router *TenantRouter `json:"router,omitempty"` // 组级路由偏好（取值范围同租户）
}

// 合法角色枚举（[RBAC_NO_INHERIT]：每个角色逐格显式授权，零继承）
var tenantRoles = map[string]bool{
	"admin": true, "user": true, "readonly": true, // v3.0.0 既有三角色按租户复用（裁定五-5）
	"team_lead": true, "auditor": true,            // v3.0.4 新增
	"global_admin": true, "global_auditor": true,  // 全局独立角色标识（裁定二-5）
}

// ===================== 身份解析 =====================

// Identity 请求身份（含租户上下文）
type Identity struct {
	Name    string
	Role    string
	Tenant  string   // 租户 ID；全局角色为 "*"
	Groups  []string // 所属组（组级配额/审计视图用）
	Global  bool     // global_admin / global_auditor
	IsUsers bool     // 是否来自 cfg.Users 多用户模式（false=单管理员回退）
}

const tenantDefault = "default"

// identityFromRequest 从请求解析身份（多用户优先，回退单管理员=global_admin，租户 "*"）
// v3.2.2：Bearer tsg_s_* 优先走 OAuth 会话（oauth.go）；API Key 通道原样保留。
func identityFromRequest(r *http.Request) (Identity, bool) {
	key := extractAPIKey(r)
	if key == "" {
		return Identity{}, false
	}
	// v3.2.2 OAuth 会话令牌：与 API Key 同权进入 RBAC 矩阵
	if strings.HasPrefix(key, oauthSessionTokenPrefix) {
		if id, ok := oauthSessionIdentity(key); ok {
			return id, true
		}
		return Identity{}, false
	}
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	for _, u := range cfg.Users {
		if u.Enabled && constantTimeEq(key, u.APIKey) {
			id := Identity{Name: u.Name, Role: u.Role, Groups: append([]string(nil), u.Groups...), IsUsers: true}
			switch u.Role {
			case "global_admin", "global_auditor":
				id.Global = true
				id.Tenant = "*"
			default:
				id.Tenant = u.Tenant
				if id.Tenant == "" {
					id.Tenant = tenantDefault
				}
			}
			return id, true
		}
	}
	// 回退单管理员模式：等价 global_admin（裁定五-5 备案：单机部署无租户语义）
	want := gatewayAPIKey()
	// [ZT_DEFAULT_DENY] 默认密钥通道须显式 defaultKeyAllowed=true，否则默认密钥不再鉴权
	if want != "" && want == apiKeyDefault && !(cfg.Security.DefaultKeyAllowed != nil && *cfg.Security.DefaultKeyAllowed) {
		return Identity{}, false
	}
	if want != "" && constantTimeEq(key, want) {
		return Identity{Name: "admin", Role: "global_admin", Tenant: "*", Global: true}, true
	}
	return Identity{}, false
}

func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// userFromRequest 兼容包装（既有调用点保留三返回值签名）
func userFromRequestCompat(r *http.Request) (string, string, bool) {
	id, ok := identityFromRequest(r)
	return id.Name, id.Role, ok
}

// ===================== RBAC 权限矩阵 =====================

// routeClassMethod 路径+方法 → 权限矩阵的端点类（v3.2.5 P1-4：GET /api/admin/config 为 admin.read）
func routeClassMethod(path, method string) string {
	if path == "/api/admin/config" && method == http.MethodGet {
		return "admin.read"
	}
	return routeClass(path)
}

// routeClass 路径 → 权限矩阵的端点类
func routeClass(path string) string {
	switch {
	case path == "/api/admin/audit-logs":
		return "audit"
	case path == "/api/admin/tenants/status":
		return "tenant.status"
	case strings.HasPrefix(path, "/api/admin/models/start"),
		strings.HasPrefix(path, "/api/admin/models/stop"),
		strings.HasPrefix(path, "/api/admin/model/download"),
		path == "/api/admin/config",
		path == "/api/admin/modules",
		path == "/api/admin/sidecar/reload",
		path == "/api/admin/v32/auto-discovery/scan",
		path == "/api/admin/v32/providers/probe":
		return "admin.write"
	case strings.HasPrefix(path, "/api/admin"):
		return "admin.read"
	case strings.HasPrefix(path, "/api/chat"), strings.HasPrefix(path, "/api/urgent"),
		strings.HasPrefix(path, "/api/agents"), strings.HasPrefix(path, "/api/feishu"),
		strings.HasPrefix(path, "/v1"):
		return "chat"
	case strings.HasPrefix(path, "/api/tools"), strings.HasPrefix(path, "/api/search"):
		return "tools"
	case strings.HasPrefix(path, "/api/ext"):
		return "ext"
	case strings.HasPrefix(path, "/mcp"):
		return "mcp"
	default:
		return "app"
	}
}

// 写方法判定（auditor 只读铁律与 readonly 写拒共用）
func isWriteMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodOptions && m != http.MethodHead
}

// rbacMatrix 角色 × 端点类 allow/deny 矩阵（代码层硬编码 = 权限天花板，[RBAC_TEAM_LEAD]）
// 值：""=允许；非空=拒绝原因（记入审计）
var rbacMatrix = map[string]map[string]string{
	"global_admin":   {"app": "", "chat": "", "tools": "", "ext": "", "mcp": "", "admin.read": "", "admin.write": "", "audit": "", "tenant.status": ""},
	"global_auditor": {"app": "", "chat": "global_auditor 仅只读审计", "tools": "global_auditor 仅只读审计", "ext": "global_auditor 仅只读审计", "mcp": "global_auditor 仅只读审计", "admin.read": "", "admin.write": "auditor 铁律：禁止任何写接口", "audit": "", "tenant.status": ""},
	"admin":          {"app": "", "chat": "", "tools": "", "ext": "", "mcp": "", "admin.read": "", "admin.write": "admin.write 属全局安全项，须 global_admin（本租户运营项经 config.json tenants 段变更）", "audit": "", "tenant.status": ""},
	"team_lead":      {"app": "", "chat": "", "tools": "", "ext": "team_lead 禁止调用 MCP 管理类工具 / sidecar 代理", "mcp": "team_lead 禁止调用 MCP 工具（含管理类）", "admin.read": "", "admin.write": "team_lead 无任何写权限（防自授权）", "audit": "", "tenant.status": ""},
	"auditor":        {"app": "", "chat": "auditor 仅只读审计", "tools": "auditor 仅只读审计", "ext": "auditor 仅只读审计", "mcp": "auditor 仅只读审计", "admin.read": "", "admin.write": "auditor 铁律：禁止任何写接口", "audit": "", "tenant.status": ""},
	"user":           {"app": "", "chat": "", "tools": "", "ext": "", "mcp": "", "admin.read": "admin 端点仅 admin/审计角色可读", "admin.write": "admin 端点仅 admin 可写", "audit": "审计日志仅 admin/team_lead/auditor 可读", "tenant.status": "租户状态仅管理角色可读"},
	"readonly":       {"app": "", "chat": "", "tools": "", "ext": "", "mcp": "", "admin.read": "", "admin.write": "admin 端点仅 admin 可写", "audit": "审计日志仅 admin/team_lead/auditor 可读", "tenant.status": "租户状态仅管理角色可读"},
}

// rbacCheck 入口层权限判定（gatewayMiddleware 调用；返回 ok=false 时带拒绝原因）
func rbacCheck(id Identity, method, path string) (bool, string) {
	cls := routeClassMethod(path, method)
	row, ok := rbacMatrix[id.Role]
	if !ok {
		return false, "未知角色 " + id.Role
	}
	if reason := row[cls]; reason != "" {
		return false, reason
	}
	// 写方法二次判定（auditor 铁律在 handler 入口层硬拒，[RBAC_AUDITOR_RO]）。
	// 管理面端点类（admin.read/admin.write/audit/tenant.status）：auditor/team_lead/readonly
	// 一律写拒；业务面端点类（chat/tools/ext/mcp/app）：POST 为协议常规用法，由矩阵逐格
	// 控制读写语义，不做方法级一刀切（否则 team_lead/readonly 的 chat POST 会被误杀），
	// 仅 readonly 维持 v3.0.0 全局写拒语义。
	if isWriteMethod(method) {
		switch cls {
		case "admin.read", "admin.write", "audit", "tenant.status":
			switch id.Role {
			case "global_auditor", "auditor":
				return false, "auditor 铁律：禁止任何写请求（handler 入口层拦截）"
			case "team_lead":
				return false, "team_lead 无管理面写权限（权限天花板，防自授权）"
			case "readonly":
				return false, "readonly 用户禁止写操作"
			}
		default:
			if id.Role == "readonly" {
				return false, "readonly 用户禁止写操作"
			}
		}
	}
	return true, ""
}

// ===================== 租户配置校验（[CFG_TEAM_SCHEMA] / [CFG_RULES_ABCD]） =====================

var tenantIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// 全局已知后端候选（租户路由偏好必须落在全局候选集内，Rule C）
func knownBackends() map[string]bool {
	set := map[string]bool{"llama": true, "lmstudio": true, "ollama": true}
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Cloud.OpenAI.APIKey != "" || len(cfg.Cloud.OpenAI.Models) > 0 {
		set["openai"] = true
	}
	if cfg.Cloud.DeepSeek.APIKey != "" || len(cfg.Cloud.DeepSeek.Models) > 0 {
		set["deepseek"] = true
	}
	for _, c := range cfg.Cloud.Custom {
		if c.Name != "" {
			set[strings.ToLower(c.Name)] = true
		}
	}
	return set
}

// validateTenantsCfg 校验租户配置（schema + 值域 + Rule C 范围检查）。
// 返回错误列表（空=通过）。安全项全局优先由 schema 字段白名单实现：
// TenantCfg 只含运营项字段，租户试图覆盖安全项在「未知/多余字段」检测中拒绝。
func validateTenantsCfg(tc TenantsCfg) []string {
	var errs []string
	seen := map[string]bool{}
	sumQuota := 0
	for i := range tc.Tenants {
		t := &tc.Tenants[i]
		if !tenantIDRe.MatchString(t.ID) {
			errs = append(errs, fmt.Sprintf("tenants.list[%d].id=%q 非法（小写字母/数字/-/_，≤64 字符）", i, t.ID))
		}
		if seen[t.ID] {
			errs = append(errs, fmt.Sprintf("租户 ID 重复：%s", t.ID))
		}
		seen[t.ID] = true
		if t.Quota.TokensPerDay < 0 || t.Quota.TokensPerUserPerDay < 0 || t.Quota.TokensPerGroupPerDay < 0 {
			errs = append(errs, fmt.Sprintf("租户 %s 配额含负值", t.ID))
		}
		// Rule C：用户/组级配额不得超过租户级配额
		if t.Quota.TokensPerDay > 0 {
			if t.Quota.TokensPerUserPerDay > t.Quota.TokensPerDay {
				errs = append(errs, fmt.Sprintf("租户 %s：tokensPerUserPerDay(%d) 超过 tokensPerDay(%d)（Rule C 越界）", t.ID, t.Quota.TokensPerUserPerDay, t.Quota.TokensPerDay))
			}
			if t.Quota.TokensPerGroupPerDay > t.Quota.TokensPerDay {
				errs = append(errs, fmt.Sprintf("租户 %s：tokensPerGroupPerDay(%d) 超过 tokensPerDay(%d)（Rule C 越界）", t.ID, t.Quota.TokensPerGroupPerDay, t.Quota.TokensPerDay))
			}
		}
		// 路由偏好必须在全局候选集内
		backends := knownBackends()
		for _, b := range t.Router.PreferredBackends {
			if !backends[strings.ToLower(b)] {
				errs = append(errs, fmt.Sprintf("租户 %s：路由偏好后端 %q 不在全局候选集内（Rule C）", t.ID, b))
			}
		}
		// 限流阈值只允许比全局更严（放宽拒绝，TEAM_CONFIG_SCHEMA_FAIL）；
		// 比较基准 = 全局生效值（显式配置值，未配置时按默认 chat60/admin10/model6）
		g := v3Config()
		gec := func(v, def int) int {
			if v > 0 {
				return v
			}
			return def
		}
		gChat, gAdmin, gModel := gec(g.RateLimit.ChatPerMin, 60), gec(g.RateLimit.AdminPerMin, 10), gec(g.RateLimit.ModelPerMin, 6)
		if t.RateLimit.ChatPerMin > 0 && t.RateLimit.ChatPerMin > gChat {
			errs = append(errs, fmt.Sprintf("租户 %s：chatPerMin(%d) 超过全局阈值(%d)（只允许收紧）", t.ID, t.RateLimit.ChatPerMin, gChat))
		}
		if t.RateLimit.AdminPerMin > 0 && t.RateLimit.AdminPerMin > gAdmin {
			errs = append(errs, fmt.Sprintf("租户 %s：adminPerMin(%d) 超过全局阈值(%d)（只允许收紧）", t.ID, t.RateLimit.AdminPerMin, gAdmin))
		}
		if t.RateLimit.ModelPerMin > 0 && t.RateLimit.ModelPerMin > gModel {
			errs = append(errs, fmt.Sprintf("租户 %s：modelPerMin(%d) 超过全局阈值(%d)（只允许收紧）", t.ID, t.RateLimit.ModelPerMin, gModel))
		}
		// 组校验
		gseen := map[string]bool{}
		for j := range t.Groups {
			gc := &t.Groups[j]
			if !tenantIDRe.MatchString(gc.ID) {
				errs = append(errs, fmt.Sprintf("租户 %s 组[%d].id=%q 非法", t.ID, j, gc.ID))
			}
			if gseen[gc.ID] {
				errs = append(errs, fmt.Sprintf("租户 %s 组 ID 重复：%s", t.ID, gc.ID))
			}
			gseen[gc.ID] = true
			if gc.Quota != nil && t.Quota.TokensPerDay > 0 && gc.Quota.TokensPerDay > t.Quota.TokensPerDay {
				errs = append(errs, fmt.Sprintf("租户 %s 组 %s：组配额(%d) 超过租户配额(%d)（Rule C 越界）", t.ID, gc.ID, gc.Quota.TokensPerDay, t.Quota.TokensPerDay))
			}
			if gc.Router != nil {
				backends := knownBackends()
				for _, b := range gc.Router.PreferredBackends {
					if !backends[strings.ToLower(b)] {
						errs = append(errs, fmt.Sprintf("租户 %s 组 %s：路由偏好后端 %q 不在全局候选集内", t.ID, gc.ID, b))
					}
				}
			}
		}
		if t.Quota.TokensPerDay > 0 {
			sumQuota += t.Quota.TokensPerDay
		}
	}
	// [MT_QUOTA_HARD]：全局配额上限为各租户配额之和的硬上限
	if tc.GlobalTokenCapPerDay > 0 && sumQuota > tc.GlobalTokenCapPerDay {
		errs = append(errs, fmt.Sprintf("各租户配额之和(%d) 超过全局硬上限 globalTokenCapPerDay(%d)（[MT_QUOTA_HARD]）", sumQuota, tc.GlobalTokenCapPerDay))
	}
	return errs
}

// validateUsersTenancy 用户条目校验：角色合法、API Key 不复用（防角色混淆）、
// 用户租户与租户定义一致（跨租户绑定拒绝，[MT_META_ISOLATION] / RBAC_TENANT_MISMATCH）
func validateUsersTenancy(users []User, tc TenantsCfg) []string {
	var errs []string
	tenantIDs := map[string]bool{}
	for i := range tc.Tenants {
		tenantIDs[tc.Tenants[i].ID] = true
	}
	names := map[string]bool{}
	keys := map[string]string{}
	for i, u := range users {
		if !tenantRoles[u.Role] {
			errs = append(errs, fmt.Sprintf("users[%d].%s 角色 %q 非法（枚举：admin/user/readonly/team_lead/auditor/global_admin/global_auditor）", i, u.Name, u.Role))
		}
		if names[u.Name] {
			errs = append(errs, fmt.Sprintf("用户名重复：%s", u.Name))
		}
		names[u.Name] = true
		if prev, dup := keys[u.APIKey]; dup {
			errs = append(errs, fmt.Sprintf("API Key 复用：用户 %s 与 %s 使用同一密钥（角色混淆攻击面，拒绝加载）", prev, u.Name))
		}
		keys[u.APIKey] = u.Name
		// 租户归属校验（tenant 缺省 = default）
		t := u.Tenant
		if t == "" {
			t = tenantDefault
		}
		switch u.Role {
		case "global_admin", "global_auditor":
			// 全局角色不挂租户
		default:
			if len(tc.Tenants) > 0 && !tenantIDs[t] {
				errs = append(errs, fmt.Sprintf("用户 %s 声明租户 %q 不存在于 tenants.list（RBAC_TENANT_MISMATCH）", u.Name, t))
			}
			// 组归属校验
			tenant := tenantByID(tc, t)
			if tenant != nil && len(u.Groups) > 0 {
				gids := map[string]bool{}
				for _, g := range tenant.Groups {
					gids[g.ID] = true
				}
				for _, g := range u.Groups {
					if !gids[g] {
						errs = append(errs, fmt.Sprintf("用户 %s 声明组 %q 不存在于租户 %s", u.Name, g, t))
					}
				}
			}
		}
	}
	// 互斥角色（裁定三 3.3）：global_admin 与 auditor 建议互斥——单角色字段下
	// 同一用户不可能同时持有两种角色；同名双条目已在上面的重名校验拒绝。
	return errs
}

func tenantByID(tc TenantsCfg, id string) *TenantCfg {
	for i := range tc.Tenants {
		if tc.Tenants[i].ID == id {
			return &tc.Tenants[i]
		}
	}
	return nil
}

// ===================== 租户配置运行态（原子替换） =====================

var (
	tenantsMu sync.RWMutex
	tenantsRT TenantsCfg // 当前生效的租户配置快照
)

func tenantsConfig() TenantsCfg {
	tenantsMu.RLock()
	defer tenantsMu.RUnlock()
	return tenantsRT
}

// applyTenantsConfig 校验 + 原子替换（[CFG_ATOMIC_SWAP]）。
// prevHash 为上一版本哈希（首次为空）。校验失败 → 保持上一版本生效并返回 false。
func applyTenantsConfig(tc TenantsCfg) bool {
	errs := validateTenantsCfg(tc)
	if len(errs) > 0 {
		for _, e := range errs {
			auditLog("TEAM_CONFIG_SCHEMA_FAIL", "system", e)
		}
		return false
	}
	prev := tenantsConfig()
	prevB, _ := json.Marshal(prev)
	curB, _ := json.Marshal(tc)
	tenantsMu.Lock()
	tenantsRT = tc
	tenantsMu.Unlock()
	auditLog("TEAM_CONFIG_APPLY", "system",
		fmt.Sprintf("租户配置生效：tenants=%d before_sha256=%.12s after_sha256=%.12s（校验通过，原子替换）",
			len(tc.Tenants), shortSHA(prevB), shortSHA(curB)))
	return true
}

func shortSHA(b []byte) string {
	s := sha256Hex(b)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// ===================== 级联规则（剩余问题 3 备案方案） =====================
//
// 全局收紧（globalTokenCapPerDay 下调）时，若既有租户配额之和超过新上限：
// 选择「自动级联收紧」而非拒绝全局变更——避免全局管理员被单租户配置锁死；
// 收紧动作逐租户审计 TEAM_CONFIG_CASCADE_CLAMP（含影响面清单），收紧后租户
// 可在旧 config.json 中看到实际生效值已被 clamp 回写。

func cascadeClampTenants() {
	tc := tenantsConfig()
	if tc.GlobalTokenCapPerDay <= 0 || len(tc.Tenants) == 0 {
		return
	}
	sum := 0
	for _, t := range tc.Tenants {
		if t.Quota.TokensPerDay > 0 {
			sum += t.Quota.TokensPerDay
		}
	}
	if sum <= tc.GlobalTokenCapPerDay {
		return
	}
	affected := []string{}
	for i := range tc.Tenants {
		if tc.Tenants[i].Quota.TokensPerDay > 0 {
			affected = append(affected, fmt.Sprintf("%s:%d", tc.Tenants[i].ID, tc.Tenants[i].Quota.TokensPerDay))
		}
	}
	// 等比收紧至总和不超上限（保留租户间相对比例）
	scale := float64(tc.GlobalTokenCapPerDay) / float64(sum)
	for i := range tc.Tenants {
		if tc.Tenants[i].Quota.TokensPerDay > 0 {
			tc.Tenants[i].Quota.TokensPerDay = int(float64(tc.Tenants[i].Quota.TokensPerDay) * scale)
		}
	}
	tenantsMu.Lock()
	tenantsRT = tc
	tenantsMu.Unlock()
	auditLog("TEAM_CONFIG_CASCADE_CLAMP", "system",
		fmt.Sprintf("全局配额上限收紧触发级联降级：受影响租户 %v 已等比收紧至 %d 以内（影响面已审计）",
			affected, tc.GlobalTokenCapPerDay))
}

// ===================== 配额引擎（[MT_QUOTA_HARD]） =====================

type quotaKey struct {
	Day    string
	Tenant string
	Scope  string // "tenant" | "user:<name>" | "group:<id>"
}

var (
	quotaMu      sync.Mutex
	quotaUsed    = map[quotaKey]int64{}
	quotaDirty   = false
)

func quotaStatePath() string {
	return filepath.Join(appDir(), "data", "quota-usage.json")
}

// estimateTokens token 估算口径（文档化：字符数/4，与主流分词近似）
func estimateTokens(text string) int64 {
	return int64(len([]rune(text)) / 4)
}

// quotaCheck 检查 (tenant, user, groups) 三层配额；返回 (ok, reason)
func quotaCheck(tenant, user string, groups []string) (bool, string) {
	tc := tenantsConfig()
	t := tenantByID(tc, tenant)
	if t == nil || t.Quota.TokensPerDay == 0 {
		return true, "" // 未配置租户或 0=不限（存量单机行为不变）
	}
	day := time.Now().Format("2006-01-02")
	quotaMu.Lock()
	defer quotaMu.Unlock()
	if t.Quota.TokensPerDay > 0 && quotaUsed[quotaKey{day, tenant, "tenant"}] >= int64(t.Quota.TokensPerDay) {
		return false, fmt.Sprintf("租户 %s 日配额已用尽（%d tokens/日）", tenant, t.Quota.TokensPerDay)
	}
	if t.Quota.TokensPerUserPerDay > 0 && user != "" &&
		quotaUsed[quotaKey{day, tenant, "user:" + user}] >= int64(t.Quota.TokensPerUserPerDay) {
		return false, fmt.Sprintf("用户 %s 日配额已用尽（%d tokens/日）", user, t.Quota.TokensPerUserPerDay)
	}
	if t.Quota.TokensPerGroupPerDay > 0 {
		for _, g := range groups {
			if quotaUsed[quotaKey{day, tenant, "group:" + g}] >= int64(t.Quota.TokensPerGroupPerDay) {
				return false, fmt.Sprintf("组 %s 日配额已用尽（%d tokens/日）", g, t.Quota.TokensPerGroupPerDay)
			}
		}
	}
	return true, ""
}

// quotaRecord 记录 token 消耗并持久化（异步落盘，小文件整体写）
func quotaRecord(tenant, user string, groups []string, tokens int64) {
	if tokens <= 0 {
		return
	}
	tc := tenantsConfig()
	t := tenantByID(tc, tenant)
	if t == nil || t.Quota.TokensPerDay == 0 {
		return
	}
	day := time.Now().Format("2006-01-02")
	quotaMu.Lock()
	quotaUsed[quotaKey{day, tenant, "tenant"}] += tokens
	if user != "" {
		quotaUsed[quotaKey{day, tenant, "user:" + user}] += tokens
	}
	for _, g := range groups {
		quotaUsed[quotaKey{day, tenant, "group:" + g}] += tokens
	}
	// 日切清理：仅保留当日
	for k := range quotaUsed {
		if k.Day != day {
			delete(quotaUsed, k)
		}
	}
	quotaMu.Unlock()
	quotaPersist()
}

func quotaPersist() {
	quotaMu.Lock()
	day := time.Now().Format("2006-01-02")
	out := map[string]int64{}
	for k, v := range quotaUsed {
		if k.Day == day {
			out[k.Tenant+"|"+k.Scope] = v
		}
	}
	quotaMu.Unlock()
	b, _ := json.Marshal(map[string]interface{}{"day": day, "usage": out})
	_ = os.MkdirAll(filepath.Dir(quotaStatePath()), 0700)
	_ = os.WriteFile(quotaStatePath(), b, 0600)
}

// quotaLoad 启动时恢复当日配额计数
func quotaLoad() {
	b, err := os.ReadFile(quotaStatePath())
	if err != nil {
		return
	}
	var m struct {
		Day   string           `json:"day"`
		Usage map[string]int64 `json:"usage"`
	}
	if json.Unmarshal(b, &m) != nil {
		return
	}
	if m.Day != time.Now().Format("2006-01-02") {
		return // 隔日作废
	}
	quotaMu.Lock()
	defer quotaMu.Unlock()
	for k, v := range m.Usage {
		parts := strings.SplitN(k, "|", 2)
		if len(parts) != 2 {
			continue
		}
		quotaUsed[quotaKey{Day: m.Day, Tenant: parts[0], Scope: parts[1]}] = v
	}
}

// ===================== 路由偏好过滤（裁定三 3.1：全局候选集内） =====================

// tenantPreferredBackends 租户/组路由偏好（组优先于租户，Rule A：无值取全局全集）
func tenantPreferredBackends(tenant string, groups []string) []string {
	tc := tenantsConfig()
	for _, g := range groups {
		t := tenantByID(tc, tenant)
		if t == nil {
			return nil
		}
		for _, gc := range t.Groups {
			if gc.ID == g && gc.Router != nil && len(gc.Router.PreferredBackends) > 0 {
				return gc.Router.PreferredBackends
			}
		}
	}
	if t := tenantByID(tc, tenant); t != nil && len(t.Router.PreferredBackends) > 0 {
		return t.Router.PreferredBackends
	}
	return nil
}

// filterCandidatesByPref 候选集 ∩ 偏好（偏好为空=不过滤）
func filterCandidatesByPref(cands, pref []string) []string {
	if len(pref) == 0 {
		return cands
	}
	set := map[string]bool{}
	for _, p := range pref {
		set[strings.ToLower(p)] = true
	}
	var out []string
	for _, c := range cands {
		if set[strings.ToLower(c)] {
			out = append(out, c)
		}
	}
	return out
}

// ===================== 审计租户过滤（[MT_AUDIT_ISOLATION]） =====================

// auditTenantScope 审计查询的租户过滤规则：
//   - global_admin / global_auditor：可查全部；显式指定非本租户 → AUDIT_CROSS_TENANT_ACCESS
//   - admin / auditor：强制本租户
//   - team_lead：强制本租户 + 限定本组（group 参数强制为本组之一）
func auditTenantScope(id Identity, qTenant, qGroup string) (tenant string, groups []string, crossTenant bool) {
	switch id.Role {
	case "global_admin", "global_auditor":
		if qTenant != "" && qTenant != "*" {
			return qTenant, nil, true
		}
		return "*", nil, false
	case "team_lead":
		return id.Tenant, id.Groups, false
	default: // admin / auditor
		return id.Tenant, nil, false
	}
}

// auditLineTenant 解析审计行的 TENANT= 字段（旧行无该字段 → "system"）
func auditLineTenant(line string) string {
	if i := strings.Index(line, "TENANT="); i >= 0 {
		rest := line[i+len("TENANT="):]
		if j := strings.IndexByte(rest, ' '); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return "system"
}

// auditLineGroup 解析审计行的 GROUP= 字段
func auditLineGroup(line string) string {
	if i := strings.Index(line, "GROUP="); i >= 0 {
		rest := line[i+len("GROUP="):]
		if j := strings.IndexByte(rest, ' '); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return ""
}

// filterAuditLines 按租户/组过滤审计行（行级强制过滤；空结果不泄露其他租户存在性）
//   - tenant=="*"：全量（仅全局角色可达此分支）
//   - groups 非空：行必须命中 GROUP= 集合之一（team_lead 按组视图）
//   - includeSystem：是否包含无租户字段的系统行（旧行/系统事件，仅全局角色可见）
func filterAuditLines(lines []string, tenant string, groups []string, includeSystem bool) []string {
	gset := map[string]bool{}
	for _, g := range groups {
		gset[g] = true
	}
	var out []string
	for _, l := range lines {
		t := auditLineTenant(l)
		if t == "system" {
			if includeSystem {
				out = append(out, l)
			}
			continue
		}
		if tenant != "*" && t != tenant {
			continue // 其他租户行一律不可见
		}
		if len(gset) > 0 {
			g := auditLineGroup(l)
			if !gset[g] { // 含空组行：team_lead 组外不可见
				continue
			}
		}
		out = append(out, l)
	}
	return out
}

// sha256Hex 便捷哈希
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return fmt.Sprintf("%x", s)
}

// auditLogT 租户感知审计（[MT_AUDIT_ISOLATION]：审计行携带 TENANT=/GROUP= 字段）
func auditLogT(action, tenant, group, user, detail string) {
	cfgMu.RLock()
	enabled := cfg.Security.AuditLogEnabled
	cfgMu.RUnlock()
	if !enabled {
		return
	}
	if tenant == "" {
		tenant = "-"
	}
	if group == "" {
		group = "-"
	}
	line := fmt.Sprintf("[%s] ACTION=%s USER=%s TENANT=%s GROUP=%s IP=%s DETAIL=%s",
		time.Now().Format("2006-01-02 15:04:05"), action, user, tenant, group, "-", detail)
	fileLog("audit", line)
	logMsg("[AUDIT] " + line)
	// v3.2.2 审计升级：同步落结构化 JSONL 哈希链条目（哈希链防篡改，见 auditv2.go）
	auditV2Write(action, tenant, group, user, "", detail, "")
}


// ===================== 租户状态视图 =====================

func tenantsStatusView(id Identity) map[string]interface{} {
	tc := tenantsConfig()
	type tview struct {
		ID        string      `json:"id"`
		Name      string      `json:"name"`
		Enabled   bool        `json:"enabled"`
		Quota     TenantQuota `json:"quota"`
		Router    []string    `json:"routerPreferredBackends"`
		Groups    int         `json:"groups"`
		UsedToday int64       `json:"usedToday"`
	}
	var list []tview
	day := time.Now().Format("2006-01-02")
	quotaMu.Lock()
	for i := range tc.Tenants {
		t := tc.Tenants[i]
		if !id.Global && t.ID != id.Tenant {
			continue // [MT_META_ISOLATION]：不跨租户枚举
		}
		enabled := t.Enabled == nil || *t.Enabled
		list = append(list, tview{
			ID: t.ID, Name: t.Name, Enabled: enabled, Quota: t.Quota,
			Router: t.Router.PreferredBackends, Groups: len(t.Groups),
			UsedToday: quotaUsed[quotaKey{day, t.ID, "tenant"}],
		})
	}
	quotaMu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return map[string]interface{}{
		"globalTokenCapPerDay": tc.GlobalTokenCapPerDay,
		"viewer":               map[string]string{"role": id.Role, "tenant": id.Tenant},
		"tenants":              list,
	}
}

// ===================== 组级审计视图数据 =====================

// groupAuditSummary 按组聚合当日审计计数（team_lead 的按组 audit 视图数据源）
func groupAuditSummary(tenant string, groups []string) map[string]int {
	tc := tenantsConfig()
	t := tenantByID(tc, tenant)
	if t == nil {
		return nil
	}
	summary := map[string]int{}
	if logFileDir == "" {
		return summary
	}
	path := filepath.Join(logFileDir, fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02")))
	data, err := os.ReadFile(path)
	if err != nil {
		return summary
	}
	gset := map[string]bool{}
	for _, g := range groups {
		gset[g] = true
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if auditLineTenant(line) != tenant {
			continue
		}
		g := auditLineGroup(line)
		if g == "" {
			continue
		}
		if len(gset) > 0 && !gset[g] {
			continue
		}
		summary[g]++
	}
	return summary
}


// applyTenantsFromLoad loadConfig 内调用：用户归属校验 + 租户配置原子应用 + 级联收紧。
// 失败语义（[CFG_ATOMIC_SWAP]）：保持上一版本生效——
//   - 用户表校验失败 → cfg.Users 回退到上一版本有效用户表（首启为空表，单管理员回退仍可用）
//   - 租户配置校验失败 → tenantsRT 保持上一版本，cfg.Tenants 同步为生效版本（不落盘非法值）
func applyTenantsFromLoad() {
	cfgMu.RLock()
	tc := cfg.Tenants
	users := append([]User(nil), cfg.Users...)
	cfgMu.RUnlock()
	if errs := validateUsersTenancy(users, tc); len(errs) > 0 {
		for _, e := range errs {
			auditLog("RBAC_TENANT_MISMATCH", "system", e)
		}
		cfgMu.Lock()
		cfg.Users = append([]User(nil), lastValidUsers...)
		cfgMu.Unlock()
		auditLog("RBAC_USERS_ROLLBACK", "system",
			fmt.Sprintf("用户表校验失败（%d 处），已回退上一版本有效用户表（%d 用户）", len(errs), len(lastValidUsers)))
	} else if len(users) > 0 {
		lastValidUsers = users
	}
	applyTenantsConfig(tc)
	cascadeClampTenants()
	// cfg.Tenants 同步为实际生效版本（含回退 / clamp），saveConfig 落盘生效值
	rt := tenantsConfig()
	cfgMu.Lock()
	cfg.Tenants = rt
	cfgMu.Unlock()
}

// lastValidUsers 上一版本通过校验的用户表（回退用）
var lastValidUsers []User


// ===================== v3.0.4 面板 Handler =====================

// handleTenantsStatus GET /api/admin/tenants/status
// 租户状态面板（矩阵类 tenant.status）：global_admin 看全部、admin/auditor/team_lead 仅本租户、
// user/readonly 无权（矩阵层已拒）。
func handleTenantsStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅 GET"})
		return
	}
	writeJSON(w, tenantsStatusView(id))
}

// handleWhitelistStatus GET /api/admin/whitelist/status
// 零信任白名单注册表（动态 kinds 完整性状态 + 静态清单），admin.read 类。
func handleWhitelistStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := identityFromRequest(r); !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅 GET"})
		return
	}
	writeJSON(w, wlRegistryView())
}

// handleAuditGroupSummary GET /api/admin/audit/group-summary[?tenant=x&group=y]
// 按组 audit 视图（task 交付项）：team_lead 自动限定本租户本组；global_admin 可指定
// tenant 查任意租户（跨租户查询记 AUDIT_CROSS_TENANT_ACCESS）。
func handleAuditGroupSummary(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅 GET"})
		return
	}
	qTenant := r.URL.Query().Get("tenant")
	qGroup := r.URL.Query().Get("group")
	tenant, groups, cross := auditTenantScope(id, qTenant, qGroup)
	if cross {
		auditLogT("AUDIT_CROSS_TENANT_ACCESS", tenant, qGroup, id.Name,
			fmt.Sprintf("global 角色跨租户查询组审计摘要 tenant=%s group=%s", tenant, qGroup))
	}
	if qGroup != "" {
		groups = []string{qGroup}
	}
	summary := groupAuditSummary(tenant, groups)
	if summary == nil {
		// 租户不存在或未配置（单管理员回退模式 = 无租户段）
		writeJSON(w, map[string]interface{}{"tenant": tenant, "groups": map[string]int{}, "note": "租户未配置（config.json tenants 段为空）"})
		return
	}
	writeJSON(w, map[string]interface{}{"tenant": tenant, "groups": summary, "generatedAt": time.Now().Format(time.RFC3339)})
}
