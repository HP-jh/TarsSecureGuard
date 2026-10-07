package main

// v3.0.4 单元测试：零信任白名单基线 + 多租户 RBAC（锦衣卫裁定 TSG-ZT-MT-2026-0929）
//
// 覆盖（裁定第三节：权限矩阵单测 100% 覆盖）：
//   - rbacMatrix 全角色 × 全端点类 × 读/写方法 交叉（7 角色 × 9 端点类 × 2 方法 = 126 格）
//   - team_lead 权限天花板（防自授权）/ auditor 只读铁律 / 角色零继承
//   - 租户配置校验（schema / Rule C 配额 / 路由偏好域 / 限流只许收紧 / 配额之和硬上限）
//   - 用户归属校验（角色枚举 / 租户与组存在性 / 重复拒绝）
//   - 配额引擎（租户/用户/组三层）与审计行过滤（租户隔离 / 组视图）
//   - 白名单值域校验（禁 CIDR/通配/相对路径）

import (
	"net/http"
	"net/http/httptest"
	"time"
	"strings"
	"testing"
)

// ===================== RBAC 权限矩阵 100% 覆盖 =====================

var allRoles = []string{"global_admin", "global_auditor", "admin", "team_lead", "auditor", "user", "readonly"}
var allClasses = []string{"app", "chat", "tools", "ext", "mcp", "admin.read", "admin.write", "audit", "tenant.status"}

// classPath 每个端点类取一条代表性路径（覆盖 routeClass 归类 + rbacCheck 判定）
var classPath = map[string]string{
	"app":           "/api/status",
	"chat":          "/api/chat/completions",
	"tools":         "/api/tools/hw.eval",
	"ext":           "/api/ext/demo/v1/ping",
	"mcp":           "/mcp",
	"admin.read":    "/api/admin/security/status",
	"admin.write":   "/api/admin/config",
	"audit":         "/api/admin/audit-logs",
	"tenant.status": "/api/admin/tenants/status",
}

func TestRouteClassMapping(t *testing.T) {
	for cls, p := range classPath {
		if got := routeClass(p); got != cls {
			t.Errorf("routeClass(%s) = %s, want %s", p, got, cls)
		}
	}
	// 前缀归类抽查
	if routeClass("/api/agents/code-assistant/run") != "chat" {
		t.Error("agents 路径应归 chat 类")
	}
	if routeClass("/v1/chat/completions") != "chat" {
		t.Error("/v1 应归 chat 类")
	}
	if routeClass("/api/feishu/send") != "chat" {
		t.Error("feishu 路径应归 chat 类")
	}
	if routeClass("/api/admin/models/start") != "admin.write" {
		t.Error("models/start 应归 admin.write 类")
	}
}

// TestRBACMatrixFullCoverage 裁定三-4：权限矩阵单测 100% 覆盖。
// 每格断言两件事：① rbacMatrix 中该格的 allow/deny 与 rbacCheck 实际判定一致；
// ② 关键铁律不被矩阵遗漏（auditor 写拒 / team_lead 管理写拒 / user 无管理面）。
func TestRBACMatrixFullCoverage(t *testing.T) {
	for _, role := range allRoles {
		row, ok := rbacMatrix[role]
		if !ok {
			t.Fatalf("角色 %s 不在矩阵中", role)
		}
		for _, cls := range allClasses {
			if _, ok := row[cls]; !ok {
				t.Errorf("角色 %s × 端点类 %s 矩阵格缺失（零继承：每格必须显式）", role, cls)
			}
			path := classPath[cls]
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				id := Identity{Name: "t-" + role, Role: role, Tenant: "t1", Groups: []string{"g1"}}
				if role == "global_admin" || role == "global_auditor" {
					id.Tenant, id.Global = "*", true
				}
				got, reason := rbacCheck(id, method, path)
				want := row[cls] == ""
				// 写方法二次判定：管理面类上 auditor/team_lead/readonly 铁拒；
				// 业务面类上 readonly 维持全局写拒
				if method == http.MethodPost {
					switch cls {
					case "admin.read", "admin.write", "audit", "tenant.status":
						switch role {
						case "global_auditor", "auditor", "team_lead", "readonly":
							want = false
						}
					default:
						if role == "readonly" {
							want = false
						}
					}
				}
				if got != want {
					t.Errorf("rbacCheck(%s %s %s) = %v (reason=%s), want %v", role, method, cls, got, reason, want)
				}
			}
		}
	}
}

// TestRBACTeamLeadCeiling team_lead 权限天花板：可带队（chat/tools/审计只读），
// 但管理面写一律拒（防自授权），admin.write 即使矩阵显式也不可能放行。
func TestRBACTeamLeadCeiling(t *testing.T) {
	id := Identity{Name: "lead", Role: "team_lead", Tenant: "t1", Groups: []string{"g1"}}
	if ok, _ := rbacCheck(id, http.MethodPost, "/api/chat/completions"); !ok {
		t.Error("team_lead 应可用 chat")
	}
	if ok, _ := rbacCheck(id, http.MethodPost, "/api/admin/config"); ok {
		t.Error("team_lead 禁止 admin.write（防自授权）")
	}
	if ok, _ := rbacCheck(id, http.MethodGet, "/api/admin/audit-logs"); !ok {
		t.Error("team_lead 应可读本组审计")
	}
	if ok, _ := rbacCheck(id, http.MethodPost, "/api/admin/audit-logs"); ok {
		t.Error("team_lead 管理面写一律拒")
	}
}

// TestRBACAuditorReadOnly auditor 只读铁律：任何写请求在入口层硬拒。
func TestRBACAuditorReadOnly(t *testing.T) {
	for _, role := range []string{"auditor", "global_auditor"} {
		id := Identity{Name: "a", Role: role, Tenant: "t1", Global: role == "global_auditor"}
		if ok, _ := rbacCheck(id, http.MethodPost, "/api/admin/config"); ok {
			t.Errorf("%s 禁止 admin.write", role)
		}
		if ok, _ := rbacCheck(id, http.MethodPost, "/api/admin/models/start"); ok {
			t.Errorf("%s 禁止模型管理写", role)
		}
		if ok, _ := rbacCheck(id, http.MethodGet, "/api/admin/audit-logs"); !ok {
			t.Errorf("%s 应可读审计", role)
		}
		if ok, _ := rbacCheck(id, http.MethodPost, "/api/chat/completions"); ok {
			t.Errorf("%s 业务面也应只读（矩阵 chat 格 deny）", role)
		}
	}
}

// TestRBACUnknownRole 未知角色零信任默认拒绝。
func TestRBACUnknownRole(t *testing.T) {
	id := Identity{Name: "x", Role: "superuser", Tenant: "t1"}
	if ok, _ := rbacCheck(id, http.MethodGet, "/api/status"); ok {
		t.Error("未知角色必须默认拒绝（零继承 + 默认 deny）")
	}
}

// TestRBACAdminTenantScoped admin 仅本租户运营；全局安全项写须 global_admin。
func TestRBACAdminTenantScoped(t *testing.T) {
	id := Identity{Name: "tadmin", Role: "admin", Tenant: "t1"}
	if ok, _ := rbacCheck(id, http.MethodPost, "/api/admin/config"); ok {
		t.Error("admin（租户级）不得触碰全局安全项写接口")
	}
	if ok, _ := rbacCheck(id, http.MethodGet, "/api/admin/tenants/status"); !ok {
		t.Error("admin 应可读本租户状态")
	}
	ga := Identity{Name: "root", Role: "global_admin", Tenant: "*", Global: true}
	if ok, _ := rbacCheck(ga, http.MethodPost, "/api/admin/config"); !ok {
		t.Error("global_admin 应可写全局配置")
	}
}

// ===================== 身份解析：默认密钥通道 =====================

func TestIdentityDefaultKeyGate(t *testing.T) {
	// 构造：单管理员回退 + 默认密钥 + 未显式 allow → 默认密钥不得鉴权
	cfgMu.Lock()
	savedKey, savedAllow, savedUsers := cfg.Security.APIKey, cfg.Security.DefaultKeyAllowed, cfg.Users
	cfg.Security.APIKey = apiKeyDefault
	cfg.Security.DefaultKeyAllowed = nil
	cfg.Users = nil
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg.Security.APIKey, cfg.Security.DefaultKeyAllowed, cfg.Users = savedKey, savedAllow, savedUsers
		cfgMu.Unlock()
	}()

	r, _ := http.NewRequest(http.MethodGet, "/api/status", nil)
	r.Header.Set("X-API-Key", apiKeyDefault)
	if _, ok := identityFromRequest(r); ok {
		t.Error("默认密钥未显式 defaultKeyAllowed=true 时必须拒绝（[ZT_DEFAULT_DENY]）")
	}
	// 显式 allow → 通过
	cfgMu.Lock()
	allow := true
	cfg.Security.DefaultKeyAllowed = &allow
	cfgMu.Unlock()
	r2, _ := http.NewRequest(http.MethodGet, "/api/status", nil)
	r2.Header.Set("X-API-Key", apiKeyDefault)
	id, ok := identityFromRequest(r2)
	if !ok || id.Role != "global_admin" || id.Tenant != "*" {
		t.Errorf("显式 allow 后默认密钥应可用并映射 global_admin，got ok=%v role=%s", ok, id.Role)
	}
	// 随机密钥仍可用（非默认通道不受影响）
	cfgMu.Lock()
	cfg.Security.APIKey = "sk-custom-304"
	cfg.Security.DefaultKeyAllowed = nil
	cfgMu.Unlock()
	r3, _ := http.NewRequest(http.MethodGet, "/api/status", nil)
	r3.Header.Set("X-API-Key", "sk-custom-304")
	if id, ok := identityFromRequest(r3); !ok || !id.Global {
		t.Error("自定义密钥应正常鉴权为 global_admin 回退")
	}
}

func TestIdentityConstantTimeEq(t *testing.T) {
	if !constantTimeEq("abc", "abc") || constantTimeEq("abc", "abd") || constantTimeEq("ab", "abc") {
		t.Error("constantTimeEq 行为错误")
	}
}

// ===================== 租户配置校验 =====================

func mkTenants() TenantsCfg {
	on := true
	return TenantsCfg{
		GlobalTokenCapPerDay: 1000000,
		Tenants: []TenantCfg{
			{
				ID: "team-a", Name: "团队A", Enabled: &on,
				Quota:  TenantQuota{TokensPerDay: 500000, TokensPerUserPerDay: 50000, TokensPerGroupPerDay: 200000},
				Router: TenantRouter{PreferredBackends: []string{"llama", "ollama"}},
				RateLimit: TenantRateLimit{ChatPerMin: 30},
				Groups: []GroupCfg{
					{ID: "g-core", Name: "核心组", Quota: &TenantQuota{TokensPerDay: 200000}, Router: &TenantRouter{PreferredBackends: []string{"ollama"}}},
				},
			},
		},
	}
}

func TestValidateTenantsCfgOK(t *testing.T) {
	if errs := validateTenantsCfg(mkTenants()); len(errs) > 0 {
		t.Errorf("合法租户配置不应报错: %v", errs)
	}
}

func TestValidateTenantsCfgBadID(t *testing.T) {
	tc := mkTenants()
	tc.Tenants[0].ID = "Bad_ID!"
	if errs := validateTenantsCfg(tc); len(errs) == 0 {
		t.Error("非法租户 ID（大写/特殊字符）应拒绝")
	}
}

func TestValidateTenantsCfgUnknownBackend(t *testing.T) {
	tc := mkTenants()
	tc.Tenants[0].Router.PreferredBackends = []string{"nonexistent-backend"}
	if errs := validateTenantsCfg(tc); len(errs) == 0 {
		t.Error("路由偏好必须在全局候选集（llama/lmstudio/ollama）内")
	}
}

func TestValidateTenantsCfgQuotaCap(t *testing.T) {
	tc := mkTenants()
	tc.Tenants[0].Quota.TokensPerDay = 2000000 // > GlobalTokenCapPerDay
	errs := validateTenantsCfg(tc)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, "; "), "globalTokenCapPerDay") {
		t.Errorf("单租户配额超全局硬上限应拒绝（Rule C / [MT_QUOTA_HARD]）: %v", errs)
	}
}

func TestValidateTenantsCfgSumCap(t *testing.T) {
	on := true
	tc := TenantsCfg{
		GlobalTokenCapPerDay: 100,
		Tenants: []TenantCfg{
			{ID: "a", Enabled: &on, Quota: TenantQuota{TokensPerDay: 80}},
			{ID: "b", Enabled: &on, Quota: TenantQuota{TokensPerDay: 80}},
		},
	}
	errs := validateTenantsCfg(tc)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, ";"), "之和") {
		t.Errorf("各租户配额之和超全局硬上限应拒绝: %v", errs)
	}
}

func TestValidateTenantsCfgRateLimitLoose(t *testing.T) {
	tc := mkTenants()
	tc.Tenants[0].RateLimit.ChatPerMin = 9999 // 放宽（全局默认 60）
	if errs := validateTenantsCfg(tc); len(errs) == 0 {
		t.Error("租户限流只许收紧，放宽应拒绝")
	}
}

func TestValidateUsersTenancy(t *testing.T) {
	on := true
	tc := mkTenants()
	// 合法用户表
	users := []User{
		{Name: "alice", APIKey: "k-alice", Role: "user", Tenant: "team-a", Groups: []string{"g-core"}, Enabled: true},
		{Name: "lead", APIKey: "k-lead", Role: "team_lead", Tenant: "team-a", Groups: []string{"g-core"}, Enabled: true},
	}
	if errs := validateUsersTenancy(users, tc); len(errs) > 0 {
		t.Errorf("合法用户表不应报错: %v", errs)
	}
	// 未知角色
	bad := append([]User(nil), users...)
	bad[0].Role = "superadmin"
	if errs := validateUsersTenancy(bad, tc); len(errs) == 0 {
		t.Error("未知角色应拒绝")
	}
	// 不存在的租户
	bad = append([]User(nil), users...)
	bad[0].Tenant = "ghost"
	if errs := validateUsersTenancy(bad, tc); len(errs) == 0 {
		t.Error("不存在的租户应拒绝")
	}
	// 不存在的组
	bad = append([]User(nil), users...)
	bad[0].Groups = []string{"nope"}
	if errs := validateUsersTenancy(bad, tc); len(errs) == 0 {
		t.Error("不存在的组应拒绝")
	}
	// 重复用户名
	bad = append([]User(nil), users...)
	bad = append(bad, User{Name: "alice", APIKey: "k2", Role: "user", Tenant: "team-a", Enabled: true})
	if errs := validateUsersTenancy(bad, tc); len(errs) == 0 {
		t.Error("重复用户名应拒绝")
	}
	_ = on
}

// ===================== 配额引擎 =====================

func TestQuotaEngine(t *testing.T) {
	// 安装运行时租户配置（绕开 cfg，直接驱动 tenantsRT）
	on := true
	tenantsMu.Lock()
	savedRT := tenantsRT
	tenantsRT = TenantsCfg{Tenants: []TenantCfg{{
		ID: "tq", Enabled: &on,
		Quota: TenantQuota{TokensPerDay: 10000, TokensPerUserPerDay: 5000, TokensPerGroupPerDay: 20000},
	}}}
	tenantsMu.Unlock()
	defer func() {
		tenantsMu.Lock()
		tenantsRT = savedRT
		tenantsMu.Unlock()
	}()
	day := timeNowDay()
	quotaMu.Lock()
	savedQuota := quotaUsed
	quotaUsed = map[quotaKey]int64{}
	quotaMu.Unlock()
	defer func() {
		quotaMu.Lock()
		quotaUsed = savedQuota
		quotaMu.Unlock()
	}()

	// 未超：放行
	if ok, _ := quotaCheck("tq", "u1", []string{"g1"}); !ok {
		t.Error("未超配额应放行")
	}
	// 记 9995 → 租户层 9995；用户层 9995；组层 9995
	quotaRecord("tq", "u1", []string{"g1"}, 9995)
	quotaMu.Lock()
	gotTenant, gotUser, gotGroup := quotaUsed[quotaKey{day, "tq", "tenant"}], quotaUsed[quotaKey{day, "tq", "user:u1"}], quotaUsed[quotaKey{day, "tq", "group:g1"}]
	quotaMu.Unlock()
	if gotTenant != 9995 || gotUser != 9995 || gotGroup != 9995 {
		t.Fatalf("quotaRecord 三层记账错误: tenant=%d user=%d group=%d", gotTenant, gotUser, gotGroup)
	}
	// 用户层已到 9995 ≥ 5000 → u1 拒
	if ok, why := quotaCheck("tq", "u1", []string{"g1"}); ok {
		t.Errorf("用户层超配额应拒绝本人（why=%s）", why)
	}
	// 再记 5 → 租户层 10000 满；其他用户也被租户层拦
	quotaRecord("tq", "u2", []string{"g1"}, 5)
	if ok, why := quotaCheck("tq", "u2", []string{"g1"}); ok {
		t.Errorf("租户层满配后应拒绝同租户用户（why=%s）", why)
	}
	// 组层：清空后单测组维度
	quotaMu.Lock()
	quotaUsed = map[quotaKey]int64{{day, "tq", "group:g1"}: 20000}
	quotaMu.Unlock()
	if ok, why := quotaCheck("tq", "u3", []string{"g1"}); ok {
		t.Errorf("组层超配额应拒绝组内用户（why=%s）", why)
	}
	// 未配置租户（0=不限）→ 放行（存量单机行为不变）
	if ok, _ := quotaCheck("unknown-tenant", "u", nil); !ok {
		t.Error("未配置租户应不限（存量行为不变）")
	}
}

// timeNowDay 测试辅助：与配额引擎相同的日键
func timeNowDay() string {
	return time.Now().Format("2006-01-02")
}

// ===================== 审计行过滤（租户隔离）=====================

func TestAuditLineParseAndFilter(t *testing.T) {
	lines := []string{
		"[2026-09-29 10:00:00] ACTION=CHAT USER=alice TENANT=team-a GROUP=g-core IP=127.0.0.1 DETAIL=x",
		"[2026-09-29 10:00:01] ACTION=CHAT USER=bob TENANT=team-b GROUP=g-x IP=127.0.0.1 DETAIL=x",
		"[2026-09-29 10:00:02] ACTION=BOOT USER=system IP=- DETAIL=旧格式行",
	}
	if auditLineTenant(lines[0]) != "team-a" || auditLineGroup(lines[0]) != "g-core" {
		t.Error("TENANT=/GROUP= 解析错误")
	}
	if auditLineTenant(lines[2]) != "system" {
		t.Error("旧行（无 TENANT 字段）应解析为 system")
	}
	// team-a 视角：只见本租户行
	out := filterAuditLines(lines, "team-a", nil, false)
	if len(out) != 1 || !strings.Contains(out[0], "alice") {
		t.Errorf("租户过滤应只保留本租户行，got %d 行", len(out))
	}
	// team_lead（组限定）：仅本组行
	out = filterAuditLines(lines, "team-a", []string{"g-core"}, false)
	if len(out) != 1 {
		t.Errorf("组过滤应保留本组行")
	}
	out = filterAuditLines(lines, "team-a", []string{"g-other"}, false)
	if len(out) != 0 {
		t.Errorf("组外行不可见")
	}
	// global 视角（tenant="*"）：全部可见（含旧行）
	out = filterAuditLines(lines, "*", nil, true)
	if len(out) != 3 {
		t.Errorf("global 角色应见全部行，got %d", len(out))
	}
	// 跨租户不可见性：team-b 视角看不到 team-a 行
	out = filterAuditLines(lines, "team-b", nil, false)
	if len(out) != 1 || !strings.Contains(out[0], "bob") {
		t.Error("team-b 视角只见 team-b 行")
	}
}

func TestAuditTenantScope(t *testing.T) {
	ga := Identity{Name: "root", Role: "global_admin", Tenant: "*", Global: true}
	if tn, _, cross := auditTenantScope(ga, "team-b", ""); tn != "team-b" || !cross {
		t.Error("global_admin 指定租户查询应返回该租户且 cross=true")
	}
	if tn, _, cross := auditTenantScope(ga, "", ""); tn != "*" || cross {
		t.Error("global_admin 不指定租户应看全部且 cross=false")
	}
	lead := Identity{Name: "l", Role: "team_lead", Tenant: "team-a", Groups: []string{"g-core"}}
	if tn, gs, _ := auditTenantScope(lead, "team-b", ""); tn != "team-a" || len(gs) != 1 {
		t.Error("team_lead 查询范围必须钉死本租户本组（参数不可越权）")
	}
	adm := Identity{Name: "a", Role: "admin", Tenant: "team-a"}
	if tn, _, _ := auditTenantScope(adm, "team-b", ""); tn != "team-a" {
		t.Error("admin 查询范围必须钉死本租户")
	}
}

// ===================== 路由偏好 =====================

func TestFilterCandidatesByPref(t *testing.T) {
	all := []string{"llama", "lmstudio", "ollama"}
	if got := filterCandidatesByPref(all, nil); len(got) != 3 {
		t.Error("Rule A：无偏好取全集")
	}
	if got := filterCandidatesByPref(all, []string{"ollama"}); len(got) != 1 || got[0] != "ollama" {
		t.Error("偏好过滤应保留偏好内候选")
	}
	if got := filterCandidatesByPref(all, []string{"nonexist"}); len(got) != 0 {
		t.Error("偏好全不在候选集内 → 空集（校验层已防，运行时兜底为空不探索）")
	}
}

// ===================== 白名单值域校验 =====================

func TestWLValidateIPList(t *testing.T) {
	if err := wlValidateIPList([]string{"192.168.1.10", "127.0.0.1"}); err != nil {
		t.Errorf("精确 IP 应合法: %v", err)
	}
	for _, bad := range []string{"192.168.0.0/16", "10.*.*.*", "0.0.0.0/0", "not-an-ip"} {
		if err := wlValidateIPList([]string{bad}); err == nil {
			t.Errorf("非法 IP 白名单项 %q 应拒绝（禁 CIDR/通配）", bad)
		}
	}
}

func TestWLValidateFileRoots(t *testing.T) {
	if err := wlValidateFileRoots([]string{"/home/user/Documents"}); err != nil {
		t.Errorf("绝对路径应合法: %v", err)
	}
	for _, bad := range []string{"relative/path", "/home/*/docs", "C:\\Users\\*"} {
		if err := wlValidateFileRoots([]string{bad}); err == nil {
			t.Errorf("非法文件根 %q 应拒绝（须绝对路径且无通配）", bad)
		}
	}
}


// ===================== gatewayMiddleware 全链路（多租户身份）=====================

// TestGatewayTenantChain 端到端验证 v3.0.4 中间件接线：
// 多用户身份 → RBAC 矩阵 → chat 配额前置检查 → 限流租户维度。
func TestGatewayTenantChain(t *testing.T) {
	resetIPRep()
	// 安装两租户三用户：auditor 禁业务面 / user 可 chat / team_lead 可 chat 禁管理写
	on := true
	cfgMu.Lock()
	savedUsers, savedAllow := cfg.Users, cfg.Security.DefaultKeyAllowed
	cfg.Users = []User{
		{Name: "aud1", APIKey: "k-aud1", Role: "auditor", Tenant: "team-a", Enabled: true},
		{Name: "usr1", APIKey: "k-usr1", Role: "user", Tenant: "team-a", Enabled: true},
		{Name: "lead1", APIKey: "k-lead1", Role: "team_lead", Tenant: "team-a", Groups: []string{"g-core"}, Enabled: true},
	}
	cfg.Security.DefaultKeyAllowed = nil
	cfgMu.Unlock()
	tenantsMu.Lock()
	savedRT := tenantsRT
	tenantsRT = TenantsCfg{Tenants: []TenantCfg{{
		ID: "team-a", Enabled: &on,
		Quota:  TenantQuota{TokensPerDay: 10000, TokensPerUserPerDay: 5000, TokensPerGroupPerDay: 20000},
		Groups: []GroupCfg{{ID: "g-core", Name: "核心"}},
	}}}
	tenantsMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg.Users, cfg.Security.DefaultKeyAllowed = savedUsers, savedAllow
		cfgMu.Unlock()
		tenantsMu.Lock()
		tenantsRT = savedRT
		tenantsMu.Unlock()
	}()

	boom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := gatewayMiddleware(boom)
	do := func(key, method, path string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "203.0.113.77:9999"
		req.Header.Set("X-API-Key", key)
		h.ServeHTTP(w, req)
		return w.Code
	}
	// auditor：chat 拒（403）、审计读放行（200）
	if c := do("k-aud1", "POST", "/api/chat/completions"); c != 403 {
		t.Errorf("auditor chat 应 403，实际 %d", c)
	}
	if c := do("k-aud1", "GET", "/api/admin/audit-logs"); c != 200 {
		t.Errorf("auditor 读审计应 200，实际 %d", c)
	}
	// user：chat 放行（200）、admin.read 拒（403）
	if c := do("k-usr1", "POST", "/api/chat/completions"); c != 200 {
		t.Errorf("user chat 应 200，实际 %d", c)
	}
	if c := do("k-usr1", "GET", "/api/admin/config"); c != 403 {
		t.Errorf("user 读 admin 端点应 403，实际 %d", c)
	}
	// team_lead：chat 放行、管理写拒
	if c := do("k-lead1", "POST", "/api/chat/completions"); c != 200 {
		t.Errorf("team_lead chat 应 200，实际 %d", c)
	}
	if c := do("k-lead1", "POST", "/api/admin/config"); c != 403 {
		t.Errorf("team_lead 管理写应 403，实际 %d", c)
	}
	// 默认密钥（未显式 allow）应 401
	if c := do(apiKeyDefault, "GET", "/api/status"); c != 401 {
		t.Errorf("默认密钥未显式 allow 应 401，实际 %d", c)
	}
}
