package main

// ===================== v3.2.2 治理层：共享记忆 / 共享信息 / 上下文拓展 /
// OAuth/IdP / 守门人 / 审计升级 =====================

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- 测试身份 ----

var (
	tu = Identity{Name: "u1", Role: "user", Tenant: "t1", IsUsers: true}
	tu2 = Identity{Name: "u2", Role: "user", Tenant: "t1", IsUsers: true}
	tx = Identity{Name: "u9", Role: "user", Tenant: "t9", IsUsers: true}
	tg = Identity{Name: "root", Role: "global_admin", Tenant: "*", Global: true}
)

func smReset() {
	sharedMemMu.Lock()
	sharedMem = map[string]map[string]SharedMemEntry{}
	sharedMemRev = 0
	sharedMemMu.Unlock()
	sharedInfoMu.Lock()
	sharedInfo = map[string]SharedInfoRecord{}
	sharedInfoRev = 0
	sharedInfoMu.Unlock()
	ctxPackMu.Lock()
	ctxPacks = map[string]contextPackStore{}
	ctxPackMu.Unlock()
}

// ===================== 共享记忆 =====================

func TestV322SharedMemoryChainResolution(t *testing.T) {
	smReset()
	// global 层（全局角色写）→ tenant 层覆盖 → user 层再覆盖
	if _, err := smSet(tg, "global", "lang", "en", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := smSet(tu, "tenant", "lang", "zh", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := smSet(tu, "user", "lang", "zh-CN", 0); err != nil {
		t.Fatal(err)
	}
	e, ns, ok := smGet(tu, "lang")
	if !ok || e.Value != "zh-CN" || ns != "user:t1/u1" {
		t.Fatalf("解析链就近覆盖失败: %v %v %v", e.Value, ns, ok)
	}
	// u2（同租户他人）：user 层不可见，落到 tenant 层
	e2, ns2, _ := smGet(tu2, "lang")
	if e2.Value != "zh" || ns2 != "tenant:t1" {
		t.Fatalf("同租户他人应见 tenant 层: %v %v", e2.Value, ns2)
	}
	// 其他租户：global 层
	e3, ns3, _ := smGet(tx, "lang")
	if e3.Value != "en" || ns3 != "global" {
		t.Fatalf("他租户应见 global 层: %v %v", e3.Value, ns3)
	}
}

func TestV322SharedMemoryTenantIsolation(t *testing.T) {
	smReset()
	if _, err := smSet(tu, "tenant", "secret", "v", 0); err != nil {
		t.Fatal(err)
	}
	// 他租户用户试图以 tenant ns 写：normalize 到自己租户 ns，不越权
	if _, err := smSet(tx, "tenant", "secret", "hack", 0); err != nil {
		t.Fatal(err)
	}
	e, _, _ := smGet(tu, "secret")
	if e.Value != "v" {
		t.Fatalf("他租户写入不应污染本租户: %v", e.Value)
	}
	// 普通用户写 global 拒绝
	if _, err := smSet(tu, "global", "k", "v", 0); err == nil {
		t.Fatal("普通用户写 global 应被拒绝")
	}
	// 删除：他租户删 "tenant" 时 normalize 到他自己的租户 ns（tenant:t9），
	// 不会越权删除本租户（tenant:t1）的数据——隔离由规范化保证
	if _, err := smDelete(tx, "tenant", "secret"); err != nil {
		t.Fatalf("删自己 ns 应成功: %v", err)
	}
	e2, _, _ := smGet(tu, "secret")
	if e2.Value != "v" {
		t.Fatalf("他租户删除不应影响本租户数据: %+v", e2)
	}
}

func TestV322SharedMemoryTTLAndValueCap(t *testing.T) {
	smReset()
	if _, err := smSet(tu, "user", "ephemeral", "x", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, _, ok := smGet(tu, "ephemeral"); ok {
		t.Fatal("TTL 过期条目不应可见")
	}
	if _, err := smSet(tu, "user", "big", strings.Repeat("a", smDefaultMaxValue+1), 0); err == nil {
		t.Fatal("超限 value 应被拒绝")
	}
}

func TestV322SharedMemoryLRUEviction(t *testing.T) {
	smReset()
	// 直接装小 ns 测驱逐逻辑（构造 5 条，上限 5，再写 1 条应驱逐最旧）
	sharedMemMu.Lock()
	sharedMem["tenant:t1"] = map[string]SharedMemEntry{}
	for i := 0; i < 5; i++ {
		sharedMem["tenant:t1"][fmt.Sprintf("k%d", i)] = SharedMemEntry{
			Value: "v", UpdatedBy: "x",
			UpdatedAt: time.Now().Add(time.Duration(i) * time.Second),
		}
	}
	sharedMemMu.Unlock()
	smEvictOldestLocked("tenant:t1", 5)
	sharedMemMu.Lock()
	if _, ok := sharedMem["tenant:t1"]["k0"]; ok {
		sharedMemMu.Unlock()
		t.Fatal("LRU 应驱逐最旧的 k0")
	}
	sharedMemMu.Unlock()
}

// ===================== 共享信息 =====================

func TestV322SharedInfoScopeAndSearch(t *testing.T) {
	smReset()
	if _, err := siAdd(tu, "fact", "部署规范", "生产环境只允许 127.0.0.1 监听", []string{"deploy"}, "tenant", 0.9); err != nil {
		t.Fatal(err)
	}
	if _, err := siAdd(tu, "preference", "回复语言", "始终中文回复", []string{"lang"}, "tenant", 0.8); err != nil {
		t.Fatal(err)
	}
	if _, err := siAdd(tg, "note", "全局公告", "v3.2.2 上线", nil, "global", 1.0); err != nil {
		t.Fatal(err)
	}
	// 本租户可见 tenant + global
	if got := len(siSearch(tu, "", "", 0)); got != 3 {
		t.Fatalf("本租户应见 3 条（2 tenant + 1 global），got %d", got)
	}
	// 他租户只见 global
	if got := len(siSearch(tx, "", "", 0)); got != 1 {
		t.Fatalf("他租户应只 1 条 global，got %d", got)
	}
	// 关键词：标题命中排最前
	recs := siSearch(tu, "部署", "", 0)
	if len(recs) != 1 || recs[0].Title != "部署规范" {
		t.Fatalf("关键词检索失败: %+v", recs)
	}
	// 标签命中
	if got := len(siSearch(tu, "lang", "", 0)); got != 1 {
		t.Fatalf("标签检索失败: %d", got)
	}
	// 普通用户写 global 拒绝
	if _, err := siAdd(tu, "note", "x", "y", nil, "global", 0.5); err == nil {
		t.Fatal("普通用户写 global 应被拒绝")
	}
	// 他租户删除本租户条目拒绝
	ids := siSearch(tu, "部署", "", 1)
	if len(ids) == 0 {
		t.Fatal("预期至少 1 条")
	}
	if _, err := siDelete(tx, ids[0].ID); err == nil {
		t.Fatal("他租户删除应被拒绝")
	}
}

func TestV322SharedInfoTypeValidation(t *testing.T) {
	smReset()
	if _, err := siAdd(tu, "bogus", "t", "c", nil, "tenant", 0.5); err == nil {
		t.Fatal("非法 type 应被拒绝")
	}
	if _, err := siAdd(tu, "", "t", "c", nil, "tenant", 0.5); err != nil {
		t.Fatalf("空 type 默认 note: %v", err)
	}
}

// ===================== 上下文组装 =====================

func TestV322ContextPackAssembly(t *testing.T) {
	smReset()
	smSet(tu, "user", "style", "concise", 0)
	siAdd(tu, "preference", "语言偏好", "中文回复", []string{"lang"}, "tenant", 0.9)
	pack := buildContextPack(tu, ContextBuildOpts{IncludeSharedInfo: true, IncludeSharedMemory: true, MaxChars: 4096})
	if !strings.Contains(pack.Text, "身份与策略") || !strings.Contains(pack.Text, "语言偏好") || !strings.Contains(pack.Text, "style = concise") {
		t.Fatalf("上下文包缺段: %q", pack.Text)
	}
	if pack.EstimatedTokens <= 0 {
		t.Fatal("token 估算应 > 0")
	}
	// 段落结构
	names := map[string]bool{}
	for _, s := range pack.Sections {
		names[s.Name] = true
	}
	if !names["身份与策略"] || !names["共享信息"] || !names["共享记忆"] {
		t.Fatalf("段落缺失: %+v", pack.Sections)
	}
}

func TestV322ContextPackBudgetTruncation(t *testing.T) {
	smReset()
	smSet(tu, "user", "k", strings.Repeat("v", 3000), 0)
	pack := buildContextPack(tu, ContextBuildOpts{IncludeSharedMemory: true, MaxChars: 600})
	if len([]rune(pack.Text)) > 700 { // 截断标记容差
		t.Fatalf("预算截断失败: %d chars", len([]rune(pack.Text)))
	}
	if !strings.Contains(pack.Text, "已截断") {
		t.Fatal("截断应带标记")
	}
}

func TestV322ContextPackSaveLoad(t *testing.T) {
	smReset()
	if err := ctxPackSave(tu, "pack1", "hello"); err != nil {
		t.Fatal(err)
	}
	if _, err := ctxPackLoad(tx, "pack1"); err == nil {
		t.Fatal("他租户读取应被拒绝")
	}
	got, err := ctxPackLoad(tu2, "pack1") // 同租户他人可读
	if err != nil || got != "hello" {
		t.Fatalf("同租户读取失败: %v %q", err, got)
	}
	// 他租户覆盖同名拒绝
	if err := ctxPackSave(tx, "pack1", "evil"); err == nil {
		t.Fatal("他租户覆盖应被拒绝")
	}
}

// ===================== 守门人 =====================

func TestV322GatekeeperBuiltinDeny(t *testing.T) {
	resetGatekeeper()
	// 安全关键配置路径 deny
	v, why := gkDecide("tars_config_set", map[string]interface{}{"path": "security.wafEnabled", "value": false})
	if v != gkDeny || !strings.Contains(why, "安全关键配置") {
		t.Fatalf("security.* 应 deny: %v %v", v, why)
	}
	v, _ = gkDecide("tars_config_set", map[string]interface{}{"path": "oauth.clientSecret", "value": "x"})
	if v != gkDeny {
		t.Fatal("oauth.* 应 deny")
	}
	// 敏感文件路径 deny
	for _, p := range []string{"/home/u/.ssh/authorized_keys", "/home/u/.env", "/home/u/id_rsa_backup", "/home/u/.git/config"} {
		if v, _ := gkDecide("tars_file_write", map[string]interface{}{"path": p, "content": "x"}); v != gkDeny {
			t.Fatalf("敏感路径应 deny: %s", p)
		}
	}
	// 普通路径 allow
	if v, _ := gkDecide("tars_file_write", map[string]interface{}{"path": "/tmp/ok.txt", "content": "x"}); v != gkAllow {
		t.Fatal("普通路径应 allow")
	}
	// >1MB confirm
	big := strings.Repeat("a", (1<<20)+1)
	if v, _ := gkDecide("tars_file_write", map[string]interface{}{"path": "/tmp/big.txt", "content": big}); v != gkConfirm {
		t.Fatal("大文件应 confirm")
	}
	// 模型动作 confirm
	for _, tool := range []string{"tars_model_start", "tars_model_stop", "tars_model_download"} {
		if v, _ := gkDecide(tool, map[string]interface{}{}); v != gkConfirm {
			t.Fatalf("%s 应 confirm", tool)
		}
	}
	// 只读工具 allow
	if v, _ := gkDecide("tars_status", map[string]interface{}{}); v != gkAllow {
		t.Fatal("只读工具应 allow")
	}
}

func TestV322GatekeeperConfigTightenOnly(t *testing.T) {
	resetGatekeeper()
	// 配置规则：把 tars_status 升级为 confirm（加严有效）
	cfgMu.Lock()
	cfg.Gatekeeper.Rules = []GKRule{{Tools: []string{"tars_status"}, Action: "confirm", Description: "test tighten"}}
	cfgMu.Unlock()
	if v, _ := gkDecide("tars_status", nil); v != gkConfirm {
		t.Fatal("配置加严（allow→confirm）应生效")
	}
	// 配置规则：把安全配置 deny 降为 allow（放宽无效）
	cfgMu.Lock()
	cfg.Gatekeeper.Rules = []GKRule{{Tools: []string{"tars_config_set"}, Action: "allow", Description: "try loosen"}}
	cfgMu.Unlock()
	if v, _ := gkDecide("tars_config_set", map[string]interface{}{"path": "security.apiKey", "value": "x"}); v != gkDeny {
		t.Fatal("配置放宽（deny→allow）应被拒绝")
	}
	cfgMu.Lock()
	cfg.Gatekeeper.Rules = nil
	cfgMu.Unlock()
}

func TestV322GatekeeperConfirmFlow(t *testing.T) {
	resetGatekeeper()
	// 直接调用（不带 token）→ 确认要求
	_, err := executeToolAs(tu, "tars_model_stop", map[string]interface{}{"id": "qwen"})
	req, ok := err.(*gkConfirmationRequired)
	if !ok {
		t.Fatalf("应返回确认要求，got %v", err)
	}
	if req.Token == "" || time.Until(req.ExpiresAt) <= 0 {
		t.Fatal("确认令牌异常")
	}
	// 正确消费成功：哈希口径剥离 confirm_token（与签发时一致）
	if err := gkConsumeConfirm(req.Token, tu.Name, "tars_model_stop", gkArgsHash("tars_model_stop", map[string]interface{}{"id": "qwen"})); err != nil {
		t.Fatalf("正确消费应成功: %v", err)
	}
	// 再消费（已用）失败——一次性
	if err := gkConsumeConfirm(req.Token, tu.Name, "tars_model_stop", gkArgsHash("tars_model_stop", map[string]interface{}{"id": "qwen"})); err == nil {
		t.Fatal("一次性令牌不应可复用")
	}
	// 参数不匹配的消费必须失败（绑定 用户/工具/参数；一次尝试即烧毁防爆破）
	_, err2 := executeToolAs(tu, "tars_model_stop", map[string]interface{}{"id": "qwen"})
	req2, ok := err2.(*gkConfirmationRequired)
	if !ok {
		t.Fatalf("第二次签发应返回确认要求，got %v", err2)
	}
	if err := gkConsumeConfirm(req2.Token, tu.Name, "tars_model_stop", gkArgsHash("tars_model_stop", map[string]interface{}{"different": true})); err == nil {
		t.Fatal("参数不匹配的消费应失败")
	}
	if err := gkConsumeConfirm(req2.Token, tu.Name, "tars_model_stop", gkArgsHash("tars_model_stop", map[string]interface{}{"id": "qwen"})); err == nil {
		t.Fatal("不匹配尝试后令牌应已烧毁（一次性）")
	}
}

func TestV322GatekeeperDenyPathViaExecuteToolAs(t *testing.T) {
	resetGatekeeper()
	// tars_config_set → security.* 直接执行应被守门人拒绝（内置 deny，enforce 默认开）
	_, err := executeToolAs(tu, "tars_config_set", map[string]interface{}{"path": "security.mode", "value": "off"})
	if err == nil {
		t.Fatal("安全关键配置经工具通道应被守门人拒绝")
	}
	if !strings.Contains(err.Error(), "守门人拒绝") {
		t.Fatalf("拒绝信息异常: %v", err)
	}
}

func TestV322GatekeeperIdentityInjectionAntiSpoof(t *testing.T) {
	resetGatekeeper()
	registerV322Tools() // 测试环境无 main 初始化，手动注册被测工具
	// 调用方伪造 _tsgIdentity 应被剥离（executeToolAs 覆盖优先）
	args := map[string]interface{}{"key": "k", "value": "v", "_tsgIdentity": Identity{Name: "fake", Role: "global_admin", Tenant: "*", Global: true}}
	_, err := executeToolAs(tu, "tars_shared_memory_set", args)
	if err != nil {
		t.Fatalf("正常写入应成功: %v", err)
	}
	// 写入者应为真实身份 tu.Name
	e, _, ok := smGet(tu, "k")
	if !ok || e.UpdatedBy != "u1" {
		t.Fatalf("身份伪造应被剥离: %+v", e)
	}
}

func resetGatekeeper() {
	gkMu.Lock()
	gkPendings = map[string]gkPending{}
	gkRateWin = map[string][]time.Time{}
	gkMu.Unlock()
	cfgMu.Lock()
	cfg.Gatekeeper = GatekeeperCfg{}
	cfgMu.Unlock()
}

// ===================== 审计 v2 =====================

func TestV322AuditV2HashChainAndTamper(t *testing.T) {
	dir := t.TempDir()
	auditV2Mu.Lock()
	auditV2Dir, auditV2File, auditV2Day, auditV2Seq, auditV2PrevHash = dir, nil, "", 0, ""
	auditV2LastSweep = time.Time{}
	auditV2Mu.Unlock()
	// 关闭旧日志通道噪音不必要——直接写三条
	auditV2Write("T1", "t1", "", "u1", "", "d1", "")
	auditV2Write("T2", "t1", "", "u1", "", "d2", "")
	auditV2Write("T3", "*", "", "system", "", "d3", "")
	day := time.Now().Format("2006-01-02")
	total, broken, msg := auditV2Verify(day)
	if total != 3 || broken != 0 {
		t.Fatalf("链应完整: total=%d broken=%d msg=%s", total, broken, msg)
	}
	// 篡改第 2 行内容 → 校验必须报断
	f := filepath.Join(dir, "audit-"+day+".jsonl")
	data, _ := os.ReadFile(f)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var e AuditV2Entry
	json.Unmarshal([]byte(lines[1]), &e)
	e.Detail = "TAMPERED"
	b, _ := json.Marshal(e)
	lines[1] = string(b)
	os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0640)
	_, broken, msg = auditV2Verify(day)
	if broken == 0 {
		t.Fatal("篡改必须被检出")
	}
	t.Log("tamper detected:", msg)
	// 复位（避免污染其他测试）
	auditV2Mu.Lock()
	auditV2Dir, auditV2File, auditV2Day, auditV2Seq, auditV2PrevHash = "", nil, "", 0, ""
	auditV2Mu.Unlock()
}

func TestV322AuditV2RestartContinuity(t *testing.T) {
	dir := t.TempDir()
	auditV2Mu.Lock()
	auditV2Dir, auditV2File, auditV2Day, auditV2Seq, auditV2PrevHash = dir, nil, "", 0, ""
	auditV2LastSweep = time.Time{}
	auditV2Mu.Unlock()
	auditV2Write("A", "t1", "", "u1", "", "x", "")
	// 模拟重启：关闭文件句柄重开
	auditV2Mu.Lock()
	auditV2File = nil
	auditV2Day = ""
	auditV2Mu.Unlock()
	auditV2Write("B", "t1", "", "u1", "", "y", "")
	day := time.Now().Format("2006-01-02")
	total, broken, msg := auditV2Verify(day)
	if total != 2 || broken != 0 {
		t.Fatalf("重启续链失败: total=%d broken=%d msg=%s", total, broken, msg)
	}
	auditV2Mu.Lock()
	auditV2Dir, auditV2File, auditV2Day, auditV2Seq, auditV2PrevHash = "", nil, "", 0, ""
	auditV2Mu.Unlock()
}

// ===================== OAuth =====================

func TestV322OAuthSessionLifecycle(t *testing.T) {
	oauthMu.Lock()
	oauthSessions = map[string]oauthSession{}
	oauthStates = map[string]oauthState{}
	oauthMu.Unlock()
	tok := oauthSessionCreate(oauthSession{Name: "alice", Role: "user", Tenant: tenantDefault, ExpiresAt: time.Now().Add(time.Hour)})
	if !strings.HasPrefix(tok, "tsg_s_") {
		t.Fatalf("会话令牌前缀异常: %s", tok)
	}
	id, ok := oauthSessionIdentity(tok)
	if !ok || id.Name != "alice" || id.Role != "user" || id.Tenant != tenantDefault {
		t.Fatalf("会话身份解析失败: %+v %v", id, ok)
	}
	if !oauthSessionRevoke(tok) {
		t.Fatal("注销应成功")
	}
	if _, ok := oauthSessionIdentity(tok); ok {
		t.Fatal("注销后令牌应失效")
	}
}

func TestV322OAuthPKCE(t *testing.T) {
	v := oauthRandomToken(48)
	c := oauthS256Challenge(v)
	if c == "" || v == c {
		t.Fatal("S256 challenge 异常")
	}
	// RFC 7636 附录 B 向量
	if got := oauthS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("S256 challenge 与 RFC 7636 向量不符: %s", got)
	}
}

func TestV322OAuthRoleMapping(t *testing.T) {
	c := OAuthCfg{RoleClaim: "roles", RoleMap: map[string]string{"admin": "admin", "viewer": "readonly"}}
	claims := map[string]interface{}{"roles": []interface{}{"viewer"}}
	if r := oauthMapRole(c, claims); r != "readonly" {
		t.Fatalf("角色映射失败: %s", r)
	}
	claims = map[string]interface{}{"roles": "admin"}
	if r := oauthMapRole(c, claims); r != "admin" {
		t.Fatalf("字符串角色映射失败: %s", r)
	}
	claims = map[string]interface{}{"roles": []interface{}{"unknown"}}
	if r := oauthMapRole(c, claims); r != "" {
		t.Fatalf("未映射且无默认应拒绝: %s", r)
	}
	c.DefaultRole = "user"
	if r := oauthMapRole(c, claims); r != "user" {
		t.Fatalf("默认角色应生效: %s", r)
	}
	// 非法目标角色拒绝（即使出现在 roleMap）
	c.RoleMap["evil"] = "superadmin"
	claims = map[string]interface{}{"roles": []interface{}{"evil"}}
	if r := oauthMapRole(c, claims); r != "user" {
		t.Fatalf("非法目标角色应回退默认: %s", r)
	}
}

func TestV322OAuthReadyFailClose(t *testing.T) {
	cfgMu.Lock()
	cfg.OAuth = OAuthCfg{}
	cfgMu.Unlock()
	if oauthReady() {
		t.Fatal("未配置必须 fail-close")
	}
	cfgMu.Lock()
	cfg.OAuth = OAuthCfg{Enabled: true, IssuerURL: "https://idp.example.com", ClientID: "c", RedirectURL: "http://127.0.0.1:18889/oauth/callback"}
	cfgMu.Unlock()
	if !oauthReady() {
		t.Fatal("配置齐全应就绪")
	}
	oidcInvalidateMeta()
	// /oauth/login 未配置时 503
	cfgMu.Lock()
	cfg.OAuth = OAuthCfg{}
	cfgMu.Unlock()
	w := httptest.NewRecorder()
	handleOAuthLogin(w, httptest.NewRequest("GET", "/oauth/login", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("未启用时 login 应 503, got %d", w.Code)
	}
}

// TestV322OAuthES256Verify 用本地生成的 P-256 密钥对验证 ES256 验签正确性
func TestV322OAuthES256Verify(t *testing.T) {
	priv, pub := genP256(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT","kid":"k1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://idp.test","sub":"alice","aud":"cid","exp":9999999999}`))
	signing := header + "." + payload
	sig := signP256(t, priv, signing)
	key := map[string]interface{}{
		"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256",
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}
	if err := jwtVerifyES256(header, payload, sig, key); err != nil {
		t.Fatalf("合法签名应通过: %v", err)
	}
	// 篡改 payload → 验签失败
	badPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://evil","sub":"bob"}`))
	if err := jwtVerifyES256(header, badPayload, sig, key); err == nil {
		t.Fatal("篡改 payload 应验签失败")
	}
	// 算法白名单：none 拒绝（在 oauthVerifyIDToken 层）
	if alg := jwtAlgFromHeader(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))); alg != "none" {
		t.Fatal("alg 解析异常")
	}
}

// TestV322OAuthRS256Verify 用本地生成的 RSA 密钥对验证手写 RS256 验签
func TestV322OAuthRS256Verify(t *testing.T) {
	priv, pub := genRSA(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"k2"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://idp.test","sub":"alice"}`))
	signing := header + "." + payload
	sig := signRS256(t, priv, signing)
	key := map[string]interface{}{
		"kty": "RSA", "kid": "k2", "alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
	}
	if err := jwtVerifyRS256(header, payload, sig, key); err != nil {
		t.Fatalf("合法 RS256 签名应通过: %v", err)
	}
	if err := jwtVerifyRS256(header, payload, base64.RawURLEncoding.EncodeToString([]byte("forged")), key); err == nil {
		t.Fatal("伪造签名应失败")
	}
}

func TestV322OAuthIDTokenFullVerify(t *testing.T) {
	priv, pub := genRSA(t)
	c := OAuthCfg{IssuerURL: "https://idp.test", ClientID: "cid"}
	kid := "k3"
	header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","typ":"JWT","kid":%q}`, kid)))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://idp.test","sub":"alice","aud":"cid","exp":9999999999,"preferred_username":"alice","roles":["admin"]}`))
	sig := signRS256(t, priv, header+"."+payload)
	token := header + "." + payload + "." + sig

	// 植入 mock JWKS 与 discovery
	oidcMu.Lock()
	oidcDisco = &oidcDiscovery{Issuer: "https://idp.test", AuthorizationEndpoint: "https://idp.test/auth", TokenEndpoint: "https://idp.test/token", JWKSURI: "https://idp.test/jwks"}
	oidcDiscoAt = time.Now()
	oidcJWKS = map[string]interface{}{kid: map[string]interface{}{
		"kty": "RSA", "kid": kid, "alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}}
	oidcJWKSAt = time.Now()
	oidcMu.Unlock()

	d, _ := oidcFetchDiscovery()
	claims, err := oauthVerifyIDToken(token, c, d)
	if err != nil {
		t.Fatalf("完整校验应通过: %v", err)
	}
	if claims["preferred_username"] != "alice" {
		t.Fatalf("claims 解析失败: %v", claims)
	}
	// 错误 iss 拒绝
	c2 := OAuthCfg{IssuerURL: "https://other.test", ClientID: "cid"}
	if _, err := oauthVerifyIDToken(token, c2, d); err == nil {
		t.Fatal("iss 不匹配应拒绝")
	}
	// 错误 aud 拒绝
	c3 := OAuthCfg{IssuerURL: "https://idp.test", ClientID: "other"}
	if _, err := oauthVerifyIDToken(token, c3, d); err == nil {
		t.Fatal("aud 不匹配应拒绝")
	}
	oidcInvalidateMeta()
}

// ===================== chat 上下文注入（集成） =====================

func TestV322ChatContextInjection(t *testing.T) {
	smReset()
	smSet(tu, "user", "project", "TSG", 0)
	siAdd(tu, "preference", "回复偏好", "简洁", nil, "tenant", 0.9)
	// 验证注入逻辑核心：ChatRequest.Context → buildContextPack 前置 system 消息
	opts := ContextBuildOpts{IncludeSharedInfo: true, IncludeSharedMemory: true}
	pack := buildContextPack(tu, opts)
	msgs := []Message{{Role: "user", Content: "hi"}}
	msgs = append([]Message{{Role: "system", Content: pack.Text}}, msgs...)
	if len(msgs) != 2 || msgs[0].Role != "system" || !strings.Contains(msgs[0].Content, "project = TSG") {
		t.Fatalf("注入失败: %+v", msgs)
	}
}

// ===================== REST 端点冒烟 =====================

func TestV322ContextRESTSmoke(t *testing.T) {
	smReset()
	// 共享记忆 REST
	w := httptest.NewRecorder()
	body := `{"key":"rk","value":"rv","namespace":"user"}`
	r := httptest.NewRequest("POST", "/api/context/memory", strings.NewReader(body))
	r.Header.Set("X-API-Key", "test-key")
	// 注入身份：借 identityFromRequest 需要配置用户——直接构造带身份的 args 走工具面已测；
	// REST 层身份从请求解析，这里用单管理员回退路径不可行（key 不匹配），
	// 改测 handler 的鉴权拒绝路径
	handleSharedMemoryREST(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("无有效身份应 401, got %d", w.Code)
	}
}

// ===================== 并发安全 =====================

func TestV322ConcurrentSharedMemoryWrites(t *testing.T) {
	smReset()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := Identity{Name: fmt.Sprintf("u%d", n), Role: "user", Tenant: "t1", IsUsers: true}
			for j := 0; j < 20; j++ {
				smSet(id, "user", fmt.Sprintf("k%d", j), "v", 0)
				smGet(id, fmt.Sprintf("k%d", j))
				siAdd(id, "note", fmt.Sprintf("t%d-%d", n, j), "c", nil, "tenant", 0.5)
			}
		}(i)
	}
	wg.Wait()
	sharedMemMu.Lock()
	n := len(sharedMem)
	sharedMemMu.Unlock()
	if n == 0 {
		t.Fatal("并发写后应有数据")
	}
	// -race 下跑到这里无 panic 即通过
}


// ---------- 加密测试辅助：本地生成密钥并按对应算法签名 ----------

func genP256(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 P-256 密钥失败: %v", err)
	}
	return priv, &priv.PublicKey
}

func genRSA(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA-2048 密钥失败: %v", err)
	}
	return priv, &priv.PublicKey
}

// signP256 用 ecdsa.Sign 直接产出 r/s，拼成 ES256 的 JWS 签名（raw R||S 各 32 字节）
func signP256(t *testing.T, priv *ecdsa.PrivateKey, signing string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("P-256 签名失败: %v", err)
	}
	buf := make([]byte, 64)
	r.FillBytes(buf[:32])
	s.FillBytes(buf[32:])
	return base64.RawURLEncoding.EncodeToString(buf)
}

// signRS256 用 rsa.SignPKCS1v15 签出 RS256 的 JWS 签名
func signRS256(t *testing.T, priv *rsa.PrivateKey, signing string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("RSA 签名失败: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}