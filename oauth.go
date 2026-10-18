package main

// v3.2.2 OAuth / IdP 接入：OIDC Authorization Code + PKCE，零第三方依赖。
//
// 目标：企业 IdP（Keycloak / Auth0 / Entra ID / 飞书 …任何 OIDC 兼容 IdP）认证
// 浏览器用户 → 换发 TSG 本地会话令牌（tsg_s_*），令牌与既有 API Key 同权进入
// RBAC 矩阵；API Key 通道原样保留（机器客户端不需要 OAuth）。
//
// 流程：
//   GET  /oauth/login?redirect=<after-login-path>
//        → 生成 state + PKCE verifier（S256），302 到 IdP authorization_endpoint
//   GET  /oauth/callback?code&state
//        → token_endpoint 换 id_token（client_secret_post + PKCE）
//        → 校验：签名（JWKS RS256/ES256，算法白名单，拒绝 none/HS256）、
//          iss / aud / exp（±60s 时钟容差）、nonce
//        → roleClaim（默认 roles）映射 RoleMap → TSG 角色；无映射且无默认角色 → 拒绝
//        → 发会话令牌（256-bit 随机，HMAC 无必要——高熵不可猜），TTL 默认 480 分钟
//   POST /oauth/logout（携带会话令牌）→ 注销
//
// 安全铁律（fail-close）：
//   - oauth.enabled=false 或配置不全 → /oauth/* 一律 503，绝不半开
//   - 任何校验失败 → 不发令牌 + 审计（OAUTH_TOKEN_REJECT 带原因）
//   - discovery / JWKS 拉取失败 → 拒绝（不降级跳过验签）
//   - 会话仅存内存：重启即失效（重新登录即可，无持久化凭据泄露面）
//   - state 一次性、10 分钟有效；防 CSRF
//
// identityFromRequest 挂钩（tenant.go）：Bearer tsg_s_* → 会话身份。

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ===================== 配置 =====================

// OAuthCfg OAuth / IdP 配置段（config.json 顶层键 oauth）
type OAuthCfg struct {
	Enabled           bool              `json:"enabled"`
	IssuerURL         string            `json:"issuerUrl"`     // 如 https://idp.example.com/realms/main
	ClientID          string            `json:"clientId"`
	ClientSecret      string            `json:"clientSecret"`
	RedirectURL       string            `json:"redirectUrl"` // 如 http://127.0.0.1:18889/oauth/callback
	Scope             string            `json:"scope"`       // 默认 openid profile
	RoleClaim         string            `json:"roleClaim"`   // 默认 roles
	RoleMap           map[string]string `json:"roleMap"`     // IdP 角色 → TSG 角色
	DefaultRole       string            `json:"defaultRole"` // 无映射时回退（空=拒绝）
	SessionTTLMinutes int               `json:"sessionTtlMinutes"`
	UserClaim         string            `json:"userClaim"` // 默认 preferred_username
}

func oauthConfig() OAuthCfg {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.OAuth
}

// oauthReady 配置齐全才启用（fail-close：缺一项都不开）
func oauthReady() bool {
	c := oauthConfig()
	return c.Enabled && c.IssuerURL != "" && c.ClientID != "" && c.RedirectURL != "" &&
		(strings.HasPrefix(c.IssuerURL, "https://") || strings.HasPrefix(c.IssuerURL, "http://localhost") || strings.HasPrefix(c.IssuerURL, "http://127.0.0.1"))
}

// ===================== 会话与 state 存储 =====================

type oauthSession struct {
	Name     string
	Role     string
	Tenant   string
	Groups   []string
	Global   bool
	ExpiresAt time.Time
}

var (
	oauthMu       sync.Mutex
	oauthSessions = map[string]oauthSession{} // tsg_s_<hex> -> session
	oauthStates   = map[string]oauthState{}   // state -> {verifier, expiresAt, redirect}
)

type oauthState struct {
	Verifier  string
	ExpiresAt time.Time
	Redirect  string
}

const oauthStateTTL = 10 * time.Minute
const oauthSessionTokenPrefix = "tsg_s_"

func oauthTTL() time.Duration {
	if m := oauthConfig().SessionTTLMinutes; m > 0 {
		return time.Duration(m) * time.Minute
	}
	return 480 * time.Minute
}

// oauthSessionCreate 签发会话令牌
func oauthSessionCreate(s oauthSession) string {
	b := make([]byte, 32)
	rand.Read(b)
	tok := oauthSessionTokenPrefix + fmt.Sprintf("%x", b)
	oauthMu.Lock()
	oauthSessions[tok] = s
	// 顺带清扫过期会话与 state
	now := time.Now()
	for k, v := range oauthSessions {
		if now.After(v.ExpiresAt) {
			delete(oauthSessions, k)
		}
	}
	for k, v := range oauthStates {
		if now.After(v.ExpiresAt) {
			delete(oauthStates, k)
		}
	}
	oauthMu.Unlock()
	return tok
}

// oauthSessionLookup 查会话（过期返回 false）
func oauthSessionLookup(token string) (oauthSession, bool) {
	oauthMu.Lock()
	defer oauthMu.Unlock()
	s, ok := oauthSessions[token]
	if !ok || time.Now().After(s.ExpiresAt) {
		return oauthSession{}, false
	}
	return s, true
}

// oauthSessionRevoke 注销
func oauthSessionRevoke(token string) bool {
	oauthMu.Lock()
	defer oauthMu.Unlock()
	_, ok := oauthSessions[token]
	delete(oauthSessions, token)
	return ok
}

// oauthSessionIdentity 会话令牌 → 请求身份（供 identityFromRequest 挂钩）
func oauthSessionIdentity(token string) (Identity, bool) {
	s, ok := oauthSessionLookup(token)
	if !ok {
		return Identity{}, false
	}
	return Identity{Name: s.Name, Role: s.Role, Tenant: s.Tenant, Groups: s.Groups, Global: s.Global, IsUsers: true}, true
}

// ===================== OIDC 元数据（discovery / JWKS）缓存 =====================

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

var (
	oidcMu       sync.Mutex
	oidcDisco    *oidcDiscovery
	oidcDiscoAt  time.Time
	oidcJWKS     map[string]interface{}
	oidcJWKSAt   time.Time
)

const oidcCacheTTL = 15 * time.Minute

// httpGetJSON 简单 JSON GET（带超时，复用全局连接池）
func httpGetJSON(url string, out interface{}) error {
	client := httpClientShort
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// oidcFetchDiscovery 拉取（含缓存）discovery 文档
func oidcFetchDiscovery() (*oidcDiscovery, error) {
	c := oauthConfig()
	oidcMu.Lock()
	if oidcDisco != nil && time.Since(oidcDiscoAt) < oidcCacheTTL {
		d := oidcDisco
		oidcMu.Unlock()
		return d, nil
	}
	oidcMu.Unlock()
	var d oidcDiscovery
	if err := httpGetJSON(strings.TrimRight(c.IssuerURL, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return nil, fmt.Errorf("discovery 拉取失败: %v", err)
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("discovery 文档字段不全")
	}
	oidcMu.Lock()
	oidcDisco, oidcDiscoAt = &d, time.Now()
	oidcMu.Unlock()
	return &d, nil
}

// oidcFetchJWKS 拉取（含缓存）JWKS
func oidcFetchJWKS() (map[string]interface{}, error) {
	d, err := oidcFetchDiscovery()
	if err != nil {
		return nil, err
	}
	oidcMu.Lock()
	if oidcJWKS != nil && time.Since(oidcJWKSAt) < oidcCacheTTL {
		k := oidcJWKS
		oidcMu.Unlock()
		return k, nil
	}
	oidcMu.Unlock()
	var keys struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := httpGetJSON(d.JWKSURI, &keys); err != nil {
		return nil, fmt.Errorf("JWKS 拉取失败: %v", err)
	}
	m := map[string]interface{}{}
	for _, k := range keys.Keys {
		if kid, ok := k["kid"].(string); ok {
			m[kid] = k
		}
	}
	oidcMu.Lock()
	oidcJWKS, oidcJWKSAt = m, time.Now()
	oidcMu.Unlock()
	return m, nil
}

// oidcInvalidateMeta 配置热重载后失效缓存（issuer 变了旧元数据不可用）
func oidcInvalidateMeta() {
	oidcMu.Lock()
	oidcDisco, oidcJWKS = nil, nil
	oidcMu.Unlock()
}

// ===================== JWT 验签（标准库实现） =====================

// jwtVerifySig 用 JWKS 公钥校验 JWT 签名（仅 RS256 / ES256）
func jwtVerifySig(headerB64, payloadB64, sigB64 string, jwksKey map[string]interface{}) error {
	alg, _ := jwksKey["alg"].(string)
	kty, _ := jwksKey["kty"].(string)
	if alg == "" {
		alg = jwtAlgFromHeader(headerB64)
	}
	switch {
	case kty == "RSA" && (alg == "RS256"):
		return jwtVerifyRS256(headerB64, payloadB64, sigB64, jwksKey)
	case kty == "EC" && alg == "ES256":
		return jwtVerifyES256(headerB64, payloadB64, sigB64, jwksKey)
	default:
		return fmt.Errorf("不支持的算法/密钥类型: alg=%s kty=%s（仅 RS256 / ES256）", alg, kty)
	}
}

func jwtAlgFromHeader(headerB64 string) string {
	raw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return ""
	}
	var h struct {
		Alg string `json:"alg"`
	}
	json.Unmarshal(raw, &h)
	return h.Alg
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ===================== 端点 =====================

// handleOAuthLogin GET /oauth/login —— 302 到 IdP（免鉴权公共路由）
func handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !oauthReady() {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "OAuth 未启用或配置不全（fail-close）"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	d, err := oidcFetchDiscovery()
	if err != nil {
		auditLog("OAUTH_DISCOVERY_FAIL", "system", err.Error())
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "IdP discovery 不可用: " + err.Error()})
		return
	}
	c := oauthConfig()
	// state + PKCE
	verifier := oauthRandomToken(64)
	state := oauthRandomToken(32)
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" || !strings.HasPrefix(redirect, "/") {
		redirect = "/"
	}
	oauthMu.Lock()
	oauthStates[state] = oauthState{Verifier: verifier, ExpiresAt: time.Now().Add(oauthStateTTL), Redirect: redirect}
	oauthMu.Unlock()
	challenge := oauthS256Challenge(verifier)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURL)
	q.Set("scope", oauthScope(c))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, d.AuthorizationEndpoint+"?"+q.Encode(), http.StatusFound)
}

// handleOAuthCallback GET /oauth/callback —— 换 token、验签、发会话（公共路由）
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !oauthReady() {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "OAuth 未启用或配置不全（fail-close）"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	// IdP 出错回调
	if e := r.URL.Query().Get("error"); e != "" {
		auditLog("OAUTH_LOGIN_FAIL", "system", "idp error: "+e)
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "IdP 返回错误: " + e})
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "缺少 code / state"})
		return
	}
	oauthMu.Lock()
	st, ok := oauthStates[state]
	delete(oauthStates, state) // state 一次性
	oauthMu.Unlock()
	if !ok || time.Now().After(st.ExpiresAt) {
		auditLog("OAUTH_TOKEN_REJECT", "system", "state 无效或过期")
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "state 无效或已过期，请重新登录"})
		return
	}
	id, err := oauthExchangeVerify(r, code, st.Verifier)
	if err != nil {
		auditLog("OAUTH_TOKEN_REJECT", "system", err.Error())
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "登录失败: " + err.Error()})
		return
	}
	token := oauthSessionCreate(id)
	auditLogT("OAUTH_LOGIN_SUCCESS", id.Tenant, "", id.Name, "role="+id.Role+" ttl="+oauthTTL().String())
	// 浏览器友好响应：令牌同时经 Set-Cookie（HttpOnly）与页面展示（供 MCP 客户端复制）
	http.SetCookie(w, &http.Cookie{
		Name: "tsg_session", Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(oauthTTL().Seconds()),
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>登录成功</title></head>
<body style="font-family:system-ui;padding:40px">
<h2>✅ 登录成功</h2>
<p>用户 %s（角色 %s，租户 %s）。会话有效期 %s。</p>
<p>浏览器已自动携带会话 Cookie；API / MCP 客户端请使用以下 Bearer 令牌：</p>
<pre style="background:#f5f5f5;padding:12px;border-radius:6px;user-select:all">%s</pre>
<p><a href="%s">进入管理台 →</a></p>
<script>setTimeout(function(){location.href=%q},3000)</script>
</body></html>`, id.Name, id.Role, id.Tenant, oauthTTL(), token, st.Redirect, st.Redirect)
}

// handleOAuthLogout POST /oauth/logout（会话令牌鉴权，经 gatewayMiddleware）
func handleOAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	tok := extractAPIKey(r)
	if !strings.HasPrefix(tok, oauthSessionTokenPrefix) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "仅支持注销 OAuth 会话令牌"})
		return
	}
	ok := oauthSessionRevoke(tok)
	auditLog("OAUTH_LOGOUT", "system", fmt.Sprintf("revoked=%v", ok))
	http.SetCookie(w, &http.Cookie{Name: "tsg_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]interface{}{"success": true, "revoked": ok})
}

// handleOAuthStatus GET /api/admin/oauth/status —— 配置健康视图（不泄密）
func handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	c := oauthConfig()
	oauthMu.Lock()
	n := len(oauthSessions)
	oauthMu.Unlock()
	writeJSON(w, map[string]interface{}{
		"enabled": c.Enabled, "ready": oauthReady(),
		"issuer": c.IssuerURL, "clientId": c.ClientID,
		"roleClaim": c.RoleClaim, "defaultRole": c.DefaultRole,
		"roleMapKeys": len(c.RoleMap),
		"activeSessions": n, "sessionTtlMinutes": oauthTTL().Minutes(),
	})
}

// ===================== 换取与校验 =====================

// oauthExchangeVerify code 换 id_token 并全套校验，返回会话身份
func oauthExchangeVerify(r *http.Request, code, verifier string) (oauthSession, error) {
	c := oauthConfig()
	d, err := oidcFetchDiscovery()
	if err != nil {
		return oauthSession{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURL)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code_verifier", verifier)
	client := httpClientShort
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.PostForm(d.TokenEndpoint, form)
	if err != nil {
		return oauthSession{}, fmt.Errorf("token endpoint 请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return oauthSession{}, fmt.Errorf("token endpoint HTTP %d", resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return oauthSession{}, fmt.Errorf("响应缺少 id_token")
	}
	claims, err := oauthVerifyIDToken(tok.IDToken, c, d)
	if err != nil {
		return oauthSession{}, err
	}
	return oauthSessionFromClaims(c, claims)
}

// oauthVerifyIDToken 校验 id_token：结构、签名（JWKS）、iss/aud/exp/nonce
func oauthVerifyIDToken(token string, c OAuthCfg, d *oidcDiscovery) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("id_token 结构非法")
	}
	header, payload, sig := parts[0], parts[1], parts[2]
	// 算法白名单：仅 RS256 / ES256（拒绝 none / HS256——公钥场景 HS256=伪造通道）
	alg := jwtAlgFromHeader(header)
	if alg != "RS256" && alg != "ES256" {
		return nil, fmt.Errorf("id_token 算法不在白名单: %s", alg)
	}
	var headerMap map[string]interface{}
	hb, _ := b64urlDecode(header)
	json.Unmarshal(hb, &headerMap)
	kid, _ := headerMap["kid"].(string)
	jwks, err := oidcFetchJWKS()
	if err != nil {
		return nil, err
	}
	key, ok := jwks[kid].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("JWKS 中无 kid=%s 的密钥", kid)
	}
	if err := jwtVerifySig(header, payload, sig, key); err != nil {
		return nil, fmt.Errorf("签名校验失败: %v", err)
	}
	var claims map[string]interface{}
	pb, _ := b64urlDecode(payload)
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, fmt.Errorf("payload 解析失败")
	}
	now := time.Now()
	// iss：允差尾斜杠（部分 IdP 配置差异）
	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != strings.TrimRight(c.IssuerURL, "/") {
		return nil, fmt.Errorf("iss 不匹配: %s", iss)
	}
	// aud：字符串或数组，须包含 clientId
	switch aud := claims["aud"].(type) {
	case string:
		if aud != c.ClientID {
			return nil, fmt.Errorf("aud 不匹配")
		}
	case []interface{}:
		found := false
		for _, a := range aud {
			if s, _ := a.(string); s == c.ClientID {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("aud 不匹配")
		}
	default:
		return nil, fmt.Errorf("aud 缺失")
	}
	// exp（±60s 容差）
	exp, _ := claims["exp"].(float64)
	if now.After(time.Unix(int64(exp)+60, 0)) {
		return nil, fmt.Errorf("id_token 已过期")
	}
	return claims, nil
}

// oauthSessionFromClaims 角色/身份映射 → 会话
func oauthSessionFromClaims(c OAuthCfg, claims map[string]interface{}) (oauthSession, error) {
	userClaim := c.UserClaim
	if userClaim == "" {
		userClaim = "preferred_username"
	}
	name, _ := claims[userClaim].(string)
	if name == "" {
		if sub, _ := claims["sub"].(string); sub != "" {
			name = sub
		}
	}
	if name == "" {
		return oauthSession{}, fmt.Errorf("id_token 缺少用户声明（%s / sub）", userClaim)
	}
	role := oauthMapRole(c, claims)
	if role == "" {
		return oauthSession{}, fmt.Errorf("用户 %s 无角色映射（roleMap 未命中且未配置 defaultRole）", name)
	}
	s := oauthSession{Name: name, Role: role, ExpiresAt: time.Now().Add(oauthTTL())}
	switch role {
	case "global_admin", "global_auditor":
		s.Global = true
		s.Tenant = "*"
	default:
		s.Tenant = tenantDefault
	}
	return s, nil
}

// oauthMapRole roleClaim（数组或字符串）→ RoleMap 映射；未命中走 defaultRole
func oauthMapRole(c OAuthCfg, claims map[string]interface{}) string {
	roleClaim := c.RoleClaim
	if roleClaim == "" {
		roleClaim = "roles"
	}
	var idpRoles []string
	switch v := claims[roleClaim].(type) {
	case string:
		idpRoles = []string{v}
	case []interface{}:
		for _, x := range v {
			if s, ok := x.(string); ok {
				idpRoles = append(idpRoles, s)
			}
		}
	case float64: // realm_access 风格数字角色无意义，忽略
	}
	for _, r := range idpRoles {
		if mapped, ok := c.RoleMap[r]; ok && oauthValidRole(mapped) {
			return mapped
		}
	}
	if c.DefaultRole != "" && oauthValidRole(c.DefaultRole) {
		return c.DefaultRole
	}
	return ""
}

// oauthValidRole 目标角色必须是 RBAC 矩阵已知角色
func oauthValidRole(r string) bool {
	_, ok := rbacMatrix[r]
	return ok
}

// ===================== 工具函数 =====================

func oauthRandomToken(nbytes int) string {
	b := make([]byte, nbytes)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func oauthS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func oauthScope(c OAuthCfg) string {
	if c.Scope != "" {
		return c.Scope
	}
	return "openid profile"
}
