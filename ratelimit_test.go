package main

import (
	"strings"
	"testing"
)

// TestRoleToTier 验证 role → tier 默认映射
func TestRoleToTier(t *testing.T) {
	cases := []struct {
		role string
		want string
	}{
		{"user", "personal"},
		{"readonly", "personal"},
		{"team_lead", "lite"},
		{"auditor", "lite"},
		{"admin", "pro"},
		{"global_auditor", "pro"},
		{"global_admin", "enterprise"},
		{"", "personal"},
		{"unknown", "personal"},
	}
	for _, c := range cases {
		got := roleToTier(c.role)
		if got != c.want {
			t.Errorf("roleToTier(%q) = %q, want %q", c.role, got, c.want)
		}
	}
}

// TestTierClassQuota 验证 tier 端点类限额覆盖逻辑
func TestTierClassQuota(t *testing.T) {
	// 构造临时 v3 配置
	v3cfgMu.Lock()
	old := v3cfg
	v3cfg = V3Config{
		RateLimit: struct {
			ChatPerMin  int                      `json:"chatPerMin"`
			AdminPerMin int                      `json:"adminPerMin"`
			ModelPerMin int                      `json:"modelPerMin"`
			PerIPTotal  int                      `json:"perIpTotal"`
			WindowSec   int                      `json:"windowSec"`
			MaxReq      int                      `json:"maxReq"`
			Tiers       map[string]RateLimitTier `json:"tiers"`
		}{
			ChatPerMin:  60,
			AdminPerMin: 10,
			ModelPerMin: 6,
			Tiers: map[string]RateLimitTier{
				"personal":   {ChatPerMin: 10, AdminPerMin: 2, ModelPerMin: 1},
				"lite":       {ChatPerMin: 30, AdminPerMin: 5, ModelPerMin: 3},
				"pro":        {ChatPerMin: 120, AdminPerMin: 20, ModelPerMin: 12},
				"enterprise": {ChatPerMin: 0, AdminPerMin: 0, ModelPerMin: 0}, // 0 = 继承全局
			},
		},
	}
	v3cfgMu.Unlock()
	defer func() {
		v3cfgMu.Lock()
		v3cfg = old
		v3cfgMu.Unlock()
	}()

	cases := []struct {
		tier, cls string
		want      int
	}{
		{"personal", "chat", 10},
		{"personal", "admin", 2},
		{"personal", "model", 1},
		{"lite", "chat", 30},
		{"pro", "chat", 120},
		{"enterprise", "chat", 60},  // 0 继承全局
		{"enterprise", "admin", 10}, // 0 继承全局
		{"unknown", "chat", 60},     // 未知 tier 回退全局
		{"", "chat", 60},            // 空 tier 回退全局
	}
	for _, c := range cases {
		got := tierClassQuota(c.tier, c.cls)
		if got != c.want {
			t.Errorf("tierClassQuota(%q, %q) = %d, want %d", c.tier, c.cls, got, c.want)
		}
	}
}

// TestTierDailyQuota 验证日限额读取
func TestTierDailyQuota(t *testing.T) {
	v3cfgMu.Lock()
	old := v3cfg
	v3cfg = V3Config{
		RateLimit: struct {
			ChatPerMin  int                      `json:"chatPerMin"`
			AdminPerMin int                      `json:"adminPerMin"`
			ModelPerMin int                      `json:"modelPerMin"`
			PerIPTotal  int                      `json:"perIpTotal"`
			WindowSec   int                      `json:"windowSec"`
			MaxReq      int                      `json:"maxReq"`
			Tiers       map[string]RateLimitTier `json:"tiers"`
		}{
			Tiers: map[string]RateLimitTier{
				"personal": {DailyQuota: 100},
				"pro":      {DailyQuota: 10000},
			},
		},
	}
	v3cfgMu.Unlock()
	defer func() {
		v3cfgMu.Lock()
		v3cfg = old
		v3cfgMu.Unlock()
	}()

	if tierDailyQuota("personal") != 100 {
		t.Errorf("personal daily quota = %d, want 100", tierDailyQuota("personal"))
	}
	if tierDailyQuota("pro") != 10000 {
		t.Errorf("pro daily quota = %d, want 10000", tierDailyQuota("pro"))
	}
	if tierDailyQuota("unknown") != 0 {
		t.Errorf("unknown daily quota = %d, want 0", tierDailyQuota("unknown"))
	}
}

// TestTierConcurrency 验证并发数读取
func TestTierConcurrency(t *testing.T) {
	v3cfgMu.Lock()
	old := v3cfg
	v3cfg = V3Config{
		RateLimit: struct {
			ChatPerMin  int                      `json:"chatPerMin"`
			AdminPerMin int                      `json:"adminPerMin"`
			ModelPerMin int                      `json:"modelPerMin"`
			PerIPTotal  int                      `json:"perIpTotal"`
			WindowSec   int                      `json:"windowSec"`
			MaxReq      int                      `json:"maxReq"`
			Tiers       map[string]RateLimitTier `json:"tiers"`
		}{
			Tiers: map[string]RateLimitTier{
				"personal": {Concurrency: 2},
				"pro":      {Concurrency: 20},
			},
		},
	}
	v3cfgMu.Unlock()
	defer func() {
		v3cfgMu.Lock()
		v3cfg = old
		v3cfgMu.Unlock()
	}()

	if tierConcurrency("personal") != 2 {
		t.Errorf("personal concurrency = %d, want 2", tierConcurrency("personal"))
	}
	if tierConcurrency("pro") != 20 {
		t.Errorf("pro concurrency = %d, want 20", tierConcurrency("pro"))
	}
	if tierConcurrency("unknown") != 0 {
		t.Errorf("unknown concurrency = %d, want 0", tierConcurrency("unknown"))
	}
}

// TestConcurEnterLeave 验证并发控制
func TestConcurEnterLeave(t *testing.T) {
	user := "testuser"
	// 清理
	rlConcurMu.Lock()
	delete(rlConcurMap, user)
	rlConcurMu.Unlock()

	if !concurEnter(user, 2) {
		t.Fatal("first enter should succeed")
	}
	if !concurEnter(user, 2) {
		t.Fatal("second enter should succeed")
	}
	if concurEnter(user, 2) {
		t.Fatal("third enter should fail (max=2)")
	}

	concurLeave(user)
	if !concurEnter(user, 2) {
		t.Fatal("enter after leave should succeed")
	}

	concurLeave(user)
	concurLeave(user)
	concurLeave(user) // 不应 panic

	rlConcurMu.Lock()
	delete(rlConcurMap, user)
	rlConcurMu.Unlock()
}

// TestAllowRateLimitedTier 验证 allowRateLimited 对 tier 限额的实际拦截
func TestAllowRateLimitedTier(t *testing.T) {
	// 清理桶
	rlBucketMu.Lock()
	rlBuckets = map[bucketKey]*tokenBucket{}
	rlBucketMu.Unlock()

	v3cfgMu.Lock()
	old := v3cfg
	v3cfg = V3Config{
		RateLimit: struct {
			ChatPerMin  int                      `json:"chatPerMin"`
			AdminPerMin int                      `json:"adminPerMin"`
			ModelPerMin int                      `json:"modelPerMin"`
			PerIPTotal  int                      `json:"perIpTotal"`
			WindowSec   int                      `json:"windowSec"`
			MaxReq      int                      `json:"maxReq"`
			Tiers       map[string]RateLimitTier `json:"tiers"`
		}{
			ChatPerMin:  60,
			AdminPerMin: 10,
			ModelPerMin: 6,
			PerIPTotal:  240,
			Tiers: map[string]RateLimitTier{
				"personal": {ChatPerMin: 1, DailyQuota: 5, Concurrency: 10},
			},
		},
	}
	v3cfgMu.Unlock()
	defer func() {
		v3cfgMu.Lock()
		v3cfg = old
		v3cfgMu.Unlock()
	}()

	// personal tier chat = 1/min，第一次应通过
	ok, reason := allowRateLimited("1.2.3.4", "alice", "user", "", "/api/chat/completions")
	if !ok {
		t.Fatalf("first request should pass: %s", reason)
	}

	// 同一用户第二次应被 tier 拦截（但 IP 维度不同用户可能通过）
	ok, reason = allowRateLimited("1.2.3.4", "alice", "user", "", "/api/chat/completions")
	if ok {
		t.Fatal("second request should be blocked by tier quota")
	}
	if reason == "" {
		t.Fatal("blocked request should have a reason")
	}

	// 并发释放
	concurLeave("alice")
}

// TestRateLimitUpgradeHint 验证升级提示文案
func TestRateLimitUpgradeHint(t *testing.T) {
	cases := []struct {
		tier string
		want string
	}{
		{"personal", "personal"},
		{"lite", "lite"},
		{"pro", "pro"},
		{"enterprise", "enterprise"},
		{"", "config.rateLimit.tiers"},
	}
	for _, c := range cases {
		hint := rateLimitUpgradeHint(c.tier)
		if hint == "" {
			t.Errorf("rateLimitUpgradeHint(%q) empty", c.tier)
		}
		if !strings.Contains(hint, c.want) && c.tier != "" {
			t.Errorf("rateLimitUpgradeHint(%q) missing %q: %s", c.tier, c.want, hint)
		}
	}
}

// TestResolveTier 验证 resolveTier 逻辑（显式 tier > role 映射）
func TestResolveTier(t *testing.T) {
	// 备份并注入临时用户
	cfgMu.Lock()
	oldUsers := cfg.Users
	cfg.Users = []User{
		{Name: "alice", Role: "user", Tier: "lite"},      // 显式 lite
		{Name: "bob", Role: "admin", Tier: ""},           // 按 role → pro
		{Name: "carol", Role: "global_admin", Tier: ""}, // 按 role → enterprise
	}
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg.Users = oldUsers
		cfgMu.Unlock()
	}()

	if got := resolveTier("alice", "user"); got != "lite" {
		t.Errorf("resolveTier(alice) = %q, want lite", got)
	}
	if got := resolveTier("bob", "admin"); got != "pro" {
		t.Errorf("resolveTier(bob) = %q, want pro", got)
	}
	if got := resolveTier("carol", "global_admin"); got != "enterprise" {
		t.Errorf("resolveTier(carol) = %q, want enterprise", got)
	}
	if got := resolveTier("admin", ""); got != "enterprise" {
		t.Errorf("resolveTier(admin fallback) = %q, want enterprise", got)
	}
	if got := resolveTier("unknown", "user"); got != "personal" {
		t.Errorf("resolveTier(unknown, user) = %q, want personal", got)
	}
}
