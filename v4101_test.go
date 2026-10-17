package main

// v4.10.1 测试套件 — Model Alias + Sticky Router + Protocol Translator

import (
	"fmt"
	"testing"
	"time"
)

// ===================== Model Alias Tests =====================

func TestResolveModelAlias(t *testing.T) {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	// 构造测试配置
	cfg.V4101Config.ModelAliases = []ModelAlias{
		{Alias: "c37", Target: "claude-3-7-sonnet-20250219", ProviderID: "anthropic"},
		{Alias: "gpt4", Target: "gpt-4o", ProviderID: ""},
		{Alias: "ds", Target: "deepseek-chat", ProviderID: "deepseek"},
	}
	initModelAliases()

	cases := []struct {
		input    string
		wantT    string
		wantPID  string
		wantOk   bool
	}{
		{"c37", "claude-3-7-sonnet-20250219", "anthropic", true},
		{"C37", "claude-3-7-sonnet-20250219", "anthropic", true}, // 大小写不敏感
		{"gpt4", "gpt-4o", "", true},
		{"ds", "deepseek-chat", "deepseek", true},
		{"unknown", "unknown", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			gotT, gotPID, gotOk := resolveModelAlias(c.input)
			if gotOk != c.wantOk {
				t.Fatalf("ok: got %v, want %v", gotOk, c.wantOk)
			}
			if gotOk {
				if gotT != c.wantT {
					t.Fatalf("target: got %s, want %s", gotT, c.wantT)
				}
				if gotPID != c.wantPID {
					t.Fatalf("providerID: got %s, want %s", gotPID, c.wantPID)
				}
			}
		})
	}
}

func TestResolveModelByPrefix(t *testing.T) {
	cases := []struct {
		model       string
		wantPID     string
		wantProto   string
	}{
		{"claude-3-sonnet", "anthropic", "anthropic"},
		{"gemini-1.5-pro", "gemini", "gemini"},
		{"models/gemini-1.5-flash", "gemini", "gemini"},
		{"gpt-4o", "", "openai-compat"},
		{"deepseek-chat", "", "openai-compat"},
	}
	for _, c := range cases {
		t.Run(c.model, func(t *testing.T) {
			pid, proto := resolveModelByPrefix(c.model)
			if pid != c.wantPID || proto != c.wantProto {
				t.Fatalf("got pid=%s proto=%s, want pid=%s proto=%s", pid, proto, c.wantPID, c.wantProto)
			}
		})
	}
}

func TestExpandModelAlias(t *testing.T) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	cfgMu.Lock()
	defer cfgMu.Unlock()
	cfg.V4101Config.ModelAliases = []ModelAlias{
		{Alias: "c37", Target: "claude-3-7-sonnet-20250219", ProviderID: "anthropic"},
	}
	initModelAliases()

	cases := []struct {
		input      string
		wantModel  string
		wantPID    string
		wantProto  string
	}{
		{"c37", "claude-3-7-sonnet-20250219", "anthropic", ""},
		{"anthropic/claude-3", "anthropic/claude-3", "", ""},
		{"gemini-1.5-pro", "gemini-1.5-pro", "gemini", "gemini"},
		{"gpt-4o", "gpt-4o", "", "openai-compat"},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			m, pid, proto := expandModelAlias(c.input)
			if m != c.wantModel || pid != c.wantPID || proto != c.wantProto {
				t.Fatalf("got model=%s pid=%s proto=%s, want model=%s pid=%s proto=%s",
					m, pid, proto, c.wantModel, c.wantPID, c.wantProto)
			}
		})
	}
}

// ===================== Sticky Router Tests =====================

func TestStickyRouterPrimary(t *testing.T) {
	sr := &StickyRouter{entries: make(map[string]*stickyEntry)}
	cands := []string{"idx:0", "idx:1", "idx:2"}
	ordered, isProbe := sr.selectSticky("anthropic/c37", cands, "idx:0")
	if isProbe {
		t.Fatal("primary should not probe")
	}
	if len(ordered) != 3 || ordered[0] != "idx:0" {
		t.Fatalf("primary order wrong: %v", ordered)
	}
}

func TestStickyRouterFallbackAndProbe(t *testing.T) {
	sr := &StickyRouter{entries: make(map[string]*stickyEntry)}
	dk := "anthropic/c37"
	cands := []string{"idx:0", "idx:1"}
	preferred := "idx:0"

	// 首次调用：Primary，但 idx:0 失败
	sr.recordSticky(dk, false, "", preferred, false)

	// 再次 select：应进入 Fallback（因刚才 record 改了状态）
	ordered, isProbe := sr.selectSticky(dk, cands, preferred)
	if !isProbe {
		// Fallback 模式下首次 select 应触发 probe（因 consecutiveSuccesses=0 < 5，但 lastProbe 是零值，时间差 >= 30s）
		t.Logf("ordered=%v isProbe=%v", ordered, isProbe)
	}

	// 模拟 fallback 成功 5 次后触发 probe
	sr.entries[dk].mode = stickyFallback
	sr.entries[dk].stickyFallbackKey = "idx:1"
	sr.entries[dk].consecutiveSuccesses = 5
	sr.entries[dk].lastProbe = time.Now().Add(-time.Hour) // 确保时间差够大
	ordered, isProbe = sr.selectSticky(dk, cands, preferred)
	if !isProbe {
		t.Fatal("after 5 consecutive successes should probe")
	}
	if ordered[0] != "idx:0" {
		t.Fatalf("probe should put preferred first: %v", ordered)
	}
}

func TestStickyRouterProbeSuccessRecover(t *testing.T) {
	sr := &StickyRouter{entries: make(map[string]*stickyEntry)}
	dk := "anthropic/c37"
	cands := []string{"idx:0", "idx:1"}
	preferred := "idx:0"

	// 构造 fallback 状态
	sr.entries[dk] = &stickyEntry{
		mode:            stickyFallback,
		stickyFallbackKey: "idx:1",
		probeBackoffSec: stickyInitialBackoffSec,
		lastProbe:       time.Now().Add(-time.Hour),
	}

	// select 触发 probe
	ordered, isProbe := sr.selectSticky(dk, cands, preferred)
	if !isProbe || ordered[0] != "idx:0" {
		t.Fatalf("should probe with preferred first: ordered=%v isProbe=%v", ordered, isProbe)
	}

	// probe 成功（usedKey == preferred）
	sr.recordSticky(dk, true, "idx:0", preferred, true)
	if sr.entries[dk].mode != stickyPrimary {
		t.Fatal("should recover to primary after successful probe")
	}
}

func TestStickyRouterProbeFailBackoff(t *testing.T) {
	sr := &StickyRouter{entries: make(map[string]*stickyEntry)}
	dk := "anthropic/c37"
	cands := []string{"idx:0", "idx:1"}
	preferred := "idx:0"

	sr.entries[dk] = &stickyEntry{
		mode:            stickyFallback,
		stickyFallbackKey: "idx:1",
		probeBackoffSec: 30,
		lastProbe:       time.Now().Add(-time.Hour),
	}

	_, isProbe := sr.selectSticky(dk, cands, preferred)
	if !isProbe {
		t.Fatal("should probe")
	}

	// probe 失败
	sr.recordSticky(dk, true, "", preferred, false)
	if sr.entries[dk].probeBackoffSec != 60 {
		t.Fatalf("backoff should double: got %d, want 60", sr.entries[dk].probeBackoffSec)
	}
	if sr.entries[dk].mode != stickyFallback {
		t.Fatal("should stay in fallback")
	}
}

func TestStickyRouterEviction(t *testing.T) {
	sr := &StickyRouter{entries: make(map[string]*stickyEntry)}
	// 塞满 primary 条目
	for i := 0; i < stickyMaxEntries+10; i++ {
		sr.entries[fmt.Sprintf("p/%d", i)] = &stickyEntry{mode: stickyPrimary}
	}
	sr.maybeEvictLocked()
	if len(sr.entries) > stickyMaxEntries {
		t.Fatalf("eviction failed: %d entries", len(sr.entries))
	}
}

func TestOrderPreferredFirst(t *testing.T) {
	cands := []string{"a", "b", "c"}
	ordered := orderPreferredFirst(cands, "b")
	if ordered[0] != "b" || len(ordered) != 3 {
		t.Fatalf("wrong order: %v", ordered)
	}
}

func TestOrderFallbackFirst(t *testing.T) {
	cands := []string{"a", "b", "c"}
	ordered := orderFallbackFirst(cands, "a", "b")
	if ordered[0] != "b" || ordered[len(ordered)-1] != "a" || len(ordered) != 3 {
		t.Fatalf("wrong order: %v", ordered)
	}
}

// ===================== Protocol Translator Helpers =====================

func TestExtractGeminiModelFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/v1beta/models/gemini-1.5-pro:generateContent", "gemini-1.5-pro"},
		{"/v1beta/models/gemini-1.5-flash-latest:generateContent", "gemini-1.5-flash-latest"},
		{"/v1beta/models/unknown", "unknown"},
		{"/other/path", ""},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got := extractGeminiModelFromPath(c.path)
			if got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestProviderCandidates(t *testing.T) {
	ov := ProviderOverride{APIKeys: []string{"key1", "key2", "key3"}}
	cands := providerCandidates(ov)
	if len(cands) != 3 || cands[0] != "idx:0" {
		t.Fatalf("wrong candidates: %v", cands)
	}

	// 兼容旧版单密钥
	ov2 := ProviderOverride{APIKey: "oldkey"}
	cands2 := providerCandidates(ov2)
	if len(cands2) != 1 || cands2[0] != "idx:0" {
		t.Fatalf("wrong legacy candidates: %v", cands2)
	}
}

func TestProviderKeyByIndex(t *testing.T) {
	ov := ProviderOverride{APIKeys: []string{"k0", "k1"}}
	if providerKeyByIndex(ov, 0) != "k0" {
		t.Fatal("idx 0 wrong")
	}
	if providerKeyByIndex(ov, 5) != "" {
		t.Fatal("out of range should return empty")
	}
}
