// v4.7.6 B18 性能：scannerUAMatch 合并正则 + sync.Map 缓存
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestV476VersionBumped(t *testing.T) {
	if version != "4.8.0" {
		t.Fatalf("version expected 4.7.6, got %s", version)
	}
}

// TestV476ScannerUAMatchBasic 命中/不命中/大小写不敏感必须正确
func TestV476ScannerUAMatchBasic(t *testing.T) {
	cases := []struct {
		ua  string
		hit bool
	}{
		{"sqlmap/1.5.2", true},
		{"nikto/2.5", true},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", false},
		{"curl/7.81.0", true},         // 黑名单里有 curl/
		{"Python-Requests/2.31.0", true}, // 大小写不敏感必须命中
		{"", false},
		{"SAFE_BROWSER", false},
		{"NMAP SCRIPTING ENGINE", true}, // 大小写不敏感 + 多词关键词
	}
	for _, c := range cases {
		got := scannerUAMatch(c.ua)
		if c.hit && got == "" {
			t.Errorf("UA %q 应命中, got empty", c.ua)
		}
		if !c.hit && got != "" {
			t.Errorf("UA %q 不应命中, got %q", c.ua, got)
		}
	}
}

// TestV476ScannerUAMatchCache 快路径：同一 UA 第二次必须命中缓存（结果不变）
func TestV476ScannerUAMatchCache(t *testing.T) {
	ua := "Mozilla/5.0 (X11; BurpSuite)"
	first := scannerUAMatch(ua)
	if first == "" {
		t.Fatal("首次扫描应命中 burpsuite")
	}
	// 缓存项存在性
	if v, ok := scannerUACache.Load(ua); !ok {
		t.Error("缓存项未写入")
	} else if v.(string) == "" {
		t.Error("缓存项存了空串但首次匹配非空")
	}
	second := scannerUAMatch(ua)
	if second != first {
		t.Errorf("缓存前后结果不一致: %q vs %q", first, second)
	}
}

// TestV476ScannerUAMatchTooLong 超长 UA 走 miss 路径（防 DoS）
func TestV476ScannerUAMatchTooLong(t *testing.T) {
	// 超过 scannerUACap 的 UA 直接返回 ""，且不入缓存
	ua := strings.Repeat("A", scannerUACap+1) + "sqlmap"
	if got := scannerUAMatch(ua); got != "" {
		t.Errorf("超长 UA 应被截断为 miss, got %q", got)
	}
	// 也不入缓存
	if _, ok := scannerUACache.Load(ua); ok {
		t.Error("超长 UA 不应入缓存")
	}
}

// TestV476ScannerUAMatchConcurrent 并发安全
func TestV476ScannerUAMatchConcurrent(t *testing.T) {
	uas := []string{
		"sqlmap/1.5.2", "nikto/2.5", "curl/7.81.0",
		"Mozilla/5.0", "nmap scripting engine",
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ua := uas[i%len(uas)]
			_ = scannerUAMatch(ua)
		}(i)
	}
	wg.Wait()
}

// TestV476WAFCheckNormalUAStillPass 正常 UA 走 WAF 完整流程不应被拦
func TestV476WAFCheckNormalUAStillPass(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	if reason := wafCheck(req); reason != "" {
		t.Errorf("正常 Chrome UA 不应被拦, got %q", reason)
	}
}

// TestV476WAFCheckScannerUAStillBlocked 扫描器 UA 仍应被 WAF 拦截
func TestV476WAFCheckScannerUAStillBlocked(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("User-Agent", "sqlmap/1.5.2#stable")
	reason := wafCheck(req)
	if reason == "" {
		t.Fatal("sqlmap UA 必须被 WAF 拦截")
	}
	if !strings.Contains(reason, "User-Agent") {
		t.Errorf("拦截原因应提到 User-Agent, got %q", reason)
	}
}

// TestV476ScannerUAMatchFasterThanLoop 性能回归：合并正则 + 缓存应该比纯循环快
func TestV476ScannerUAMatchFasterThanLoop(t *testing.T) {
	// 1 万次同一 UA（常见浏览器）：纯循环会跑 1 万次完整 ToLower + 30 次 Contains
	// 合并正则 + 缓存：第 1 次 regex 匹配 + sync.Map Store，后续 9999 次是 sync.Map Load
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	N := 10000
	start := time.Now()
	for i := 0; i < N; i++ {
		_ = scannerUAMatch(ua)
	}
	elapsed := time.Since(start)
	// 1 万次同一 UA 应在 100ms 内完成（缓存命中）
	if elapsed > 100*time.Millisecond {
		t.Errorf("缓存路径 1万次 %v，期望 < 100ms", elapsed)
	}
	t.Logf("10000x 缓存命中耗时 %v", elapsed)
}
