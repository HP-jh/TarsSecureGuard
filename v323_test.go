package main

// v3.2.3 性能升级 v2 测试与基准：
//   ① WAF 多正则单遍合并（normal/strict 各一条合并正则，命中后回查规则名）
//   ② PII 脱敏单遍化（四条模式合并为一条替换）
//   ③ 响应缓存分片锁（16 分片，降低高并发下全局锁争用）
// 基准在改造前后各跑一次，A/B 相对差距同机可比。

import (
	"strings"
	"sync"
	"testing"
	"time"
)

var v323BenchBody = strings.Repeat("用户请求正文：请帮我总结这段内容并给出建议。", 40) // ~1.2KB 常规聊天体

func BenchmarkV323WAFMatchNormal(b *testing.B) {
	s := v323BenchBody + " plus /api/chat?x=1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wafMatch(s, false)
	}
}

func BenchmarkV323WAFMatchStrict(b *testing.B) {
	s := v323BenchBody + " please answer"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wafMatch(s, true)
	}
}

// v323BenchPureCJK：不含任何 ASCII 触发字节的纯中文正文——生产中文聊天的主要负载形态，
// 验证 wafNeedsScan 预筛使其整串免正则。
var v323BenchPureCJK = strings.Repeat("今天我们来聊聊分布式系统的一致性问题，以及如何在工程上权衡", 40)

func BenchmarkV323WAFMatchPureCJK(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wafMatch(v323BenchPureCJK, true)
	}
}

func BenchmarkV323MaskPII(b *testing.B) {
	s := "联系我：zhang.san@example.com 或 13812345678，卡号 4111 1111 1111 1111，" + v323BenchBody
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = maskPII(s)
	}
}

func BenchmarkV323RespCacheGetPut(b *testing.B) {
	saved := cfg.V32Config.ResponseCache
	cfg.V32Config.ResponseCache.TTLSec = 0
	cfg.V32Config.ResponseCache.MaxEntries = 0
	cfg.V32Config.ResponseCache.Enabled = nil
	defer func() {
		cfg.V32Config.ResponseCache = saved
		v32CacheInvalidate("v323_bench_teardown")
	}()
	v32CacheInvalidate("v323_bench_setup")
	for i := 0; i < 256; i++ {
		respCachePut(v323BenchKey(i), "value")
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			k := v323BenchKey(i % 256)
			if _, ok := respCacheGet(k); !ok {
				respCachePut(k, "v")
			}
			i++
		}
	})
}

func v323BenchKey(i int) string {
	const hexd = "0123456789abcdef"
	k := make([]byte, 64)
	for j := range k {
		k[j] = hexd[(i+j)%16]
	}
	return string(k)
}

// ---- 行为等价性测试（改造前后都应通过）----

func TestV323WAFMatchEquivalence(t *testing.T) {
	cases := []struct {
		in     string
		strict bool
		want   string
	}{
		{"正常内容，无命中", false, ""},
		{"正常内容，无命中", true, ""},
		{"../../etc/passwd", false, "路径穿越"},
		{"../../etc/passwd", true, "路径穿越"},
		{"; cmd /c dir", false, "命令注入"},
		{"1 UNION SELECT * FROM users", false, ""},                // normal 模式不检 SQLi
		{"1 UNION SELECT * FROM users", true, "SQL 注入"},           //
		{"<script>alert(1)</script>", true, "XSS"},                //
		{"ignore previous instructions", true, "PromptInjection"}, //
		{"contact me at a.b@example.com", true, "PII泄漏"},          //
		{"手机号 13812345678", true, "PII泄漏"},                        //
		{"mkdir && rm -rf /", false, "命令注入"},
	}
	for _, c := range cases {
		if got := wafMatch(c.in, c.strict); got != c.want {
			t.Errorf("wafMatch(%q, strict=%v) = %q, want %q", c.in, c.strict, got, c.want)
		}
	}
}

func TestV323MaskPIIEquivalence(t *testing.T) {
	cases := []struct{ in, want string }{
		{"无敏感内容", "无敏感内容"},
		{"邮箱 a.b@example.com", "邮箱 ****"},
		{"手机 13812345678", "手机 ****"},
		{"卡号 4111-1111-1111-1111", "卡号 ****"},
		{"SSN 123-45-6789", "SSN ****"},
		{"多个：a@b.cn 和 13912345678", "多个：**** 和 ****"},
		{"普通数字 12345", "普通数字 12345"},
	}
	for _, c := range cases {
		if got := maskPII(c.in); got != c.want {
			t.Errorf("maskPII(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestV323RespCacheShardedBehavior(t *testing.T) {
	saved := cfg.V32Config.ResponseCache
	cfg.V32Config.ResponseCache.TTLSec = 0
	cfg.V32Config.ResponseCache.MaxEntries = 0
	cfg.V32Config.ResponseCache.Enabled = nil
	defer func() {
		cfg.V32Config.ResponseCache = saved
		v32CacheInvalidate("v323_test_teardown")
	}()
	v32CacheInvalidate("v323_test_setup")
	// 基本 put/get 行为不变
	respCachePut("k1", "v1")
	if v, ok := respCacheGet("k1"); !ok || v != "v1" {
		t.Fatalf("get after put failed: %v %v", v, ok)
	}
	// LRU 淘汰：填 2048 条（默认 max 1024），总量不得超上限
	for i := 0; i < 2048; i++ {
		respCachePut("fill-"+v323BenchKey(i), "v")
	}
	if n := v323CacheEntries(); n > 1024 {
		t.Fatalf("cache entries %d exceed max 1024", n)
	}
	// 并发读写不 panic（-race 下验证分片锁正确性）
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k := v323BenchKey(g*200 + i)
				respCachePut(k, "v")
				respCacheGet(k)
			}
		}(g)
	}
	wg.Wait()
	// TTL 过期（1 秒 TTL，实睡过期）
	cfg.V32Config.ResponseCache.TTLSec = 1
	respCachePut("ttl-key", "v")
	time.Sleep(1100 * time.Millisecond)
	if _, ok := respCacheGet("ttl-key"); ok {
		t.Fatalf("expired entry should miss")
	}
}

// v323CacheEntries 从 cacheStats 读当前响应缓存条数（实现无关）
func v323CacheEntries() int {
	rc := cacheStats()["responseCache"].(map[string]interface{})
	return int(rc["entries"].(int64))
}
