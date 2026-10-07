package main

// v3.2.0 性能基准 harness（v3.2.0 树）。
// 与 bench/base305 完全同口径：同一 httptest mock 上游、同消息规模、
// 顺序 300 + 并发 16×50。走 v3.2.0 出站链路 callProviderChat
// （共享连接池 + 协议适配缓存；响应缓存按场景开关）。
// 运行：go test -run 'TestBenchOutboundV32|TestBenchCacheHit|TestBenchPoolReuse' -v -count=1
//
// 注意：本文件同时是可复现基准（README「性能」一节的测量方法），随源码一起交付。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func v32BenchPercentile(us []float64, p float64) float64 {
	if len(us) == 0 {
		return 0
	}
	s := make([]float64, len(us))
	copy(s, us)
	sort.Float64s(s)
	idx := int(float64(len(s)) * p)
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func v32BenchStats(us []float64) (mean, p50, p99 float64) {
	if len(us) == 0 {
		return 0, 0, 0
	}
	var sum float64
	for _, v := range us {
		sum += v
	}
	return sum / float64(len(us)), v32BenchPercentile(us, 0.5), v32BenchPercentile(us, 0.99)
}

func v32BenchSetup(t *testing.T) (srv *httptest.Server, spec ProviderSpec, restore func()) {
	if err := loadProviderRegistry(); err != nil {
		t.Fatalf("loadProviderRegistry: %v", err)
	}
	initPooledClients(32)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"` + strings.Repeat("ok", 128) + `"}}]}`))
	}))
	saved := cfg.V32Config.Providers
	savedCache := cfg.V32Config.ResponseCache
	cfg.V32Config.Providers = map[string]ProviderOverride{
		"openai": {APIKey: "bench-key", BaseURL: srv.URL},
	}
	spec, _ = providerSpec("openai")
	return srv, spec, func() {
		cfg.V32Config.Providers = saved
		cfg.V32Config.ResponseCache = savedCache
		v32CacheInvalidate("bench_teardown")
	}
}

func v32BenchMsgs(i int) []Message {
	return []Message{
		{Role: "system", Content: "你是乐于助人的助手。"},
		{Role: "user", Content: fmt.Sprintf("bench-%04d ", i) + strings.Repeat("x ", 48)},
	}
}

// 场景 A：响应缓存关闭——与 v3.0.5 基线同口径（纯链路延迟，含连接池收益）
func TestBenchOutboundV32(t *testing.T) {
	srv, spec, restore := v32BenchSetup(t)
	defer srv.Close()
	defer restore()
	noCache := false
	cfg.V32Config.ResponseCache.Enabled = &noCache

	for i := 0; i < 20; i++ {
		if _, err := callProviderChat(spec, "gpt-4o", v32BenchMsgs(i), "bench", ""); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}

	seq := make([]float64, 0, 300)
	for i := 0; i < 300; i++ {
		st := time.Now()
		if _, err := callProviderChat(spec, "gpt-4o", v32BenchMsgs(i), "bench", ""); err != nil {
			t.Fatalf("seq: %v", err)
		}
		seq = append(seq, float64(time.Since(st).Microseconds()))
	}
	mean, p50, p99 := v32BenchStats(seq)
	t.Logf("RESULT seq n=300 mean_us=%.0f p50_us=%.0f p99_us=%.0f", mean, p50, p99)

	var mu sync.Mutex
	conc := make([]float64, 0, 800)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			local := make([]float64, 0, 50)
			for i := 0; i < 50; i++ {
				st := time.Now()
				if _, err := callProviderChat(spec, "gpt-4o", v32BenchMsgs(w*1000+i), "bench", ""); err != nil {
					t.Errorf("conc: %v", err)
					return
				}
				local = append(local, float64(time.Since(st).Microseconds()))
			}
			mu.Lock()
			conc = append(conc, local...)
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	cmean, cp50, cp99 := v32BenchStats(conc)
	t.Logf("RESULT conc n=%d mean_us=%.0f p50_us=%.0f p99_us=%.0f", len(conc), cmean, cp50, cp99)
}

// 场景 B：响应缓存命中率——两个口径都测，如实报告：
//   B1 混合负载（60% 重复请求、200 模板池）：命中率上限受负载结构限制
//   B2 模板型负载（70% 重复请求、150 模板池）：网关典型场景（系统提示词/常用模板复用）
func TestBenchCacheHit(t *testing.T) {
	srv, spec, restore := v32BenchSetup(t)
	defer srv.Close()
	defer restore()

	// B1：500 次请求，60% 来自重复 prompt、40% 唯一
	v32CacheInvalidate("bench_cache_b1")
	for i := 0; i < 500; i++ {
		var msgs []Message
		if i%5 < 3 {
			msgs = v32BenchMsgs(i % 200)
		} else {
			msgs = v32BenchMsgs(100000 + i)
		}
		if _, err := callProviderChat(spec, "gpt-4o", msgs, "bench-cache", ""); err != nil {
			t.Fatalf("b1 req %d: %v", i, err)
		}
	}
	st := cacheStats()
	if rc, ok := st["responseCache"].(map[string]interface{}); ok {
		t.Logf("RESULT b1_mixed_60pct_repeat responseHitRatePct=%v hits=%v misses=%v",
			rc["hitRatePct"], rc["hits"], rc["misses"])
	}

	// B2：500 次请求，70% 来自 150 个模板 prompt、30% 唯一
	v32CacheInvalidate("bench_cache_b2")
	for i := 0; i < 500; i++ {
		var msgs []Message
		if i%10 < 7 {
			msgs = v32BenchMsgs(i % 150)
		} else {
			msgs = v32BenchMsgs(200000 + i)
		}
		if _, err := callProviderChat(spec, "gpt-4o", msgs, "bench-cache", ""); err != nil {
			t.Fatalf("b2 req %d: %v", i, err)
		}
	}
	st2 := cacheStats()
	t.Logf("RESULT b2_template_70pct_repeat stats=%v", st2)
}

// 场景 C：连接池复用率（v3.2.0 专属指标；16 并发 × 50 = 800 次出站）
func TestBenchPoolReuse(t *testing.T) {
	srv, spec, restore := v32BenchSetup(t)
	defer srv.Close()
	defer restore()
	noCache := false
	cfg.V32Config.ResponseCache.Enabled = &noCache

	beforeNew := poolConnNew.Load()
	beforeReused := poolConnReused.Load()
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := callProviderChat(spec, "gpt-4o", v32BenchMsgs(w*100000+i), "bench-pool", ""); err != nil {
					t.Errorf("pool: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	t.Logf("RESULT pool connNew=%d connReused=%d reuseRatePct=%.2f",
		poolConnNew.Load()-beforeNew, poolConnReused.Load()-beforeReused, poolReuseRatePct())
}
