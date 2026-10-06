package main

// ===================== v3.2.2 性能升级 v1 测试 =====================
// 覆盖：日志常开句柄管线（写入/轮转/并发）、池化客户端复用、
// tier1 预编译正则行为不变、A/B 基准（旧 open-per-line vs 新常开句柄）。

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- 日志管线 ----

func fileLogTestSetup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	logFileMu.Lock()
	logFileDir = dir
	logHandles = map[string]*logHandle{}
	logFileMu.Unlock()
	t.Cleanup(func() {
		logFileMu.Lock()
		logFileDir = ""
		for p, h := range logHandles {
			h.f.Close()
			delete(logHandles, p)
		}
		logFileMu.Unlock()
	})
	return dir
}

func TestV322FileLogPersistentHandle(t *testing.T) {
	dir := fileLogTestSetup(t)
	for i := 0; i < 5; i++ {
		fileLog("audit", fmt.Sprintf("line-%d", i))
	}
	// 常开句柄：写入 5 行后句柄应已缓存且只有一个
	logFileMu.Lock()
	h, ok := logHandles["audit"]
	logFileMu.Unlock()
	if !ok || h == nil || h.f == nil {
		t.Fatal("句柄应常开缓存")
	}
	b, err := os.ReadFile(filepath.Join(dir, "audit-"+time.Now().Format("2006-01-02")+".log"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "\n"); got != 5 {
		t.Fatalf("应有 5 行, got %d", got)
	}
}

func TestV322FileLogDayRollover(t *testing.T) {
	dir := fileLogTestSetup(t)
	today := time.Now().Format("2006-01-02")
	prev := logDayFunc
	defer func() { logDayFunc = prev }()
	// 第一天：写入走 tars-2000-01-01.log
	logDayFunc = func() string { return "2000-01-01" }
	fileLog("tars", "day1-line")
	// 第二天（回到今天）：应轮转到 tars-<today>.log，旧句柄关闭
	logDayFunc = func() string { return today }
	fileLog("tars", "day2-line")
	b1, err := os.ReadFile(filepath.Join(dir, "tars-2000-01-01.log"))
	if err != nil || !strings.Contains(string(b1), "day1-line") {
		t.Fatalf("旧文件应含第一行: %v %q", err, b1)
	}
	b2, err := os.ReadFile(filepath.Join(dir, "tars-"+today+".log"))
	if err != nil || !strings.Contains(string(b2), "day2-line") {
		t.Fatalf("新文件应含第二行: %v %q", err, b2)
	}
	// 轮转后句柄应指向新日期
	logFileMu.Lock()
	h := logHandles["tars"]
	logFileMu.Unlock()
	if h == nil || h.day != today {
		t.Fatalf("轮转后句柄应指向新日期: %+v", h)
	}
}

func TestV322FileLogConcurrent(t *testing.T) {
	dir := fileLogTestSetup(t)
	const goroutines, per = 16, 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				fileLog("waf", fmt.Sprintf("g%d-i%d", g, i))
			}
		}(g)
	}
	wg.Wait()
	day := time.Now().Format("2006-01-02")
	b, err := os.ReadFile(filepath.Join(dir, "waf-"+day+".log"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "\n"); got != goroutines*per {
		t.Fatalf("并发写应无丢失: want %d got %d", goroutines*per, got)
	}
}

// ---- 池化客户端 ----

func TestV322PooledHTTPClientSharesTransport(t *testing.T) {
	c1 := pooledHTTPClient(5 * time.Second)
	c2 := pooledHTTPClient(9 * time.Second)
	if c1.Transport == nil || c2.Transport == nil {
		t.Fatal("池化客户端必须挂共享 Transport")
	}
	if fmt.Sprintf("%p", c1.Transport) != fmt.Sprintf("%p", c2.Transport) {
		t.Fatal("不同超时的池化客户端应共享同一 Transport（连接复用前提）")
	}
	if c1.Timeout != 5*time.Second || c2.Timeout != 9*time.Second {
		t.Fatal("超时应各自生效")
	}
}

func TestV322PooledHTTPClientReuse(t *testing.T) {
	// 同一 host 连续两次请求应复用连接（poolConnReused 递增）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c := pooledHTTPClient(5 * time.Second)
	for i := 0; i < 2; i++ {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if poolConnReused.Load() < 1 {
		t.Fatalf("第二次请求应命中空闲连接, reused=%d", poolConnReused.Load())
	}
}

func TestV322CustomToolTransportTuned(t *testing.T) {
	tr, ok := customToolClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("customToolClient 应保留独立 Transport（SSRF 隔离）")
	}
	if tr.MaxIdleConnsPerHost != 8 || tr.MaxIdleConns != 64 {
		t.Fatalf("customTool Transport 池参数应已调优: %+v", tr)
	}
	if tr.DialContext == nil {
		t.Fatal("SSRF 拨号校验必须保留")
	}
}

// ---- tier1 正则行为不变 ----

func TestV322Tier1RegexHoisted(t *testing.T) {
	var v map[string]interface{}
	if err := tier1ParseClixmlJSON(`<S>{"a":1}</S>`, &v); err != nil || v["a"] != float64(1) {
		t.Fatalf("CLIXML 解析行为应不变: %v %v", err, v)
	}
	if g := tier1ParseLspciGPU(`00:02.0 "VGA compatible controller" "Intel" "UHD Graphics"`); g != "Intel UHD Graphics" {
		t.Fatalf("lspci 解析行为应不变: %q", g)
	}
	kv := tier1ParseSPXML("<key>Model</key><string>Mac14,2</string>")
	if kv["Model"] != "Mac14,2" {
		t.Fatalf("plist 解析行为应不变: %v", kv)
	}
}

// ---- A/B 基准：旧 open-per-line vs 新常开句柄（同一文件、同机对照）----

// legacyFileLogPerLine v3.2.2 之前的实现：每行 open→write→close
func legacyFileLogPerLine(dir, prefix, line string) {
	name := filepath.Join(dir, fmt.Sprintf("%s-%s.log", prefix, time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line + "\n")
}

func BenchmarkV322AuditLogOldOpenPerLine(b *testing.B) {
	dir := b.TempDir()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		legacyFileLogPerLine(dir, "audit", fmt.Sprintf("ACTION=BENCH USER=u DETAIL=%d", i))
	}
}

func BenchmarkV322AuditLogNewPersistentHandle(b *testing.B) {
	dir := b.TempDir()
	logFileMu.Lock()
	logFileDir = dir
	logHandles = map[string]*logHandle{}
	logFileMu.Unlock()
	b.Cleanup(func() {
		logFileMu.Lock()
		logFileDir = ""
		for p, h := range logHandles {
			h.f.Close()
			delete(logHandles, p)
		}
		logFileMu.Unlock()
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fileLog("audit", fmt.Sprintf("ACTION=BENCH USER=u DETAIL=%d", i))
	}
}
