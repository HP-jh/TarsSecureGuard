package bench

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// Result 单条 benchmark 结果
type Result struct {
	Name        string        `json:"name"`
	N           int           `json:"n"`
	Duration    time.Duration `json:"duration_ns"`
	PerOp       time.Duration `json:"per_op_ns"`
	AllocsPerOp int64         `json:"allocs_per_op"`
	BytesPerOp  int64         `json:"bytes_per_op"`
}

// Harness 统一的 benchmark 收集器
type Harness struct {
	results []Result
}

// NewHarness 创建新的 harness
func NewHarness() *Harness {
	return &Harness{results: make([]Result, 0)}
}

// Run 执行单个 benchmark 并收集结果
//
// v4.7.0 修复：不再嵌套调用 testing.Benchmark——它内部会对全局 benchmarkLock
// 加锁，而外层若也处于 go test -bench 的框架中（BenchmarkHarness* 系列），
// 两层锁永远等不到对方，形成死锁（B8 v4.5.0 遗留问题：汇总基准在真实
// `go test -bench` 下必挂）。改为固定迭代次数 + 手动计时 + runtime.MemStats
// 采集内存分配，语义与原来等价（PerOp / AllocsPerOp / BytesPerOp），且
// 在 Test 与 Benchmark 两种外层环境下行为一致。
func (h *Harness) Run(name string, fn func(b *testing.B)) Result {
	const iterations = 1000
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	t0 := time.Now()
	fn(&testing.B{N: iterations})
	elapsed := time.Since(t0)
	runtime.ReadMemStats(&after)

	r := Result{
		Name:     name,
		N:        iterations,
		Duration: elapsed,
		PerOp:    elapsed / iterations,
	}
	if iterations > 0 {
		r.AllocsPerOp = int64(after.Mallocs-before.Mallocs) / iterations
		r.BytesPerOp = int64(after.TotalAlloc-before.TotalAlloc) / iterations
	}
	h.results = append(h.results, r)
	return r
}

// Results 返回所有结果
func (h *Harness) Results() []Result {
	return h.results
}

// Report 生成文本报告
func (h *Harness) Report() string {
	out := "=== Benchmark Report ===\n"
	out += fmt.Sprintf("%-40s %10s %12s %12s %12s\n", "Name", "N", "PerOp", "Allocs/op", "Bytes/op")
	for _, r := range h.results {
		out += fmt.Sprintf("%-40s %10d %12s %12d %12d\n", r.Name, r.N, r.PerOp, r.AllocsPerOp, r.BytesPerOp)
	}
	return out
}

// JSON 生成 JSON 报告
func (h *Harness) JSON() ([]byte, error) {
	return json.MarshalIndent(h.results, "", "  ")
}

// Summary 返回汇总（总测试数、平均 per-op）
func (h *Harness) Summary() map[string]any {
	var totalOps int
	var totalPerOp time.Duration
	for _, r := range h.results {
		totalOps += r.N
		totalPerOp += r.PerOp
	}
	avg := time.Duration(0)
	if len(h.results) > 0 {
		avg = totalPerOp / time.Duration(len(h.results))
	}
	return map[string]any{
		"total_benchmarks": len(h.results),
		"total_iterations": totalOps,
		"avg_per_op_ns":    avg.Nanoseconds(),
	}
}
