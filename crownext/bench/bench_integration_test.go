package bench

import (
	"os"
	"testing"
	"time"
)

func TestHarnessCollectAndReport(t *testing.T) {
	h := NewHarness()
	h.Run("Test/Fast", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = i * 2
		}
	})
	h.Run("Test/Slow", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sum := 0
			for j := 0; j < 100; j++ {
				sum += j
			}
			_ = sum
		}
	})

	if len(h.Results()) != 2 {
		t.Fatalf("expected 2 results, got %d", len(h.Results()))
	}

	report := h.Report()
	if report == "" {
		t.Fatal("report should not be empty")
	}

	j, err := h.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(j) == 0 {
		t.Fatal("json should not be empty")
	}

	summary := h.Summary()
	if summary["total_benchmarks"] != 2 {
		t.Fatalf("expected 2 benchmarks in summary, got %v", summary["total_benchmarks"])
	}
}

func TestBaselineSaveLoad(t *testing.T) {
	h := NewHarness()
	h.Run("Test/Base", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = i * 2
		}
	})

	bl := NewBaseline("v4.4.0", h.Results())
	path := "/tmp/tsg-bench-test-baseline.json"
	defer os.Remove(path)

	if err := SaveBaseline(path, bl); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != "v4.4.0" {
		t.Fatalf("expected version v4.4.0, got %s", loaded.Version)
	}
	if len(loaded.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(loaded.Results))
	}
}

func TestCompareRegression(t *testing.T) {
	base := &Baseline{
		Version:   "v4.4.0",
		Timestamp: time.Now(),
		Results: map[string]Result{
			"A": {Name: "A", PerOp: 100},
			"B": {Name: "B", PerOp: 200},
		},
	}
	current := []Result{
		{Name: "A", PerOp: 110}, // +10% 不触发退化（阈值 5% 以上才触发，等等，10% > 5%，应该触发）
		{Name: "B", PerOp: 210}, // +5% 刚好触发退化
	}

	regs := Compare(current, base)
	if len(regs) != 2 {
		t.Fatalf("expected 2 regressions, got %d", len(regs))
	}
	if regs[0].Name != "A" && regs[0].Name != "B" {
		t.Fatalf("unexpected regression name: %s", regs[0].Name)
	}
}

func TestCompareNoRegression(t *testing.T) {
	base := &Baseline{
		Results: map[string]Result{
			"A": {Name: "A", PerOp: 100},
		},
	}
	current := []Result{
		{Name: "A", PerOp: 102}, // +2% 不触发退化
	}
	regs := Compare(current, base)
	if len(regs) != 0 {
		t.Fatalf("expected 0 regressions, got %d", len(regs))
	}
}

func TestTrendReport(t *testing.T) {
	bl1 := &Baseline{
		Version:   "v4.4.0",
		Timestamp: time.Now().Add(-24 * time.Hour),
		Results: map[string]Result{
			"A": {Name: "A", PerOp: 100},
		},
	}
	bl2 := &Baseline{
		Version:   "v4.4.1",
		Timestamp: time.Now(),
		Results: map[string]Result{
			"A": {Name: "A", PerOp: 90},
		},
	}

	tr := BuildTrend([]*Baseline{bl1, bl2})
	if len(tr.Points) != 2 {
		t.Fatalf("expected 2 trend points, got %d", len(tr.Points))
	}
	if len(tr.ByBench["A"]) != 2 {
		t.Fatalf("expected 2 points for A, got %d", len(tr.ByBench["A"]))
	}

	_, err := tr.JSON()
	if err != nil {
		t.Fatal(err)
	}

	html := tr.HTML()
	if html == "" {
		t.Fatal("html should not be empty")
	}
}

func TestWriteReport(t *testing.T) {
	h := NewHarness()
	h.Run("Test/W", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = i * 2
		}
	})

	dir := "/tmp/tsg-bench-test-report"
	defer os.RemoveAll(dir)

	if err := WriteReport(dir, h, "v4.4.0"); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(dir + "/benchmark.json"); err != nil {
		t.Fatal("benchmark.json not found")
	}
	if _, err := os.Stat(dir + "/baseline.json"); err != nil {
		t.Fatal("baseline.json not found")
	}
	if _, err := os.Stat(dir + "/report.txt"); err != nil {
		t.Fatal("report.txt not found")
	}
}
