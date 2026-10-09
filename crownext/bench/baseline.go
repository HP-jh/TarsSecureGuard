package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Baseline 保存一组 benchmark 的基线结果
type Baseline struct {
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Results   map[string]Result `json:"results"`
}

// Regression 退化项
type Regression struct {
	Name        string
	Baseline    time.Duration
	Current     time.Duration
	DeltaPct    float64
	Worsened    bool
}

// NewBaseline 从当前 harness 创建基线
func NewBaseline(version string, results []Result) *Baseline {
	b := &Baseline{
		Version:   version,
		Timestamp: time.Now(),
		Results:   make(map[string]Result),
	}
	for _, r := range results {
		b.Results[r.Name] = r
	}
	return b
}

// SaveBaseline 保存基线到文件
func SaveBaseline(path string, b *Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadBaseline 从文件加载基线
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Compare 对比当前结果与基线，返回退化项
func Compare(current []Result, baseline *Baseline) []Regression {
	var regs []Regression
	for _, r := range current {
		base, ok := baseline.Results[r.Name]
		if !ok {
			continue
		}
		var delta float64
		if base.PerOp > 0 {
			delta = float64(r.PerOp-base.PerOp) / float64(base.PerOp) * 100
		}
		worsened := delta >= 5.0 // 5% 及以上视为退化
		if worsened {
			regs = append(regs, Regression{
				Name:     r.Name,
				Baseline: base.PerOp,
				Current:  r.PerOp,
				DeltaPct: delta,
				Worsened: true,
			})
		}
	}
	return regs
}

// CompareReport 生成对比报告文本
func CompareReport(regs []Regression) string {
	if len(regs) == 0 {
		return "✅ 无性能退化（阈值 5%）\n"
	}
	out := fmt.Sprintf("⚠️ 发现 %d 项性能退化（阈值 5%%）：\n", len(regs))
	out += fmt.Sprintf("%-40s %12s %12s %10s\n", "Name", "Baseline", "Current", "Delta%")
	for _, r := range regs {
		out += fmt.Sprintf("%-40s %12s %12s %9.1f%%\n", r.Name, r.Baseline, r.Current, r.DeltaPct)
	}
	return out
}
