package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// TrendPoint 趋势数据点
type TrendPoint struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	AvgPerOp  int64     `json:"avg_per_op_ns"`
}

// TrendReport 趋势看板数据
type TrendReport struct {
	Points    []TrendPoint          `json:"points"`
	ByBench   map[string][]TrendPoint `json:"by_bench"`
	Generated time.Time             `json:"generated"`
}

// BuildTrend 从多个基线构建趋势报告
func BuildTrend(baselines []*Baseline) *TrendReport {
	tr := &TrendReport{
		Points:    make([]TrendPoint, 0, len(baselines)),
		ByBench:   make(map[string][]TrendPoint),
		Generated: time.Now(),
	}

	for _, bl := range baselines {
		var total int64
		var count int
		for name, r := range bl.Results {
			total += r.PerOp.Nanoseconds()
			count++
			tr.ByBench[name] = append(tr.ByBench[name], TrendPoint{
				Version:   bl.Version,
				Timestamp: bl.Timestamp,
				AvgPerOp:  r.PerOp.Nanoseconds(),
			})
		}
		if count > 0 {
			tr.Points = append(tr.Points, TrendPoint{
				Version:   bl.Version,
				Timestamp: bl.Timestamp,
				AvgPerOp:  total / int64(count),
			})
		}
	}

	// 排序
	sort.Slice(tr.Points, func(i, j int) bool {
		return tr.Points[i].Timestamp.Before(tr.Points[j].Timestamp)
	})
	for _, pts := range tr.ByBench {
		sort.Slice(pts, func(i, j int) bool {
			return pts[i].Timestamp.Before(pts[j].Timestamp)
		})
	}
	return tr
}

// JSON 输出趋势报告 JSON
func (tr *TrendReport) JSON() ([]byte, error) {
	return json.MarshalIndent(tr, "", "  ")
}

// HTML 输出简易 HTML 趋势看板
func (tr *TrendReport) HTML() string {
	h := `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>TSG 性能趋势看板</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px}
h1{color:#1a1a1a}
table{width:100%;border-collapse:collapse;margin-top:20px}
th,td{padding:8px 12px;border:1px solid #ddd;text-align:left}
th{background:#f5f5f5}
tr:hover{background:#fafafa}
.regression{color:#c00}
.improvement{color:#080}
</style></head>
<body>
<h1>TSG 性能趋势看板</h1>
<p>生成时间: ` + tr.Generated.Format("2006-01-02 15:04:05") + `</p>
<h2>版本汇总</h2>
<table>
<tr><th>版本</th><th>时间</th><th>平均 per-op (ns)</th></tr>
`
	for _, p := range tr.Points {
		h += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%d</td></tr>\n",
			p.Version, p.Timestamp.Format("2006-01-02 15:04"), p.AvgPerOp)
	}
	h += `</table>
<h2>各基准项趋势</h2>
<table>
<tr><th>基准项</th><th>版本</th><th>per-op (ns)</th><th>趋势</th></tr>
`
	for name, pts := range tr.ByBench {
		for i, p := range pts {
			cls := ""
			label := "—"
			if i > 0 {
				prev := pts[i-1].AvgPerOp
				if prev > 0 {
					delta := float64(p.AvgPerOp-prev) / float64(prev) * 100
					if delta > 5 {
						cls = "regression"
						label = fmt.Sprintf("+%.1f%%", delta)
					} else if delta < -5 {
						cls = "improvement"
						label = fmt.Sprintf("%.1f%%", delta)
					} else {
						label = fmt.Sprintf("%.1f%%", delta)
					}
				}
			}
			h += fmt.Sprintf("<tr class=\"%s\"><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>\n",
				cls, name, p.Version, p.AvgPerOp, label)
		}
	}
	h += `</table>
</body></html>`
	return h
}

// WriteReport 将完整报告写入目录（JSON + HTML + baseline）
func WriteReport(dir string, harness *Harness, version string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// harness JSON
	j, err := harness.JSON()
	if err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/benchmark.json", j, 0644); err != nil {
		return err
	}

	// baseline
	bl := NewBaseline(version, harness.Results())
	if err := SaveBaseline(dir+"/baseline.json", bl); err != nil {
		return err
	}

	// report text
	if err := os.WriteFile(dir+"/report.txt", []byte(harness.Report()), 0644); err != nil {
		return err
	}

	return nil
}
