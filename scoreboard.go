package main

// v3.0.0 C 线：模型评分系统（scoreBoard 模块）
//
// 设计依据：架构方案第三节 C 线 + 锦衣卫附加意见 D（防伪造）：
//   - 评分 = 运行时分（成功率×时延归一）融合 lm-eval-harness 离线评测分
//   - lm-eval 结果由 Python 边车（Tier 2，可选安装）产出 JSON 后导入，
//     v3.0.0 不捆绑 Python；未导入时仅展示运行时分并明确标注"无离线评测数据"
//   - 诚实标注：lm-eval 分数为"相对参考"（同一任务集内的相对排名），
//     绝不冒充绝对能力值 —— UI 与 API 均带 relative=true 标记
//   - 运行时分数据源 = smartRouter 的 arm 统计（同源防伪造：非 admin 已降权）

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"sync"
)

// ===================== lm-eval 导入 =====================

// LMEvalEntry lm-eval-harness 边车产出的单模型评测条目
type LMEvalEntry struct {
	Model   string  `json:"model"`           // 模型名（与 TSG 模型注册名对齐）
	Taskset string  `json:"taskset"`         // 任务集名（如 cn_ceval_mini）
	AccAvg  float64 `json:"acc_avg"`         // 平均准确率（0-1）
	Note    string  `json:"note,omitempty"`  // 边车备注
}

var (
	sbMu      sync.Mutex
	sbLMEval  = map[string]LMEvalEntry{} // model -> entry
	sbLoaded  bool
)

const sbImportFile = "scoreboard/lmeval_results.json"

// sbLoadLMEval 一次性导入 lm-eval 结果（启动时 + 手动刷新）
func sbLoadLMEval() {
	b, err := os.ReadFile(sbImportFile)
	if err != nil {
		return
	}
	var entries []LMEvalEntry
	if json.Unmarshal(b, &entries) != nil {
		auditLog("SCOREBOARD_IMPORT_FAIL", "system", "lmeval_results.json 解析失败")
		return
	}
	sbMu.Lock()
	defer sbMu.Unlock()
	sbLMEval = map[string]LMEvalEntry{}
	for _, e := range entries {
		if e.Model != "" {
			sbLMEval[e.Model] = e
		}
	}
	sbLoaded = true
	auditLog("SCOREBOARD_IMPORT", "system", "lm-eval-harness 离线评测结果已导入（相对参考）")
}

// ===================== 融合评分 =====================

// sbRuntimeScore 运行时分：0-100（成功率 70% 权重 + 时延归一 30% 权重）
func sbRuntimeScore(arm *rtArm) (float64, uint64) {
	if arm == nil || arm.Calls == 0 {
		return 0, 0
	}
	succRate := float64(arm.Successes) / float64(arm.Calls)
	latScore := 0.0
	if arm.Successes > 0 && arm.AvgLatMs > 0 {
		// 200ms 满分，10s 零分的线性归一
		latScore = 1 - arm.AvgLatMs/10000
		if latScore < 0 {
			latScore = 0
		}
		if arm.AvgLatMs <= 200 {
			latScore = 1
		}
	}
	return (succRate*0.7 + latScore*0.3) * 100, arm.Calls
}

// sbFused 融合总分：运行时分 ×0.6 + lm-eval ×0.4（无离线数据时运行时分 ×1.0 并标注）
func sbFused(arm *rtArm, model string) map[string]interface{} {
	rt, calls := sbRuntimeScore(arm)
	sbMu.Lock()
	lm, hasLM := sbLMEval[model]
	sbMu.Unlock()
	fused := rt
	relative := false
	if hasLM {
		fused = rt*0.6 + lm.AccAvg*100*0.4
		relative = true
	}
	return map[string]interface{}{
		"model":       model,
		"runtimeScore": round2(rt),
		"calls":       calls,
		"successes":   armSuccesses(arm),
		"avgLatMs":    round2(armLat(arm)),
		"lmevalScore": map[string]interface{}{"present": hasLM, "accAvg": round2(lm.AccAvg), "taskset": lm.Taskset, "relative": true},
		"fusedScore":  round2(fused),
		"fusedBasis":  map[bool]string{true: "runtime×0.6 + lm-eval(相对参考)×0.4", false: "仅运行时分（无离线评测数据）"}[hasLM],
		"relativeRef": relative,
	}
}

func armSuccesses(a *rtArm) uint64 { if a == nil { return 0 }; return a.Successes }
func armLat(a *rtArm) float64     { if a == nil { return 0 }; return a.AvgLatMs }
func round2(f float64) float64    { return float64(int(f*100+0.5)) / 100 }

// ===================== 管理端点 =====================

// handleScoreBoard 模型评分榜（admin；数据源 = smartRouter arms + lm-eval 导入）
func handleScoreBoard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// 手动刷新导入（边车跑完评测后调用）
		sbLoadLMEval()
	}
	rtMu.Lock()
	arms := map[string]*rtArm{}
	for k, v := range rtSt.Arms {
		cp := *v
		arms[k] = &cp
	}
	rtMu.Unlock()
	var rows []map[string]interface{}
	for model, arm := range arms {
		rows = append(rows, sbFused(arm, model))
	}
	// 未出现在 arms 但有 lm-eval 数据的模型也列出（离线评测可先于运行）
	sbMu.Lock()
	for model, lm := range sbLMEval {
		if _, ok := arms[model]; !ok {
			rows = append(rows, sbFused(nil, model))
			_ = lm
		}
	}
	sbMu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		return rows[i]["fusedScore"].(float64) > rows[j]["fusedScore"].(float64)
	})
	writeJSON(w, map[string]interface{}{
		"rows":       rows,
		"importFile": sbImportFile,
		"disclaimer": "lm-eval 分数为同任务集内相对参考，非绝对能力值；运行时分基于网关真实调用统计",
	})
}

// ===================== route_preview（MCP 工具数据源） =====================

// routePreview 给定模型名，预演两阶段路由决策（不实际调用），admin/MCP 专用
func routePreview(model string, role string) map[string]interface{} {
	cands := rtCandidates()
	pick, explored := rtPickPreview(cands)
	return map[string]interface{}{
		"inputModel":  model,
		"stage":       "static-then-bandit",
		"candidates":  cands,
		"previewPick": pick,
		"explored":    explored,
		"epsilon":     rtCurrentEpsilon(),
		"role":        role,
	}
}

// rtPickPreview 只读版 rtPick（不改变状态、不消耗探索预算）
func rtPickPreview(candidates []string) (string, bool) {
	rtMu.Lock()
	defer rtMu.Unlock()
	if len(candidates) == 0 {
		return "", false
	}
	if len(candidates) == 1 {
		return candidates[0], false
	}
	eps := rtSt.Epsilon
	best, bestScore := "", -1e9
	for _, c := range candidates {
		arm := rtSt.Arms[c]
		score := 0.5
		if arm != nil && arm.Calls > 0 {
			score = arm.RewSum / float64(arm.Calls)
		}
		if score > bestScore {
			best, bestScore = c, score
		}
	}
	// 预演会探索吗：以当前 ε 概率说明（不实际掷骰，避免双重随机）
	return best, eps > 0.05
}
