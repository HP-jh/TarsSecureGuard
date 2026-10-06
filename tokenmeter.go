package main

// ===================== v3.4.0 轻量 Token 测量器 =====================
//
// 用户诉求（项 2）：「内置轻量级 Token 测量器，实时反馈每次调用的成本」。
// 设计：
//   - 埋点在 routeChatEx 出口（命名返回值 defer），所有聊天路径
//     （本地 / LM Studio / Ollama / 云端 provider / custom 协议）统一覆盖，
//     成功与失败都记账（失败 usage 为 0 不计成本）
//   - 计价三层：config v34.pricing（override）> 注册表 modelPricing（精确模型）
//     > 注册表 pricing（provider 默认）；无定价的模型只记 tokens 不计金额
//     （本地模型免费，金额 0）
//   - 存储：内存环形缓冲（2000 条）+ 聚合计（最近 8 天 / 按模型），
//     进程重启清零——测量器是运行时观测面，不做持久化账本（与配额、审计分离）
//   - API（tokenMeter 模块，默认开）：
//       GET  /api/admin/v34/meter        汇总 + 最近明细 + 按模型 top
//       POST /api/admin/v34/meter        清零
//       POST /api/v34/meter/estimate     轻量估算：文本 → tokens → 成本参考
//       GET  /api/v34/meter/savings      工具链路降耗收益

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Pricing 模型定价（USD / 1M tokens）
type Pricing struct {
	Input  float64 `json:"input"`
	Output float64 `json:"output"`
}

// MeterEntry 单次调用计量记录
type MeterEntry struct {
	Time     string  `json:"time"`  // RFC3339
	Model    string  `json:"model"` //实际路由到的模型
	Backend  string  `json:"backend"`
	Provider string  `json:"provider,omitempty"`
	Prompt   int64   `json:"prompt"`
	Complete int64   `json:"complete"`
	Total    int64   `json:"total"`
	CostUSD  float64 `json:"cost"`
	Priced   bool    `json:"priced"` // 是否有定价（false = 免费本地 / 未登记价格）
	Error    bool    `json:"error,omitempty"`
}

const meterRingSize = 2000

var (
	meterMu      sync.Mutex
	meterRing    = make([]MeterEntry, 0, meterRingSize)
	meterStats   = map[string]*meterAgg{} // key: day (2006-01-02)，保留最近 8 天
	meterByModel = map[string]*meterAgg{} // key: model
)

type meterAgg struct {
	Calls    int64   `json:"calls"`
	Errors   int64   `json:"errors"`
	Prompt   int64   `json:"prompt"`
	Complete int64   `json:"complete"`
	Total    int64   `json:"total"`
	CostUSD  float64 `json:"cost"`
}

func (a *meterAgg) add(e MeterEntry) {
	a.Calls++
	if e.Error {
		a.Errors++
	}
	a.Prompt += e.Prompt
	a.Complete += e.Complete
	a.Total += e.Total
	a.CostUSD += e.CostUSD
}

func (a *meterAgg) clone() *meterAgg {
	return &meterAgg{a.Calls, a.Errors, a.Prompt, a.Complete, a.Total, a.CostUSD}
}

// meterRecord 记一条调用计量（routeChatEx defer 出口统一调用）
func meterRecord(e MeterEntry) {
	if e.Time == "" {
		e.Time = time.Now().Format(time.RFC3339)
	}
	meterMu.Lock()
	defer meterMu.Unlock()
	if len(meterRing) >= meterRingSize {
		copy(meterRing, meterRing[1:])
		meterRing[len(meterRing)-1] = e
	} else {
		meterRing = append(meterRing, e)
	}
	day := time.Now().Format("2006-01-02")
	if a, ok := meterStats[day]; ok {
		a.add(e)
	} else {
		a := &meterAgg{}
		a.add(e)
		meterStats[day] = a
		if len(meterStats) > 8 { // 只保留最近 8 天聚合
			keys := make([]string, 0, len(meterStats))
			for k := range meterStats {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys[:len(keys)-8] {
				delete(meterStats, k)
			}
		}
	}
	if a, ok := meterByModel[e.Model]; ok {
		a.add(e)
	} else {
		a := &meterAgg{}
		a.add(e)
		meterByModel[e.Model] = a
	}
}

// pricingFor 定价三层：config v34.pricing override > registry modelPricing > registry pricing
func pricingFor(pid, model string) (Pricing, bool) {
	// override：provider/model 全名 > 裸模型名
	cfgMu.RLock()
	if cfg.V34Config.Pricing.Overrides != nil {
		if p, ok := cfg.V34Config.Pricing.Overrides[pid+"/"+model]; ok && p != nil {
			cfgMu.RUnlock()
			return *p, true
		}
		if p, ok := cfg.V34Config.Pricing.Overrides[model]; ok && p != nil {
			cfgMu.RUnlock()
			return *p, true
		}
	}
	cfgMu.RUnlock()
	// registry
	if pid != "" {
		if spec, ok := providerSpec(pid); ok {
			if p, ok2 := spec.ModelPricing[model]; ok2 && p != nil {
				return *p, true
			}
			if spec.Pricing != nil {
				return *spec.Pricing, true
			}
		}
	}
	return Pricing{}, false
}

// meterCost 按定价折算单次调用成本（USD）
func meterCost(pid, model string, u Usage) (float64, bool) {
	// 本地后端免费：llama / lmstudio / ollama 无 provider 定价即免费
	if pid == "" || pid == "llama" || pid == "lmstudio" || pid == "ollama" {
		return 0, false
	}
	p, ok := pricingFor(pid, model)
	if !ok {
		return 0, false
	}
	return float64(u.PromptTokens)/1e6*p.Input + float64(u.CompletionTokens)/1e6*p.Output, true
}

// meterHook routeChatEx 出口埋点：ChatResult → 计量记录
func meterHook(model string, res ChatResult, err error) {
	if !moduleEnabledByID("tokenMeter") {
		return
	}
	e := MeterEntry{
		Model:    model,
		Backend:  res.Backend,
		Provider: res.Backend,
		Error:    err != nil,
		Prompt:   res.Usage.PromptTokens,
		Complete: res.Usage.CompletionTokens,
		Total:    res.Usage.TotalTokens,
	}
	if pid, rest, ok := splitProviderModel(model); ok {
		if cost, priced := meterCost(pid, rest, res.Usage); priced {
			e.CostUSD, e.Priced = cost, true
		}
	} else if cost, priced := meterCost(res.Backend, model, res.Usage); priced {
		e.CostUSD, e.Priced = cost, true
	}
	meterRecord(e)
}

// handleV34Meter GET：汇总（今日 / 各天 / 按模型 top / 最近明细）；POST：清零
func handleV34Meter(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		meterMu.Lock()
		meterRing = meterRing[:0]
		meterStats = map[string]*meterAgg{}
		meterByModel = map[string]*meterAgg{}
		meterMu.Unlock()
		auditLog("METER_RESET", "system", "Token 测量器已清零")
		writeJSON(w, map[string]interface{}{"ok": true})
		return
	}
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	meterMu.Lock()
	today := time.Now().Format("2006-01-02")
	days := map[string]*meterAgg{}
	for k, v := range meterStats {
		days[k] = v.clone()
	}
	models := map[string]*meterAgg{}
	for k, v := range meterByModel {
		models[k] = v.clone()
	}
	recent := append([]MeterEntry(nil), meterRing...)
	toolSlimMu.Lock()
	saved, slimCalls := toolSlimSaved, toolSlimCalls
	toolSlimMu.Unlock()
	meterMu.Unlock()

	var total meterAgg
	for _, v := range days {
		total.Calls += v.Calls
		total.Errors += v.Errors
		total.Prompt += v.Prompt
		total.Complete += v.Complete
		total.Total += v.Total
		total.CostUSD += v.CostUSD
	}
	if len(recent) > 50 {
		recent = recent[len(recent)-50:]
	}
	type modelRow struct {
		Model string    `json:"model"`
		Agg   *meterAgg `json:"agg"`
	}
	rows := make([]modelRow, 0, len(models))
	for k, v := range models {
		rows = append(rows, modelRow{k, v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Agg.Total > rows[j].Agg.Total })
	if len(rows) > 20 {
		rows = rows[:20]
	}
	writeJSON(w, map[string]interface{}{
		"version":     version,
		"today":       days[today],
		"total":       &total,
		"byDay":       days,
		"byModel":     rows,
		"recent":      recent,
		"ringSize":    meterRingSize,
		"slimSaved":   saved,
		"slimCalls":   slimCalls,
		"module":      moduleEnabledByID("tokenMeter"),
	})
}

// handleV34MeterEstimate POST {text, model?}：轻量估算 tokens 与成本参考
func handleV34MeterEstimate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var req struct {
		Text  string `json:"text"`
		Model string `json:"model,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 {text, model?}"})
		return
	}
	tokens := estimateTokens(req.Text)
	resp := map[string]interface{}{
		"chars":   len([]rune(req.Text)),
		"tokens":  tokens,
		"note":    "tokens 为字符数/4 的轻量估算（无分词器依赖）；实际计费以后端返回 usage 为准",
		"version": version,
	}
	if req.Model != "" {
		pid, rest := "", req.Model
		if p, m2, ok := splitProviderModel(req.Model); ok {
			pid, rest = p, m2
		}
		resp["model"] = req.Model
		if p, ok := pricingFor(pid, rest); ok {
			resp["priced"] = true
			resp["costPerCallUSD"] = float64(tokens) / 1e6 * p.Input
			resp["pricing"] = p
		} else {
			resp["priced"] = false
			resp["costPerCallUSD"] = 0
		}
		writeJSON(w, resp)
		return
	}
	// 未指定模型：有定价模型的全量对比（按单次成本升序 top 10）
	type row struct {
		Model string  `json:"model"`
		Input float64 `json:"input"`
		Cost  float64 `json:"costPerCallUSD"`
	}
	var rows []row
	preg.mu.RLock()
	for _, id := range preg.order {
		s := preg.specs[id]
		if s.Kind != "cloud" {
			continue
		}
		for _, m := range providerEffectiveModels(s) {
			if p, ok := pricingFor(s.ID, m); ok {
				rows = append(rows, row{s.ID + "/" + m, p.Input, float64(tokens) / 1e6 * p.Input})
			}
		}
	}
	preg.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Cost < rows[j].Cost })
	if len(rows) > 10 {
		rows = rows[:10]
	}
	resp["comparison"] = rows
	writeJSON(w, resp)
}

// ===================== v3.4.0 工具链路降耗 =====================
//
// 用户诉求（项 2 前半）：「压缩中间环节、减少冗余 Token 消耗」。
// 落点：出站 tools schema 瘦身——剔除 JSON Schema 默认值字段
// （strict:false、additionalProperties:false、空容器），这些字段对模型理解
// 工具无增益、纯耗 token；收益（节省 token 估算）累计进测量器汇总。

var (
	toolSlimMu    sync.Mutex
	toolSlimSaved int64 // 累计节省的估算 tokens
	toolSlimCalls int64
)

// slimToolsSchema tools 数组瘦身：递归剔除冗余键，返回瘦身结果。
// 瘦身反而变大 / 解析失败时原样返回（保守降级，绝不破坏语义）。
func slimToolsSchema(tools json.RawMessage) json.RawMessage {
	if len(tools) == 0 || string(tools) == "null" {
		return tools
	}
	var arr []interface{}
	if err := json.Unmarshal(tools, &arr); err != nil || len(arr) == 0 {
		return tools
	}
	before := len(tools)
	slimmed := make([]interface{}, 0, len(arr))
	for _, t := range arr {
		slimmed = append(slimmed, slimSchemaNode(t))
	}
	out, err := json.Marshal(slimmed)
	if err != nil || len(out) >= before {
		return tools
	}
	toolSlimMu.Lock()
	toolSlimSaved += int64((before - len(out)) / 4)
	toolSlimCalls++
	toolSlimMu.Unlock()
	return out
}

// slimSchemaNode 递归剔除 schema 冗余键：
//   - strict / additionalProperties 仅在 true 时保留（false 是默认值）
//   - 空数组 / 空对象 / 空字符串剔除
func slimSchemaNode(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, val := range t {
			if k == "strict" || k == "additionalProperties" {
				if b, ok := val.(bool); ok && !b {
					continue
				}
			}
			if s, ok := val.([]interface{}); ok && len(s) == 0 {
				continue
			}
			if m, ok := val.(map[string]interface{}); ok && len(m) == 0 {
				continue
			}
			if s, ok := val.(string); ok && s == "" {
				continue
			}
			out[k] = slimSchemaNode(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(t))
		for _, x := range t {
			out = append(out, slimSchemaNode(x))
		}
		return out
	default:
		return v
	}
}
