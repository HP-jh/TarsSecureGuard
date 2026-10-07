package main

// ===================== v3.3.0 模型能力库与能力匹配 =====================
//
// 用户诉求（项4）：「用户添加模型后，系统根据标签自动识别其能力边界（如视觉、
// 长上下文、函数调用等），实现智能路由与按需调度」。
//
// 三层数据来源（优先级从高到低）：
//   override  —— config.json v33.modelCaps（用户显式覆盖，最长正确）
//   registry  —— providers/*.json 的 defaultCaps / modelCaps（注册表随版本维护）
//   inferred  —— 模型名启发式推断（诚实标注 source=inferred，可能不准）
//
// 能力感知路由（capabilityRoute）：请求带图片（vision）或 tools（函数调用）或
// 超长输入（longContext）而目标模型缺该能力时，在「已就绪」的 provider 里
// 找一个具备能力的模型改道，并落审计；找不到则放行原模型（由后端自然报错）。
// 关闭开关：modules.capabilityHub=false 或 config v33.capabilities.autoReroute=false。
//
// 安全不变量：能力路由只改「模型选择」，不绕过任何安全链（WAF/PII/语义分级/
// 限流仍在改道之前完成）；本模块不出站请求（候选就绪状态来自既有探测结果）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// 能力常量（小写、稳定字符串，UI 与 API 直接消费）
const (
	capVision      = "vision"      // 视觉 / 多模态输入
	capTools       = "tools"       // 函数调用 / tool use
	capLongContext = "longContext" // 长上下文（≥128k）
	capJSONMode    = "json"        // JSON 输出模式
	capReasoning   = "reasoning"   // 推理增强
)

// capKnown 支持的能力标签全集（矩阵与校验用）
var capKnown = []string{capVision, capTools, capLongContext, capJSONMode, capReasoning}

// capDesc 能力中文说明（UI 徽章 tooltip）
var capDesc = map[string]string{
	capVision:      "视觉/多模态输入",
	capTools:       "函数调用",
	capLongContext: "长上下文(≥128k)",
	capJSONMode:    "JSON 输出模式",
	capReasoning:   "推理增强",
}

// inferModelCapabilities 模型名启发式推断（仅对未知模型兜底；结果诚实标注 inferred）。
// 匹配一律小写子串；宁可漏判不可乱判——只收录高置信模式。
func inferModelCapabilities(model string) []string {
	m := strings.ToLower(model)
	var caps []string
	has := func(pats ...string) bool {
		for _, p := range pats {
			if strings.Contains(m, p) {
				return true
			}
		}
		return false
	}
	if has("vl", "vision", "llava", "gpt-4o", "gpt-4.1", "omni", "claude", "gemini", "pixtral", "internvl", "grok-4") {
		caps = append(caps, capVision)
	}
	if has("gpt-", "claude", "gemini", "qwen", "deepseek", "glm", "kimi", "moonshot", "mistral", "llama-3", "llama-4", "grok", "tool", "fc", "function") {
		caps = append(caps, capTools)
	}
	if has("128k", "200k", "256k", "1m", "long", "claude", "gemini", "qwen", "deepseek", "kimi", "glm") {
		caps = append(caps, capLongContext)
	}
	if has("json") {
		caps = append(caps, capJSONMode)
	}
	if has("-r1", "o1", "o3", "o4", "thinking", "reasoner", "qwq", "magistral", "-grok-4") {
		caps = append(caps, capReasoning)
	}
	return caps
}

// normalizeCaps 排序去重 + 过滤未知标签 + 归一到规范形式（override 写入时校验）。
// 大小写不敏感匹配（"LONGCONTEXT"/"longcontext" 均归一为 "longContext"）。
func normalizeCaps(caps []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range caps {
		c = strings.TrimSpace(strings.ToLower(c))
		if c == "" {
			continue
		}
		canonical := ""
		for _, k := range capKnown {
			if strings.ToLower(k) == c {
				canonical = k
				break
			}
		}
		if canonical == "" || seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out
}

// modelCapabilitiesFor 解析单个模型的能力三层数据。
// pid 可为空（config cloud 段 / 本地模型无 provider 前缀）。
// 返回 (能力列表, 来源 override|registry|inferred)。
func modelCapabilitiesFor(pid, model string) ([]string, string) {
	if pid == "" {
		// 覆盖层：裸模型名
		if caps := v33CapsOverride(model); len(caps) > 0 {
			return caps, "override"
		}
		return inferModelCapabilities(model), "inferred"
	}
	// 覆盖层：provider/model 全名优先，其次裸模型名
	if caps := v33CapsOverride(pid + "/" + model); len(caps) > 0 {
		return caps, "override"
	}
	if caps := v33CapsOverride(model); len(caps) > 0 {
		return caps, "override"
	}
	// 注册表层：modelCaps 精确 > defaultCaps 继承
	if spec, ok := providerSpec(pid); ok {
		if caps, ok2 := spec.ModelCaps[model]; ok2 && len(caps) > 0 {
			return normalizeCaps(caps), "registry"
		}
		if len(spec.DefaultCaps) > 0 {
			return normalizeCaps(spec.DefaultCaps), "registry"
		}
	}
	return inferModelCapabilities(model), "inferred"
}

// v33CapsOverride 读 config v33.modelCaps 覆盖层
func v33CapsOverride(key string) []string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.V33Config.ModelCaps == nil {
		return nil
	}
	return normalizeCaps(cfg.V33Config.ModelCaps[key])
}

// capsContain 能力集合是否覆盖 needs
func capsContain(caps, needs []string) bool {
	set := map[string]bool{}
	for _, c := range caps {
		set[c] = true
	}
	for _, n := range needs {
		if !set[n] {
			return false
		}
	}
	return true
}

// capabilityNeeds 从请求特征推导所需能力：
// 消息带图片 → vision；带 tools → tools；估算输入 > 32k tokens → longContext。
func capabilityNeeds(msgs []Message, tools json.RawMessage) []string {
	var needs []string
	for _, m := range msgs {
		if len(m.Images) > 0 {
			needs = append(needs, capVision)
			break
		}
	}
	if len(tools) > 0 && string(tools) != "null" && strings.TrimSpace(string(tools)) != "" {
		needs = append(needs, capTools)
	}
	total := int64(0)
	for _, m := range msgs {
		total += estimateTokens(m.Content)
	}
	if total > 32000 {
		needs = append(needs, capLongContext)
	}
	return normalizeCaps(needs)
}

// capabilityRoute 能力感知改道：目标模型缺所需能力时找已就绪的具备能力的模型。
// 返回 (实际模型, 是否改道, 说明)。needs 为空 / 模型具备能力 / 找不到候选时
// 原样放行（找不到时说明里注明 no-capable-model，由后端自然报错）。
func capabilityRoute(model string, needs []string) (string, bool, string) {
	if len(needs) == 0 || !moduleEnabledByID("capabilityHub") || !v33AutoReroute() {
		return model, false, ""
	}
	pid, rest := model, ""
	if p, r, ok := splitProviderModel(model); ok {
		pid, rest = p, r
	} else {
		rest = model
	}
	caps, _ := modelCapabilitiesFor(pid, rest)
	if capsContain(caps, needs) {
		return model, false, ""
	}
	// 候选：已就绪 provider 的模型里具备所需能力者；同 provider 优先，其余按注册表序
	type cand struct {
		pid   string
		model string
		score int
	}
	var cands []cand
	preg.mu.RLock()
	for _, id := range preg.order {
		s := preg.specs[id]
		if !providerEnabled(s) {
			continue
		}
		if ready, _ := providerReady(s); !ready {
			continue
		}
		for _, m := range providerEffectiveModels(s) {
			mc, _ := modelCapabilitiesFor(s.ID, m)
			if capsContain(mc, needs) {
				score := 1
				if s.ID == pid {
					score = 0
				}
				cands = append(cands, cand{pid: s.ID, model: m, score: score})
			}
		}
	}
	preg.mu.RUnlock()
	if len(cands) == 0 {
		auditLog("CAP_REROUTE_SKIP", "system", fmt.Sprintf("模型 %s 缺能力 %v，但无已就绪候选，放行原模型", model, needs))
		return model, false, "no-capable-model"
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score < cands[j].score })
	pick := cands[0]
	pickFull := pick.pid + "/" + pick.model
	auditLog("CAP_REROUTE", "system", fmt.Sprintf("能力改道：%s 缺 %v → %s", model, needs, pickFull))
	return pickFull, true, "rerouted:" + model + "→" + pickFull
}

// v33AutoReroute 能力改道开关（默认开）
func v33AutoReroute() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.V33Config.Capabilities.AutoReroute != nil {
		return *cfg.V33Config.Capabilities.AutoReroute
	}
	return true
}

// ===================== 能力矩阵 =====================

// CapModelEntry 能力矩阵单行
type CapModelEntry struct {
	Model        string   `json:"model"`
	Provider     string   `json:"provider"`
	Kind         string   `json:"kind"` // cloud | local
	Capabilities []string `json:"capabilities"`
	Source       string   `json:"source"` // override | registry | inferred
	Status       string   `json:"status"` // online | needs-key | disabled | local | configured
}

// capabilityMatrix 全量模型 × 能力矩阵：
// 覆盖 provider 注册表模型、config cloud 段模型（openai/deepseek/custom）与本地 GGUF。
func capabilityMatrix() []CapModelEntry {
	var out []CapModelEntry
	seen := map[string]bool{}
	add := func(model, pid, kind, status string) {
		key := pid + "/" + model
		if seen[key] {
			return
		}
		seen[key] = true
		caps, src := modelCapabilitiesFor(pid, model)
		out = append(out, CapModelEntry{
			Model: model, Provider: pid, Kind: kind,
			Capabilities: caps, Source: src, Status: status,
		})
	}
	// provider 注册表
	preg.mu.RLock()
	for _, id := range preg.order {
		s := preg.specs[id]
		if !providerEnabled(s) {
			continue
		}
		_, reason := providerReady(s)
		status := "online"
		if reason == "needs-key" {
			status = "needs-key"
		}
		if reason == "disabled" {
			status = "disabled"
		}
		if s.Kind == "local" {
			status = "local"
		}
		for _, m := range providerEffectiveModels(s) {
			add(m, s.ID, s.Kind, status)
		}
	}
	preg.mu.RUnlock()
	// config cloud 段（legacy + custom）
	for _, cc := range allCloudCfgs() {
		for _, m := range cc.Models {
			add(m, "config:"+cc.Name, "cloud", "configured")
		}
	}
	// 本地 GGUF
	for _, gm := range ggufModels {
		add(gm.ID, "llama", "local", "local")
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Model < out[j].Model
	})
	return out
}

// ===================== 管理端点 =====================

// handleV33Capabilities GET /api/admin/v33/capabilities —— 能力矩阵（admin.read）
// POST /api/admin/v33/capabilities —— 写覆盖层 {model, capabilities|null}
// （/api/admin/* 由 gatewayMiddleware 统一鉴权 + RBAC，与 handleModules 等一致）
func handleV33Capabilities(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"version":      version,
			"capabilities": capKnown,
			"descriptions": capDesc,
			"autoReroute":  v33AutoReroute(),
			"module":       moduleEnabledByID("capabilityHub"),
			"models":       capabilityMatrix(),
		})
	case http.MethodPost:
		var req struct {
			Model        string   `json:"model"`
			Capabilities []string `json:"capabilities"` // null/空 = 清除覆盖
			AutoReroute  *bool    `json:"autoReroute"`   // 单独传 = 切换自动改道开关
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 {model, capabilities} 或 {autoReroute}"})
			return
		}
		// 仅切开关（不带 model）
		if req.Model == "" && req.AutoReroute != nil {
			cfgMu.Lock()
			cfg.V33Config.Capabilities.AutoReroute = req.AutoReroute
			cfgMu.Unlock()
			if err := saveConfigChecked(); err != nil {
				writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "保存失败: " + err.Error()})
				return
			}
			auditLog("CAP_REROUTE_TOGGLE", "system", fmt.Sprintf("能力改道自动开关 -> %v", *req.AutoReroute))
			writeJSON(w, map[string]interface{}{"ok": true, "autoReroute": *req.AutoReroute})
			return
		}
		if req.Model == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 {model, capabilities}"})
			return
		}
		caps := normalizeCaps(req.Capabilities)
		cfgMu.Lock()
		if cfg.V33Config.ModelCaps == nil {
			cfg.V33Config.ModelCaps = map[string][]string{}
		}
		if caps == nil {
			delete(cfg.V33Config.ModelCaps, req.Model)
		} else {
			cfg.V33Config.ModelCaps[req.Model] = caps
		}
		cfgMu.Unlock()
		if err := saveConfigChecked(); err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "保存失败: " + err.Error()})
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "model": req.Model, "capabilities": caps})
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}
