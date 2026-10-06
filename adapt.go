package main

// ===================== v3.5.0 极致模块化与自适应 =====================
//
// 项 6（极致模块化 · 按需裁剪）：
//   - 内置裁剪档案（minimal / standard / full / privacy / lowspec）一键切换，
//     应用时走依赖闭合（复用 modules.go 拓扑规则），落盘 + 审计；
//   - 自定义档案：把当前模块开关组合保存为命名档案，随时套用 / 删除
//     （config 顶层 moduleProfiles 段，2 秒热重载兼容）。
//
// 项 7（自适应适配 · 设备性能 / 使用习惯 / 新手-高阶）：
//   - 模块使用埋点：moduleRoute 每次命中记账（调用次数 + 最后使用时间，进程内）；
//   - 自适应建议引擎：结合硬件档位（assessHardware）、模块使用习惯（moduleUsage）、
//     Token 成本（meterStats）生成可执行建议，POST 一键应用；
//   - 新手 / 高阶 UI 模式：beginner 模式前端只保留核心页面（config ui.mode）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ===================== 模块使用埋点（使用习惯自适应） =====================

type moduleUsageStat struct {
	Calls    int64     `json:"calls"`
	LastUsed time.Time `json:"lastUsed"`
}

var (
	usageMu     sync.Mutex
	moduleUsage = map[string]*moduleUsageStat{}
)

// noteModuleUse moduleRoute 命中埋点（模块开启且请求到达 handler 时 +1）
func noteModuleUse(id string) {
	usageMu.Lock()
	if s, ok := moduleUsage[id]; ok {
		s.Calls++
		s.LastUsed = time.Now()
	} else {
		moduleUsage[id] = &moduleUsageStat{Calls: 1, LastUsed: time.Now()}
	}
	usageMu.Unlock()
}

// moduleUsageSnapshot 返回使用统计快照（含从未使用的模块，calls=0）
func moduleUsageSnapshot() map[string]moduleUsageStat {
	usageMu.Lock()
	out := map[string]moduleUsageStat{}
	for _, m := range moduleRegistry {
		if s, ok := moduleUsage[m.ID]; ok {
			out[m.ID] = moduleUsageStat{Calls: s.Calls, LastUsed: s.LastUsed}
		} else {
			out[m.ID] = moduleUsageStat{}
		}
	}
	usageMu.Unlock()
	return out
}

// ===================== 裁剪档案（项 6） =====================

// moduleProfileDesc 档案元信息（内置 + 自定义共用展示形态）
type moduleProfileDesc struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Builtin     bool   `json:"builtin"`
}

// builtinProfiles 内置裁剪档案。States 只列显式 true 的模块，
// 未列出的模块一律 false（standard 档特殊：按注册表 Default 展开）。
var builtinProfiles = []struct {
	ID, Name, Description string
	// Standard 为 true 时按注册表 Default 值展开（跟随版本演进，不硬编码清单）
	Standard bool
	// Full 为 true 时在 Standard 基础上再全开（默认关闭的也开）
	Full bool
	On   []string
}{
	{
		ID: "minimal", Name: "极简", Description: "只保留对话链路与基础工具：安全核心 + 聊天 API + 本地/云端模型 + 记忆 + 内置工具 + 统计。其余全部关闭，内存占用与攻击面最小。",
		On: []string{"chatApi", "localModels", "cloudModels", "memory", "builtinTools", "stats", "adaptive"},
	},
	{
		ID: "standard", Name: "标准", Description: "按注册表默认拓扑展开（跟随版本演进的官方推荐配置）。",
		Standard: true,
	},
	{
		ID: "full", Name: "全量", Description: "全部可选模块开启（含默认关闭的 customTools / customAgents / autoStartModel / urgentChat）。",
		Standard: true, Full: true,
	},
	{
		ID: "privacy", Name: "纯本地", Description: "零外联隐私档：关闭一切对外网络模块（云端模型 / 搜索 / 抓取 / MCP / 连接器 / 外置宿主），只走本地推理。",
		On: []string{"chatApi", "localModels", "memory", "builtinTools", "stats", "autoDiscovery", "hardwareAdvisor", "resourceGuardian", "semanticGuard", "tokenMeter", "adaptive"},
	},
	{
		ID: "lowspec", Name: "低配", Description: "D 档 / 低内存设备省资源档：极简对话链路 + 资源守护器 + 语义分级（安全不降级），关闭自动发现 / 评分榜 / 能力库等开销项。",
		On: []string{"chatApi", "localModels", "cloudModels", "memory", "builtinTools", "resourceGuardian", "semanticGuard", "adaptive"},
	},
}

// profileStates 展开某内置档案为完整模块状态表（未做依赖闭合）
func profileStates(idx int) map[string]bool {
	states := map[string]bool{}
	p := builtinProfiles[idx]
	if p.Standard {
		for _, m := range moduleRegistry {
			states[m.ID] = m.Default || p.Full
		}
	} else {
		for _, m := range moduleRegistry {
			states[m.ID] = false
		}
		for _, id := range p.On {
			if _, known := registryLookup(id); known {
				states[id] = true
			}
		}
	}
	return states
}

// registryLookup 查注册表
func registryLookup(id string) (Module, bool) {
	for _, m := range moduleRegistry {
		if m.ID == id {
			return m, true
		}
	}
	return Module{}, false
}

// closeDeps 档案语义的依赖闭合（与配置热重载路径不同，结果与处理顺序无关）：
// 档案显式声明的开启集为唯一权威——传递性补全其依赖（连带开启），
// 未被任何开启模块需要的模块一律关闭。返回闭合后的新表（不改入参）。
func closeDeps(states map[string]bool) map[string]bool {
	next := map[string]bool{}
	for _, m := range moduleRegistry {
		next[m.ID] = false
	}
	// BFS 传递闭包：从显式开启的模块出发，沿依赖边扩散
	queue := make([]string, 0, len(moduleRegistry))
	for _, m := range moduleRegistry {
		if states[m.ID] {
			queue = append(queue, m.ID)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if next[id] {
			continue
		}
		next[id] = true
		if m, ok := registryLookup(id); ok {
			for _, d := range m.Deps {
				if !next[d] {
					queue = append(queue, d)
				}
			}
		}
	}
	// 连带开启的依赖落审计（区分用户显式声明与闭包补全）
	for _, m := range moduleRegistry {
		if next[m.ID] && !states[m.ID] {
			auditLog("MODULE_AUTO_ENABLE", "system", fmt.Sprintf("裁剪档案闭合：模块依赖 %s 已连带开启", m.ID))
		}
	}
	return next
}

// applyModuleStates 应用一份闭合后的模块状态表（内存 + 落盘 + 工作者对齐由调用方决定）
func applyModuleStates(states map[string]bool, reason string) {
	modMu.Lock()
	modStates = states
	cfg.Modules = map[string]bool{}
	for _, m := range moduleRegistry {
		cfg.Modules[m.ID] = states[m.ID]
	}
	modMu.Unlock()
	saveConfig()
	markConfigLoaded()
	reconcileModuleWorkers()
	auditLog("MODULE_PROFILE_APPLY", "system", "已应用裁剪档案: "+reason)
}

// profileChanges 计算档案应用将产生的变更清单（from → to）
func profileChanges(target map[string]bool) []map[string]interface{} {
	changes := []map[string]interface{}{}
	for _, m := range moduleRegistry {
		from := moduleEnabledByID(m.ID)
		to := target[m.ID]
		if from != to {
			changes = append(changes, map[string]interface{}{"id": m.ID, "from": from, "to": to})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i]["id"].(string) < changes[j]["id"].(string) })
	return changes
}

// ===================== 自适应建议引擎（项 7） =====================

// adaptiveSuggestion 一条可执行（或纯提示）的自适应建议
type adaptiveSuggestion struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`   // eco | module-off | module-on | info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	ModuleID string `json:"moduleId,omitempty"` // kind=module-* 时的目标模块
	Apply    bool   `json:"apply"`               // 是否可一键应用
}

// adaptiveSuggestions 生成当前建议列表（纯函数式：不改任何状态）
func adaptiveSuggestions() []adaptiveSuggestion {
	var out []adaptiveSuggestion
	uptime := time.Since(startTime)
	hw := assessHardware()
	usage := moduleUsageSnapshot()

	// R1：D 档硬件 + eco 未启用 → 建议 eco 省资源档
	if hw.Grade == "D" && !ecoActive() {
		out = append(out, adaptiveSuggestion{
			ID: "eco-on", Kind: "eco", Apply: true,
			Title: "启用 eco 省资源档",
			Detail: fmt.Sprintf("硬件评估 D 档（总分 %d/100）：建议启用 eco 档（GOMEMLIMIT 收紧至 128MB 软上限，高耗模块收紧）。", hw.Scores.Total),
		})
	}

	// R2：开启但从未使用过的非核心模块（运行 > 10 分钟）→ 建议关闭省资源
	if uptime > 10*time.Minute {
		for _, m := range moduleRegistry {
			if !moduleEnabledByID(m.ID) {
				continue
			}
			if m.Category != "tools" && m.Category != "ops" {
				continue // core / models / security 类不自动建议关闭
			}
			// 被其它已开启模块依赖的不建议关（关了也会被闭合规则连带关掉，提示口径复杂）
			dependents := false
			for _, o := range moduleRegistry {
				if o.ID != m.ID && moduleEnabledByID(o.ID) && containsStr(o.Deps, m.ID) {
					dependents = true
					break
				}
			}
			if dependents {
				continue
			}
			if s, ok := usage[m.ID]; ok && s.Calls == 0 {
				out = append(out, adaptiveSuggestion{
					ID: "mod-off-" + m.ID, Kind: "module-off", Apply: true, ModuleID: m.ID,
					Title: fmt.Sprintf("关闭闲置模块 %s（%s）", m.Name, m.ID),
					Detail: fmt.Sprintf("该模块自启动（%s）以来从未被调用，且无其它开启中的模块依赖它，关闭可省资源、缩小攻击面。", fmtDur(uptime)),
				})
			}
		}
	}

	// R3：硬件充裕 + 有本地模型 + autoStartModel 关 → 建议开启启动自拉
	if (hw.Grade == "S" || hw.Grade == "A" || hw.Grade == "B") &&
		moduleEnabledByID("localModels") && !moduleEnabledByID("autoStartModel") {
		if lm := getLocalModelList(); len(lm) > 0 {
			out = append(out, adaptiveSuggestion{
				ID: "mod-on-autoStartModel", Kind: "module-on", Apply: true, ModuleID: "autoStartModel",
				Title: "开启「启动自动拉起本地模型」",
				Detail: fmt.Sprintf("硬件 %s 档且已发现 %d 个本地模型：开启后网关启动 2 秒自动拉起默认模型，省去手动启动。", hw.Grade, len(lm)),
			})
		}
	}

	// R4：Token 成本可观 + 本地模型可用 → 本地优先提示（纯信息，不自动改）
	if total := meterTotalCost(); total > 1.0 {
		if lm := getLocalModelList(); len(lm) > 0 {
			out = append(out, adaptiveSuggestion{
				ID: "local-first", Kind: "info", Apply: false,
				Title: fmt.Sprintf("云端调用成本已达 $%.2f，建议本地优先", total),
				Detail: fmt.Sprintf("已发现 %d 个本地模型；高频 / 长文本任务改走本地可显著降本（Token 测量器页可对比单次成本）。", len(lm)),
			})
		}
	}

	if out == nil {
		out = []adaptiveSuggestion{}
	}
	return out
}

// applyAdaptiveSuggestion 应用一条建议，返回 (说明, error)
func applyAdaptiveSuggestion(id string) (string, error) {
	for _, s := range adaptiveSuggestions() {
		if s.ID != id {
			continue
		}
		switch s.Kind {
		case "eco":
			enableEcoMode("自适应建议: " + s.Title)
			return "eco 省资源档已启用", nil
		case "module-off":
			if err := setModuleEnabled(s.ModuleID, false); err != nil {
				return "", err
			}
			reconcileModuleWorkers()
			auditLog("ADAPTIVE_APPLY", "system", "自适应建议已应用: "+s.Title)
			return "模块 " + s.ModuleID + " 已关闭", nil
		case "module-on":
			if err := setModuleEnabled(s.ModuleID, true); err != nil {
				return "", err
			}
			reconcileModuleWorkers()
			auditLog("ADAPTIVE_APPLY", "system", "自适应建议已应用: "+s.Title)
			return "模块 " + s.ModuleID + " 已开启", nil
		default:
			return "", fmt.Errorf("该建议为纯提示，无需应用")
		}
	}
	return "", fmt.Errorf("建议不存在或已过期: %s", id)
}

// meterTotalCost Token 测量器累计成本（USD）
func meterTotalCost() float64 {
	meterMu.Lock()
	defer meterMu.Unlock()
	var total float64
	for _, v := range meterStats {
		if v != nil {
			total += v.CostUSD
		}
	}
	return total
}

// fmtDur 时长人类可读
func fmtDur(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	}
	return fmt.Sprintf("%d 小时", int(d.Hours()))
}

// ===================== UI 模式（项 7：新手 / 高阶） =====================

// uiMode 当前 UI 模式（beginner | advanced，默认 advanced）
func uiMode() string {
	cfgMu.RLock()
	m := cfg.V35Config.UI.Mode
	cfgMu.RUnlock()
	if m == "beginner" {
		return "beginner"
	}
	return "advanced"
}

// ===================== v3.5.0 API =====================

// handleV35Profile GET：档案清单 + 当前模块态；POST：apply / save / delete
func handleV35Profile(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cur := map[string]bool{}
		for _, m := range moduleRegistry {
			cur[m.ID] = moduleEnabledByID(m.ID)
		}
		// active：当前模块态与档案闭合态完全一致
		activeOf := func(name string) bool {
			target, ok := profileTargetStates(name)
			if !ok {
				return false
			}
			closed := closeDeps(target)
			for _, m := range moduleRegistry {
				if cur[m.ID] != closed[m.ID] {
					return false
				}
			}
			return true
		}
		onCount := func(name string) int {
			target, ok := profileTargetStates(name)
			if !ok {
				return 0
			}
			n := 0
			for _, v := range closeDeps(target) {
				if v {
					n++
				}
			}
			return n
		}
		builtin := []map[string]interface{}{}
		for _, p := range builtinProfiles {
			builtin = append(builtin, map[string]interface{}{
				"id": p.ID, "name": p.Name, "description": p.Description, "builtin": true,
				"active": activeOf(p.ID), "onCount": onCount(p.ID),
			})
		}
		custom := []map[string]interface{}{}
		names := make([]string, 0, len(cfg.V35Config.ModuleProfiles))
		for k := range cfg.V35Config.ModuleProfiles {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			custom = append(custom, map[string]interface{}{
				"id": k, "name": k, "description": "自定义档案（保存时的开关组合快照）", "builtin": false,
				"active": activeOf(k), "onCount": onCount(k),
			})
		}
		current := map[string]bool{}
		for _, m := range moduleRegistry {
			current[m.ID] = moduleEnabledByID(m.ID)
		}
		writeJSON(w, map[string]interface{}{
			"version":        version,
			"builtin":        builtin,
			"custom":         custom,
			"current":        current,
			"uiMode":         uiMode(),
			"moduleUsage":    moduleUsageSnapshot(),
			"uptimeSeconds":  int(time.Since(startTime).Seconds()),
		})
		return
	case http.MethodPost:
		var req struct {
			Action  string `json:"action"` // apply | save | delete
			Profile string `json:"profile"`
			DryRun  bool   `json:"dryRun,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Action == "" || req.Profile == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 {action: apply|save|delete, profile: 名称}"})
			return
		}
		switch req.Action {
		case "apply":
			target, ok := profileTargetStates(req.Profile)
			if !ok {
				writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "档案不存在: " + req.Profile})
				return
			}
			changes := profileChanges(target)
			if req.DryRun {
				writeJSON(w, map[string]interface{}{"ok": true, "dryRun": true, "changes": changes})
				return
			}
			applyModuleStates(closeDeps(target), "apply "+req.Profile)
			writeJSON(w, map[string]interface{}{"ok": true, "applied": req.Profile, "changes": changes})
			return
		case "save":
			name := sanitizeProfileName(req.Profile)
			if name == "" {
				writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "档案名仅允许字母数字-_（1~32 字符）"})
				return
			}
			if isBuiltinProfile(name) {
				writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "不能覆盖内置档案名: " + name})
				return
			}
			snap := map[string]bool{}
			for _, m := range moduleRegistry {
				snap[m.ID] = moduleEnabledByID(m.ID)
			}
			cfgMu.Lock()
			if cfg.V35Config.ModuleProfiles == nil {
				cfg.V35Config.ModuleProfiles = map[string]map[string]bool{}
			}
			cfg.V35Config.ModuleProfiles[name] = snap
			cfgMu.Unlock()
			saveConfig()
			markConfigLoaded()
			auditLog("MODULE_PROFILE_SAVE", "system", "已保存自定义裁剪档案: "+name)
			writeJSON(w, map[string]interface{}{"ok": true, "saved": name})
			return
		case "delete":
			if isBuiltinProfile(req.Profile) {
				writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "内置档案不可删除"})
				return
			}
			cfgMu.Lock()
			if _, ok := cfg.V35Config.ModuleProfiles[req.Profile]; !ok {
				cfgMu.Unlock()
				writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "自定义档案不存在: " + req.Profile})
				return
			}
			delete(cfg.V35Config.ModuleProfiles, req.Profile)
			cfgMu.Unlock()
			saveConfig()
			markConfigLoaded()
			auditLog("MODULE_PROFILE_DELETE", "system", "已删除自定义裁剪档案: "+req.Profile)
			writeJSON(w, map[string]interface{}{"ok": true, "deleted": req.Profile})
			return
		default:
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "action 仅支持 apply | save | delete"})
			return
		}
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
}

// profileTargetStates 取某档案的目标状态表（内置或自定义）
func profileTargetStates(name string) (map[string]bool, bool) {
	for i, p := range builtinProfiles {
		if p.ID == name {
			return profileStates(i), true
		}
	}
	cfgMu.RLock()
	states, ok := cfg.V35Config.ModuleProfiles[name]
	cfgMu.RUnlock()
	if ok {
		cp := map[string]bool{}
		for _, m := range moduleRegistry {
			if v, seen := states[m.ID]; seen {
				cp[m.ID] = v
			} else {
				cp[m.ID] = false
			}
		}
		return cp, true
	}
	return nil, false
}

// isBuiltinProfile 判断是否内置档案名
func isBuiltinProfile(name string) bool {
	for _, p := range builtinProfiles {
		if p.ID == name {
			return true
		}
	}
	return false
}

// sanitizeProfileName 自定义档案名合法化（字母数字-_，1~32 字符）
func sanitizeProfileName(s string) string {
	out := []rune{}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out = append(out, r)
		}
	}
	if len(out) == 0 || len(out) > 32 {
		return ""
	}
	return string(out)
}

// handleV35Adaptive GET：建议列表；POST：应用一条建议
func handleV35Adaptive(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"version":     version,
			"suggestions": adaptiveSuggestions(),
			"usage":       moduleUsageSnapshot(),
		})
		return
	case http.MethodPost:
		var req struct {
			Apply string `json:"apply"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Apply == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 {apply: 建议ID}"})
			return
		}
		msg, err := applyAdaptiveSuggestion(req.Apply)
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "applied": req.Apply, "message": msg})
		return
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
}

// handleV35UIMode GET：当前模式；POST：切换（beginner | advanced）
func handleV35UIMode(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"version": version, "mode": uiMode()})
		return
	case http.MethodPost:
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Mode != "beginner" && req.Mode != "advanced") {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 {mode: beginner|advanced}"})
			return
		}
		cfgMu.Lock()
		cfg.V35Config.UI.Mode = req.Mode
		cfgMu.Unlock()
		saveConfig()
		markConfigLoaded()
		auditLog("UI_MODE_CHANGE", "system", "界面模式切换为 "+req.Mode)
		writeJSON(w, map[string]interface{}{"ok": true, "mode": req.Mode})
		return
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
}
