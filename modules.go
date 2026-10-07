package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ===================== 模块框架（v2.0.0 模块化重构）=====================
//
// 设计铁律（用户需求 + 锦衣卫预审约束）：
//  1. 安全保护模块（security-core）无开关、强制加载：不进入本注册表的开关体系，
//     中间件链硬编码在 main 中间件里，任何配置 / API / UI 均无法关闭。
//  2. 每个功能一个独立开关（一个功能一个模块），config.json modules 段 +
//     POST /api/admin/modules 双入口，统一走既有 2 秒热重载管线。
//  3. 依赖拓扑：开启依赖者自动连带开启其依赖（记日志）；关闭被依赖者时
//     API 路径直接拒绝；热重载路径自动纠正（连带关闭依赖者）并落审计。
//  4. 模块关闭时其路由返回 503（不泄露内部路由结构，只给模块 ID 与开启方法）；
//     后台 goroutine 通过 context 取消真正停止，热重载频繁切换无泄漏。

// Module 模块定义（静态注册表）
type Module struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"` // core | models | tools | network | ops
	Default     bool     `json:"default"`  // 首次运行默认开关
	Deps        []string `json:"deps"`     // 依赖的模块 ID
	HasWorker   bool     `json:"hasWorker"`
}

// moduleRegistry 可选功能模块注册表（security-core 不在此列，不可关闭）
var moduleRegistry = []Module{
	{ID: "chatApi", Name: "Chat API", Description: "聊天补全与 OpenAI 兼容 /v1 层", Category: "core", Default: true},
	{ID: "localModels", Name: "Local Models", Description: "本地 GGUF 模型启停/状态、LM Studio/Ollama 后端", Category: "models", Default: true},
	{ID: "modelDownload", Name: "Model Download", Description: "模型下载管理器（含进度）", Category: "models", Default: true, Deps: []string{"localModels"}},
	{ID: "autoStartModel", Name: "Auto Start Model", Description: "启动 2 秒后自动拉起默认本地模型", Category: "models", Default: false, Deps: []string{"localModels"}, HasWorker: true},
	{ID: "cloudModels", Name: "Cloud Models", Description: "云端模型路由（OpenAI / DeepSeek / 自定义）", Category: "models", Default: true},
	{ID: "webSearch", Name: "Web Search", Description: "内置 Bing RSS 与 Serper 搜索", Category: "tools", Default: true},
	{ID: "webFetch", Name: "Web Fetch", Description: "URL 抓取转文本", Category: "tools", Default: true},
	{ID: "openapiTools", Name: "OpenAPI Tools", Description: "OpenAPI 文档解析工具", Category: "tools", Default: true, Deps: []string{"webFetch"}},
	{ID: "mcpExternal", Name: "External MCP", Description: "外部 MCP stdio 服务器接入", Category: "tools", Default: true},
	{ID: "builtinTools", Name: "Builtin Tools", Description: "内置工具注册表 /api/tools/", Category: "tools", Default: true},
	{ID: "customTools", Name: "Custom Tools", Description: "用户自定义 HTTP 转发工具（config.customTools）", Category: "tools", Default: false, Deps: []string{"builtinTools"}},
	{ID: "customAgents", Name: "Custom Agents", Description: "用户自定义 agent 角色（config.customAgents）", Category: "tools", Default: false, Deps: []string{"chatApi"}},
	{ID: "memory", Name: "Memory", Description: "记忆持久化", Category: "core", Default: true},
	{ID: "stats", Name: "Stats", Description: "统计面板与 24 小时请求历史", Category: "ops", Default: true},
	{ID: "autoDiscovery", Name: "Auto Discovery", Description: "每 60 秒自动发现本地/远端模型", Category: "ops", Default: true, Deps: []string{"localModels"}, HasWorker: true},
	{ID: "urgentChat", Name: "Urgent Chat", Description: "紧急直通通道（低延迟直连）", Category: "core", Default: false, Deps: []string{"chatApi"}},
	{ID: "hardwareAdvisor", Name: "Hardware Advisor", Description: "硬件评估与提升建议引擎", Category: "ops", Default: true},
	{ID: "resourceGuardian", Name: "Resource Guardian", Description: "资源守护器：GOMEMLIMIT 软上限 + L0-L3 分级响应 + eco 省资源档", Category: "ops", Default: true, HasWorker: true},
	{ID: "semanticGuard", Name: "Semantic Guard", Description: "语义分级分流：静态规则 + 灰区送本地小模型（fail-close，AI 只能加严）", Category: "security", Default: true, HasWorker: false},
	{ID: "smartRouter", Name: "Smart Router", Description: "两阶段路由：静态规则优先 + ε-greedy bandit 优化自动分支（非 admin 反馈降权防伪造）", Category: "ops", Default: true, HasWorker: false},
	{ID: "scoreBoard", Name: "Score Board", Description: "模型评分榜：运行时分融合 lm-eval-harness 离线评测（相对参考，诚实标注）", Category: "ops", Default: true, HasWorker: false},
	// v3.0.1：sidecar 外置模块宿主（modules.d + SHA-256 钉扎 + 低权限代理）
	{ID: "sidecarHub", Name: "Sidecar Hub", Description: "外置模块宿主：modules.d manifest + SHA-256 钉扎 + 生命周期监管 + /api/ext/ 低权限反向代理", Category: "tools", Default: true, HasWorker: true},
	// v3.2.2 治理层：共享记忆 / 共享信息 / 上下文拓展 MCP
	{ID: "contextGov", Name: "Context Governance", Description: "共享记忆（命名空间 KV + 解析链）/ 共享信息（结构化知识条目）/ 上下文组装（预算化注入）", Category: "core", Default: true, Deps: []string{"builtinTools"}},
	// v3.3.0：模型能力库与能力感知路由（能力矩阵 / 自动推断 / 智能改道）
	{ID: "capabilityHub", Name: "Capability Hub", Description: "模型能力库：能力标签自动推断 + 能力矩阵 + 能力感知路由改道（v3.3.0）", Category: "models", Default: true, Deps: []string{"chatApi"}},
	// v3.4.0：轻量 Token 测量器（成本实时反馈 / tools 瘦身降耗）
	{ID: "tokenMeter", Name: "Token Meter", Description: "轻量 Token 测量器：每次调用的 tokens 与成本实时反馈、tools schema 瘦身降耗（v3.4.0）", Category: "ops", Default: true, Deps: []string{"chatApi"}},
	// v3.4.0：连接器生态（内置模板 + 用户实例，AI 可调用 conn_* 工具）
	{ID: "connectors", Name: "Connectors", Description: "连接器生态：内置模板目录 + 用户实例，AI 经 conn_* 工具无缝接入外部平台与数据源（v3.4.0）", Category: "tools", Default: true, Deps: []string{"builtinTools"}},
	// v3.5.0：极致模块化（裁剪档案）与自适应（使用习惯建议 / 新手-高阶 UI 模式）
	{ID: "adaptive", Name: "Adaptive", Description: "极致模块化与自适应：内置/自定义裁剪档案一键切换、模块使用习惯分析建议、新手/高阶界面模式（v3.5.0）", Category: "ops", Default: true},
	// v3.7.0：扩展器 / 一键配置器（探测本机 AI 工具并生成接入 TSG 的配置片段）
	{ID: "extender", Name: "Extender", Description: "扩展器 / 一键配置器：探测本机已装的 AI 工具（OpenClaw/Continue/Aider/Cline/ZooCode/Codex），一键生成接入 TSG 端点的配置片段（v3.7.0）", Category: "tools", Default: true},
}

// securityModuleDesc 安全模块在模块列表中的展示形态（locked，无开关）
var securityModuleDesc = Module{
	ID: "security-core", Name: "Security Core", Description: "WAF / 鉴权 / RBAC / 速率限制 / 审计日志 / PII 脱敏（强制加载，不可关闭）",
	Category: "security", Default: true,
}

// ===================== 模块运行态 =====================

var (
	modMu     sync.RWMutex
	modStates = map[string]bool{} // 当前生效的模块开关
)

// initModuleDefaults 按注册表 Default 值初始化（首次运行 / 配置无 modules 段时）
func initModuleDefaults() {
	modMu.Lock()
	defer modMu.Unlock()
	modStates = map[string]bool{}
	for _, m := range moduleRegistry {
		modStates[m.ID] = m.Default
	}
}

// applyModulesFromConfig 从 cfg.Modules 应用开关并处理依赖拓扑（含自动纠正）。
// 依赖违例在热重载路径无法"拒绝"（文件已写），采取自动纠正并落审计：
//   - 开启某模块但依赖关闭 -> 连带开启依赖
//   - 关闭某模块但被已开启模块依赖 -> 连带关闭依赖者
func applyModulesFromConfig() {
	modMu.Lock()
	// 1) 以注册表为基准展开配置
	states := map[string]bool{}
	for _, m := range moduleRegistry {
		if v, ok := cfg.Modules[m.ID]; ok {
			states[m.ID] = v
		} else {
			states[m.ID] = m.Default
		}
	}
	// 2) 依赖闭合：迭代直至稳定（最多 N 轮，防环死循环）
	for iter := 0; iter <= len(moduleRegistry); iter++ {
		changed := false
		for _, m := range moduleRegistry {
			if states[m.ID] {
				for _, d := range m.Deps {
					if !states[d] {
						states[d] = true
						auditLog("MODULE_AUTO_ENABLE", "system", fmt.Sprintf("模块 %s 依赖 %s，已连带开启", m.ID, d))
						changed = true
					}
				}
			} else {
				for _, o := range moduleRegistry {
					if states[o.ID] && containsStr(o.Deps, m.ID) {
						states[o.ID] = false
						auditLog("MODULE_AUTO_DISABLE", "system", fmt.Sprintf("模块 %s 的依赖 %s 已关闭，已连带关闭", o.ID, m.ID))
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	// 3) 生效并回写 cfg.Modules（保证 saveConfig 落盘的拓扑是闭合的）
	modStates = states
	cfg.Modules = map[string]bool{}
	for _, m := range moduleRegistry {
		cfg.Modules[m.ID] = states[m.ID]
	}
	modMu.Unlock()
}

// moduleEnabledByID 查询模块是否开启。无显式状态时回退注册表 Default
// （全新安装 / 测试环境未加载 config 时按默认拓扑生效，不误杀默认模块）
func moduleEnabledByID(id string) bool {
	modMu.RLock()
	v, ok := modStates[id]
	modMu.RUnlock()
	if ok {
		return v
	}
	for _, m := range moduleRegistry {
		if m.ID == id {
			return m.Default
		}
	}
	return false
}

// setModuleEnabled API 路径开关模块：拒绝未知/锁定模块，拒绝依赖违例，落盘 + 生效
func setModuleEnabled(id string, enabled bool) error {
	known := false
	for _, m := range moduleRegistry {
		if m.ID == id {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("未知模块: %s", id)
	}
	modMu.Lock()
	next := map[string]bool{}
	for k, v := range modStates {
		next[k] = v
	}
	next[id] = enabled
	if enabled {
		for _, m := range moduleRegistry {
			if next[m.ID] {
				for _, d := range m.Deps {
					if !next[d] {
						next[d] = true
						auditLog("MODULE_AUTO_ENABLE", "system", fmt.Sprintf("模块 %s 依赖 %s，已连带开启", m.ID, d))
					}
				}
			}
		}
	} else {
		for _, m := range moduleRegistry {
			if m.ID != id && next[m.ID] && containsStr(m.Deps, id) {
				modMu.Unlock()
				return fmt.Errorf("模块 %s 依赖 %s，请先关闭 %s", m.ID, id, m.ID)
			}
		}
	}
	modStates = next
	cfg.Modules = next
	modMu.Unlock()
	saveConfig()
	markConfigLoaded() // saveConfig 回写后指纹已变，刷新基线避免热重载自我触发
	return nil
}

// moduleRoute 路由包装：模块关闭时返回 503（不泄露内部路由结构）
func moduleRoute(id string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !moduleEnabledByID(id) {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
				"error": "module " + id + " disabled",
				"hint":  "config.json modules." + id + "=true（2 秒热重载生效）或 POST /api/admin/modules",
			})
			return
		}
		noteModuleUse(id) // v3.5.0：模块使用埋点（使用习惯自适应）
		h(w, r)
	}
}

// ===================== 模块后台工作者生命周期 =====================

type moduleWorker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

var (
	workersMu     sync.Mutex
	moduleWorkers = map[string]*moduleWorker{}
)

// startModuleWorker 启动（或重启）某模块的后台工作者；fn 必须在 ctx 取消时及时返回
func startModuleWorker(id string, fn func(ctx context.Context)) {
	stopModuleWorker(id)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	workersMu.Lock()
	moduleWorkers[id] = &moduleWorker{cancel: cancel, done: done}
	workersMu.Unlock()
	go func() {
		defer close(done)
		fn(ctx)
	}()
}

// stopModuleWorker 停止后台工作者并等待其退出（上限 3 秒，防泄漏）
func stopModuleWorker(id string) {
	workersMu.Lock()
	w, ok := moduleWorkers[id]
	if ok {
		delete(moduleWorkers, id)
	}
	workersMu.Unlock()
	if !ok {
		return
	}
	w.cancel()
	select {
	case <-w.done:
	case <-time.After(3 * time.Second):
		logMsg("[MODULE] 警告: 工作者 " + id + " 3 秒内未退出")
	}
}

// reconcileModuleWorkers 热重载后对齐工作者与模块开关
func reconcileModuleWorkers() {
	for _, m := range moduleRegistry {
		if !m.HasWorker {
			continue
		}
		if moduleEnabledByID(m.ID) {
			if fn, ok := moduleWorkerFn(m.ID); ok {
				startModuleWorker(m.ID, fn)
			}
		} else {
			stopModuleWorker(m.ID)
		}
	}
}

// moduleWorkerFns 各模块的后台任务实现（由 main.go 定义）
var moduleWorkerFns = map[string]func(ctx context.Context){}

func moduleWorkerFn(id string) (func(ctx context.Context), bool) {
	fn, ok := moduleWorkerFns[id]
	return fn, ok
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ===================== 模块管理 API =====================

// handleModules GET: 模块清单（含锁定态/依赖/运行态）；POST: 切换开关（admin only）
func handleModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		list := []map[string]interface{}{
			{
				"id": "security-core", "name": securityModuleDesc.Name, "description": securityModuleDesc.Description,
				"category": "security", "enabled": true, "locked": true, "deps": []string{},
				"running": true,
			},
		}
		for _, m := range moduleRegistry {
			list = append(list, map[string]interface{}{
				"id": m.ID, "name": m.Name, "description": m.Description,
				"category":  m.Category,
				"enabled":   moduleEnabledByID(m.ID),
				"locked":    false,
				"deps":      m.Deps,
				"default":   m.Default,
				"hasWorker": m.HasWorker,
				"running":   moduleEnabledByID(m.ID),
			})
		}
		writeJSON(w, map[string]interface{}{"modules": list, "total": len(list)})
		return
	}
	var body struct {
		ID      string `json:"id"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" || body.Enabled == nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "body: {\"id\": \"<module>\", \"enabled\": true|false}"})
		return
	}
	if body.ID == "security-core" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "安全保护模块强制加载，不可关闭"})
		return
	}
	if err := setModuleEnabled(body.ID, *body.Enabled); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// 立即对齐后台工作者（路由经 moduleRoute 包装，无需重注册即已生效）
	reconcileModuleWorkers()
	uname, _, _ := userFromRequest(r)
	auditLog("MODULE_TOGGLE", uname, fmt.Sprintf("模块 %s -> %v", body.ID, *body.Enabled))
	writeJSON(w, map[string]interface{}{"success": true, "id": body.ID, "enabled": *body.Enabled})
}

// moduleIDsSorted 排序输出模块 ID（诊断用）
func moduleIDsSorted() []string {
	ids := []string{"security-core"}
	for _, m := range moduleRegistry {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	return ids
}
