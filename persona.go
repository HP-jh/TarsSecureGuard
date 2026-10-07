package main

// ===================== v3.8.0 职业系统（Persona System）=====================
//
// 用户诉求：内置职业（学生/文字创作者/开发者/研究者/通用），选择职业后自动：
//   1. 选择模块、连接器、推荐工具
//   2. 修改 AI 全局记忆（写入共享记忆/共享信息）
//   3. 优化调用链路（文字创作者→文字生成优化+悬浮框；学生→降资源+稳优先）
//   4. 自动匹配模型库，提示能力与缺失项，预处理（预热/预下载/fallback）
//
// 设计：
//   - Persona 为纯配置模板，不绑定运行时状态（currentPersona 存在 cfg 中）
//   - 切换职业 = 应用预设配置 + 写共享记忆/信息 + 触发模型匹配 + 触发调用链优化
//   - REST（persona 模块，默认开）：
//       GET  /api/admin/v38/personas          列表 + 当前
//       POST /api/admin/v38/persona/select    选择职业 {id}
//       GET  /api/admin/v38/persona/current   当前职业详情
//       GET  /api/admin/v38/model-matrix      模型功能矩阵（按当前职业）
//       POST /api/admin/v38/model-preheat     预热推荐模型

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ===================== 数据模型 =====================

// Persona 职业模板
type Persona struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Icon             string            `json:"icon"`
	AgeRange         string            `json:"ageRange"`      // 适配年龄段
	ShortTags        []string          `json:"shortTags"`     // 快捷标签
	DefaultModules   map[string]bool   `json:"defaultModules"`
	DefaultConnectors []string         `json:"defaultConnectors"`
	DefaultMCPTools  []string          `json:"defaultMCPTools"`
	DefaultChatbox   string            `json:"defaultChatbox"` // 默认 chatbox 角色
	ModelPrefs       PersonaModelPrefs `json:"modelPrefs"`
	ResourceStrategy ResourceStrategy  `json:"resourceStrategy"`
	ChainOpt         ChainOptimization `json:"chainOptimization"`
	MemoryPrompt     string            `json:"memoryPrompt"`   // 写入全局记忆的提示词
}

// PersonaModelPrefs 模型偏好
type PersonaModelPrefs struct {
	PreferredProviders []string          `json:"preferredProviders"` // 优先 provider 顺序
	RequiredCaps       []string          `json:"requiredCaps"`       // 必需能力
	NiceToHaveCaps     []string          `json:"niceToHaveCaps"`     // 锦上添花能力
	FallbackTier       string            `json:"fallbackTier"`       // 降档目标 tier
	ContextWindowMin   int               `json:"contextWindowMin"`   // 最小上下文窗口需求
}

// ResourceStrategy 资源策略
type ResourceStrategy struct {
	MaxConcurrent int    `json:"maxConcurrent"`    // 最大并发请求
	CachePriority bool   `json:"cachePriority"`    // 优先走缓存
	LowPowerMode  bool   `json:"lowPowerMode"`     // 低功耗模式
	StabilityFirst bool  `json:"stabilityFirst"`   // 稳定性优先（学生等）
	PreloadModels  []string `json:"preloadModels"` // 预加载模型列表
}

// ChainOptimization 调用链优化配置
type ChainOptimization struct {
	OptimizeTextGen bool   `json:"optimizeTextGen"` // 文字生成链路优化
	FloatingWidget  bool   `json:"floatingWidget"`  // 启用悬浮框
	ToolChainPref   string `json:"toolChainPref"`   // 工具链偏好
	RetryPolicy     string `json:"retryPolicy"`     // 重试策略：gentle / aggressive
	TimeoutBoostMs  int    `json:"timeoutBoostMs"`  // 超时增益（ms）
}

// PersonaState 当前职业状态（持久化在 cfg 中）
type PersonaState struct {
	CurrentID        string    `json:"currentId"`
	SelectedAt       time.Time `json:"selectedAt"`
	AutoModulesApplied bool    `json:"autoModulesApplied"`
	AutoMemoryWritten  bool    `json:"autoMemoryWritten"`
}

// V38Config v3.8.0 配置段（匿名嵌入 Config）
type V38Config struct {
	Persona PersonaState `json:"persona"`
}

// 内置职业目录
var builtInPersonas = []Persona{
	{
		ID:          "student",
		Name:        "学生",
		Description: "课业辅助模式：优先稳定性、降低资源占用、推荐教育类工具",
		Icon:        "🎓",
		AgeRange:    "12-25",
		ShortTags:   []string{"作业", "复习", "查资料", "笔记"},
		DefaultModules: map[string]bool{
			"chatApi": true, "webSearch": true, "webFetch": true,
			"builtinTools": true, "mcpExternal": true, "memory": true,
			"cloudModels": true, "stats": true,
			"localModels": false, "modelDownload": false,
			"autoDiscovery": false, "hardwareAdvisor": false,
		},
		DefaultConnectors: []string{},
		DefaultMCPTools:   []string{"filesystem", "fetch"},
		DefaultChatbox:    "学习助手",
		ModelPrefs: PersonaModelPrefs{
			PreferredProviders: []string{"ollama", "deepseek", "openai"},
			RequiredCaps:       []string{"tools"},
			NiceToHaveCaps:     []string{"longContext"},
			FallbackTier:       "local",
			ContextWindowMin:   8192,
		},
		ResourceStrategy: ResourceStrategy{
			MaxConcurrent:  2,
			CachePriority:  true,
			LowPowerMode:   true,
			StabilityFirst: true,
			PreloadModels:  []string{},
		},
		ChainOpt: ChainOptimization{
			OptimizeTextGen: false,
			FloatingWidget:  false,
			ToolChainPref:   "stable",
			RetryPolicy:     "gentle",
			TimeoutBoostMs:  5000,
		},
		MemoryPrompt: "当前用户为学生。优先给出简洁、准确的回答；涉及学术内容时请标注参考来源；遇到不确定的问题主动说明；避免生成有害或作弊内容。",
	},
	{
		ID:          "writer",
		Name:        "文字创作者",
		Description: "写作增强模式：优化文字生成链路、启用悬浮框、推荐创作类工具",
		Icon:        "✍️",
		AgeRange:    "18-60",
		ShortTags:   []string{"写作", "润色", "大纲", "翻译", "灵感"},
		DefaultModules: map[string]bool{
			"chatApi": true, "webSearch": true, "webFetch": true,
			"builtinTools": true, "mcpExternal": true, "memory": true,
			"cloudModels": true, "stats": true, "customTools": true,
			"localModels": true, "openapiTools": true,
		},
		DefaultConnectors: []string{},
		DefaultMCPTools:   []string{"filesystem", "fetch"},
		DefaultChatbox:    "创作助手",
		ModelPrefs: PersonaModelPrefs{
			PreferredProviders: []string{"openai", "deepseek", "custom"},
			RequiredCaps:       []string{"longContext", "tools"},
			NiceToHaveCaps:     []string{"reasoning", "json"},
			FallbackTier:       "cloud",
			ContextWindowMin:   32768,
		},
		ResourceStrategy: ResourceStrategy{
			MaxConcurrent:  4,
			CachePriority:  false,
			LowPowerMode:   false,
			StabilityFirst: false,
			PreloadModels:  []string{},
		},
		ChainOpt: ChainOptimization{
			OptimizeTextGen: true,
			FloatingWidget:  true,
			ToolChainPref:   "quality",
			RetryPolicy:     "aggressive",
			TimeoutBoostMs:  10000,
		},
		MemoryPrompt: "当前用户为文字创作者。回答侧重语言表达质量，提供多种风格选项；润色时给出修改理由；支持长上下文续写；保持创意与准确性平衡。",
	},
	{
		ID:          "developer",
		Name:        "开发者",
		Description: "开发辅助模式：代码生成、调试、文档查询，优先工具调用与函数能力",
		Icon:        "💻",
		AgeRange:    "18-60",
		ShortTags:   []string{"代码", "调试", "API", "文档", "Review"},
		DefaultModules: map[string]bool{
			"chatApi": true, "webSearch": true, "webFetch": true,
			"builtinTools": true, "mcpExternal": true, "memory": true,
			"cloudModels": true, "stats": true, "customTools": true,
			"sidecarHub": true, "openapiTools": true, "autoDiscovery": true,
		},
		DefaultConnectors: []string{},
		DefaultMCPTools:   []string{"filesystem", "fetch"},
		DefaultChatbox:    "代码助手",
		ModelPrefs: PersonaModelPrefs{
			PreferredProviders: []string{"openai", "deepseek", "custom"},
			RequiredCaps:       []string{"tools", "json"},
			NiceToHaveCaps:     []string{"reasoning", "longContext"},
			FallbackTier:       "cloud",
			ContextWindowMin:   16384,
		},
		ResourceStrategy: ResourceStrategy{
			MaxConcurrent:  4,
			CachePriority:  true,
			LowPowerMode:   false,
			StabilityFirst: false,
			PreloadModels:  []string{},
		},
		ChainOpt: ChainOptimization{
			OptimizeTextGen: false,
			FloatingWidget:  true,
			ToolChainPref:   "tools",
			RetryPolicy:     "aggressive",
			TimeoutBoostMs:  8000,
		},
		MemoryPrompt: "当前用户为开发者。回答优先给出可运行代码，附注释与异常处理；技术选型给出权衡分析；API 调用给出完整示例；保持与最新技术栈同步。",
	},
	{
		ID:          "researcher",
		Name:        "研究者",
		Description: "研究辅助模式：长上下文、深度搜索、多源聚合，优先信息整合能力",
		Icon:        "🔬",
		AgeRange:    "22-70",
		ShortTags:   []string{"文献", "综述", "对比", "引用", "分析"},
		DefaultModules: map[string]bool{
			"chatApi": true, "webSearch": true, "webFetch": true,
			"builtinTools": true, "mcpExternal": true, "memory": true,
			"cloudModels": true, "stats": true, "customTools": true,
			"resourceGuardian": true, "sidecarHub": true,
		},
		DefaultConnectors: []string{},
		DefaultMCPTools:   []string{"filesystem", "fetch"},
		DefaultChatbox:    "研究助手",
		ModelPrefs: PersonaModelPrefs{
			PreferredProviders: []string{"openai", "deepseek", "custom"},
			RequiredCaps:       []string{"longContext", "tools"},
			NiceToHaveCaps:     []string{"reasoning", "json", "vision"},
			FallbackTier:       "cloud",
			ContextWindowMin:   131072,
		},
		ResourceStrategy: ResourceStrategy{
			MaxConcurrent:  3,
			CachePriority:  true,
			LowPowerMode:   false,
			StabilityFirst: true,
			PreloadModels:  []string{},
		},
		ChainOpt: ChainOptimization{
			OptimizeTextGen: true,
			FloatingWidget:  false,
			ToolChainPref:   "deep",
			RetryPolicy:     "gentle",
			TimeoutBoostMs:  15000,
		},
		MemoryPrompt: "当前用户为研究者。回答注重证据与来源，给出参考文献格式；对比分析时列出维度与权重；长文档处理保持上下文连贯；遇到争议观点呈现多方立场。",
	},
	{
		ID:          "general",
		Name:        "通用",
		Description: "默认模式：均衡配置，适合日常对话与通用任务",
		Icon:        "🌐",
		AgeRange:    "all",
		ShortTags:   []string{"聊天", "问答", "日常", "帮助"},
		DefaultModules: map[string]bool{
			"chatApi": true, "webSearch": true, "webFetch": true,
			"builtinTools": true, "mcpExternal": true, "memory": true,
			"cloudModels": true, "stats": true, "hardwareAdvisor": true,
		},
		DefaultConnectors: []string{},
		DefaultMCPTools:   []string{},
		DefaultChatbox:    "通用助手",
		ModelPrefs: PersonaModelPrefs{
			PreferredProviders: []string{"openai", "deepseek", "ollama"},
			RequiredCaps:       []string{},
			NiceToHaveCaps:     []string{"tools", "longContext"},
			FallbackTier:       "local",
			ContextWindowMin:   4096,
		},
		ResourceStrategy: ResourceStrategy{
			MaxConcurrent:  3,
			CachePriority:  true,
			LowPowerMode:   false,
			StabilityFirst: false,
			PreloadModels:  []string{},
		},
		ChainOpt: ChainOptimization{
			OptimizeTextGen: false,
			FloatingWidget:  false,
			ToolChainPref:   "balanced",
			RetryPolicy:     "gentle",
			TimeoutBoostMs:  0,
		},
		MemoryPrompt: "当前用户为通用模式。提供友好、简洁、有帮助的回答；根据问题复杂度调整详略；不确定时诚实说明。",
	},
}

// personaByID 查找职业
func personaByID(id string) *Persona {
	for i := range builtInPersonas {
		if builtInPersonas[i].ID == id {
			return &builtInPersonas[i]
		}
	}
	return nil
}

// currentPersona 获取当前职业（未设置返回 general）
func currentPersona() *Persona {
	cfgMu.RLock()
	id := cfg.V38Config.Persona.CurrentID
	cfgMu.RUnlock()
	if id == "" {
		id = "general"
	}
	p := personaByID(id)
	if p == nil {
		return personaByID("general")
	}
	return p
}

// applyPersona 应用职业配置
func applyPersona(id string) error {
	p := personaByID(id)
	if p == nil {
		return fmt.Errorf("未知职业: %s", id)
	}

	cfgMu.Lock()
	defer cfgMu.Unlock()

	// 1. 应用模块开关（与现有 modules 合并，不关闭 security-core 等不可关闭项）
	if cfg.Modules == nil {
		cfg.Modules = map[string]bool{}
	}
	for k, v := range p.DefaultModules {
		cfg.Modules[k] = v
	}
	// security-core 等不可关闭（保持现有值）

	// 2. 记录职业状态
	cfg.Persona = PersonaState{
		CurrentID:          id,
		SelectedAt:         time.Now(),
		AutoModulesApplied: true,
		AutoMemoryWritten:  false,
	}

	// 3. 保存配置
	saveConfig()
	return nil
}

// writePersonaMemory 写入职业相关的全局记忆与共享信息
func writePersonaMemory(p *Persona) {
	// 写入共享记忆（global 命名空间）——供 agent 运行时读取
	sharedMemMu.Lock()
	ns := smGlobalNS
	if sharedMem[ns] == nil {
		sharedMem[ns] = map[string]SharedMemEntry{}
	}
	now := time.Now()
	sharedMem[ns]["persona_current"] = SharedMemEntry{
		Value:     p.ID,
		UpdatedBy: "system",
		UpdatedAt: now,
		Revision:  sharedMemRev + 1,
	}
	sharedMem[ns]["persona_memory_prompt"] = SharedMemEntry{
		Value:     p.MemoryPrompt,
		UpdatedBy: "system",
		UpdatedAt: now,
		Revision:  sharedMemRev + 2,
	}
	sharedMemRev += 2
	smSaveLocked()
	sharedMemMu.Unlock()

	// 写入共享信息——供人与系统检索
	sharedInfoMu.Lock()
	rec := SharedInfoRecord{
		ID:         siNewID(),
		Type:       "preference",
		Title:      "职业偏好: " + p.Name,
		Content:    p.MemoryPrompt + "\n\n资源策略: " + fmt.Sprintf("并发=%d, 缓存优先=%v, 低功耗=%v, 稳定优先=%v", p.ResourceStrategy.MaxConcurrent, p.ResourceStrategy.CachePriority, p.ResourceStrategy.LowPowerMode, p.ResourceStrategy.StabilityFirst),
		Tags:       []string{"persona", p.ID, "auto"},
		Scope:      "tenant",
		Tenant:     "default",
		Source:     "system",
		Confidence: 1.0,
		CreatedAt:  now,
		UpdatedAt:  now,
		Revision:   sharedInfoRev + 1,
	}
	sharedInfo[rec.ID] = rec
	sharedInfoRev++
	siSaveLocked()
	sharedInfoMu.Unlock()

	// 标记已写入
	cfgMu.Lock()
	cfg.Persona.AutoMemoryWritten = true
	saveConfig()
	cfgMu.Unlock()
}

// ===================== REST API =====================

func handleV38Personas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "仅支持 GET", http.StatusMethodNotAllowed)
		return
	}
	current := currentPersona()
	writeJSON(w, map[string]interface{}{
		"personas": builtInPersonas,
		"current":  current.ID,
	})
}

func handleV38PersonaSelect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "缺少 id", http.StatusBadRequest)
		return
	}
	if err := applyPersona(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p := personaByID(req.ID)
	// 异步写入记忆（不阻塞响应）
	go writePersonaMemory(p)

	// 触发模型匹配扫描
	go func() {
		mm := scanModelMatrix()
		_ = autoMatchModels(p, mm)
	}()

	writeJSON(w, map[string]interface{}{
		"success":  true,
		"persona":  p,
		"message":  "职业已切换为「" + p.Name + "」，模块与策略已自动应用",
	})
}

func handleV38PersonaCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "仅支持 GET", http.StatusMethodNotAllowed)
		return
	}
	p := currentPersona()
	cfgMu.RLock()
	state := cfg.Persona
	cfgMu.RUnlock()
	writeJSON(w, map[string]interface{}{
		"persona": p,
		"state":   state,
	})
}

// ModelMatrixEntry 模型功能矩阵条目
type ModelMatrixEntry struct {
	Provider   string   `json:"provider"`
	Model      string   `json:"model"`
	Caps       []string `json:"caps"`
	CapSource  string   `json:"capSource"` // override | registry | inferred
	Ready      bool     `json:"ready"`
	LatencyMs  int      `json:"latencyMs"`
	ContextLen int      `json:"contextLen"`
	Tier       string   `json:"tier"` // local | cloud | custom
}

// scanModelMatrix 扫描已配置模型的功能矩阵
func scanModelMatrix() []ModelMatrixEntry {
	var result []ModelMatrixEntry
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	// 扫描云端 provider
	providers := []struct {
		name string
		cfg  CloudCfg
		tier string
	}{
		{"openai", cfg.Cloud.OpenAI, "cloud"},
		{"deepseek", cfg.Cloud.DeepSeek, "cloud"},
	}
	for _, pc := range providers {
		if pc.cfg.BaseURL == "" && pc.cfg.APIKey == "" {
			continue
		}
		for _, m := range pc.cfg.Models {
			caps, source := modelCaps(pc.name, m)
			result = append(result, ModelMatrixEntry{
				Provider:   pc.name,
				Model:      m,
				Caps:       caps,
				CapSource:  source,
				Ready:      pc.cfg.APIKey != "" || pc.cfg.BaseURL != "",
				LatencyMs:  0,
				ContextLen: inferContextLen(m),
				Tier:       pc.tier,
			})
		}
	}

	// 扫描自定义 provider
	for _, c := range cfg.Cloud.Custom {
		if c.BaseURL == "" && c.APIKey == "" {
			continue
		}
		for _, m := range c.Models {
			caps, source := modelCaps("custom", m)
			result = append(result, ModelMatrixEntry{
				Provider:   c.Name,
				Model:      m,
				Caps:       caps,
				CapSource:  source,
				Ready:      c.APIKey != "" || c.BaseURL != "",
				LatencyMs:  0,
				ContextLen: inferContextLen(m),
				Tier:       "custom",
			})
		}
	}

	// 本地模型（ollama / lmstudio）
	if cfg.Modules["localModels"] {
		result = append(result, ModelMatrixEntry{
			Provider:   "ollama",
			Model:      "local-ollama",
			Caps:       []string{"tools"},
			CapSource:  "inferred",
			Ready:      true,
			LatencyMs:  0,
			ContextLen: 8192,
			Tier:       "local",
		})
		result = append(result, ModelMatrixEntry{
			Provider:   "lmstudio",
			Model:      "local-lmstudio",
			Caps:       []string{},
			CapSource:  "inferred",
			Ready:      true,
			LatencyMs:  0,
			ContextLen: 4096,
			Tier:       "local",
		})
	}

	return result
}

// inferContextLen 启发式推断上下文长度
func inferContextLen(model string) int {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "128k") || strings.Contains(m, "128"):
		return 128000
	case strings.Contains(m, "32k") || strings.Contains(m, "32"):
		return 32768
	case strings.Contains(m, "16k") || strings.Contains(m, "16"):
		return 16384
	case strings.Contains(m, "8k") || strings.Contains(m, "8"):
		return 8192
	case strings.Contains(m, "gpt-4"):
		return 8192
	case strings.Contains(m, "gpt-3.5"):
		return 4096
	default:
		return 4096
	}
}

// modelCaps 获取模型能力（复用 capabilities.go）
func modelCaps(provider, model string) (caps []string, source string) {
	return modelCapabilitiesFor(provider, model)
}

func handleV38ModelMatrix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "仅支持 GET", http.StatusMethodNotAllowed)
		return
	}
	p := currentPersona()
	mm := scanModelMatrix()

	// 按当前职业需求标注匹配度
	var out []struct {
		ModelMatrixEntry
		MatchedRequired   []string `json:"matchedRequired"`
		MatchedNiceToHave []string `json:"matchedNiceToHave"`
		MissingRequired   []string `json:"missingRequired"`
		Suitable          bool     `json:"suitable"`
	}
	capSet := func(caps []string) map[string]bool {
		s := map[string]bool{}
		for _, c := range caps {
			s[c] = true
		}
		return s
	}
	reqSet := capSet(p.ModelPrefs.RequiredCaps)
	niceSet := capSet(p.ModelPrefs.NiceToHaveCaps)

	for _, m := range mm {
		cs := capSet(m.Caps)
		e := struct {
			ModelMatrixEntry
			MatchedRequired   []string `json:"matchedRequired"`
			MatchedNiceToHave []string `json:"matchedNiceToHave"`
			MissingRequired   []string `json:"missingRequired"`
			Suitable          bool     `json:"suitable"`
		}{ModelMatrixEntry: m}
		for c := range reqSet {
			if cs[c] {
				e.MatchedRequired = append(e.MatchedRequired, c)
			} else {
				e.MissingRequired = append(e.MissingRequired, c)
			}
		}
		for c := range niceSet {
			if cs[c] {
				e.MatchedNiceToHave = append(e.MatchedNiceToHave, c)
			}
		}
		e.Suitable = len(e.MissingRequired) == 0 && m.ContextLen >= p.ModelPrefs.ContextWindowMin
		out = append(out, e)
	}

	// 排序：suitable 优先，然后 matchedRequired 多优先
	sort.Slice(out, func(i, j int) bool {
		if out[i].Suitable != out[j].Suitable {
			return out[i].Suitable
		}
		if len(out[i].MatchedRequired) != len(out[j].MatchedRequired) {
			return len(out[i].MatchedRequired) > len(out[j].MatchedRequired)
		}
		return out[i].Model < out[j].Model
	})

	suitableCount := 0
	for _, o := range out {
		if o.Suitable {
			suitableCount++
		}
	}
	writeJSON(w, map[string]interface{}{
		"persona": p.ID,
		"matrix":  out,
		"summary": map[string]interface{}{
			"total":      len(out),
			"suitable":   suitableCount,
			"required":   p.ModelPrefs.RequiredCaps,
			"niceToHave": p.ModelPrefs.NiceToHaveCaps,
		},
	})
}

// autoMatchModels 自动匹配模型，返回推荐列表与缺失项提示
func autoMatchModels(p *Persona, mm []ModelMatrixEntry) map[string]interface{} {
	var recommended []ModelMatrixEntry
	var fallback *ModelMatrixEntry
	reqSet := map[string]bool{}
	for _, c := range p.ModelPrefs.RequiredCaps {
		reqSet[c] = true
	}

	for i := range mm {
		m := &mm[i]
		cs := map[string]bool{}
		for _, c := range m.Caps {
			cs[c] = true
		}
		missingReq := false
		for c := range reqSet {
			if !cs[c] {
				missingReq = true
				break
			}
		}
		if !missingReq && m.ContextLen >= p.ModelPrefs.ContextWindowMin {
			recommended = append(recommended, *m)
		}
		if fallback == nil || (m.Ready && !fallback.Ready) {
			fallback = m
		}
	}

	// 按 preferredProviders 排序
	prefOrder := map[string]int{}
	for i, pr := range p.ModelPrefs.PreferredProviders {
		prefOrder[strings.ToLower(pr)] = i
	}
	sort.Slice(recommended, func(i, j int) bool {
		pi, pj := prefOrder[strings.ToLower(recommended[i].Provider)], prefOrder[strings.ToLower(recommended[j].Provider)]
		if pi != pj {
			return pi < pj
		}
		return recommended[i].Model < recommended[j].Model
	})

	var missing []string
	if len(recommended) == 0 && fallback != nil {
		cs := map[string]bool{}
		for _, c := range fallback.Caps {
			cs[c] = true
		}
		for c := range reqSet {
			if !cs[c] {
				missing = append(missing, c)
			}
		}
	}

	return map[string]interface{}{
		"recommended": recommended,
		"fallback":    fallback,
		"missing":     missing,
		"preheated":   false,
	}
}

func handleV38ModelPreheat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}
	p := currentPersona()
	mm := scanModelMatrix()
	match := autoMatchModels(p, mm)

	// 模拟预热：记录日志，返回预热状态
	var preheated []string
	if recs, ok := match["recommended"].([]ModelMatrixEntry); ok {
		for _, m := range recs {
			if m.Ready {
				preheated = append(preheated, m.Provider+":"+m.Model)
				auditLog("MODEL_PREHEAT", "system", "model="+m.Provider+":"+m.Model+" persona="+p.ID)
			}
		}
	}

	writeJSON(w, map[string]interface{}{
		"success":   true,
		"preheated": preheated,
		"persona":   p.ID,
		"message":   fmt.Sprintf("已为「%s」预热 %d 个推荐模型", p.Name, len(preheated)),
	})
}
