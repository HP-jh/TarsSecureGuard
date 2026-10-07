package main

// ===================== v3.2.0 Provider Registry =====================
//
// 「AI 时代的路由器」核心件：每个 provider 一个配置文件（providers/*.json，
// go:embed 编译进二进制）+ 一份运行时覆盖（config.json 的 providers 段 / 环境变量）。
// 新增 provider 只需：① 往 providers/ 放一个 JSON；② （可选）在 config.json
// providers.<id>.apiKey 填密钥——不改任何核心代码。
//
// 安全红线（继承锦衣卫 Tier 1 精神）：
//   - 密钥只经 config.json providers 段或环境变量注入，注册表文件本身不含密钥
//   - 注册表文件禁止出现 "apiKey"/"sk-" 等敏感字样（测试静态扫描）
//   - 所有出站请求经共享连接池（pool.go），走既有 obs/审计链路
//   - 不可绕过 WAF / 语义分级 / 限流：本模块只在 routeChat 的「云端分支」内工作

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
)

//go:embed providers/*.json
var providerFS embed.FS

// ProviderSpec 单个 provider 的静态注册项（providers/<id>.json）
type ProviderSpec struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`     // cloud | local
	Protocol string   `json:"protocol"` // openai-compat | anthropic | gemini | ollama | custom
	BaseURL  string   `json:"baseURL"`
	ChatPath string   `json:"chatPath"`
	KeyEnv   string   `json:"keyEnv"`
	Docs     string   `json:"docs"`
	Models   []string `json:"models"`
	Notes    string   `json:"notes"`
	// v3.3.0：
	ApplyURL    string              `json:"applyUrl,omitempty"`    // API 申请直达链接（UI「获取 Key」入口）
	DefaultCaps []string            `json:"defaultCaps,omitempty"` // 模型默认能力继承
	ModelCaps   map[string][]string `json:"modelCaps,omitempty"`   // 模型级能力覆盖
	Pricing     *Pricing            `json:"pricing,omitempty"`     // provider 级默认定价（USD/1M tokens）
	ModelPricing map[string]*Pricing `json:"modelPricing,omitempty"` // 模型级定价覆盖
	Custom      *CustomAdapterSpec  `json:"custom,omitempty"`      // custom 协议模板（任意后端接入）
}

// CustomAdapterSpec v3.3.0：custom 协议模板——任意 HTTP 后端的声明式接入。
// 请求：Method（默认 POST）+ Path（拼在 baseURL 后）+ Headers（值支持 {{.Key}} 等
// 占位符）+ Body（JSON 模板，任意层级值支持占位符）；
// 响应：ResponsePath 点路径取内容字符串（如 "data.choices.0.message.content"）。
// 占位符全集见 callCustomProvider 注释。
type CustomAdapterSpec struct {
	Method       string                 `json:"method,omitempty"`
	Path         string                 `json:"path"`
	Headers      map[string]string      `json:"headers,omitempty"`
	Body         map[string]interface{} `json:"body,omitempty"`
	ResponsePath string                 `json:"responsePath"`
}

// providerRegistry 加载后的注册表（启动加载一次；热重载仅刷新覆盖层）
type providerRegistry struct {
	mu    sync.RWMutex
	specs map[string]ProviderSpec // key: provider id
	order []string                // 稳定输出顺序（按 id 排序）
}

var preg = &providerRegistry{}

// loadProviderRegistry 启动时加载内嵌注册表文件（失败即致命——注册表是编译产物，损坏说明构建有问题）
func loadProviderRegistry() error {
	entries, err := providerFS.ReadDir("providers")
	if err != nil {
		return err
	}
	specs := map[string]ProviderSpec{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := providerFS.ReadFile("providers/" + e.Name())
		if err != nil {
			return err
		}
		var spec ProviderSpec
		if err := json.Unmarshal(data, &spec); err != nil {
			return fmt.Errorf("provider 注册表文件 %s 解析失败: %w", e.Name(), err)
		}
		if spec.ID == "" || spec.BaseURL == "" || spec.Protocol == "" {
			return fmt.Errorf("provider 注册表文件 %s 缺少 id/baseURL/protocol", e.Name())
		}
		specs[spec.ID] = spec
	}
	if len(specs) < 20 {
		return fmt.Errorf("provider 注册表条目不足 20（当前 %d）", len(specs))
	}
	order := make([]string, 0, len(specs))
	for id := range specs {
		order = append(order, id)
	}
	sort.Strings(order)
	preg.mu.Lock()
	preg.specs = specs
	preg.order = order
	preg.mu.Unlock()
	return nil
}

// providerCount 注册表规模（测试用）
func providerCount() (cloud, local int) {
	preg.mu.RLock()
	defer preg.mu.RUnlock()
	for _, s := range preg.specs {
		if s.Kind == "cloud" {
			cloud++
		} else {
			local++
		}
	}
	return
}

// providerSpec 取单个 provider 静态定义
func providerSpec(id string) (ProviderSpec, bool) {
	preg.mu.RLock()
	defer preg.mu.RUnlock()
	s, ok := preg.specs[id]
	return s, ok
}

// providerEffectiveURL 解析生效 baseURL / chatPath（config 覆盖 > 注册表默认）
func providerEffectiveURL(spec ProviderSpec) (base, chatPath string) {
	base = spec.BaseURL
	chatPath = spec.ChatPath
	if ov := cfg.V32Config.Providers[spec.ID]; ov.BaseURL != "" {
		base = ov.BaseURL
	}
	return base, chatPath
}

// providerAPIKey 密钥解析优先级：config.json providers.<id>.apiKey > 环境变量 keyEnv。
// 只返回密钥值；绝不写日志、绝不进响应。
func providerAPIKey(spec ProviderSpec) (string, bool) {
	if ov := cfg.V32Config.Providers[spec.ID]; ov.APIKey != "" {
		return ov.APIKey, true
	}
	if spec.KeyEnv != "" {
		if v := os.Getenv(spec.KeyEnv); v != "" {
			return v, true
		}
	}
	return "", false
}

// providerEnabled provider 是否启用（默认启用；config providers.<id>.enabled=false 关闭）
func providerEnabled(spec ProviderSpec) bool {
	if ov := cfg.V32Config.Providers[spec.ID]; ov.Enabled != nil {
		return *ov.Enabled
	}
	return true
}

// providerEffectiveModels 模型清单（config 覆盖 > 注册表默认）
func providerEffectiveModels(spec ProviderSpec) []string {
	if ov := cfg.V32Config.Providers[spec.ID]; len(ov.Models) > 0 {
		return ov.Models
	}
	return spec.Models
}

// providerReady provider 是否「已配置可用」（本地运行时恒 ready；云端需密钥 + 启用）
func providerReady(spec ProviderSpec) (ready bool, reason string) {
	if !providerEnabled(spec) {
		return false, "disabled"
	}
	if spec.Kind == "local" {
		return true, ""
	}
	if _, ok := providerAPIKey(spec); !ok {
		return false, "needs-key"
	}
	return true, ""
}

// splitProviderModel 解析 "providerId/model" 形式（providerId 必须在注册表中）
func splitProviderModel(model string) (pid, rest string, ok bool) {
	i := strings.Index(model, "/")
	if i <= 0 || i == len(model)-1 {
		return "", "", false
	}
	pid, rest = model[:i], model[i+1:]
	if rest == "" {
		return "", "", false
	}
	if _, found := providerSpec(pid); !found {
		return "", "", false
	}
	return pid, rest, true
}

// findProviderByModel 全模型名精确匹配：返回注册表中声明了该模型的 provider
func findProviderByModel(model string) (ProviderSpec, bool) {
	preg.mu.RLock()
	defer preg.mu.RUnlock()
	for _, id := range preg.order {
		s := preg.specs[id]
		if !providerEnabled(s) {
			continue
		}
		for _, m := range providerEffectiveModels(s) {
			if m == model {
				return s, true
			}
		}
	}
	return ProviderSpec{}, false
}

// findCloudProviderByModel 仅在云端 provider 中按裸模型名反查（不含本地运行时——
// 本地路由仍走 lmstudio/ollama 前缀与可达性回退，避免注册表劫持既有本地链路）。
// 新增云端 provider 后其 models 列表里的裸模型名即可直接路由，无需改核心代码。
func findCloudProviderByModel(model string) (ProviderSpec, bool) {
	if spec, ok := findProviderByModel(model); ok && spec.Kind == "cloud" {
		return spec, true
	}
	return ProviderSpec{}, false
}

// providerChatEndpoint 拼出完整聊天端点（gemini 的 {model} 占位符在此展开）
func providerChatEndpoint(spec ProviderSpec, model string) string {
	base, chatPath := providerEffectiveURL(spec)
	base = strings.TrimSuffix(base, "/")
	if spec.Protocol == "gemini" {
		return base + strings.ReplaceAll(chatPath, "{model}", model)
	}
	return base + chatPath
}

// handleV32Providers GET /api/admin/v32/providers —— 注册表面板数据。
// 输出永不包含密钥本体，只有 keySet 布尔。
func handleV32Providers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	preg.mu.RLock()
	defer preg.mu.RUnlock()
	states := cbStates()
	list := make([]map[string]interface{}, 0, len(preg.order))
	for _, id := range preg.order {
		s := preg.specs[id]
		keySet := false
		if _, ok := providerAPIKey(s); ok {
			keySet = true
		}
		ready, reason := providerReady(s)
		cb := ""
		if st, ok := states[id]; ok {
			cb = st
		}
		list = append(list, map[string]interface{}{
			"id":       s.ID,
			"name":     s.Name,
			"kind":     s.Kind,
			"protocol": s.Protocol,
			"baseURL":  s.BaseURL,
			"keyEnv":   s.KeyEnv,
			"keySet":   keySet,
			"enabled":  providerEnabled(s),
			"ready":    ready,
			"reason":   reason,
			"circuit":  cb,
			"models":   providerEffectiveModels(s),
			"applyUrl": s.ApplyURL,
			"pricing":  s.Pricing,
			"modelPricing": s.ModelPricing,
			"docs":     s.Docs,
			"notes":    s.Notes,
		})
	}
	writeJSON(w, map[string]interface{}{
		"version":   version,
		"total":     len(list),
		"providers": list,
	})
}
