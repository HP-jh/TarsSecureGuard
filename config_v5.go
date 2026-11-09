package main

// config_v5.go - 统一配置结构（Phase E: 配置简化）
//
// 问题：当前配置分散在 7 个版本化结构体中（V3Config, V32Config, V33Config,
//       V34Config, V35Config, V38Config, V4101Config），难以维护和理解。
//
// 解决方案：创建 UnifiedConfig 结构，按功能域组织配置，提供向后兼容的迁移路径。

import (
	"encoding/json"
	"fmt"
	"os"
)

// UnifiedConfig v5 统一配置结构
// 按功能域组织，替代分散的版本化配置段
type UnifiedConfig struct {
	// Cloud providers and models
	Cloud struct {
		OpenAI   CloudCfg   `json:"openai"`
		DeepSeek CloudCfg   `json:"deepseek"`
		Custom   []CloudCfg `json:"custom"`
	} `json:"cloud"`

	// Providers v3.2+ provider registry and overrides
	Providers struct {
		Registry map[string]ProviderOverride `json:"registry"`
		Circuit  struct {
			FailureThreshold int `json:"failureThreshold"` // default: 5
			OpenSeconds      int `json:"openSeconds"`      // default: 30
			ProbeIntervalSec int `json:"probeIntervalSec"` // default: 60, 0=disabled
		} `json:"circuit"`
		ResponseCache struct {
			Enabled    bool `json:"enabled"`    // default: true
			TTLSec     int  `json:"ttlSec"`     // default: 300
			MaxEntries int  `json:"maxEntries"` // default: 256
		} `json:"responseCache"`
		Pool struct {
			MaxIdleConnsPerHost int `json:"maxIdleConnsPerHost"` // default: 32
		} `json:"pool"`
	} `json:"providers"`

	// Security core (cannot be disabled)
	Security struct {
		WAFEnabled        bool        `json:"wafEnabled"` // default: true (forced)
		Mode              string      `json:"mode"`       // normal | strict
		APIKey            string      `json:"apiKey"`
		Firewall          FirewallCfg `json:"firewall"`
		DefaultKeyAllowed *bool       `json:"defaultKeyAllowed"`
		PIIMaskEnabled    bool        `json:"piimaskEnabled"`
		PIIMaskLevel      string      `json:"piimaskLevel"` // full | partial | hash
		CSP               CSPConfig   `json:"csp"`
		AuditLogEnabled   bool        `json:"auditLogEnabled"` // default: true
	} `json:"security"`

	// Resource management v3.0+
	Resource struct {
		Guardian struct {
			Enabled       bool  `json:"enabled"`       // default: true
			MemoryLimitMB int64 `json:"memoryLimitMB"` // default: 1024
			CPUThreshold  int   `json:"cpuThreshold"`  // default: 80
		} `json:"guardian"`
		Tier1 struct {
			Enabled *bool `json:"enabled"` // default: true (nil=true for legacy)
		} `json:"tier1"`
	} `json:"resource"`

	// Rate limiting v3.0+
	RateLimit struct {
		IPReputation struct {
			Enabled *bool `json:"enabled"` // default: true (nil=true for legacy)
		} `json:"ipReputation"`
		SemanticGuard struct {
			Enabled *bool `json:"enabled"` // default: true (nil=true for legacy)
		} `json:"semanticGuard"`
	} `json:"rateLimit"`

	// Smart routing v3.0+
	Router struct {
		Enabled *bool `json:"enabled"` // default: true (nil=true for legacy)
	} `json:"router"`

	// Capabilities v3.3+
	Capabilities struct {
		AutoReroute bool              `json:"autoReroute"` // default: true
		ModelCaps   map[string][]string `json:"modelCaps"`
	} `json:"capabilities"`

	// Pricing and connectors v3.4+
	Pricing struct {
		Overrides map[string]*Pricing `json:"overrides"`
	} `json:"pricing"`
	Connectors []ConnectorInstance `json:"connectors"`

	// UI v3.5+
	UI struct {
		Mode           string                       `json:"mode"` // beginner | advanced
		ModuleProfiles map[string]map[string]bool   `json:"moduleProfiles"`
	} `json:"ui"`

	// Persona v3.8+
	Persona PersonaConfig `json:"persona"`

	// Model aliases and sticky routing v4.10.1+
	ModelAliases []ModelAlias `json:"modelAliases"`
	StickyRouter struct {
		Enabled    bool `json:"enabled"`    // default: true
		PersistSec int  `json:"persistSec"` // default: 60
		MaxEntries int  `json:"maxEntries"` // default: 1024
	} `json:"stickyRouter"`

	// Search
	Search struct {
		Engine string `json:"engine"` // builtin | serper
		APIKey string `json:"apiKey"`
	} `json:"search"`

	// MCP external servers
	MCP struct {
		ExternalServers []ExtServer `json:"externalServers"`
	} `json:"mcp"`

	// Users and tenants
	Users   []User     `json:"users"`
	Tenants TenantsCfg `json:"tenants"`

	// Modules (feature flags)
	Modules map[string]bool `json:"modules"`

	// Custom tools and agents
	CustomTools  []CustomTool     `json:"customTools"`
	CustomAgents []CustomAgentDef `json:"customAgents"`

	// System paths
	Paths struct {
		ModelDir     string   `json:"modelDir"`
		LlamaDir     string   `json:"llamaDir"`
		AllowedRoots []string `json:"allowedRoots"`
	} `json:"paths"`

	// Direct connection
	Direct DirectCfg `json:"direct"`

	// OAuth and governance v3.2.2+
	OAuth      OAuthCfg      `json:"oauth"`
	Gatekeeper GatekeeperCfg `json:"gatekeeper"`
	Audit      AuditCfg      `json:"audit"`

	// Install and data roots v4.15.1+
	InstallRoot string `json:"installRoot"`
	DataRoot    string `json:"dataRoot"`
}

// MigrateToUnified 将旧配置迁移到统一结构
// 向后兼容：从分散的版本化结构合并到 UnifiedConfig
func MigrateToUnified(cfg *Config) *UnifiedConfig {
	uc := &UnifiedConfig{}

	// Cloud providers
	uc.Cloud.OpenAI = cfg.Cloud.OpenAI
	uc.Cloud.DeepSeek = cfg.Cloud.DeepSeek
	uc.Cloud.Custom = cfg.Cloud.Custom

	// Providers (from V32Config)
	uc.Providers.Registry = cfg.V32Config.Providers
	if uc.Providers.Registry == nil {
		uc.Providers.Registry = make(map[string]ProviderOverride)
	}
	uc.Providers.Circuit.FailureThreshold = cfg.V32Config.Circuit.FailureThreshold
	uc.Providers.Circuit.OpenSeconds = cfg.V32Config.Circuit.OpenSeconds
	uc.Providers.Circuit.ProbeIntervalSec = cfg.V32Config.Circuit.ProbeIntervalSec
	uc.Providers.ResponseCache.TTLSec = cfg.V32Config.ResponseCache.TTLSec
	uc.Providers.ResponseCache.MaxEntries = cfg.V32Config.ResponseCache.MaxEntries
	if cfg.V32Config.ResponseCache.Enabled != nil {
		uc.Providers.ResponseCache.Enabled = *cfg.V32Config.ResponseCache.Enabled
	} else {
		uc.Providers.ResponseCache.Enabled = true // default
	}
	uc.Providers.Pool.MaxIdleConnsPerHost = cfg.V32Config.Pool.MaxIdleConnsPerHost

	// Security
	uc.Security.WAFEnabled = cfg.Security.WAFEnabled
	uc.Security.Mode = cfg.Security.Mode
	uc.Security.APIKey = cfg.Security.APIKey
	uc.Security.Firewall = cfg.Security.Firewall
	uc.Security.DefaultKeyAllowed = cfg.Security.DefaultKeyAllowed
	uc.Security.PIIMaskEnabled = cfg.Security.PIIMaskEnabled
	uc.Security.PIIMaskLevel = cfg.Security.PIIMaskLevel
	uc.Security.CSP = cfg.Security.CSP
	uc.Security.AuditLogEnabled = cfg.Security.AuditLogEnabled

	// Resource (from V3Config)
	uc.Resource.Guardian.Enabled = true // default
	uc.Resource.Guardian.MemoryLimitMB = cfg.V3Config.Resource.MemoryLimitMB
	uc.Resource.Guardian.CPUThreshold = cfg.V3Config.Resource.CPUThreshold
	uc.Resource.Tier1.Enabled = cfg.V3Config.Tier1.Enabled

	// Rate limiting (from V3Config)
	uc.RateLimit.IPReputation.Enabled = cfg.V3Config.IPReputation.Enabled
	uc.RateLimit.SemanticGuard.Enabled = cfg.V3Config.SemanticGuard.Enabled

	// Router (from V3Config)
	uc.Router.Enabled = cfg.V3Config.Router.Enabled

	// Capabilities (from V33Config)
	if cfg.V33Config.Capabilities.AutoReroute != nil {
		uc.Capabilities.AutoReroute = *cfg.V33Config.Capabilities.AutoReroute
	} else {
		uc.Capabilities.AutoReroute = true // default
	}
	uc.Capabilities.ModelCaps = cfg.V33Config.ModelCaps

	// Pricing (from V34Config)
	uc.Pricing.Overrides = cfg.V34Config.Pricing.Overrides
	uc.Connectors = cfg.V34Config.Connectors

	// UI (from V35Config)
	uc.UI.Mode = cfg.V35Config.UI.Mode
	uc.UI.ModuleProfiles = cfg.V35Config.ModuleProfiles

	// Persona (from V38Config)
	uc.Persona = cfg.V38Config.Persona

	// Model aliases (from V4101Config)
	uc.ModelAliases = cfg.V4101Config.ModelAliases
	uc.StickyRouter.Enabled = cfg.V4101Config.StickyRouter.Enabled
	uc.StickyRouter.PersistSec = cfg.V4101Config.StickyRouter.PersistSec
	uc.StickyRouter.MaxEntries = cfg.V4101Config.StickyRouter.MaxEntries

	// Search
	uc.Search.Engine = cfg.Search.Engine
	uc.Search.APIKey = cfg.Search.APIKey

	// MCP
	uc.MCP.ExternalServers = cfg.MCP.ExternalServers

	// Users and tenants
	uc.Users = cfg.Users
	uc.Tenants = cfg.Tenants

	// Modules
	uc.Modules = cfg.Modules

	// Custom tools and agents
	uc.CustomTools = cfg.CustomTools
	uc.CustomAgents = cfg.CustomAgents

	// Paths
	uc.Paths.ModelDir = cfg.Paths.ModelDir
	uc.Paths.LlamaDir = cfg.Paths.LlamaDir
	uc.Paths.AllowedRoots = cfg.Paths.AllowedRoots

	// Direct
	uc.Direct = cfg.Direct

	// OAuth and governance
	uc.OAuth = cfg.OAuth
	uc.Gatekeeper = cfg.Gatekeeper
	uc.Audit = cfg.Audit

	// Install and data roots
	uc.InstallRoot = cfg.InstallRoot
	uc.DataRoot = cfg.DataRoot

	return uc
}

// SaveUnifiedConfig 保存统一配置到文件
func SaveUnifiedConfig(path string, uc *UnifiedConfig) error {
	data, err := json.MarshalIndent(uc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal unified config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write unified config: %w", err)
	}

	return nil
}

// LoadUnifiedConfig 从文件加载统一配置
func LoadUnifiedConfig(path string) (*UnifiedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read unified config: %w", err)
	}

	uc := &UnifiedConfig{}
	if err := json.Unmarshal(data, uc); err != nil {
		return nil, fmt.Errorf("unmarshal unified config: %w", err)
	}

	return uc, nil
}

// MergeUnifiedToConfig 将统一配置合并回旧结构（向后兼容）
// 用于渐进式迁移：新配置写入 UnifiedConfig，旧代码仍读取 Config
func MergeUnifiedToConfig(uc *UnifiedConfig, cfg *Config) {
	// Cloud
	cfg.Cloud.OpenAI = uc.Cloud.OpenAI
	cfg.Cloud.DeepSeek = uc.Cloud.DeepSeek
	cfg.Cloud.Custom = uc.Cloud.Custom

	// Providers (to V32Config)
	cfg.V32Config.Providers = uc.Providers.Registry
	cfg.V32Config.Circuit.FailureThreshold = uc.Providers.Circuit.FailureThreshold
	cfg.V32Config.Circuit.OpenSeconds = uc.Providers.Circuit.OpenSeconds
	cfg.V32Config.Circuit.ProbeIntervalSec = uc.Providers.Circuit.ProbeIntervalSec
	cfg.V32Config.ResponseCache.TTLSec = uc.Providers.ResponseCache.TTLSec
	cfg.V32Config.ResponseCache.MaxEntries = uc.Providers.ResponseCache.MaxEntries
	enabled := uc.Providers.ResponseCache.Enabled
	cfg.V32Config.ResponseCache.Enabled = &enabled
	cfg.V32Config.Pool.MaxIdleConnsPerHost = uc.Providers.Pool.MaxIdleConnsPerHost

	// Security
	cfg.Security.WAFEnabled = uc.Security.WAFEnabled
	cfg.Security.Mode = uc.Security.Mode
	cfg.Security.APIKey = uc.Security.APIKey
	cfg.Security.Firewall = uc.Security.Firewall
	cfg.Security.DefaultKeyAllowed = uc.Security.DefaultKeyAllowed
	cfg.Security.PIIMaskEnabled = uc.Security.PIIMaskEnabled
	cfg.Security.PIIMaskLevel = uc.Security.PIIMaskLevel
	cfg.Security.CSP = uc.Security.CSP
	cfg.Security.AuditLogEnabled = uc.Security.AuditLogEnabled

	// Resource (to V3Config)
	cfg.V3Config.Resource.MemoryLimitMB = uc.Resource.Guardian.MemoryLimitMB
	cfg.V3Config.Resource.CPUThreshold = uc.Resource.Guardian.CPUThreshold
	cfg.V3Config.Tier1.Enabled = uc.Resource.Tier1.Enabled

	// Rate limiting (to V3Config)
	cfg.V3Config.IPReputation.Enabled = uc.RateLimit.IPReputation.Enabled
	cfg.V3Config.SemanticGuard.Enabled = uc.RateLimit.SemanticGuard.Enabled

	// Router (to V3Config)
	cfg.V3Config.Router.Enabled = uc.Router.Enabled

	// Capabilities (to V33Config)
	autoReroute := uc.Capabilities.AutoReroute
	cfg.V33Config.Capabilities.AutoReroute = &autoReroute
	cfg.V33Config.ModelCaps = uc.Capabilities.ModelCaps

	// Pricing (to V34Config)
	cfg.V34Config.Pricing.Overrides = uc.Pricing.Overrides
	cfg.V34Config.Connectors = uc.Connectors

	// UI (to V35Config)
	cfg.V35Config.UI.Mode = uc.UI.Mode
	cfg.V35Config.ModuleProfiles = uc.UI.ModuleProfiles

	// Persona (to V38Config)
	cfg.V38Config.Persona = uc.Persona

	// Model aliases (to V4101Config)
	cfg.V4101Config.ModelAliases = uc.ModelAliases
	cfg.V4101Config.StickyRouter.Enabled = uc.StickyRouter.Enabled
	cfg.V4101Config.StickyRouter.PersistSec = uc.StickyRouter.PersistSec
	cfg.V4101Config.StickyRouter.MaxEntries = uc.StickyRouter.MaxEntries

	// Search
	cfg.Search.Engine = uc.Search.Engine
	cfg.Search.APIKey = uc.Search.APIKey

	// MCP
	cfg.MCP.ExternalServers = uc.MCP.ExternalServers

	// Users and tenants
	cfg.Users = uc.Users
	cfg.Tenants = uc.Tenants

	// Modules
	cfg.Modules = uc.Modules

	// Custom tools and agents
	cfg.CustomTools = uc.CustomTools
	cfg.CustomAgents = uc.CustomAgents

	// Paths
	cfg.Paths.ModelDir = uc.Paths.ModelDir
	cfg.Paths.LlamaDir = uc.Paths.LlamaDir
	cfg.Paths.AllowedRoots = uc.Paths.AllowedRoots

	// Direct
	cfg.Direct = uc.Direct

	// OAuth and governance
	cfg.OAuth = uc.OAuth
	cfg.Gatekeeper = uc.Gatekeeper
	cfg.Audit = uc.Audit

	// Install and data roots
	cfg.InstallRoot = uc.InstallRoot
	cfg.DataRoot = uc.DataRoot
}
