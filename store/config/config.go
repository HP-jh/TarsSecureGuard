// Package config 提供网关配置的加载、校验与原子落盘。
//
// 设计契约（保留清单 F-19 + 必修缺陷）：
//   - 两阶段解析：顶层先解为 map[string]json.RawMessage，再按已知段类型化；
//     下划线注释键（如 providers._说明）容忍并告警，未知段原样保留——
//     修复 v3.8.0「一个注释键导致整份配置反序列化失败、静默回退默认」的 P0 缺陷；
//   - 解析失败显式报错，绝不静默丢弃（调用方应保留上一有效版本）；
//   - 安全底线自动纠正：security.mode 不允许 "off"（CONFIG_CORRECTED 语义）；
//   - Save 原子写（临时文件 + rename），权限 0600。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// 已知段（B1 骨架范围；后续批次新增类型化段时在此登记）。
const (
	SectionListen    = "listen"
	SectionSecurity  = "security"
	SectionProviders = "providers"
)

// 安全底线取值。
const (
	ModeNormal = "normal"
	ModeStrict = "strict"
)

// Listen 接入段。
type Listen struct {
	Addr string `json:"addr"` // 监听地址，默认 :18889
}

// Security 安全段。安全核心强制（F-02）：mode 只允许 normal/strict。
type Security struct {
	Mode string `json:"mode"`
}

// Config 是类型化配置。
// Unknown 保存未类型化段（含下划线注释键）的原文：不参与校验，Save 时原样带回。
// Providers 各条目以 RawMessage 保存，由 providers 域（B5）逐条类型化解析——
// 单条目解析失败只影响该条目，不再拖垮整份配置。
type Config struct {
	Listen    Listen                     `json:"listen"`
	Security  Security                   `json:"security"`
	Providers map[string]json.RawMessage `json:"providers"`

	Unknown  map[string]json.RawMessage `json:"-"`
	warnings []string                   `json:"-"`
}

// Default 返回内置默认配置（安全底线已就位）。
func Default() *Config {
	return &Config{
		Listen:    Listen{Addr: ":18889"},
		Security:  Security{Mode: ModeNormal},
		Providers: map[string]json.RawMessage{},
		Unknown:   map[string]json.RawMessage{},
	}
}

// Load 从 path 加载配置。
// 文件不存在 → 返回默认配置并记告警（不视为错误）；
// 内容解析失败 → 返回错误，调用方必须保留上一有效版本，不得静默回退。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			c := Default()
			c.warnf("config: file %s not found, using built-in defaults", path)
			return c, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse 解析配置字节流（两阶段）。
func Parse(data []byte) (*Config, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: invalid JSON at top level (refusing silent fallback): %w", err)
	}
	c := Default()
	for k, v := range raw {
		switch k {
		case SectionListen:
			if err := json.Unmarshal(v, &c.Listen); err != nil {
				return nil, fmt.Errorf("config: section %q: %w", k, err)
			}
		case SectionSecurity:
			if err := json.Unmarshal(v, &c.Security); err != nil {
				return nil, fmt.Errorf("config: section %q: %w", k, err)
			}
		case SectionProviders:
			if err := c.parseProviders(v); err != nil {
				return nil, err
			}
		default:
			c.Unknown[k] = v
			if strings.HasPrefix(k, "_") {
				c.warnf("config: annotation key %q tolerated (not validated)", k)
			} else {
				c.warnf("config: unknown section %q preserved verbatim", k)
			}
		}
	}
	c.applySecurityFloor()
	return c, nil
}

// parseProviders 解析 providers 段：段本身必须是对象；
// 每个非下划线条目必须是 JSON 对象（具体字段由 providers 域校验）。
// 下划线条目（如 "_说明"）容忍并保留原文。
func (c *Config) parseProviders(v json.RawMessage) error {
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(v, &entries); err != nil {
		return fmt.Errorf("config: section %q must be a JSON object: %w", SectionProviders, err)
	}
	for name, ev := range entries {
		if strings.HasPrefix(name, "_") {
			c.warnf("config: providers annotation key %q tolerated", name)
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(ev, &obj); err != nil {
			return fmt.Errorf("config: provider %q must be a JSON object: %w", name, err)
		}
	}
	c.Providers = entries
	return nil
}

// applySecurityFloor 执行安全底线自动纠正（F-02/F-03：安全核心强制、只能加严）。
func (c *Config) applySecurityFloor() {
	switch c.Security.Mode {
	case ModeNormal, ModeStrict:
		// 合法取值不动
	default:
		c.warnf("config: security.mode %q not allowed, auto-corrected to %q (CONFIG_CORRECTED)", c.Security.Mode, ModeNormal)
		c.Security.Mode = ModeNormal
	}
	if c.Listen.Addr == "" {
		c.warnf("config: listen.addr empty, auto-corrected to %q", ":18889")
		c.Listen.Addr = ":18889"
	}
}

// Save 原子写配置到 path：类型化段覆盖同名键，Unknown 段原样带回；
// 临时文件 + rename，权限 0600。
func (c *Config) Save(path string) error {
	raw := make(map[string]json.RawMessage, len(c.Unknown)+3)
	for k, v := range c.Unknown {
		raw[k] = v
	}
	put := func(k string, val any) error {
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("config: marshal section %q: %w", k, err)
		}
		raw[k] = b
		return nil
	}
	if err := put(SectionListen, c.Listen); err != nil {
		return err
	}
	if err := put(SectionSecurity, c.Security); err != nil {
		return err
	}
	if err := put(SectionProviders, c.Providers); err != nil {
		return err
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("config: write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: atomic rename: %w", err)
	}
	return nil
}

// Warnings 返回加载/纠正过程中产生的告警副本。
func (c *Config) Warnings() []string {
	out := make([]string, len(c.warnings))
	copy(out, c.warnings)
	return out
}

func (c *Config) warnf(format string, args ...any) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}
