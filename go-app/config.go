package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type CloudProvider struct {
	APIKey  string `json:"apiKey"`
	BaseURL string `json:"baseUrl"`
	Name    string `json:"name"`
}

type CloudConfig struct {
	OpenAI   CloudProvider `json:"openai"`
	DeepSeek CloudProvider `json:"deepseek"`
}

type SecurityConfig struct {
	APIKey string `json:"apiKey"`
	Mode   string `json:"mode"`
	WAF    bool   `json:"wafEnabled"`
}

type SearchConfig struct {
	Engine string `json:"engine"`
	APIKey string `json:"apiKey"`
}

type Config struct {
	Cloud    CloudConfig    `json:"cloud"`
	Search   SearchConfig   `json:"search"`
	Security SecurityConfig `json:"security"`
}

func defaultConfig() Config {
	return Config{
		Cloud: CloudConfig{
			OpenAI: CloudProvider{BaseURL: "https://api.openai.com/v1", Name: "OpenAI"},
			DeepSeek: CloudProvider{BaseURL: "https://api.deepseek.com/v1", Name: "DeepSeek"},
		},
		Search: SearchConfig{Engine: "builtin"},
		Security: SecurityConfig{APIKey: apiKeyDefault, Mode: "normal", WAF: true},
	}
}

func resolveConfigPath() {
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		p := filepath.Join(exeDir, "config.json")
		if _, err := os.Stat(p); err == nil {
			configPath = p
			return
		}
	}
	configPath = "config.json"
}

func resolvePaths() {
	baseDir := "."
	if configPath != "" {
		if d := filepath.Dir(configPath); d != "" {
			baseDir = d
		}
	}
	if exe, err := os.Executable(); err == nil {
		if fi, err := os.Stat(exe); err == nil && !fi.IsDir() {
			if strings.HasSuffix(strings.ToLower(exe), ".exe") {
				baseDir = filepath.Dir(exe)
			}
		}
	}
	modelDir = filepath.Join(baseDir, "models")
	llamaDir = filepath.Join(baseDir, "llama.cpp")
	for _, d := range []string{modelDir, llamaDir} {
		_ = os.MkdirAll(d, 0755)
	}
	allowedRoots = []string{modelDir, llamaDir}
}

func loadConfig() {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	cfg = defaultConfig()
	data, err := os.ReadFile(configPath)
	if err != nil {
		logMsg("config.json not found, using defaults")
		saveConfigLocked()
		resolvePaths()
		return
	}
	data = []byte(strings.TrimPrefix(string(data), "\xef\xbb\xbf"))
	if err := json.Unmarshal(data, &cfg); err != nil {
		logMsg("config.json parse error, using defaults: " + err.Error())
		cfg = defaultConfig()
	}
	resolvePaths()
}

func saveConfig() {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	saveConfigLocked()
}

func saveConfigLocked() {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(configPath, data, 0644)
}

func setJSONPath(m map[string]interface{}, path, value string) {
	parts := strings.Split(path, ".")
	for i := 0; i < len(parts)-1; i++ {
		k := parts[i]
		if _, ok := m[k].(map[string]interface{}); !ok {
			m[k] = map[string]interface{}{}
		}
		m = m[k].(map[string]interface{})
	}
	m[parts[len(parts)-1]] = value
}
