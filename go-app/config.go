package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ===================== 配置 =====================
type Config struct {
	Cloud struct {
		OpenAI   CloudCfg   `json:"openai"`
		DeepSeek CloudCfg   `json:"deepseek"`
		Custom   []CloudCfg `json:"custom"`
	} `json:"cloud"`
	Search struct {
		Engine string `json:"engine"`
		APIKey string `json:"apiKey"`
	} `json:"search"`
	Security struct {
		WAFEnabled bool   `json:"wafEnabled"`
		Mode       string `json:"mode"`
		APIKey     string `json:"apiKey"`
	} `json:"security"`
	MCP struct {
		ExternalServers []ExtServer `json:"externalServers"`
	} `json:"mcp"`
	Paths struct {
		ModelDir     string   `json:"modelDir"`
		LlamaDir     string   `json:"llamaDir"`
		AllowedRoots []string `json:"allowedRoots"`
	} `json:"paths"`
}

type CloudCfg struct {
	Name    string   `json:"name"`
	BaseURL string   `json:"baseUrl"`
	APIKey  string   `json:"apiKey"`
	Models  []string `json:"models"`
}

type ExtServer struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Enabled bool     `json:"enabled"`
}

func loadConfig() {
	cfg = Config{}
	cfg.Security.WAFEnabled = true
	cfg.Security.Mode = "normal"
	cfg.Security.APIKey = apiKeyDefault
	cfg.Search.Engine = "builtin"
	cfg.MCP.ExternalServers = []ExtServer{}
	parsed := false
	if data, err := os.ReadFile(configPath); err == nil {
		data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
		var c Config
		if json.Unmarshal(data, &c) == nil {
			cfg = c
			parsed = true
			if !bytes.Contains(data, []byte(`"wafEnabled"`)) {
				cfg.Security.WAFEnabled = true
			}
		}
	}
	if cfg.Security.APIKey == "" {
		cfg.Security.APIKey = apiKeyDefault
	}
	if cfg.Security.Mode == "" {
		cfg.Security.Mode = "normal"
	}
	if cfg.Search.Engine == "" {
		cfg.Search.Engine = "builtin"
	}
	if cfg.MCP.ExternalServers == nil {
		cfg.MCP.ExternalServers = []ExtServer{}
	}
	resolvePaths()
	if parsed {
		saveConfig()
	}
}

func saveConfig() {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(configPath, data, 0644)
}

func appDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func resolveConfigPath() {
	for i, a := range os.Args {
		if (a == "-config" || a == "--config") && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			return
		}
	}
	if v := os.Getenv("TARS_CONFIG"); v != "" {
		configPath = v
		return
	}
	d := appDir()
	for _, c := range []string{filepath.Join(d, "config.json"), filepath.Join(d, "..", "config.json")} {
		if fileExists(c) {
			configPath = c
			return
		}
	}
	if fileExists("config.json") {
		configPath = "config.json"
		return
	}
	configPath = filepath.Join(d, "config.json")
}

func resolvePaths() {
	exeDir := appDir()
	if cfg.Paths.ModelDir != "" {
		modelDir = cfg.Paths.ModelDir
	} else {
		modelDir = filepath.Join(exeDir, "Models")
		for _, c := range []string{
			filepath.Join(exeDir, "Models"),
			filepath.Join(exeDir, "..", "Models"),
			filepath.Join(exeDir, "..", "..", "Models"),
		} {
			if isDir(c) {
				modelDir = c
				break
			}
		}
		cfg.Paths.ModelDir = modelDir
	}
	if cfg.Paths.LlamaDir != "" {
		llamaDir = cfg.Paths.LlamaDir
	} else {
		llamaDir = filepath.Join(exeDir, "llama")
		for _, c := range []string{
			filepath.Join(exeDir, "llama"),
			filepath.Join(exeDir, "..", "llama"),
			filepath.Join(exeDir, "..", "..", "llama"),
		} {
			if isDir(c) {
				llamaDir = c
				break
			}
		}
		cfg.Paths.LlamaDir = llamaDir
	}
	if len(cfg.Paths.AllowedRoots) > 0 {
		allowedRoots = append([]string(nil), cfg.Paths.AllowedRoots...)
		return
	}
	roots := []string{exeDir}
	if home, err := os.UserHomeDir(); err == nil {
		for _, sub := range []string{"Desktop", "Documents", "Downloads", "Doubao"} {
			if isDir(filepath.Join(home, sub)) {
				roots = append(roots, filepath.Join(home, sub))
			}
		}
	}
	parent := filepath.Dir(exeDir)
	if isDir(parent) && filepath.Clean(parent) != filepath.Clean(exeDir) {
		roots = append(roots, parent)
	}
	allowedRoots = roots
	cfg.Paths.AllowedRoots = append([]string(nil), roots...)
}

func exeDrive() string {
	exe, err := os.Executable()
	if err == nil && len(exe) >= 3 && exe[1] == ':' {
		return string(exe[0]) + `:\`
	}
	return `C:\`
}

func setJSONPath(root map[string]interface{}, path string, value interface{}) {
	parts := strings.Split(path, ".")
	cur := root
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = value
			return
		}
		next, ok := cur[p].(map[string]interface{})
		if !ok {
			next = map[string]interface{}{}
			cur[p] = next
		}
		cur = next
	}
}
