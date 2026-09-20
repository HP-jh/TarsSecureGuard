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
		Engine string `json:"engine"` // builtin | serper
		APIKey string `json:"apiKey"`
	} `json:"search"`
	Security struct {
		WAFEnabled   bool   `json:"wafEnabled"`
		Mode         string `json:"mode"` // normal | strict | off
		APIKey       string `json:"apiKey"`
		FirewallLock *bool  `json:"firewallLock"` // 默认 true：启动时自动加 Windows 防火墙规则
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
		// 剥离 UTF-8 BOM：记事本等编辑器保存的 JSON 可能带 BOM，Go 解析会失败
		data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
		var c Config
		if json.Unmarshal(data, &c) == nil {
			cfg = c
			parsed = true
			// 配置中未显式声明 wafEnabled 时保持默认开启（bool 零值会误关 WAF）
			if !bytes.Contains(data, []byte(`"wafEnabled"`)) {
				cfg.Security.WAFEnabled = true
			}
		}
	}
	// 默认值兜底
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
	// 解析应用路径（模型目录 / llama 引擎目录 / 授权读写根）
	resolvePaths()
	// 仅当配置解析成功时才回写（解析失败时绝不覆盖用户文件）
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

// ===================== 路径解析（开源化：默认以 exe 所在目录为基准） =====================

// appDir 返回 exe 所在目录；所有默认路径都以此为基准，解压即用。
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

// resolveConfigPath 决定配置文件位置：
// -config 参数 > 环境变量 TARS_CONFIG > exe 同目录 config.json > exe 父目录 config.json > 当前目录
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

// resolvePaths 依据配置（cfg.Paths）或默认布局解析应用路径，
// 并把探测结果回写 cfg.Paths 以便 saveConfig 持久化、用户可手工编辑。
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

// exeDrive 返回 exe 所在盘符（用于磁盘占用统计）
func exeDrive() string {
	exe, err := os.Executable()
	if err == nil && len(exe) >= 3 && exe[1] == ':' {
		return string(exe[0]) + `:\`
	}
	return `C:\`
}

// ===================== 配置路径写入 =====================
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
