package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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
		WAFEnabled      bool        `json:"wafEnabled"`
		Mode            string      `json:"mode"` // normal | strict（off 已废弃：安全模块不可关闭）
		APIKey          string      `json:"apiKey"`
		FirewallLock    *bool       `json:"firewallLock"`    // v1 兼容字段：默认 true（见 firewallPolicyLegacy）
		AuditLogEnabled bool        `json:"auditLogEnabled"` // 审计日志开关（默认 true）
		Firewall        FirewallCfg `json:"firewall"`
	} `json:"security"`
	Users []User `json:"users"` // 多用户 RBAC（空则回退单管理员模式）
	MCP   struct {
		ExternalServers []ExtServer `json:"externalServers"`
	} `json:"mcp"`
	Paths struct {
		ModelDir     string   `json:"modelDir"`
		LlamaDir     string   `json:"llamaDir"`
		AllowedRoots []string `json:"allowedRoots"`
	} `json:"paths"`
	// v2.0.0 模块化：「决策即配置」——所有可选项均为 config 分选项，默认最优安全档
	Modules      map[string]bool  `json:"modules"`      // 功能模块开关（security-core 不在此列，不可关闭）
	CustomTools  []CustomTool     `json:"customTools"`  // 用户自定义 HTTP 转发工具（SSRF 加固）
	CustomAgents []CustomAgentDef `json:"customAgents"` // 用户自定义 agent 角色
	Direct       DirectCfg        `json:"direct"`       // 系统直连层传输切换点
}

// FirewallCfg 防火墙策略档位（passive | dynamic-ban | os-link，默认 passive）
type FirewallCfg struct {
	Policy      string `json:"policy"`
	BanDuration string `json:"banDuration"` // dynamic-ban 封禁时长，默认 10m
}

// DirectCfg 系统直连层传输切换（native | grpc-sidecar，默认 native）
type DirectCfg struct {
	Transport   string `json:"transport"`
	GRPCSidecar struct {
		Address string `json:"address"` // 仅允许 127.0.0.1/localhost/unix socket
	} `json:"grpcSidecar"`
}

// CustomAgentDef 用户自定义 agent 角色
type CustomAgentDef struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prompt string `json:"prompt"`
	Model  string `json:"model"` // 绑定模型（可空 = auto）
}

// User 单用户配置（RBAC）
type User struct {
	Name    string `json:"name"`
	APIKey  string `json:"apiKey"`
	Role    string `json:"role"` // admin | user | readonly
	Enabled bool   `json:"enabled"`
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
			// v3.0.0：加载 v3 扩展段（resource / rateLimit / ipReputation）
			loadV3Config(data)
			// 配置中未显式声明 wafEnabled 时保持默认开启（bool 零值会误关 WAF）
			if !bytes.Contains(data, []byte(`"wafEnabled"`)) {
				cfg.Security.WAFEnabled = true
			}
			// 审计日志默认开启
			if !bytes.Contains(data, []byte(`"auditLogEnabled"`)) {
				cfg.Security.AuditLogEnabled = true
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
	// 环境变量可覆盖敏感 Key（防止明文落盘）
	if v := os.Getenv("TARS_API_KEY"); v != "" {
		cfg.Security.APIKey = v
	}
	if v := os.Getenv("TARS_OPENAI_KEY"); v != "" {
		cfg.Cloud.OpenAI.APIKey = v
	}
	if v := os.Getenv("TARS_DEEPSEEK_KEY"); v != "" {
		cfg.Cloud.DeepSeek.APIKey = v
	}
	if v := os.Getenv("TARS_SEARCH_KEY"); v != "" {
		cfg.Search.APIKey = v
	}
	// 解析应用路径（模型目录 / llama 引擎目录 / 授权读写根）
	resolvePaths()
	// v2.0.0：安全纠正 + 模块开关应用 + 直连/防火墙档位校验
	// （loadConfig 是启动加载与热重载的共同入口，两条路径都生效）
	validateAndCorrectConfig()
	applyModulesFromConfig()
	// 仅当配置解析成功时才回写（解析失败时绝不覆盖用户文件）；
	// 回写必须发生在纠正之后，确保后门值（wafEnabled:false / mode:"off"）不会原样落盘
	if parsed {
		saveConfig()
	}
	// 记录当前配置文件指纹，作为热重载的基线（含纠正后回写的内容，防止自触发）
	markConfigLoaded()
}

// validateAndCorrectConfig 安全铁律校验：安全保护模块不可关闭。
// v1.x 的 security.wafEnabled:false 与 mode:"off" 是「关安全模块」的后门，v2.0 封堵：
// 配置校验遇到即自动纠正并落审计 CONFIG_CORRECTED（记录原始值与纠正值）。
func validateAndCorrectConfig() {
	if !cfg.Security.WAFEnabled {
		auditLog("CONFIG_CORRECTED", "system", "security.wafEnabled=false -> true（安全模块不可关闭）")
		cfg.Security.WAFEnabled = true
	}
	if cfg.Security.Mode != "strict" && cfg.Security.Mode != "normal" {
		auditLog("CONFIG_CORRECTED", "system", fmt.Sprintf("security.mode=%q -> \"normal\"（off 已废弃）", cfg.Security.Mode))
		cfg.Security.Mode = "normal"
	}
	// 防火墙档位白名单；空值按 v1 兼容逻辑解析（firewallLock 启用且 Windows -> os-link，否则 passive）
	switch cfg.Security.Firewall.Policy {
	case "", fwPolicyPassive, fwPolicyDynamicBan, fwPolicyOSLink:
	default:
		auditLog("CONFIG_CORRECTED", "system", fmt.Sprintf("security.firewall.policy=%q -> \"passive\"", cfg.Security.Firewall.Policy))
		cfg.Security.Firewall.Policy = fwPolicyPassive
	}
	if cfg.Security.Firewall.Policy == "" {
		if firewallLockEnabled() && runtime.GOOS == "windows" {
			cfg.Security.Firewall.Policy = fwPolicyOSLink // 保持 v1 Windows 行为
		} else {
			cfg.Security.Firewall.Policy = fwPolicyPassive
		}
	}
	// 直连档位白名单
	switch cfg.Direct.Transport {
	case "", "native", "grpc-sidecar":
	default:
		auditLog("CONFIG_CORRECTED", "system", fmt.Sprintf("direct.transport=%q -> \"native\"", cfg.Direct.Transport))
		cfg.Direct.Transport = "native"
	}
	if cfg.Direct.Transport == "" {
		cfg.Direct.Transport = "native"
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

// exeDrive 返回磁盘占用统计的基准路径（v2.1.0 跨平台修复）：
//   - Windows：exe 所在盘符根（如 C:\），保持 v1/v2.0 行为
//   - Linux / macOS：exe 所在目录（此前硬编码回落 C:\，导致 Statfs 恒失败、
//     硬件评估磁盘分恒为 0 的哑分）
func exeDrive() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if runtime.GOOS == "windows" && len(exe) >= 3 && exe[1] == ':' {
		return string(exe[0]) + `:\`
	}
	return filepath.Dir(exe)
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

// ===================== 配置热重载（新增：v1.0.2 功能强化） =====================
//
// 采用轮询 + 文件内容哈希的方式监听 config.json 变化（不引入外部依赖），
// 检测到变化且文件可完整解析时自动调用 loadConfig 重载，无需重启服务。

var lastCfgHash string // 上次加载时 config.json 的 SHA-256 指纹

// configHash 计算配置文件的 SHA-256 指纹；读取失败返回空串
func configHash() string {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// markConfigLoaded 记录当前配置文件指纹（loadConfig 完成后调用，作为变更检测基线）
func markConfigLoaded() {
	lastCfgHash = configHash()
}

// configParsable 预检配置文件当前内容是否为合法 JSON（容忍 UTF-8 BOM）。
// 用于过滤编辑器保存过程中的“半写状态”，避免把瞬时不完整的文件重载进来。
func configParsable() bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var probe Config
	return json.Unmarshal(data, &probe) == nil
}

// watchConfig 每 2 秒轮询一次配置文件指纹，变化时自动重载并记录日志。
// 说明：loadConfig 解析成功后会 saveConfig 回写文件（规范化格式），
// 重载完成后以回写后的指纹为新基线，避免自我触发循环重载。
func watchConfig() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h := configHash()
		if h == "" || h == lastCfgHash {
			continue // 文件不可读或无变化
		}
		if !configParsable() {
			continue // 文件写入未完成（半写状态），等下一轮再试
		}
		logMsg("[CONFIG] 检测到配置文件变化，自动重载...")
		auditLog("CONFIG_HOT_RELOAD", "system", "外部 config.json 变更已热重载（含模块/防火墙对齐）") // v3.0.0 B 线：热重载审计
		loadConfig()
		// v2.0.0：模块工作者与防火墙档位随配置对齐（路由经 moduleRoute 包装即时生效）
		reconcileModuleWorkers()
		firewallReconcile()
		// loadConfig 内部 markConfigLoaded 已刷新基线（含 saveConfig 回写后的内容）
		logMsg("[CONFIG] 配置重载完成")
	}
}
