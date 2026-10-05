package main

// ===================== v3.0.5 self-diagnostic CLI（tsg doctor）=====================
//
// 用法：
//   tsg doctor            人读表格输出（PASS/WARN/FAIL/INFO + 下一步建议）
//   tsg doctor --json     机器可读 JSON（CI / 外部 AI 定时巡检）
//   tsg doctor --config <path>   指定 config.json（与网关同名参数一致）
//
// 退出码：0 = 全部通过（可有 WARN）；2 = 仅 WARN；1 = 存在 FAIL。
// doctor 为只读诊断：不启动网关、不改配置、不触发密钥轮换；唯一写动作是
// 权限检查时的临时文件创建+删除（检查应用目录可写性本身）。

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	doctorPass = "PASS"
	doctorWarn = "WARN"
	doctorFail = "FAIL"
	doctorInfo = "INFO"
)

type doctorCheck struct {
	Category string `json:"category"` // 配置 / 网络 / 依赖 / 权限 / 端口 / 资源
	Name     string `json:"name"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	NextStep string `json:"next_step,omitempty"` // FAIL/WARN 必给清晰下一步
}

type doctorReport struct {
	Version    string        `json:"version"`
	GOOS       string        `json:"goos"`
	GOARCH     string        `json:"goarch"`
	Time       string        `json:"time"`
	ConfigPath string        `json:"config_path"`
	AppDir     string        `json:"app_dir"`
	Checks     []doctorCheck `json:"checks"`
	Summary    struct {
		Pass int `json:"pass"`
		Warn int `json:"warn"`
		Fail int `json:"fail"`
		Info int `json:"info"`
	} `json:"summary"`
}

// doctorCfg doctor 专用的轻量配置视图：直接从 config.json 原文解析，
// 不触碰全局 cfg / 不触发 loadConfig 的任何补齐副作用。
type doctorCfg struct {
	Users []struct {
		Name   string   `json:"name"`
		Role   string   `json:"role"`
		Tenant string   `json:"tenant"`
		APIKey string   `json:"apiKey"`
		Groups []string `json:"groups"`
	} `json:"users"`
	Security struct {
		APIKey            string `json:"apiKey"`
		AuditLogEnabled   *bool  `json:"auditLogEnabled"`
		DefaultKeyAllowed *bool  `json:"defaultKeyAllowed"`
		Mode              string `json:"mode"`
	} `json:"security"`
	Paths struct {
		ModelDir string `json:"modelDir"`
		LlamaDir string `json:"llamaDir"`
	} `json:"paths"`
	Modules map[string]bool `json:"modules"`
	Tenants struct {
		Tenants []struct {
			ID      string `json:"id"`
			Enabled *bool  `json:"enabled"`
		} `json:"tenants"`
	} `json:"tenants"`
}

func runDoctor(args []string) {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json", "-json":
			asJSON = true
		case "--help", "-h", "help":
			fmt.Println(`TarsSecureGuard self-diagnostic (tsg doctor)

用法:
  tsg doctor              运行全部检查，表格输出
  tsg doctor --json       JSON 输出（CI / 自动巡检）
  tsg doctor --config <config.json>   指定配置文件（默认与网关同一解析顺序）

检查范围: 配置 / 网络 / 依赖 / 权限 / 端口 / 资源
退出码: 0=全部通过(可有WARN)  2=仅有WARN  1=存在FAIL`)
			return
		}
	}
	rep := &doctorReport{Version: version, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Time: time.Now().Format("2006-01-02 15:04:05")}

	resolveConfigPath() // 纯路径解析，无副作用；兼容 -config / TARS_CONFIG
	rep.ConfigPath = configPath
	rep.AppDir = appDir()

	cfgRaw, cfgParseErr := doctorLoadConfig()
	dc := &doctorChecks{rep: rep}

	// —— 分类检查（顺序即输出顺序）——
	dc.checkConfig(cfgRaw, cfgParseErr)
	dc.checkPermissions(cfgRaw)
	dc.checkPorts()
	dc.checkNetwork()
	dc.checkDeps(cfgRaw)
	dc.checkResources()
	dc.checkRuntime(cfgRaw)

	for _, c := range rep.Checks {
		switch c.Status {
		case doctorPass:
			rep.Summary.Pass++
		case doctorWarn:
			rep.Summary.Warn++
		case doctorFail:
			rep.Summary.Fail++
		default:
			rep.Summary.Info++
		}
	}

	if asJSON {
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
	} else {
		doctorPrintHuman(rep)
	}
	switch {
	case rep.Summary.Fail > 0:
		os.Exit(1)
	case rep.Summary.Warn > 0:
		os.Exit(2)
	default:
		os.Exit(0)
	}
}

func doctorLoadConfig() (*doctorCfg, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	data = []byte(strings.TrimPrefix(string(data), "\xEF\xBB\xBF"))
	var c doctorCfg
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

type doctorChecks struct{ rep *doctorReport }

func (d *doctorChecks) add(c doctorCheck) { d.rep.Checks = append(d.rep.Checks, c) }

// ===================== 1. 配置 =====================

func (d *doctorChecks) checkConfig(c *doctorCfg, parseErr error) {
	cat := "配置"
	if parseErr != nil {
		if os.IsNotExist(parseErr) {
			d.add(doctorCheck{cat, "config.json 存在性", doctorWarn,
				"未找到配置文件（" + configPath + "）——按全新安装处理",
				"首次运行网关会生成默认配置；或用 tsg -config <路径> 指定"})
			return
		}
		d.add(doctorCheck{cat, "config.json 可解析", doctorFail,
			"JSON 解析失败: " + parseErr.Error(),
			"用编辑器检查该文件是否为合法 JSON（常见问题：多余逗号 / 中文引号 / BOM）"})
		return
	}
	d.add(doctorCheck{cat, "config.json 可解析", doctorPass, configPath, ""})

	// 用户角色合法性
	validRoles := map[string]bool{"global_admin": true, "global_auditor": true, "admin": true,
		"team_lead": true, "auditor": true, "user": true, "readonly": true}
	badRole, dupUser := "", ""
	seen := map[string]bool{}
	for _, u := range c.Users {
		if !validRoles[u.Role] {
			badRole = u.Name + "=" + u.Role
			break
		}
		if seen[u.Name] {
			dupUser = u.Name
		}
		seen[u.Name] = true
	}
	if badRole != "" {
		d.add(doctorCheck{cat, "用户角色合法性", doctorFail, "未知角色: " + badRole,
			"角色必须是 admin/user/readonly/team_lead/auditor/global_admin/global_auditor 之一，修正 users 段后重启"})
	} else if dupUser != "" {
		d.add(doctorCheck{cat, "用户名唯一性", doctorFail, "重复用户名: " + dupUser,
			"删除或重命名重复的 users 条目（网关启动时会强校验拒绝）"})
	} else {
		d.add(doctorCheck{cat, "用户角色与唯一性", doctorPass,
			fmt.Sprintf("%d 个用户，角色均合法且无重名", len(c.Users)), ""})
	}

	// 默认密钥通道（v3.0.4 零信任基线）
	if c.Security.APIKey == "" || c.Security.APIKey == apiKeyDefault {
		if c.Security.DefaultKeyAllowed != nil && *c.Security.DefaultKeyAllowed {
			d.add(doctorCheck{cat, "默认密钥通道", doctorWarn,
				"显式允许了公开默认密钥（Security.DefaultKeyAllowed=true）",
				"仅限离线单机演示；联网环境请删除该项并让网关自动轮换随机密钥（gateway-key.txt）"})
		} else {
			d.add(doctorCheck{cat, "默认密钥通道", doctorPass,
				"默认密钥未放行（零信任基线符合 v3.0.4）", ""})
		}
	} else {
		d.add(doctorCheck{cat, "API 密钥", doctorPass, "已配置自定义密钥（值不显示）", ""})
	}

	// 审计开关
	if c.Security.AuditLogEnabled != nil && !*c.Security.AuditLogEnabled {
		d.add(doctorCheck{cat, "审计日志", doctorWarn, "Security.AuditLogEnabled=false，安全事件不落盘",
			"生产/多人环境建议开启（logs/audit-YYYY-MM-DD.log，含 TRACE= 关联字段）"})
	} else {
		d.add(doctorCheck{cat, "审计日志", doctorPass, "已开启（默认）", ""})
	}
}

// ===================== 2. 权限 =====================

func (d *doctorChecks) checkPermissions(c *doctorCfg) {
	cat := "权限"
	// 应用目录可写（临时文件创建+删除）
	probe := filepath.Join(appDir(), ".doctor-probe-"+fmt.Sprintf("%d", time.Now().UnixNano()))
	if err := os.WriteFile(probe, []byte("t"), 0600); err != nil {
		d.add(doctorCheck{cat, "应用目录可写", doctorFail,
			"无法写入 " + appDir() + ": " + err.Error(),
			"右键目录→属性→安全（Windows）或 chmod u+w（Unix）授予当前用户写权限"})
	} else {
		os.Remove(probe)
		d.add(doctorCheck{cat, "应用目录可写", doctorPass, appDir(), ""})
	}

	// gateway-key.txt 权限（仅 Unix 检查 mode；Windows 跳过）
	keyPath := filepath.Join(appDir(), "gateway-key.txt")
	if runtime.GOOS != "windows" && fileExists(keyPath) {
		if fi, err := os.Stat(keyPath); err == nil && fi.Mode().Perm() != 0600 {
			d.add(doctorCheck{cat, "网关密钥文件权限", doctorFail,
				fmt.Sprintf("gateway-key.txt 权限为 %o（应为 600）", fi.Mode().Perm()),
				"chmod 600 gateway-key.txt"})
		} else if err == nil {
			d.add(doctorCheck{cat, "网关密钥文件权限", doctorPass, "gateway-key.txt 已存在且权限 600", ""})
		}
	} else if fileExists(keyPath) {
		d.add(doctorCheck{cat, "网关密钥文件权限", doctorPass, "gateway-key.txt 已存在（Windows 由系统 ACL 保护）", ""})
	} else {
		d.add(doctorCheck{cat, "网关密钥文件权限", doctorInfo,
			"gateway-key.txt 不存在（未发生自动轮换或全新安装）", ""})
	}

	// config.json 世界可写检查（Unix）
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(configPath); err == nil && fi.Mode().Perm()&0002 != 0 {
			d.add(doctorCheck{cat, "配置文件权限", doctorFail,
				fmt.Sprintf("config.json 世界可写（%o）", fi.Mode().Perm()),
				"chmod 644 config.json（或更严格）——世界可写意味着任何本地进程可改网关安全策略"})
		} else if err == nil {
			d.add(doctorCheck{cat, "配置文件权限", doctorPass, "config.json 非世界可写", ""})
		}
	}
}

// ===================== 3. 端口 =====================

func doctorPortInUse(portNum int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", portNum), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (d *doctorChecks) checkPorts() {
	cat := "端口"
	// 18889 网关
	if doctorPortInUse(port) {
		d.add(doctorCheck{cat, "网关端口 18889", doctorInfo,
			"已有进程监听（网关运行中？）",
			"如需重启：先停旧实例再启动，避免端口冲突；Windows: netstat -ano | findstr 18889"})
	} else {
		// 试绑定确认可用
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			ln.Close()
			d.add(doctorCheck{cat, "网关端口 18889", doctorPass, "空闲可绑定", ""})
		} else {
			d.add(doctorCheck{cat, "网关端口 18889", doctorFail,
				"无法监听: " + err.Error(),
				"检查端口是否被其他程序占用（netstat / lsof -i:18889），或防火墙策略"})
		}
	}
	// 18890 本地模型服务
	if doctorPortInUse(modelPort) {
		d.add(doctorCheck{cat, "模型服务端口 18890", doctorPass, "llama-server 运行中", ""})
	} else {
		d.add(doctorCheck{cat, "模型服务端口 18890", doctorInfo,
			"未监听（首次 chat 请求会按需自动拉起 llama-server）", ""})
	}
}

// ===================== 4. 网络（后端可达性 / 网关运行态探测）====================

func doctorHTTPGet(url string, timeout time.Duration) (int, error) {
	client := pooledHTTPClient(timeout) // v3.2.2：走共享连接池
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return resp.StatusCode, nil
}

func (d *doctorChecks) checkNetwork() {
	cat := "网络"
	// LM Studio
	if code, err := doctorHTTPGet(lmStudioBase+"/v1/models", 2*time.Second); err == nil && code < 500 {
		d.add(doctorCheck{cat, "LM Studio (127.0.0.1:1234)", doctorPass,
			fmt.Sprintf("可达（HTTP %d）", code), ""})
	} else {
		d.add(doctorCheck{cat, "LM Studio (127.0.0.1:1234)", doctorInfo,
			"不可达（未启动或未开启本地服务器）",
			"如需使用：打开 LM Studio → Developer → Start Server；不影响 llama/ollama 后端"})
	}
	// Ollama
	if code, err := doctorHTTPGet(ollamaBase+"/api/tags", 2*time.Second); err == nil && code < 500 {
		d.add(doctorCheck{cat, "Ollama (127.0.0.1:11434)", doctorPass,
			fmt.Sprintf("可达（HTTP %d）", code), ""})
	} else {
		d.add(doctorCheck{cat, "Ollama (127.0.0.1:11434)", doctorInfo,
			"不可达（未启动）",
			"如需使用：ollama serve；不影响 llama/lmstudio 后端"})
	}
}

// ===================== 5. 依赖 =====================

func (d *doctorChecks) checkDeps(c *doctorCfg) {
	cat := "依赖"
	if c == nil {
		d.add(doctorCheck{cat, "模型目录 / llama-server", doctorWarn,
			"配置未解析，跳过路径检查", "先修复 config.json 后再跑一次 tsg doctor"})
		return
	}
	// 模型目录
	mDir := c.Paths.ModelDir
	if mDir == "" {
		mDir = filepath.Join(appDir(), "Models")
	}
	if isDir(mDir) {
		gguf := countGGUF(mDir)
		if gguf == 0 {
			d.add(doctorCheck{cat, "模型目录", doctorWarn, mDir + "（无 GGUF 模型文件）",
				"放入 .gguf 模型，或经管理面板 /api/admin/model/download 下载"})
		} else {
			d.add(doctorCheck{cat, "模型目录", doctorPass,
				fmt.Sprintf("%s（%d 个 GGUF）", mDir, gguf), ""})
		}
	} else {
		d.add(doctorCheck{cat, "模型目录", doctorWarn, "不存在: " + mDir,
			"创建该目录并放入 GGUF 模型，或在 config.json paths.modelDir 指向正确位置"})
	}
	// llama-server 可执行文件
	lDir := c.Paths.LlamaDir
	if lDir == "" {
		lDir = filepath.Join(appDir(), "llama")
	}
	found := ""
	for _, name := range []string{"llama-server", "llama-server.exe"} {
		p := filepath.Join(lDir, name)
		if fileExists(p) {
			found = p
			break
		}
	}
	if found != "" {
		d.add(doctorCheck{cat, "llama-server", doctorPass, found, ""})
	} else {
		d.add(doctorCheck{cat, "llama-server", doctorWarn, "未找到（" + lDir + "）",
			"llama 后端将不可用；下载 llama.cpp 发行版放入该目录，或改用 LM Studio / Ollama 后端"})
	}
	// 前端（go:embed 恒在）
	d.add(doctorCheck{cat, "前端页面", doctorPass, "已内嵌（go:embed frontend/index.html）", ""})
}

func countGGUF(dir string) int {
	n := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".gguf") {
			n++
		}
	}
	return n
}

// ===================== 6. 资源 =====================

func (d *doctorChecks) checkResources() {
	cat := "资源"
	ram := physicalMemoryGB()
	switch {
	case ram < 2:
		d.add(doctorCheck{cat, "内存", doctorFail, fmt.Sprintf("物理内存 %.1f GB（< 2 GB，低于最低要求）", ram),
			"升级内存，或仅使用 1-3B 量化小模型并保持 modules 最小集"})
	case ram < 4:
		d.add(doctorCheck{cat, "内存", doctorWarn, fmt.Sprintf("物理内存 %.1f GB（< 4 GB，仅建议小模型）", ram),
			"建议 7B 以上模型使用 Q4 量化；关注 tsg_guard_tier 指标（L1 降级/L2 熔断阈值）"})
	default:
		d.add(doctorCheck{cat, "内存", doctorPass, fmt.Sprintf("物理内存 %.1f GB", ram), ""})
	}

	freeGB := -1.0
	if du, err := getDiskUsage(exeDrive()); err == nil {
		freeGB = float64(du.Free) / (1 << 30)
	}
	switch {
	case freeGB < 0:
		d.add(doctorCheck{cat, "磁盘", doctorInfo, "无法读取磁盘剩余空间", ""})
	case freeGB < 1:
		d.add(doctorCheck{cat, "磁盘", doctorFail, fmt.Sprintf("剩余 %.1f GB（< 1 GB，日志/配额/模型缓存可能写满）", freeGB),
			"清理 logs/ 与 models/ 下不再使用的大文件"})
	case freeGB < 5:
		d.add(doctorCheck{cat, "磁盘", doctorWarn, fmt.Sprintf("剩余 %.1f GB（< 5 GB）", freeGB),
			"模型下载前确认空间；日志按天滚动，可定期清理旧文件"})
	default:
		d.add(doctorCheck{cat, "磁盘", doctorPass, fmt.Sprintf("剩余 %.1f GB", freeGB), ""})
	}
}

// ===================== 7. 运行态（网关已启动时的附加探测）====================

func (d *doctorChecks) checkRuntime(c *doctorCfg) {
	cat := "运行态"
	if !doctorPortInUse(port) {
		d.add(doctorCheck{cat, "网关进程", doctorInfo, "未运行（以下运行态检查跳过）",
			"启动后可再次运行 tsg doctor 验证 /health 与 /metrics"})
		return
	}
	// /health 免鉴权
	if code, err := doctorHTTPGet(fmt.Sprintf("http://127.0.0.1:%d/health", port), 2*time.Second); err == nil && code == 200 {
		d.add(doctorCheck{cat, "GET /health", doctorPass, "HTTP 200", ""})
	} else {
		d.add(doctorCheck{cat, "GET /health", doctorWarn, fmt.Sprintf("网关在监听但 /health 异常: %v", err),
			"查看 logs/tars-YYYY-MM-DD.log 尾部；确认进程非启动中途崩溃重启"})
	}
	// /metrics 带密钥探测（密钥从 gateway-key.txt 或 config 读取，仅在本地内存中使用，不回显）
	key := doctorProbeKey(c)
	if key == "" {
		d.add(doctorCheck{cat, "GET /metrics", doctorInfo, "网关运行中，但未取到探测密钥（跳过）",
			"可用 curl -H 'X-API-Key: <你的密钥>' http://127.0.0.1:18889/metrics 手动验证"})
		return
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/metrics", port), nil)
	req.Header.Set("X-API-Key", key)
	client := pooledHTTPClient(3 * time.Second) // v3.2.2：走共享连接池
	resp, err := client.Do(req)
	if err != nil {
		d.add(doctorCheck{cat, "GET /metrics", doctorWarn, "请求失败: " + err.Error(),
			"确认网关版本 ≥ 3.0.5（老版本无此端点）；查看网关日志"})
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode == 200 {
		d.add(doctorCheck{cat, "GET /metrics", doctorPass, "HTTP 200（Prometheus 文本格式，已带鉴权）", ""})
	} else {
		d.add(doctorCheck{cat, "GET /metrics", doctorWarn, fmt.Sprintf("HTTP %d", resp.StatusCode),
			"401=密钥与网关不一致（以 gateway-key.txt 为准）；404=网关版本 < 3.0.5，请升级"})
	}
}

// doctorProbeKey 读取本地探测密钥（仅用于 127.0.0.1 探测，绝不输出）：
// 优先 gateway-key.txt（KEY=xxx 行），否则 config users[0]/security.apiKey。
func doctorProbeKey(c *doctorCfg) string {
	if data, err := os.ReadFile(filepath.Join(appDir(), "gateway-key.txt")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "KEY=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "KEY="))
			}
		}
	}
	if c != nil {
		for _, u := range c.Users {
			if u.APIKey != "" {
				return u.APIKey
			}
		}
		if c.Security.APIKey != "" && c.Security.APIKey != apiKeyDefault {
			return c.Security.APIKey
		}
	}
	return ""
}

// ===================== 人读输出 =====================

func doctorPrintHuman(rep *doctorReport) {
	fmt.Printf("TarsSecureGuard v%s self-diagnostic (tsg doctor)\n", rep.Version)
	fmt.Printf("平台: %s/%s   配置: %s   应用目录: %s\n", rep.GOOS, rep.GOARCH, rep.ConfigPath, rep.AppDir)
	fmt.Println(strings.Repeat("─", 72))
	cur := ""
	for _, c := range rep.Checks {
		if c.Category != cur {
			cur = c.Category
			fmt.Printf("\n[%s]\n", cur)
		}
		icon := map[string]string{doctorPass: "✔", doctorWarn: "▲", doctorFail: "✘", doctorInfo: "·"}[c.Status]
		fmt.Printf("  %s %-6s %s\n", icon, c.Status, c.Name)
		if c.Message != "" {
			fmt.Printf("         %s\n", c.Message)
		}
		if c.NextStep != "" {
			fmt.Printf("         → 下一步: %s\n", c.NextStep)
		}
	}
	fmt.Println("\n" + strings.Repeat("─", 72))
	fmt.Printf("汇总: %d PASS / %d WARN / %d FAIL / %d INFO\n",
		rep.Summary.Pass, rep.Summary.Warn, rep.Summary.Fail, rep.Summary.Info)

	var fails, warns []string
	for _, c := range rep.Checks {
		if c.Status == doctorFail {
			fails = append(fails, c.Name+" — "+c.NextStep)
		} else if c.Status == doctorWarn {
			warns = append(warns, c.Name+" — "+c.NextStep)
		}
	}
	sort.Strings(fails)
	sort.Strings(warns)
	if len(fails) > 0 {
		fmt.Println("\n需要立即处理（FAIL）:")
		for _, f := range fails {
			fmt.Println("  ✘ " + f)
		}
	}
	if len(warns) > 0 {
		fmt.Println("\n建议关注（WARN）:")
		for _, w := range warns {
			fmt.Println("  ▲ " + w)
		}
	}
	if len(fails) == 0 && len(warns) == 0 {
		fmt.Println("\n全部检查通过，网关环境健康。")
	}
}
