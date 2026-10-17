package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"
)

// ===================== LangProbe v4.8.0 语言探测引擎 =====================
// 启动时并发探测用户系统可用编程语言，为各模块选择最佳实现。

const probeTimeout = 3 * time.Second

// LangCapability 单语言探测结果
type LangCapability struct {
	Lang     string   `json:"lang"`
	Version  string   `json:"version"`
	Path     string   `json:"path"`
	Platform string   `json:"platform"`
	Score    int      `json:"score"`
	Features []string `json:"features"`
	Modules  []string `json:"modules"`
}

// CapabilityReport 全系统能力报告
type CapabilityReport struct {
	Available []LangCapability   `json:"available"`
	Missing   []string           `json:"missing"`
	Recommend []InstallTip       `json:"recommend"`
	Selected  map[string]string  `json:"selected"` // module -> best lang (backward compat)
	Adapters  map[string][]string `json:"adapters"` // module -> priority-sorted langs (v4.10.0+)
}

// InstallTip 安装建议
type InstallTip struct {
	Lang     string   `json:"lang"`
	Command  string   `json:"command"`
	Unlocks  []string `json:"unlocks"`
	Priority int      `json:"priority"`
}

// langProbeTarget 探测目标定义
type langProbeTarget struct {
	Name      string
	Commands  []string          // 探测命令候选（按优先级）
	VersionArg string           // --version / -V 等
	FeatureTest map[string]string // feature -> 验证脚本片段
	Score     int               // 基础分
	Features  []string          // 该语言默认解锁的能力标签
}

// 探测目标库（按优先级排序）
var langProbeTargets = func() []langProbeTarget {
	isWin := runtime.GOOS == "windows"
	isMac := runtime.GOOS == "darwin"
	tgts := []langProbeTarget{
		{Name: "bash", Commands: []string{"bash"}, VersionArg: "--version", Score: 60,
			Features: []string{"shell-script", "unix-pipe", "log-rotate"}},
		{Name: "sh", Commands: []string{"sh"}, VersionArg: "--version", Score: 50,
			Features: []string{"shell-script", "unix-pipe"}},
	}
	if isWin {
		tgts = append(tgts,
			langProbeTarget{Name: "pwsh", Commands: []string{"pwsh", "pwsh.exe"}, VersionArg: "--version", Score: 90,
				Features: []string{"windows-firewall", "eventlog", "hardware-wmi", "process-monitor"},
				FeatureTest: map[string]string{"NetSecurity": `try { Import-Module NetSecurity -EA Stop; "ok" } catch { "no" }`}},
			langProbeTarget{Name: "powershell", Commands: []string{"powershell", "powershell.exe"}, VersionArg: "-Command", Score: 70,
				Features: []string{"windows-firewall", "eventlog", "hardware-wmi"},
				FeatureTest: map[string]string{"NetSecurity": `try { Import-Module NetSecurity -EA Stop; "ok" } catch { "no" }`}},
			langProbeTarget{Name: "cmd", Commands: []string{"cmd", "cmd.exe"}, VersionArg: "/c", Score: 40,
				Features: []string{"batch-script"}},
			langProbeTarget{Name: "cscript", Commands: []string{"cscript"}, VersionArg: "//?", Score: 30,
				Features: []string{"vbscript", "legacy"}},
		)
	} else {
		tgts = append(tgts,
			langProbeTarget{Name: "python3", Commands: []string{"python3", "python"}, VersionArg: "--version", Score: 95,
				Features: []string{"linux-firewall", "process-monitor", "log-parser", "net-connections", "hardware-psutil"},
				FeatureTest: map[string]string{"psutil": `import psutil; print("ok")`, "iptables": `import iptc; print("ok")`}},
			langProbeTarget{Name: "python", Commands: []string{"python", "python3"}, VersionArg: "--version", Score: 90,
				Features: []string{"linux-firewall", "process-monitor", "log-parser", "net-connections", "hardware-psutil"},
				FeatureTest: map[string]string{"psutil": `import psutil; print("ok")`, "iptables": `import iptc; print("ok")`}},
			langProbeTarget{Name: "node", Commands: []string{"node"}, VersionArg: "--version", Score: 60,
				Features: []string{"json-tool", "frontend-build"}},
			langProbeTarget{Name: "ruby", Commands: []string{"ruby"}, VersionArg: "--version", Score: 40,
				Features: []string{"legacy-script"}},
			langProbeTarget{Name: "perl", Commands: []string{"perl"}, VersionArg: "--version", Score: 35,
				Features: []string{"text-processing", "legacy"}},
			langProbeTarget{Name: "java", Commands: []string{"java"}, VersionArg: "--version", Score: 30,
				Features: []string{"enterprise-tool"}},
		)
	}
	if isMac {
		tgts = append(tgts,
			langProbeTarget{Name: "osascript", Commands: []string{"osascript"}, VersionArg: "--version", Score: 80,
				Features: []string{"macos-native", "notifications", "unified-log"}},
		)
	}
	// dotnet 跨平台但企业环境多见
	tgts = append(tgts,
		langProbeTarget{Name: "dotnet", Commands: []string{"dotnet"}, VersionArg: "--version", Score: 35,
			Features: []string{"enterprise-tool"}},
	)
	return tgts
}()

// 全局探测结果（启动后缓存）
var (
	capabilityReport   *CapabilityReport
	capabilityReportMu sync.RWMutex
	capabilityOnce     sync.Once
)

// getCapabilityReport 获取探测报告（首次调用触发探测）
func getCapabilityReport() *CapabilityReport {
	capabilityOnce.Do(func() {
		capabilityReport = runLangProbe()
	})
	capabilityReportMu.RLock()
	defer capabilityReportMu.RUnlock()
	// 返回副本防外部修改
	b, _ := json.Marshal(capabilityReport)
	var cp CapabilityReport
	json.Unmarshal(b, &cp)
	return &cp
}

// runLangProbe 执行并发探测
func runLangProbe() *CapabilityReport {
	report := &CapabilityReport{
		Available: []LangCapability{},
		Missing:   []string{},
		Recommend: []InstallTip{},
		Selected:  map[string]string{},
	}

	type result struct {
		cap *LangCapability
		name string
	}
	ch := make(chan result, len(langProbeTargets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // 最大 8 并发

	for _, t := range langProbeTargets {
		wg.Add(1)
		go func(tgt langProbeTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cap := probeOneLang(tgt)
			if cap != nil {
				ch <- result{cap: cap, name: tgt.Name}
			} else {
				ch <- result{name: tgt.Name}
			}
		}(t)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for r := range ch {
		if r.cap != nil {
			report.Available = append(report.Available, *r.cap)
		} else {
			report.Missing = append(report.Missing, r.name)
		}
	}

	// 按评分排序
	sort.Slice(report.Available, func(i, j int) bool {
		return report.Available[i].Score > report.Available[j].Score
	})

	// 计算模块-语言映射（v4.10.0 支持多级回退链）
	report.Selected, report.Adapters = selectBestLangs(report.Available)

	// 生成安装建议
	report.Recommend = generateInstallTips(report)

	return report
}

// probeOneLang 探测单个语言
func probeOneLang(t langProbeTarget) *LangCapability {
	var foundPath, foundVersion string
	for _, cmd := range t.Commands {
		path, err := exec.LookPath(cmd)
		if err == nil && path != "" {
			foundPath = path
			break
		}
	}
	if foundPath == "" {
		return nil
	}

	// 获取版本
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, foundPath, t.VersionArg).Output()
	if err != nil {
		// 某些解释器 --version 会返回非零，仍尝试解析输出
		out, _ = exec.CommandContext(ctx, foundPath, t.VersionArg).CombinedOutput()
	}
	foundVersion = parseVersion(string(out))

	cap := &LangCapability{
		Lang:     t.Name,
		Version:  foundVersion,
		Path:     foundPath,
		Platform: runtime.GOOS,
		Score:    t.Score,
		Features: append([]string{}, t.Features...),
	}

	// 能力验证脚本
	for mod, script := range t.FeatureTest {
		ctx2, cancel2 := context.WithTimeout(context.Background(), probeTimeout)
		var ok bool
		switch t.Name {
		case "pwsh", "powershell":
			out2, err2 := exec.CommandContext(ctx2, foundPath, "-Command", script).CombinedOutput()
			ok = err2 == nil && strings.Contains(string(out2), "ok")
		case "python3", "python":
			out2, err2 := exec.CommandContext(ctx2, foundPath, "-c", script).CombinedOutput()
			ok = err2 == nil && strings.Contains(string(out2), "ok")
		default:
			ok = true // 其他语言不测模块
		}
		cancel2()
		if ok {
			cap.Modules = append(cap.Modules, mod)
			cap.Score += 5 // 模块可用加分
		}
	}

	return cap
}

// parseVersion 从 --version 输出提取版本号
func parseVersion(s string) string {
	// 常见格式：Python 3.11.4, PowerShell 7.4.2, node v18.17.0
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 找第一个看起来像版本号的 token (x.y.z 或 vx.y.z)
		for _, tok := range strings.Fields(line) {
			tok = strings.TrimPrefix(tok, "v")
			if len(tok) >= 3 && tok[0] >= '0' && tok[0] <= '9' {
				return tok
			}
		}
	}
	return "unknown"
}

// selectBestLangs 为每个模块选择最佳语言
func selectBestLangs(avail []LangCapability) (selected map[string]string, adapters map[string][]string) {
	selected = map[string]string{}
	adapters = map[string][]string{}
	// 模块到所需能力标签的映射
	moduleNeeds := map[string][]string{
		"firewall":        {"windows-firewall", "linux-firewall"},
		"logging":         {"eventlog", "log-parser", "unified-log"},
		"process":         {"process-monitor"},
		"network":         {"net-connections"},
		"hardware":        {"hardware-wmi", "hardware-psutil"},
		"prompt-injection": {"go-native"}, // v4.10.0 tripwire — GoCore first
	}
	for mod, needs := range moduleNeeds {
		var scored []struct {
			lang  string
			score int
		}
		for _, c := range avail {
			for _, need := range needs {
				if hasFeature(c.Features, need) {
					scored = append(scored, struct{ lang string; score int }{c.Lang, c.Score})
				}
			}
		}
		// Sort by score descending
		for i := range scored {
			for j := i + 1; j < len(scored); j++ {
				if scored[i].score < scored[j].score {
					scored[i], scored[j] = scored[j], scored[i]
				}
			}
		}
		var chain []string
		for _, s := range scored {
			chain = append(chain, s.lang)
		}
		// Three-level fallback: GoCore(1) > OtherLang(2) > GoFallback(3)
		if len(chain) == 0 {
			chain = []string{"go"}
		}
		// Ensure "go" is in the chain as ultimate fallback
		hasGo := false
		for _, l := range chain {
			if l == "go" {
				hasGo = true
				break
			}
		}
		if !hasGo {
			chain = append(chain, "go")
		}
		adapters[mod] = chain
		selected[mod] = chain[0] // backward compat: best available
	}
	return selected, adapters
}

func hasFeature(fs []string, f string) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

// generateInstallTips 生成安装建议
func generateInstallTips(r *CapabilityReport) []InstallTip {
	var tips []InstallTip
	plat := runtime.GOOS
	has := map[string]bool{}
	for _, c := range r.Available {
		has[c.Lang] = true
	}

	if !has["python3"] && !has["python"] {
		cmd := "sudo apt install python3 python3-pip"
		if plat == "darwin" {
			cmd = "brew install python3"
		} else if plat == "windows" {
			cmd = "winget install Python.Python.3"
		}
		tips = append(tips, InstallTip{
			Lang:     "Python",
			Command:  cmd,
			Unlocks:  []string{"进程监控增强", "网络连接分析", "日志结构化解析", "Linux防火墙深度控制"},
			Priority: 1,
		})
	}

	if plat == "windows" && !has["pwsh"] {
		tips = append(tips, InstallTip{
			Lang:     "PowerShell 7",
			Command:  "winget install Microsoft.PowerShell",
			Unlocks:  []string{"Windows防火墙深度控制", "系统事件日志读写", "硬件信息深度采集"},
			Priority: 1,
		})
	}

	if !has["node"] {
		cmd := "sudo apt install nodejs npm"
		if plat == "darwin" {
			cmd = "brew install node"
		} else if plat == "windows" {
			cmd = "winget install OpenJS.NodeJS"
		}
		tips = append(tips, InstallTip{
			Lang:     "Node.js",
			Command:  cmd,
			Unlocks:  []string{"前端构建工具集成", "JSON处理增强"},
			Priority: 2,
		})
	}

	if plat == "darwin" && !has["osascript"] {
		// macOS 自带，不会缺失
	}

	sort.Slice(tips, func(i, j int) bool { return tips[i].Priority < tips[j].Priority })
	return tips
}

// ===================== HTTP API =====================

func handleLangProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rep := getCapabilityReport()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rep)
}

func handleLangProbeRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 强制重新探测
	capabilityReportMu.Lock()
	capabilityReport = runLangProbe()
	capabilityReportMu.Unlock()
	rep := getCapabilityReport()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rep)
}

// ===================== LangBridge 脚本执行 =====================

// ScriptSandbox 脚本执行沙箱
type ScriptSandbox struct {
	Timeout   time.Duration
	MaxOutput int
	WorkDir   string
}

func defaultSandbox() *ScriptSandbox {
	return &ScriptSandbox{Timeout: 30 * time.Second, MaxOutput: 10 << 20, WorkDir: ""}
}

// RunScript 在沙箱中执行脚本
func (sb *ScriptSandbox) RunScript(ctx context.Context, interpreter string, script string, args ...string) ([]byte, error) {
	if sb.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, sb.Timeout)
		defer cancel()
	}
	cmdArgs := append([]string{}, args...)
	cmdArgs = append(cmdArgs, script)
	cmd := exec.CommandContext(ctx, interpreter, cmdArgs...)
	if sb.WorkDir != "" {
		cmd.Dir = sb.WorkDir
	}
	out, err := cmd.CombinedOutput()
	if sb.MaxOutput > 0 && len(out) > sb.MaxOutput {
		out = out[:sb.MaxOutput]
	}
	return out, err
}

// RunScriptStdin 通过 stdin 传递脚本（更安全，避免参数注入）
func (sb *ScriptSandbox) RunScriptStdin(ctx context.Context, interpreter string, stdinScript string, extraArgs ...string) ([]byte, error) {
	if sb.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, sb.Timeout)
		defer cancel()
	}
	args := append([]string{}, extraArgs...)
	cmd := exec.CommandContext(ctx, interpreter, args...)
	cmd.Stdin = strings.NewReader(stdinScript)
	if sb.WorkDir != "" {
		cmd.Dir = sb.WorkDir
	}
	out, err := cmd.CombinedOutput()
	if sb.MaxOutput > 0 && len(out) > sb.MaxOutput {
		out = out[:sb.MaxOutput]
	}
	return out, err
}

// renderTemplate 使用 text/template 渲染脚本（禁止字符串拼接命令）
func renderTemplate(tplStr string, params map[string]interface{}) (string, error) {
	tpl, err := template.New("script").Parse(tplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, params); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// langBridgeExec 统一脚本执行入口（根据 CapabilityReport 选语言）
func langBridgeExec(ctx context.Context, module, scriptTemplate string, params map[string]interface{}) ([]byte, error) {
	rep := getCapabilityReport()
	lang, ok := rep.Selected[module]
	if !ok || lang == "" || lang == "go" {
		return nil, fmt.Errorf("module %s: no enhanced lang available, use Go native", module)
	}

	script, err := renderTemplate(scriptTemplate, params)
	if err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}

	// 找解释器路径
	var interp string
	for _, c := range rep.Available {
		if c.Lang == lang {
			interp = c.Path
			break
		}
	}
	if interp == "" {
		return nil, fmt.Errorf("interpreter %s not found", lang)
	}

	sb := defaultSandbox()
	switch lang {
	case "pwsh", "powershell":
		return sb.RunScriptStdin(ctx, interp, script, "-Command", "-")
	case "python3", "python":
		return sb.RunScriptStdin(ctx, interp, script, "-c", "-")
	case "bash", "sh":
		return sb.RunScriptStdin(ctx, interp, script)
	case "node":
		return sb.RunScriptStdin(ctx, interp, script, "-e")
	default:
		return sb.RunScriptStdin(ctx, interp, script)
	}
}

// doctorLangProbeChecks 为 doctor 生成 LangProbe 相关检查项
func doctorLangProbeChecks() []doctorCheck {
	rep := getCapabilityReport()
	var checks []doctorCheck
	cat := "语言探测"

	if len(rep.Available) == 0 {
		checks = append(checks, doctorCheck{cat, "系统语言探测", doctorWarn,
			"未探测到任何增强语言，所有模块使用 Go 原生实现",
			"安装 Python 或 PowerShell 以解锁增强功能（详见管理面板「系统能力」）"})
		return checks
	}

	var langs []string
	for _, c := range rep.Available {
		langs = append(langs, fmt.Sprintf("%s %s", c.Lang, c.Version))
	}
	checks = append(checks, doctorCheck{cat, "系统语言探测", doctorPass,
		fmt.Sprintf("探测到 %d 种语言: %s", len(rep.Available), strings.Join(langs, ", ")),
		""})

	for mod, lang := range rep.Selected {
		if lang == "go" {
			checks = append(checks, doctorCheck{cat, mod + " 模块", doctorInfo,
				"使用 Go 原生实现（无增强语言可用）", ""})
		} else {
			checks = append(checks, doctorCheck{cat, mod + " 模块", doctorPass,
				fmt.Sprintf("使用 %s 增强实现", lang), ""})
		}
	}

	if len(rep.Recommend) > 0 {
		var recs []string
		for _, t := range rep.Recommend {
			recs = append(recs, t.Lang)
		}
		checks = append(checks, doctorCheck{cat, "安装建议", doctorInfo,
			fmt.Sprintf("推荐安装: %s", strings.Join(recs, ", ")),
			"安装后可解锁更多增强功能"})
	}

	return checks
}

