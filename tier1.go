package main

// ===================== v3.0.1 Tier 1：系统原生命令探测宿主 ====================
//
// 依据：锦衣卫指挥使裁定书 TSG-TIER1-2026-0929（七条红线，全项落地）：
//  [TIER1_EXEC_MANDATORY]  全部调用走 exec.Command 数组式 argv；禁止 -Command /
//                         -EncodedCommand / -ExecutionPolicy Bypass / bash -c / cmd /c
//                         等 shell 中介；PowerShell 仅允许 -File + 预置脚本（SHA-256 校验）
//  [TIER1_AUDIT_MANDATORY] 每次调用必写审计：TIER1_COMMAND_EXEC / _FAIL / _TIMEOUT，
//                         字段 ts/cmd/argv/caller/exit/dur 全量记录
//  [TIER1_CACHE_DEGRADE]  仅缓存静态硬件属性；TTL 60-3600 clamp（默认 300）；
//                         重启/热重载/安全级别变更/POLICY_VIOLATION 全量失效；
//                         缓存文件 0600 + HMAC-SHA256（密钥仅存内存）；
//                         篡改 → AUDIT_TIER1_CACHE_TAMPER + 降级 Tier 0；
//                         降级 → AUDIT_TIER1_DEGRADE（degrade_reason + fallback_data_source）
//  [TIER1_TOGGLE]         默认开启；config.tier1.enabled 用户可关；
//                         关闭只影响硬件评估精度（回退 Tier 0），不触碰 security-core
//  [TIER1_ALLOWLIST]      命令白名单强制（Windows PowerShell -File 预置脚本 /
//                         Linux lspci/dmidecode/cat / macOS system_profiler -xml）；
//                         禁 sudo/su/runas、管道、重定向、环境变量注入
//  [TIER1_PROC_TIMEOUT]   单次调用 3 秒上限；同一命令连续 3 次超时/非零退出 → 降级；
//                         降级后每 60 秒一次恢复探测；进程树清理（Windows Job Object /
//                         Unix Setpgid+kill -pgid）
//  [TIER1_PRIVILEGE]      以 TSG 当前权限执行，绝不自动提权；权限不足按降级处理
//
// 硬件评估引擎（hardware.go）是唯一消费方：动态指标（磁盘/可用内存）永远走 Tier 0，
// 本层只补 Tier 0 拿不到的静态属性（CPU 型号 / GPU 型号 / 主板机型）。

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ---------- 配置（guardsupport.go V3Config.Tier1） ----------

func tier1Enabled() bool {
	c := v3Config()
	if c.Tier1.Enabled == nil {
		return true // 默认开启（[TIER1_TOGGLE]）
	}
	return *c.Tier1.Enabled
}

// tier1CacheTTL 静态属性缓存 TTL：config.tier1.cacheTtlSeconds，范围 60-3600，
// 超范围按边界 clamp（[TIER1_CACHE_DEGRADE] 条件 2），默认 300 秒（5 分钟）。
// 极低频变更项（主板机型等）同样适用本 TTL：探测成本低（每 TTL 一次），
// 统一 TTL 换取配置面最小，如需放宽由用户显式配置。
func tier1CacheTTL() time.Duration {
	sec := v3Config().Tier1.CacheTTLSeconds
	if sec == 0 {
		sec = 300
	}
	if sec < 60 {
		sec = 60
	}
	if sec > 3600 {
		sec = 3600
	}
	return time.Duration(sec) * time.Second
}

// ---------- 审计（[TIER1_AUDIT_MANDATORY]） ----------

// tier1Audit 每次调用必写审计，不可采样跳过。字段对齐裁定要求：
// ts(毫秒) / cmd(全路径) / argv(参数摘要) / caller(调用方模块) /
// exit(0|code|timeout|permission-denied|not-found) / dur(ms)
func tier1Audit(event, caller, cmdPath string, argv []string, exit string, durMs int64) {
	argvJSON, _ := json.Marshal(argv)
	auditLog(event, "tier1", fmt.Sprintf(
		"ts=%d cmd=%s argv=%s caller=%s exit=%s dur=%dms",
		time.Now().UnixMilli(), cmdPath, string(argvJSON), caller, exit, durMs))
}

// ---------- 白名单（[TIER1_ALLOWLIST]） ----------

var tier1DmidecodeTypes = map[string]bool{
	"0": true, "1": true, "2": true, "3": true, "4": true, "17": true,
}

var tier1ProcFiles = map[string]bool{
	"/proc/cpuinfo": true,
	"/proc/meminfo": true,
}

var tier1SPDataTypes = map[string]bool{
	"SPHardwareDataType": true,
	"SPMemoryDataType":   true,
	"SPDisplaysDataType": true,
	"SPNVMeDataType":     true,
}

// tier1AllowListed 校验本次调用是否命中白名单。任何未命中 → POLICY_VIOLATION 审计 +
// 拒绝执行 + 全量缓存失效（[TIER1_CACHE_DEGRADE] 条件 3）。
func tier1AllowListed(caller string, argv []string) bool {
	ok := false
	switch runtime.GOOS {
	case "windows":
		// 唯一允许形态：powershell.exe -NoProfile -NonInteractive -OutputFormat XML
		//   -ExecutionPolicy RemoteSigned -File <预置脚本路径>
		if len(argv) == 9 && strings.EqualFold(argv[0], "powershell.exe") &&
			argv[1] == "-NoProfile" && argv[2] == "-NonInteractive" &&
			argv[3] == "-OutputFormat" && argv[4] == "XML" &&
			argv[5] == "-ExecutionPolicy" && argv[6] == "RemoteSigned" &&
			argv[7] == "-File" && argv[8] == tier1ScriptPath() {
			ok = true
		}
	case "linux":
		switch {
		case len(argv) == 3 && argv[0] == "lspci" && argv[1] == "-mm" && argv[2] == "-v":
			ok = true
		case len(argv) == 3 && argv[0] == "dmidecode" && argv[1] == "-t" &&
			tier1DmidecodeTypes[argv[2]]:
			ok = true
		case len(argv) == 2 && argv[0] == "cat" && tier1ProcFiles[argv[1]]:
			ok = true
		}
	case "darwin":
		if len(argv) == 3 && argv[0] == "system_profiler" && argv[1] == "-xml" &&
			tier1SPDataTypes[argv[2]] {
			ok = true
		}
	}
	if !ok {
		argvJSON, _ := json.Marshal(argv)
		auditLog("POLICY_VIOLATION", "tier1", fmt.Sprintf(
			"白名单外 Tier 1 调用被拒绝：caller=%s argv=%s（[TIER1_ALLOWLIST]）", caller, string(argvJSON)))
		tier1CacheInvalidate("policy_violation")
	}
	return ok
}

// ---------- 熔断（[TIER1_PROC_TIMEOUT]） ----------

const (
	tier1Timeout       = 3 * time.Second  // 单次调用上限（含进程启动）
	tier1FailThreshold = 3                // 连续失败阈值 → 降级
	tier1RecoveryEvery = 60 * time.Second // 降级后恢复探测间隔
)

type tier1Breaker struct {
	fails       int
	tripped     bool
	trippedAt   time.Time
	lastProbeAt time.Time
}

var (
	tier1Mu       sync.Mutex
	tier1Breakers = map[string]*tier1Breaker{}
)

// tier1BreakerAllow 命令放行判定：未熔断直接放；熔断后每 60 秒放一次恢复探测。
func tier1BreakerAllow(key string, now time.Time) (allowed, isRecovery bool) {
	tier1Mu.Lock()
	defer tier1Mu.Unlock()
	b := tier1Breakers[key]
	if b == nil || !b.tripped {
		return true, false
	}
	if now.Sub(b.lastProbeAt) >= tier1RecoveryEvery {
		b.lastProbeAt = now
		return true, true
	}
	return false, false
}

// tier1BreakerRecord 记录一次结果：成功清零；失败累计，连续 3 次 → 熔断 + 降级审计。
func tier1BreakerRecord(key string, success bool, exit string) {
	tier1Mu.Lock()
	b := tier1Breakers[key]
	if b == nil {
		b = &tier1Breaker{}
		tier1Breakers[key] = b
	}
	if success {
		wasTripped := b.tripped
		b.fails = 0
		b.tripped = false
		tier1Mu.Unlock()
		if wasTripped {
			auditLog("TIER1_RECOVERED", "tier1", "命令恢复（key="+key+"），退出熔断")
		}
		return
	}
	b.fails++
	if !b.tripped && b.fails >= tier1FailThreshold {
		b.tripped = true
		b.trippedAt = time.Now()
		b.lastProbeAt = time.Now()
		fails := b.fails
		tier1Mu.Unlock()
		// [TIER1_CACHE_DEGRADE] 条件 5：降级审计（degrade_reason + fallback_data_source）
		auditLog("AUDIT_TIER1_DEGRADE", "tier1", fmt.Sprintf(
			"degrade_reason=连续 %d 次失败(最后 exit=%s) fallback_data_source=tier0 key=%s",
			fails, exit, key))
		return
	}
	tier1Mu.Unlock()
}

// ---------- 执行入口（唯一通道） ----------

// tier1Run Tier 1 命令唯一执行入口：白名单 → 熔断 → LookPath → 3 秒超时执行 →
// 进程树清理 → 全量审计。任何失败均如实返回，调用方按 Tier 0 降级，绝不提权重试。
func tier1Run(caller string, argv []string) (string, error) {
	key := strings.Join(argv, " ")
	if !tier1AllowListed(caller, argv) {
		return "", fmt.Errorf("tier1: 白名单外调用被拒绝")
	}
	if allowed, _ := tier1BreakerAllow(key, time.Now()); !allowed {
		return "", fmt.Errorf("tier1: 命令已熔断降级（key=%s，每 60 秒恢复探测）", key)
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		tier1Audit("TIER1_COMMAND_FAIL", caller, argv[0], argv[1:], "not-found", 0)
		tier1BreakerRecord(key, false, "not-found")
		return "", fmt.Errorf("tier1: 命令不可用: %s", argv[0])
	}
	var out bytes.Buffer
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	start := time.Now()
	timedOut, err := tier1ExecCmd(cmd, tier1Timeout)
	dur := time.Since(start).Milliseconds()
	if timedOut {
		// [TIER1_PROC_TIMEOUT]：超时已强制清理整棵进程树（平台实现负责）
		tier1Audit("TIER1_COMMAND_TIMEOUT", caller, path, argv[1:], "timeout", dur)
		tier1BreakerRecord(key, false, "timeout")
		return out.String(), fmt.Errorf("tier1: 命令超时（3 秒上限）: %s", argv[0])
	}
	if err != nil {
		exit := fmt.Sprintf("code:%v", err)
		low := strings.ToLower(out.String())
		if strings.Contains(low, "permission") || strings.Contains(low, "administrator") ||
			strings.Contains(low, "sudo") || strings.Contains(low, "not permitted") {
			// [TIER1_PRIVILEGE]：权限不足按降级处理，绝不尝试提权
			exit = "permission-denied"
		}
		tier1Audit("TIER1_COMMAND_FAIL", caller, path, argv[1:], exit, dur)
		tier1BreakerRecord(key, false, exit)
		return out.String(), fmt.Errorf("tier1: 命令失败(%s): %v", exit, err)
	}
	tier1Audit("TIER1_COMMAND_EXEC", caller, path, argv[1:], "0", dur)
	tier1BreakerRecord(key, true, "0")
	return out.String(), nil
}

// ---------- 缓存（[TIER1_CACHE_DEGRADE]） ----------

// HMAC 密钥：进程启动时生成的 32 字节随机值，仅存内存。
// 进程重启后密钥变化 → 旧缓存文件校验必失败；启动路径直接删除缓存文件
// （重启=显式失效），因此运行中校验失败即判定为篡改。
var tier1CacheKey = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败极罕见：确定性回落保证进程内读写一致
		for i := range b {
			b[i] = byte(i * 7)
		}
	}
	return b
}()

var (
	tier1CacheMu       sync.Mutex
	tier1TamperPending bool // 读到篡改后，本轮快照直接降级 Tier 0
)

func tier1CachePath() string {
	return filepath.Join("state", "tier1-cache.json")
}

type tier1CacheFile struct {
	WrittenAt int64             `json:"writtenAt"`
	Data      map[string]string `json:"data"`
	HMAC      string            `json:"hmac"`
}

func tier1CacheMAC(f *tier1CacheFile) string {
	mac := hmac.New(sha256.New, tier1CacheKey)
	mac.Write([]byte(fmt.Sprintf("%d|", f.WrittenAt)))
	keys := make([]string, 0, len(f.Data))
	for k := range f.Data {
		keys = append(keys, k)
	}
	// 固定序遍历，保证同一内容 MAC 一致（数据量 4 项，选择排序足够）
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		mac.Write([]byte(k + "\x00" + f.Data[k] + "\x00"))
	}
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// tier1CacheLoad 读缓存：HMAC 校验失败 → 篡改审计 + 删除 + 置降级标记；
// TTL 过期 → 未命中。仅存静态属性（[TIER1_CACHE_DEGRADE] 条件 1）。
func tier1CacheLoad() (map[string]string, bool) {
	tier1CacheMu.Lock()
	defer tier1CacheMu.Unlock()
	if tier1TamperPending {
		return nil, false
	}
	raw, err := os.ReadFile(tier1CachePath())
	if err != nil {
		return nil, false
	}
	var f tier1CacheFile
	if json.Unmarshal(raw, &f) != nil || f.WrittenAt == 0 || f.Data == nil {
		return nil, false
	}
	if !hmac.Equal([]byte(f.HMAC), []byte(tier1CacheMAC(&f))) {
		// 篡改：删除 + 审计 + 本轮降级 Tier 0（裁定条件 4）
		os.Remove(tier1CachePath())
		tier1TamperPending = true
		auditLog("AUDIT_TIER1_CACHE_TAMPER", "tier1",
			"缓存文件 HMAC 校验失败，已删除并降级 Tier 0（fallback_data_source=tier0）")
		return nil, false
	}
	if time.Since(time.Unix(f.WrittenAt, 0)) > tier1CacheTTL() {
		return nil, false
	}
	return f.Data, true
}

func tier1CacheStore(data map[string]string) {
	tier1CacheMu.Lock()
	defer tier1CacheMu.Unlock()
	tier1TamperPending = false
	f := tier1CacheFile{WrittenAt: time.Now().Unix(), Data: data}
	f.HMAC = tier1CacheMAC(&f)
	b, err := json.Marshal(&f)
	if err != nil {
		return
	}
	_ = os.MkdirAll("state", 0o755)
	// 文件权限 0600（裁定条件 4）；先删旧文件避免继承旧权限
	os.Remove(tier1CachePath())
	_ = os.WriteFile(tier1CachePath(), b, 0o600)
}

// tier1CacheInvalidate 全量失效（裁定条件 3）：配置热重载 / 安全级别变更 /
// POLICY_VIOLATION / 开关切换统一走这里。
func tier1CacheInvalidate(reason string) {
	tier1CacheMu.Lock()
	defer tier1CacheMu.Unlock()
	if err := os.Remove(tier1CachePath()); err == nil {
		auditLog("TIER1_CACHE_INVALIDATED", "tier1", "reason="+reason)
	}
	tier1TamperPending = false
}

// ---------- 硬件快照（hardware.go 消费） ----------

type tier1HW struct {
	Active        bool   `json:"active"`
	CPUModel      string `json:"cpuModel"`
	GPUModel      string `json:"gpuModel"`
	BoardModel    string `json:"boardModel"`
	Source        string `json:"source"`
	Cached        bool   `json:"cached"`
	Degraded      bool   `json:"degraded"`
	DegradeReason string `json:"degradeReason"`
}

var tier1SnapMu sync.Mutex

// tier1HardwareSnapshot Tier 1 静态硬件属性唯一出口。
// 关闭 → Tier 0 视图；缓存命中 → 不 spawn 任何子进程（不许每请求 spawn 子进程）；
// 缓存过期 → 按平台执行白名单探测后回填。
func tier1HardwareSnapshot() tier1HW {
	tier1SnapMu.Lock()
	defer tier1SnapMu.Unlock()
	if !tier1Enabled() {
		return tier1HW{Degraded: true,
			DegradeReason: "config.tier1.enabled=false，Tier 1 已关闭（硬件评估回退 Tier 0）"}
	}
	if d, ok := tier1CacheLoad(); ok {
		return tier1HW{Active: true, Cached: true,
			CPUModel: d["cpuModel"], GPUModel: d["gpuModel"], BoardModel: d["boardModel"],
			Source: d["source"]}
	}
	if tier1TamperNow() {
		// 篡改后本轮直接降级 Tier 0，下一轮再探测回填
		return tier1HW{Degraded: true,
			DegradeReason: "Tier 1 缓存检测到篡改（AUDIT_TIER1_CACHE_TAMPER），本轮降级 Tier 0"}
	}
	s := tier1Probe()
	if s.Active {
		tier1CacheStore(map[string]string{
			"cpuModel":   s.CPUModel,
			"gpuModel":   s.GPUModel,
			"boardModel": s.BoardModel,
			"source":     s.Source,
		})
	}
	return s
}

func tier1TamperNow() bool {
	tier1CacheMu.Lock()
	defer tier1CacheMu.Unlock()
	return tier1TamperPending
}

// ---------- 平台探测 ----------

func tier1Probe() tier1HW {
	switch runtime.GOOS {
	case "windows":
		return tier1ProbeWindows()
	case "linux":
		return tier1ProbeLinux()
	case "darwin":
		return tier1ProbeDarwin()
	}
	return tier1HW{Degraded: true, DegradeReason: "平台不支持 Tier 1 探测"}
}

// tier1ProbeWindows powershell.exe -File 预置脚本（唯一允许形态），
// 启动与每次执行前均校验脚本 SHA-256（[TIER1_ALLOWLIST]）。
func tier1ProbeWindows() tier1HW {
	if err := tier1ScriptEnsure(); err != nil {
		return tier1HW{Degraded: true, DegradeReason: "预置脚本校验失败: " + err.Error()}
	}
	out, err := tier1Run("hardware-assessment", []string{
		"powershell.exe", "-NoProfile", "-NonInteractive",
		"-OutputFormat", "XML", "-ExecutionPolicy", "RemoteSigned",
		"-File", tier1ScriptPath(),
	})
	hw := tier1HW{Active: true, Source: "tier1: powershell 预置脚本（SHA-256 校验）"}
	if err != nil {
		hw.Degraded = true
		hw.DegradeReason = err.Error()
		return hw
	}
	var parsed struct {
		GPU         string `json:"gpu"`
		CPUModel    string `json:"cpuModel"`
		SystemModel string `json:"systemModel"`
		Board       string `json:"board"`
	}
	if err := tier1ParseClixmlJSON(out, &parsed); err != nil {
		hw.Degraded = true
		hw.DegradeReason = "脚本输出解析失败: " + err.Error()
		return hw
	}
	g := strings.TrimSpace(parsed.GPU)
	if g != "" && !strings.EqualFold(g, "Microsoft Basic Display Adapter") {
		hw.GPUModel = g
	}
	hw.CPUModel = strings.TrimSpace(parsed.CPUModel)
	hw.BoardModel = strings.TrimSpace(parsed.Board)
	if hw.BoardModel == "" {
		hw.BoardModel = strings.TrimSpace(parsed.SystemModel)
	}
	return hw
}

// tier1ParseClixmlJSON 从 PowerShell -OutputFormat XML（CLIXML）包裹中取出脚本输出的
// JSON 字符串并解析。脚本只输出单个 JSON 字符串 → <S>…</S> 节点；
// stderr 合流可能混入 CLIXML 记录，故遍历全部 <S> 节点，取第一个可解析为 JSON 的。
func tier1ParseClixmlJSON(out string, v interface{}) error {
	re := regexp.MustCompile(`(?s)<S>(.*?)</S>`)
	found := false
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		if json.Unmarshal([]byte(html.UnescapeString(m[1])), v) == nil {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("未找到可解析的 <S> JSON 输出节点")
	}
	return nil
}

// tier1ProbeLinux 白名单探测：lspci -mm -v（GPU）/ cat /proc/cpuinfo（CPU 型号）/
// dmidecode -t 1（机型）。dmidecode 需 root：非 root 权限不足即降级该字段，绝不 sudo。
func tier1ProbeLinux() tier1HW {
	hw := tier1HW{Active: true, Source: "tier1: lspci -mm -v / cat /proc/cpuinfo / dmidecode -t"}
	if out, err := tier1Run("hardware-assessment", []string{"lspci", "-mm", "-v"}); err == nil {
		hw.GPUModel = tier1ParseLspciGPU(out)
	}
	if out, err := tier1Run("hardware-assessment", []string{"cat", "/proc/cpuinfo"}); err == nil {
		hw.CPUModel = tier1ParseCPUInfo(out)
	}
	if out, err := tier1Run("hardware-assessment", []string{"dmidecode", "-t", "1"}); err == nil {
		hw.BoardModel = tier1ParseDMIField(out, "Product Name")
		if hw.BoardModel == "" {
			hw.BoardModel = tier1ParseDMIField(out, "Manufacturer")
		}
	}
	return hw
}

// tier1ParseLspciGPU 解析 lspci -mm 输出：`槽位 "类别" "厂商" "设备" …`，
// 取 VGA / 3D / Display controller 的 厂商+设备。
func tier1ParseLspciGPU(out string) string {
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		fields := regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(l, -1)
		if len(fields) < 3 {
			continue
		}
		class := strings.ToLower(fields[0][1])
		if strings.Contains(class, "vga") || strings.Contains(class, "3d") || strings.Contains(class, "display") {
			name := strings.TrimSpace(fields[1][1] + " " + fields[2][1])
			if name != "" {
				return name
			}
		}
	}
	return ""
}

func tier1ParseCPUInfo(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "model name") {
			if i := strings.Index(line, ":"); i > 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func tier1ParseDMIField(out, field string) string {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, field+":") {
			return strings.TrimSpace(strings.TrimPrefix(t, field+":"))
		}
	}
	return ""
}

// tier1ProbeDarwin system_profiler -xml（唯一允许形态）。
// XML 输出的键名随 macOS 版本有差异，解析采用「键值对收集 + 多候选键」，
// 解析不到的字段留空降级，不阻塞评估（Intel 机型键名与 Apple Silicon 不同，
// 全部候选键逐一尝试）。
func tier1ProbeDarwin() tier1HW {
	hw := tier1HW{Active: true, Source: "tier1: system_profiler -xml SPHardwareDataType / SPDisplaysDataType"}
	if out, err := tier1Run("hardware-assessment", []string{"system_profiler", "-xml", "SPHardwareDataType"}); err == nil {
		kv := tier1ParseSPXML(out)
		hw.BoardModel = firstNonEmpty(kv["machine_model"], kv["machine_name"], kv["model_identifier"])
		hw.CPUModel = firstNonEmpty(kv["cpu_type"], kv["chip_type"], kv["Processor Name"], kv["processor_name"])
	}
	if out, err := tier1Run("hardware-assessment", []string{"system_profiler", "-xml", "SPDisplaysDataType"}); err == nil {
		kv := tier1ParseSPXML(out)
		hw.GPUModel = firstNonEmpty(kv["Chipset Model"], kv["chipset_model"], kv["_name"])
	}
	return hw
}

// tier1ParseSPXML 收集 plist XML 里相邻的 <key>K</key><string>V</string> 对。
func tier1ParseSPXML(out string) map[string]string {
	kv := map[string]string{}
	re := regexp.MustCompile(`(?s)<key>([^<]+)</key>\s*<string>([^<]*)</string>`)
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		k := strings.TrimSpace(m[1])
		if _, exists := kv[k]; !exists {
			kv[k] = strings.TrimSpace(html.UnescapeString(m[2]))
		}
	}
	return kv
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ---------- 预置 PowerShell 脚本（Windows） ----------

//go:embed tier1_hwprobe.ps1
var tier1PSScript []byte

// tier1ScriptPath 预置脚本落盘位置：配置目录 tier1/hwprobe.ps1
// （脚本内置于发布包 exe，落盘仅为满足 -File 调用形态）。
func tier1ScriptPath() string {
	return filepath.Join(filepath.Dir(configPath), "tier1", "hwprobe.ps1")
}

// tier1ScriptEnsure 材料化预置脚本并做 SHA-256 校验：
//   - 启动与每次执行前调用：磁盘内容与 exe 内置模板哈希不一致 → 用内置模板重写
//     并审计 TIER1_SCRIPT_RESTORED（执行内容永远是校验过的内置版本）
//   - 落盘后回读再校验，防写入失败
func tier1ScriptEnsure() error {
	path := tier1ScriptPath()
	want := sha256.Sum256(tier1PSScript)
	if raw, err := os.ReadFile(path); err == nil {
		got := sha256.Sum256(raw)
		if bytes.Equal(got[:], want[:]) {
			return nil
		}
		auditLog("TIER1_SCRIPT_RESTORED", "tier1",
			"预置脚本哈希与内置模板不一致，已用内置模板重写（拒绝执行被篡改的脚本内容）")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_ = os.Remove(path)
	if err := os.WriteFile(path, tier1PSScript, 0o600); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	got := sha256.Sum256(raw)
	if !bytes.Equal(got[:], want[:]) {
		return fmt.Errorf("脚本落盘后校验不一致")
	}
	return nil
}

// ---------- 杂项 ----------

// tier1StartupClear 进程重启 = 全量缓存失效（裁定条件 3）。
// HMAC 密钥仅存内存，重启后旧缓存校验必失败；启动时直接删除，把「正常重启」与
// 「运行中篡改」区分开，后者才落 AUDIT_TIER1_CACHE_TAMPER。
// 仅 HTTP 服务模式调用（--mcp-stdio 不动缓存，避免误清运行中网关的缓存）。
func tier1StartupClear() {
	tier1CacheMu.Lock()
	defer tier1CacheMu.Unlock()
	os.Remove(tier1CachePath())
	tier1TamperPending = false
}
