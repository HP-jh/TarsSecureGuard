package main

// ===================== v3.0.1 sidecarHub：外置模块宿主 ====================
//
// v3.0.0 架构定稿「Sidecar 模块协议（模块化 2.0）」的宿主实装（此前仅有协议规划
// 与 K8s 部署示例，宿主本体缺失）。设计要点（锦衣卫裁定 3 全项落实）：
//   - manifest 发现：modules.d/{id}.json 声明入口与传输；artifact 必须位于
//     modules.d/{id}/ 目录内、且被 command argv 显式引用（防任意路径执行）
//   - SHA-256 钉扎：artifact 摘要写入主 config sidecar.modules.<id>.sha256 由
//     管理员确认；未钉扎 / 不匹配 → 拒绝加载 + 审计 SIDECAR_LOAD_REJECTED
//   - 传输：Unix domain socket（Linux/macOS）、127.0.0.1 回环 + token（Windows，
//     named pipe 监听需第三方 winio，违反零依赖铁律，回环+token 为架构允许形态）
//   - 鉴权：每次网关启动为各模块生成 32 字节随机 token，经环境变量
//     TSG_SIDECAR_TOKEN 交付；模块对生命周期与代理请求校验 X-TSG-Token
//   - 低权限：manifest 可声明 user（Unix：root 网关降权 setuid；非 root 保持当前
//     权限并审计）；Windows：Job Object（kill-on-close + UI 限制）。绝不提权
//   - 生命周期：POST /init（下发 config）/ POST /start / POST /stop、
//     GET /health、GET /config-schema
//   - 监管：30 秒健康检查；崩溃退避重启 1s/2s/4s…上限 60s；连续 5 次失败停用 +
//     审计 + 状态面板告警（POST /api/admin/sidecar/reload 重新纳管）
//   - 反向代理：/api/ext/{id}/* → 模块；ID 从注册表解析，路径伪造无从发生；
//     客户端鉴权头剥除、注入模块 token；全部流量过网关 WAF/RBAC/审计（中间件链）
//   - 最小环境：子进程仅继承 PATH/HOME/TMPDIR 等最小集，网关自身的 API Key
//     环境变量绝不透传给模块

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	sidecarHealthEvery = 30 * time.Second // 健康检查周期
	sidecarBringUpWait = 10 * time.Second // 拉起后等待 /health 就绪上限
	sidecarStopGrace   = 3 * time.Second  // POST /stop 后等待进程退出上限
	sidecarMaxFails    = 5                // 连续失败阈值 → 停用
	sidecarMaxBackoff  = 60 * time.Second // 退避重启上限
)

var sidecarIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// sidecarManifest modules.d/{id}.json
type sidecarManifest struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Enabled  *bool    `json:"enabled"`  // 默认 true
	Artifact string   `json:"artifact"` // 相对 modules.d/<id>/ 的入口文件
	Command  []string `json:"command"`  // argv 数组（禁 shell；至少一项引用 artifact）
	User     string   `json:"user"`     // 可选（Unix 降权目标用户）
}

// sidecarModule 运行态（字段经 hubMu 保护；ExitCh/cmd 由所属 supervisor goroutine 独占）
type sidecarModule struct {
	ID           string
	Name         string
	Version      string
	User         string
	ArtifactPath string
	Command      []string
	SHA256       string // artifact 实测摘要
	Token        string
	Config       json.RawMessage
	ChangeKey    string // manifest 原文 + 钉扎项 指纹（变更检测；不变则不动）
	Addr         string // "unix:<sock>" | "tcp:127.0.0.1:<port>"
	SockPath     string
	State        string // starting|running|disabled
	LastErr      string
	Fails        int
	Backoff      time.Duration
	Restarts     int
	LastHealthy  time.Time
	StartedAt    time.Time

	// supervisor 生命周期
	supCtx    context.Context
	supCancel context.CancelFunc
	supDone   chan struct{}

	// 进程（supervisor 独占）
	cmd     *exec.Cmd
	exitCh  chan error
	killFn  func()
	httpc   *http.Client
	stopped bool
}

// 拒绝加载的模块（未钉扎/摘要不符/manifest 非法），供状态面板展示
type sidecarRejected struct {
	Reason string `json:"reason"`
	At     string `json:"at"`
}

var (
	hubMu         sync.Mutex
	hubMods       = map[string]*sidecarModule{}
	hubRejected   = map[string]sidecarRejected{}
	hubRejectedK  = map[string]string{} // 拒绝审计去重：id -> changeKey
	hubCtx        context.Context
)

func sidecarHubDir() string { return filepath.Join(filepath.Dir(configPath), "modules.d") }

// ===================== worker（模块注册表 sidecarHub，HasWorker） ====================

func sidecarHubWorker(ctx context.Context) {
	hubMu.Lock()
	hubCtx = ctx
	hubMu.Unlock()
	sidecarScan()
	<-ctx.Done()
	// 网关关闭 / 模块被关：逐个优雅停机（supervisor 在 ctx.Done 时自行 POST /stop + 清理）
	hubMu.Lock()
	mods := make([]*sidecarModule, 0, len(hubMods))
	for _, m := range hubMods {
		mods = append(mods, m)
	}
	hubMu.Unlock()
	for _, m := range mods {
		if m.supCancel != nil {
			m.supCancel()
		}
	}
	for _, m := range mods {
		if m.supDone != nil {
			select {
			case <-m.supDone:
			case <-time.After(sidecarStopGrace + 2*time.Second):
			}
		}
	}
}

// sidecarHotRescan 配置热重载后调用：manifest / 钉扎 / 下发配置任一变化才动对应模块，
// 未变化者（含 disabled）原样保留。hubCtx 未就绪（模块未开）时静默跳过。
func sidecarHotRescan() {
	hubMu.Lock()
	ctx := hubCtx
	hubMu.Unlock()
	if ctx == nil {
		return
	}
	sidecarScan()
}

// ===================== manifest 发现与校验 ====================

// sidecarScan 扫描 modules.d/*.json：
//   - 新 manifest / 钉扎变化 → 停旧载新；无变化 → 跳过（保持 disabled 等状态）
//   - manifest 消失 → 停止并移除
//   - 校验不过 → 记录拒绝原因 + 审计（同一 changeKey 只审计一次，防轮询刷屏）
func sidecarScan() {
	dir := sidecarHubDir()
	pins := v3Config().Sidecar.Modules
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // 无 modules.d 目录 = 无模块，正常
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(raw) == 0 {
			continue
		}
		var man sidecarManifest
		if json.Unmarshal(raw, &man) != nil || !sidecarIDRe.MatchString(man.ID) || len(man.Command) == 0 {
			sidecarReject("hello" /* placeholder */, string(sha256Raw(raw)), "manifest 非法（id/JSON/command）", dir, e.Name())
			continue
		}
		id := man.ID
		seen[id] = true
		pin := pins[id]
		// 变更指纹 = manifest 原文 + 钉扎摘要 + 下发配置
		changeKey := fmt.Sprintf("%x", sha256Raw(append(append([]byte{}, raw...), []byte(pin.SHA256+string(pin.Config))...)))
		hubMu.Lock()
		if old, ok := hubMods[id]; ok && old.ChangeKey == changeKey {
			hubMu.Unlock()
			continue // 无变化：不动（含 disabled 状态保留）
		}
		_, wasLoaded := hubMods[id]
		hubMu.Unlock()
		if wasLoaded {
			logMsg("[SIDECAR] manifest/钉扎变更，重载模块 " + id)
			sidecarUnload(id)
		}
		// manifest.enabled=false：登记拒绝原因但不审计噪声
		if man.Enabled != nil && !*man.Enabled {
			hubMu.Lock()
			hubRejected[id] = sidecarRejected{Reason: "manifest enabled=false（管理员停用）", At: nowStamp()}
			hubMu.Unlock()
			continue
		}
		// artifact 路径校验：必须在 modules.d/<id>/ 内
		if man.Artifact == "" {
			sidecarReject(id, changeKey, "缺少 artifact 字段", dir, e.Name())
			continue
		}
		artDir := filepath.Join(dir, id)
		artPath := filepath.Clean(filepath.Join(artDir, filepath.Clean(man.Artifact)))
		if rel, err := filepath.Rel(artDir, artPath); err != nil || strings.HasPrefix(rel, "..") {
			sidecarReject(id, changeKey, "artifact 逃逸 modules.d/"+id+"/ 目录", dir, e.Name())
			continue
		}
		artRaw, err := os.ReadFile(artPath)
		if err != nil {
			sidecarReject(id, changeKey, "artifact 不可读: "+err.Error(), dir, e.Name())
			continue
		}
		artSHA := fmt.Sprintf("%x", sha256Raw(artRaw))
		// 钉扎校验（锦衣卫裁定 3）
		if pin.SHA256 == "" {
			sidecarReject(id, changeKey, fmt.Sprintf(
				"artifact 未钉扎：请在 config.json sidecar.modules.%s.sha256 填入 %s 后由管理员确认", id, artSHA), dir, e.Name())
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(pin.SHA256), artSHA) {
			sidecarReject(id, changeKey, fmt.Sprintf(
				"artifact 摘要不符（期望 %s 实测 %s），拒绝加载", pin.SHA256, artSHA), dir, e.Name())
			continue
		}
		// command argv 校验：至少一项引用 artifact（绝对路径或 modules.d/<id>/<artifact> 相对形态）
		refOK := false
		relRef := filepath.ToSlash(filepath.Join("modules.d", id, man.Artifact))
		for _, a := range man.Command {
			if a == "" || strings.ContainsAny(a, "\x00") {
				refOK = false
				break
			}
			if filepath.Clean(a) == artPath || filepath.ToSlash(filepath.Clean(a)) == relRef {
				refOK = true
			}
		}
		if !refOK {
			sidecarReject(id, changeKey, "command 未引用 artifact（argv 须包含 artifact 路径）", dir, e.Name())
			continue
		}
		// 通过：登记并启动 supervisor
		m := &sidecarModule{
			ID: id, Name: man.Name, Version: man.Version, User: man.User,
			ArtifactPath: artPath, Command: append([]string(nil), man.Command...),
			SHA256: artSHA, Token: sidecarNewToken(), Config: pin.Config,
			ChangeKey: changeKey, State: "starting",
		}
		if m.Name == "" {
			m.Name = id
		}
		m.supCtx, m.supCancel = context.WithCancel(hubCtxActive())
		m.supDone = make(chan struct{})
		hubMu.Lock()
		hubMods[id] = m
		delete(hubRejected, id)
		hubMu.Unlock()
		auditLog("SIDECAR_MANIFEST_LOADED", "sidecarHub", fmt.Sprintf(
			"模块 %s (%s) manifest 校验通过 artifact_sha256=%s", id, m.Version, artSHA))
		go sidecarSupervise(m)
	}
	// manifest 消失：停用对应模块
	hubMu.Lock()
	var gone []string
	for id := range hubMods {
		if !seen[id] {
			gone = append(gone, id)
		}
	}
	hubMu.Unlock()
	for _, id := range gone {
		sidecarUnload(id)
	}
}

func sha256Raw(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func hubCtxActive() context.Context {
	hubMu.Lock()
	defer hubMu.Unlock()
	if hubCtx == nil {
		return context.Background()
	}
	return hubCtx
}

// sidecarReject 拒绝加载：记录状态面板可见的原因 + 去重审计
func sidecarReject(id, changeKey, reason, dir, file string) {
	if id == "" || id == "hello" {
		id = strings.TrimSuffix(file, ".json")
	}
	hubMu.Lock()
	prev, had := hubRejectedK[id]
	hubRejected[id] = sidecarRejected{Reason: reason, At: nowStamp()}
	hubMu.Unlock()
	if !had || prev != changeKey {
		hubRejectedK[id] = changeKey
		auditLog("SIDECAR_LOAD_REJECTED", "sidecarHub", fmt.Sprintf("模块 %s 拒绝加载：%s", id, reason))
	}
}

// sidecarUnload 停止 supervisor 并移除模块
func sidecarUnload(id string) {
	hubMu.Lock()
	m, ok := hubMods[id]
	if ok {
		delete(hubMods, id)
	}
	hubMu.Unlock()
	if !ok || m.supCancel == nil {
		return
	}
	m.supCancel()
	select {
	case <-m.supDone:
	case <-time.After(sidecarStopGrace + 2*time.Second):
	}
}

func sidecarNewToken() string {
	// 每次拉起重新随机：token 只通过环境变量下发给本模块进程，绝不落盘、不进主 config
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败的确定性回落：时间熵 + 进程指纹（仅用于本轮会话内传输校验）
		seed := fmt.Appendf(nil, "%d-%d", time.Now().UnixNano(), os.Getpid())
		return hex.EncodeToString(sha256Raw(seed))
	}
	return hex.EncodeToString(b)
}

// ===================== supervisor：拉起 / 监管 / 退避重启 ====================

func sidecarSupervise(m *sidecarModule) {
	defer close(m.supDone)
	for {
		if m.supCtx.Err() != nil {
			return
		}
		if err := sidecarBringUp(m); err != nil {
			m.setState("starting", err.Error())
			m.Fails++
			if !sidecarFailGate(m, "bring-up 失败: "+err.Error()) {
				return
			}
			if !sidecarBackoffSleep(m) {
				return
			}
			continue
		}
		// 拉起成功：进入监管循环（阻塞至崩溃 / 停机 / 停用）
		crashed := sidecarMonitor(m)
		if m.State == "disabled" || m.supCtx.Err() != nil {
			return
		}
		if crashed {
			m.Restarts++
			auditLog("SIDECAR_MODULE_CRASHED", "sidecarHub", fmt.Sprintf(
				"模块 %s 进程异常退出（第 %d 次重启，退避 %s）：%s",
				m.ID, m.Restarts, m.Backoff, m.LastErr))
			m.Fails++
			if !sidecarFailGate(m, "崩溃") {
				return
			}
			if !sidecarBackoffSleep(m) {
				return
			}
		}
	}
}

// sidecarFailGate 连续失败达阈值 → 停用 + 审计 + 告警标记；返回 false 表示 supervisor 退出
func sidecarFailGate(m *sidecarModule, what string) bool {
	if m.Fails < sidecarMaxFails {
		return true
	}
	m.setState("disabled", fmt.Sprintf("连续 %d 次失败（%s）已停用；修复后 POST /api/admin/sidecar/reload 重新纳管", m.Fails, what))
	sidecarTeardown(m)
	auditLog("SIDECAR_MODULE_DISABLED", "sidecarHub", fmt.Sprintf(
		"模块 %s 连续 %d 次失败（%s），已停用并告警（UI 状态面板可见）", m.ID, m.Fails, what))
	return false
}

// sidecarBackoffSleep 1s→2s→4s…上限 60s；ctx 取消立即返回 false
func sidecarBackoffSleep(m *sidecarModule) bool {
	if m.Backoff == 0 {
		m.Backoff = time.Second
	} else {
		m.Backoff *= 2
		if m.Backoff > sidecarMaxBackoff {
			m.Backoff = sidecarMaxBackoff
		}
	}
	t := time.NewTimer(m.Backoff)
	defer t.Stop()
	select {
	case <-m.supCtx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (m *sidecarModule) setState(s, lastErr string) {
	hubMu.Lock()
	m.State = s
	if lastErr != "" {
		m.LastErr = lastErr
	}
	hubMu.Unlock()
}

// sidecarBringUp 准备传输端点 → 低权限拉起 → 等 /health 就绪 → /init → /start
func sidecarBringUp(m *sidecarModule) error {
	// 1) 传输端点
	if err := sidecarPrepareAddr(m); err != nil {
		return err
	}
	// 2) 拉起（argv 数组式，禁 shell）
	argv0 := m.Command[0]
	path := argv0
	if !strings.ContainsRune(filepath.ToSlash(argv0), '/') && !strings.ContainsRune(argv0, '\\') {
		var err error
		if path, err = exec.LookPath(argv0); err != nil {
			return fmt.Errorf("命令不可用 %s: %v", argv0, err)
		}
	}
	cmd := exec.Command(path, m.Command[1:]...)
	cmd.Env = sidecarEnv(m)
	if err := sidecarPrepareOS(cmd, m); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("进程启动失败: %v", err)
	}
	kill := sidecarAttachOS(cmd, m)
	m.cmd = cmd
	m.exitCh = make(chan error, 1)
	m.killFn = kill
	m.stopped = false
	go func() { m.exitCh <- cmd.Wait() }()
	m.httpc = sidecarHTTPClient(m)
	m.setState("starting", "")
	// 3) 等待 /health 就绪
	deadline := time.Now().Add(sidecarBringUpWait)
	for {
		code, _, err := sidecarCall(m, http.MethodGet, "/health", nil, 3*time.Second)
		if err == nil && code == http.StatusOK {
			break
		}
		select {
		case werr := <-m.exitCh:
			m.exitDrained()
			return fmt.Errorf("进程在就绪前退出: %v", werr)
		default:
		}
		if time.Now().After(deadline) {
			sidecarTeardown(m)
			return fmt.Errorf("%s 内 /health 未就绪", sidecarBringUpWait)
		}
		select {
		case werr := <-m.exitCh:
			m.exitDrained()
			return fmt.Errorf("进程在就绪前退出: %v", werr)
		case <-m.supCtx.Done():
			sidecarTeardown(m)
			return fmt.Errorf("supervisor 取消")
		case <-time.After(500 * time.Millisecond):
		}
	}
	// 4) /init 下发配置（config 为空则下发 null，协议上属合法值）
	initBody, _ := json.Marshal(map[string]interface{}{"config": json.RawMessage(orJSONNull(m.Config))})
	if code, body, err := sidecarCall(m, http.MethodPost, "/init", initBody, 5*time.Second); err != nil || code != http.StatusOK {
		sidecarTeardown(m)
		return fmt.Errorf("/init 失败 code=%d err=%v body=%s", code, err, truncStr(body, 200))
	}
	// 5) /start
	if code, body, err := sidecarCall(m, http.MethodPost, "/start", []byte("{}"), 5*time.Second); err != nil || code != http.StatusOK {
		sidecarTeardown(m)
		return fmt.Errorf("/start 失败 code=%d err=%v body=%s", code, err, truncStr(body, 200))
	}
	now := time.Now()
	hubMu.Lock()
	m.State = "running"
	m.StartedAt = now
	m.LastHealthy = now
	m.Fails = 0
	m.Backoff = 0
	hubMu.Unlock()
	auditLog("SIDECAR_MODULE_STARTED", "sidecarHub", fmt.Sprintf(
		"模块 %s 就绪 addr=%s（传输 %s）", m.ID, m.Addr, sidecarTransportName(m)))
	return nil
}

// sidecarMonitor 监管循环：30 秒健康检查 + 崩溃侦测；返回 true=进程崩溃退出
func sidecarMonitor(m *sidecarModule) bool {
	t := time.NewTicker(sidecarHealthEvery)
	defer t.Stop()
	for {
		select {
		case <-m.supCtx.Done():
			sidecarGracefulStop(m)
			return false
		case werr := <-m.exitCh:
			m.exitDrained()
			hubMu.Lock()
			m.LastErr = fmt.Sprintf("exit: %v", werr)
			hubMu.Unlock()
			return true
		case <-t.C:
			code, _, err := sidecarCall(m, http.MethodGet, "/health", nil, 5*time.Second)
			hubMu.Lock()
			if err == nil && code == http.StatusOK {
				m.Fails = 0
				m.LastHealthy = time.Now()
				m.LastErr = ""
			} else {
				m.Fails++
				m.LastErr = fmt.Sprintf("健康检查失败（第 %d/%d 连续）: code=%d err=%v", m.Fails, sidecarMaxFails, code, err)
				// 进程已死但 Wait 未被消费：视同崩溃
				select {
				case werr := <-m.exitCh:
					m.exitDrained()
					m.LastErr = fmt.Sprintf("exit: %v", werr)
					hubMu.Unlock()
					return true
				default:
				}
			}
			disabled := m.Fails >= sidecarMaxFails
			hubMu.Unlock()
			if disabled {
				m.setState("disabled", "连续健康检查失败达到停用阈值")
				sidecarTeardown(m)
				auditLog("SIDECAR_MODULE_DISABLED", "sidecarHub", fmt.Sprintf(
					"模块 %s 连续 %d 次健康检查失败，已停用并告警（UI 状态面板可见）", m.ID, sidecarMaxFails))
				return false
			}
		}
	}
}

func (m *sidecarModule) exitDrained() { m.exitCh = nil }

func truncStr(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func orJSONNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// sidecarGracefulStop POST /stop → 等退出（上限 3s）→ 强杀进程树
func sidecarGracefulStop(m *sidecarModule) {
	if m.stopped {
		return
	}
	m.stopped = true
	if code, _, err := sidecarCall(m, http.MethodPost, "/stop", []byte("{}"), sidecarStopGrace); err == nil && code == http.StatusOK {
		// 给进程一点自然退出时间
		deadline := time.Now().Add(sidecarStopGrace)
		for m.exitCh != nil {
			select {
			case <-m.exitCh:
				m.exitDrained()
				goto done
			case <-time.After(200 * time.Millisecond):
				if time.Now().After(deadline) {
					goto done
				}
			}
		}
	}
done:
	sidecarTeardown(m)
	auditLog("SIDECAR_MODULE_STOPPED", "sidecarHub", "模块 "+m.ID+" 已停止")
}

// sidecarTeardown 强杀进程树 + 清理 socket；幂等
func sidecarTeardown(m *sidecarModule) {
	if m.killFn != nil {
		m.killFn()
		m.killFn = nil
	}
	if m.exitCh != nil {
		select {
		case <-m.exitCh:
		default:
		}
		m.exitCh = nil
	}
	if m.SockPath != "" {
		os.Remove(m.SockPath)
	}
}

// ===================== 传输端点与 HTTP 客户端 ====================

func sidecarTransportName(m *sidecarModule) string {
	if strings.HasPrefix(m.Addr, "unix:") {
		return "unix domain socket"
	}
	return "127.0.0.1 回环 + token"
}

func sidecarPrepareAddr(m *sidecarModule) error {
	if runtime.GOOS == "windows" {
		// 预占一个回环端口（listen :0 取号后立即释放，模块绑定；本地回环竞态可忽略）
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		addr := l.Addr().String()
		l.Close()
		m.Addr = "tcp:" + addr
		m.SockPath = ""
		return nil
	}
	sockDir := filepath.Join(filepath.Dir(configPath), "state", "sidecar")
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		return err
	}
	abs, err := filepath.Abs(filepath.Join(sockDir, m.ID+".sock"))
	if err != nil {
		return err
	}
	os.Remove(abs) // 清理陈旧 socket
	m.SockPath = abs
	m.Addr = "unix:" + abs
	return nil
}

func sidecarHTTPClient(m *sidecarModule) *http.Client {
	tr := &http.Transport{MaxIdleConns: 4, IdleConnTimeout: 60 * time.Second}
	if strings.HasPrefix(m.Addr, "unix:") {
		sock := strings.TrimPrefix(m.Addr, "unix:")
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
	}
	return &http.Client{Transport: tr}
}

// sidecarCall 生命周期调用（token 头由 transport 上层注入）
func sidecarCall(m *sidecarModule, method, path string, body []byte, timeout time.Duration) (int, []byte, error) {
	c := m.httpc
	hubMu.Lock()
	c2 := m.httpc
	hubMu.Unlock()
	if c2 != nil {
		c = c2
	}
	if c == nil {
		return 0, nil, fmt.Errorf("客户端未初始化")
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://sidecar"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-TSG-Token", m.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.Timeout = timeout
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, nil
}

// sidecarEnv 最小环境：模块只拿到身份/端点/token 与运行时必需的基础变量，
// 网关自身的 API Key 环境变量（TARS_*_KEY 等）绝不透传
func sidecarEnv(m *sidecarModule) []string {
	transport := "tcp"
	if strings.HasPrefix(m.Addr, "unix:") {
		transport = "unix"
	}
	env := []string{
		"TSG_SIDECAR_ID=" + m.ID,
		"TSG_SIDECAR_TRANSPORT=" + transport,
		"TSG_SIDECAR_ADDR=" + strings.TrimPrefix(m.Addr, transport+":"),
		"TSG_SIDECAR_TOKEN=" + m.Token,
	}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG",
		"SYSTEMROOT", "SYSTEMDRIVE", "USERPROFILE", "COMSPEC", "PATHEXT", "WINDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// ===================== 反向代理 /api/ext/{id}/* ====================

// handleSidecarProxy 反向代理（moduleRoute("sidecarHub") 包装 + 网关中间件链在前：
// WAF / RBAC / 限流 / 审计全部生效）。模块 ID 从注册表解析，与 manifest 一致是
// 查找的先决条件，跨模块路径伪造无从发生。
func handleSidecarProxy(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/ext/")
	id := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		id = rest[:i]
	}
	if !sidecarIDRe.MatchString(id) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "sidecar 模块不存在: " + id})
		return
	}
	hubMu.Lock()
	m, ok := hubMods[id]
	state, lastErr := "", ""
	if ok {
		state, lastErr = m.State, m.LastErr
	}
	hubMu.Unlock()
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "sidecar 模块不存在: " + id})
		return
	}
	if state != "running" {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error": "sidecar 模块 " + id + " 当前不可用（state=" + state + "）",
			"hint":  lastErr,
		})
		return
	}
	sub := strings.TrimPrefix(r.URL.Path, "/api/ext/"+id)
	if sub == "" {
		sub = "/"
	}
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "sidecar"
			req.URL.Path = sub
			req.Host = "sidecar"
			req.Header.Set("X-TSG-Token", m.Token)
			// 客户端鉴权头剥除：模块不接触网关 API Key
			req.Header.Del("Authorization")
			req.Header.Del("X-API-Key")
		},
		Transport: m.httpc.Transport,
		FlushInterval: -1, // 流式响应直通
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			auditLog("SIDECAR_PROXY_ERROR", "sidecarHub", fmt.Sprintf("模块 %s 代理失败: %v", id, err))
			writeJSONStatus(rw, http.StatusBadGateway, map[string]string{"error": "sidecar 上游不可达"})
		},
	}
	proxy.ServeHTTP(w, r)
}

// ===================== 状态面板与重新纳管 ====================

// handleSidecarStatus GET /api/admin/sidecar/status：模块状态 + 拒绝清单 + 告警位
func handleSidecarStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, sidecarStatusSnapshot())
}

func sidecarStatusSnapshot() map[string]interface{} {
	hubMu.Lock()
	defer hubMu.Unlock()
	mods := make([]map[string]interface{}, 0, len(hubMods))
	alert := false
	for _, m := range hubMods {
		if m.State == "disabled" {
			alert = true
		}
		mods = append(mods, map[string]interface{}{
			"id": m.ID, "name": m.Name, "version": m.Version,
			"state":        m.State,
			"addr":         m.Addr,
			"artifact":     m.ArtifactPath,
			"sha256":       m.SHA256,
			"restarts":     m.Restarts,
			"fails":        m.Fails,
			"backoffMs":    m.Backoff.Milliseconds(),
			"lastError":    m.LastErr,
			"lastHealthy":  stampOrEmpty(m.LastHealthy),
			"startedAt":    stampOrEmpty(m.StartedAt),
			"degradedUser": m.User,
		})
	}
	rej := make([]map[string]interface{}, 0, len(hubRejected))
	for id, rr := range hubRejected {
		rej = append(rej, map[string]interface{}{"id": id, "reason": rr.Reason, "at": rr.At})
	}
	return map[string]interface{}{
		"modules": mods, "rejected": rej, "alert": alert,
		"hint": "拒绝加载的模块需在 config.json sidecar.modules.<id>.sha256 钉扎正确摘要后由管理员确认；停用模块修复后 POST /api/admin/sidecar/reload 重新纳管",
	}
}

func stampOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

// handleSidecarReload POST /api/admin/sidecar/reload：全量重载（含重新纳管停用模块）
func handleSidecarReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	hubMu.Lock()
	ctx := hubCtx
	mods := make([]*sidecarModule, 0, len(hubMods))
	for _, m := range hubMods {
		mods = append(mods, m)
	}
	hubMu.Unlock()
	if ctx == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "sidecarHub 模块未运行"})
		return
	}
	for _, m := range mods {
		if m.supCancel != nil {
			m.supCancel()
		}
	}
	for _, m := range mods {
		if m.supDone != nil {
			select {
			case <-m.supDone:
			case <-time.After(sidecarStopGrace + 2*time.Second):
			}
		}
	}
	hubMu.Lock()
	hubMods = map[string]*sidecarModule{}
	hubRejectedK = map[string]string{}
	hubMu.Unlock()
	sidecarScan()
	uname, _, _ := userFromRequest(r)
	auditLog("SIDECAR_RELOAD", uname, "管理员触发 sidecar 全量重载")
	writeJSON(w, sidecarStatusSnapshot())
}

// ===================== MCP tars_module_schema 数据源 ====================

// sidecarSchemaSnapshot 各运行中模块的 /config-schema（敏感字段脱敏后返回）
func sidecarSchemaSnapshot() []map[string]interface{} {
	hubMu.Lock()
	mods := make([]*sidecarModule, 0)
	for _, m := range hubMods {
		if m.State == "running" {
			mods = append(mods, m)
		}
	}
	hubMu.Unlock()
	out := []map[string]interface{}{}
	for _, m := range mods {
		_, body, err := sidecarCall(m, http.MethodGet, "/config-schema", nil, 3*time.Second)
		if err != nil {
			out = append(out, map[string]interface{}{"id": m.ID, "error": "schema 获取失败: " + err.Error()})
			continue
		}
		var v interface{}
		if json.Unmarshal(body, &v) != nil {
			out = append(out, map[string]interface{}{"id": m.ID, "error": "schema 非法 JSON"})
			continue
		}
		out = append(out, map[string]interface{}{"id": m.ID, "schema": sidecarSanitizeNode(v)})
	}
	return out
}

// sensitiveSchemaKeys schema 中命中即脱敏的键名（大小写不敏感）
var sensitiveSchemaKeys = map[string]bool{
	"password": true, "secret": true, "token": true, "apikey": true,
	"api_key": true, "credential": true, "privatekey": true, "private_key": true,
}

// sidecarSanitizeNode 递归脱敏：敏感键名 / 标记 "sensitive": true 的字段值 → [已隐藏]
func sidecarSanitizeNode(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, val := range t {
			if sensitiveSchemaKeys[strings.ToLower(k)] {
				out[k] = "[已隐藏]"
				continue
			}
			if m2, ok := val.(map[string]interface{}); ok {
				if f, _ := m2["sensitive"].(bool); f {
					out[k] = "[已隐藏]"
					continue
				}
			}
			out[k] = sidecarSanitizeNode(val)
		}
		return out
	case []interface{}:
		lst := make([]interface{}, len(t))
		for i, val := range t {
			lst[i] = sidecarSanitizeNode(val)
		}
		return lst
	}
	return v
}
