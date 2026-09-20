package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// ===================== Windows 系统防火墙集成 =====================
//
// 设计：启动时自动加一条 Windows 防火墙规则，拒绝任何来自非 loopback
// 网卡的 TCP 18889 入站连接。loopback (127.0.0.1) 流量由 OS 内部处理，
// 不受此规则影响。这样即使本机其他进程被攻陷，外部设备也扫不到这个端口。
//
// 需要管理员权限；非管理员启动时优雅降级，仅记录日志不崩溃。

const firewallRuleName = "TarsSecureGuard-BlockExternal"

var (
	firewallMu       sync.Mutex
	firewallApplied  bool
	firewallLastMsg  string
)

// firewallLockEnabled 返回是否启用防火墙锁定
func firewallLockEnabled() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Security.FirewallLock == nil {
		return true // 默认开启
	}
	return *cfg.Security.FirewallLock
}

// ensureFirewallRule 在 Windows 上确保防火墙规则存在（幂等）
func ensureFirewallRule() {
	firewallMu.Lock()
	defer firewallMu.Unlock()

	if runtime.GOOS != "windows" {
		firewallLastMsg = "非 Windows 系统，跳过防火墙规则配置"
		return
	}
	if !firewallLockEnabled() {
		firewallLastMsg = "配置中已关闭防火墙锁定"
		return
	}

	// 先查询规则是否已存在
	check := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", fmt.Sprintf("name=%s", firewallRuleName))
	if out, err := check.CombinedOutput(); err == nil && strings.Contains(string(out), firewallRuleName) {
		firewallApplied = true
		firewallLastMsg = "防火墙规则已存在"
		logMsg("[Firewall] 规则已存在，无需重复添加")
		return
	}

	// 添加规则：拒绝所有外部网卡的 TCP 18889 入站
	// loopback 流量自动绕过防火墙，所以不需要单独放行
	add := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", firewallRuleName),
		"dir=in",
		"action=block",
		"protocol=TCP",
		fmt.Sprintf("localport=%d", port),
		"remoteip=any",
		"enable=yes",
	)
	out, err := add.CombinedOutput()
	if err != nil {
		firewallApplied = false
		firewallLastMsg = "添加防火墙规则失败（需要管理员权限？）: " + strings.TrimSpace(string(out))
		logMsg("[Firewall] " + firewallLastMsg)
		return
	}
	firewallApplied = true
	firewallLastMsg = "已添加防火墙规则：拒绝外部网卡访问 " + fmt.Sprintf("127.0.0.1:%d", port)
	logMsg("[Firewall] " + firewallLastMsg)
}

// firewallStatus 返回防火墙状态快照
func firewallStatus() map[string]interface{} {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	return map[string]interface{}{
		"applied":       firewallApplied,
		"enabled":      firewallLockEnabled(),
		"ruleName":     firewallRuleName,
		"message":      firewallLastMsg,
		"port":         port,
		"platform":     runtime.GOOS,
		"loopbackOnly": true,
	}
}

// removeFirewallRule 移除规则（卸载/重置时用）
func removeFirewallRule() {
	if runtime.GOOS != "windows" {
		return
	}
	del := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", firewallRuleName))
	del.Run()
	firewallApplied = false
	firewallLastMsg = "规则已移除"
}
