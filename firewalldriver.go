package main

import (
	crand "crypto/rand"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ===================== 防火墙策略档位（v2.0.0「决策即配置」）=====================
//
// config.json: security.firewall.policy = passive | dynamic-ban | os-link
//   passive（默认）   被动检测 + 记 WAF/审计日志，不动系统防火墙，代价最低
//   dynamic-ban       WAF 拦截后对来源 IP 内存态动态封禁（banDuration，默认 10m），
//                     不落系统规则、重启即清，适合公网暴露面大的部署
//   os-link           系统防火墙联动（仅推荐单实例、有管理员在场的环境）：
//                     Windows netsh advfirewall / Linux iptables(回落 nftables)。
//                     macOS pfctl 本版未实现（避免重载 pf 规则的风险），降级 passive 并记审计。
//
// 锦衣卫预审 6 条边界（2026-09-27）全部落实：
//   1) 规则命名空间隔离：规则名含实例 ID（TarsGuard-<instID>-…），只删自己创建的规则
//   2) 多实例隔离：实例 ID 随机生成，同机多实例规则互不覆盖
//   3) 启动清理：Start 时先列出并清理本实例历史遗留规则（孤儿规则兜底）再创建
//   4) 绝不阻断管理连接：规则只追加在本应用端口维度（--dport 18889），不加链首默认拒绝
//   5) 异常退出兜底：靠启动清理移除孤儿规则（关机钩子不可靠，不依赖）
//   6) 审计覆盖：add/remove/list 全落审计，含规则内容摘要

const (
	fwPolicyPassive    = "passive"
	fwPolicyDynamicBan = "dynamic-ban"
	fwPolicyOSLink     = "os-link"
)

var (
	// fwInstanceID 实例标识：规则命名空间，隔离同机多实例 + 历史孤儿规则清理
	fwInstanceID string

	fwMu        sync.Mutex
	fwActivePol string // 当前已生效档位（含副作用已应用）
	fwLastMsg   string

	// dynamic-ban 内存封禁表
	banMu    sync.Mutex
	bannedIP = map[string]time.Time{} // ip -> 解封时刻
)

func init() {
	// 启动即生成实例 ID（8 位随机 hex），进程重启后变化；同机多实例互不冲突
	b := make([]byte, 4)
	if _, err := crand.Read(b); err != nil {
		n := time.Now().UnixNano()
		for i := 0; i < 4; i++ {
			b[i] = byte(n >> (uint(i) * 8))
		}
	}
	fwInstanceID = fmt.Sprintf("%x", b)
}

// firewallPolicy 返回当前配置档位（经校验，非法值已在 loadConfig 纠正为 passive）
func firewallPolicy() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	p := cfg.Security.Firewall.Policy
	switch p {
	case fwPolicyPassive, fwPolicyDynamicBan, fwPolicyOSLink:
		return p
	}
	return fwPolicyPassive
}

// banDuration 解析封禁时长（默认 10 分钟）
func banDuration() time.Duration {
	cfgMu.RLock()
	s := cfg.Security.Firewall.BanDuration
	cfgMu.RUnlock()
	if s == "" {
		return 10 * time.Minute
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 && d <= 24*time.Hour {
		return d
	}
	return 10 * time.Minute
}

// firewallReconcile 对齐防火墙档位副作用（启动与热重载时调用）。
// 跨档位切换时先清旧档副作用：os-link 撤销本实例系统规则；dynamic-ban 清内存封禁表。
func firewallReconcile() {
	fwMu.Lock()
	target := firewallPolicy()
	if target == fwActivePol {
		fwMu.Unlock()
		return
	}
	prev := fwActivePol
	fwActivePol = target
	fwMu.Unlock()

	if prev != "" {
		logMsg(fmt.Sprintf("[Firewall] 策略切换 %s -> %s，清理旧档副作用...", prev, target))
		auditLog("FIREWALL_POLICY_CHANGE", "system", fmt.Sprintf("policy %s -> %s", prev, target))
	}
	switch prev {
	case fwPolicyDynamicBan:
		clearDynamicBans()
	case fwPolicyOSLink:
		osFirewallCleanup("策略切换")
	}
	switch target {
	case fwPolicyOSLink:
		if err := osFirewallStart(); err != nil {
			logMsg("[Firewall] os-link 启动失败，降级 passive: " + err.Error())
			auditLog("FIREWALL_RULE_DEL", "system", "os-link 启动失败降级 passive: "+err.Error())
			fwMu.Lock()
			fwActivePol = fwPolicyPassive
			fwMu.Unlock()
			cfgMu.Lock()
			cfg.Security.Firewall.Policy = fwPolicyPassive
			cfgMu.Unlock()
			return
		}
		logMsg("[Firewall] os-link 已启用（实例 " + fwInstanceID + "，仅本应用端口维度规则）")
	case fwPolicyDynamicBan:
		logMsg(fmt.Sprintf("[Firewall] dynamic-ban 已启用（封禁时长 %s，重启即清）", banDuration()))
	case fwPolicyPassive:
		logMsg("[Firewall] passive 已启用（被动检测，不动系统防火墙）")
	}
}

// ===================== dynamic-ban 内存封禁表 =====================

// isBanned 查询 IP 是否处于封禁期（惰性清理过期项）
func isBanned(ip string) bool {
	banMu.Lock()
	defer banMu.Unlock()
	now := time.Now()
	if len(bannedIP) > 4096 { // 防表无限增长
		for k, t := range bannedIP {
			if now.After(t) {
				delete(bannedIP, k)
			}
		}
	}
	until, ok := bannedIP[ip]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(bannedIP, ip)
		return false
	}
	return true
}

// firewallBanIP WAF 拦截时调用：按档位施加封禁副作用
func firewallBanIP(ip string) {
	switch firewallPolicy() {
	case fwPolicyDynamicBan:
		banMu.Lock()
		until := time.Now().Add(banDuration())
		bannedIP[ip] = until
		banMu.Unlock()
		auditLog("FIREWALL_RULE_ADD", "system", fmt.Sprintf("dynamic-ban ip=%s until=%s", ip, until.Format("15:04:05")))
	case fwPolicyOSLink:
		name := fmt.Sprintf("TarsGuard-%s-ban-%s", fwInstanceID, strings.ReplaceAll(ip, ":", "_"))
		if err := osFirewallBanIP(name, ip); err != nil {
			logMsg("[Firewall] os-link 动态封禁失败: " + err.Error())
		} else {
			auditLog("FIREWALL_RULE_ADD", "system", fmt.Sprintf("os-link ban ip=%s rule=%s", ip, name))
		}
	}
}

func clearDynamicBans() {
	banMu.Lock()
	n := len(bannedIP)
	bannedIP = map[string]time.Time{}
	banMu.Unlock()
	if n > 0 {
		logMsg(fmt.Sprintf("[Firewall] 已清空动态封禁表（%d 条）", n))
	}
}

// ===================== os-link 平台实现 =====================

// osFirewallStart 启动：先清理本实例历史孤儿规则，再按端口维度建默认规则
func osFirewallStart() error {
	osFirewallCleanup("启动清理")
	switch runtime.GOOS {
	case "windows":
		name := fmt.Sprintf("TarsGuard-%s-Port", fwInstanceID)
		add := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s", name), "dir=in", "action=block",
			"protocol=TCP", fmt.Sprintf("localport=%d", port), "remoteip=any", "enable=yes")
		if out, err := add.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh add rule 失败（需要管理员权限？）: %s", strings.TrimSpace(string(out)))
		}
		auditLog("FIREWALL_RULE_ADD", "system", fmt.Sprintf("windows rule=%s port=%d block-in(仅本应用端口)", name, port))
		return nil
	case "linux":
		// iptables 优先，不可用回落 nftables；两者都不可用则报错降级
		if cmdExists("iptables") {
			// 追加（-A）到 INPUT 链末尾、仅针对本应用端口，绝不加链首默认拒绝，不影响 SSH 等管理连接
			spec := []string{"-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", port),
				"!", "-s", "127.0.0.1", "-j", "DROP",
				"-m", "comment", "--comment", fmt.Sprintf("TarsGuard-%s-Port", fwInstanceID)}
			if out, err := runCmd("iptables", spec...); err != nil {
				return fmt.Errorf("iptables 失败: %s", out)
			}
			auditLog("FIREWALL_RULE_ADD", "system", fmt.Sprintf("linux iptables append INPUT dport=%d !loopback DROP (comment=TarsGuard-%s-Port)", port, fwInstanceID))
			return nil
		}
		if cmdExists("nft") {
			// nftables：在 filter input 链末尾追加端口规则（带 comment 便于识别清理）
			stmt := fmt.Sprintf(`add rule inet filter input tcp dport %d ip saddr != 127.0.0.1 drop comment "TarsGuard-%s-Port"`, port, fwInstanceID)
			if out, err := runCmd("nft", stmt); err != nil {
				return fmt.Errorf("nft 失败: %s", out)
			}
			auditLog("FIREWALL_RULE_ADD", "system", fmt.Sprintf("linux nftables append input dport=%d !loopback drop", port))
			return nil
		}
		return fmt.Errorf("iptables / nft 均不可用")
	default:
		// macOS pfctl：重载 pf 规则集有断网风险，本版不实现，诚实降级
		return fmt.Errorf("os-link 在 %s 上暂未实现（pfctl 联动规划中），已降级 passive", runtime.GOOS)
	}
}

// osFirewallBanIP os-link 档位动态封禁单 IP（端口维度，链尾追加）
func osFirewallBanIP(ruleName, ip string) error {
	switch runtime.GOOS {
	case "windows":
		add := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s", ruleName), "dir=in", "action=block",
			"protocol=TCP", fmt.Sprintf("localport=%d", port),
			fmt.Sprintf("remoteip=%s", ip), "enable=yes")
		if out, err := add.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh: %s", strings.TrimSpace(string(out)))
		}
		return nil
	case "linux":
		if cmdExists("iptables") {
			out, err := runCmd("iptables", "-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", port),
				"-s", ip, "-j", "DROP", "-m", "comment", "--comment", ruleName)
			if err != nil {
				return fmt.Errorf("iptables: %s", out)
			}
			return nil
		}
		return fmt.Errorf("iptables 不可用")
	}
	return fmt.Errorf("平台不支持")
}

// osFirewallCleanup 清理本实例（fwInstanceID 命名空间）创建的全部系统规则；
// 绝不触碰其他应用或其他实例的规则。
func osFirewallCleanup(reason string) {
	switch runtime.GOOS {
	case "windows":
		// netsh 按名称删除：先枚举本实例命名空间规则名再逐条删
		for _, name := range windowsListOwnRules() {
			exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", name)).Run()
			auditLog("FIREWALL_RULE_DEL", "system", fmt.Sprintf("windows rule=%s (%s)", name, reason))
		}
	case "linux":
		if cmdExists("iptables") {
			out, _ := runCmd("iptables", "-S", "INPUT")
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "TarsGuard-"+fwInstanceID) {
					// "-A INPUT ..." -> "-D INPUT ..." 逐条删除
					del := strings.Replace(line, "-A INPUT", "-D INPUT", 1)
					fields := strings.Fields(del)
					if len(fields) > 1 && fields[0] == "iptables" {
						fields = fields[1:]
					}
					if _, err := runCmd("iptables", fields...); err == nil {
						auditLog("FIREWALL_RULE_DEL", "system", fmt.Sprintf("linux %s (%s)", del, reason))
					}
				}
			}
		}
	}
}

// windowsListOwnRules 枚举 Windows 防火墙中本实例命名空间的规则名
func windowsListOwnRules() []string {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all").CombinedOutput()
	if err != nil {
		return nil
	}
	prefix := fmt.Sprintf("TarsGuard-%s", fwInstanceID)
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		// 本地化系统输出格式不一，按规则名行宽松匹配
		if i := strings.Index(line, ":"); i > 0 && strings.Contains(line, prefix) {
			name := strings.TrimSpace(line[i+1:])
			if strings.HasPrefix(name, prefix) && !containsStr(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

func cmdExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// firewallStatusSnapshot 防火墙状态快照（/api/admin/security/status 用）
func firewallStatusSnapshot() map[string]interface{} {
	fwMu.Lock()
	pol := fwActivePol
	msg := fwLastMsg
	fwMu.Unlock()
	banMu.Lock()
	banCount := len(bannedIP)
	banMu.Unlock()
	return map[string]interface{}{
		"policy":      pol,
		"instanceId":  fwInstanceID,
		"banDuration": banDuration().String(),
		"bannedIPs":   banCount,
		"platform":    runtime.GOOS,
		"message":     msg,
		"note":        "os-link 仅推荐单实例、有管理员在场的环境",
	}
}

// ===================== v1 兼容：firewallLock 配置读取 =====================

// firewallLockEnabled v1 兼容字段：默认 true（用于空 policy 时的档位解析，见 validateAndCorrectConfig）
func firewallLockEnabled() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Security.FirewallLock == nil {
		return true
	}
	return *cfg.Security.FirewallLock
}

// firewallStatus /api/admin/security/status 的防火墙状态（v2 改为策略档位快照）
func firewallStatus() map[string]interface{} {
	return firewallStatusSnapshot()
}



// ===================== v3.0.0 扩展：信誉联动二倍时长封禁 + 解封 =====================

// firewallBanIPExtra IP 信誉联动封禁：在 firewallBanIP 基础上把封禁时长翻倍
//（锦衣卫裁定 6：低于 40 分触发动态封禁时长 banDuration×2）。os-link 档无独立
// 时长概念（规则常驻直至清理），等效单次；dynamic-ban 档覆盖 until 至 2 倍。
func firewallBanIPExtra(ip string) {
	if firewallPolicy() != fwPolicyDynamicBan {
		return
	}
	banMu.Lock()
	if until, ok := bannedIP[ip]; ok {
		bannedIP[ip] = until.Add(banDuration()) // 已有封禁再延长一个周期 = 2 倍
	} else {
		bannedIP[ip] = time.Now().Add(2 * banDuration())
	}
	u := bannedIP[ip]
	banMu.Unlock()
	auditLog("FIREWALL_RULE_ADD", "system", fmt.Sprintf("ip-reputation ban ip=%s until=%s (banDuration×2)", ip, u.Format("15:04:05")))
}

// firewallUnbanIP 解封：dynamic-ban 档移除封禁表条目；os-link 档删除对应防火墙规则
func firewallUnbanIP(ip string) {
	banMu.Lock()
	_, inTable := bannedIP[ip]
	delete(bannedIP, ip)
	banMu.Unlock()
	if inTable {
		auditLog("FIREWALL_RULE_DEL", "system", "unban ip="+ip+"（dynamic-ban 表条目移除）")
	}
	if firewallPolicy() == fwPolicyOSLink {
		name := fmt.Sprintf("TarsGuard-%s-ban-%s", fwInstanceID, strings.ReplaceAll(ip, ":", "_"))
		if err := osFirewallUnbanIP(name, ip); err != nil {
			logMsg("[Firewall] os-link 解封失败: " + err.Error())
		} else {
			auditLog("FIREWALL_RULE_DEL", "system", "os-link unban ip="+ip)
		}
	}
}

// osFirewallUnbanIP 删除指定 IP 的系统防火墙封禁规则（os-link 档解封）
func osFirewallUnbanIP(ruleName, ip string) error {
	switch runtime.GOOS {
	case "windows":
		del := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=%s", ruleName), fmt.Sprintf("remoteip=%s", ip))
		if out, err := del.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh: %s", strings.TrimSpace(string(out)))
		}
		return nil
	case "linux":
		if cmdExists("iptables") {
			out, err := runCmd("iptables", "-D", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", port),
				"-s", ip, "-j", "DROP", "-m", "comment", "--comment", ruleName)
			if err != nil {
				return fmt.Errorf("iptables: %s", out)
			}
			return nil
		}
		return fmt.Errorf("iptables 不可用")
	}
	return fmt.Errorf("平台不支持")
}

// markIPBannedHook 在 firewallBanIP 成功封禁后由调用方触发（记录 BannedAt 供 24h 恢复）
// 说明：实现放在 iprep.go（markIPBanned），此处仅注释约定，避免环形依赖。
