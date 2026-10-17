package main

// v3.0.4 零信任白名单基线（锦衣卫裁定 TSG-ZT-2026-0929 第一节，强制条款）。
//
// 红线落实：
//   [ZT_DEFAULT_DENY]     默认拒绝基线：所有白名单条目必须显式声明，无「未配置即放行」通道
//   [ZT_EXPLICIT]         显式声明：禁止通配符 / CIDR 隐式包含 / 环境变量静默注入白名单条目
//   [ZT_CHANGE_AUDIT]     变更审计：WHITELIST_ADD / REMOVE / MODIFY，含操作人、前后 SHA-256
//   [ZT_INTEGRITY]        完整性校验：whitelist-integrity.json 基线，失配即
//                         WHITELIST_INTEGRITY_FAIL 并保持上一版本白名单生效（不得降级运行）
//   [ZT_HOT_RELOAD]       热加载经审计 diff 通道，禁止绕过审计直接改内存态
//   [ZT_BASELINE_SCOPE]   覆盖 ipReputation.whitelist / paths.allowedRoots /
//                         mcp.externalServers / sidecar.modules 钉扎 + 静态白名单清单（只读）
//
// 威胁模型（诚实声明）：完整性文件与 config.json 同盘同权限，无法防御拥有文件系统
// 写权限的攻击者同时改写两者；本机制保证的是——任何白名单变化都必然产生审计事件
// （热重载 diff 或基线重建事件），启动时基线失配会被拒绝并告警，管理员可据此追责。

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ===================== 白名单种类注册表 =====================

// 动态白名单（配置声明，可经审计通道变更）
const (
	wlKindIPRep        = "ip_reputation.whitelist"    // B 线：IP 信誉豁免（精确 IP，禁 CIDR/通配）
	wlKindFileRoots    = "paths.allowedRoots"         // stdio 文件工具授权读写根
	wlKindMCPServers   = "mcp.externalServers"        // MCP 外部服务器（须显式 enabled）
	wlKindSidecarPins  = "sidecar.modules"            // sidecar artifact SHA-256 钉扎
	wlKindDefaultKeyCh = "security.defaultKeyChannel" // 默认密钥通道（例外通道，须显式 enable）
)

// 静态白名单（代码级声明，运行期不可变更，列入注册表供审计查阅）
var wlStaticKinds = map[string]string{
	"static:tier1.argv":       "Tier 1 系统命令 argv 白名单（tier1.go，硬编码）",
	"static:trustedOrigins":   "受信任同源（loopback:port，main.go 硬编码）",
	"static:publicRoutes":     "免鉴权公共路由（/ /index.html /admin /health）",
	"static:mcp.tools":        "MCP 工具注册表（HTTP 25 个 tars_* / stdio 6 工具，代码注册）",
	"static:firewall.policy":  "防火墙档位枚举（passive|dynamic-ban|os-link）",
	"static:direct.transport": "直连档位枚举（native|grpc-sidecar）",
}

// wlDynamicKinds 参与完整性基线与 diff 审计的动态白名单种类
var wlDynamicKinds = []string{wlKindIPRep, wlKindFileRoots, wlKindMCPServers, wlKindSidecarPins}

// ===================== 完整性基线文件 =====================

type wlIntegrityEntry struct {
	SHA256  string   `json:"sha256"`  // 条目集合规范化 JSON 的 SHA-256
	Entries []string `json:"entries"` // 条目快照（失配时回退到上一版本用）
}

type wlIntegrityFile struct {
	Version   int                          `json:"version"`
	UpdatedAt string                       `json:"updatedAt"`
	Kinds     map[string]wlIntegrityEntry `json:"kinds"`
}

var (
	wlMu       sync.Mutex
	wlBaseline wlIntegrityFile // 当前生效的完整性基线（内存态）
	wlLoaded   bool            // 基线是否已加载（boot 完成标记）
)

func wlIntegrityPath() string {
	return filepath.Join(appDir(), "whitelist-integrity.json")
}

// wlSnapshotEntries 取某动态白名单的当前配置条目（升序规范化）
func wlSnapshotEntries(kind string) []string {
	var out []string
	switch kind {
	case wlKindIPRep:
		out = append(out, v3Config().IPReputation.Whitelist...)
	case wlKindFileRoots:
		cfgMu.RLock()
		out = append(out, cfg.Paths.AllowedRoots...)
		cfgMu.RUnlock()
	case wlKindMCPServers:
		cfgMu.RLock()
		for _, s := range cfg.MCP.ExternalServers {
			// 只有显式 enabled 的服务器构成放行条目（[ZT_EXPLICIT]）
			if s.Enabled {
				out = append(out, s.Name)
			}
		}
		cfgMu.RUnlock()
	case wlKindSidecarPins:
		c := v3Config()
		ids := make([]string, 0, len(c.Sidecar.Modules))
		for id := range c.Sidecar.Modules {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			out = append(out, id+"@"+c.Sidecar.Modules[id].SHA256)
		}
	}
	sort.Strings(out)
	return out
}

func wlHashEntries(entries []string) string {
	b, _ := json.Marshal(entries)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ===================== 启动 / 热重载统一入口 =====================

// wlReconcile 白名单基线对账。reason: boot | hot_reload | api
//   - boot：无基线文件 → 建立基线（WHITELIST_BASELINE_INIT，逐 kind 审计）；
//     有基线文件 → 逐 kind 比对，失配 kind 触发 WHITELIST_INTEGRITY_FAIL 并
//     回退到基线条目（保持上一版本生效，不得降级运行）。
//   - hot_reload / api：与内存基线 diff，产生 WHITELIST_ADD/REMOVE/MODIFY 审计后重钉基线。
func wlReconcile(reason string) {
	wlMu.Lock()
	defer wlMu.Unlock()
	now := time.Now().Format("2006-01-02 15:04:05")
	if !wlLoaded {
		// 首次加载：读盘或建立基线
		var f wlIntegrityFile
		data, err := os.ReadFile(wlIntegrityPath())
		if err == nil && json.Unmarshal(data, &f) == nil && f.Version == 1 && len(f.Kinds) > 0 {
			wlBaseline = f
			wlLoaded = true
			// 逐 kind 失配检查（boot）
			for _, kind := range wlDynamicKinds {
				cur := wlSnapshotEntries(kind)
				base, ok := f.Kinds[kind]
				if !ok {
					continue
				}
				if wlHashEntries(cur) != base.SHA256 {
					auditLog("WHITELIST_INTEGRITY_FAIL", "system",
						fmt.Sprintf("kind=%s reason=boot_mismatch baseline=%s actual=%s —— 拒绝加载新值，保持基线（上一版本）生效（[ZT_INTEGRITY]）",
							kind, base.SHA256, wlHashEntries(cur)))
					wlRollbackKind(kind, base.Entries)
				}
			}
			auditLog("WHITELIST_BASELINE_LOADED", "system",
				fmt.Sprintf("白名单完整性基线已加载（%d 个动态种类，%d 个静态种类）",
					len(f.Kinds), len(wlStaticKinds)))
			return
		}
		// 无基线文件：bootstrap
		wlBaseline = wlIntegrityFile{Version: 1, UpdatedAt: now, Kinds: map[string]wlIntegrityEntry{}}
		for _, kind := range wlDynamicKinds {
			cur := wlSnapshotEntries(kind)
			wlBaseline.Kinds[kind] = wlIntegrityEntry{SHA256: wlHashEntries(cur), Entries: cur}
			auditLog("WHITELIST_BASELINE_INIT", "system",
				fmt.Sprintf("kind=%s entries=%d sha256=%s —— 首次建立零信任基线（[ZT_DEFAULT_DENY]）",
					kind, len(cur), wlHashEntries(cur)))
		}
		wlPersistBaselineLocked()
		wlLoaded = true
		return
	}
	// 热重载 / API 变更：diff 审计 + 重钉基线（[ZT_CHANGE_AUDIT] / [ZT_HOT_RELOAD]）
	operator := "config.json(外部变更)"
	if reason == "api" {
		operator = "admin-api"
	}
	for _, kind := range wlDynamicKinds {
		cur := wlSnapshotEntries(kind)
		prev, ok := wlBaseline.Kinds[kind]
		if !ok {
			wlBaseline.Kinds[kind] = wlIntegrityEntry{SHA256: wlHashEntries(cur), Entries: cur}
			continue
		}
		curH, prevH := wlHashEntries(cur), prev.SHA256
		if curH == prevH {
			continue
		}
		added, removed := diffStrSets(prev.Entries, cur)
		for _, a := range added {
			auditLog("WHITELIST_ADD", operator,
				fmt.Sprintf("kind=%s entry=%q before_sha256=%s after_sha256=%s（[ZT_CHANGE_AUDIT]）",
					kind, a, prevH, curH))
		}
		for _, rm := range removed {
			auditLog("WHITELIST_REMOVE", operator,
				fmt.Sprintf("kind=%s entry=%q before_sha256=%s after_sha256=%s（[ZT_CHANGE_AUDIT]）",
					kind, rm, prevH, curH))
		}
		if len(added) == 0 && len(removed) == 0 {
			// 条目集相同但内容重排（仅 sidecar 钉扎值变化会出现）→ MODIFY
			auditLog("WHITELIST_MODIFY", operator,
				fmt.Sprintf("kind=%s before_sha256=%s after_sha256=%s 条目值变更（[ZT_CHANGE_AUDIT]）",
					kind, prevH, curH))
		}
		wlBaseline.Kinds[kind] = wlIntegrityEntry{SHA256: curH, Entries: cur}
	}
	wlBaseline.UpdatedAt = now
	wlPersistBaselineLocked()
}

// wlRollbackKind 将失配 kind 的配置回退到基线条目（保持上一版本生效）
func wlRollbackKind(kind string, entries []string) {
	switch kind {
	case wlKindIPRep:
		cfgMu.Lock()
		cfg.V3Config.IPReputation.Whitelist = append([]string(nil), entries...)
		cfgMu.Unlock()
		// guardsupport v3 快照同步回退（iprep.go 运行时读该快照）
		v3cfgMu.Lock()
		v3cfg.IPReputation.Whitelist = append([]string(nil), entries...)
		v3cfgMu.Unlock()
	case wlKindFileRoots:
		cfgMu.Lock()
		cfg.Paths.AllowedRoots = append([]string(nil), entries...)
		allowedRoots = append([]string(nil), entries...)
		cfgMu.Unlock()
		// 注意：loadConfig 随后会 saveConfig 回写，回退值随配置持久化，
		// 下一轮基线以回退后的内容重钉（篡改值被淘汰出局）。
	case wlKindMCPServers, wlKindSidecarPins:
		// MCP 服务器 / sidecar 钉扎：sidecarHub 的 manifest 校验本身有二次钉扎
		// 比对（篡改值会被拒载）；此处仅审计，不静默改写结构体。
		auditLog("WHITELIST_INTEGRITY_ROLLBACK", "system",
			fmt.Sprintf("kind=%s 保留基线条目 %d 条，配置新值被拒绝", kind, len(entries)))
	}
}

func wlPersistBaselineLocked() {
	data, err := json.MarshalIndent(wlBaseline, "", "  ")
	if err != nil {
		return
	}
	// 0600：基线文件与审计链同级别保护，防止低权限进程篡改
	_ = os.WriteFile(wlIntegrityPath(), data, 0600)
}

// diffStrSets 返回 added / removed（prev → cur）
func diffStrSets(prev, cur []string) (added, removed []string) {
	pm := map[string]bool{}
	for _, p := range prev {
		pm[p] = true
	}
	cm := map[string]bool{}
	for _, c := range cur {
		cm[c] = true
	}
	for _, c := range cur {
		if !pm[c] {
			added = append(added, c)
		}
	}
	for _, p := range prev {
		if !cm[p] {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

// ===================== 白名单值校验（[ZT_EXPLICIT]） =====================

// wlValidateIPList 校验 IP 信誉白名单值：仅精确 IP，禁 CIDR / 通配符 / 范围
func wlValidateIPList(list []string) error {
	for _, s := range list {
		if net.ParseIP(s) == nil {
			return fmt.Errorf("条目 %q 不是精确 IP 地址（零信任基线禁止 CIDR / 通配符，[ZT_EXPLICIT]）", s)
		}
	}
	return nil
}

// wlValidateFileRoots 校验文件根白名单值：绝对路径、无通配符
func wlValidateFileRoots(list []string) error {
	for _, s := range list {
		if s == "" || !filepath.IsAbs(s) {
			return fmt.Errorf("条目 %q 不是绝对路径（零信任基线禁止相对 / 通配路径）", s)
		}
		if wlContainsAny(s, "*?[") {
			return fmt.Errorf("条目 %q 含通配符（零信任基线禁止通配展开，[ZT_EXPLICIT]）", s)
		}
	}
	return nil
}

func wlContainsAny(s string, set string) bool {
	for _, r := range set {
		for _, c := range s {
			if c == r {
				return true
			}
		}
	}
	return false
}

// wlRegistryView 白名单注册表视图（/api/admin/whitelist/status 数据源）：
// 动态 kinds（当前条目 + 基线哈希）+ 静态 kinds（只读说明）。
func wlRegistryView() map[string]interface{} {
	wlMu.Lock()
	defer wlMu.Unlock()
	out := map[string]interface{}{"dynamic": map[string]interface{}{}, "static": map[string]string{}}
	dyn := out["dynamic"].(map[string]interface{})
	for _, kind := range wlDynamicKinds {
		entries := wlSnapshotEntries(kind)
		base := wlBaseline.Kinds[kind]
		status := "ok"
		if wlLoaded && base.SHA256 != "" && base.SHA256 != wlHashEntries(entries) {
			status = "integrity_fail_rolled_back"
		}
		dyn[kind] = map[string]interface{}{
			"entries":         entries,
			"count":           len(entries),
			"baseline_sha256": base.SHA256,
			"current_sha256":  wlHashEntries(entries),
			"status":          status,
		}
	}
	out["static"] = wlStaticKinds
	return out
}

// ===================== 默认密钥通道治理（例外项 E1，[ZT_DEFAULT_DENY]） =====================
//
// 现状（v3.0.3 及之前）：security.apiKey 缺省回落到硬编码常量 apiKeyDefault
// （"tars-gateway-key"），前端同款兜底 —— 这是一个公开可知、无显式 enable 的
// 默认放行通道，本版剔除：
//   - 全新安装（无 config.json）：首启生成的 config.json 显式写入
//     security.defaultKeyAllowed=true（小白一键体验保留，但通道处于显式声明状态）
//   - 存量升级（config.json 无 defaultKeyAllowed 字段）：视为未显式 enable，
//     自动轮换为随机密钥并落盘 gateway-key.txt（0600），审计 WHITELIST_REMOVE +
//     SECURITY_KEY_ROTATED；前端 401 时弹窗引导输入新密钥

// wlDefaultKeyAllowed 默认密钥通道是否被显式 enable（nil = 否）
func wlDefaultKeyAllowed() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.Security.DefaultKeyAllowed != nil && *cfg.Security.DefaultKeyAllowed
}

// rotateGatewayKey 生成随机 32 字节 hex 密钥并写入 gateway-key.txt（0600）
func rotateGatewayKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败极罕见；退化为时间熵（仍优于公开常量）
		b = []byte(fmt.Sprintf("tsg-%d-rotated", time.Now().UnixNano()))
	}
	key := hex.EncodeToString(b)
	note := "TarsSecureGuard 网关 API Key（零信任基线自动轮换生成）\n" +
		"默认密钥通道已按 v3.0.4 零信任基线剔除；请将此密钥填入前端设置或客户端 X-API-Key。\n" +
		"若需恢复默认密钥通道（不推荐，仅限本机单用户场景），在 config.json 显式写入\n" +
		"\"security\": { \"defaultKeyAllowed\": true } 并重启。\n"
	_ = os.WriteFile(filepath.Join(appDir(), "gateway-key.txt"), []byte(note+"KEY="+key+"\n"), 0600)
	return key
}

// enforceDefaultKeyChannel loadConfig 内调用：处置默认密钥通道
func enforceDefaultKeyChannel(freshInstall bool) {
	cfgMu.Lock()
	key := cfg.Security.APIKey
	allowed := cfg.Security.DefaultKeyAllowed != nil && *cfg.Security.DefaultKeyAllowed
	rotate := false
	if (key == "" || key == apiKeyDefault) && !allowed {
		if freshInstall {
			// 全新安装：显式写入 defaultKeyAllowed=true（通道显式化，小白体验保留）
			t := true
			cfg.Security.DefaultKeyAllowed = &t
			cfgMu.Unlock()
			auditLog("WHITELIST_ADD", "system(bootstrap)",
				fmt.Sprintf("kind=%s entry=api-key-default —— 全新安装显式启用默认密钥通道（仅绑定 127.0.0.1；可在 config.json 关闭）（[ZT_DEFAULT_DENY]）", wlKindDefaultKeyCh))
			return
		}
		rotate = true
	}
	cfgMu.Unlock()
	if rotate {
		newKey := rotateGatewayKey()
		cfgMu.Lock()
		cfg.Security.APIKey = newKey
		cfgMu.Unlock()
		auditLog("WHITELIST_REMOVE", "system(zero-trust)",
			fmt.Sprintf("kind=%s entry=api-key-default —— 存量配置未显式 enable 默认密钥通道，已剔除（[ZT_DEFAULT_DENY]）", wlKindDefaultKeyCh))
		auditLog("SECURITY_KEY_ROTATED", "system(zero-trust)",
			"网关密钥已自动轮换为随机密钥，新密钥见安装目录 gateway-key.txt；前端首次请求 401 时按提示输入即可")
		logMsg("[SECURITY] 默认密钥通道已剔除（零信任基线）：新密钥已写入 gateway-key.txt")
	}
}


// wlValidateOnLoad v3.0.4 [ZT_EXPLICIT]：加载期白名单值域校验入口（loadConfig 调用）。
// 非法值（CIDR / 通配 / 相对路径）剔除并审计 WHITELIST_INVALID_ENTRY；合法值保持不变。
func wlValidateOnLoad() {
	// IP 信誉白名单
	tc := v3Config()
	if tc.IPReputation.Whitelist != nil {
		if err := wlValidateIPList(tc.IPReputation.Whitelist); err != nil {
			keep := tc.IPReputation.Whitelist[:0]
			for _, ip := range tc.IPReputation.Whitelist {
				if e := wlValidateIPList([]string{ip}); e == nil {
					keep = append(keep, ip)
				} else {
					auditLog("WHITELIST_INVALID_ENTRY", "system(zero-trust)",
						fmt.Sprintf("kind=%s entry=%s —— %v（[ZT_EXPLICIT] 剔除）", wlKindIPRep, ip, e))
				}
			}
			cfgMu.Lock()
			cfg.V3Config.IPReputation.Whitelist = append([]string(nil), keep...)
			cfgMu.Unlock()
			v3cfgMu.Lock()
			v3cfg.IPReputation.Whitelist = append([]string(nil), keep...)
			v3cfgMu.Unlock()
		}
	}
	// 文件授权根
	cfgMu.RLock()
	roots := append([]string(nil), cfg.Paths.AllowedRoots...)
	cfgMu.RUnlock()
	if roots != nil {
		if err := wlValidateFileRoots(roots); err != nil {
			keep := roots[:0]
			for _, p := range roots {
				if e := wlValidateFileRoots([]string{p}); e == nil {
					keep = append(keep, p)
				} else {
					auditLog("WHITELIST_INVALID_ENTRY", "system(zero-trust)",
						fmt.Sprintf("kind=%s entry=%s —— %v（[ZT_EXPLICIT] 剔除）", wlKindFileRoots, p, e))
				}
			}
			cfgMu.Lock()
			cfg.Paths.AllowedRoots = append([]string(nil), keep...)
			cfgMu.Unlock()
		}
	}
}
