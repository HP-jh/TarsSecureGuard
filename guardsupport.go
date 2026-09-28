package main

// v3.0.0 M1 支撑函数：资源守护器 / 限流 / IP 信誉共用的配置读取、
// 模块开关、server 引用与刷盘工具。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// cfgInt 从 config 自定义段读整数值（v3 新段用 map 松散读取，0 = 未配置）。
// cfg 为结构体，这里通过重新序列化读取顶层自定义段，避免侵入既有结构。
func cfgInt(section, key string) int {
	cfgMu.RLock()
	b, err := json.Marshal(cfg)
	cfgMu.RUnlock()
	if err != nil {
		return 0
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m); err != nil {
		return 0
	}
	if sec, ok := m[section].(map[string]interface{}); ok {
		if v, ok := sec[key].(float64); ok {
			return int(v)
		}
	}
	return 0
}

// v3CfgSections v3.0.0 新增配置段（存于 cfg.V3，随主配置持久化与热重载）
type V3Config struct {
	Resource struct {
		MemLimitMB int `json:"memLimitMB"` // 0 = auto（min(物理10%,384MB)，eco 档 128MB）
	} `json:"resource"`
	RateLimit struct {
		ChatPerMin  int `json:"chatPerMin"`  // chat 类默认 60
		AdminPerMin int `json:"adminPerMin"` // admin 类默认 10
		ModelPerMin int `json:"modelPerMin"` // 模型操作默认 6
		PerIPTotal  int `json:"perIpTotal"`  // 单 IP 总量默认 240/分（防洗端点绕过分维度）
	} `json:"rateLimit"`
	IPReputation struct {
		Enabled   *bool    `json:"enabled"`   // 默认 true
		Whitelist []string `json:"whitelist"` // 白名单 IP 不参与评分
	} `json:"ipReputation"`
	SemanticGuard struct {
		Enabled      *bool  `json:"enabled"`       // 默认 true（security-core 静态 deny 不受此开关影响）
		EngineURL    string `json:"engineUrl"`     // 本地 0.5B-1.5B 小模型引擎端点
		FallbackMode string `json:"fallbackMode"`  // 仅接受 "block"（锦衣卫裁定 1）
		GrayIPPerMin int    `json:"grayIpPerMin"`  // 灰区单 IP 上限，默认 5/分钟
		CacheTTLMin  int    `json:"cacheTtlMin"`   // 指纹缓存 TTL，默认 60 分钟
	} `json:"semanticGuard"`
	Router struct {
		EpsilonStart float64 `json:"epsilonStart"` // ε-greedy 初始探索率，默认 0.1
		EpsilonMin   float64   `json:"epsilonMin"`   // 衰减下限，默认 0.02
		Enabled      *bool     `json:"enabled"`      // 默认 true（静态路由不受影响，仅叠加探索）
	}
}

var (
	v3cfgMu sync.RWMutex
	v3cfg   V3Config
)

// loadV3Config 从主 config 的 v3 段加载（loadConfig 时同步调用）
func loadV3Config(b []byte) {
	v3cfgMu.Lock()
	defer v3cfgMu.Unlock()
	v3cfg = V3Config{}
	_ = json.Unmarshal(b, &v3cfg)
}

func v3Config() V3Config {
	v3cfgMu.RLock()
	defer v3cfgMu.RUnlock()
	return v3cfg
}

// configModuleExplicit 判断 modules.<id> 是否被用户显式配置（区分默认值）
func configModuleExplicit(id string) bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg.Modules == nil {
		return false
	}
	_, ok := cfg.Modules[id]
	return ok
}

// setModuleState 直接设置模块开关（eco 档默认关闭高耗模块用；不触发依赖纠正，
// 因为这三个目标模块均无被依赖者）
func setModuleState(id string, on bool) {
	cfgMu.Lock()
	if cfg.Modules == nil {
		cfg.Modules = map[string]bool{}
	}
	cfg.Modules[id] = on
	cfgMu.Unlock()
}

// ===================== server 引用（L3 drain 用）=====================

var (
	srvMu    sync.Mutex
	srvInst  *http.Server
)

func registerServer(s *http.Server) {
	srvMu.Lock()
	srvInst = s
	srvMu.Unlock()
}

func serverRef() *http.Server {
	srvMu.Lock()
	defer srvMu.Unlock()
	return srvInst
}

// ===================== 刷盘与守护器状态 =====================

// flushFileLogs 确保日志落盘。fileLog 为同步 open-append-close 模型，
// 写返回即在 OS 页缓存（进程退出不丢）；此处补一次 Audit 终止标记写入以固化队列末端。
func flushFileLogs() {
	fileLog("audit", fmt.Sprintf("[%s] ACTION=AUDIT_QUEUE_FLUSHED USER=system IP=- DETAIL=flush before exit",
		time.Now().Format("2006-01-02 15:04:05")))
}

// saveGuardState 守护器状态持久化（state 目录，冷却判定用）
func saveGuardState() {
	dir := "state"
	_ = os.MkdirAll(dir, 0o755)
	st := map[string]interface{}{
		"lastL3At":  guardL3At.Unix(),
		"eco":       guardEco,
		"savedAt":   time.Now().Unix(),
	}
	b, _ := json.Marshal(st)
	_ = os.WriteFile(filepath.Join(dir, "guard.json"), b, 0o600)
}

// loadGuardState 启动时恢复守护器状态（60 秒冷却窗口判定）
func loadGuardState() {
	b, err := os.ReadFile(filepath.Join("state", "guard.json"))
	if err != nil {
		return
	}
	var st struct {
		LastL3At int64 `json:"lastL3At"`
		Eco      bool  `json:"eco"`
	}
	if json.Unmarshal(b, &st) == nil && st.LastL3At > 0 {
		guardL3At = time.Unix(st.LastL3At, 0)
		if time.Since(guardL3At) < 60*time.Second {
			logMsg("[GUARD] 检测到 60 秒内重复 L3，进入冷却态：本轮不自动触发停机，请检查内存占用根因")
			auditLog("RESOURCE_L3_COOLDOWN", "system", "watchdog 冷却窗口内，跳过自动停机")
		}
	}
}



// handleGuardStatus 资源守护器面板数据（UI 3.0 资源守护面板数据源）
func handleGuardStatus(w http.ResponseWriter, r *http.Request) {
	guardMu.Lock()
	tier := guardTier
	eco := guardEco
	limit := memLimit
	l3at := guardL3At
	fuse := modelLoadFuse
	guardMu.Unlock()
	tierNames := map[int]string{0: "L0 正常", 1: "L1 黄色(降级非核心)", 2: "L2 橙色(熔断高耗)", 3: "L3 红色(停机流程)"}
	writeJSON(w, map[string]interface{}{
		"tier":          tierNames[tier],
		"tierLevel":     tier,
		"ecoMode":       eco,
		"memLimitMB":    limit >> 20,
		"rssMB":         currentRSSMB(),
		"goroutines":    runtime.NumGoroutine(),
		"modelLoadFuse": fuse,
		"lastL3At":      l3at.Unix(),
	})
}
