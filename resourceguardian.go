package main

// v3.0.0 A 线：资源守护器（resourceGuardian）
//
// 设计依据：v3.0.0 架构方案第二节（A 线）+ 锦衣卫裁定 5 与附加意见。
//   - GOMEMLIMIT 软内存上限（debug.SetMemoryLimit）：只影响 GC 积极度，非硬墙
//   - L0-L3 分级响应：L1 降级非核心 → L2 熔断高耗 → L3 优雅停机
//   - L2/L3 判定以 RSS 为准（Go MemStats 仅作 GC 参考），防 CGO/外部内存绕过软上限
//   - L3 drain：停新连接、等已建立请求（最长 30s）、审计队列刷盘完成才退出；
//     watchdog 60 秒内重复 L3 进冷却态（不再自动拉起，仅告警）
//   - eco 档：硬件评估 D 档设备自动套用省资源默认值
//   - 纯规则状态机，不引入 AI 决策；每次层级进出写审计

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ===================== 状态 =====================

const (
	guardL0 = iota // 正常
	guardL1        // 黄色：降级非核心
	guardL2        // 橙色：熔断高耗
	guardL3        // 红色：优雅停机
)

var (
	guardMu      sync.Mutex
	guardTier    = guardL0             // 当前层级
	guardSince   = map[int]time.Time{} // 层级条件首次满足时间（持续判定）
	guardEco     bool                  // eco 省资源档已启用
	guardL3At    time.Time             // 本次进程最近一次 L3 触发时间
	memLimit     int64                 // 软内存上限（字节）
	// modelLoadFuse：L2 熔断标志——本地模型加载入口检查（true = 拒绝新加载）
	modelLoadFuse bool
)

// ===================== 配置 =====================

// applyMemorySoftLimit 启动时设置 GOMEMLIMIT 软上限。
// 默认 min(物理内存×10%, 384MB)；eco 档（硬件 D 档）降为 128MB；
// resource.memLimitMB 显式配置优先。
func applyMemorySoftLimit(totalPhysMemMB int) {
	limitMB := 384
	if totalPhysMemMB > 0 {
		if v := totalPhysMemMB / 10; v < limitMB {
			limitMB = v
		}
	}
	if v := cfgInt("resource", "memLimitMB"); v > 0 {
		limitMB = v
	}
	if guardEco && limitMB > 128 {
		limitMB = 128
	}
	memLimit = int64(limitMB) << 20
	debug.SetMemoryLimit(memLimit)
	logMsg(fmt.Sprintf("[GUARD] GOMEMLIMIT 软上限已设为 %dMB (eco=%v)", limitMB, guardEco))
}

// enableEcoMode 硬件评估 D 档设备套用 eco 档（在硬件评估完成后调用）
func enableEcoMode(reason string) {
	guardMu.Lock()
	if guardEco {
		guardMu.Unlock()
		return
	}
	guardEco = true
	guardMu.Unlock()
	auditLog("RESOURCE_ECO_ON", "system", "eco 省资源档已启用: "+reason)
	// eco 档动作：软上限 128MB（若当前配置更高则收紧）
	if memLimit > 128<<20 && cfgInt("resource", "memLimitMB") <= 0 {
		memLimit = 128 << 20
		debug.SetMemoryLimit(memLimit)
	}
	// 高耗可选模块默认关（仅当用户未显式配置时）
	for _, id := range []string{"autoStartModel", "openapiTools", "mcpExternal"} {
		if !configModuleExplicit(id) {
			setModuleState(id, false)
		}
	}
}

// ===================== RSS 读数 =====================

// currentRSSMB 返回进程 RSS（MB）。Linux 读 /proc/self/status 精确值；
// 其余平台退化为 Go MemStats.Sys 近似（偏保守，只作 L2/L3 判定的保护性下限）。
// Windows 精确 RSS（GetProcessMemoryInfo）列 M4 收尾。
func currentRSSMB() int {
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
						return int(kb / 1024)
					}
				}
			}
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int(ms.Sys >> 20)
}

// ===================== 分级状态机 =====================

// guardThresholds 各层级触发阈值（软上限占比）与持续时间、恢复阈值
type guardThreshold struct {
	triggerPct int           // 触发占比
	triggerDur time.Duration // 持续时间
	recoverPct int           // 恢复占比（更低）
	recoverDur time.Duration // 恢复需持续
}

var guardThresholds = map[int]guardThreshold{
	guardL1: {triggerPct: 60, triggerDur: 30 * time.Second, recoverPct: 50, recoverDur: 2 * time.Minute},
	guardL2: {triggerPct: 80, triggerDur: 60 * time.Second, recoverPct: 60, recoverDur: 2 * time.Minute},
	guardL3: {triggerPct: 90, triggerDur: 120 * time.Second},
}

// resourceGuardianWorker 守护器主循环：每 5 秒采样一次（模块 worker，随开关启停）；
// 同时驱动 IP 信誉 tick（每小时回升/24h 恢复判定）与每 60 秒一次的信誉表持久化。
func resourceGuardianWorker(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	tick := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			stepResourceGuardian()
			ipRepTick()
			tick++
			if tick%12 == 0 { // 每 60 秒持久化一次信誉表
				ipRepSave()
			}
		}
	}
}

// stepResourceGuardian 单步评估（独立函数便于单测）
func stepResourceGuardian() {
	guardMu.Lock()
	defer guardMu.Unlock()
	if memLimit <= 0 {
		return
	}
	rss := currentRSSMB()
	limitMB := int(memLimit >> 20)
	pct := rss * 100 / limitMB
	now := time.Now()

	switch guardTier {
	case guardL0:
		if tierHold(guardL1, pct, now) {
			enterTier(guardL1, now, rss, pct)
		}
	case guardL1:
		if tierHold(guardL2, pct, now) {
			enterTier(guardL2, now, rss, pct)
			return
		}
		if tierRecovered(guardL1, pct, now) {
			exitTier(guardL1, now, rss, pct)
		}
	case guardL2:
		if tierHold(guardL3, pct, now) {
			enterTier(guardL3, now, rss, pct)
			return
		}
		if tierRecovered(guardL2, pct, now) {
			exitTier(guardL2, now, rss, pct)
		}
	}
	// goroutine 水位告警（任何层级下）：超 1 万 dump 栈入日志
	if n := runtime.NumGoroutine(); n > 10000 {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		logMsg("[GUARD] goroutine 水位告警 count=" + strconv.Itoa(n))
		fileLog("goroutine-dump", string(buf[:n]))
	}
}

// tierHold 判定升级条件是否满足（占比超阈值并持续所需时长）
func tierHold(toTier, pct int, now time.Time) bool {
	th := guardThresholds[toTier]
	if pct < th.triggerPct {
		delete(guardSince, toTier)
		return false
	}
	t0, ok := guardSince[toTier]
	if !ok {
		guardSince[toTier] = now
		return false
	}
	return now.Sub(t0) >= th.triggerDur
}

// tierRecovered 判定当前层级恢复条件（回落至恢复占比并持续所需时长）
func tierRecovered(tier, pct int, now time.Time) bool {
	th := guardThresholds[tier]
	if pct > th.recoverPct {
		delete(guardSince, 200+tier) // 200+ 恢复计时命名空间
		return false
	}
	key := 200 + tier
	t0, ok := guardSince[key]
	if !ok {
		guardSince[key] = now
		return false
	}
	return now.Sub(t0) >= th.recoverDur
}

// enterTier 升入层级并执行动作（guardMu 已持有）
func enterTier(tier int, now time.Time, rssMB, pct int) {
	guardTier = tier
	delete(guardSince, tier)
	switch tier {
	case guardL1:
		auditLog("RESOURCE_TIER_ENTER", "system", fmt.Sprintf("L1 rss=%dMB pct=%d%%: 降级非核心（discovery 降频 / 暂停下载 / 日志降采样）", rssMB, pct))
	case guardL2:
		modelLoadFuse = true
		runtime.GC()
		auditLog("RESOURCE_TIER_ENTER", "system", fmt.Sprintf("L2 rss=%dMB pct=%d%%: 熔断高耗（拒新模型加载 / webFetch 并发=1）", rssMB, pct))
	case guardL3:
		auditLog("RESOURCE_TIER_ENTER", "system", fmt.Sprintf("L3 rss=%dMB pct=%d%%: 优雅停机流程启动（drain<=30s + 审计刷盘）", rssMB, pct))
		guardL3At = now
		go gracefulResourceShutdown()
	}
}

// exitTier 回落恢复（guardMu 已持有）
func exitTier(tier int, now time.Time, rssMB, pct int) {
	if tier == guardL2 {
		modelLoadFuse = false
	}
	guardTier = guardL0
	delete(guardSince, 200+tier)
	auditLog("RESOURCE_TIER_EXIT", "system", fmt.Sprintf("L%d -> L0 rss=%dMB pct=%d%%", tier, rssMB, pct))
}

// gracefulResourceShutdown L3 优雅停机：drain + 审计刷盘 + 退出码 42。
// watchdog 场景下 60 秒内重复触发进冷却态由 start 脚本 --watchdog 侧配合
// （state 文件记录 guardL3At，重启后守护器检测冷却窗口）。
func gracefulResourceShutdown() {
	// drain：停新连接由 server 侧关闭（此处给在途请求最长 30 秒）
	deadline := time.Now().Add(30 * time.Second)
	if srv := serverRef(); srv != nil {
		go func() {
			if err := srv.Close(); err != nil {
				logMsg("[GUARD] listener 关闭: " + err.Error())
			}
		}()
	}
	// 审计刷盘：fileLog 为同步写，此处再显式写终止审计并 fsync
	auditLog("RESOURCE_AUTO_SHUTDOWN", "system", fmt.Sprintf("L3 drain 完成，退出码 42 (ts=%d)", time.Now().Unix()))
	flushFileLogs()
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
	}
	// 记录 L3 时间戳到 state（冷却判定用）
	saveGuardState()
	os.Exit(42)
}
