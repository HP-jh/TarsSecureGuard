package main

// v4.10.1 Sticky Session + Smart Failover — Surpass LLMux
// Kingdom 7 层归位：界·Domain = gateway / 门·Phylum = routing / 纲·Class = sticky-router
//
// 借鉴 LLMux dispatcher.rs 状态机思路（AGPL-3.0 隔离，Go 自研实现）：
// - Primary 模式：请求优先走首选账户（保持 prompt cache 热）
// - Fallback 模式：首选失效时切备用账户，指数退避探测恢复
// - 账户级 sticky：按 providerID + model 为 dispatch key 分组
// - 内存状态 + config 持久化（简化版，不走 SQLite）

import (
	"fmt"
	"sync"
	"time"
)

const (
	stickyProbeTriggerCount = 5               // fallback 连续成功 N 次后触发探测
	stickyInitialBackoffSec = 30              // 首次探测退避 30s
	stickyMaxBackoffSec     = 600             // 最大退避 600s
	stickyMaxEntries        = 1024            // 内存条目上限
)

type stickyMode int

const (
	stickyPrimary  stickyMode = iota // 首选账户正常
	stickyFallback                   // 已切换至备用账户
)

// stickyEntry 单个 dispatch key 的路由状态
type stickyEntry struct {
	mode                 stickyMode
	stickyFallbackKey    string    // 当前粘滞的备用账户标识（通常是备用 API key 前缀或索引）
	consecutiveSuccesses int       // fallback 模式下连续成功次数
	lastProbe            time.Time // 上次探测时刻
	probeBackoffSec      int       // 当前探测退避秒数
}

// StickyRouter 粘滞路由状态机
type StickyRouter struct {
	mu      sync.RWMutex
	entries map[string]*stickyEntry // key: "providerID/model"
	dirty   bool
}

var stickyRouter = &StickyRouter{entries: make(map[string]*stickyEntry)}

// selectSticky 为指定 dispatchKey 选择候选账户排序。
// candidates: 可用账户标识列表（如 ["key1", "key2", ...]）
// preferred:  首选账户标识
// 返回排序后的候选列表 + 是否为探测请求
func (sr *StickyRouter) selectSticky(dispatchKey string, candidates []string, preferred string) (ordered []string, isProbe bool) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if len(candidates) == 0 {
		return nil, false
	}

	e, ok := sr.entries[dispatchKey]
	if !ok {
		e = &stickyEntry{mode: stickyPrimary, probeBackoffSec: stickyInitialBackoffSec}
		sr.entries[dispatchKey] = e
	}

	// 首选账户已不在候选集 → 强制回到 Primary（由 record 处理降级）
	preferredExists := false
	for _, c := range candidates {
		if c == preferred {
			preferredExists = true
			break
		}
	}
	if !preferredExists {
		e.mode = stickyPrimary
		e.stickyFallbackKey = ""
		sr.dirty = true
	}

	if e.mode == stickyPrimary {
		return orderPreferredFirst(candidates, preferred), false
	}

	// Fallback 模式：判断是否需要探测首选账户
	shouldProbe := e.consecutiveSuccesses >= stickyProbeTriggerCount ||
		time.Since(e.lastProbe) >= time.Duration(e.probeBackoffSec)*time.Second

	if shouldProbe {
		return orderPreferredFirst(candidates, preferred), true
	}
	return orderFallbackFirst(candidates, preferred, e.stickyFallbackKey), false
}

// recordSticky 记录一次调度结果，更新状态机
func (sr *StickyRouter) recordSticky(dispatchKey string, isProbe bool, usedKey string, preferred string, success bool) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	e, ok := sr.entries[dispatchKey]
	if !ok {
		return
	}

	switch e.mode {
	case stickyPrimary:
		if !success || usedKey != preferred {
			// 首选失败 → 进入 Fallback
			fallback := usedKey
			if fallback == preferred || fallback == "" {
				fallback = pickFirstNonPreferred(e, preferred) // 辅助：从已知候选选一个非首选
			}
			e.mode = stickyFallback
			e.stickyFallbackKey = fallback
			e.consecutiveSuccesses = 0
			if fallback != "" {
				e.consecutiveSuccesses = 1
			}
			e.lastProbe = time.Now()
			e.probeBackoffSec = stickyInitialBackoffSec
			sr.dirty = true
		}
	case stickyFallback:
		if isProbe {
			if success && usedKey == preferred {
				// 探测成功 → 恢复 Primary
				e.mode = stickyPrimary
				e.stickyFallbackKey = ""
				e.consecutiveSuccesses = 0
				sr.dirty = true
			} else {
				// 探测失败 → 指数退避
				if e.probeBackoffSec < stickyMaxBackoffSec {
					e.probeBackoffSec *= 2
					if e.probeBackoffSec > stickyMaxBackoffSec {
						e.probeBackoffSec = stickyMaxBackoffSec
					}
				}
				e.consecutiveSuccesses = 0
				e.lastProbe = time.Now()
				if usedKey != "" && usedKey != preferred {
					e.stickyFallbackKey = usedKey
				}
				sr.dirty = true
			}
		} else if success {
			e.consecutiveSuccesses++
			if usedKey != "" {
				e.stickyFallbackKey = usedKey
			}
			sr.dirty = true
		}
	}

	sr.maybeEvictLocked()
}

// maybeEvictLocked 淘汰旧条目：Primary 条目优先淘汰，保留 Fallback（含活跃故障转移状态）
func (sr *StickyRouter) maybeEvictLocked() {
	if len(sr.entries) <= stickyMaxEntries {
		return
	}
	for k, e := range sr.entries {
		if e.mode == stickyPrimary {
			delete(sr.entries, k)
		}
		if len(sr.entries) <= stickyMaxEntries {
			break
		}
	}
}

// ResetSticky 重置指定 provider/model 的 sticky 状态（admin API 用）
func (sr *StickyRouter) ResetSticky(dispatchKey string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	delete(sr.entries, dispatchKey)
	sr.dirty = true
}

// Snapshot 导出当前状态（用于持久化或观测）
func (sr *StickyRouter) Snapshot() map[string]map[string]interface{} {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	out := make(map[string]map[string]interface{}, len(sr.entries))
	for k, e := range sr.entries {
		mode := "primary"
		if e.mode == stickyFallback {
			mode = "fallback"
		}
		out[k] = map[string]interface{}{
			"mode":                  mode,
			"stickyFallbackKey":     e.stickyFallbackKey,
			"consecutiveSuccesses":  e.consecutiveSuccesses,
			"lastProbe":             e.lastProbe.Format(time.RFC3339),
			"probeBackoffSec":       e.probeBackoffSec,
		}
	}
	return out
}

// --- helpers ---

func orderPreferredFirst(candidates []string, preferred string) []string {
	out := make([]string, 0, len(candidates))
	var pref *string
	for _, c := range candidates {
		if c == preferred {
			p := c
			pref = &p
		} else {
			out = append(out, c)
		}
	}
	if pref != nil {
		out = append([]string{*pref}, out...)
	}
	return out
}

func orderFallbackFirst(candidates []string, preferred string, fallback string) []string {
	out := make([]string, 0, len(candidates))
	var fb, pref *string
	for _, c := range candidates {
		if c == fallback {
			p := c
			fb = &p
		} else if c == preferred {
			p := c
			pref = &p
		} else {
			out = append(out, c)
		}
	}
	if fb != nil {
		out = append([]string{*fb}, out...)
	}
	if pref != nil {
		out = append(out, *pref)
	}
	return out
}

// pickFirstNonPreferred 辅助：在信息不足时选一个非首选作为 fallback
func pickFirstNonPreferred(e *stickyEntry, preferred string) string {
	if e.stickyFallbackKey != "" && e.stickyFallbackKey != preferred {
		return e.stickyFallbackKey
	}
	return ""
}

// providerCandidates 从 ProviderOverride 生成候选账户列表（支持多密钥）
func providerCandidates(ov ProviderOverride) []string {
	// v4.10.1：ProviderOverride.APIKeys 支持多密钥；单密钥兼容旧版 APIKey
	keys := ov.APIKeys
	if len(keys) == 0 && ov.APIKey != "" {
		keys = []string{ov.APIKey}
	}
	cands := make([]string, 0, len(keys))
	for i, k := range keys {
		if k != "" {
			// 候选标识：索引形式 "idx:0" 便于 sticky 路由区分同一 provider 的不同 key
			cands = append(cands, fmt.Sprintf("idx:%d", i))
		}
	}
	return cands
}

// providerKeyByIndex 按索引取实际密钥
func providerKeyByIndex(ov ProviderOverride, idx int) string {
	keys := ov.APIKeys
	if len(keys) == 0 && ov.APIKey != "" {
		keys = []string{ov.APIKey}
	}
	if idx >= 0 && idx < len(keys) {
		return keys[idx]
	}
	return ""
}
