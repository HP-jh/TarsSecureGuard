package main

// ===================== v3.2.0 健康度探测 + 熔断器（Circuit Breaker）=====================
//
// 每个 provider 一个三态熔断器：closed（正常）→ open（连续失败达阈值，拒绝出站，
// 快速失败省得客户端干等超时）→ half-open（冷却期满放一个探测请求）→ 恢复/再熔断。
//
//   - 阈值 / 冷却时长 / 探测间隔均可经 config.json v32.circuit 配置
//   - 健康探测 worker 只探测「已配密钥」的云端 provider（无密钥探测必然 401，
//     只产生噪音）；本地运行时由 auto-discovery 模块另行覆盖
//   - 熔断只影响「路由可用性」，绝不影响安全链：被熔断的 provider 直接
//     快速失败，请求仍走完整 WAF / 语义分级 / 限流 / 审计链路
//   - 状态迁移写审计日志（PROVIDER_CIRCUIT_OPEN / _RECOVER），供面板回溯

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type breakerState int

const (
	cbClosed breakerState = iota
	cbOpen
	cbHalfOpen
)

func (s breakerState) String() string {
	switch s {
	case cbClosed:
		return "closed"
	case cbOpen:
		return "open"
	default:
		return "half-open"
	}
}

type breaker struct {
	state        breakerState
	failures     int       // closed 态连续失败计数
	openedAt     time.Time // 进入 open 的时刻
	halfOpenBusy bool      // half-open 态是否已有在途探测
}

var (
	cbMu    sync.Mutex
	cbTable = map[string]*breaker{}
)

// v32CircuitDefaults 熔断参数（config v32.circuit 可覆盖）
func v32CircuitDefaults() (threshold int, openSec, probeSec int) {
	threshold, openSec, probeSec = 5, 30, 60
	c := cfg.V32Config.Circuit
	if c.FailureThreshold > 0 {
		threshold = c.FailureThreshold
	}
	if c.OpenSeconds > 0 {
		openSec = c.OpenSeconds
	}
	if c.ProbeIntervalSec > 0 {
		probeSec = c.ProbeIntervalSec
	}
	return
}

// cbAllow 该 provider 当前是否放行出站请求（open 态直接拒绝）
func cbAllow(id string) bool {
	cbMu.Lock()
	defer cbMu.Unlock()
	b, ok := cbTable[id]
	if !ok || b.state == cbClosed {
		return true
	}
	if b.state == cbOpen {
		_, openSec, _ := v32CircuitDefaults()
		if time.Since(b.openedAt) >= time.Duration(openSec)*time.Second {
			b.state = cbHalfOpen
			b.halfOpenBusy = true
			return true // 冷却期满：转 half-open，放一个请求试探
		}
		return false
	}
	// half-open：探测在途中，其余请求仍拒绝
	return false
}

// cbRecord 记录一次出站结果（ok=true 复位；ok=false 计数直至熔断）
func cbRecord(id string, ok bool) {
	threshold, openSec, _ := v32CircuitDefaults()
	cbMu.Lock()
	b, exists := cbTable[id]
	if !exists {
		b = &breaker{}
		cbTable[id] = b
	}
	prev := b.state
	if ok {
		b.state = cbClosed
		b.failures = 0
		b.halfOpenBusy = false
	} else {
		switch b.state {
		case cbHalfOpen:
			b.state = cbOpen
			b.openedAt = time.Now()
			b.halfOpenBusy = false
			b.failures = 0
		case cbOpen:
			// half-open 探测失败后的重复记录，忽略
		default: // closed
			b.failures++
			if b.failures >= threshold {
				b.state = cbOpen
				b.openedAt = time.Now()
			}
		}
	}
	cur := b.state
	cbMu.Unlock()
	// 状态迁移审计（锁外调用，避免与审计内部锁交叉）
	if prev != cur {
		if cur == cbOpen {
			auditLog("PROVIDER_CIRCUIT_OPEN", "system", fmt.Sprintf("provider=%s 连续失败熔断（%d 次），冷却 %ds", id, threshold, openSec))
		} else if prev == cbOpen && cur != cbOpen {
			auditLog("PROVIDER_CIRCUIT_RECOVER", "system", fmt.Sprintf("provider=%s 熔断恢复（%s）", id, cur))
		}
	}
}

// cbStates 全量快照（面板用）
func cbStates() map[string]string {
	cbMu.Lock()
	defer cbMu.Unlock()
	out := map[string]string{}
	for id, b := range cbTable {
		out[id] = b.state.String()
	}
	return out
}

// providerHealthProbe 探测单个 provider 的健康端点（按协议取最便宜的可鉴权 GET）
func providerHealthProbe(spec ProviderSpec) bool {
	key, hasKey := providerAPIKey(spec)
	base, _ := providerEffectiveURL(spec)
	base = strings.TrimSuffix(base, "/")
	var url string
	req, err := func() (*http.Request, error) {
		switch spec.Protocol {
		case "anthropic":
			url = base + "/v1/models"
			r, e := http.NewRequest(http.MethodGet, url, nil)
			if e != nil {
				return nil, e
			}
			r.Header.Set("x-api-key", key)
			r.Header.Set("anthropic-version", "2023-06-01")
			return r, nil
		case "gemini":
			url = base + "/v1beta/models"
			r, e := http.NewRequest(http.MethodGet, url, nil)
			if e != nil {
				return nil, e
			}
			r.Header.Set("x-goog-api-key", key)
			return r, nil
		case "ollama":
			url = base + "/api/tags"
			return http.NewRequest(http.MethodGet, url, nil)
		default: // openai-compat
			url = base + "/models"
			r, e := http.NewRequest(http.MethodGet, url, nil)
			if e != nil {
				return nil, e
			}
			if hasKey {
				r.Header.Set("Authorization", "Bearer "+key)
			}
			return r, nil
		}
	}()
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: 8 * time.Second}
	if sharedTransport != nil {
		client.Transport = trackedTransport{sharedTransport}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// 2xx = 健康；401/403 = 密钥问题（不算网络故障，但也不算健康——按失败计）
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// providerHealthWorker 周期探测已配置密钥的云端 provider。
// intervalSec <= 0 时不启动（config v32.circuit.probeIntervalSec=0 关闭）。
func providerHealthWorker(stop <-chan struct{}) {
	_, _, probeSec := v32CircuitDefaults()
	if probeSec <= 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(probeSec) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			preg.mu.RLock()
			var targets []ProviderSpec
			for _, id := range preg.order {
				s := preg.specs[id]
				if s.Kind != "cloud" || !providerEnabled(s) {
					continue
				}
				if _, ok := providerAPIKey(s); !ok {
					continue // 未配密钥不探测
				}
				targets = append(targets, s)
			}
			preg.mu.RUnlock()
			for _, s := range targets {
				// 只探测当前处于熔断/未知态的 provider，健康的不打扰
				if st, ok := cbStates()[s.ID]; ok && st == "closed" {
					continue
				}
				cbRecord(s.ID, providerHealthProbe(s))
			}
		}
	}
}

// handleV32ProvidersProbe POST /api/admin/v32/providers/probe —— 手动触发一次
// 全量（或 ?id=xxx 单个）健康探测（admin.write，与 auto-discovery/scan 同级）
func handleV32ProvidersProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	id := r.URL.Query().Get("id")
	preg.mu.RLock()
	var targets []ProviderSpec
	for _, pid := range preg.order {
		if id != "" && pid != id {
			continue
		}
		s := preg.specs[pid]
		if s.Kind != "cloud" {
			continue
		}
		if _, ok := providerAPIKey(s); !ok {
			continue
		}
		targets = append(targets, s)
	}
	preg.mu.RUnlock()
	results := map[string]bool{}
	for _, s := range targets {
		ok := providerHealthProbe(s)
		cbRecord(s.ID, ok)
		results[s.ID] = ok
	}
	auditLog("PROVIDER_PROBE_MANUAL", "system", fmt.Sprintf("手动健康探测 %d 个 provider（%d 健康）", len(results), countTrue(results)))
	writeJSON(w, map[string]interface{}{"success": true, "probed": len(results), "healthy": countTrue(results), "results": results})
}

func countTrue(m map[string]bool) int {
	n := 0
	for _, v := range m {
		if v {
			n++
		}
	}
	return n
}
