package main

// v3.2.2 共享记忆（shared memory）：跨客户端 / 跨 agent 的命名空间化 KV 记忆。
//
// 与既有 tars_memory_*（全局平铺 map）的关系：旧记忆保持只读兼容，本模块是
// 治理层升级——三个命名空间 + 解析链 + 治理上限 + 租户隔离：
//
//   命名空间        写权限                          读（解析链顺序）
//   global          仅 global_admin                 第 3 优先
//   tenant:<t>      本租户任何非 readonly 用户       第 2 优先
//   user:<t>/<u>    本用户本人                      第 1 优先
//
//   读取走解析链：user → tenant → global，同 key 就近覆盖（近者优先）。
//
// 治理上限（防滥用，代码级默认 + config 可收紧不可放宽）：
//   - 每 namespace 最多 1000 个 key；单值最大 64KB；全局最多 10000 key
//   - LRU 驱逐：namespace 超限时按 UpdatedAt 最旧驱逐
//   - TTL：条目可带 expiresAt，惰性过期（读时不返回、定期清扫）
//
// 持久化：shared-memory.json（temp+rename 原子写），启动恢复。
// 审计：SHARED_MEMORY_SET / DELETE / CROSS_TENANT_DENIED 全事件。
// MCP 工具：tars_shared_memory_set / get / list / delete（经守门人确认后写入）。
// REST：/api/context/memory（GET/POST/DELETE）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ===================== 数据模型 =====================

// SharedMemEntry 共享记忆条目
type SharedMemEntry struct {
	Value     string     `json:"value"`
	UpdatedBy string     `json:"updatedBy"`
	UpdatedAt time.Time  `json:"updatedAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Revision  int64      `json:"revision"`
}

var (
	sharedMemMu    sync.Mutex
	sharedMem      = map[string]map[string]SharedMemEntry{} // ns -> key -> entry
	sharedMemRev   int64                                     // 全局修订号（单调递增）
)

// 治理上限（代码级默认；config 仅允许收紧）
const (
	smDefaultMaxPerNS  = 1000
	smDefaultMaxValue  = 64 * 1024
	smDefaultMaxTotal  = 10000
)

// smMaxPerNS / smMaxValue / smMaxTotal 读取上限（未配置 = 默认；配置值只能更小）
func smLimits() (maxPerNS, maxValue, maxTotal int) {
	maxPerNS, maxValue, maxTotal = smDefaultMaxPerNS, smDefaultMaxValue, smDefaultMaxTotal
	// v3.2.2 治理配置段（松散读取，见 guardsupport.go cfgInt 模式）
	if v := cfgInt("sharedMemory", "maxKeysPerNamespace"); v > 0 && v < maxPerNS {
		maxPerNS = v
	}
	if v := cfgInt("sharedMemory", "maxValueBytes"); v > 0 && v < maxValue {
		maxValue = v
	}
	if v := cfgInt("sharedMemory", "maxTotalKeys"); v > 0 && v < maxTotal {
		maxTotal = v
	}
	return
}

func smUserNS(tenant, user string) string   { return "user:" + tenant + "/" + user }
func smTenantNS(tenant string) string       { return "tenant:" + tenant }
const smGlobalNS = "global"

// smNormalizeNS 规范化调用方请求的 namespace：自动限定到调用方可写的合法范围
func smNormalizeNS(id Identity, ns string) (string, error) {
	switch ns {
	case "", "user":
		return smUserNS(id.Tenant, id.Name), nil
	case "tenant":
		return smTenantNS(id.Tenant), nil
	case "global":
		if !id.Global {
			return "", fmt.Errorf("global 命名空间仅全局角色可写")
		}
		return smGlobalNS, nil
	default:
		return "", fmt.Errorf("namespace 只能是 user / tenant / global")
	}
}

// ===================== 核心 API =====================

// smSet 写入（含权限 / 上限 / LRU / TTL / 审计）
func smSet(id Identity, ns, key, value string, ttl time.Duration) (SharedMemEntry, error) {
	if id.Name == "" {
		return SharedMemEntry{}, fmt.Errorf("需要身份才能写共享记忆")
	}
	if key == "" || len(key) > 256 {
		return SharedMemEntry{}, fmt.Errorf("key 不能为空且不超过 256 字符")
	}
	ns, err := smNormalizeNS(id, ns)
	if err != nil {
		auditLogT("SHARED_MEMORY_CROSS_TENANT_DENIED", id.Tenant, "", id.Name, "ns="+ns+" key="+key)
		return SharedMemEntry{}, err
	}
	maxPerNS, maxValue, maxTotal := smLimits()
	if len(value) > maxValue {
		return SharedMemEntry{}, fmt.Errorf("value 超过上限 %d 字节", maxValue)
	}
	sharedMemMu.Lock()
	defer sharedMemMu.Unlock()
	if sharedMem[ns] == nil {
		sharedMem[ns] = map[string]SharedMemEntry{}
	}
	if _, exists := sharedMem[ns][key]; !exists {
		total := 0
		for _, m := range sharedMem {
			total += len(m)
		}
		if total >= maxTotal {
			return SharedMemEntry{}, fmt.Errorf("全局共享记忆 key 数达到上限 %d", maxTotal)
		}
		if len(sharedMem[ns]) >= maxPerNS {
			smEvictOldestLocked(ns, maxPerNS)
		}
	}
	sharedMemRev++
	e := SharedMemEntry{
		Value: value, UpdatedBy: id.Name, UpdatedAt: time.Now(), Revision: sharedMemRev,
	}
	if ttl > 0 {
		t := time.Now().Add(ttl)
		e.ExpiresAt = &t
	}
	sharedMem[ns][key] = e
	smSaveLocked()
	auditLogT("SHARED_MEMORY_SET", id.Tenant, "", id.Name, fmt.Sprintf("ns=%s key=%s bytes=%d rev=%d", ns, key, len(value), e.Revision))
	return e, nil
}

// smEvictOldestLocked LRU 驱逐最旧一条（调用方持锁）
func smEvictOldestLocked(ns string, cap int) {
	for len(sharedMem[ns]) >= cap {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, v := range sharedMem[ns] {
			if first || v.UpdatedAt.Before(oldest) {
				oldestKey, oldest, first = k, v.UpdatedAt, false
			}
		}
		if oldestKey == "" {
			return
		}
		delete(sharedMem[ns], oldestKey)
	}
}

// smGet 解析链读取：user → tenant → global（就近覆盖）；返回条目与来源 ns
func smGet(id Identity, key string) (SharedMemEntry, string, bool) {
	chain := []string{smUserNS(id.Tenant, id.Name), smTenantNS(id.Tenant)}
	if id.Global {
		chain = append(chain, smGlobalNS)
	} else if id.Tenant == "*" {
		chain = append(chain, smGlobalNS)
	}
	sharedMemMu.Lock()
	defer sharedMemMu.Unlock()
	smSweepExpiredLocked()
	for _, ns := range chain {
		if e, ok := sharedMem[ns][key]; ok {
			return e, ns, true
		}
	}
	// global 角色额外可读 global ns（上面已含）；普通用户的 global 读放这里：
	if !id.Global {
		if e, ok := sharedMem[smGlobalNS][key]; ok {
			return e, smGlobalNS, true
		}
	}
	return SharedMemEntry{}, "", false
}

// smList 列出调用方可见条目（解析链合并视图；同 key 就近层覆盖远层）
func smList(id Identity, prefix string) []map[string]interface{} {
	chain := []string{smUserNS(id.Tenant, id.Name), smTenantNS(id.Tenant), smGlobalNS}
	res := map[string]struct {
		ns, key string
		e       SharedMemEntry
	}{}
	sharedMemMu.Lock()
	smSweepExpiredLocked()
	// 从最远层（global）开始写入、最近层最后写入 → 同 key 时最近层覆盖远层
	for i := len(chain) - 1; i >= 0; i-- {
		for k, e := range sharedMem[chain[i]] {
			if prefix != "" && !strings.HasPrefix(k, prefix) {
				continue
			}
			res[k] = struct {
				ns, key string
				e       SharedMemEntry
			}{chain[i], k, e}
		}
	}
	sharedMemMu.Unlock()
	var list []map[string]interface{}
	for _, h := range res {
		list = append(list, map[string]interface{}{
			"key": h.key, "value": h.e.Value, "namespace": h.ns,
			"updatedBy": h.e.UpdatedBy, "updatedAt": h.e.UpdatedAt,
			"revision": h.e.Revision, "expiresAt": h.e.ExpiresAt,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i]["key"].(string) < list[j]["key"].(string)
	})
	// 上限保护：最多返回 500 条（防枚举风暴）
	if len(list) > 500 {
		list = list[:500]
	}
	return list
}

// smDelete 删除（仅能删自己可写命名空间内的条目）
func smDelete(id Identity, ns, key string) (bool, error) {
	ns, err := smNormalizeNS(id, ns)
	if err != nil {
		return false, err
	}
	sharedMemMu.Lock()
	defer sharedMemMu.Unlock()
	if sharedMem[ns] == nil {
		return false, nil
	}
	if _, ok := sharedMem[ns][key]; !ok {
		return false, nil
	}
	delete(sharedMem[ns], key)
	smSaveLocked()
	auditLogT("SHARED_MEMORY_DELETE", id.Tenant, "", id.Name, fmt.Sprintf("ns=%s key=%s", ns, key))
	return true, nil
}

// smSweepExpiredLocked 惰性清扫过期条目（调用方持锁；每 1000 次读做一次全扫的开销不可接受，直接每次轻扫）
func smSweepExpiredLocked() {
	now := time.Now()
	for ns, m := range sharedMem {
		for k, e := range m {
			if e.ExpiresAt != nil && now.After(*e.ExpiresAt) {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(sharedMem, ns)
		}
	}
}

// ===================== 持久化 =====================

func sharedMemoryPath() string {
	return filepath.Join(appDir(), "shared-memory.json")
}

// smSaveLocked 落盘（temp + rename 原子写；调用方持锁）
func smSaveLocked() {
	data, err := json.MarshalIndent(sharedMem, "", "  ")
	if err != nil {
		return
	}
	tmp := sharedMemoryPath() + ".tmp"
	if os.WriteFile(tmp, data, 0640) == nil {
		os.Rename(tmp, sharedMemoryPath())
	}
}

// loadSharedMemory 启动恢复
func loadSharedMemory() {
	data, err := os.ReadFile(sharedMemoryPath())
	if err != nil {
		return
	}
	var m map[string]map[string]SharedMemEntry
	if json.Unmarshal(data, &m) == nil && m != nil {
		sharedMemMu.Lock()
		sharedMem = m
		sharedMemMu.Unlock()
	}
	logMsg(fmt.Sprintf("[SHARED-MEMORY] 恢复 %d 个命名空间", len(sharedMem)))
}

// ===================== REST：/api/context/memory =====================

func handleSharedMemoryREST(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"items": smList(id, r.URL.Query().Get("prefix"))})
	case http.MethodPost:
		var req struct {
			Key        string `json:"key"`
			Value      string `json:"value"`
			Namespace  string `json:"namespace"`
			TTLSeconds int    `json:"ttlSeconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "key 与 value 必填"})
			return
		}
		e, err := smSet(id, req.Namespace, req.Key, req.Value, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]interface{}{"success": true, "revision": e.Revision})
	case http.MethodDelete:
		key := r.URL.Query().Get("key")
		ns := r.URL.Query().Get("namespace")
		if key == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "key 必填"})
			return
		}
		deleted, err := smDelete(id, ns, key)
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]interface{}{"success": true, "deleted": deleted})
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}
