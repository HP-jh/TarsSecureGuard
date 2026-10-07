package main

// v3.2.2 共享信息（shared info）：结构化、可检索的团队知识面。
//
// 与共享记忆的分工：共享记忆是「机器用的 KV」（agent 运行时状态、就近覆盖），
// 共享信息是「人机共用的知识条目」——有类型、标题、标签、置信度、来源，
// 供上下文组装引擎按主题相关性挑选注入，也可被人检索。
//
//   条目模型：{id, type, title, content, tags[], scope, tenant, source,
//             confidence, createdAt, updatedAt, revision}
//   类型：fact（事实）/ preference（偏好）/ note（备忘）/ link（外链）
//   可见性：tenant（本租户，默认）/ global（仅全局角色可写，全员可读）
//
// 治理：最多 5000 条、单条 content ≤ 32KB、title ≤ 200 字符；revision 单调递增。
// 审计：SHARED_INFO_ADD / DELETE / CROSS_TENANT_DENIED 全事件。
// REST：/api/context/info（GET 搜索 / POST 新增 / DELETE 删除）
// MCP 工具：tars_shared_info_add / tars_shared_info_search（读）/ tars_shared_info_delete

import (
	"crypto/rand"
	"encoding/hex"
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

// SharedInfoRecord 共享信息条目
type SharedInfoRecord struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"` // fact | preference | note | link
	Title      string    `json:"title"`
	Content    string    `json:"content"`
	Tags       []string  `json:"tags,omitempty"`
	Scope      string    `json:"scope"` // tenant | global
	Tenant     string    `json:"tenant"`
	Source     string    `json:"source"` // 创建者
	Confidence float64   `json:"confidence"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Revision   int64     `json:"revision"`
}

var (
	sharedInfoMu   sync.Mutex
	sharedInfo     = map[string]SharedInfoRecord{} // id -> record
	sharedInfoRev  int64
)

const (
	siMaxRecords     = 5000
	siMaxContent     = 32 * 1024
	siMaxTitle       = 200
	siDefaultVisible = 200 // 搜索返回上限
)

var siAllowedTypes = map[string]bool{"fact": true, "preference": true, "note": true, "link": true}

// ===================== 核心 API =====================

func siNewID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "si_" + hex.EncodeToString(b)
}

// siValidateType / siNormalizeType
func siNormalizeType(t string) (string, error) {
	if t == "" {
		return "note", nil
	}
	if !siAllowedTypes[t] {
		return "", fmt.Errorf("type 只能是 fact / preference / note / link")
	}
	return t, nil
}

// siAdd 新增条目（scope 归一化：非全局角色强制 tenant + 本租户）
func siAdd(id Identity, typ, title, content string, tags []string, scope string, confidence float64) (SharedInfoRecord, error) {
	if id.Name == "" {
		return SharedInfoRecord{}, fmt.Errorf("需要身份才能写共享信息")
	}
	typ, err := siNormalizeType(typ)
	if err != nil {
		return SharedInfoRecord{}, err
	}
	if strings.TrimSpace(title) == "" || len(title) > siMaxTitle {
		return SharedInfoRecord{}, fmt.Errorf("title 必填且不超过 %d 字符", siMaxTitle)
	}
	if content == "" || len(content) > siMaxContent {
		return SharedInfoRecord{}, fmt.Errorf("content 必填且不超过 %d 字节", siMaxContent)
	}
	if confidence < 0 || confidence > 1 {
		confidence = 0.5
	}
	tenant := id.Tenant
	if scope == "global" {
		if !id.Global {
			auditLogT("SHARED_INFO_CROSS_TENANT_DENIED", id.Tenant, "", id.Name, "attempt global scope title="+title)
			return SharedInfoRecord{}, fmt.Errorf("global 共享信息仅全局角色可写")
		}
		tenant = "*"
	} else {
		scope = "tenant"
	}
	if len(tags) > 20 {
		tags = tags[:20]
	}
	sharedInfoMu.Lock()
	defer sharedInfoMu.Unlock()
	if len(sharedInfo) >= siMaxRecords {
		return SharedInfoRecord{}, fmt.Errorf("共享信息条目数达到上限 %d", siMaxRecords)
	}
	sharedInfoRev++
	now := time.Now()
	rec := SharedInfoRecord{
		ID: siNewID(), Type: typ, Title: title, Content: content, Tags: tags,
		Scope: scope, Tenant: tenant, Source: id.Name, Confidence: confidence,
		CreatedAt: now, UpdatedAt: now, Revision: sharedInfoRev,
	}
	sharedInfo[rec.ID] = rec
	siSaveLocked()
	auditLogT("SHARED_INFO_ADD", id.Tenant, "", id.Name, fmt.Sprintf("id=%s type=%s scope=%s title=%.60s", rec.ID, typ, scope, title))
	return rec, nil
}

// siVisible 判断条目对身份是否可见（global 全见；普通身份见本租户 + global 条目）
func siVisible(id Identity, rec SharedInfoRecord) bool {
	if id.Global {
		return true
	}
	return rec.Tenant == id.Tenant || rec.Scope == "global"
}

// siSearch 关键词检索（title/content/tag 命中；q 为空 = 按时间倒序全览）
// 返回已按 (相关性, 更新时间) 排序的可见条目。
func siSearch(id Identity, q, typ string, limit int) []SharedInfoRecord {
	if limit <= 0 || limit > siDefaultVisible {
		limit = siDefaultVisible
	}
	q = strings.ToLower(strings.TrimSpace(q))
	sharedInfoMu.Lock()
	var hits []struct {
		rec  SharedInfoRecord
		rank int
	}
	for _, rec := range sharedInfo {
		if !siVisible(id, rec) {
			continue
		}
		if typ != "" && rec.Type != typ {
			continue
		}
		rank := 0
		if q != "" {
			ltitle := strings.ToLower(rec.Title)
			lcontent := strings.ToLower(rec.Content)
			switch {
			case strings.Contains(ltitle, q):
				rank = 100
			case hasTag(rec.Tags, q):
				rank = 80
			case strings.Contains(lcontent, q):
				rank = 40
			default:
				continue // 不命中不返回
			}
		}
		hits = append(hits, struct {
			rec  SharedInfoRecord
			rank int
		}{rec, rank})
	}
	sharedInfoMu.Unlock()
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].rank != hits[j].rank {
			return hits[i].rank > hits[j].rank
		}
		return hits[i].rec.UpdatedAt.After(hits[j].rec.UpdatedAt)
	})
	var out []SharedInfoRecord
	for _, h := range hits {
		out = append(out, h.rec)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func hasTag(tags []string, q string) bool {
	for _, t := range tags {
		if strings.ToLower(t) == q {
			return true
		}
	}
	return false
}

// siDelete 删除条目（本租户条目本租户可删；global 条目仅全局角色）
func siDelete(id Identity, recID string) (bool, error) {
	sharedInfoMu.Lock()
	rec, ok := sharedInfo[recID]
	sharedInfoMu.Unlock()
	if !ok {
		return false, nil
	}
	if rec.Scope == "global" {
		if !id.Global {
			return false, fmt.Errorf("global 条目仅全局角色可删")
		}
	} else if rec.Tenant != id.Tenant && !id.Global {
		auditLogT("SHARED_INFO_CROSS_TENANT_DENIED", id.Tenant, "", id.Name, "delete id="+recID)
		return false, fmt.Errorf("无权删除其他租户的条目")
	}
	sharedInfoMu.Lock()
	delete(sharedInfo, recID)
	siSaveLocked()
	sharedInfoMu.Unlock()
	auditLogT("SHARED_INFO_DELETE", id.Tenant, "", id.Name, fmt.Sprintf("id=%s title=%.60s", recID, rec.Title))
	return true, nil
}

// ===================== 持久化 =====================

func sharedInfoPath() string {
	return filepath.Join(appDir(), "shared-info.json")
}

func siSaveLocked() {
	data, err := json.MarshalIndent(map[string][]SharedInfoRecord{"data": siSliceLocked()}, "", "  ")
	if err != nil {
		return
	}
	tmp := sharedInfoPath() + ".tmp"
	if os.WriteFile(tmp, data, 0640) == nil {
		os.Rename(tmp, sharedInfoPath())
	}
}

// siSliceLocked 稳定序列化（按 ID 排序，文件内容可 diff）
func siSliceLocked() []SharedInfoRecord {
	ids := make([]string, 0, len(sharedInfo))
	for k := range sharedInfo {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	out := make([]SharedInfoRecord, 0, len(ids))
	for _, k := range ids {
		out = append(out, sharedInfo[k])
	}
	return out
}

// loadSharedInfo 启动恢复
func loadSharedInfo() {
	data, err := os.ReadFile(sharedInfoPath())
	if err != nil {
		return
	}
	var wrap struct {
		Data []SharedInfoRecord `json:"data"`
	}
	if json.Unmarshal(data, &wrap) == nil {
		sharedInfoMu.Lock()
		sharedInfo = map[string]SharedInfoRecord{}
		for _, rec := range wrap.Data {
			sharedInfo[rec.ID] = rec
			if rec.Revision > sharedInfoRev {
				sharedInfoRev = rec.Revision
			}
		}
		sharedInfoMu.Unlock()
	}
	logMsg(fmt.Sprintf("[SHARED-INFO] 恢复 %d 条共享信息", len(sharedInfo)))
}

// ===================== REST：/api/context/info =====================

func handleSharedInfoREST(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit := 0
		fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
		recs := siSearch(id, r.URL.Query().Get("q"), r.URL.Query().Get("type"), limit)
		writeJSON(w, map[string]interface{}{"items": recs, "count": len(recs)})
	case http.MethodPost:
		var req struct {
			Type       string   `json:"type"`
			Title      string   `json:"title"`
			Content    string   `json:"content"`
			Tags       []string `json:"tags"`
			Scope      string   `json:"scope"`
			Confidence float64  `json:"confidence"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Title == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "title 与 content 必填"})
			return
		}
		rec, err := siAdd(id, req.Type, req.Title, req.Content, req.Tags, req.Scope, req.Confidence)
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]interface{}{"success": true, "id": rec.ID, "revision": rec.Revision})
	case http.MethodDelete:
		recID := r.URL.Query().Get("id")
		if recID == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "id 必填"})
			return
		}
		deleted, err := siDelete(id, recID)
		if err != nil {
			writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]interface{}{"success": true, "deleted": deleted})
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}
