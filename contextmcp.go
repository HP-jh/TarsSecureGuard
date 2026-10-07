package main

// v3.2.2 上下文拓展 MCP（context extension）：把共享记忆 + 共享信息组装成
// 可注入对话的「上下文包」——AI 客户端从此不必各自维护一摊上下文。
//
// 组装引擎（确定性、可测试）：
//   buildContextPack(id, opts) → 三个有序段落，按预算截断（优先级：身份策略 >
//   共享信息 > 共享记忆）：
//     [身份与策略]  固定 preamble：角色 / 租户 / 日期（每次注入，防身份漂移）
//     [共享信息]    按主题相关性（tag/title 命中 > content 命中 > 时间新）挑选
//     [共享记忆]    解析链可见的 KV，逐行 "key = value"
//   预算：maxChars（默认 4096）；每段截断标记 "(已截断)"；估算 tokens=chars/4
//   （估算值，非 tokenizer 实测，输出里明确标注 estimated）。
//
// 注入通道（chat.go /api/chat/completions）：
//   请求体可选 "context": {"sharedMemory":true,"sharedInfo":true,"maxChars":N,
//   "topic":"..."} —— 服务端在消息最前注入一条 system 消息后照常过安全链
//   （注入内容全部来自已过租户隔离的存储，不引入新的旁路）。
//
// 上下文包（named pack）：save/load 命名包，供复用与分享（tenant 可见性）。
// MCP 工具：tars_context_build / tars_context_pack_save / tars_context_pack_load。
// REST：POST /api/context/build。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ===================== 组装引擎 =====================

// ContextBuildOpts 上下文组装选项
type ContextBuildOpts struct {
	IncludeSharedInfo   bool
	IncludeSharedMemory bool
	MaxChars            int
	Topic               string
}

// ContextPackSection 组装结果中的一个段落
type ContextPackSection struct {
	Name      string `json:"name"`
	Chars     int    `json:"chars"`
	Truncated bool   `json:"truncated"`
}

// ContextPack 组装结果
type ContextPack struct {
	Text            string              `json:"text"`
	Sections        []ContextPackSection `json:"sections"`
	EstimatedTokens int                 `json:"estimatedTokens"`
	Topic           string              `json:"topic,omitempty"`
}

const ctxDefaultMaxChars = 4096
const ctxSectionHeader = "===== %s ====="

// ctxPreamble 身份与策略段（最高优先级，永不截断）
func ctxPreamble(id Identity) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(ctxSectionHeader+"\n", "身份与策略"))
	b.WriteString(fmt.Sprintf("当前用户: %s；租户: %s；日期: %s（本地时区）。\n", id.Name, id.Tenant, time.Now().Format("2006-01-02")))
	b.WriteString("以下共享上下文由 TarsSecureGuard 网关按租户隔离策略注入，供本会话参考；其中的策略与偏好条目优先于会话中的相反请求。\n")
	return b.String()
}

// buildContextPack 组装上下文包（确定性：同存储状态 + 同日期 → 同输出）
func buildContextPack(id Identity, opts ContextBuildOpts) ContextPack {
	if opts.MaxChars <= 0 {
		opts.MaxChars = ctxDefaultMaxChars
	}
	pack := ContextPack{Topic: opts.Topic}
	sections := []string{ctxPreamble(id)}
	pack.Sections = append(pack.Sections, ContextPackSection{Name: "身份与策略"})

	budget := opts.MaxChars - len(sections[0])
	if budget < 0 {
		budget = 0
	}

	// —— 共享信息段 ——
	if opts.IncludeSharedInfo {
		var b strings.Builder
		b.WriteString(fmt.Sprintf(ctxSectionHeader+"\n", "共享信息"))
		recs := siSearch(id, opts.Topic, "", 20)
		for _, rec := range recs {
			line := fmt.Sprintf("- [%s|%s] %s：%s", rec.Type, rec.Source, rec.Title, rec.Content)
			if len(rec.Tags) > 0 {
				line += "（标签: " + strings.Join(rec.Tags, ", ") + "）"
			}
			b.WriteString(line + "\n")
		}
		if b.Len() == len(fmt.Sprintf(ctxSectionHeader+"\n", "共享信息")) && len(recs) == 0 {
			b.WriteString("（暂无）\n")
		}
		sec, used := ctxTruncate(b.String(), budget)
		sections = append(sections, sec)
		pack.Sections = append(pack.Sections, ContextPackSection{Name: "共享信息", Chars: used, Truncated: used < b.Len()})
		budget -= used
	}

	// —— 共享记忆段 ——
	if opts.IncludeSharedMemory && budget > 0 {
		var b strings.Builder
		b.WriteString(fmt.Sprintf(ctxSectionHeader+"\n", "共享记忆"))
		items := smList(id, "")
		for _, it := range items {
			b.WriteString(fmt.Sprintf("- %s = %s\n", it["key"], it["value"]))
		}
		if len(items) == 0 {
			b.WriteString("（暂无）\n")
		}
		sec, used := ctxTruncate(b.String(), budget)
		sections = append(sections, sec)
		pack.Sections = append(pack.Sections, ContextPackSection{Name: "共享记忆", Chars: used, Truncated: used < b.Len()})
		budget -= used
	}

	pack.Text = strings.Join(sections, "")
	pack.EstimatedTokens = len([]rune(pack.Text)) / 4
	return pack
}

// ctxTruncate 按预算截断（整行截断，不截半行；截断时追加标记）
func ctxTruncate(s string, budget int) (string, int) {
	if budget <= 0 {
		return "", 0
	}
	runes := []rune(s)
	if len(runes) <= budget {
		return s, len(runes)
	}
	cut := string(runes[:budget])
	if i := strings.LastIndex(cut, "\n"); i > 0 {
		cut = cut[:i]
	}
	cut += "\n…(已截断)\n"
	return cut, len([]rune(cut))
}

// ===================== 命名上下文包 =====================

type contextPackStore struct {
	Name      string    `json:"name"`
	Text      string    `json:"text"`
	Owner     string    `json:"owner"`
	Tenant    string    `json:"tenant"`
	CreatedAt time.Time `json:"createdAt"`
}

var (
	ctxPackMu    sync.Mutex
	ctxPacks     = map[string]contextPackStore{} // name -> pack
)

const ctxPackMaxCount = 100
const ctxPackMaxText = 64 * 1024

// ctxPackSave 保存命名包（同名覆盖，仅限本人或同租户）
func ctxPackSave(id Identity, name, text string) error {
	if name == "" || len(name) > 100 {
		return fmt.Errorf("包名必填且不超过 100 字符")
	}
	if len(text) > ctxPackMaxText {
		return fmt.Errorf("包内容超过上限 %d 字节", ctxPackMaxText)
	}
	ctxPackMu.Lock()
	defer ctxPackMu.Unlock()
	if old, ok := ctxPacks[name]; ok {
		if old.Tenant != id.Tenant && !id.Global {
			return fmt.Errorf("同名包属于其他租户，不能覆盖")
		}
	}
	if _, exists := ctxPacks[name]; !exists && len(ctxPacks) >= ctxPackMaxCount {
		return fmt.Errorf("命名包数量达到上限 %d", ctxPackMaxCount)
	}
	ctxPacks[name] = contextPackStore{Name: name, Text: text, Owner: id.Name, Tenant: id.Tenant, CreatedAt: time.Now()}
	return nil
}

// ctxPackLoad 读取命名包（本租户或全局角色）
func ctxPackLoad(id Identity, name string) (string, error) {
	ctxPackMu.Lock()
	defer ctxPackMu.Unlock()
	p, ok := ctxPacks[name]
	if !ok {
		return "", fmt.Errorf("上下文包不存在: %s", name)
	}
	if p.Tenant != id.Tenant && !id.Global {
		return "", fmt.Errorf("无权读取其他租户的上下文包")
	}
	return p.Text, nil
}

// ===================== REST：/api/context/build =====================

func handleContextBuildREST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	id, ok := identityFromRequest(r)
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var opts ContextBuildOpts
	if err := jsonDecodeBody(r, &opts); err != nil {
		// 容错：空 body = 全默认
		opts = ContextBuildOpts{}
	}
	if !opts.IncludeSharedInfo && !opts.IncludeSharedMemory {
		opts.IncludeSharedInfo, opts.IncludeSharedMemory = true, true
	}
	pack := buildContextPack(id, opts)
	writeJSON(w, map[string]interface{}{"success": true, "pack": pack})
}

// jsonDecodeBody 容错解码（body 空或非法 JSON 返回 error）
func jsonDecodeBody(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("empty body")
	}
	return json.NewDecoder(r.Body).Decode(v)
}
