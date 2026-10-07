package main

// v3.7.0 扩展器 / 一键配置器（Extender）
//
// 定位转变的落地：TSG 不只是"AI 网关"，更是「AI 工具的配置层」——
// 别的 AI 编码/对话工具环境配置复杂，而 TSG 恰好有环境探测能力。
// 本模块探测本机已安装的主流 AI 工具（OpenClaw / Continue / Aider /
// Cline / ZooCode / Roo Code / Codex CLI），并生成把该工具接入
// TSG OpenAI 兼容端点（http://127.0.0.1:<port>/v1）的配置片段。
//
// 设计原则（与调研结论一致）：
//  - 纯配置级对接：只生成配置片段，不写入第三方工具的配置文件，
//    不 vendor 任何第三方代码（保持零外部依赖铁律）；
//  - 探测只读：LookPath + 目录/文件存在性检查，绝不执行第三方二进制；
//  - 密钥安全：片段默认用占位符；仅当请求显式 includeKey=true 时才
//    内嵌真实网关密钥，并写审计日志。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// extDecodeJSONBody 统一 JSON body 解析
func extDecodeJSONBody(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// extenderSnippet 一份可直接复制粘贴的接入配置片段
type extenderSnippet struct {
	Lang  string `json:"lang"`  // 片段语言（json / json5 / yaml / toml / text）
	File  string `json:"file"`  // 片段应粘贴到的目标文件（示意路径，可为空）
	Code  string `json:"code"`  // 片段正文
	Steps string `json:"steps"` // 操作步骤说明（纯文本）
}

// extenderTarget 一个可探测、可生成接入配置的第三方 AI 工具
type extenderTarget struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`     // agent / editor-plugin / cli
	License  string `json:"license"`  // 上游协议（全部为 MIT/Apache 兼容，无 GPL 污染）
	Homepage string `json:"homepage"`
	Desc     string `json:"desc"`
	// Status: ok = 可正常对接；warn = 已检测但上游已停摆等需要提示的情况
	Status string `json:"status"` // ok / warn
	Note   string `json:"note,omitempty"`

	installed bool
	detect    func() (bool, string)
	snippet   func(baseURL, key, model string) extenderSnippet
}

// extenderBaseURL TSG 对外暴露的 OpenAI 兼容端点基址
func extenderBaseURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/v1", port)
}

// extenderDefaultKeySnippet 片段默认密钥占位符
const extenderDefaultKeySnippet = "YOUR_TSG_API_KEY"

// extenderDefaultModel 片段示例模型（本地默认档，用户可替换）
const extenderDefaultModel = "qwen2.5-3b"

// ---------- 探测辅助（全部只读，不执行任何第三方二进制） ----------

func extHome() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

func extLookPath(bin string) (bool, string) {
	p, err := exec.LookPath(bin)
	if err != nil || p == "" {
		return false, ""
	}
	return true, "可执行文件: " + p
}

// extVSCodeExtDir 在 VS Code / Cursor 的扩展目录中查找匹配 glob 的扩展
func extVSCodeExtDir(pattern string) (bool, string) {
	home := extHome()
	if home == "" {
		return false, ""
	}
	for _, base := range []string{".vscode/extensions", ".cursor/extensions"} {
		matches, _ := filepath.Glob(filepath.Join(home, base, pattern))
		if len(matches) > 0 {
			return true, "已安装扩展: " + matches[0]
		}
	}
	return false, ""
}

func extPathExists(p string) (bool, string) {
	if p == "" {
		return false, ""
	}
	if _, err := os.Stat(p); err == nil {
		return true, "找到配置: " + p
	}
	return false, ""
}

// ---------- 目标注册表 ----------

func extenderTargets() []*extenderTarget {
	home := extHome()
	return []*extenderTarget{
		{
			ID: "openclaw", Name: "OpenClaw", Kind: "agent",
			License: "MIT", Homepage: "https://openclaw.ai",
			Desc:   "开源个人 AI 助手框架（原 Clawdbot/Moltbot），provider 面支持 openai-compatible 网关，是配置级对接的首选目标。",
			Status: "ok",
			detect: func() (bool, string) {
				if ok, d := extLookPath("openclaw"); ok {
					return true, d
				}
				if home != "" {
					return extPathExists(filepath.Join(home, ".openclaw", "openclaw.json"))
				}
				return false, ""
			},
			snippet: func(baseURL, key, model string) extenderSnippet {
				code := `{
  providers: {
    "tars-guard": {
      npm: "@ai-sdk/openai-compatible",
      options: {
        baseURL: "` + baseURL + `",
        apiKey: "` + key + `"
      }
    }
  },
  agents: {
    defaults: {
      model: { primary: "tars-guard/` + model + `" }
    }
  }
}`
				return extenderSnippet{
					Lang: "json5", File: "~/.openclaw/openclaw.json",
					Code: code,
					Steps: "将片段合并进 ~/.openclaw/openclaw.json（JSON5，保留既有字段）；providers 与 agents.defaults.model 同级。若已有 providers，只需追加 tars-guard 一项。",
				}
			},
		},
		{
			ID: "continue", Name: "Continue", Kind: "editor-plugin",
			License: "Apache 2.0", Homepage: "https://continue.dev",
			Desc:   "VS Code / JetBrains 开源 AI 编码助手，config.json 原生支持 openai provider 自定义 apiBase。",
			Status: "ok",
			detect: func() (bool, string) {
				if home == "" {
					return false, ""
				}
				return extPathExists(filepath.Join(home, ".continue"))
			},
			snippet: func(baseURL, key, model string) extenderSnippet {
				code := `{
  "models": [
    {
      "title": "TSG Local",
      "provider": "openai",
      "model": "` + model + `",
      "apiBase": "` + baseURL + `",
      "apiKey": "` + key + `"
    }
  ]
}`
				return extenderSnippet{
					Lang: "json", File: "~/.continue/config.json",
					Code: code,
					Steps: "将 models 数组合并进 ~/.continue/config.json（保留既有模型条目）；保存后 Continue 面板即可选择「TSG Local」。",
				}
			},
		},
		{
			ID: "aider", Name: "Aider", Kind: "cli",
			License: "Apache 2.0", Homepage: "https://aider.chat",
			Desc:   "终端 AI 结对编程工具，litellm 风格的 openai/ 前缀模型名 + openai-api-base 即可指向任意网关。",
			Status: "ok",
			detect: func() (bool, string) {
				return extLookPath("aider")
			},
			snippet: func(baseURL, key, model string) extenderSnippet {
				code := `model: openai/` + model + `
openai-api-base: ` + baseURL + `
api-key: openai=` + key + "\n"
				return extenderSnippet{
					Lang: "yaml", File: ".aider.conf.yml（项目根目录）",
					Code: code,
					Steps: "将片段写入项目根目录 .aider.conf.yml（或合并进已有文件）；也可用命令行等效参数 aider --model openai/" + model + " --openai-api-base " + baseURL,
				}
			},
		},
		{
			ID: "cline", Name: "Cline", Kind: "editor-plugin",
			License: "Apache 2.0", Homepage: "https://cline.bot",
			Desc:   "VS Code 自主编码插件；provider 配置在插件面板内（OpenAI Compatible），按步骤填三项即可接入。",
			Status: "ok",
			detect: func() (bool, string) {
				return extVSCodeExtDir("cline.cline-*")
			},
			snippet: func(baseURL, key, model string) extenderSnippet {
				code := "Provider: OpenAI Compatible\nBase URL: " + baseURL + "\nAPI Key: " + key + "\nModel ID: " + model
				return extenderSnippet{
					Lang: "text", File: "Cline 插件设置（VS Code 内）",
					Code: code,
					Steps: "VS Code → Cline 插件 → 设置图标 → API Provider 选「OpenAI Compatible」，依次粘贴 Base URL / API Key / Model ID。",
				}
			},
		},
		{
			ID: "zoocode", Name: "ZooCode", Kind: "editor-plugin",
			License: "Apache 2.0", Homepage: "https://github.com/zoo-code/zoo-code",
			Desc:   "Roo Code 停摆后的社区接棒 fork，配置面与 Roo 同源（OpenAI Compatible provider）。",
			Status: "ok",
			detect: func() (bool, string) {
				return extVSCodeExtDir("*zoocode*")
			},
			snippet: func(baseURL, key, model string) extenderSnippet {
				code := "Provider: OpenAI Compatible\nBase URL: " + baseURL + "\nAPI Key: " + key + "\nModel ID: " + model
				return extenderSnippet{
					Lang: "text", File: "ZooCode 插件设置（VS Code 内）",
					Code: code,
					Steps: "VS Code → ZooCode → Settings → API Provider 选「OpenAI Compatible」，粘贴 Base URL / API Key / Model ID。",
				}
			},
		},
		{
			ID: "roocode", Name: "Roo Code（已停摆）", Kind: "editor-plugin",
			License: "Apache 2.0", Homepage: "https://github.com/RooCodeInc/Roo-Code",
			Desc:   "曾为主流 VS Code 自主编码插件；上游自 2026-05 起停止维护，社区已迁移至 ZooCode。",
			Status: "warn",
			Note:   "上游已停摆（2026-05），建议迁移到社区接棒 fork ZooCode；仍可按同款步骤接入 TSG。",
			detect: func() (bool, string) {
				return extVSCodeExtDir("*roo-cline*")
			},
			snippet: func(baseURL, key, model string) extenderSnippet {
				code := "Provider: OpenAI Compatible\nBase URL: " + baseURL + "\nAPI Key: " + key + "\nModel ID: " + model
				return extenderSnippet{
					Lang: "text", File: "Roo Code 插件设置（VS Code 内）",
					Code: code,
					Steps: "VS Code → Roo Code → Settings → API Provider 选「OpenAI Compatible」，粘贴 Base URL / API Key / Model ID。建议尽快迁移 ZooCode。",
				}
			},
		},
		{
			ID: "codex", Name: "Codex CLI", Kind: "cli",
			License: "Apache 2.0", Homepage: "https://github.com/openai/codex",
			Desc:   "OpenAI 开源终端编码 agent；config.toml 的 model_providers 支持自定义 openai-compatible 端点。",
			Status: "ok",
			detect: func() (bool, string) {
				if ok, d := extLookPath("codex"); ok {
					return true, d
				}
				if home != "" {
					return extPathExists(filepath.Join(home, ".codex"))
				}
				return false, ""
			},
			snippet: func(baseURL, key, model string) extenderSnippet {
				code := `[model_providers.tars-guard]
name = "TarsSecureGuard"
base_url = "` + baseURL + `"
env_key = "TSG_API_KEY"
wire_api = "chat"

model = "` + model + `"
model_provider = "tars-guard"`
				return extenderSnippet{
					Lang: "toml", File: "~/.codex/config.toml",
					Code: code,
					Steps: "将片段合并进 ~/.codex/config.toml；env_key 指定的环境变量需在 shell 中 export TSG_API_KEY=" + key + "（密钥不建议写入文件）。",
				}
			},
		},
	}
}

// ---------- HTTP handlers ----------

// handleV37Extender GET: 探测全部目标 + 端点信息
func handleV37Extender(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		targets := extenderTargets()
		out := make([]map[string]interface{}, 0, len(targets))
		installed := 0
		for _, t := range targets {
			ok, detail := t.detect()
			if ok {
				installed++
			}
			out = append(out, map[string]interface{}{
				"id": t.ID, "name": t.Name, "kind": t.Kind,
				"license": t.License, "homepage": t.Homepage, "desc": t.Desc,
				"status": t.Status, "note": t.Note,
				"installed": ok, "detail": detail,
			})
		}
		writeJSON(w, map[string]interface{}{
			"version":    version,
			"module":     "extender",
			"baseUrl":    extenderBaseURL(),
			"model":      extenderDefaultModel,
			"chatApiOn":  moduleEnabledByID("chatApi"),
			"installed":  installed,
			"total":      len(targets),
			"targets":    out,
			"keyMasked":  "YOUR_TSG_API_KEY（生成片段时可勾选内嵌真实密钥）",
		})
	case http.MethodPost:
		var req struct {
			Target     string `json:"target"`
			IncludeKey bool   `json:"includeKey"`
			Model      string `json:"model,omitempty"`
		}
		if err := extDecodeJSONBody(r, &req); err != nil || req.Target == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "需要 {target, includeKey}"})
			return
		}
		var tgt *extenderTarget
		for _, t := range extenderTargets() {
			if t.ID == req.Target {
				tgt = t
				break
			}
		}
		if tgt == nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "未知目标: " + req.Target})
			return
		}
		key := extenderDefaultKeySnippet
		if req.IncludeKey {
			key = gatewayAPIKey()
			auditLog("EXTENDER_KEY", userFromRequestSafe(r), fmt.Sprintf("为 %s 生成含真实网关密钥的接入片段", tgt.Name))
		}
		model := req.Model
		if model == "" {
			model = extenderDefaultModel
		}
		writeJSON(w, map[string]interface{}{
			"version":     version,
			"target":      tgt.ID,
			"name":        tgt.Name,
			"snippet":     tgt.snippet(extenderBaseURL(), key, model),
			"keyEmbedded": req.IncludeKey,
		})
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// extenderInstalledSummary 供 dashboard / README 之外的信息输出复用
func extenderInstalledSummary() string {
	var names []string
	for _, t := range extenderTargets() {
		if ok, _ := t.detect(); ok {
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, "、")
}
