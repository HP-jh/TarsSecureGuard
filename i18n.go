package main

// ===================== v4.7.0 多语言兜底（i18n）=====================
//
// 目标：即使未安装语言包，也能运行最基础功能，错误消息可理解。
// 策略：内置 zh（中文，默认）+ en（英文）两语言包；请求带 Accept-Language
// 时自动匹配，无匹配则回退中文。前端 humanErrMsg 同步扩展多语言。

import (
	"net/http"
	"strings"
	"sync"
)

// 内置语言包（仅覆盖高频错误与 UI 标签，不全量翻译）
var builtinMessages = map[string]map[string]string{
	"zh": {
		// 错误类
		"err.unauthorized":       "未授权：需要有效的 API Key 或登录会话",
		"err.forbidden":          "没有权限做这个操作（当前密钥的角色不够）",
		"err.notfound":           "接口不存在——网关和页面版本可能不匹配，试试重启网关",
		"err.ratelimit":          "操作太快啦，稍等几秒再试",
		"err.internal":           "网关内部出了点问题，请稍后重试或查看日志",
		"err.badrequest":         "请求参数有误，请检查后再试",
		"err.shutdown.denied":    "当前未以管理员身份运行，无法直接关闭进程。请从前端设置页点击「关闭网关」",
		"err.shutdown.adminonly": "关闭网关需要管理员权限",
		// UI 标签
		"ui.status.running":      "运行中",
		"ui.status.stopped":      "已停止",
		"ui.btn.shutdown":        "关闭网关",
		"ui.lang.zh":             "中文",
		"ui.lang.en":             "English",
		"ui.avcompat.title":      "安全软件兼容",
		"ui.avcompat.ok":         "未发现冲突",
		"ui.avcompat.warn":       "检测到安全软件，已尝试自动兼容",
		// 审计/系统
		"sys.startup":            "TarsSecureGuard 已启动",
		"sys.shutdown":           "TarsSecureGuard 已关闭",
		"sys.sigblocked":         "收到关闭信号，但因非管理员运行已拦截（防自关保护）",
	},
	"en": {
		"err.unauthorized":       "Unauthorized: valid API Key or session required",
		"err.forbidden":          "Permission denied (insufficient role for this key)",
		"err.notfound":           "Endpoint not found — gateway and page versions may mismatch, try restarting",
		"err.ratelimit":          "Too many requests, please wait a few seconds",
		"err.internal":           "Internal gateway error, please retry later or check logs",
		"err.badrequest":         "Bad request, please check your input",
		"err.shutdown.denied":    "Not running as administrator. Please use the 'Shutdown Gateway' button in Settings.",
		"err.shutdown.adminonly": "Shutting down the gateway requires administrator privileges",
		"ui.status.running":      "Running",
		"ui.status.stopped":      "Stopped",
		"ui.btn.shutdown":        "Shutdown Gateway",
		"ui.lang.zh":             "中文",
		"ui.lang.en":             "English",
		"ui.avcompat.title":      "Security Software Compatibility",
		"ui.avcompat.ok":         "No conflicts detected",
		"ui.avcompat.warn":       "Security software detected, auto-compatibility attempted",
		"sys.startup":            "TarsSecureGuard started",
		"sys.shutdown":           "TarsSecureGuard shut down",
		"sys.sigblocked":         "Shutdown signal intercepted (self-protection active, not admin)",
	},
}

var (
	i18nMu       sync.RWMutex
	i18nFallback = "zh"
)

// pickLang 根据 Accept-Language 头选择最佳匹配语言
func pickLang(r *http.Request) string {
	al := r.Header.Get("Accept-Language")
	if al == "" {
		return i18nFallback
	}
	// 简单前缀匹配：zh-CN, zh-TW → zh；en-US, en-GB → en
	al = strings.ToLower(al)
	for tag := range builtinMessages {
		if strings.Contains(al, tag) {
			return tag
		}
	}
	return i18nFallback
}

// i18nT 翻译一条消息；lang 为空时使用 fallback
func i18nT(lang, key string) string {
	if lang == "" {
		lang = i18nFallback
	}
	i18nMu.RLock()
	m, ok := builtinMessages[lang]
	if !ok {
		m = builtinMessages[i18nFallback]
	}
	v := m[key]
	i18nMu.RUnlock()
	if v == "" {
		// 兜底：返回 key 本身，确保调用方永远拿到非空字符串
		return key
	}
	return v
}

// i18nTReq 从请求自动提取语言并翻译
func i18nTReq(r *http.Request, key string) string {
	return i18nT(pickLang(r), key)
}

// i18nErrorJSON 返回带翻译错误消息的 JSON（供 handler 使用）
func i18nErrorJSON(w http.ResponseWriter, r *http.Request, code int, key string) {
	writeJSONStatus(w, code, map[string]string{
		"error": i18nTReq(r, key),
		"key":   key,
		"lang":  pickLang(r),
	})
}

// i18nRegister 允许运行时扩展语言包（热插拔语言包入口）
func i18nRegister(lang string, msgs map[string]string) {
	i18nMu.Lock()
	defer i18nMu.Unlock()
	if builtinMessages[lang] == nil {
		builtinMessages[lang] = map[string]string{}
	}
	for k, v := range msgs {
		builtinMessages[lang][k] = v
	}
}

// i18nListLanguages 返回当前支持的语言列表
func i18nListLanguages() []string {
	i18nMu.RLock()
	defer i18nMu.RUnlock()
	var out []string
	for k := range builtinMessages {
		out = append(out, k)
	}
	return out
}
