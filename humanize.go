package main

import (
	"fmt"
	"net/http"
	"strings"
)

// ===================== v4.26.0 错误信息人话化 =====================
//
// 目标：把技术黑话翻译成普通人能看懂的话，让用户知道发生了什么、
// 该怎么办，而不是面对 "rule 5 triggered" 一脸懵。
//
// 设计原则：
// 1. 不说黑话——不用 "WAF"、"CRLF"、"User-Agent" 等技术术语
// 2. 给原因——告诉用户 "为什么" 被拦
// 3. 给办法——告诉用户 "接下来怎么做"
// 4. 中英双语——默认中文，英文兜底

// HumanError 人话错误结构
type HumanError struct {
	Code       string `json:"code"`       // 机器可读错误码（如 WAF_PATH_TRAVERSAL）
	Message    string `json:"message"`    // 原始技术消息（向后兼容）
	Human      string `json:"human"`      // 人话说明（按用户语言）
	Suggestion string `json:"suggestion"` // 建议操作
}

// errMap 错误码 → 人话映射（中英双语）
var errMap = map[string]struct {
	Zh        string // 中文人话
	En        string // 英文人话
	ZhSuggest string // 中文建议
	EnSuggest string // 英文建议
}{
	// ===== WAF 拦截（14 条）=====
	"WAF_PATH_TRAVERSAL": {
		Zh:        "你输入的内容里包含危险的路径穿越尝试（比如 ../），系统已自动拦截。",
		En:        "Your input contains a dangerous path traversal attempt (e.g., ../) and has been blocked.",
		ZhSuggest: "请删除输入中的 '../' 或 '..' 等路径跳跃字符后重试。",
		EnSuggest: "Please remove '../' or '..' path-jumping characters and try again.",
	},
	"WAF_COMMAND_INJECTION": {
		Zh:        "你输入的内容看起来像命令注入攻击（比如包含 ;cmd 或 &&bash），系统已拦截。",
		En:        "Your input looks like a command injection attack (e.g., ;cmd or &&bash) and has been blocked.",
		ZhSuggest: "请删除输入中的命令连接符（;、&&、反引号）后重试。",
		EnSuggest: "Please remove command connectors (;, &&, backticks) and try again.",
	},
	"WAF_SQL_INJECTION": {
		Zh:        "你输入的内容包含 SQL 注入特征（比如 UNION SELECT），系统已拦截以保护数据安全。",
		En:        "Your input contains SQL injection patterns (e.g., UNION SELECT) and has been blocked to protect data safety.",
		ZhSuggest: "如果你是在正常提问，请换用更口语化的表达方式，避免使用数据库关键词。",
		EnSuggest: "If you're asking a normal question, please rephrase in everyday language without database keywords.",
	},
	"WAF_XSS": {
		Zh:        "你输入的内容包含网页脚本攻击特征（比如 <script>），系统已拦截。",
		En:        "Your input contains cross-site scripting (XSS) patterns (e.g., <script>) and has been blocked.",
		ZhSuggest: "请删除 HTML 标签或 JavaScript 代码后重试。",
		EnSuggest: "Please remove HTML tags or JavaScript code and try again.",
	},
	"WAF_PROMPT_INJECTION": {
		Zh:        "你输入的内容试图篡改 AI 的行为指令（比如 \"忽略之前的规则\"），系统已拦截。",
		En:        "Your input attempts to override AI behavior instructions (e.g., 'ignore previous rules') and has been blocked.",
		ZhSuggest: "请不要尝试让 AI 忽略安全规则或扮演其他角色，直接提出你的正常需求即可。",
		EnSuggest: "Please don't try to make the AI ignore safety rules; just ask your question directly.",
	},
	"WAF_PII_LEAK": {
		Zh:        "你输入的内容包含敏感个人信息（如身份证号、银行卡号、手机号），系统已拦截以防泄露。",
		En:        "Your input contains sensitive personal information (ID, bank card, phone) and has been blocked to prevent leakage.",
		ZhSuggest: "如需使用请对敏感信息做脱敏处理（如把手机号中间四位换成 ****）。",
		EnSuggest: "If needed, please mask sensitive info (e.g., replace middle digits of phone with ****).",
	},
	"WAF_RATE_LIMIT": {
		Zh:        "你的请求太频繁了，系统暂时限制了访问。",
		En:        "Your requests are too frequent; access has been temporarily limited.",
		ZhSuggest: "请稍等 1 分钟后再试，或降低操作频率。",
		EnSuggest: "Please wait a minute and try again, or reduce your request frequency.",
	},
	"WAF_BAD_METHOD": {
		Zh:        "你使用了系统不支持的请求方式（如 TRACE、CONNECT），请求被拒绝。",
		En:        "You used an unsupported HTTP method (e.g., TRACE, CONNECT); the request was rejected.",
		ZhSuggest: "请使用 GET 或 POST 等标准方式访问。",
		EnSuggest: "Please use standard methods like GET or POST.",
	},
	"WAF_SCANNER_UA": {
		Zh:        "你的请求来源被识别为自动化扫描工具，已被拦截。",
		En:        "Your request was identified as coming from an automated scanning tool and has been blocked.",
		ZhSuggest: "如果你不是扫描工具，请使用常规浏览器访问。",
		EnSuggest: "If you are not a scanner, please use a regular browser.",
	},
	"WAF_SENSITIVE_PATH": {
		Zh:        "你访问的路径属于敏感系统路径（如 .env、.git），系统已拦截。",
		En:        "The path you accessed is a sensitive system path (e.g., .env, .git) and has been blocked.",
		ZhSuggest: "请通过正常的管理面板操作，不要直接访问系统内部路径。",
		EnSuggest: "Please use the normal admin panel; don't directly access internal system paths.",
	},
	"WAF_HOST_INJECTION": {
		Zh:        "请求中的主机地址包含非法字符，系统已拦截。",
		En:        "The host address in your request contains illegal characters and has been blocked.",
		ZhSuggest: "请检查访问地址是否正确，不要使用包含换行符的 URL。",
		EnSuggest: "Please check that the URL is correct and doesn't contain newline characters.",
	},
	"WAF_HEADER_INJECTION": {
		Zh:        "请求头中包含非法字符（如换行符），系统已拦截。",
		En:        "Your request headers contain illegal characters (e.g., newlines) and have been blocked.",
		ZhSuggest: "请检查请求头内容，确保不包含特殊控制字符。",
		EnSuggest: "Please check your request headers and ensure no special control characters are present.",
	},
	"WAF_REQUEST_SMUGGLING": {
		Zh:        "请求格式存在安全风险（同时包含 Content-Length 和 Transfer-Encoding），系统已拦截。",
		En:        "Your request format has a security risk (both Content-Length and Transfer-Encoding present) and has been blocked.",
		ZhSuggest: "请检查客户端或代理配置，确保不混用两种长度声明。",
		EnSuggest: "Please check your client or proxy config to avoid mixing both length declarations.",
	},
	"WAF_BODY_TOO_LARGE": {
		Zh:        "你发送的内容太大了，超过了系统允许的最大大小。",
		En:        "Your content is too large and exceeds the maximum allowed size.",
		ZhSuggest: "请缩小内容体积后重试，或分批发送。",
		EnSuggest: "Please reduce the content size or send it in batches.",
	},

	// ===== 权限与配额（4 条）=====
	"AUTH_FORBIDDEN": {
		Zh:        "你没有权限执行这个操作。",
		En:        "You don't have permission to perform this action.",
		ZhSuggest: "请联系管理员确认你的账号权限，或登录更高权限的账号。",
		EnSuggest: "Please contact an admin to confirm your account permissions or log in with a higher-privilege account.",
	},
	"AUTH_ROLE_REQUIRED": {
		Zh:        "你的账号角色不满足此操作的要求。",
		En:        "Your account role does not meet the requirements for this action.",
		ZhSuggest: "请联系管理员升级你的角色权限。",
		EnSuggest: "Please contact an admin to upgrade your role.",
	},
	"QUOTA_EXCEEDED": {
		Zh:        "你的使用配额已用完，暂时无法继续操作。",
		En:        "Your usage quota has been exhausted; you cannot continue for now.",
		ZhSuggest: "请等待配额重置（通常每小时/每天自动恢复），或联系管理员提升配额。",
		EnSuggest: "Please wait for quota reset (usually hourly/daily) or contact an admin to increase it.",
	},
	"ORIGIN_NOT_ALLOWED": {
		Zh:        "你的访问来源（域名或IP）不在系统白名单中。",
		En:        "Your access origin (domain or IP) is not on the system whitelist.",
		ZhSuggest: "请从允许的地址访问，或联系管理员将你的来源加入白名单。",
		EnSuggest: "Please access from an allowed address or ask an admin to add your origin to the whitelist.",
	},

	// ===== 请求格式错误（5 条）=====
	"REQ_POST_ONLY": {
		Zh:        "这个接口只接受 POST 请求，你用了别的方式。",
		En:        "This endpoint only accepts POST requests; you used a different method.",
		ZhSuggest: "请将请求方法改为 POST 后重试。",
		EnSuggest: "Please change your request method to POST and try again.",
	},
	"REQ_INVALID_JSON": {
		Zh:        "请求内容不是有效的 JSON 格式，系统无法解析。",
		En:        "The request body is not valid JSON and cannot be parsed.",
		ZhSuggest: "请检查请求体格式，确保是合法的 JSON（注意引号、逗号、括号配对）。",
		EnSuggest: "Please check your request body format and ensure valid JSON (quotes, commas, brackets).",
	},
	"REQ_SERVER_NOT_FOUND": {
		Zh:        "找不到对应的服务器或资源。",
		En:        "The requested server or resource was not found.",
		ZhSuggest: "请检查请求路径或资源ID是否正确。",
		EnSuggest: "Please check that the request path or resource ID is correct.",
	},
	"REQ_INTERNAL_ERROR": {
		Zh:        "系统内部出了点小问题，但已经自动恢复并记录了日志。",
		En:        "An internal error occurred, but the system has automatically recovered and logged the issue.",
		ZhSuggest: "请稍等片刻后重试，如果持续出现请反馈给管理员。",
		EnSuggest: "Please try again in a moment; if it persists, report it to an admin.",
	},

	// ===== 语义安全（3 条）=====
	"SEMANTIC_BLOCKED": {
		Zh:        "AI 安全护栏判定你的内容存在风险，已自动拦截。",
		En:        "The AI safety guard determined your content poses a risk and has automatically blocked it.",
		ZhSuggest: "请调整措辞，避免涉及敏感或不当内容后重试。",
		EnSuggest: "Please rephrase to avoid sensitive or inappropriate content and try again.",
	},
	"SEMANTIC_ENGINE_UNAVAILABLE": {
		Zh:        "AI 安全引擎暂时不可用，系统按最严格策略处理了请求。",
		En:        "The AI safety engine is temporarily unavailable; the request was handled with the strictest policy.",
		ZhSuggest: "请稍后重试，或联系管理员检查引擎状态。",
		EnSuggest: "Please try again later or contact an admin to check the engine status.",
	},

	// ===== 网关通用（2 条）=====
	"GATEWAY_TIMEOUT": {
		Zh:        "后端响应超时，请求未能及时完成。",
		En:        "The backend response timed out; the request could not complete in time.",
		ZhSuggest: "请稍后重试，如果频繁出现请检查网络或后端服务状态。",
		EnSuggest: "Please try again later; if frequent, check network or backend service status.",
	},
	"GATEWAY_UNREACHABLE": {
		Zh:        "目标服务暂时无法连接，可能是重启或维护中。",
		En:        "The target service is temporarily unreachable; it may be restarting or under maintenance.",
		ZhSuggest: "请稍后重试，或确认目标服务是否正常运行。",
		EnSuggest: "Please try again later or confirm the target service is running.",
	},
}

// detectLang 从请求头或默认配置判断用户语言
func detectLang(r *http.Request) string {
	// 优先 Accept-Language
	al := r.Header.Get("Accept-Language")
	if strings.Contains(al, "zh") {
		return "zh"
	}
	if strings.Contains(al, "en") {
		return "en"
	}
	// 其次看 Cookie
	if c, _ := r.Cookie("tsg_lang"); c != nil {
		if strings.HasPrefix(c.Value, "zh") {
			return "zh"
		}
		return "en"
	}
	return "zh" // 默认中文
}

// humanize 将错误码翻译为人话
func humanize(code string, lang string) (human, suggestion string) {
	m, ok := errMap[code]
	if !ok {
		return "", ""
	}
	if lang == "en" {
		return m.En, m.EnSuggest
	}
	return m.Zh, m.ZhSuggest
}

// classifyError 根据原始错误消息推断错误码
func classifyError(msg string) string {
	msg = strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "路径穿越"):
		return "WAF_PATH_TRAVERSAL"
	case strings.Contains(msg, "命令注入"):
		return "WAF_COMMAND_INJECTION"
	case strings.Contains(msg, "sql 注入"):
		return "WAF_SQL_INJECTION"
	case strings.Contains(msg, "xss"):
		return "WAF_XSS"
	case strings.Contains(msg, "promptinjection"):
		return "WAF_PROMPT_INJECTION"
	case strings.Contains(msg, "pii泄漏") || strings.Contains(msg, "pii"):
		return "WAF_PII_LEAK"
	case strings.Contains(msg, "请求频率超限") || strings.Contains(msg, "rate limit"):
		return "WAF_RATE_LIMIT"
	case strings.Contains(msg, "异常 http 方法"):
		return "WAF_BAD_METHOD"
	case strings.Contains(msg, "扫描器 user-agent"):
		return "WAF_SCANNER_UA"
	case strings.Contains(msg, "敏感路径探测"):
		return "WAF_SENSITIVE_PATH"
	case strings.Contains(msg, "host 头注入"):
		return "WAF_HOST_INJECTION"
	case strings.Contains(msg, "请求头 crlf") || strings.Contains(msg, "请求头 null"):
		return "WAF_HEADER_INJECTION"
	case strings.Contains(msg, "http 请求走私") || strings.Contains(msg, "cl+te"):
		return "WAF_REQUEST_SMUGGLING"
	case strings.Contains(msg, "请求体过大"):
		return "WAF_BODY_TOO_LARGE"
	case strings.Contains(msg, "权限不足") && strings.Contains(msg, "需要"):
		return "AUTH_ROLE_REQUIRED"
	case strings.Contains(msg, "权限不足"):
		return "AUTH_FORBIDDEN"
	case strings.Contains(msg, "配额超限"):
		return "QUOTA_EXCEEDED"
	case strings.Contains(msg, "origin not allowed"):
		return "ORIGIN_NOT_ALLOWED"
	case strings.Contains(msg, "post only"):
		return "REQ_POST_ONLY"
	case strings.Contains(msg, "invalid json"):
		return "REQ_INVALID_JSON"
	case strings.Contains(msg, "server not found"):
		return "REQ_SERVER_NOT_FOUND"
	case strings.Contains(msg, "internal error"):
		return "REQ_INTERNAL_ERROR"
	case strings.Contains(msg, "内容被安全护栏拦截"):
		return "SEMANTIC_BLOCKED"
	case strings.Contains(msg, "semantic_engine_unavailable"):
		return "SEMANTIC_ENGINE_UNAVAILABLE"
	default:
		return ""
	}
}

// writeHumanizedJSONStatus 返回带人话解释的错误 JSON
func writeHumanizedJSONStatus(w http.ResponseWriter, r *http.Request, code int, data map[string]string) {
	lang := detectLang(r)
	if msg, ok := data["error"]; ok && msg != "" {
		if ec := classifyError(msg); ec != "" {
			data["code"] = ec
			if h, s := humanize(ec, lang); h != "" {
				data["human"] = h
				data["suggestion"] = s
			}
		}
	}
	writeJSONStatus(w, code, data)
}

// wafBlockHumanized WAF 拦截统一入口（替代原 blockRequest 中的 writeJSONStatus）
func wafBlockHumanized(w http.ResponseWriter, r *http.Request, reason string) {
	lang := detectLang(r)
	ec := classifyError(reason)
	if ec == "" {
		ec = "WAF_UNKNOWN"
	}
	data := map[string]string{
		"error": fmt.Sprintf("blocked by WAF: %s", reason),
	}
	if h, s := humanize(ec, lang); h != "" {
		data["code"] = ec
		data["human"] = h
		data["suggestion"] = s
	}
	writeJSONStatus(w, http.StatusForbidden, data)
}
