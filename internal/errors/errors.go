// Package errors 提供统一的错误类型和错误处理（参考阿里巴巴错误治理规范）
//
// 解决的问题：
//   - 当前代码混用 fmt.Errorf / logMsg / auditLog，错误类型不统一
//   - 缺乏结构化的错误码，前端难以精确处理
//   - 错误信息国际化困难
//
// 设计原则：
//   - 每个错误有唯一的 ErrorCode（便于日志检索和前端匹配）
//   - 错误分为内部错误（InternalError）和用户可见错误（UserError）
//   - 支持 i18n：错误码 + 参数 → 多语言消息
//   - 与审计日志集成：Error.Audit() 自动落审计

package errors

import (
	"fmt"
	"net/http"
)

// ErrorCode 标准化错误码
type ErrorCode string

// 错误码常量（按模块分组，便于检索）
const (
	// 认证与授权
	ErrUnauthorized   ErrorCode = "AUTH_001"
	ErrForbidden      ErrorCode = "AUTH_002"
	ErrQuotaExceeded  ErrorCode = "AUTH_003"
	ErrTokenExpired   ErrorCode = "AUTH_004"

	// 安全防护
	ErrWAFBlocked     ErrorCode = "SEC_001"
	ErrSemanticBlock  ErrorCode = "SEC_002"
	ErrIPBanned       ErrorCode = "SEC_003"
	ErrRateLimited    ErrorCode = "SEC_004"
	ErrSSRFBlocked    ErrorCode = "SEC_005"
	ErrPIIDetected    ErrorCode = "SEC_006"

	// 路由与后端
	ErrNoBackend      ErrorCode = "RT_001"
	ErrBackendDown    ErrorCode = "RT_002"
	ErrCircuitOpen    ErrorCode = "RT_003"
	ErrTimeout        ErrorCode = "RT_004"

	// 模块系统
	ErrModuleDisabled ErrorCode = "MOD_001"
	ErrModuleDep      ErrorCode = "MOD_002"

	// 配置
	ErrConfigInvalid  ErrorCode = "CFG_001"
	ErrConfigLocked   ErrorCode = "CFG_002"

	// 通用
	ErrInternal       ErrorCode = "INT_001"
	ErrBadRequest     ErrorCode = "INT_002"
	ErrNotFound       ErrorCode = "INT_003"
)

// TSGError 统一错误结构
type TSGError struct {
	Code    ErrorCode      `json:"code"`
	HTTP    int            `json:"httpStatus"`
	Message string         `json:"message"`    // 默认消息（中文）
	Detail  string         `json:"detail,omitempty"` // 详细上下文
	Cause   error          `json:"-"`          // 原始错误（不序列化）
	Audit   bool           `json:"-"`          // 是否需要审计
}

func (e *TSGError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *TSGError) Unwrap() error { return e.Cause }

// New 创建新错误
func New(code ErrorCode, httpStatus int, message string) *TSGError {
	return &TSGError{
		Code:    code,
		HTTP:    httpStatus,
		Message: message,
		Audit:   httpStatus >= 500, // 5xx 默认审计
	}
}

// WithDetail 添加详细信息
func (e *TSGError) WithDetail(detail string) *TSGError {
	cp := *e
	cp.Detail = detail
	return &cp
}

// WithCause 包装原始错误
func (e *TSGError) WithCause(cause error) *TSGError {
	cp := *e
	cp.Cause = cause
	return &cp
}

// WithAudit 标记需要审计
func (e *TSGError) WithAudit() *TSGError {
	cp := *e
	cp.Audit = true
	return &cp
}

// JSON 返回可序列化的错误响应（前端友好）
func (e *TSGError) JSON() map[string]interface{} {
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    string(e.Code),
			"message": e.Message,
		},
	}
	if e.Detail != "" {
		resp["error"].(map[string]interface{})["detail"] = e.Detail
	}
	// v4.7.4 小白化：hint 字段告诉用户怎么做
	resp["hint"] = hintForCode(e.Code)
	return resp
}

// hintForCode 根据错误码返回用户友好的提示
func hintForCode(code ErrorCode) string {
	switch code {
	case ErrUnauthorized:
		return "请检查 API Key 是否正确，可在设置中重新配置"
	case ErrForbidden:
		return "当前角色权限不足，请联系管理员"
	case ErrQuotaExceeded:
		return "今日配额已用完，明天重置或联系管理员提升"
	case ErrWAFBlocked:
		return "请求被安全防护拦截，请检查请求内容是否包含特殊字符"
	case ErrRateLimited:
		return "请求过于频繁，请稍后重试"
	case ErrNoBackend:
		return "没有可用的模型后端，请检查模型是否启动或配置是否正确"
	case ErrModuleDisabled:
		return "该功能模块未启用，可在模块管理中开启"
	default:
		return ""
	}
}

// 预定义的常用错误实例
var (
	Unauthorized   = New(ErrUnauthorized, http.StatusUnauthorized, "未授权")
	Forbidden      = New(ErrForbidden, http.StatusForbidden, "权限不足")
	RateLimited    = New(ErrRateLimited, http.StatusTooManyRequests, "请求过于频繁")
	Internal       = New(ErrInternal, http.StatusInternalServerError, "内部错误")
	BadRequest     = New(ErrBadRequest, http.StatusBadRequest, "请求参数错误")
	NotFound       = New(ErrNotFound, http.StatusNotFound, "资源不存在")
)

// WriteJSON 将错误写入 HTTP 响应
func WriteJSON(w http.ResponseWriter, e *TSGError) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(e.HTTP)
	// 使用标准库 json，保持零依赖
	data := e.JSON()
	// 手动序列化避免 import cycle
	fmt.Fprintf(w, `{"error":{"code":"%s","message":"%s"`, e.Code, escapeJSON(e.Message))
	if e.Detail != "" {
		fmt.Fprintf(w, `,"detail":"%s"`, escapeJSON(e.Detail))
	}
	hint := hintForCode(e.Code)
	if hint != "" {
		fmt.Fprintf(w, `},"hint":"%s"}`, escapeJSON(hint))
	} else {
		fmt.Fprint(w, `}}`)
	}
	_ = data // suppress unused warning
}

func escapeJSON(s string) string {
	// 简单的 JSON 转义（标准库 encoding/json 会在 handler 中使用）
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			result = append(result, '\\', '"')
		case '\\':
			result = append(result, '\\', '\\')
		case '\n':
			result = append(result, '\\', 'n')
		case '\r':
			result = append(result, '\\', 'r')
		case '\t':
			result = append(result, '\\', 't')
		default:
			result = append(result, c)
		}
	}
	return string(result)
}
