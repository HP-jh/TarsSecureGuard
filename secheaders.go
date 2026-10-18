package main

// ===================== v4.36.0 HTTP 安全响应头自动加固 =====================
//
// 自动为所有 HTTP 响应添加安全响应头，防止常见客户端攻击。
// 覆盖 OWASP 推荐的核心安全头，默认启用，零配置开箱即用。

import (
	"net/http"
	"strings"
	"sync"
)

// SecurityHeadersConfig v4.36.0 安全响应头配置
type SecurityHeadersConfig struct {
	Enabled                 bool              `json:"secHeadersEnabled"`
	XFrameOptions           string            `json:"xFrameOptions"`           // DENY | SAMEORIGIN
	XContentTypeOptions     bool              `json:"xContentTypeOptions"`     // nosniff
	ReferrerPolicy          string            `json:"referrerPolicy"`          // strict-origin-when-cross-origin
	XXSSProtection          bool              `json:"xXSSProtection"`          // 1; mode=block
	PermissionsPolicy       string            `json:"permissionsPolicy"`       // 功能策略
	StrictTransportSecurity string            `json:"strictTransportSecurity"` // max-age=...
	CustomHeaders           map[string]string `json:"customHeaders"`
	ExcludePaths            []string          `json:"excludePaths"`
}

var (
	secHeadersMu     sync.RWMutex
	secHeadersConfig *SecurityHeadersConfig
)

// initSecurityHeaders 初始化安全响应头中间件配置
func initSecurityHeaders(cfg *SecurityHeadersConfig) {
	if cfg == nil {
		cfg = &SecurityHeadersConfig{
			Enabled:                 true,
			XFrameOptions:           "DENY",
			XContentTypeOptions:     true,
			ReferrerPolicy:          "strict-origin-when-cross-origin",
			XXSSProtection:          true,
			PermissionsPolicy:       "camera=(), microphone=(), geolocation=()",
			StrictTransportSecurity: "max-age=63072000; includeSubDomains; preload",
		}
	}
	secHeadersMu.Lock()
	secHeadersConfig = cfg
	secHeadersMu.Unlock()
}

// securityHeadersMiddleware 安全响应头中间件
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secHeadersMu.RLock()
		cfg := secHeadersConfig
		secHeadersMu.RUnlock()

		if cfg == nil || !cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		for _, path := range cfg.ExcludePaths {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		if cfg.XFrameOptions != "" {
			w.Header().Set("X-Frame-Options", cfg.XFrameOptions)
		}
		if cfg.XContentTypeOptions {
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		if cfg.ReferrerPolicy != "" {
			w.Header().Set("Referrer-Policy", cfg.ReferrerPolicy)
		}
		if cfg.XXSSProtection {
			w.Header().Set("X-XSS-Protection", "1; mode=block")
		}
		if cfg.PermissionsPolicy != "" {
			w.Header().Set("Permissions-Policy", cfg.PermissionsPolicy)
		}
		if cfg.StrictTransportSecurity != "" {
			w.Header().Set("Strict-Transport-Security", cfg.StrictTransportSecurity)
		}
		for k, v := range cfg.CustomHeaders {
			w.Header().Set(k, v)
		}

		next.ServeHTTP(w, r)
	})
}
