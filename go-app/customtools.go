package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ===================== 用户自定义 HTTP 转发工具（v2.0.0）=====================
//
// config.json customTools[]: {name, description, endpoint, method, headers, secretHeaders}
//   - headers       静态头（明文可见）
//   - secretHeaders 敏感头：值支持 "env:VAR" 引用环境变量，避免明文落盘
//
// 锦衣卫预审红线（2026-09-27，SSRF 防护 5 条，全部落实）：
//   1. 请求发出前二次校验解析后 IP：拒绝 RFC1918/回环/链路本地/云元数据/未指定地址；
//      校验放在自定义 DialContext 内（连接时对实际 IP 校验，防 DNS 重绑定）
//   2. 禁用重定向跟随（CheckRedirect 返回 http.ErrUseLastResponse，不自动跳转）
//   3. 协议白名单：仅 http / https
//   4. 超时 30 秒；响应大小限制 2MB（复用 maxFetchBytes）
//   5. 每次调用落审计 CUSTOM_TOOL_CALL（目标 URL + 结果状态）

// CustomTool 用户自定义 HTTP 转发工具定义
type CustomTool struct {
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Endpoint      string            `json:"endpoint"`
	Method        string            `json:"method"` // GET | POST（默认 GET）
	Headers       map[string]string `json:"headers,omitempty"`
	SecretHeaders map[string]string `json:"secretHeaders,omitempty"` // 值支持 env:VAR 引用
}

// customToolClient SSRF 加固的专用 HTTP 客户端（与全局 httpClient 隔离）
var customToolClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // 禁用重定向跟随（防 3xx 跳内网绕过）
	},
	Transport: &http.Transport{
		DialContext: ssrfSafeDialContext(), // 连接时校验实际 IP（防 DNS 重绑定）
	},
}

// ssrfSafeDialContext 仅允许连接公网地址；解析出的任一 IP 落入私网/保留段即拒绝
func ssrfSafeDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("SSRF 防护: 非法地址 %s", addr)
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var public net.IP
		for _, ip := range ips {
			if !isPublicIP(ip.IP) {
				return nil, fmt.Errorf("SSRF 防护: 拒绝非公网地址 %s（%s）", host, ip.IP)
			}
			if public == nil {
				public = ip.IP
			}
		}
		if public == nil {
			return nil, fmt.Errorf("SSRF 防护: %s 无可解析公网地址", host)
		}
		d := &net.Dialer{Timeout: 10 * time.Second}
		// 用已校验的 IP 直连（域名解析结果与实际连接目标一致）
		return d.DialContext(ctx, network, net.JoinHostPort(public.String(), port))
	}
}

// isPublicIP 校验 IP 是否公网：拒绝回环/RFC1918/链路本地(含 169.254.169.254 云元数据)/组播/未指定
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified())
}

// customToolList 当前配置的自定义工具（仅 customTools 模块开启时对外可见）
func customToolList() []CustomTool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return append([]CustomTool(nil), cfg.CustomTools...)
}

// findCustomTool 按名称查找（返回是否找到）
func findCustomTool(name string) (CustomTool, bool) {
	for _, t := range customToolList() {
		if t.Name == name {
			return t, true
		}
	}
	return CustomTool{}, false
}

// resolveSecretHeader 展开 secretHeaders 的 env:VAR 引用；无前缀按明文值处理
func resolveSecretHeader(v string) string {
	if strings.HasPrefix(v, "env:") {
		return os.Getenv(strings.TrimPrefix(v, "env:"))
	}
	return v
}

// executeCustomTool 执行自定义 HTTP 转发工具（SSRF 五条红线全部在此落地）
func executeCustomTool(name string, args map[string]interface{}) (interface{}, error) {
	tool, ok := findCustomTool(name)
	if !ok {
		return nil, fmt.Errorf("自定义工具不存在: %s", name)
	}
	// 红线 3：协议白名单（仅 http/https）
	u := tool.Endpoint
	if !isHTTPURL(u) {
		auditLog("CUSTOM_TOOL_CALL", "system", fmt.Sprintf("tool=%s url=%s status=rejected(协议白名单)", name, u))
		return nil, fmt.Errorf("endpoint 仅允许 http/https: %s", u)
	}
	method := strings.ToUpper(strings.TrimSpace(tool.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		return nil, fmt.Errorf("method 仅允许 GET/POST")
	}

	var body io.Reader
	if method == http.MethodPost {
		b, _ := json.Marshal(args)
		body = bytes.NewReader(b)
	} else if len(args) > 0 {
		// GET：args 序列化为 query
		q := make([]string, 0, len(args))
		for k, v := range args {
			bs, _ := json.Marshal(v)
			q = append(q, fmt.Sprintf("%s=%s", k, strings.Trim(string(bs), `"`)))
		}
		u = u + "?" + strings.Join(q, "&")
	}

	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	for k, v := range tool.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range tool.SecretHeaders {
		req.Header.Set(k, resolveSecretHeader(v))
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := customToolClient.Do(req)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	if err != nil {
		// 红线 5：审计（失败也记）
		auditLog("CUSTOM_TOOL_CALL", "system", fmt.Sprintf("tool=%s url=%s status=error(%v)", name, tool.Endpoint, err))
		return nil, err
	}
	defer resp.Body.Close()
	// 红线 4：响应限制 2MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		auditLog("CUSTOM_TOOL_CALL", "system", fmt.Sprintf("tool=%s url=%s status=%d body_err=%v", name, tool.Endpoint, status, err))
		return nil, err
	}
	auditLog("CUSTOM_TOOL_CALL", "system", fmt.Sprintf("tool=%s url=%s status=%d bytes=%d", name, tool.Endpoint, status, len(data)))
	return map[string]interface{}{
		"status":    status,
		"body":      string(data),
		"truncated": len(data) >= maxFetchBytes,
	}, nil
}

// customToolDescriptions 注册到工具列表的形态
func customToolDescriptions() []map[string]interface{} {
	var out []map[string]interface{}
	for _, t := range customToolList() {
		out = append(out, map[string]interface{}{
			"name":        t.Name,
			"description": t.Description,
			"module":      "customTools",
			"custom":      true,
		})
	}
	return out
}
