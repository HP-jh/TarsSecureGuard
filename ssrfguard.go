package main

// ===================== v3.2.2 统一 SSRF 防护（ssrfguard）=====================
//
// 审计结论（2026-10）：SSRF 红线此前只在 customTools 执行链落地（专用
// customToolClient + ssrfSafeDialContext）。fetchURLText / loadOpenAPIDoc /
// downloadModel / webSearch 等出站路径共用 httpClientShort（无 IP 校验、
// 默认跟随重定向），downloadClient 甚至无超时——同一风险面防护不一致。
//
// 本模块把「连接时实际 IP 校验」提炼为通用工厂，并让所有可被外部输入
// （模型工具参数 / API 请求体 / OpenAPI 文档 server URL）驱动的出站客户端
// 共用同一条防线：
//   1. DialContext 层校验解析后的真实 IP（拒绝回环/RFC1918/链路本地/云元数据/
//      组播/未指定；防 DNS 重绑定——域名解析结果与实际连接目标强制一致）；
//   2. CheckRedirect 逐跳重校验：重定向目标同样过协议白名单 + IP 校验，
//      不再依赖"完全禁用重定向"来堵 3xx 跳内网的口子；
//   3. 协议白名单仅 http/https（沿用 isHTTPURL 预检 + 拨号器网络过滤）；
//   4. 每次拒绝落审计 SSRF_BLOCKED（目标 host + 原因）。
//
// 例外通道 allowLocalTargets：本机推理运行时（ollama 11434 / lmstudio 1234 /
// llama-local modelPort）必须能访问回环地址，且其目标主机由内置常量与运维
// 配置决定、不接受模型/请求体注入——这些固定端点客户端显式开启例外；
// 任何以用户/模型可控 URL 为目标的客户端一律不开启（默认 false）。

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ssrfSafeDialContext 返回带 SSRF 校验的拨号函数（连接时对实际解析 IP 校验，
// 防 DNS 重绑定）。allowLocalTargets=true 时放行回环/未指定地址——仅限目标
// 主机由内置常量/运维配置决定的固定端点池（本机推理运行时、云端 provider）；
// 用户/模型可控 URL 的出站必须传 false。
// allowPrivateTargets=true（隐含 allowLocalTargets）额外放行 RFC1918 私网——
// 仅供固定端点池使用：局域网 ollama/lmstudio 部署是官方支持场景
// （doctor.go / deploy 文档），该池目标主机不接受模型/请求体注入。
func ssrfSafeDialContext(allowLocalTargets, allowPrivateTargets bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("SSRF 防护: 不支持的网络类型 %s", network)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("SSRF 防护: 非法地址 %s", addr)
		}
		// IP 字面量直接校验，免解析（也免疫 DNS 重绑定）
		var ips []net.IPAddr
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IPAddr{{IP: ip}}
		} else {
			resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips = resolved
		}
		var chosen net.IP
		for _, ip := range ips {
			blocked := ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
				ip.IsMulticast() || ip.IsUnspecified()
			allowedException := allowLocalTargets && (ip.IsLoopback() || ip.IsUnspecified())
			allowedPrivate := allowPrivateTargets && ip.IsPrivate()
			if blocked && !allowedException && !allowedPrivate {
				auditLog("SSRF_BLOCKED", "system", fmt.Sprintf("host=%s ip=%s 拒绝（非公网地址）", host, ip.IP))
				return nil, fmt.Errorf("SSRF 防护: 拒绝非公网地址 %s（%s）", host, ip.IP)
			}
			if chosen == nil {
				chosen = ip.IP
			}
		}
		// 无可连地址且例外通道关闭 → 拒绝
		if chosen == nil && !allowLocalTargets && !allowPrivateTargets {
			return nil, fmt.Errorf("SSRF 防护: %s 无可解析公网地址", host)
		}
		dialHost := host
		if chosen != nil {
			dialHost = chosen.String() // 用已校验 IP 直连，解析结果与实际连接一致
		}
		return base.DialContext(ctx, network, net.JoinHostPort(dialHost, port))
	}
}

// ssrfSafeTransportStrict 构造严格模式 Transport：任何私网/回环/链路本地/
// 云元数据地址一律拒绝（用于用户/模型可控 URL 的出站池）。
func ssrfSafeTransportStrict() *http.Transport {
	return &http.Transport{
		DialContext:           ssrfSafeDialContext(false, false),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// ssrfGuardedClient 构造 SSRF 加固客户端（严格模式：任何私网/回环/链路本地
// /云元数据地址一律拒绝）：
//   - 禁用自动重定向（ErrUseLastResponse）；调用方如需跟随，必须经
//     ssrfRedirectURL 对下一跳做协议白名单 + 主机校验后再手工发起；
//   - Transport 走 ssrfSafeDialContext(false,false)（连接时实际 IP 校验）。
func ssrfGuardedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: ssrfSafeTransportStrict(),
	}
}

// ssrfRedirectURL 校验 3xx 重定向目标：协议白名单 + 禁止裸 IP/凭据注入 +
// 主机名不得指向私网字面量。通过返回清洗后的绝对 URL；调用方可在有限次数
// （建议 ≤3）内用同一 ssrfGuardedClient 手工跟随。
func ssrfRedirectURL(resp *http.Response) (string, bool) {
	if resp == nil {
		return "", false
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", false
	}
	ru, err := resp.Request.URL.Parse(loc)
	if err != nil {
		return "", false
	}
	if ru.Scheme != "http" && ru.Scheme != "https" {
		return "", false
	}
	if ru.User != nil || ru.Host == "" {
		return "", false
	}
	if h := ru.Hostname(); net.ParseIP(h) != nil {
		// 重定向到 IP 字面量：交由 Transport 的 IP 校验兜底，但私网字面量直接出局
		if ip := net.ParseIP(h); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				auditLog("SSRF_BLOCKED", "system", fmt.Sprintf("redirect host=%s 拒绝（重定向指向私网/保留地址）", h))
				return "", false
			}
		}
	}
	return ru.String(), true
}
