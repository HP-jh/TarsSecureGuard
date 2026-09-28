package main

import (
	"fmt"
	"strings"
)

// ===================== 系统直连层传输切换点（v2.0.0「决策即配置」）=====================
//
// 采纳优化任务调研结论「保持 Go 核心、不重写」，但把直连传输做成可配置切换点：
//   config.json: direct.transport = native（默认）| grpc-sidecar
//     direct.grpcSidecar.address：边车地址（仅允许本地 Unix socket 或 127.0.0.1）
//
// 锦衣卫预审 4 条安全边界（2026-09-27，写入设计与文档）：
//   1. 边车通信仅限本地（127.0.0.1 / Unix socket），不开放新的外部监听端口
//   2. 所有外部流量必经核心网关 security-core 中间件链（WAF+鉴权+RBAC）再转发边车，
//      边车本身不独立接收外部请求
//   3. 核心与边车之间启用 mTLS 或共享密钥认证（预留接口 sidecarSecret，本版未启用）
//   4. 边车不可用时自动回落 native 模式，不因边车故障导致服务中断
//
// 说明：grpc-sidecar 当前为预留切换点（协议接入为后续工作）；边车侧先按
// OpenAI 兼容 HTTP 端点对接，调用失败自动回落 native。

type DirectTransport interface {
	Name() string
	ChatEndpoint() (string, error) // OpenAI 兼容 chat/completions 端点
}

// nativeTransport 现有 Go 原生直连：llama-server 本地子进程（127.0.0.1:18890）
type nativeTransport struct{}

func (nativeTransport) Name() string { return "native" }

func (nativeTransport) ChatEndpoint() (string, error) {
	return fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", modelPort), nil
}

// grpcSidecarTransport gRPC 边车切换点（预留）：地址仅允许本地回环
type grpcSidecarTransport struct{ addr string }

func (grpcSidecarTransport) Name() string { return "grpc-sidecar" }

func (g grpcSidecarTransport) ChatEndpoint() (string, error) {
	if g.addr == "" {
		// 边界 4：未配置地址 -> 报警用并回落 native（由调用方 fallback）
		logMsg("[Direct] grpc-sidecar 未配置 address，回落 native")
		return nativeTransport{}.ChatEndpoint()
	}
	host := g.addr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" && !strings.HasPrefix(g.addr, "unix:") {
		return "", fmt.Errorf("边车地址仅允许本地（127.0.0.1/localhost/unix socket），当前: %s", g.addr)
	}
	return "http://" + g.addr + "/v1/chat/completions", nil
}

// currentDirectTransport 按配置返回当前直连传输实现
func currentDirectTransport() DirectTransport {
	cfgMu.RLock()
	t := cfg.Direct.Transport
	addr := cfg.Direct.GRPCSidecar.Address
	cfgMu.RUnlock()
	switch t {
	case "grpc-sidecar":
		return grpcSidecarTransport{addr: addr}
	default:
		return nativeTransport{}
	}
}

// directChatEndpoint 直连 chat 端点（边车不可用时自动回落 native —— 边界 4）
func directChatEndpoint() (string, error) {
	tr := currentDirectTransport()
	ep, err := tr.ChatEndpoint()
	if err != nil {
		logMsg("[Direct] " + tr.Name() + " 不可用，回落 native: " + err.Error())
		return nativeTransport{}.ChatEndpoint()
	}
	if tr.Name() != "native" {
		logMsg("[Direct] 使用 " + tr.Name() + " 端点 " + ep + "（预留切换点）")
	}
	return ep, nil
}
