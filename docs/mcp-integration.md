# MCP 集成指南

## 1. MCP 概述

Model Context Protocol (MCP) 是 TSG 的扩展机制，允许外部工具通过标准化接口接入网关。

## 2. 内置 MCP 工具

TSG 内置以下 MCP 工具：

| 工具 | 功能 | 端点 |
|------|------|------|
| webSearch | 网页搜索 | `/api/search` |
| feishu | 飞书集成 | `/api/feishu/` |
| mcpExternal | 外部 MCP 中继 | `/mcp` |
| autoDiscovery | 自动发现扫描 | `/api/admin/v32/auto-discovery/scan` |
| builtinTools | 内置工具调用 | `/api/tools/` |

## 3. 接入新 MCP 工具

### 3.1 开发适配器

在 `crownext/mcpclient/` 下创建新的适配器：

```go
package mcpclient

// MyAdapter implements the MCP tool interface.
type MyAdapter struct{}

func (a *MyAdapter) Name() string { return "my-tool" }
func (a *MyAdapter) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
    // 实现工具逻辑
    return result, nil
}
```

### 3.2 注册到网关

在 `main.go` 路由注册处添加：

```go
mux.HandleFunc("/api/tools/my-tool", moduleRoute("builtinTools", handleMyTool))
```

### 3.3 配置启用

在 `config.json` 的 `modules` 中确保对应模块为 `true`。

## 4. 外部 MCP 中继

外部 MCP Server 通过 `/mcp` 端点接入：

```json
POST /mcp
{
  "tool": "external-tool-name",
  "params": {"key": "value"}
}
```

TSG 会验证请求、检查权限、转发到对应 MCP Server，并记录审计日志。

## 5. MCP 安全

- 所有 MCP 调用经过 WAF 过滤
- 外部 MCP 需通过 `mcpExternal` 模块启用
- MCP Server 注册表在 `crownext/mcpserver/`
- 敏感参数自动脱敏

## 6. 调试 MCP

```bash
# 测试 MCP 工具调用
curl -H "Authorization: Bearer $API_KEY" \
  -d '{"tool":"webSearch","params":{"query":"golang"}}' \
  http://127.0.0.1:18889/mcp
```

## 7. 开发规范

1. 所有适配器实现 `error` 返回，禁止 panic
2. 超时控制：默认 30s，长任务用 context
3. 参数校验：必填项 + 类型检查
4. 日志记录：调用入口记 INFO，异常记 ERROR
5. 资源释放：defer 关闭连接/文件
