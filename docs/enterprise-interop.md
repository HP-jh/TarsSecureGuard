# TSG ↔ TarsEnterprise 互操作

## 1. 概述

TSG v4.13.0 引入与 TarsEnterprise 的双向互操作能力，支持：

- **接收指令**：TarsEnterprise 向 TSG 下发控制命令
- **事件推送**：TSG 向 TarsEnterprise 实时推送状态/告警/审计事件
- **双向同步**：角色、数据、配置的跨系统同步

## 2. 通信模型

```
┌─────────────────┐         POST /receive-command         ┌─────────────────┐
│  TarsEnterprise │  ───────────────────────────────────► │      TSG        │
│                 │                                       │                 │
│                 │  ◄──────────────────────────────────  │                 │
│                 │         SSE /events (stream)          │                 │
└─────────────────┘                                       └─────────────────┘
```

- **下行通道**：HTTP POST，命令请求/响应模式
- **上行通道**：SSE (Server-Sent Events)，单向实时流

## 3. 接收指令

### 端点

```
POST /api/v1/interop/receive-command
Content-Type: application/json
```

### 请求体

```json
{
  "command": "status",
  "target": "gateway",
  "payload": {},
  "source": "tars-enterprise-01",
  "timestamp": "2026-10-17T14:30:00Z"
}
```

### 响应体

```json
{
  "success": true,
  "message": "Gateway running, 142 active connections",
  "data": {
    "version": "v4.15.0",
    "uptime": "72h13m",
    "connections": 142
  }
}
```

## 4. 支持指令

| 指令 | 说明 | 示例 Payload |
|------|------|-------------|
| `ping` | 连通性测试 | `{}` |
| `status` | 获取网关状态 | `{}` |
| `sync_role` | 同步角色定义 | `{"roles": [...]}` |
| `sync_data` | 同步知识库数据 | `{"kb_id": "...", "entries": [...]}` |
| `exec` | 执行自定义操作 | `{"action": "reload", "target": "waf"}` |

## 5. 事件推送

### 端点

```
GET /api/v1/interop/events
Accept: text/event-stream
```

### SSE 格式

```
event: alert
data: {"type":"alert","payload":{"level":"warning","msg":"WAF blocked 50 req/s"},"timestamp":"2026-10-17T14:30:00Z"}

```

### 事件类型

| 类型 | 说明 | 触发条件 |
|------|------|---------|
| `status` | 状态变更 | 网关启停/配置重载 |
| `alert` | 安全告警 | WAF 拦截/异常流量 |
| `audit` | 审计记录 | 敏感操作执行 |
| `sync` | 同步确认 | 数据同步完成 |

## 6. 配置

```json
{
  "interop": {
    "enabled": true,
    "allowed_sources": ["tars-enterprise-01"],
    "event_buffer": 16,
    "command_timeout": "30s"
  }
}
```

## 7. 安全

- 指令来源校验（`source` 白名单）
- 敏感指令需 admin 令牌
- SSE 连接带超时心跳（60s）
- 事件缓冲区满时丢弃旧事件
