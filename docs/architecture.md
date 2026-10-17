# TarsSecureGuard 系统架构总览

## 1. 请求流向

```
Client Request
    │
    ▼
┌─────────────────┐
│  gatewayMiddleware  │  ← WAF / 鉴权 / CORS / 统计
│  (WAF → Auth → RBAC → Audit → RateLimit) │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│   HTTP Router   │  ← 模块路由 (moduleRoute 包装)
│  (mux.HandleFunc)   │  ← 关闭的模块返回 503
└─────────────────┘
    │
    ├── /api/chat/*      → Chat API (多 provider 聚合)
    ├── /api/admin/*     → Admin 面板 (模块管理 / 配置 / 审计)
    ├── /api/kb/*        → Knowledge Base v1/v2
    ├── /api/obsidian/*  → Obsidian Vault 同步
    ├── /api/voicecorrection/* → 语音纠错
    ├── /api/v1/interop/* → TarsEnterprise 互操作
    ├── /api/admin/update/* → 自动更新管理
    ├── /mcp               → MCP 外部工具
    ├── /ws/events         → SSE 实时事件流
    └── /                  → 前端 (embed.FS)
```

## 2. 模块依赖

```
main.go
├── kingdom/          ← 动物分类学架构注册中心
├── crownext/         ← 扩展模块
│   ├── security/     ← 安全引擎
│   ├── agentmesh/    ← 智能体网格
│   ├── mcpclient/    ← MCP 客户端
│   ├── mcpserver/    ← MCP 服务端
│   ├── assistant/    ← 助手系统
│   ├── skylink/      ← 天空链路
│   ├── threatmodel/  ← 威胁模型
│   ├── vault/        ← 安全金库
│   └── bench/        ← 性能基准
├── pkg/
│   ├── kb/           ← 知识库 (TF-IDF + chunk)
│   ├── obsidian/     ← Obsidian 连接器
│   ├── voicecorrection/ ← 语音纠错
│   ├── interop/      ← 企业互操作
│   └── update/       ← 自动更新
└── frontend/         ← 单 HTML 前端 (embed)
```

## 3. 部署拓扑

### 单机模式（默认）
```
[TSG Binary]
   ├── port 18889  ← HTTP 网关
   └── port 18890  ← 模型服务 (llama-server)
```

### 带外部模型
```
[TSG Binary] ←──→ [LM Studio @ :1234]
               ←──→ [Ollama @ :11434]
               ←──→ [Cloud Provider APIs]
```

### 企业级部署
```
[Load Balancer]
      │
   ┌──┴──┐
[TSG-1] [TSG-2]  ← 多实例 + 共享配置
   │       │
[NATS] ←──→ [TarsEnterprise]
```

## 4. 数据流

```
Config (config.json)
    │
    ├── Modules (on/off) ──→ moduleRoute 503 控制
    ├── Providers (keys) ──→ 云端模型调用
    ├── Guard (rules)    ──→ WAF / 动态防护
    └── Roles (RBAC)     ──→ 权限判定

Runtime Data
    ├── logs/            ← 文件日志
    ├── data/            ← 状态持久化
    ├── knowledge/       ← 知识库文档
    └── ~/.tars/         ← 自动更新缓存
```

## 5. 安全层

| 层级 | 组件 | 职责 |
|------|------|------|
| L1 | WAF | 请求过滤、注入检测、速率限制 |
| L2 | Auth | API Key / Token 校验 |
| L3 | RBAC | 角色权限矩阵 (admin/audit/user) |
| L4 | Audit | 审计日志、hash 链 |
| L5 | Path Guard | 文件读写安全边界 |
| L6 | Self-Protect | 进程自我保护 |

## 6. 版本演进

- v3.x: 治理层、性能升级、WAF 加固
- v4.0+: Crown 架构、12 节点、26 职业
- v4.10+: 多协议透传 (Anthropic/Gemini)
- v4.12+: 知识库 v2、Obsidian、语音纠错
- v4.13+: TarsEnterprise 互操作
- v4.14+: 自动更新系统
