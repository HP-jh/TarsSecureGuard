# TarsSecureGuard 架构优化方案

**版本**: v4.3.0  
**编制日期**: 2026-11-09  
**文档状态**: 草案 (Draft)

---

## 目录

1. [当前架构评估](#1-当前架构评估)
2. [优化方案总览](#2-优化方案总览)
3. [P0 级优化：代码组织重构](#3-p0-级优化代码组织重构)
4. [P1 级优化：中间件管道重构](#4-p1-级优化中间件管道重构)
5. [P1 级优化：配置管理简化](#5-p1-级优化配置管理简化)
6. [P2 级优化：性能与可观测性增强](#6-p2-级优化性能与可观测性增强)
7. [业界参考架构](#7-业界参考架构)
8. [分阶段执行计划](#8-分阶段执行计划)
9. [风险评估与缓解措施](#9-风险评估与缓解措施)

---

## 1. 当前架构评估

### 1.1 项目概况

TarsSecureGuard 是一个企业级 AI 网关系统，当前版本 v4.3.0 包含约 **35,000 行 Go 代码**，分布在 **100+ 个源文件**中。系统提供：

- 多后端模型路由（本地 GGUF、LM Studio、Ollama、云端 Provider）
- 完整的安全防护（WAF、RBAC、PII 脱敏、SSRF 防护）
- 智能路由（ε-greedy bandit 算法）
- 模块化架构（30+ 功能模块）
- 可观测性（Prometheus metrics、分布式 tracing）
- 连接池自适应扩缩容

### 1.2 架构优势 (Strengths)

| 领域 | 优势点 | 技术实现 |
|------|--------|----------|
| **安全纵深** | 多层防御体系 | WAF + RBAC + PII Mask + SSRF Guard + IP Reputation |
| **模块化设计** | 细粒度功能开关 | 依赖拓扑自动纠正、热重载、工作者生命周期管理 |
| **智能路由** | 两阶段路由 | 静态规则优先 + ε-greedy bandit 优化自动分支 |
| **可观测性** | 全链路追踪 | trace_id 透传、Prometheus metrics、审计日志关联 |
| **连接池** | 自适应扩缩容 | QPS 感知、HTTP/2 复用率监控、5~200 动态区间 |
| **配置热重载** | 2 秒轮询 | SHA-256 指纹比对、原子化回写、依赖自动对齐 |

### 1.3 架构问题 (Weaknesses)

#### 1.3.1 代码组织问题（严重）

**问题描述**：所有 Go 源文件平铺在根目录，全部属于 `package main`。

```
当前结构：
TarsSecureGuard/
├── main.go (1016 lines)
├── config.go (651 lines)
├── chat.go (741 lines)
├── waf.go (539 lines)
├── router.go (285 lines)
├── observability.go (688 lines)
├── pool.go (238 lines)
├── handlers.go (516 lines)
├── ... (90+ more files)
└── total: ~35,000 lines in root
```

**影响**：
- 代码导航困难，新人上手成本高
- 模块边界模糊，隐式依赖难以追踪
- 无法独立测试和部署子模块
- 违反 Go 项目标准布局（Standard Go Project Layout）

#### 1.3.2 中间件管道问题（重要）

**问题描述**：`gatewayMiddleware` 是一个 500+ 行的单体函数，包含 15+ 个处理阶段：

```go
// main.go: gatewayMiddleware (当前状态)
func gatewayMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 1. Panic recovery
        // 2. 动态防护蜜罐
        // 3. 影子规则流水线
        // 4. 小时统计
        // 5. 安全头设置
        // 6. Body 大小限制
        // 7. IP 封禁检查
        // 8. WAF 检测
        // 9. CORS 预检
        // 10. 公共路由放行
        // 11. 身份认证
        // 12. RBAC 权限检查
        // 13. 配额检查
        // 14. 速率限制
        // 15. 请求计数
        // 16. 响应脱敏
        // 17. 404 扫描检测
        next.ServeHTTP(w, r)
    })
}
```

**影响**：
- 难以添加/移除/调整中间件顺序
- 测试覆盖困难（需要模拟完整请求链路）
- 不符合 Chain of Responsibility 模式

#### 1.3.3 配置管理问题（重要）

**问题描述**：配置结构采用多层嵌套 + 匿名内嵌，导致：

```go
// config.go: Config 结构 (当前状态)
type Config struct {
    Cloud struct { ... }
    Security struct { ... }
    Users []User
    Tenants TenantsCfg
    MCP struct { ... }
    Paths struct { ... }
    Modules map[string]bool
    CustomTools []CustomTool
    CustomAgents []CustomAgentDef
    Direct DirectCfg
    V3Config        // 匿名内嵌：resource/rateLimit/ipReputation/semantic/router/tier1
    V32Config       // 匿名内嵌：providers/circuit/responseCache/pool
    V33Config       // 匿名内嵌：capabilities/modelCaps
    V34Config       // 匿名内嵌：pricing/connectors
    V35Config       // 匿名内嵌：ui/moduleProfiles
    OAuth OAuthCfg
    Gatekeeper GatekeeperCfg
    Audit AuditCfg
    V38Config       // 匿名内嵌：persona
    V4101Config     // 匿名内嵌：modelAliases/stickyRouter
    InstallRoot string
    DataRoot string
}
```

**影响**：
- 配置字段分散在多个版本段中，难以理解完整配置
- 匿名内嵌导致 JSON 序列化时字段提升，用户难以定位配置项
- 默认值逻辑分散在 `loadConfig`、`validateAndCorrectConfig` 等多处

#### 1.3.4 错误处理问题（中等）

**问题描述**：错误处理模式不统一：

```go
// 模式 1: 直接返回错误字符串
if err != nil {
    writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
    return
}

// 模式 2: 使用 i18n 错误码
i18nErrorJSON(w, r, http.StatusBadRequest, "err.invalidrequest")

// 模式 3: 带 hint 的错误
i18nErrorJSONWithHint(w, r, http.StatusUnauthorized, "err.unauthorized", "err.unauthorized.hint")
```

**影响**：
- 错误响应格式不一致
- 部分错误缺少上下文信息
- 国际化覆盖不完整

---

## 2. 优化方案总览

### 2.1 优先级矩阵

| 优先级 | 优化项 | 影响范围 | 风险等级 | 预估工时 |
|--------|--------|----------|----------|----------|
| **P0** | 代码组织重构 | 全局 | 中 | 3-4 周 |
| **P1** | 中间件管道重构 | 核心链路 | 低 | 1-2 周 |
| **P1** | 配置管理简化 | 配置系统 | 低 | 1 周 |
| **P1** | 错误处理标准化 | API 层 | 低 | 3-5 天 |
| **P2** | 性能优化（参考业界） | 出站链路 | 中 | 2 周 |
| **P2** | UI 现代化 | 前端 | 高 | 4-6 周 |

### 2.2 优化目标

- **可维护性**：代码导航时间减少 50%，新人上手时间从 2 周降至 3 天
- **可测试性**：单元测试覆盖率从 ~30% 提升至 70%+
- **可扩展性**：新功能开发周期减少 30%
- **性能**：P99 延迟降低 20%，连接复用率提升至 90%+

---

## 3. P0 级优化：代码组织重构

### 3.1 目标架构

采用 **Clean Architecture** 风格，按领域划分包结构：

```
TarsSecureGuard/
├── cmd/                          # 入口程序
│   ├── tsg/                      # 主网关
│   │   └── main.go
│   ├── tsg-doctor/               # 诊断工具
│   │   └── main.go
│   └── tsg-android/              # Android 入口
│       └── main.go
│
├── internal/                     # 内部包（不对外暴露）
│   ├── gateway/                  # 网关核心
│   │   ├── server.go             # HTTP 服务器
│   │   ├── middleware.go         # 中间件链
│   │   ├── router.go             # 路由注册
│   │   └── context.go            # 请求上下文
│   │
│   ├── security/                 # 安全模块
│   │   ├── waf/                  # WAF 引擎
│   │   │   ├── rules.go
│   │   │   ├── scanner.go
│   │   │   └── pii.go
│   │   ├── auth/                 # 认证授权
│   │   │   ├── apikey.go
│   │   │   ├── rbac.go
│   │   │   └── oauth.go
│   │   └── ssrf/                 # SSRF 防护
│   │       └── guard.go
│   │
│   ├── routing/                  # 智能路由
│   │   ├── static.go             # 静态规则路由
│   │   ├── bandit.go             # ε-greedy bandit
│   │   ├── capability.go         # 能力感知路由
│   │   └── backend/              # 后端适配
│   │       ├── llama.go
│   │       ├── lmstudio.go
│   │       ├── ollama.go
│   │       └── cloud.go
│   │
│   ├── modules/                  # 模块系统
│   │   ├── registry.go           # 模块注册表
│   │   ├── lifecycle.go          # 生命周期管理
│   │   ├── deps.go               # 依赖拓扑
│   │   └── workers.go            # 后台工作者
│   │
│   ├── config/                   # 配置管理
│   │   ├── schema.go             # 配置结构定义
│   │   ├── loader.go             # 配置加载
│   │   ├── hotreload.go          # 热重载
│   │   └── defaults.go           # 默认值
│   │
│   ├── observability/            # 可观测性
│   │   ├── metrics.go            # Prometheus metrics
│   │   ├── tracing.go            # 分布式追踪
│   │   └── audit.go              # 审计日志
│   │
│   ├── pool/                     # 连接池
│   │   ├── transport.go          # HTTP Transport
│   │   ├── adaptive.go           # 自适应扩缩容
│   │   └── stats.go              # 复用率统计
│   │
│   ├── chat/                     # 聊天处理
│   │   ├── handler.go            # 请求处理
│   │   ├── message.go            # 消息模型
│   │   ├── context.go            # 上下文注入
│   │   └── agents.go             # Agent 系统
│   │
│   └── tools/                    # 工具系统
│       ├── builtin/              # 内置工具
│       ├── custom/               # 自定义工具
│       ├── mcp/                  # MCP 协议
│       └── openapi/              # OpenAPI 工具
│
├── pkg/                          # 公共包（可对外暴露）
│   ├── data/                     # 数据层抽象
│   ├── kb/                       # 知识库
│   ├── mcp/                      # MCP 客户端/服务端
│   └── interop/                  # 互操作协议
│
├── frontend/                     # 前端资源
│   ├── index.html
│   └── i18n.js
│
├── configs/                      # 配置模板
│   └── config.example.json
│
├── scripts/                      # 构建脚本
├── docs/                         # 文档
└── go.mod
```

### 3.2 迁移策略

采用 **Strangler Fig Pattern**（绞杀者模式）逐步迁移：

```
阶段 1: 建立新结构骨架
  ├── 创建 internal/ 目录结构
  ├── 迁移纯工具函数（无状态）
  └── 保持原有代码可运行

阶段 2: 按领域迁移
  ├── 迁移 security 相关代码
  ├── 迁移 routing 相关代码
  ├── 迁移 modules 相关代码
  └── 每次迁移后运行完整测试

阶段 3: 清理旧代码
  ├── 删除根目录已迁移文件
  ├── 更新 import 路径
  └── 更新 CI/CD 配置
```

### 3.3 具体文件迁移映射

| 当前文件 | 目标位置 | 行数 | 依赖复杂度 |
|----------|----------|------|------------|
| `main.go` | `cmd/tsg/main.go` + `internal/gateway/server.go` | 1016 | 高 |
| `config.go` | `internal/config/*.go` | 651 | 高 |
| `chat.go` | `internal/chat/*.go` | 741 | 中 |
| `waf.go` | `internal/security/waf/*.go` | 539 | 中 |
| `router.go` | `internal/routing/*.go` | 285 | 中 |
| `observability.go` | `internal/observability/*.go` | 688 | 中 |
| `pool.go` | `internal/pool/*.go` | 238 | 低 |
| `handlers.go` | 分散到各领域的 `handler.go` | 516 | 高 |

### 3.4 风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| 迁移过程中引入 bug | 中 | 高 | 保持完整测试覆盖，每次迁移后回归测试 |
| 团队不熟悉新结构 | 中 | 中 | 编写迁移指南，代码审查 |
| CI/CD 配置失效 | 低 | 高 | 提前更新构建脚本 |

---

## 4. P1 级优化：中间件管道重构

### 4.1 当前问题

`gatewayMiddleware` 是一个 500+ 行的单体函数，违反单一职责原则。

### 4.2 目标设计

采用 **Chain of Responsibility** 模式，将中间件拆分为独立的处理器：

```go
// internal/gateway/middleware.go

// Middleware 定义中间件接口
type Middleware interface {
    // Name 返回中间件名称（用于日志和调试）
    Name() string
    // Handle 处理请求，调用 next 继续链路或提前返回
    Handle(ctx *RequestContext, next HandlerFunc) error
}

// HandlerFunc 处理函数签名
type HandlerFunc func(ctx *RequestContext) error

// RequestContext 请求上下文（扩展 http.Request）
type RequestContext struct {
    *http.Request
    ResponseWriter http.ResponseWriter
    TraceID        string
    Identity       *Identity
    ModuleID       string
    StartTime      time.Time
}

// Chain 中间件链
type Chain struct {
    middlewares []Middleware
}

// NewChain 创建中间件链
func NewChain(middlewares ...Middleware) *Chain {
    return &Chain{middlewares: middlewares}
}

// Handler 将链转换为 http.Handler
func (c *Chain) Handler(final HandlerFunc) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx := &RequestContext{
            Request:        r,
            ResponseWriter: w,
            StartTime:      time.Now(),
        }
        
        // 构建调用链
        var execute HandlerFunc = final
        for i := len(c.middlewares) - 1; i >= 0; i-- {
            mw := c.middlewares[i]
            next := execute
            execute = func(ctx *RequestContext) error {
                return mw.Handle(ctx, next)
            }
        }
        
        if err := execute(ctx); err != nil {
            // 统一错误处理
            handleError(ctx, err)
        }
    })
}
```

### 4.3 中间件拆分

```go
// internal/gateway/middlewares/

// 1. RecoveryMiddleware - Panic 恢复
type RecoveryMiddleware struct{}

func (m *RecoveryMiddleware) Name() string { return "recovery" }

func (m *RecoveryMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    defer func() {
        if p := recover(); p != nil {
            log.Printf("[PANIC] %s %s: %v", ctx.Method, ctx.URL.Path, p)
            ctx.ResponseWriter.WriteHeader(http.StatusInternalServerError)
            json.NewEncoder(ctx.ResponseWriter).Encode(map[string]string{
                "error": "internal error",
            })
        }
    }()
    return next(ctx)
}

// 2. TraceMiddleware - 追踪 ID 生成与透传
type TraceMiddleware struct{}

func (m *TraceMiddleware) Name() string { return "trace" }

func (m *TraceMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    traceID := genTraceID()
    ctx.TraceID = traceID
    ctx.Request = ctx.Request.WithContext(
        context.WithValue(ctx.Request.Context(), obsTraceKey{}, traceID),
    )
    ctx.ResponseWriter.Header().Set("X-Trace-Id", traceID)
    obsTraceStart(traceID, ctx.Method, ctx.URL.Path, ctx.StartTime)
    defer func() {
        obsTraceFinish(traceID, ctx.Status(), time.Since(ctx.StartTime))
    }()
    return next(ctx)
}

// 3. SecurityHeadersMiddleware - 安全头设置
type SecurityHeadersMiddleware struct{}

func (m *SecurityHeadersMiddleware) Name() string { return "security-headers" }

func (m *SecurityHeadersMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    setSecurityHeaders(ctx.ResponseWriter, ctx.Request)
    return next(ctx)
}

// 4. BodyLimitMiddleware - 请求体大小限制
type BodyLimitMiddleware struct {
    MaxBytes int64
}

func (m *BodyLimitMiddleware) Name() string { return "body-limit" }

func (m *BodyLimitMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    if ctx.Body != nil {
        ctx.Body = http.MaxBytesReader(ctx.ResponseWriter, ctx.Body, m.MaxBytes)
    }
    return next(ctx)
}

// 5. IPBanMiddleware - IP 封禁检查
type IPBanMiddleware struct{}

func (m *IPBanMiddleware) Name() string { return "ip-ban" }

func (m *IPBanMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    ip := clientIP(ctx.Request)
    if isBanned(ip) {
        blockRequest(ctx.ResponseWriter, ctx.Request, "IP 处于动态封禁期")
        return nil
    }
    return next(ctx)
}

// 6. WAFMiddleware - WAF 检测
type WAFMiddleware struct{}

func (m *WAFMiddleware) Name() string { return "waf" }

func (m *WAFMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    if reason := wafCheck(ctx.Request); reason != "" {
        ip := clientIP(ctx.Request)
        ipRepPenalty(ip, 30, "waf", reason)
        blockRequest(ctx.ResponseWriter, ctx.Request, reason)
        return nil
    }
    return next(ctx)
}

// 7. CORSMiddleware - 跨域处理
type CORSMiddleware struct{}

func (m *CORSMiddleware) Name() string { return "cors" }

func (m *CORSMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    if ctx.Method == http.MethodOptions {
        origin := ctx.Header.Get("Origin")
        if origin != "" && !isTrustedOrigin(origin) {
            ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
            return nil
        }
        ctx.ResponseWriter.WriteHeader(http.StatusNoContent)
        return nil
    }
    return next(ctx)
}

// 8. AuthMiddleware - 身份认证
type AuthMiddleware struct{}

func (m *AuthMiddleware) Name() string { return "auth" }

func (m *AuthMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    if isPublicRoute(ctx.URL.Path) {
        return next(ctx)
    }
    
    id, ok := identityFromRequest(ctx.Request)
    if !ok {
        ctx.ResponseWriter.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(ctx.ResponseWriter).Encode(map[string]string{
            "error": "unauthorized",
        })
        return nil
    }
    ctx.Identity = id
    return next(ctx)
}

// 9. RBACMiddleware - 权限检查
type RBACMiddleware struct{}

func (m *RBACMiddleware) Name() string { return "rbac" }

func (m *RBACMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    if ctx.Identity == nil {
        return next(ctx) // 公共路由无需权限检查
    }
    
    ok, reason := rbacCheck(ctx.Identity, ctx.Method, ctx.URL.Path)
    if !ok {
        ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
        json.NewEncoder(ctx.ResponseWriter).Encode(map[string]string{
            "error": "权限不足: " + reason,
        })
        return nil
    }
    return next(ctx)
}

// 10. RateLimitMiddleware - 速率限制
type RateLimitMiddleware struct{}

func (m *RateLimitMiddleware) Name() string { return "rate-limit" }

func (m *RateLimitMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    if ctx.Identity != nil {
        if !rateLimitMiddleware(ctx.ResponseWriter, ctx.Request, ctx.Identity.Name, ctx.Identity.Tenant) {
            return nil
        }
    }
    return next(ctx)
}

// 11. QuotaMiddleware - 配额检查
type QuotaMiddleware struct{}

func (m *QuotaMiddleware) Name() string { return "quota" }

func (m *QuotaMiddleware) Handle(ctx *RequestContext, next HandlerFunc) error {
    if ctx.Identity != nil && routeClass(ctx.URL.Path) == "chat" {
        ok, why := quotaCheck(ctx.Identity.Tenant, ctx.Identity.Name, ctx.Identity.Groups)
        if !ok {
            ctx.ResponseWriter.WriteHeader(http.StatusTooManyRequests)
            json.NewEncoder(ctx.ResponseWriter).Encode(map[string]string{
                "error": "配额超限: " + why,
            })
            return nil
        }
    }
    return next(ctx)
}
```

### 4.4 组装中间件链

```go
// internal/gateway/server.go

func buildMiddlewareChain() *Chain {
    return NewChain(
        // 基础设施层
        &RecoveryMiddleware{},
        &TraceMiddleware{},
        &SecurityHeadersMiddleware{},
        &BodyLimitMiddleware{MaxBytes: maxBodyBytes},
        
        // 安全层
        &IPBanMiddleware{},
        &WAFMiddleware{},
        &CORSMiddleware{},
        
        // 认证授权层
        &AuthMiddleware{},
        &RBACMiddleware{},
        
        // 流量控制层
        &RateLimitMiddleware{},
        &QuotaMiddleware{},
        
        // 业务层
        &MetricsMiddleware{},
        &ResponseMaskMiddleware{},
    )
}

func main() {
    mux := http.NewServeMux()
    registerRoutes(mux)
    
    chain := buildMiddlewareChain()
    server := &http.Server{
        Addr:    fmt.Sprintf("127.0.0.1:%d", port),
        Handler: chain.Handler(func(ctx *RequestContext) error {
            // 最终处理器：路由到具体 handler
            mux.ServeHTTP(ctx.ResponseWriter, ctx.Request)
            return nil
        }),
        // ... 其他配置
    }
}
```

### 4.5 收益

| 指标 | 当前 | 优化后 |
|------|------|--------|
| 中间件函数行数 | 500+ 行 | 每个 20-50 行 |
| 单元测试难度 | 高（需模拟完整链路） | 低（可独立测试） |
| 添加新中间件 | 修改主函数 | 实现接口 + 注册 |
| 中间件顺序调整 | 修改代码逻辑 | 调整注册顺序 |

---

## 5. P1 级优化：配置管理简化

### 5.1 当前问题

配置结构采用多层匿名内嵌，导致：
- 字段分散在多个版本段中
- JSON 序列化时字段提升，用户难以理解
- 默认值逻辑分散

### 5.2 目标设计

采用**扁平化 + 命名空间**的配置结构：

```go
// internal/config/schema.go

// Config 统一配置结构（扁平化，按功能命名空间组织）
type Config struct {
    // 服务器配置
    Server ServerConfig `json:"server"`
    
    // 安全配置
    Security SecurityConfig `json:"security"`
    
    // 云端模型配置
    Cloud CloudConfig `json:"cloud"`
    
    // 本地模型配置
    Local LocalConfig `json:"local"`
    
    // 路由配置
    Routing RoutingConfig `json:"routing"`
    
    // 连接池配置
    Pool PoolConfig `json:"pool"`
    
    // 模块配置
    Modules ModulesConfig `json:"modules"`
    
    // 多租户配置
    Tenants TenantsConfig `json:"tenants"`
    
    // 可观测性配置
    Observability ObservabilityConfig `json:"observability"`
    
    // 工具配置
    Tools ToolsConfig `json:"tools"`
    
    // 路径配置
    Paths PathsConfig `json:"paths"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
    Port       int    `json:"port"`        // 默认 18889
    ListenAddr string `json:"listenAddr"`  // 默认 127.0.0.1
}

// SecurityConfig 安全配置（整合原 Security + WAF + RBAC + PII + CSP）
type SecurityConfig struct {
    // API 密钥
    APIKey            string `json:"apiKey"`
    DefaultKeyAllowed bool   `json:"defaultKeyAllowed"`
    
    // WAF
    WAFEnabled bool   `json:"wafEnabled"` // 始终 true，保留仅供状态展示
    Mode       string `json:"mode"`       // normal | strict
    
    // 防火墙
    Firewall FirewallConfig `json:"firewall"`
    
    // 审计
    AuditLogEnabled bool `json:"auditLogEnabled"`
    
    // PII 脱敏
    PIIMaskEnabled bool   `json:"piimaskEnabled"`
    PIIMaskLevel   string `json:"piimaskLevel"` // full | partial | hash
    
    // CSP
    CSP CSPConfig `json:"csp"`
}

// RoutingConfig 路由配置（整合原 Router + SemanticGuard + CapabilityHub）
type RoutingConfig struct {
    // 智能路由
    SmartRouter SmartRouterConfig `json:"smartRouter"`
    
    // 语义分级
    SemanticGuard SemanticGuardConfig `json:"semanticGuard"`
    
    // 能力感知
    Capability CapabilityConfig `json:"capability"`
}

// SmartRouterConfig 智能路由配置
type SmartRouterConfig struct {
    Enabled      *bool   `json:"enabled"`      // 默认 true
    EpsilonStart float64 `json:"epsilonStart"` // 默认 0.1
    EpsilonMin   float64 `json:"epsilonMin"`   // 默认 0.02
}

// PoolConfig 连接池配置
type PoolConfig struct {
    MaxIdleConnsPerHost int  `json:"maxIdleConnsPerHost"` // 默认 32
    AdaptiveEnabled     bool `json:"adaptiveEnabled"`     // 默认 true
    AdaptiveMin         int  `json:"adaptiveMin"`         // 默认 5
    AdaptiveMax         int  `json:"adaptiveMax"`         // 默认 200
}

// ModulesConfig 模块配置
type ModulesConfig struct {
    // 模块开关（动态生成，不硬编码）
    States map[string]bool `json:"states"`
}
```

### 5.3 配置加载简化

```go
// internal/config/loader.go

// Load 加载配置（单一入口，统一处理默认值、校验、纠正）
func Load(path string) (*Config, error) {
    // 1. 读取文件
    data, err := os.ReadFile(path)
    if err != nil {
        return loadDefaults(), nil // 首次运行
    }
    
    // 2. 解析 JSON
    var cfg Config
    if err := json.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("配置解析失败: %w", err)
    }
    
    // 3. 应用默认值（统一在 defaults.go 中定义）
    applyDefaults(&cfg)
    
    // 4. 校验与纠正（统一逻辑）
    if err := validate(&cfg); err != nil {
        return nil, err
    }
    
    // 5. 安全铁律（不可关闭的功能）
    enforceSecurityRules(&cfg)
    
    return &cfg, nil
}

// applyDefaults 应用默认值（集中管理）
func applyDefaults(cfg *Config) {
    // 服务器
    if cfg.Server.Port == 0 {
        cfg.Server.Port = 18889
    }
    if cfg.Server.ListenAddr == "" {
        cfg.Server.ListenAddr = "127.0.0.1"
    }
    
    // 安全
    if cfg.Security.Mode == "" {
        cfg.Security.Mode = "normal"
    }
    cfg.Security.WAFEnabled = true // 铁律
    
    // 路由
    if cfg.Routing.SmartRouter.Enabled == nil {
        t := true
        cfg.Routing.SmartRouter.Enabled = &t
    }
    if cfg.Routing.SmartRouter.EpsilonStart == 0 {
        cfg.Routing.SmartRouter.EpsilonStart = 0.1
    }
    if cfg.Routing.SmartRouter.EpsilonMin == 0 {
        cfg.Routing.SmartRouter.EpsilonMin = 0.02
    }
    
    // 连接池
    if cfg.Pool.MaxIdleConnsPerHost == 0 {
        cfg.Pool.MaxIdleConnsPerHost = 32
    }
    if cfg.Pool.AdaptiveMin == 0 {
        cfg.Pool.AdaptiveMin = 5
    }
    if cfg.Pool.AdaptiveMax == 0 {
        cfg.Pool.AdaptiveMax = 200
    }
    
    // ... 其他默认值
}
```

### 5.4 配置迁移工具

提供迁移脚本，自动将旧版配置转换为新版格式：

```go
// scripts/migrate-config/main.go

func migrate(oldPath, newPath string) error {
    oldData, err := os.ReadFile(oldPath)
    if err != nil {
        return err
    }
    
    var oldCfg OldConfig // v4.3.0 结构
    if err := json.Unmarshal(oldData, &oldCfg); err != nil {
        return err
    }
    
    newCfg := convertToNewFormat(oldCfg)
    
    newData, err := json.MarshalIndent(newCfg, "", "  ")
    if err != nil {
        return err
    }
    
    return os.WriteFile(newPath, newData, 0644)
}
```

### 5.5 配置示例对比

**旧版配置**（字段分散）：
```json
{
  "cloud": { "openai": { "apiKey": "..." } },
  "security": { "mode": "normal", "wafEnabled": true },
  "v3Config": { "rateLimit": { "windowSec": 10, "maxReq": 120 } },
  "v32Config": { "pool": { "maxIdleConnsPerHost": 32 } },
  "v33Config": { "capabilities": { "autoReroute": true } }
}
```

**新版配置**（扁平化）：
```json
{
  "cloud": { "openai": { "apiKey": "..." } },
  "security": { "mode": "normal", "wafEnabled": true },
  "routing": {
    "smartRouter": { "enabled": true, "epsilonStart": 0.1 },
    "capability": { "autoReroute": true }
  },
  "pool": { "maxIdleConnsPerHost": 32, "adaptiveEnabled": true }
}
```

---

## 6. P2 级优化：性能与可观测性增强

### 6.1 参考架构：腾讯 NT 架构

**核心理念**：双进程架构，UI 与业务分离。

**借鉴点**：
- 将前端资源服务独立为静态文件服务器（可选 CDN）
- 后端专注 API 处理，减少 HTML 渲染开销

```go
// 优化前：前端嵌入后端
//go:embed frontend/*
var frontendFS embed.FS

// 优化后：前端独立部署（可选）
// 后端仅提供 API，前端由 Nginx/CDN 服务
```

### 6.2 参考架构：字节跳动双线程模型

**核心理念**：主线程处理业务，独立线程处理日志/监控。

**借鉴点**：
- 审计日志异步写入（当前是同步）
- 指标采集异步化，不阻塞请求链路

```go
// internal/observability/async_writer.go

// AsyncAuditWriter 异步审计日志写入器
type AsyncAuditWriter struct {
    queue   chan AuditEntry
    wg      sync.WaitGroup
    stopped atomic.Bool
}

// NewAsyncAuditWriter 创建异步写入器
func NewAsyncAuditWriter(bufferSize int) *AsyncAuditWriter {
    w := &AsyncAuditWriter{
        queue: make(chan AuditEntry, bufferSize),
    }
    w.wg.Add(1)
    go w.worker()
    return w
}

// Write 异步写入（非阻塞）
func (w *AsyncAuditWriter) Write(entry AuditEntry) {
    if w.stopped.Load() {
        return
    }
    select {
    case w.queue <- entry:
    default:
        // 队列满时降级：记录指标但不阻塞
        metrics.AuditDropped.Inc()
    }
}

func (w *AsyncAuditWriter) worker() {
    defer w.wg.Done()
    for entry := range w.queue {
        // 批量写入文件
        w.flush([]AuditEntry{entry})
    }
}
```

### 6.3 参考架构：阿里巴巴编译优化

**核心理念**：编译期优化，减少运行时开销。

**借鉴点**：
- 使用 `go build -ldflags="-s -w"` 减小二进制体积
- 启用 PGO（Profile-Guided Optimization）
- 使用 `sync.Pool` 复用对象

```go
// internal/pool/object_pool.go

// MessagePool 消息对象池（减少 GC 压力）
var MessagePool = sync.Pool{
    New: func() interface{} {
        return &Message{
            Content: make([]byte, 0, 4096),
        }
    },
}

// GetMessage 获取消息对象
func GetMessage() *Message {
    return MessagePool.Get().(*Message)
}

// PutMessage 归还消息对象
func PutMessage(m *Message) {
    m.Reset()
    MessagePool.Put(m)
}
```

### 6.4 连接池优化

当前连接池已实现自适应扩缩容，可进一步优化：

```go
// internal/pool/optimized_transport.go

// OptimizedTransport 优化的 Transport
type OptimizedTransport struct {
    *http.Transport
    
    // 预热连接（减少首次请求延迟）
    warmupHosts []string
    
    // 连接健康检查
    healthCheckInterval time.Duration
}

// Warmup 预热指定主机的连接
func (t *OptimizedTransport) Warmup(hosts []string) {
    for _, host := range hosts {
        go func(h string) {
            // 发送 HEAD 请求建立连接
            req, _ := http.NewRequest("HEAD", "http://"+h, nil)
            client := &http.Client{Transport: t.Transport, Timeout: 5 * time.Second}
            client.Do(req)
        }(host)
    }
}
```

### 6.5 可观测性增强

```go
// internal/observability/enhanced_metrics.go

// EnhancedMetrics 增强指标
type EnhancedMetrics struct {
    // 现有指标
    HTTPRequests    *prometheus.CounterVec
    RequestDuration *prometheus.HistogramVec
    
    // 新增指标
    // 1. 后端延迟分位数（P50/P95/P99）
    BackendLatencyP50 *prometheus.GaugeVec
    BackendLatencyP95 *prometheus.GaugeVec
    BackendLatencyP99 *prometheus.GaugeVec
    
    // 2. 连接池健康度
    PoolHealthScore prometheus.Gauge
    
    // 3. 模块使用热度
    ModuleUsageHeat *prometheus.CounterVec
    
    // 4. 错误分类统计
    ErrorsByCategory *prometheus.CounterVec
}
```

---

## 7. 业界参考架构

### 7.1 腾讯 NT 架构

**背景**：腾讯 QQ 团队在 2023 年推出的新架构，采用 Electron + 跨平台 C++ 内核。

**核心特点**：
- 双进程架构：UI 进程与业务进程分离
- 消息收发独立线程，不阻塞 UI
- 本地数据库独立进程管理

**TarsSecureGuard 借鉴**：
| 特性 | 腾讯 NT | TarsSecureGuard 应用 |
|------|---------|---------------------|
| 进程分离 | UI 与业务分离 | 前端静态化，后端专注 API |
| 消息线程 | 独立消息收发线程 | 审计日志异步写入 |
| 数据库 | 独立数据库进程 | 可选：状态持久化独立服务 |

### 7.2 字节跳动双线程模型

**背景**：字节跳动内部网关架构，采用双线程处理模型。

**核心特点**：
- 主线程：处理业务逻辑
- 辅助线程：处理日志、监控、指标上报
- 线程间通过无锁队列通信

**TarsSecureGuard 借鉴**：
| 特性 | 字节跳动 | TarsSecureGuard 应用 |
|------|----------|---------------------|
| 双线程 | 业务 + 日志分离 | 审计/指标异步化 |
| 无锁队列 | 高性能线程通信 | `chan` 缓冲区替代同步调用 |
| 降级策略 | 队列满时丢弃 | 指标采集降级不阻塞请求 |

### 7.3 阿里巴巴编译优化

**背景**：阿里巴巴在 Go 编译优化方面的实践。

**核心特点**：
- PGO（Profile-Guided Optimization）：基于运行时 profile 优化编译
- 对象池复用：减少 GC 压力
- 逃逸分析优化：减少堆分配

**TarsSecureGuard 借鉴**：
| 特性 | 阿里巴巴 | TarsSecureGuard 应用 |
|------|----------|---------------------|
| PGO | 编译期优化 | `go build -pgo=profile.pprof` |
| 对象池 | `sync.Pool` 复用 | Message、Buffer 对象池 |
| 逃逸分析 | 减少堆分配 | 审查热路径变量逃逸 |

### 7.4 其他参考

#### 7.4.1 Cloudflare Workers 架构

**核心特点**：
- 边缘计算，请求就近处理
- V8 Isolate 隔离，安全且高效
- 毫秒级冷启动

**借鉴点**：
- 模块化设计，每个功能独立部署
- 无状态设计，易于水平扩展

#### 7.4.2 Envoy Proxy 架构

**核心特点**：
- 插件化过滤器链
- 动态配置（xDS 协议）
- 完善的可观测性

**借鉴点**：
- 中间件链设计（已在本方案中采用）
- 配置热更新机制

---

## 8. 分阶段执行计划

### 8.1 阶段一：基础重构（第 1-4 周）

**目标**：完成 P0 代码组织重构，建立新目录结构。

| 周次 | 任务 | 产出 | 验收标准 |
|------|------|------|----------|
| W1 | 设计新目录结构，创建骨架 | 目录结构文档 | 团队评审通过 |
| W2 | 迁移无状态工具函数 | `internal/utils/` | 测试通过 |
| W3 | 迁移 security 模块 | `internal/security/` | WAF/RBAC 测试通过 |
| W4 | 迁移 routing 模块 | `internal/routing/` | 路由测试通过 |

**风险缓解**：
- 每周进行完整回归测试
- 保持旧代码可回退（Git 分支）

### 8.2 阶段二：中间件重构（第 5-6 周）

**目标**：完成 P1 中间件管道重构。

| 周次 | 任务 | 产出 | 验收标准 |
|------|------|------|----------|
| W5 | 设计中间件接口，拆分现有中间件 | 10+ 独立中间件 | 单元测试覆盖 |
| W6 | 集成测试，性能基准测试 | 测试报告 | 性能不退化 |

**风险缓解**：
- 新旧中间件并行运行（A/B 测试）
- 灰度发布，逐步切流

### 8.3 阶段三：配置简化（第 7 周）

**目标**：完成 P1 配置管理简化。

| 周次 | 任务 | 产出 | 验收标准 |
|------|------|------|----------|
| W7 | 设计新配置结构，编写迁移工具 | 迁移脚本 + 文档 | 迁移成功率 100% |

**风险缓解**：
- 提供配置回滚机制
- 兼容旧配置格式（过渡期）

### 8.4 阶段四：性能优化（第 8-9 周）

**目标**：完成 P2 性能优化。

| 周次 | 任务 | 产出 | 验收标准 |
|------|------|------|----------|
| W8 | 审计日志异步化 | AsyncAuditWriter | 延迟降低 50% |
| W9 | 连接池预热、对象池 | 优化代码 + 基准测试 | P99 延迟降低 20% |

**风险缓解**：
- 性能基准测试对比
- 监控指标无异常

### 8.5 阶段五：UI 现代化（第 10-15 周，可选）

**目标**：前端技术栈升级。

| 周次 | 任务 | 产出 | 验收标准 |
|------|------|------|----------|
| W10-11 | 技术选型，架构设计 | 设计文档 | 团队评审通过 |
| W12-14 | 开发新前端 | React/Vue 应用 | 功能完整 |
| W15 | 集成测试，上线 | 生产环境 | 用户验收通过 |

**风险缓解**：
- 新旧前端并行运行
- 用户反馈收集

### 8.6 里程碑总览

```
Week 1-4:   [████████████████] P0 代码组织重构
Week 5-6:   [████████]        P1 中间件管道重构
Week 7:     [████]            P1 配置管理简化
Week 8-9:   [████████]        P2 性能优化
Week 10-15: [████████████████████████] P2 UI 现代化（可选）
```

---

## 9. 风险评估与缓解措施

### 9.1 风险矩阵

| 风险 | 概率 | 影响 | 等级 | 缓解措施 |
|------|------|------|------|----------|
| 迁移引入 Bug | 中 | 高 | 🔴 高 | 完整测试覆盖，灰度发布 |
| 性能退化 | 低 | 高 | 🟡 中 | 基准测试对比，监控告警 |
| 团队不熟悉新结构 | 中 | 中 | 🟡 中 | 文档 + 培训 + 代码审查 |
| 配置迁移失败 | 低 | 高 | 🟡 中 | 回滚机制，兼容旧格式 |
| CI/CD 配置失效 | 低 | 中 | 🟢 低 | 提前更新，本地验证 |

### 9.2 回滚策略

每个阶段都设计回滚点：

```
阶段 1 回滚：Git 分支切换回旧结构
阶段 2 回滚：中间件链配置开关，切回单体中间件
阶段 3 回滚：配置格式兼容，旧配置仍可用
阶段 4 回滚：性能优化代码开关，关闭异步化
阶段 5 回滚：新旧前端并行，切回旧前端
```

### 9.3 成功标准

| 指标 | 当前值 | 目标值 | 衡量方式 |
|------|--------|--------|----------|
| 代码导航时间 | ~15 min | ~5 min | 新人调研 |
| 单元测试覆盖率 | ~30% | 70%+ | CI 报告 |
| P99 延迟 | 基准值 | -20% | 性能测试 |
| 连接复用率 | ~70% | 90%+ | 指标监控 |
| 新功能开发周期 | 基准值 | -30% | 项目跟踪 |

---

## 附录 A：术语表

| 术语 | 说明 |
|------|------|
| **Chain of Responsibility** | 责任链模式，请求沿链传递，每个处理器决定是否处理 |
| **Strangler Fig Pattern** | 绞杀者模式，逐步替换旧系统，而非一次性重写 |
| **Clean Architecture** | 整洁架构，按领域划分，依赖指向内部 |
| **PGO** | Profile-Guided Optimization，基于运行时 profile 的编译优化 |
| **ε-greedy** | 探索-利用策略，以 ε 概率探索，1-ε 概率利用最优选择 |

---

## 附录 B：参考资源

1. **Go 项目标准布局**: https://github.com/golang-standards/project-layout
2. **Clean Architecture in Go**: https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html
3. **Envoy Proxy 架构**: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/
4. **腾讯 QQ NT 架构**: https://mp.weixin.qq.com/s/xxx
5. **Go 性能优化指南**: https://go.dev/doc/perf

---

*文档结束*
