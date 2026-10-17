# 顶层 .go 文件归位方案

> 审计日期：2026-10-15
> 审计人：工部尚书
> 基线 commit：7d6ca6a

---

## 现状

根目录共有 **114 个 `.go` 文件**，全部为 `package main`。其中包括：

- 业务逻辑文件（~70 个）：`waf.go`、`gatekeeper.go`、`router.go`、`handlers.go` 等
- 平台适配文件（~20 个）：`*_windows.go`、`*_unix.go`、`*_darwin.go`、`*_linux.go`、`*_other.go`
- 版本测试文件（~24 个）：`v301_test.go` ~ `v476_test.go`

## 为什么现在不能简单移动

### 1. 单包约束

Go 规定：**同一目录下所有 `.go` 文件必须属于同一个 package**。当前根目录所有文件都是 `package main`，它们之间可以自由调用彼此的**未导出**（小写开头）函数和变量。

若按 `internal/<domain>/` 模式拆分，需要：
- 每个子目录声明独立 package 名（如 `package security`、`package waf`）
- 原来在 `package main` 中互相调用的函数，如果跨包使用，必须改为**导出**（大写开头）
- 涉及约 **70+ 个业务文件**、**数百个未导出符号**的可见性变更

### 2. 循环依赖风险

当前 `package main` 中所有文件互相可见，没有包边界。拆分后可能出现：

```
internal/security/waf.go  →  internal/router/router.go
internal/router/router.go  →  internal/security/waf.go   # 循环依赖
```

需要预先进行依赖图分析，识别循环依赖环，设计接口层解耦。

### 3. 构建验证成本

拆分后必须验证：
- `go build ./...` 全平台通过（6 个 GOOS/GOARCH 组合）
- `go test -race ./...` 全绿
- 前端 embed 路径不变（`//go:embed frontend/index.html`）
- Tauri sidecar 构建路径不变（`src-tauri/binaries/`）

任何遗漏都会导致 release pipeline 失败。

---

## 推荐分步实施方案

### Phase 1：测试文件归位（低风险，可立即做）

将版本测试文件按大版本分组：

```
v3xx_test.go  →  internal/test/v3/
v4xx_test.go  →  internal/test/v4/
```

这些测试文件只测试历史功能，不引用根目录的未导出符号（它们通过 `httptest` 和公开 API 测试），移动风险最低。

### Phase 2：平台适配文件归位（低风险）

按 OS 分组：

```
*_windows.go       →  internal/platform/windows/
*_unix.go / *_linux.go / *_darwin.go  →  internal/platform/unix/
*_other.go         →  internal/platform/common/
```

平台文件通常只被主包通过 build tag 条件编译引用，跨包依赖少。

### Phase 3：纯工具/独立模块归位（中风险）

识别无外部依赖或依赖极少的文件：

```
doctor.go           →  internal/doctor/        # 独立 CLI 诊断
crownext/bench/     →  internal/bench/         # 已是子目录，可继续拆分
kingdom/            →  已是独立包，保持现状
```

### Phase 4：核心业务域拆分（高风险，需专门版本）

按领域拆分主体代码，建议在一个专门的 **v5.0.0** 或 **仓库整理专项版本** 中实施：

```
internal/
  security/
    waf.go              # WAF + PII
    gatekeeper.go       # 守门人
    semanticguard.go    # 语义防护
    ssrfguard.go        # SSRF 防护
    firewall*.go        # 防火墙
    whitelist.go        # 白名单
    selfprotect*.go     # 自保护
  routing/
    router.go           # 智能路由
    adapters.go         # 协议适配
    connectors.go       # 连接器
    direct.go           # 直连层
  auth/
    oauth*.go           # OAuth/OIDC
    tenant.go           # 多租户 RBAC
    ratelimit.go        # 限流
  infra/
    config.go           # 配置管理
    logging.go          # 日志管线
    observability.go    # 可观测性
    pool.go             # 连接池
    circuit.go          # 熔断器
    auditv2.go          # 审计链
  api/
    handlers.go         # HTTP handler
    web.go              # Web 服务
    chat.go             # 聊天处理
    mcp*.go             # MCP 协议
  domain/
    modules.go          # 模块注册表
    models.go           # 模型管理
    providers/          # provider 注册表（已是子目录）
    agents.go           # Agent 系统
    persona.go          # 职业系统
    langprobe.go        # LangProbe
    i18n*.go            # 国际化
    memory.go           # 共享记忆
    sharedinfo.go       # 共享信息
    knowledgebase.go    # 知识库
    tools.go            # 工具系统
    customtools.go      # 自定义工具
    contextmcp.go       # 上下文 MCP
    extender.go         # 扩展器
    scoreboard.go       # 评分榜
    hardware*.go        # 硬件评估
    device*.go          # 设备信息
    resourceguardian.go # 资源守护
    tokenmeter.go       # Token 测量
    stability.go        # 稳定性
    iprep.go            # IP 信誉
    dynadef.go          # 动态防御
    clientlauncher.go   # 客户端启动器
    avcompat*.go        # 杀软兼容
```

### Phase 5：main.go 瘦身

最终 `main.go` 只保留：
- `func main()` 入口
- `//go:embed` 指令
- 全局变量声明（迁移到 `internal/app/`）
- 路由注册（调用各包的 `RegisterRoutes`）

---

## 实施建议

1. **不要在本任务中强行实施** —— 涉及 114 个文件、数百个符号的可见性变更，一次改错会导致构建失败。
2. **建议单独开一个版本**（如 v4.10.0「仓库结构整理」或 v5.0.0）专门做这件事。
3. **先画依赖图** —— 用 `go list -deps` / `godepgraph` 生成包依赖图，识别循环依赖。
4. **逐包迁移、逐包验证** —— 一次只迁移一个领域，确保 `go build` + `go test -race` 全绿后再迁下一个。
5. **保留根目录的 `package main` 存根** —— 在迁移完成前，根目录保留一个薄 `main.go` 导入所有 internal 包。

---

## 立即可以做的低风险整理

以下操作不涉及 Go 包拆分，可立即执行：

| 操作 | 文件 | 目标 |
|------|------|------|
| 删除旧 SHA256SUMS | `SHA256SUMS-v4.2.0.txt`、`SHA256SUMS-v4.6.1.txt` | 根目录只保留当前 `SHA256SUMS.txt` |
| 归档杂文档 | `OPTIMIZATION_REPORT.md`、`SECURITY-AUDITS.md`、`COMPATIBILITY.md` | 移入 `docs/` |
| 删除孤本 | `CHANGELOG-v4.1.0.md` | 内容已并入主 `CHANGELOG.md` |
| 建立规范 | `VERSIONING.md`、`CHANGELOG.md`、`.github/RELEASE_TEMPLATE.md` | 新增 |
| 自动化 | `.github/workflows/changelog.yml` | Release published 自动更新 CHANGELOG |
