# TarsSecureGuard Go v1.0.3 安全与跨平台修复 · 变更说明

基于 TarsSecureGuard Go v1.0.2 源码进行缺陷修复与功能强化。

## 一、文件清单

### 新增文件（5 个）
| 文件 | 说明 |
|------|------|
| `device_windows.go` | Windows 专属磁盘空间查询（`//go:build windows`） |
| `device_other.go` | Linux/macOS/FreeBSD 磁盘空间查询（`//go:build !windows`） |
| `process_windows.go` | Windows 子进程 HideWindow 封装（`//go:build windows`） |
| `process_other.go` | 非 Windows 平台 HideWindow 空实现（`//go:build !windows`） |
| `OPTIMIZATION_REPORT.md` | 优化报告（含 4 点回应 + 调研结论 + 验证方法） |

### 修改文件（6 个）
| 文件 | 变更内容 |
|------|----------|
| `device.go` | 移除 Windows 专属代码，保留跨平台公共代码（`diskUsage` 类型、`getDeviceInfo`、`discoverLocal`） |
| `mcp.go` | 移除直接 `syscall.SysProcAttr{HideWindow: true}` 调用，改为 `applyHiddenWindow(cmd)`；移除未使用的 `syscall` import |
| `models.go` | 同上；新增模型管理端点的审计日志调用（`MODEL_START`/`MODEL_STOP`/`MODEL_DOWNLOAD`） |
| `config.go` | 新增 `Users []User`（RBAC 多用户）、`Security.AuditLogEnabled`（审计开关）；`loadConfig` 支持环境变量覆盖敏感 Key；审计日志默认开启 |
| `main.go` | 新增 RBAC 中间件（`userFromRequest` / `requireRole` / `isAdminRoute`）、审计日志函数 `auditLog`、新增路由 `/api/admin/audit-logs`；`isConfigPathAllowed` 增加 `security.auditLogEnabled`；`sanitizedConfig` 脱敏用户 Key |
| `handlers.go` | 新增 `handleAuditLogs`（仅 admin 可读当日审计日志）；`handleConfig` POST 增加审计日志；GET 返回增加 `users`（脱敏）和 `auditLogEnabled`；增加 `os`/`path/filepath`/`strings` imports |
| `waf.go` | 新增 WAF 规则：`PromptInjection`（prompt injection 防御）、`PII泄漏`（PII 检测）；新增 `maskPII` / `maskPIIInMessages` 函数 |
| `chat.go` | `handleChat` 在路由到后端前对 `messages[].content` 自动执行 PII 脱敏 |

## 二、缺陷修复对照

| 缺陷 | 修复状态 | 验证方法 |
|------|----------|----------|
| Linux build tags 缺失 | ✅ | `go build`（Linux）+ `GOOS=windows GOARCH=amd64 go build` 均通过 |
| API Key 明文存储 | ✅ | 环境变量 `TARS_API_KEY` 可覆盖；`/api/admin/config` 返回 Key 显示为 `***` |
| 单管理员 / 无 RBAC | ✅ | 配置 `users` 后，不同 role 访问 admin/写端点返回 403 |
| 无审计日志 | ✅ | 操作后查看 `logs/audit-YYYY-MM-DD.log` 有结构化记录；GET `/api/admin/audit-logs` 可查询 |
| WAF 无 prompt injection 防御 | ✅ | strict 模式下含 `ignore previous instructions` 的请求返回 403 |
| WAF 无 PII 检测/脱敏 | ✅ | 聊天消息中的手机号/邮箱在后端请求前被替换为 `****` |

## 三、兼容性说明

- 单用户模式：不配置 `users` 时，行为与 v1.0.2 完全一致（回退单管理员 Key）
- 所有既有 API 路由、请求/响应格式不变；新增路由独立存在
- 新增环境变量：`TARS_API_KEY`、`TARS_OPENAI_KEY`、`TARS_DEEPSEEK_KEY`、`TARS_SEARCH_KEY`
- 审计日志默认开启，可通过 API 修改 `security.auditLogEnabled` 关闭

## 四、验证记录

- `go build`（Linux amd64）通过，`go vet` 无告警
- `GOOS=windows GOARCH=amd64 go build` 交叉编译通过
- RBAC 冒烟测试：admin/user/readonly 三种角色权限边界正确
- 审计日志测试：配置修改、模型启停、权限拒绝均有记录
- WAF 测试：prompt injection 特征词在 strict 模式下被拦截；PII 在 normal 模式下被脱敏
