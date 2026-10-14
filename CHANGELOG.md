# Changelog

所有 TarsSecureGuard 的显著变更都记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

---

## [Unreleased]

### Planned
- 仓库结构整理（VERSIONING.md / CHANGELOG.md / RELEASE_TEMPLATE.md / 文档归档）
- 顶层 `.go` 文件归位分析（`internal/<domain>/` 模式评估）

---

## [4.9.0] - 2026-10-14

### Added
- **Kingdom Animal Taxonomy Architecture**：动物分类学模块组织（界→门→纲→目→科→属→种，≥5 层）
- **Protectiva（防护层）**：WAF、外网防护、MCP 扫描、传输加密、动态防御、实时监控
- **Functionalis（功能层）**：聊天/模型/工具/连接器协调引擎
- **Frontend（前端层）**：UI 框架与仪表盘统一入口
- **Backend（后端层）**：API 网关与存储抽象
- **LangBridge**：多语言探测与桥接（Go/Python/PowerShell/Node.js/eBPF）

---

## [4.8.0] - 2026-10-14

### Added
- **LangProbe 多语言深度集成框架**

---

## [4.7.8] - 2026-10-14

### Fixed
- 从 v4.7.7 的补丁修复（详见 commit 对比）

---

## [4.7.6] - 2026-10-13

### Performance
- WAF UA 扫描优化：30 个扫描器 UA 关键词合并为单条正则，启动时编译一次
- `sync.Map` 缓存：同一 UA 第二次直接查表，避免重复正则开销；miss 也缓存空串

---

## [4.7.5] - 2026-10-13

### Security
- 全请求头 CRLF/NULL 注入检测：扫描 `r.Header` 所有键值对，任一 value 含 `\r`、`\n`、`\x00` 即拦截
- 拦截信息含字段名，响应/审计可见具体 header-name，便于安全团队定位

---

## [4.7.4] - 2026-10-13

### Improved
- 401 错误本地化 + hint 引导：响应里增加 `hint` 字段，告诉用户怎么填密钥、密钥从哪来（zh/en 自动匹配）
- `main.go` 401 走 i18n：原本硬编码的「unauthorized」改为按 `Accept-Language` 返回中英文 + 引导 hint

---

## [4.7.3] - 2026-10-12

### Added
- 多语言兜底：内置 zh/en 消息映射，`Accept-Language` 解析
- 系统日志跨平台抽象层（Unix syslog / Windows EventLog）
- 防自关保护：非管理员运行时拦截关闭信号
- 安全软件兼容：检测 360/火绒/Defender，自动添加信任
- 前端：i18n、语言切换、AV 兼容面板、网关关闭按钮

---

## [4.7.2] - 2026-10-12

### Security
- HTTP server 显式设置 `ReadHeaderTimeout=10s`，与现有 `ReadTimeout`/`WriteTimeout` 形成三层超时
- 防 Slowloris 慢连接攻击：header 读取阶段即触发超时，释放 server 资源

---

## [4.7.1] - 2026-10-12

### Security
- WAF Host 头注入检测：拒绝含 CRLF（`\r\n`）或 NULL 字节（`\x00`）的 Host 头
- HTTP 请求走私检测：检测同时存在 `Content-Length` 与 `Transfer-Encoding` 头的请求（CL+TE 向量）

---

## [4.7.0] - 2026-10-12

### Added
- GitHub Pages 官方三站（介绍站 / 下载站 / 性能监控站）
- README 新增 6 语言版本（EN / RU / AR / FR / JA / KO）
- 红蓝对抗渗透测试报告 7 语言版
- 安装器加固：统一资产命名、SHA256 校验、桌面快捷方式（Linux .desktop / macOS .command / Windows .lnk）
- 基准死锁修复：`crownext/bench/harness.go` 改为手动计时 + `runtime.MemStats`

---

## [4.6.3] - 2026-10-11

## [4.6.2] - 2026-10-11

## [4.6.1] - 2026-10-11

## [4.6.0] - 2026-10-11

### Added
- 客户端下载器主线：多平台构建 + Release 资产自动发布（`release.yml`）

---

## [4.5.3] - 2026-10-10

---

## [4.5.0] - 2026-10-10

### Added
- 完整性能评价体系：基准 harness + 回归基线 + 趋势看板（吞吐/延迟/资源占用/各模块热点/退化曲线）

---

## [4.4.0] - 2026-10-09

### Security
- 火绒/360 风格最坏情况加密兜底：分层加密 + 启动验证哨兵 + 透明加密 + 防内存转储方案 A+B

---

## [4.3.0] - 2026-10-09

### Added
- 安全性能评价系统：动态防护 + 静态防护，5 文件 33 测试 -race 全绿

---

## [4.2.0] - 2026-10-09

### Added
- Android MVP：纯 Go 交叉编译 arm64 + Kotlin 壳子 App（启动/停止/状态/持久化/日志导出）

---

## [4.1.0] - 2026-10-09

### Added
- 系统兼容补齐方案：每个 release 补齐跨平台二进制（linux/darwin/windows × amd64/arm64）

---

## [4.0.0] - 2026-10-08

### Changed
- **Kingdom 架构重写**：Crown Envelope / Pipeline / Bus + 12 节点 + 26 职业 + Token 策略
- 王冠架构：模块间通过 Crown Bus 通信，节点化组织代码

---

## [3.9.0] - 2026-10-07

---

## [3.8.0] - 2026-10-07

### Added
- 内置职业系统：学生 / 文字创作者 / 开发者 / 研究者 / 通用，5 种角色一键切换
- 职业自动配置：自动应用模块开关、推荐 MCP 工具、写入共享记忆与共享信息
- 调用链优化：按职业自动调整 temperature / max_tokens / 重试策略 / 超时
- 模型库自动匹配：扫描已配置模型生成功能矩阵，按职业需求排序

---

## [3.7.0] - 2026-10-06

### Added
- Extender 模块：7 目标探测 + 接入片段生成
- 密钥占位 / 显式内嵌 + 审计
- RooCode 停摆警示 + ZooCode 引导

---

## [3.6.0] - 2026-10-05

### Added
- 统一安装器：`install.sh`（Linux/macOS）+ `install.ps1`（Windows），自动识别架构
- 官方引流站：`site/index.html` 单页官网，SEO 基线，GitHub Pages 即用

---

## [3.5.0] - 2026-10-05

### Added
- 裁剪档案：内置 5 档（minimal/standard/full/privacy/lowspec），BFS 传递闭包补全依赖
- 自适应建议引擎：结合硬件档位、使用习惯与 Token 成本生成模块开关建议
- 新手 / 高阶界面模式：`ui.mode` beginner 仅保留核心 6 页

---

## [3.4.0] - 2026-10-04

### Added
- 连接器生态：内置 8 个模板（github_repo / webhook_notify / weather 等），参数展开 + SSRF 五红线
- Token 测量器：进程内环形缓冲 + 按天/按模型聚合，23 个云端 provider 内置定价
- 工具链路降耗：tools schema 出站瘦身，节省 tokens 进测量器

---

## [3.3.0] - 2026-10-04

### Added
- custom 协议适配器：任意后端接入，模板化声明，多模态全链路
- 模型能力库与能力感知路由：vision/tools/longContext/json/reasoning 标签，自动改道
- API 申请直达：24 个云端 provider 补 `applyUrl`

---

## [3.2.4] - 2026-10-04

### Added
- 治理层前端可视化：治理总览 / 共享记忆 / 共享信息 / 审计链 v2 四页面全部接真实 API

### Fixed
- 版本徽章漂移：侧边栏静态 "v3.2.1" 修正为 v3.2.4
- 共享信息页输入框与列表容器 ID 冲突（`si-content` → `si-body`）

---

## [3.2.3] - 2026-10-04

### Performance
- WAF 合并正则 + ASCII 触发字节预筛：纯中文正文 strict 扫描 474µs → 0.99µs（-99.8%）
- PII 脱敏四模式单遍化：97µs → 81µs（-15%）
- 响应缓存 16 分片锁：并发 get/put 206ns → 186ns（-10% @ 2 核）

---

## [3.2.2] - 2026-10-04

### Added
- 共享记忆：三层命名空间（user/tenant/global），就近覆盖解析链
- 共享信息：结构化知识条目（fact/preference/note/link），加权检索
- 上下文拓展 MCP：`tars_context_build` 确定性上下文包
- OAuth / OIDC 接入：Authorization Code + PKCE（S256），手写标准库 JWT 验签
- 守门人：动作级防线，内置规则 + 自定义收紧-only，两阶段确认
- 审计升级 v2：hash-chain（SHA256），`/api/admin/audit/verify` 全链重算

### Performance
- 日志常开句柄管线：单行落盘 4004ns → 832ns（-79%）
- 连接池覆盖补全：doctor / web fetch 接入共享 Transport
- tier1 正则包级预编译

---

## [3.2.1] - 2026-10-04

### Added
- 桌面客户端（Tauri 2）：原生窗口零浏览器依赖，Sidecar 外嵌 Go 网关
- `--no-browser` 启动标记，`TSG_APP_DIR` 环境变量覆盖数据目录
- 三平台安装包：Windows NSIS / macOS universal dmg / Linux deb + AppImage

---

## [3.2.0] - 2026-10-04

### Added
- provider-registry：24 云端 + 8 本地运行时内置注册
- 共享连接池：复用率 98.5%（800 并发出站）
- 熔断器：closed/open/half-open 三态，连续 5 次失败熔断 30s
- 两级缓存：协议适配缓存 + 租户隔离响应缓存
- 协议适配器：openai-compat / anthropic / gemini / ollama 原生

### Performance
- 出站顺序 P99 177µs → 107µs（-40%）
- 并发 16×50 P99 2536µs → 1855µs（-27%）

---

## [3.0.5] - 2026-09-29

### Added
- Prometheus `/metrics`：15 指标族（QPS/延迟/WAF/路由/资源/模块/配额/uptime）
- 分布式 trace_id 全链路：16-hex 随机，响应头回显，出站转发
- `tsg doctor` 自诊断 CLI：7 大类 18 项检查，退出码 0/1/2
- Grafana dashboard 模板：23 面板四行布局

---

## [3.0.4] - 2026-09-29

### Security
- 零信任白名单基线：默认密钥显式化、IP 白名单值域校验、文件根绝对路径、变更审计
- 多租户 RBAC：7 角色（admin/user/readonly/team_lead/auditor/global_admin/global_auditor），7×9 端点类矩阵
- 三层日配额：租户/用户/组，级联收紧 cascadeClampTenants
- 审计按组视图：行级强制过滤，跨租户查询记 `AUDIT_CROSS_TENANT_ACCESS`

---

## [3.0.1] - 2026-09-29

### Added
- Tier 1 系统原生命令探测：`tier1.go` + 平台执行器，exec.Command 数组式 argv，3 秒超时
- sidecarHub 外置模块宿主：manifest + SHA-256 钉扎 + 低权限代理 + 生命周期监管

### Security
- Tier 1 七条红线：强制审计、缓存 HMAC 防篡改、白名单精确匹配、熔断降级、权限不足即降级不自动提权

---

## [3.0.0] - 2026-09-28

### Added
- 资源守护器：GOMEMLIMIT 软上限，L0-L3 分级响应状态机
- 语义检测分级分流：静态规则 + 灰区送本地小模型，fail-close
- 三维令牌桶限流 + 本地 IP 信誉评分
- 两阶段智能路由：静态规则 + ε-greedy bandit
- MCP stdio：JSON-RPC 2.0 over stdio，6 个工具

---

## [2.1.0] - 2026-09-28

### Fixed
- Linux/macOS 硬件评估磁盘分恒为 0：平台感知 `exeDrive()`
- GPU 检测单路径阻塞：每平台主探测 + 回退探测 + 超时
- Linux 动态链接 glibc：`CGO_ENABLED=0` 全平台纯静态

### Performance
- 构建精简：`-ldflags "-s -w"` + `-trimpath`，体积下降 29.3%~31.2%

---

## [2.0.0] - 2026-09-27

### Added
- 模块化重构：17 个可选模块进注册表，security-core 强制加载不可关闭
- 防火墙三档策略：passive / dynamic-ban / os-link
- 直连层切换点：`direct.transport: native | grpc-sidecar`
- customTools：自定义 HTTP 转发工具，SSRF 五红线
- 硬件水平检测：四维评分 + S/A/B/C/D 评级 + 模型档位推荐

---

## [1.0.3] - 2026-09-27

### Security
- API Key 明文存储 → 环境变量覆盖 + 脱敏
- 单管理员 → RBAC 多用户（admin/user/readonly）
- 审计日志：结构化 JSONL，`/api/admin/audit-logs` 查询
- WAF PromptInjection 防御 + PII 检测/脱敏

### Fixed
- Linux build tags 缺失：设备/进程平台拆分文件
