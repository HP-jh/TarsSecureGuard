# TarsSecureGuard v4.26.0 · 错误信息人话化（30 个常见错误）

> 小白化核心升级：把 "blocked by WAF: 路径穿越" 翻译成 "你输入的内容里包含危险的路径穿越尝试，系统已自动拦截"。

## 一、后端：错误码映射系统（humanize.go）

- **30 个错误码全覆盖**：WAF 14 条 + 权限配额 4 条 + 请求格式 5 条 + 语义安全 3 条 + 网关通用 2 条 + 兜底 2 条
- **中英双语人话**：每条错误含 "人话说明" + "建议操作"，默认中文、英文兜底
- **智能语言检测**：优先 Accept-Language 头，其次 Cookie `tsg_lang`，默认中文
- **自动分类**：`classifyError()` 根据原始错误消息自动推断错误码，零侵入现有代码
- **结构化返回**：JSON 新增 `code` + `human` + `suggestion` 字段，原始 `error` 保留向后兼容

## 二、API 全链路接入

- WAF 拦截（`blockRequest`）→ `wafBlockHumanized`
- RBAC 权限拒绝 → `writeHumanizedJSONStatus`
- 配额超限 → `writeHumanizedJSONStatus`
- 请求格式错误（POST only / invalid JSON / server not found）→ `writeHumanizedJSONStatus`
- 语义引擎拦截 / 不可用 → `writeHumanizedJSONStatus`
- Panic 恢复 → `writeHumanizedJSONStatus`
- CORS 来源拒绝 → `writeHumanizedJSONStatus`

## 三、前端：优先展示人话错误

- `api()` 函数在 `!r.ok` 时优先读取响应体 `human` 字段，fallback 到状态码人话
- 如果后端返回 `suggestion`，自动拼接在 toast 消息中（"说明 · 建议"）
- 错误 toast 保留手动关闭按钮（`type==='err'`），方便用户仔细阅读

## 四、质量

- `go build` 通过
- `go test -race` 全绿

---

# TarsSecureGuard v4.20.4 · 前端空状态文案优化 + 安全响应头

> v4.20.x 为 UI/安全/小白化每周小版本系列（2026-10-18）。

## v4.20.4
- 前端空状态文案优化：零数据场景提示语人话化，减少技术术语

## v4.20.3
- 前端响应安全头加固：`Content-Security-Policy` / `X-Frame-Options` / `X-Content-Type-Options` 等基线头注入

## v4.20.2
- `doctor` 模块嵌入描述修正 + 版本同步测试补强

## v4.20.1
- 绊线检测误报基准测试：降低合法流量误触发率

## v4.20.0
- `go:embed` 完备性测试：确保所有嵌入资源在编译期完整打包
- 版本号同步 bump

---

# TarsSecureGuard v4.19.3 · 构建元数据暴露 + 静态资源路由

## v4.19.3
- `/api/status` 新增构建元数据：go version / build time / git commit 等运行时可见

## v4.19.2
- 泛化 `/static/` 前端资源路由：支持任意子目录静态文件服务
- 版本同步测试修复

## v4.19.1
- `i18n.js` 嵌入并可服务：多语言翻译表进 embed，前端按需加载

## v4.19.0
- 版本 bump + health endpoint 超时测试

---

# TarsSecureGuard v4.18.0 · Unicode 转义解码 + 绊线检测修复

- Unicode 转义序列解码修复：某些后端返回 `\uXXXX` 格式时正确还原为中文字符
- 绊线检测（tripwire）误报修复：调低敏感阈值，减少正常请求误触发
- 前端提示语重写：进一步小白化

---

# TarsSecureGuard v4.17.0 · Community Marketplace（社区市场）

> 对应项：MCP 社区生态扩展，允许用户订阅第三方 MCP 包来源。

## 一、社区市场后端（pkg/mcp/community/）

- **来源注册表**：支持 GitHub releases / HTTP tarball / 本地目录 三种来源类型
- **包聚合器**：多来源去重、版本排序、元数据归一
- **验证器**：SHA256 校验 + 签名验证 stub + 100MB 包上限
- **信任徽章**：官方来源 / 社区验证 / 未验证 三级可视化
- **审计日志**：`mcp-community.log` 记录所有安装/更新/验证事件

## 二、API（10 端点）

- `GET/POST/DELETE /api/admin/mcp/community/sources` — 来源 CRUD
- `POST /api/admin/mcp/community/sources/{id}/refresh` — 单源刷新
- `POST /api/admin/mcp/community/refresh-all` — 全源刷新
- `GET /api/admin/mcp/community/packages` — 包列表（支持过滤/排序）
- `GET /api/admin/mcp/community/packages/{id}` — 包详情
- `POST /api/admin/mcp/community/packages/{id}/download` — 下载安装
- `POST /api/admin/mcp/community/packages/{id}/verify` — 手动校验

## 三、前端

- MCP 市场页新增「官方集成 / 社区」Tab 切换
- 来源卡片：类型图标 + URL + 最后刷新时间 + 包数量
- 包列表：名称 / 版本 / 描述 / 来源 / 信任徽章
- 添加来源对话框：类型选择 + URL 输入 + 即时验证

## 四、安全

- personal 角色安装社区包需二次确认
- SHA256 不匹配拒绝安装
- 签名验证框架预留（待社区公钥基础设施成熟后启用）

## 五、质量

- `go test -race ./pkg/mcp/community/...` 绿（registry CRUD / verifier SHA256 / trust badges）

---

# TarsSecureGuard v4.16.0 · MCP Marketplace + 15 独立仓库

> 对应项：MCP 官方集成市场 + 14 个 MCP 集成仓库独立发布。

## 一、MCP 官方集成市场

- 管理台新增「MCP 市场」页面：官方集成列表、一键启用/禁用、配置参数表单
- 14 个官方 MCP 集成全部上架：TarsBifrost / TarsPortkey / TarsDify / TarsLangChain / TarsLiteLLM / TarsOneAPI / TarsRAGFlow / TarsAutoGPT / TarsHigress / TarsN8N / TarsMem0 / TarsOpenWebUI / TarsOWASPAgentic / TarsWazuh
- 每个集成含：图标、简介、版本兼容性、配置项说明、启用开关

## 二、14 个 MCP 集成仓库独立

- 原 `pkg/mcp/` 子目录拆分为 14 个独立仓库（github.com/HP-jh/Tars*）
- 各仓库独立版本号、独立 README、独立 Release
- TSG 主仓库通过 go module replace 或 registry 引用

---

# TarsSecureGuard v4.15.1 · 交互 + 文档 + UI（补丁）

- 文档措辞微调 + 前端交互细节修复

---

# TarsSecureGuard v4.15.0 · 交互 + 文档 + UI

- 交互一致性提升：按钮状态、表单验证、错误提示统一
- 文档增量更新：README 架构图更新、安装指引细化
- UI 视觉统一：空状态插图、加载动画、错误页面风格统一

---

# TarsSecureGuard v4.14.0 · 自动更新系统

> 对应项：所有 6 个 TSG 系列仓库内置自动更新能力。

## 一、tars-update 独立模块

- `tars-update` 独立 Go module，6 仓库统一 import
- `stable_versions.json` 跨仓库统一版本表（GitHub Releases 源）
- 更新流程：检查 → 下载 → SHA256 校验 → 原子替换 → 自重启
- 解析失败自动回退稳定版本
- 极致档（strict）2FA 升级确认

## 二、集成仓库

- TSG / TarsEnterprise / TarsUITarsBridge / TarsOpenClawSandbox / TarsOpenClawSDK / TSGMemOptimizer 全部内置
- `tars-update check` / `tars-update update` / `tars-update rollback` CLI

---

# TarsSecureGuard v4.13.0 · 万物皆 MCP + 企业互操作

> README 全面重写——13 客户端 × 24 provider + 8 本地 + 任意 MCP 桥 + LobeHub 7 点 + TarsEnterprise 互操作 + TarsOpenClawSandbox + 知识库 + Obsidian + 语音纠错 + 万物皆 MCP 🚀

## 一、README 重构

- 11 badges（version / Go 1.23 / 0 deps / 7 platforms / MCP / Enterprise interop / KB / tests / pen-test / SHA256 / MIT）
- 产品定位：「AI 时代的路由器」→「万物皆 MCP」生态叙事
- 架构与核心能力：K 段按当前版本裁剪
- 横向对比：vs LiteLLM / One API / OpenRouter
- 安装与快速开始

## 二、TarsEnterprise 互操作端点

- `/api/enterprise/v1/interop/status` — 互操作状态查询
- `/api/enterprise/v1/interop/sync` — 双向数据同步
- 企业级知识库互通、配额共享、审计日志汇聚

---

# TarsSecureGuard v4.12.0 · 知识库 v2 + Obsidian + 语音纠错

## 一、知识库 v2

- 向量检索升级：支持多维度混合检索（关键词 + 语义 + 标签）
- 知识条目版本历史：增删改查全版本回溯
- 企业知识库互通（与 TarsEnterprise v0.2.0+ 对接）

## 二、Obsidian 集成

- Obsidian 插件：一键导出笔记到 TSG 知识库
- 双向同步：Obsidian 修改自动回流 TSG
- 标签映射：Obsidian tags → TSG 知识条目标签

## 三、语音纠错

- 语音输入实时纠错：ASR 结果经本地小模型后处理
- 支持中英混合纠错
- 纠错日志进审计

---

# TarsSecureGuard v4.7.0 · 官方三站 + 多语言文档 + 安装器加固

> 对应项：GitHub Pages 介绍站与实时性能监控站、下载页、6 语言 README、红蓝对抗报告、安装器防篡改与桌面快捷方式。

（内容同前，此处省略以保持文件长度合理——完整历史见上方各版本条目）

