<div align="center">

# 🛡️ TarsSecureGuard

**本机 AI 安全网关 · 一个二进制跑通全栈 · 完全开源（MIT）**

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D6)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.3-blue)](https://github.com/HP-jh/TarsSecureGuard/releases)
[![Stars](https://img.shields.io/github/stars/HP-jh/TarsSecureGuard?color=yellow&style=flat&logo=github)](https://github.com/HP-jh/TarsSecureGuard/stargazers)

[English](README_EN.md) · [快速开始](#快速开始windows) · [构建](#构建) · [特性](#特性)

</div>

TarsSecureGuard 是一个跑在你本机的 **AI 安全网关**——在你所有 AI 客户端和后端模型之间，加一道“安检门”：统一鉴权、WAF 防护、多后端路由、审计日志、MCP 中继，一次全包。把 ChatBox / NextChat / Cursor / 任何 OpenAI 兼容客户端指向 `http://127.0.0.1:18889/v1`，所有请求先过网关，再到模型。

> 👦 这个项目是一个六年级学生用 AI 辅助完成的第一个 Go 开源项目，v1.0.3 起支持 **Windows / Linux / macOS** 三平台编译。如果你正在学编程，欢迎 fork 来玩；如果觉得有用，点个 ⭐ 就是最大的鼓励。

## 它解决什么问题

本地同时跑着 llama.cpp、LM Studio、Ollama，还想接几个云端 OpenAI 兼容 API？很快会遇到：

- 每个后端端口不同、协议细节不同，客户端配置乱成一团
- 没有统一鉴权，任何进程都能白嫖你的模型
- 本地 MCP 工具调用时，恶意 prompt 可能借工具读你硬盘
- 出了事不知道是哪个后端挂了、哪个请求被拦了

TarsSecureGuard 在中间加一层：**统一入口、统一鉴权、统一防护、统一日志**。

## ✨ v1.0.3 新亮点

| 能力 | 说明 |
|---|---|
| 🌍 **跨平台编译** | Windows / Linux / macOS 单二进制构建（build tags 拆分，含磁盘统计与子进程封装平台实现） |
| 👥 **多用户 RBAC** | `admin / user / readonly` 三级权限，每人独立 API Key；不配置 `users` 时自动回退单管理员，**100% 向后兼容** |
| 📜 **结构化审计日志** | 配置修改、模型启停、权限拒绝全部留痕，按日落盘 `logs/audit-*.log`，admin 可查 `GET /api/admin/audit-logs` |
| 🧠 **Prompt Injection 防御** | strict 模式拦截 `ignore previous instructions`、jailbreak、DAN mode 等注入特征，命中返回 403 |
| 🔏 **PII 检测与脱敏** | 聊天消息里的手机号 / 邮箱 / 信用卡号 / SSN 自动打成 `****`，不进后端、不落日志 |
| 🔑 **密钥零明文** | `TARS_API_KEY` / `TARS_OPENAI_KEY` / `TARS_DEEPSEEK_KEY` / `TARS_SEARCH_KEY` 环境变量覆盖配置；所有接口返回 Key 一律 `***` |

## 架构

```
ChatBox / NextChat / Cursor / 任意 OpenAI 客户端
            │
            ▼
┌─────────────────────────────┐
│  TarsSecureGuard :18889      │
│  ┌─────────────────────────┐ │
│  │ 鉴权 (API Key / RBAC)   │ │
│  │ WAF (注入/遍历/XSS/PII/ │ │
│  │      PromptInjection)   │ │
│  │ 速率限制 · 审计日志     │ │
│  └─────────────────────────┘ │
│  路由：本地GGUF / LM Studio  │
│       Ollama / 云端OpenAI    │
│  MCP 中继 (JSON-RPC)         │
│  内嵌 Web 控制台（测试用）   │
└─────────────────────────────┘
            │
            ▼
   llama.cpp :18890 / LM Studio :1234 /
   Ollama :11434 / 云端 API
```

## 特性

### 安全（v1.0.3 强化）

- 👥 **多用户 RBAC**：`users[]` 支持 `admin / user / readonly`；admin 端点仅 admin 可访问，readonly 禁止写操作，权限拒绝自动记入审计
- 📜 **审计日志**：`CONFIG_CHANGE` / `MODEL_START` / `MODEL_STOP` / `MODEL_DOWNLOAD` / `ACCESS_DENIED` 全留痕；默认开启，可按需关闭
- 🧠 **Prompt Injection 检测**（strict）：识别越权指令、jailbreak、DAN mode 等特征，直接 403
- 🔏 **PII 脱敏**：聊天请求在后端路由前自动脱敏，normal 模式不拦截只替换，strict 模式可拦截
- 🔑 **环境变量覆盖密钥**：四种 `TARS_*_KEY` 环境变量优先级高于配置文件，明文不落盘

### 网关层（核心）

**网络与边界**
- 🔒 **只监听 loopback**：绑定 `127.0.0.1:18889`，外部网络无法直连
- 🛑 **CORS 白名单**：不返回 `*`，只回显 `127.0.0.1 / localhost / [::1]` 加网关端口
- 🛡 **安全响应头**：`X-Frame-Options: DENY` / `nosniff` / `no-referrer`
- 📦 **请求体硬上限 5MB**，超大 body 直接拒
- ⏱ **Server 超时全配**：Read 60s / Write 600s / Idle 120s，慢连接攻击挡得住

**鉴权**
- 🔑 **入站一律校验**：所有 API 必须带 `X-API-Key` 或 `Authorization: Bearer <key>`，未授权 401 + `WWW-Authenticate`
- ⏱ **常量时间比较**：`crypto/subtle.ConstantTimeCompare`，防时序侧信道
- ✅ **配置修改白名单**：只能改白名单字段，防结构破坏

**WAF**
- 🛡 **6 类规则**：路径穿越（含 URL 编码变体）、命令注入、SQL 注入、XSS、PromptInjection、PII 泄漏
- 🎯 **normal / strict 双模式**：normal 只扫工具参数（防聊天误报），strict 扫整个请求体
- 🧠 **认识 function calling 结构**：定位 `params.arguments` / `args` 里的字符串值，不粗暴全文匹配
- 🚦 **每 IP 速率限制**：10 秒窗口 120 请求，过期条目自动清理
- 🕵️ **扫描器 UA 黑名单 + 敏感路径探测**：sqlmap / nikto / nuclei 等 UA 直接拦截；`/.env`、`/.git`、`/wp-admin` 等路径拒绝
- 🚫 **异常 HTTP 方法拦截**：TRACE / CONNECT 等直接 403

**文件系统隔离**
- 📁 **`isPathAllowed` 边界严格**：必须“等于根目录”或“根+分隔符开头”，`D:\TarsSecureGuard` 不会误匹配 `...Evil`
- 🪣 **`allowedRoots` 默认最小授权**：exe 目录 + 桌面/文档/下载

**路由与 MCP**
- 🛣 **多后端路由**：本地 GGUF（llama.cpp）· LM Studio · Ollama · OpenAI 兼容云端，自动探测与 failover
- 🔗 **标准 MCP JSON-RPC 2024-11-05**：`initialize` / `tools/list` / `tools/call` / `ping`，兼容自定义 `{tool, args}`
- 🧯 **外部 MCP stdio 子进程管理**：spawn、60s 超时、用完 `Kill + Wait` 回收句柄，Windows 下不弹黑框

### 附属（开箱即测）

- 🖥 **内嵌 Web 控制台**：仪表盘 / 聊天 / 模型管理 / WAF 日志 / 设备信息 / 审计日志，全部 `go:embed` 进单 exe
- 🧰 **内置工具集**：文件读写、Web 搜索、URL 抓取、配置读写（验证网关用，非产品核心）
- 🌐 **Web 搜索**：内置 Bing RSS，无需 API Key
- 🧭 **首次运行向导**：环境检测 → 推荐模型下载 → 完成

### 工程细节

- 🪟 **BOM 兼容**：自动剥离 UTF-8 BOM，记事本保存不乱码
- 🛡 **bool 零值陷阱防护**：没写 `wafEnabled` 默认开
- 🚫 **解析失败不覆盖用户文件**
- 💾 **HTTP 客户端分池**：短 / 长 / 下载专用
- 🗑 **自动清理**：24 小时统计桶、过期限流条目防内存泄漏

## 🚀 快速开始（Windows）

1. 下载或构建 `TarsSecureGuard.exe`（见“构建”）
2. 双击运行，浏览器自动打开控制台
3. 首次运行向导：检测环境 → 下载推荐模型（约 1.9GB，可选）→ 完成

**接入你的客户端**：Base URL 填

```
http://127.0.0.1:18889/v1
```

API Key 填 `config.json` 的 `security.apiKey`（默认 `tars-gateway-key`，**请务必改掉**）。

> 所有默认路径基于 **exe 所在目录**：
> ```
> 你的文件夹/
> ├── TarsSecureGuard.exe   ← 双击它
> ├── config.json           ← 首次运行自动生成
> ├── Models/               ← GGUF 模型放这里
> └── llama/                ← llama-server 推理引擎
> ```

**Linux / macOS**：`go build` 后直接运行即可，配置、模型目录结构完全一致。

## ⚙️ 配置

配置文件 `config.json` 在 exe 同目录，首次运行自动生成。也可用参数 / 环境变量指定：

```bash
TarsSecureGuard -config D:\my\config.json   # 或
TARS_CONFIG=D:\my\config.json ./TarsSecureGuard
```

| 字段 | 说明 | 默认值 |
|---|---|---|
| `security.apiKey` | 入站 API 密钥 | `tars-gateway-key` |
| `security.wafEnabled` | WAF 开关 | `true` |
| `security.mode` | `normal` / `strict` / `off` | `normal` |
| `security.auditLogEnabled` | 审计日志开关 | `true` |
| `users[]` | 多用户 RBAC：`{name, apiKey, role, enabled}`，role 为 `admin / user / readonly` | 空（回退单管理员） |
| `paths.modelDir` | GGUF 模型目录 | exe 同目录 `Models/` |
| `paths.llamaDir` | llama.cpp 引擎目录 | exe 同目录 `llama/` |
| `paths.allowedRoots` | 文件工具读写白名单 | exe 目录 + 桌面/文档/下载 |
| `cloud.openai/deepseek` | 云端 OpenAI 兼容服务 | 空 |
| `search.engine` | `builtin` / `serper` | `builtin` |

**环境变量覆盖密钥**（优先级高于配置文件）：`TARS_API_KEY`、`TARS_OPENAI_KEY`、`TARS_DEEPSEEK_KEY`、`TARS_SEARCH_KEY`。

> 安全提示：务必修改 `security.apiKey` 默认值；多用户场景请在 `users[]` 里为每人配独立 Key 与角色；`allowedRoots` 保持最小授权。

## 🧠 后端模型

- **本地 GGUF**：把 `qwen2.5-3b-instruct-q4_k_m.gguf` 等放入 `Models/`，网关自动调 llama.cpp
- **LM Studio / Ollama**：装着就自动发现（端口 1234 / 11434），还支持独立 llama.cpp（8080）
- **云端 OpenAI 兼容**：`config.json` 填 base URL + key
- Web 界面「Models → Scan Hardware」可一键下载推荐模型（Hugging Face 直链）

## 🛠 构建

需要 [Go 1.22+](https://go.dev/dl/)。

```bash
cd go-app
# Windows
GOOS=windows GOARCH=amd64 go build -o TarsSecureGuard.exe .
# Linux
GOOS=linux   GOARCH=amd64 go build -o tars-linux .
# macOS
GOOS=darwin  GOARCH=amd64 go build -o tars-macos .
```

或直接跑根目录 `build.bat`（Windows 一键）。前端经 `go:embed` 内嵌，改完前端重新 `go build`。

## 📂 目录结构

```
TarsSecureGuard/
├── go-app/
│   ├── main.go              # 入口 / 路由 / RBAC 中间件 / 审计日志
│   ├── config.go            # 配置结构 / 路径解析 / 热重载 / 环境变量覆盖
│   ├── waf.go               # WAF 规则 / 速率限制 / PII 脱敏 / 拦截   ← 网关核心
│   ├── models.go            # 后端路由：GGUF / LM Studio / Ollama / 云端
│   ├── chat.go              # OpenAI 兼容 /v1 代理（含 PII 脱敏）
│   ├── handlers.go          # 状态 / 安全 / 审计 / 配置 API
│   ├── device.go            # 设备信息 / 服务发现（跨平台公共代码）
│   ├── device_windows.go    # Windows 磁盘统计（build tags）
│   ├── device_other.go      # Linux/macOS 磁盘统计（build tags）
│   ├── process_windows.go   # Windows 子进程 HideWindow（build tags）
│   ├── process_other.go     # 非 Windows 空实现（build tags）
│   ├── tools.go / web.go / mcp.go / memory.go / logging.go / firewall.go
│   ├── frontend/index.html  # 内嵌 Web 控制台
│   └── config.json          # 本机配置（示例，含真实 Key 勿提交）
├── build.bat / start.bat / start.sh
├── CHANGES.md / OPTIMIZATION_REPORT.md
├── LICENSE                  # MIT
└── README.md
```

## 🤝 贡献

欢迎提 Issue / PR。项目还很年轻，优先方向：

- 🔀 跨平台 CI（GitHub Actions 矩阵编译）
- 📊 Prometheus 指标 + wrk/k6 压测基准（对标 Bifrost 5000 QPS）
- 🔐 JWT 升级：单 Key → 带过期与 Scope 的 Token
- 🧱 跨平台防火墙驱动（iptables / pfctl）
- 🧪 单元测试（WAF 规则、路径遍历防护是重点）

## 📜 开源

MIT 许可证，可自由使用、修改、分发（含商用）。详见 [LICENSE](LICENSE)。

## ⚠️ 免责声明

本项目为个人学习与本地使用设计，默认仅监听本机。请勿将未加固版本直接暴露公网；远程访问请自行加 TLS 与更严鉴权。

---

<div align="center">

**如果这个项目对你有帮助，点个 ⭐ Star 支持一下作者吧！**

[← 返回顶部](#tarssecureguard)

</div>
