<div align="center">

# TarsSecureGuard

**面向本地 AI 工作流的安全网关 · 完全开源（MIT）**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/HP-jh/TarsSecureGuard/releases)
[![Stars](https://img.shields.io/github/stars/HP-jh/TarsSecureGuard?color=yellow&style=flat&logo=github)](https://github.com/HP-jh/TarsSecureGuard/stargazers)

[English](README_EN.md) · [快速开始](#-快速开始windows) · [构建](#-构建) · [特性](#-特性)

</div>

TarsSecureGuard 是一个跑在你本机的 **AI 安全网关**。它站在所有 AI 客户端和后端模型之间，负责鉴权、WAF 防护、多后端路由、审计日志和 MCP 中继。内嵌的 Web 控制台和内置工具只是"开箱即测"的附属品——真正的用法是：把你已有的 ChatBox / NextChat / Cursor / 任何 OpenAI 兼容客户端指向 `http://127.0.0.1:18889/v1`，所有请求先过网关再到模型。

> 👦 这个项目是一个六年级学生在 AI 辅助下完成的第一个 Go 开源项目。如果你正在学编程，欢迎 fork 来玩；如果你觉得有用，点个 star 就是最大的鼓励。

## 它解决什么问题

如果你本地同时跑着 llama.cpp、LM Studio、Ollama，还想接几个云端 OpenAI 兼容 API，很快会遇到：

- 每个后端端口不同、协议细节不同，客户端配置乱
- 没有统一鉴权，哪个客户端都能调你的模型
- 本地跑 MCP 工具时，恶意 prompt 可以通过工具调用读你硬盘上任意文件
- 出了问题不知道是哪个后端挂了、哪个请求被拦了

TarsSecureGuard 在中间加一层：**统一入口、统一鉴权、统一防护、统一日志**。

## 架构

```
ChatBox / NextChat / Cursor / 任意 OpenAI 客户端
            │
            ▼
┌─────────────────────────────┐
│  TarsSecureGuard :18889      │
│  ┌─────────────────────────┐ │
│  │ 鉴权 (X-API-Key)       │ │
│  │ WAF (注入/遍历/XSS)    │ │
│  │ 速率限制                │ │
│  │ 审计日志                │ │
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

## ✨ 特性（按重要性排）

**网关层（核心）**
- 🔒 **本地优先**：默认只监听 `127.0.0.1`，不暴露公网
- 🛡 **内置 WAF**：路径穿越 / 命令注入 / SQL 注入 / XSS 正则检测 + 每 IP 速率限制
- 🔑 **入站鉴权**：所有 API 必须带 `X-API-Key` 或 `Authorization: Bearer <key>`，未授权一律 401
- 🛣 **多后端路由**：本地 GGUF（llama.cpp）· LM Studio · Ollama · OpenAI 兼容云端，自动 failover
- 📋 **审计日志**：每个请求记录来源、路径、状态码、WAF 判定
- 🔗 **MCP 中继**：标准 JSON-RPC 端点，外部 MCP 服务器以 stdio 方式接入

**附属（开箱即测）**
- 🖥 **内嵌 Web 控制台**：仪表盘 / 聊天测试 / 模型管理 / WAF 日志 / 设备信息，全部 go:embed 进单 exe
- 🧰 **内置工具集**：文件读写、Web 搜索、URL 抓取、配置读写——用来验证网关是否正常工作，不是产品核心
- 🧭 **首次运行向导**：环境检测 → 推荐模型下载 → 完成
- 🌐 **Web 搜索**：内置 Bing RSS 源，无需 API Key

## 🚀 快速开始（Windows）

1. 下载或构建 `TarsSecureGuard.exe`（见下方"构建"）
2. 双击运行（程序会自动打开浏览器到测试控制台）
3. 首次运行三步向导：检测环境 → 下载推荐模型（约 1.9GB，可选）→ 完成

**把你自己的客户端接上**：在任意 OpenAI 兼容客户端里，把 Base URL 填成

```
http://127.0.0.1:18889/v1
```

API Key 填 `config.json` 里 `security.apiKey` 的值（默认 `tars-gateway-key`，请改掉）。之后所有请求都会先经过 WAF 和鉴权。

> 所有默认路径都基于 **exe 所在目录**：
>
> ```
> 你的文件夹/
> ├── TarsSecureGuard.exe   ← 双击它
> ├── config.json           ← 首次运行自动生成
> ├── Models/               ← GGUF 模型文件放这里
> └── llama/                ← llama-server.exe 推理引擎
> ```

## ⚙️ 配置

配置文件 `config.json` 在 exe 同目录，首次运行自动生成。也可用参数/环境变量指定：

```bash
TarsSecureGuard.exe -config D:\my\config.json   # 或
set TARS_CONFIG=D:\my\config.json
```

| 字段 | 说明 | 默认值 |
|---|---|---|
| `security.apiKey` | 入站 API 密钥 | `tars-gateway-key` |
| `security.wafEnabled` | WAF 开关 | `true` |
| `security.mode` | `normal`（只扫工具参数）/ `strict`（扫全部）/ `off` | `normal` |
| `paths.modelDir` | GGUF 模型目录 | exe 同目录 `Models/` |
| `paths.llamaDir` | llama.cpp 推理引擎目录 | exe 同目录 `llama/` |
| `paths.allowedRoots` | 文件工具可读写的根目录白名单 | exe 目录 + 用户桌面/文档/下载 |
| `cloud.openai/deepseek` | 云端 OpenAI 兼容服务 | 空 |
| `search.engine` | `builtin`（内置 Bing）/ `serper` | `builtin` |

> 安全提示：请修改 `security.apiKey` 默认值；`allowedRoots` 保持最小授权范围。

## 🧠 后端模型

- **本地 GGUF**：把 `qwen2.5-3b-instruct-q4_k_m.gguf` 等文件放入 `Models/`，网关自动调 llama.cpp
- **LM Studio / Ollama**：装着就自动发现（端口 1234 / 11434）
- **云端 OpenAI 兼容**：在 `config.json` 里填 base URL + key
- Web 界面「Models → Scan Hardware」可一键下载推荐模型（Hugging Face 直链）

## 🛠 构建

需要 [Go 1.22+](https://go.dev/dl/)。

```bash
# 方式一：一键脚本（Windows）
build.bat

# 方式二：命令行
cd go-app
go build -o ../dist/TarsSecureGuard.exe .
```

前端 `go-app/frontend/index.html` 通过 `go:embed` 内嵌，改完前端重新 `go build` 即可。

## 📂 目录结构

```
TarsSecureGuard/
├── go-app/
│   ├── main.go            # 入口 / 路由 / 中间件（WAF·鉴权·CORS）
│   ├── config.go          # 配置结构与路径解析
│   ├── waf.go             # WAF 规则 / 速率限制 / 拦截   ← 网关核心
│   ├── models.go          # 后端路由：GGUF / LM Studio / Ollama / 云端
│   ├── chat.go            # OpenAI 兼容 /v1 代理
│   ├── tools.go           # 内置工具（测试用，非产品核心）
│   ├── handlers.go        # 状态 / 安全 / 日志 / 配置 API
│   ├── device.go          # 设备信息 / 服务发现
│   ├── web.go             # 搜索 / URL 抓取
│   ├── mcp.go             # MCP 中继端点 / 外部 MCP 客户端
│   ├── memory.go          # 长期记忆（测试用）
│   ├── frontend/index.html# 内嵌 Web 控制台（测试用）
│   └── config.json        # 本机配置（不入库）
├── build.bat              # Windows 一键构建
├── LICENSE                # MIT 许可证
└── README.md
```

## 🤝 贡献

欢迎提 Issue / PR。这个项目还很年轻，优先想做的方向：

- 更严的 WAF 规则集（已知 CVE 模式、Jailbreak prompt 检测）
- TLS / HTTPS 支持（当前只监听 loopback）
- 更细粒度的 RBAC（按 key 限制能访问哪些后端）
- macOS / Linux 构建
- 单元测试（WAF 规则、路径遍历防护是重点）

## 📜 开源

本项目以 **MIT 许可证** 开源，可自由使用、修改、分发（含商用）。详见 [LICENSE](LICENSE)。

## ⚠️ 免责声明

本项目为个人学习与本地使用设计，监听地址默认仅限本机。请勿将未加固的版本直接暴露到公网；若需远程访问，请自行增加 TLS 与更严格的鉴权。

---

<div align="center">

**如果这个项目对你有帮助，点个 ⭐ Star 支持一下作者吧！**

[← 返回顶部](#tarssecureguard)

</div>
