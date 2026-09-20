<div align="center">

# TarsSecureGuard

**本地 AI 网关 · 双击即用 · 完全开源（MIT）**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/HP-jh/TarsSecureGuard/releases)
[![Stars](https://img.shields.io/github/stars/HP-jh/TarsSecureGuard?color=yellow&style=flat&logo=github)](https://github.com/HP-jh/TarsSecureGuard/stargazers)

[English](README_EN.md) · [快速开始](#-快速开始windows) · [构建](#-构建) · [特性](#-特性)

</div>

一个运行在你自己电脑上的 AI 网关：管理本地 GGUF 模型（llama.cpp）、接入 LM Studio / Ollama / 云端模型、内置 Web 搜索、7 个智能体、MCP 工具中继，以及一个带速率限制和注入检测的安全模块（WAF）。前端网页内嵌在单个可执行文件中——**不需要安装任何运行时，双击 .exe 就能用**。

> 👦 这个项目是一个六年级学生在 AI 辅助下完成的第一个 Go 开源项目。如果你正在学编程，欢迎 fork 来玩；如果你觉得有用，点个 star 就是最大的鼓励。

## ✨ 特性

- 🔒 **本地优先**：默认只监听 `127.0.0.1`，模型推理完全离线运行
- 🛡 **内置 WAF**：路径穿越 / 命令注入 / SQL 注入 / XSS 检测 + 每 IP 速率限制
- 🔑 **入站鉴权**：`X-API-Key` 或 `Authorization: Bearer <key>`
- 🤖 **多后端路由**：本地 GGUF（llama.cpp）· LM Studio · Ollama · OpenAI 兼容云端
- 🧰 **7 个内置智能体**：代码助手 / 写作 / 翻译 / 摘要 / 数据分析 / 安全分析 / 紧急响应
- 🌐 **Web 搜索**：内置 Bing RSS 源，无需 API Key
- 🔗 **MCP 中继**：兼容标准 MCP JSON-RPC，可接入外部 MCP 服务器
- 🖥 **图形化界面**：内嵌 Web 控制台（仪表盘 / 聊天 / 模型管理 / 安全日志 / 设备信息）
- 🧭 **首次运行向导**：环境检测 → 推荐模型下载 → 完成，三步上手

## 🚀 快速开始（Windows）

1. 下载或构建 `TarsSecureGuard.exe`（见下方"构建"）
2. 双击运行（程序会自动打开浏览器）
3. 首次运行会弹出欢迎向导：检测环境 → 下载推荐模型（约 1.9GB，可选）→ 完成

> 也可以把 exe 放进任意文件夹直接运行。所有默认路径都基于 **exe 所在目录**：
>
> ```
> 你的文件夹/
> ├── TarsSecureGuard.exe   ← 双击它
> ├── config.json           ← 首次运行自动生成
> ├── Models/               ← GGUF 模型文件放这里
> └── llama/                ← llama-server.exe 推理引擎
> ```

浏览器访问 `http://127.0.0.1:18889`（API 端口 `18889`，本地模型服务端口 `18890`）。

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

## 🧠 模型

- 本地模型：把 `qwen2.5-3b-instruct-q4_k_m.gguf` 等 GGUF 文件放入 `Models/` 目录
- 在 Web 界面「Models → Scan Hardware」可一键下载推荐模型（Hugging Face 直链）
- 已安装 [LM Studio](https://lmstudio.ai/)（端口 1234）或 [Ollama](https://ollama.com/)（端口 11434）会自动被发现并接入

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
│   ├── waf.go             # WAF 规则 / 速率限制 / 拦截
│   ├── models.go          # 本地 GGUF 模型管理 / LM Studio·Ollama 探测
│   ├── chat.go            # 聊天路由 / OpenAI 兼容 /v1
│   ├── tools.go           # 内置工具注册表
│   ├── handlers.go        # 状态 / 安全 / 日志 / 配置等 API
│   ├── device.go          # 设备信息 / 磁盘 / 服务发现
│   ├── web.go             # 搜索 / URL 抓取 / OpenAPI
│   ├── mcp.go             # MCP 中继端点 / 外部 MCP 客户端
│   ├── memory.go          # 长期记忆持久化
│   ├── frontend/index.html# 内嵌 Web 控制台
│   └── config.json        # 本机配置（不入库）
├── build.bat              # Windows 一键构建
├── LICENSE                # MIT 许可证
└── README.md
```

## 🤝 贡献

欢迎提 Issue / PR。这个项目还很年轻，有很多可以改进的地方：

- 更多模型推荐与自动下载
- macOS / Linux 构建
- Docker 镜像
- 更多 MCP 服务器接入示例
- 单元测试

## 📜 开源

本项目以 **MIT 许可证** 开源，可自由使用、修改、分发（含商用）。详见 [LICENSE](LICENSE)。

## ⚠️ 免责声明

本项目为个人学习与本地使用设计，监听地址默认仅限本机。请勿将未加固的版本直接暴露到公网；若需远程访问，请自行增加 TLS 与更严格的鉴权。

---

<div align="center">

**如果这个项目对你有帮助，点个 ⭐ Star 支持一下作者吧！**

[← 返回顶部](#tarssecureguard)

</div>
