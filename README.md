🌐 **多语言版本**：[🇨🇳 简体中文](README.md) · [🇺🇸 English](README.en.md) · [🇷🇺 Русский](README.ru.md) · [🇸🇦 العربية](README.ar.md) · [🇫🇷 Français](README.fr.md) · [🇯🇵 日本語](README.ja.md) · [🇰🇷 한국어](README.ko.md)

---

<div align="center">

# 🛡️ TarsSecureGuard

### AI 时代的路由器与配置器 —— 自带安全带、桌面客户端、可插拔 MCP 桥、企业级互通

<p>
<b>零依赖单文件</b> · <b>7 平台原生产物</b> · <b>Security Core 不可关闭</b> · <b>Tauri 桌面客户端</b> · <b>auto-include MCP 桥</b> · <b>知识库 + Obsidian</b> · <b>企业级互通</b> · <b>万物皆 MCP 🚀</b>
</p>

<p>
本地 AI 安全网关（LLM 代理）。左边接 <b>13 种 AI 软件客户端</b>（Claude Desktop / Cursor / Cline / Continue / Windsurf / Codex / Roo Code / VS Code Copilot / Zed / JetBrains …），<br/>
右边连 <b>24 家云端模型 + 8 种本地推理运行时</b>（OpenAI / Anthropic / Gemini / DeepSeek / 通义 / 文心 / GLM / 豆包 / Kimi / 混元 / 星火 / Groq / Ollama / vLLM …），<br/>
外面挂 <b>任意 MCP 桥</b>（字节 UI-TARS 桌面操控 / LobeHub 7 点融合 / TarsEnterprise 企业版互通 / TarsOpenClawSandbox 沙箱化），<br/>
里面开 <b>知识库 + Obsidian 双向同步 + 语音纠错</b>，中间强制开启 WAF、提示词注入防护、PII 脱敏、限流、IP 信誉、RBAC、审计——<b>连得多，更要守得住</b>。
</p>

<p>
<b>v4.11+ 自带桌面客户端</b>：系统托盘 / loading 窗口 / 管理员权限 / 自更新器 / WebSocket 实时事件，<br/>
<b>v4.12+ 内置知识大脑</b>：Markdown 解析 + 多 provider embedding + 向量检索 + Obsidian Vault 双向同步 + 语音纠错<br/>
<b>v4.13+ 跨企业互通</b>：<code>POST /api/v1/interop/receive-command</code> 接收 TarsEnterprise 指令 + <code>GET /api/v1/interop/events</code> SSE 实时事件流<br/>
Windows / macOS / Linux / Android 全平台一致体验——<b>解压即用，双击就起，浏览器自动打开中文管理面板</b>。
</p>

<p>
<img alt="Version" src="https://img.shields.io/badge/version-4.13.0-success?style=flat-square">
<img alt="Go" src="https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white&style=flat-square">
<img alt="Deps" src="https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square">
<img alt="Platforms" src="https://img.shields.io/badge/platforms-7%20native%20targets-blueviolet?style=flat-square">
<img alt="MCP" src="https://img.shields.io/badge/MCP-stdio%20%2B%20HTTP%20%2B%20auto--include-22d3ee?style=flat-square">
<img alt="Enterprise" src="https://img.shields.io/badge/TSG%E2%86%94Enterprise-interop-blue?style=flat-square">
<img alt="KB" src="https://img.shields.io/badge/Knowledge%20Base-v2%20%2B%20Obsidian%20%2B%20Voice-blueviolet?style=flat-square">
<img alt="Tests" src="https://img.shields.io/badge/tests-race%20green-brightgreen?style=flat-square">
<img alt="PenTest" src="https://img.shields.io/badge/pen--test-passing-success?style=flat-square">
<img alt="SHA256" src="https://img.shields.io/badge/SHA256-verified-informational?style=flat-square">
<img alt="License" src="https://img.shields.io/badge/license-MIT-orange?style=flat-square">
</p>

</div>

---

## 📣 推荐语

> **当每个 AI 客户端都自带一套私有的模型生态时，TarsSecureGuard 让你只需一个 OpenAI 兼容密钥，就能把所有模型、所有客户端、所有外部 MCP 工具、所有企业版网关接进来——而且强制系好安全带。**
>
> v4.13 起，TSG 是**网关 + 桌面客户端 + MCP 桥接器 + 知识库 + 企业互通层**五件套：
>
> - **🖥️ Tauri 桌面客户端**：系统托盘 / loading 窗口 / 管理员权限 / 自更新器 / WebSocket 事件——Windows / macOS / Linux / Android 一致体验
> - **🔌 auto-include MCP 桥**：在 `config.json` 加一行就挂载外部 MCP server（字节 UI-TARS 桌面操控 / 任意 MCP 工具），不用改 TSG 代码
> - **📚 知识库 v2 + Obsidian 双向同步**（v4.12+）：Markdown 解析 + 多 provider embedding（OpenAI / Doubao / bge-m3）+ 向量检索 + Obsidian Vault 双向同步 + 语音纠错
> - **🤝 TSG ↔ TarsEnterprise 互通**（v4.13+）：企业版网关可发指令 / 推 state / 订阅事件，TSG 也能反向拉取 + 校验角色 token
> - **🛡️ Security Core 不可关闭**：WAF / 提示词注入 / PII / 限流 / IP 信誉 / RBAC / 审计 默认开启，**不可关闭**
> - **🧩 万物皆 MCP**：TarsWingGuard 模块化打包 + 单参数解锁高级套餐（羽翼防护 / 知识大脑 / 视觉雷达 / 智能体沙箱 / 多渠道 / 画板 / 监控）
> - **🌍 7 平台原生产物**：linux-amd64/arm64 + darwin-amd64/arm64 + windows-amd64.exe/arm64.exe + android-arm64，一个都不少
> - **📦 零依赖单文件**：`go.mod` 零第三方依赖，无容器、无数据库、无外部服务，**U 盘拷出去就能跑**
>
> 不是又一个让你拉 1GB 镜像、装 MySQL、装 Python/Node 的"重型网关"——是一个 **零依赖、纯静态、拷到 U 盘里都能跑** 的本地 AI 安全网关 + 桌面客户端 + 知识库 + 企业互通层。

---

## 🌟 介绍语

TarsSecureGuard 是一款**本地优先（local-first）的 AI 网关 + 桌面客户端 + 知识库 + 企业互通层**。它站在你和所有 AI 能力之间：左边是你的 AI 软件，右边是 24 家云端模型 + 8 种本地推理运行时，外面是字节 UI-TARS 之类的 MCP 桥 + TarsEnterprise 企业版网关 + TarsOpenClawSandbox 沙箱；里面是知识库 + Obsidian Vault；对内统一调度、统一治理、统一审计，对外暴露一个 OpenAI 兼容端点（HTTP 或 **stdio**）+ MCP 标准协议 + 跨企业互通接口。

家里的路由器不生产网线，也不生产网站——它让每一台设备都能安全上网。TarsSecureGuard 不生产模型，也不绑架你用某个客户端——**它让每一个 AI 客户端都能安全地用上每一个模型 + 每一个外部工具 + 每一个企业资源。** 知识库与个人笔记（Obsidian）一并连进来，企业版网关和沙箱化外部组件也一并接进来。

### v4.13 能力矩阵

| 模块 | 版本 | 状态 | 说明 |
|---|---|---|---|
| **Security Core 不可关闭** | v3.0+ | ✅ | WAF / Prompt 注入 / PII / 限流 / IP 信誉 / RBAC / 审计 / SSRF 五红线 / 语义灰区 fail-close |
| **Universal Connector 路由器** | v3.2+ | ✅ | 13 客户端 × 24 provider，新增 provider 只写 JSON |
| **Extender 配置器** | v3.7+ | ✅ | 探测本机已装 AI 工具（OpenClaw / Continue / Aider / Cline / Codex），一键生成接入配置 |
| **Persona 职业系统** | v3.8+ | ✅ | 5 种职业模板自适应模块、链路与模型匹配 |
| **Multi-agent + 设备网** | v4.1+ | ✅ | multi-agent 协作 / MCP / distributed device mesh |
| **Kingdom 分类学架构** | v4.9+ | ✅ | 界门纲目科属种分层，零破坏兼容层 |
| **🆕 Tauri 桌面客户端** | v4.11+ | ✅ | 系统托盘 + loading 窗口 + 管理员权限 + 自更新器 + WebSocket 事件 + 7 平台产物 |
| **🆕 auto-include MCP 桥** | v4.11+ | ✅ | config.json 一行挂载外部 MCP server，工具自动合并到 /tools/list |
| **🆕 360 安全 UI** | v4.11+ | ✅ | 左侧导航 + 右侧大面板，仿 360 安全卫士 |
| **🆕 LobeHub 多设备路由** | v4.11+ | ✅ | 多设备协作 + 多智能体风格 |
| **🆕 Token 用量看板** | v4.11+ | ✅ | 按 provider / 应用 / 天统计 Token 与成本 |
| **🆕 vKey 虚拟密钥体系** | v4.11+ | ✅ | 每用户 / 每应用独立虚拟密钥 + 配额 + 审计 + 撤销 |
| **🆕 模型路由策略** | v4.11+ | ✅ | 简单请求走小模型省钱，复杂请求走大模型保质 |
| **🆕 字节 UI-TARS 桌面操控** | v4.11+ | ✅ | UI-TARS-1.5-7B / Doubao 视觉模型，AI 通过 MCP 调用截屏 / 点击 / 输入 / 滚动 / 开浏览器 |
| **🆕 Knowledge Base v2** | **v4.12+** | ✅ | Markdown 解析 + chunk + 多 provider embedding + 向量检索 + rerank + 写回 |
| **🆕 Obsidian 双向同步** | **v4.12+** | ✅ | 读 vault + fsnotify 监听 + frontmatter + 双向链接 + tag 同步 |
| **🆕 voice_correction 语音纠错** | **v4.12+** | ✅ | 编辑距离 + 拼音匹配 + 同义词 + 简繁互转 + 模糊匹配 |
| **🆕 TSG ↔ TarsEnterprise 互通** | **v4.13+** | ✅ | `POST /interop/receive-command` + `GET /interop/events`（SSE）+ 角色 token 验签 |
| **🆕 画板可视化工作流** | v4.14+ | 🎯 | 拖拽节点 + AI 实时调整 + 独立上下文 per-agent |
| **🆕 安全极致档（8 项）** | v4.17+ | 🎯 | 动态拦截 / AI 识别 / 多渠道警告 / 客户端成熟度 / RBAC / 杀软兼容 / 抗外部攻击 / 内核级自保 |
| **🆕 15+ 开源 MCP 化** | v4.15+ | 🎯 | LobeHub / Bifrost / Portkey / OneAPI / LiteLLM / Higress / Dify / LangChain / N8N / AutoGPT / RAGFlow / Mem0 / OWASP / Wazuh / Open WebUI |
| **🆕 TarsWingGuard 模块化打包** | v0.1+ | ✅ | 核心 vs 羽翼哲学 + `wing.tier=basic|pro|ultimate` 单参数解锁高级套餐 |

### 五大核心特点

| 特点 | 说明 |
|------|------|
| 🔌 **连接一切** | 13 客户端 × 24 云 provider + 8 本地运行时 + 任意 MCP bridge + 跨企业互通，新增 provider / 工具 / 角色只写配置不改代码 |
| 📚 **知识库 + Obsidian**（v4.12+） | Markdown 解析 + 多 provider embedding + 向量检索 + Obsidian Vault 双向同步 + 语音纠错入库前自动标准化 |
| 🤝 **企业级互通**（v4.13+） | TSG ↔ TarsEnterprise 双向：发指令 / 推 state / 订阅事件流 / 角色 token 验签，**安全握手默认开** |
| 🖥️ **桌面客户端** | Tauri 跨平台客户端：系统托盘常驻、loading 启动窗口、管理员权限开机自启、自更新器自动拉新版、WebSocket 实时事件，Windows / macOS / Linux / Android 一致体验 |
| 🧩 **可插拔 MCP 桥 + 万物皆 MCP** | 字节 UI-TARS 桌面操控 / TarsWingGuard 模块化套餐 / TarsOpenClawSandbox 沙箱 / TarsVoiceCorrection 语音纠错，**所有能力都可 MCP 化挂载** |
| 💻 **环境兼容性好** | 一份代码，7 平台原生产物（linux / darwin / windows × amd64 / arm64 + android-arm64），`CGO_ENABLED=0` 纯静态，老内核、内网隔离即拷即跑 |
| 🔒 **Security Core 不可关闭** | WAF / 提示词注入 / PII 脱敏 / 三维令牌桶限流 / IP 信誉 / RBAC 三角色 / hash-chain 审计 / SSRF 五红线 / 防火墙三档联动 / 语义灰区 fail-close——**连接再广，安全链一行不削**。「AI 只能加严」单向合并铁律 |

### 进阶能力

- **🖥️ Tauri 桌面客户端**：系统托盘常驻 + loading 启动窗口 + 管理员权限 + WebSocket 实时事件 + 7 平台产物 + 自更新器
- **🔌 auto-include MCP 桥**：在 `config.json` 加一行 `auto_include`，网关启动时自动扫描并挂载外部 MCP server
- **🖱️ 字节 UI-TARS 桌面操控**：集成 UI-TARS-1.5-7B / Doubao 视觉模型，AI 通过 MCP 调用截屏、点击、输入、滚动、开浏览器——让 AI 真的能"动手"操作你的桌面
- **📚 知识库 v2 + Obsidian 双向同步**（v4.12+）：Markdown 解析 / chunk / embedding / 向量检索 / rerank / 写回；Obsidian Vault 读 + 监听 + 写回 + frontmatter + 双向链接 + tag
- **🎙️ voice_correction 语音纠错**（v4.12+）：编辑距离 + 拼音匹配 + 同义词 + 简繁互转 + 模糊匹配，5 工具 MCP
- **🤝 TSG ↔ TarsEnterprise 互通**（v4.13+）：`POST /api/v1/interop/receive-command` 接收 TE 指令 + `GET /api/v1/interop/events` SSE 实时事件流 + 角色 token 验签
- **🛡️ 360 安全 UI**：左侧导航 + 右侧大面板，仿 360 安全卫士布局，安全模块可视化（WAF 日志 / 拦截统计 / 信誉评分 / 审计链 一屏搞定）
- **🧠 LobeHub 多设备路由**：多设备协作 / 多智能体风格，AI 模块支持多 provider 路由 + 多 agent 协作
- **📊 Token 用量看板**：按 provider / 应用 / 天统计 Token 与成本，可视化看板
- **🔑 vKey 虚拟密钥体系**：每用户 / 每应用独立虚拟密钥，配额 + 审计 + 撤销，对标奇安信
- **🎯 模型路由策略**：简单请求走小模型省钱，复杂请求走大模型保质，自动选择
- **🧩 TarsWingGuard 模块化打包**（v0.1+）：核心 = 默认开；羽翼 = 单参数 `wing.tier=pro` 一键解锁 7 大高级模块（羽翼防护 / 知识大脑 / 视觉雷达 / 智能体沙箱 / 多渠道 / 画板 / 监控）
- **🔐 TarsOpenClawSandbox 沙箱**（v0.1+）：覆盖 OpenClaw 8 类 CVE（plugin hijack / token leak / CSWSH / path traversal / SSRF / LLM injection / OAuth CSRF / IM smuggling），gVisor runsc 主选 + firecracker 备用 + Tailscale 默认替代 85% 公网暴露
- **🏢 TarsEnterprise 企业版**（v0.1+）：6 公司类型（学校 / 互联网 / KPI / 咨询 / 金融 / 政企）+ 3 交互方式（NOB / 网关调度 / OpenAI Realtime）+ 智能体沙箱 + TOP 应用统计到智能体级 + 小白化极致

---

## 🚀 一条命令，解压即用

不需要 Docker，不需要 Postgres，不需要 Node.js / Python / 任何运行时，U 盘拷出去都能跑。

**macOS / Linux：**

```bash
curl -fsSL https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
tsg
```

**Windows PowerShell：**

```powershell
irm https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.ps1 | iex
tsg
```

→ 检测系统 → 下载二进制 → SHA256 校验 → 安装完成
→ 启动网关，桌面客户端自动起，浏览器自动打开 http://127.0.0.1:18889

**网络受限？** 设置国内镜像（已内置 gh-proxy / ghfast fallback）：

```bash
TSG_MIRROR=gh-proxy curl -fsSL https://gh-proxy.com/raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
```

---

## 📦 下载 v4.13.0 二进制

7 平台原生产物 + SHA256 校验随附。

| 平台 | 文件 | 大小 |
|---|---|---|
| Linux x86_64 | `tsg-v4.13.0-linux-amd64` | ~12 MB |
| Linux ARM64 | `tsg-v4.13.0-linux-arm64` | ~12 MB |
| macOS Intel | `tsg-v4.13.0-darwin-amd64` | ~12 MB |
| macOS Apple Silicon | `tsg-v4.13.0-darwin-arm64` | ~12 MB |
| Windows x64 | `tsg-v4.13.0-windows-amd64.exe` | ~13 MB |
| Windows ARM64 | `tsg-v4.13.0-windows-arm64.exe` | ~13 MB |
| Android ARM64 | `tsg-v4.13.0-android-arm64` | ~12 MB |

所有平台共享 [SHA256SUMS-v4.13.0.txt](https://github.com/HP-jh/TarsSecureGuard/releases/download/v4.13.0/SHA256SUMS-v4.13.0.txt) 校验。

---

## 🆚 对比其他 AI 网关

| 网关 | 依赖 | 体积 | 安全默认 | MCP | 桌面客户端 | 知识库 | 企业互通 |
|---|---|---|---|---|---|---|---|
| **TSG v4.13** | **0** | **~12 MB** | **不可关闭** | **客户端 + 服务端 + auto-include** | **Tauri 7 平台** | **v2 + Obsidian** | **TSG↔Enterprise** |
| Bifrost (Go) | Go runtime | ~30 MB | 关闭 | ✅ 服务端 | — | — | — |
| LiteLLM | Python + Postgres + Redis | ~1 GB | 关闭 | ✅ 服务端 | — | — | — |
| Portkey | Node.js + Redis | ~50 MB | 部分 | ✅ 服务端 | — | — | — |
| OneAPI | Go runtime | ~15 MB | 关闭 | — | — | — | — |
| Higress (Go) | Go runtime | ~50 MB | 部分 | ✅ 服务端 | — | — | — |

完整对比见 [COMPARISON.md](https://github.com/HP-jh/TarsSecureGuard/blob/main/COMPARISON.md)。

---

## 💎 订阅版（Subscription）

> **社区版完全免费、开源（MIT）；订阅版面向希望"省心 + 合规 + 持续更新"的用户。**

| 能力 | 社区版（免费） | **订阅版（推荐）** |
|------|:---:|:---:|
| 网关 / 本地与云端模型 / WAF / 语义防护 / 限流 / IP 信誉 / RBAC / 审计 | ✅ | ✅ |
| Tauri 桌面客户端 / 7 平台产物 / auto-include MCP 桥 / 360 UI / LobeHub | ✅ | ✅ |
| Knowledge Base v2 + Obsidian 双向同步 + voice_correction | ✅ | ✅ |
| TSG ↔ TarsEnterprise 互通 | ✅ | ✅ |
| TarsWingGuard 模块化套餐（basic / pro / ultimate） | ✅ | ✅ |
| **一键更新包**（云盘最新版自动构建，免手动） | — | ✅ |
| **安全规则库持续更新**（最新 Prompt 注入 / 越狱特征、IP 信誉策略） | 社区节奏 | **优先更新** |
| **lm-eval 离线评测数据导入与调优建议** | 手动 | ✅ 专家调优 |
| **企业版 6 公司类型套件**（学校 / 互联网 / KPI / 咨询 / 金融 / 政企） | 单独购 | ✅ 包含 |
| 私有化 / 内网合规部署支持 | — | ✅ |
| 原厂技术支持与 SLA | — | ✅ |

订阅即获得**持续的安全防护更新与省心交付**：你只管解压使用，防护、稳定性与兼容性由订阅持续兜底。

---

## 🔗 关联项目（5 仓库生态 · 万物皆 MCP 🚀）

| 仓库 | 定位 | 状态 |
|---|---|---|
| **[TarsSecureGuard](https://github.com/HP-jh/TarsSecureGuard)** | 本仓库 · 主网关 + 桌面客户端 + 知识库 + 企业互通 | ✅ v4.13.0 |
| **[TarsUITarsBridge](https://github.com/HP-jh/TarsUITarsBridge)** | 字节 UI-TARS 桌面操控 MCP 化独立仓库 | ✅ v0.1.0 |
| **[TarsOpenClawSandbox](https://github.com/HP-jh/TarsOpenClawSandbox)** | OpenClaw 漏洞覆盖沙箱（gVisor + firecracker + Tailscale） | ✅ v0.1.0 |
| **[TarsEnterprise](https://github.com/HP-jh/TarsEnterprise)** | 企业版网关（6 公司类型 + TSG 互通 + 智能体沙箱 + TOP 看板） | ✅ v0.2.0 |
| **[TarsWingGuard](https://github.com/HP-jh/TarsWingGuard)** | 模块化打包层（核心 vs 羽翼 + `wing.tier` 单参数解锁） | ✅ v0.1.0 |
| **[TarsVoiceCorrection](https://github.com/HP-jh/TarsVoiceCorrection)** | 语音输入纠错 MCP 工具单一来源 | 🚧 v0.1.0 跑中 |

---

## 🛣️ 路线图

详细规划见 [VERSIONING.md](https://github.com/HP-jh/TarsSecureGuard/blob/main/VERSIONING.md)，近期：

- **v4.11.x** — Tauri 桌面客户端 / auto-include / 360 UI / LobeHub 多设备路由 / Token 看板 / vKey / 模型路由 ✅
- **v4.12.0** — Knowledge Base v2 + Obsidian 双向同步 + voice_correction ✅
- **v4.13.0** — TSG ↔ TarsEnterprise 互通（`POST /interop/receive-command` + `GET /interop/events` SSE）✅
- **v4.14.x** — 画板可视化工作流 + AI 实时调整 + 独立上下文 + 大版本自定义应用接入 🎯
- **v4.15.x ~ v4.16.x** — 15+ 开源 MCP 化（LobeHub / Bifrost / Portkey / OneAPI / LiteLLM / Higress / Dify / LangChain / N8N / AutoGPT / RAGFlow / Mem0 / OWASP / Wazuh / Open WebUI）🎯
- **v4.17.x** — 安全极致档 8 项（动态拦截 / AI 识别 / 多渠道警告 / 客户端成熟度 / RBAC / 杀软兼容 / 抗外部攻击 / 内核级自保）🎯
- **v4.18.x ~ v4.19.x** — 精简代码 + 6 语言共生 + UI 界面 🎯
- 长期 — TarsWingGuard 持续打包 + TarsEnterprise 持续演进 + TarsOpenClawSandbox 持续覆盖 CVE

---

## 🤝 贡献

欢迎 PR / Issue / Discussion。开发流程见 [CHANGES.md](https://github.com/HP-jh/TarsSecureGuard/blob/main/CHANGES.md)。

---

## 📜 License

MIT — 详见 [LICENSE](https://github.com/HP-jh/TarsSecureGuard/blob/main/LICENSE)。

---

<div align="center">

© 2026 TarsSecureGuard · The Router of the AI Era · 万物皆 MCP 🚀 · MIT

</div>
