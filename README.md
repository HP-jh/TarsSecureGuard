<div align="center">

# 🛡️ TarsSecureGuard

### 本地优先 AI 网关 · 安全 Core 强制 · 万物皆 MCP

<p>
<img alt="Version" src="https://img.shields.io/badge/version-4.17.0-success">
<img alt="Go" src="https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white">
<img alt="Deps" src="https://img.shields.io/badge/dependencies-0-brightgreen">
<img alt="Platforms" src="https://img.shields.io/badge/platforms-7%20targets-blueviolet">
<img alt="MCP" src="https://img.shields.io/badge/MCP-Universal-blue">
<img alt="Enterprise" src="https://img.shields.io/badge/Enterprise-Interop-9cf">
<img alt="KB" src="https://img.shields.io/badge/KnowledgeBase-Obsidian-8A2BE2">
<img alt="Tests" src="https://img.shields.io/badge/tests-race%20green">
<img alt="PenTest" src="https://img.shields.io/badge/pen--test-passed-critical">
<img alt="SHA256" src="https://img.shields.io/badge/SHA256-verified-lightgrey">
<img alt="License" src="https://img.shields.io/badge/license-MIT-orange">
</p>

<p>
<b>零依赖</b> · <b>单文件</b> · <b>纯静态</b> · <b>解压即用</b> · <b>安全默认开启</b> · <b>不可关闭</b>
</p>

</div>

---

## 一句话定位

**TarsSecureGuard 是 AI 时代的路由器与配置器——左边接入 13 种 AI 客户端，右边连通 24 家云端模型商 + 8 种本地运行时 + 任意 MCP 生态；中间强制系好安全带：WAF、语义防护、分层限流、IP 信誉、RBAC、审计与 PII 脱敏全程不可绕过。**

从 Claude Desktop 到 Cursor，从 OpenAI 到 Ollama，从官方集成到社区 Marketplace——**一个 OpenAI 兼容密钥，打开所有模型、所有工具、所有协议**。Tauri 桌面端让这一切脱离浏览器，vKey 虚拟密钥体系让分发与回收秒级完成。

> 📊 **横向对比**：TSG vs Bifrost / LiteLLM / Portkey / promptward / ClawVault / llm-gateway —— 见 [COMPARISON.md](COMPARISON.md)

---

## 🏰 架构 · Kingdom 分类学

TSG v4.x 采用 **Crown Bus + Pipeline + Envelope** 三层架构，以 Kingdom 分类学组织 12 节点 × 26 职业：

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Crown（王冠调度层）                            │
│    Bus（总线）── 12 节点消息路由 │ Pipeline（流水线）── 阶段化编排      │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Envelope（信封）── 统一协议封装
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Security Core（强制·不可关闭）                     │
│   WAF → 语义分流 → 限流 → IP信誉 → RBAC → 审计 → PII → hash-chain    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
   ┌─────────┐          ┌──────────┐          ┌──────────┐
   │ Universal│          │  Persona │          │ Multi-agent│
   │ Connector│          │  角色面具 │          │  设备网   │
   │ 24+8+N   │          │ vKey 分发 │          │ E2E 加密  │
   └─────────┘          └──────────┘          └──────────┘
```

### 12 节点 × 26 职业

| 节点域 | 核心职业 | 职责 |
|--------|---------|------|
| **Security Core** | WAF Guard / Semantic Sentinel / Rate Limiter / IP Reputation / RBAC Enforcer / Auditor / PII Scrubber | 七层防护链，fail-close，AI 只能加严 |
| **Universal Connector** | Provider Registrar / Protocol Adapter / MCP Bridge / Stdio Broker / LobeHub Agent | 24 云端 + 8 本地 + 任意 MCP 桥接 |
| **Extender** | Detector / Configurator / Key Injector / Audit Logger | 自动探测本机 AI 工具并生成接入配置 |
| **Persona** | vKey Manager / Role Masker / Token Accountant / Namespace Guardian | 虚拟密钥 + 角色面具 + Token 看板 |
| **Smart Router** | Bandit Strategist / Score Keeper / Circuit Breaker | ε-greedy 自动优选 + 熔断降级 |
| **Resource Guardian** | Memory Warden / Load Balancer / Drain Coordinator | L0-L3 分级响应，RSS 口径 |

### Token 策略

- **运行时分**：成功率 × 时延 动态评分
- **离线评测**：lm-eval-harness 诚实标注（相对参考，不捆绑 Python）
- **Token 看板**：实时可视化的多维度模型消耗与性能面板
- **vKey 虚拟密钥**：秒级创建/回收/限额，与物理 provider 密钥解耦

---

## 💎 五大核心能力

### 1. Security Core —— 安全带不可解

WAF（路径穿越 / 命令注入 / SQLi / XSS / **Prompt 注入** / **越狱检测**）→ 语义检测分级分流（灰区送本地 0.5B–1.5B 小模型，fail-close 铁律）→ 三维令牌桶限流（IP×端点 / Key×端点 / IP 总量）→ 本地 IP 信誉评分（起分 100，自动封禁/恢复）→ RBAC 三角色 → hash-chain 审计 v2 → PII 四模式单遍脱敏 → SSRF 五红线。

**连接再广，安全链一行不削；AI 只能加严，100% 单测 + 运行时审计。**

### 2. Universal Connector —— 万物皆 MCP 🚀

**13 客户端 × 24 provider + 8 本地 + 任意 MCP 桥 + LobeHub 7 点**：

- **客户端**：Claude Desktop / Cursor / Cline / Continue / Windsurf / Codex CLI / Warp / Cody / JetBrains / Tabnine / Zed / Roo Code / VS Code Copilot
- **云端**：OpenAI / Anthropic / Gemini / DeepSeek / 通义 / 文心 / GLM / 豆包 / Kimi / MiniMax / 混元 / 星火 / Groq 等 24 家
- **本地**：Ollama / LM Studio / vLLM / llama.cpp / 等 8 种
- **MCP 桥**：任意 MCP Server 通过 stdio / HTTP / Streamable HTTP 接入
- **LobeHub**：7 点生态位覆盖（Chat / Agent / Plugin / Knowledge / Model / Provider / Market）

三种纳入模式：**embed（内嵌）/ federate（联邦）/ wrap-cli-as-mcp（包装 CLI）**。新增 provider **只写配置不改代码**。

### 3. Extender —— 配置器反向接管

别的 AI 工具环境配置繁琐？TSG 反过来替你配好——内置探测器扫出本机已装的 OpenClaw / Continue / Aider / Cline / ZooCode / Codex CLI，一键生成接入配置片段，密钥可选内嵌并全程审计。**零 GPL 污染、零外部依赖。**

### 4. Persona —— 角色面具与 vKey

- **角色面具**：不同场景切换不同系统提示与策略
- **vKey 虚拟密钥体系**：物理密钥隐藏，vKey 秒级分发/回收/限额
- **Token 看板**：实时消耗、性能退化、成本趋势一屏掌控
- **命名空间隔离**：user → tenant → global 三层，就近覆盖

### 5. Multi-agent + 设备网 —— 协作与隔离

- **多智能体协作**：Crown Bus 消息路由支持多 agent 并行与串行编排
- **设备网**：本地设备发现与纳管
- **E2E 加密**：好友基础 + 端到端加密（v4.18+ 路线）

---

## 🆕 v4.11+ 新增亮点

| 版本 | 核心新增 |
|------|---------|
| **v4.11** | Tauri 桌面端（脱离浏览器，原生窗口）/ auto-include MCP 桥（自动发现 MCP Server）/ 360 UI（全新管理面板）/ LobeHub 深度集成 / Token 看板 / vKey 模型路由 |
| **v4.12** | UI-TARS 桌面操控 MCP 集成（AI 直接操控本地 GUI） |
| **v4.13** | **万物皆 MCP** —— 任意工具、任意协议、任意数据源统一桥接；TarsEnterprise / TarsOpenClawSandbox / KnowledgeBase / Obsidian / Voice Correction 全打通 |
| **v4.17** | **Community Marketplace** —— 社区 MCP 包发现、来源注册、信任验证、一键安装；SHA256 校验 + 签名验证 + 100MB 上限 + personal 二次确认 |

---

## 🗺️ 版本路线

- **v4.18** Friend Foundation —— 好友基础 + E2E 加密 + 命名空间隔离
- **v4.19** 企业级审计增强 + 合规报表导出
- **v4.20** 智能体工作流编排可视化
- **v4.21** 联邦学习轻量节点

> 完整变更日志见 [CHANGES.md](CHANGES.md)

---

## 📊 横向对比

| 维度 | **TarsSecureGuard** | LiteLLM | Bifrost | Portkey | promptward | ClawVault |
|------|:-------------------:|:-------:|:-------:|:-------:|:----------:|:---------:|
| **技术栈** | Go（零依赖） | Python（需 PG+Redis） | Rust | Go | Python | Go |
| **部署重量** | 单文件 20MB | 镜像 500MB+，整套 ~1GB | 中等 | 轻量 | 中等 | 中等 |
| **安全默认** | ✅ 强制开启，不可关闭 | 可选插件 | 可选中间件 | 可选策略 | 可选 | 可选 |
| **语义防护** | ✅ fail-close + 本地小模型 | 基础过滤 | 无 | 基础 | 有 | 无 |
| **本地优先** | ✅ 纯静态，拷到 U 盘即跑 | 云模型为主 | 云为主 | 云为主 | 云为主 | 混合 |
| **MCP 生态** | ✅ 万物皆 MCP + 社区市场 | 无 | 无 | 无 | 无 | 无 |
| **桌面端** | ✅ Tauri 原生窗口 | 无 | 无 | 无 | 无 | 无 |
| **资源守护** | ✅ L0-L3 分级 + RSS 口径 | 无 | 无 | 无 | 无 | 无 |
| ** provider 数** | 24 云端 + 8 本地 + N MCP | 100+ | 15+ | 20+ | 10+ | 8+ |
| **许可证** | MIT | MIT | Apache-2 | MIT | MIT | MIT |

**核心差异**：TSG 不拼"provider 数量"，而是占据被忽视但对个人与内网极痛的生态位——**零配置 + 单文件 + 安全默认强制 + 本地优先 + MCP 万物互联**。重型网关服务有大平台团队的企业；TSG 服务"今天就想安全、稳定地把 AI 用起来"的个人、极客与隔离内网。

---

## 🚀 快速开始

### 一键安装（自动识别系统与架构）

```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.ps1 | iex
```

安装后运行 `tsg` 启动，浏览器自动打开 `http://127.0.0.1:18889`；`tsg doctor` 环境自检。

### Tauri 桌面端（推荐）

从 [Release](../../releases) 下载对应平台安装包（Windows `.exe` / macOS `.dmg` / Linux `.deb`·`.AppImage`）→ 双击安装 → 原生窗口直接打开管理台，无需浏览器。

### 从源码运行

```sh
git clone https://github.com/HP-jh/TarsSecureGuard && cd TarsSecureGuard
go run .          # 或 ./start.sh（Windows 双击 start.bat）
```

### MCP stdio 接入

```sh
./tarssecureguard --mcp-stdio
# 在支持 MCP stdio 的本地 agent 中注册为 MCP server，即自动获得全套受防护工具
```

### 六平台构建

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=4.17.0" -o tarssecureguard .
go test -race ./...      # 单元 + 集成测试
```

> 默认管理端口 `18889`，API Key 请在 `config.json` 修改或用环境变量 `TARS_API_KEY` 注入。

---

## 🏰 最深护城河

1. **工程简洁层**：零第三方依赖、纯静态单文件、七平台产物。对手能模仿，但需长期克制——多数团队做不到。
2. **安全知识层**：Security Core 是整套针对 LLM 的防御资产——WAF 特征、语义灰区判定、IP 信誉指纹、PII 模式、审计体系。**真实样本越多 → 规则越准 → 误报越低 → 用户越多 → 样本越多**，自我强化飞轮。
3. **信任与分发层**：安全产品最终壁垒是"从未出事"的信任记录。v4.x **万物皆 MCP + 社区 Marketplace** 让防护能力随生态自动扩散，形成分发飞轮。

---

## 📚 文档索引

- [CHANGES.md](CHANGES.md) —— 版本完整变更
- [COMPARISON.md](COMPARISON.md) —— 横向对比详情
- [COMPATIBILITY.md](COMPATIBILITY.md) —— 跨平台矩阵与构建指南
- [docs/v4.17.0-marketplace.md](docs/v4.17.0-marketplace.md) —— Community Marketplace 设计与使用
- [docs/v4.13.0-mcp-universal.md](docs/v4.13.0-mcp-universal.md) —— 万物皆 MCP 架构
- [docs/v3.2.2-governance.md](docs/v3.2.2-governance.md) —— 治理层（共享记忆 / 共享信息 / OAuth / 守门人 / 审计）
- [deploy/](deploy) —— systemd / Docker / K8s / LaunchDaemon 部署件

---

## 👤 关于作者

> 我是这个项目的发起者，一名正在读小学的学生。
> 从架构设计到代码实现，**由我主导并借助 AI 工具完成**。如果你认可这个项目，希望能给我一个 **Star**，这对我意义重大。

## 🤝 欢迎支持

- 遇到问题请提交 [Issue](https://github.com/HP-jh/TarsSecureGuard/issues)
- 觉得不错请点 **Star**，是最大的鼓励
- 欢迎分享给有需要的朋友

## ⚠️ 维护说明

> **本项目依赖 AI 服务套餐，若因套餐额度耗尽或服务商调整，可能导致更新暂时停滞。**
> 如遇较长时间未更新，请理解这是 AI 服务限制所致，并非项目放弃维护。
> 恢复服务后会第一时间继续推进，感谢你的耐心与包容。

---

<div align="center">

🛡️ **TarsSecureGuard —— Your AI's Safety Belt。解压即用，安全常驻。**

[MIT License](LICENSE)

</div>
