<div align="center">

# 🛡️ TarsSecureGuard

### Your AI's Safety Belt —— 给你的 AI 系上安全带

<p>
<b>解压即用</b> · <b>安全性强</b> · <b>无需配置</b> · <b>全平台兼容</b>
</p>

<p>
一个零依赖、单文件、纯静态的<b>本地 AI 安全网关</b>：统一纳管本地 GGUF / LM Studio / Ollama 与云端模型，<br/>
在最外层强制开启 WAF、语义防护、分层限流、IP 信誉、RBAC、审计与 PII 脱敏，<br/>
并以资源守护器、智能路由与模型评分，让本地 AI <b>跑得稳、选得优、守得住</b>。
</p>

<p>
<img alt="Version" src="https://img.shields.io/badge/version-3.0.0-success">
<img alt="Go" src="https://img.shields.io/badge/Go-1.22.5-00ADD8?logo=go&logoColor=white">
<img alt="Deps" src="https://img.shields.io/badge/dependencies-0-brightgreen">
<img alt="Platforms" src="https://img.shields.io/badge/platform-6%20targets-blueviolet">
<img alt="Tests" src="https://img.shields.io/badge/tests-race%20green">
<img alt="License" src="https://img.shields.io/badge/license-MIT-orange">
</p>

</div>

---

## 📣 推荐语

> **不想配环境、不想写 YAML、不想让本地模型裸奔、也不想它在你电脑上失控？TarsSecureGuard 是你的答案。**
>
> 下载一个压缩包，解压，双击 —— 浏览器自动打开中文管理面板，本地模型、云端模型、搜索、工具、安全审计全部就位。
> 它不是又一个需要 Docker + 数据库 + Redis 的"重型网关"，而是一个 **零依赖、纯静态、拷到 U 盘里都能跑** 的安全网关；
> v3.0 更进一步，像安全带一样——平时无感，出事的瞬间把你牢牢护住。
>
> 当 LiteLLM 还在让你拉 1GB 镜像、New API 还在让你装 MySQL 时，TarsSecureGuard 已经替你把安全带系好了。

---

## 🌟 介绍语

TarsSecureGuard 是一款**本地优先（local-first）的 AI 安全网关**。它站在你和本地推理引擎（llama.cpp / LM Studio / Ollama）以及云端模型（OpenAI / DeepSeek / 自定义）之间，对外只暴露一个 OpenAI 兼容端点（HTTP 或 **stdio**），对内统一调度、统一治理、统一审计。

### 四大核心特点

| 特点 | 说明 |
|------|------|
| 📦 **解压即用** | 无需安装、无需容器、无需数据库。压缩包解压，双击 `start.bat` / `start.sh`，服务即起，浏览器自动打开中文面板。 |
| 🔒 **安全性强** | Security Core 强制加载、**不可关闭**：WAF（路径穿越 / 命令注入 / SQLi / XSS / **Prompt 注入** / **PII 检测**）、**语义检测分级分流（fail-close）**、**三维令牌桶限流**、**本地 IP 信誉评分**、RBAC 三角色、结构化审计、PII 脱敏、SSRF 五红线、防火墙三档联动。 |
| ⚙️ **无需配置** | 开箱即有合理默认；本地模型**自动发现**（每 60 秒探测 LM Studio / Ollama / llama.cpp）；`config.json` 改动 2 秒热重载，改完不重启。 |
| 💻 **环境兼容性好** | 一份代码，六平台产物（macOS Intel/Apple Silicon、Linux x86_64/ARM64、Windows x64/ARM64）；`CGO_ENABLED=0` 纯静态，老内核、老发行版、内网隔离即拷即跑。 |

### 💎 订阅版（Subscription）

> **社区版完全免费、开源（MIT）；订阅版面向希望"省心 + 合规 + 持续更新"的用户。**

| 能力 | 社区版（免费） | **订阅版（推荐）** |
|------|:---:|:---:|
| 网关 / 本地与云端模型 / WAF / 语义防护 / 限流 / IP 信誉 / RBAC / 审计 | ✅ | ✅ |
| 资源守护器 / 智能路由 / 模型评分 / MCP stdio | ✅ | ✅ |
| 全平台六架构产物 | ✅ | ✅ |
| **一键更新包**（云盘最新版自动构建，免手动） | — | ✅ |
| **安全规则库持续更新**（最新 Prompt 注入 / 越狱特征、IP 信誉策略） | 社区节奏 | **优先更新** |
| **lm-eval 离线评测数据导入与调优建议** | 手动 | ✅ 专家调优 |
| 私有化 / 内网合规部署支持 | — | ✅ |
| 原厂技术支持与 SLA | — | ✅ |

订阅即获得**持续的安全防护更新与省心交付**：你只管解压使用，防护、稳定性与兼容性由订阅持续兜底。

---

## 🧩 v3.0.0 能力一览（"Your AI's Safety Belt"）

### A 线 · 资源守护器（resourceGuardian）
- `GOMEMLIMIT` 软内存上限（min(物理 10%, 384MB)，eco 档 128MB，可覆盖）。
- **L0–L3 分级响应**：L1 降级非核心 → L2 熔断高耗 → L3 优雅停机（30s drain + 审计刷盘 + 状态保存 + 退出码 42 + 冷却防风暴）。
- L2/L3 以 **RSS 口径**判定，捕捉 CGO / 外部内存泄漏；eco 省资源档对 D 档硬件自动套用。

### B 线 · 防护升级
- **语义检测分级分流（semanticGuard）**：静态规则先行，灰区送本地 0.5B–1.5B 小模型判定；**fail-close 铁律**——引擎不可用直接 503，绝不放行；指纹缓存 + 灰区速率上限。
- **三维令牌桶限流（rateLimiter）**：IP×端点类 / Key×端点类 / IP 总量，超限 429 并联动信誉扣分。
- **本地 IP 信誉（ipReputation）**：起分 100，WAF/扫描/限流扣分，低分自动封禁、白名单、24h 自动恢复、NAT 异常告警、admin 解封。
- 「**AI 只能加严**」单向合并铁律：安全策略只允许更严格，100% 单测 + 运行时审计。

### C 线 · 两阶段智能路由
- **smartRouter**：静态规则优先兜底 + **ε-greedy bandit**（ε 0.1→0.02 衰减），按成功率/时延历史自动优选后端；非 admin 反馈降权防伪造。
- **scoreBoard**：运行时分（成功率×时延）融合 **lm-eval-harness** 离线评测（相对参考、诚实标注；Python 边车按需，不捆绑）。

### D 线 · 生态位升维
- **`--mcp-stdio`：JSON-RPC 2.0 over stdio**，任何本地 agent 接入即获全套防护——本版核心差异化。
- 工具：`tars_guarded_chat` / `tars_guard_status` / `tars_route_preview` / `tars_model_score` / `tars_module_schema` / `tars_ip_reputation_unban`；管理操作需 `TSG_ADMIN_KEY`，全程审计。

### E 线 · 稳定性工程
- panic recovery 全覆盖；Go fuzzing（WAF / 配置解析 / 语义归一）；**8 小时 soak 压测脚本**（`soak.sh` / `soak.ps1`）；单元 + httptest 集成测试 `-race` 全绿。

### 平台与交付
- UI 全量中文化；**部署件齐全**：systemd unit、Dockerfile、docker-compose（rootless）、K8s sidecar 示例、macOS LaunchDaemon（见 [`deploy/`](./deploy)）。
- `go.mod` 零第三方依赖，全部标准库 —— **零供应链攻击面**。

---

## 🏗️ 架构

```
                 ┌──────────────────────────────────────────────────┐
 OpenAI SDK /    │            Security Core（强制·不可关闭）           │
 本地 Agent ───▶ │ WAF → 语义分流 → 限流 → IP信誉 → RBAC → 审计 → PII │
 (HTTP / stdio)  └─────────────────────────┬────────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    │   两阶段智能路由（静态规则 + ε-greedy bandit）  │
                    └──────────────────────┬───────────────────────┘
        ┌────────────┬────────────┬─────────┴────────┬────────────┬────────────┐
        ▼            ▼            ▼                  ▼            ▼            ▼
   本地 GGUF      LM Studio    Ollama            云端模型      工具/MCP     资源守护器
  (llama.cpp)     :1234        :11434         OpenAI/DeepSeek  搜索/抓取    L0-L3/评分
```

---

## 🚀 快速开始

### Windows
解压压缩包 → 双击 `start.bat`（未编译会自动 go build）→ 浏览器自动打开 `http://127.0.0.1:18889`。

### macOS / Linux
```sh
unzip tarssecureguard-v3.0.0-src.zip && cd tarssecureguard-v3.0.0
./start.sh
```

### MCP stdio 接入（核心差异化）
```sh
./tarssecureguard --mcp-stdio
# 在支持 MCP stdio 的本地 agent 中把该命令注册为一个 MCP server，
# 即自动获得 tars_guarded_chat 等全套受防护工具。
```

### 从源码构建（六平台）
```sh
GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=3.0.0" -o tarssecureguard .
go test -race ./...      # 单元 + 集成测试
./soak.sh                # 8 小时稳定性压测（可选）
```
完整六平台构建命令与最低系统矩阵见 [COMPATIBILITY.md](./COMPATIBILITY.md)。

> 默认管理端口 `18889`，本地模型端口 `18890`；默认 API Key `tars-gateway-key`，请在 `config.json` 修改或用环境变量 `TARS_API_KEY` 注入；管理操作可用 `TSG_ADMIN_KEY`。

---

## 🖥️ 跨平台兼容矩阵

| 平台 | 最低系统 | 状态 |
|------|----------|:---:|
| macOS Intel (amd64) | macOS 10.15 Catalina | ✅ |
| macOS Apple Silicon (arm64) | macOS 11 Big Sur | ✅ |
| Linux x86_64 | 内核 2.6.32+（纯静态） | ✅ |
| Linux ARM64 | 内核 2.6.32+（纯静态） | ✅ |
| Windows x64 | Windows 10 / 11 | ✅ |
| Windows ARM64 | Windows 10/11 on ARM | ⚠️ 实验性 |

详见 [COMPATIBILITY.md](./COMPATIBILITY.md)。

---

## 🥊 最大竞争对手分析

**结论：当前最大、最需要正面回应的竞争对手是 LiteLLM**（开源 AI 网关事实标准，约 6 万 Star，生态与心智最强）；国内市场 **New API / One API** 是 Go 路线心智领导者；"本地优先"定位上 **OmniRoute** 最接近。

| 对手 | 优势 | 相对 TarsSecureGuard 的短板 |
|------|------|----------------------------|
| **LiteLLM**（最大对手） | 提供商覆盖最广、生态成熟、虚拟密钥/预算/重试完善、海外心智第一 | Python 技术栈，部署重（需 Postgres + Redis，镜像 500MB+，整套近 1GB）；云模型为中心；安全非默认卖点；无单文件解压即用；无语义 fail-close / 资源守护 |
| **New API / One API**（国内心智） | Go 编写、国产模型全、渠道/令牌/计费/充值运营链路完整 | 定位"API 转售/运营计费"，需 MySQL + Redis；参数繁杂；非本地模型 / 单机安全场景设计 |
| **OmniRoute**（本地优先） | 明确 local-first、Star 增长快、自动降级与多路由策略 | 偏"多供应商聚合路由"，安全治理（WAF/语义/RBAC/限流/IP 信誉/审计/PII）非核心；单文件零依赖内网合规并非其主张 |
| **LM Studio / Ollama + OpenWebUI**（"够用"替代品） | 用户已安装、GUI 友好、模型发现方便 | 它们是**运行时**而非治理网关：不提供 WAF、语义防护、限流、IP 信誉、RBAC、审计、资源守护 —— TarsSecureGuard 恰好纳管并补齐这一层 |

**差异化打法**：不拼"提供商数量"，而占据被忽视、对个人与内网极痛的生态位 —— **「零配置 + 单文件 + 安全默认开启 + 本地优先 + stdio 即插即护」**。重型网关服务于有平台团队的大企业；TarsSecureGuard 服务于"今天就想安全、稳定地把本地 AI 用起来"的个人、极客与隔离内网。

---

## 🏰 最深护城河分析

**结论：最深的护城河是「Security Core」沉淀的信任资产与 LLM 安全防御知识库，并由「零依赖单文件」的零攻击面工程持续加固；v3.0 的 MCP stdio 让这套防护随接入自动分发，进一步扩大护城河。**

护城河由浅到深分三层：

1. **工程简洁层（易被复制，短期优势）**：零第三方依赖、纯静态单文件、六平台、资源守护与智能路由。对手能模仿，但需长期克制、放弃生态——多数团队做不到。

2. **安全知识层（核心壁垒，随时间复利）**：Security Core 是一整套**针对 LLM 的防御资产**——WAF 与 Prompt 注入/越狱特征、语义灰区判定（fail-close）、IP 信誉行为指纹、三维限流、PII 模式与脱敏、SSRF 五红线、防火墙联动、审计体系，以及在"检出率 vs 误报率"上的持续调优。**真实样本越多 → 规则越准 → 误报越低 → 用户越多 → 样本越多**，自我强化飞轮，后发者无法靠一次抄代码补齐。

3. **信任与分发层（最深、最难复制）**：安全产品的最终壁垒是**"从未出事"的信任记录**与合规心智；"安全永远无法关闭 / AI 只能加严"的设计承诺沉淀为默认选择。v3.0 的 **stdio 即插即护**意味着任何本地 agent 接入即继承整套防护——防护能力随接入自动扩散，形成**分发飞轮**。订阅版以持续安全更新与 SLA 把信任变现。信任无法在一个季度内建立，也无法被价格战摧毁。

> **诚实判断**：项目处于成长期，护城河仍在"加宽中"——功能层面可被复制。真正的宽度由**采用量带来的防御数据 + stdio 分发飞轮 + 长期无事故信任记录**决定。订阅版的战略价值，正是把"持续安全更新"做成可复利、可收费、可沉淀信任的资产。

---

## 📚 文档

- [CHANGES.md](./CHANGES.md) —— 各版本完整变更（含 v3.0.0 五线进展）
- [COMPATIBILITY.md](./COMPATIBILITY.md) —— 跨平台兼容矩阵与构建指南
- [OPTIMIZATION_REPORT.md](./OPTIMIZATION_REPORT.md) —— 优化报告与技术路线
- [deploy/](./deploy) —— systemd / Docker / docker-compose / K8s / LaunchDaemon 部署件

## 📄 许可证

[MIT License](./LICENSE) —— 可自由使用、修改与分享。

<div align="center">

🛡️ **TarsSecureGuard —— Your AI's Safety Belt。解压即用，安全常驻。**

</div>
