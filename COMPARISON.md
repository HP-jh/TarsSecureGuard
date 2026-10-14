# TarsSecureGuard vs 其他 AI 网关 / LLM Gateway

> 最后更新：v4.9.0 (2026-10-14)

## 一句话定位

**TSG 是零依赖单文件的本地 AI 安全网关**：Security Core 强制开启，接 13 种客户端，连 35 家 provider，MCP stdio 即插即护。解压即用，数据不出本机。

## 对比表

| 能力 | TSG | Bifrost (Maxim) | LiteLLM | Portkey | promptward | ClawVault (斗象) | llm-gateway (OpenZiti) |
|---|---|---|---|---|---|---|---|
| 语言 | Go | Go | Python | TypeScript | Rust | 未知 | Go |
| 单文件零依赖 | ✅ | ❌ (npx/Docker) | ❌ (Python+Postgres) | ❌ | ✅ | ❌ | ❌ |
| 开源协议 | MIT | Apache 2.0 | MIT | MIT (open core) | 开源 | 开源 | Apache 2.0 |
| OpenAI 兼容 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Provider 数 | 35 | 20+ | 100+ | 1600+ | — | — | 多 |
| 安全 Core 强制 | ✅ 不可关 | ❌ 可选 | ❌ 可选 | ❌ 可选 | ✅ | ✅ | ❌ |
| Prompt 注入防护 | ✅ 特征+语义 fail-close | 插件 | 插件 | 插件 | ✅ 专门做 | ✅ | ❌ |
| PII 脱敏 | ✅ | — | — | ✅ | ✅ | ✅ | ❌ |
| 三维限流 + IP 信誉 | ✅ | — | — | ✅ | — | — | ❌ |
| SSRF 五红线 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| hash-chain 审计 | ✅ | — | — | ✅ | — | — | ❌ |
| MCP stdio 本地防护 | ✅ | ✅ (MCP 工具) | — | ✅ (MCP gateway) | — | ✅ (Agent 工具管控) | ❌ |
| 本地优先 / 数据不出机 | ✅ | ❌ | ✅ self-host | ❌ cloud | ✅ | ✅ | ✅ zero-trust |
| 跨平台二进制 | Win/mac/Linux/Android | npx/Docker | Docker | Docker | 单二进制 | 未知 | Docker |
| 成本 | 免费 | 免费 (公司商业) | 免费 | 免费+云付费 | 免费 | 免费 | 免费 |

## TSG 不适合谁

- 你要管 1600+ 模型、企业级合规审计、SIEM 外发 → 用 Portkey 或奇安信
- 你只要 prompt injection 检测，不要路由 → 用 promptward
- 你要 Python 生态深度集成 → 用 LiteLLM

## TSG 适合谁

- 你是开发者，想在自己电脑上安全地用 Claude Desktop / Cursor / Cline / Continue
- 你在隔离内网，不能装 Docker / Python / Postgres
- 你要把 AI 网关拷到 U 盘里应急
- 你要 MCP 工具调用在本地就被包一层安全壳，不开端口
- 你不想让任何云厂商看到你的 prompt
