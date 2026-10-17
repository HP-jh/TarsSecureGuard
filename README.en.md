🌐 **Languages**: [🇨🇳 简体中文](README.md) · [🇺🇸 English](README.en.md) · [🇷🇺 Русский](README.ru.md) · [🇸🇦 العربية](README.ar.md) · [🇫🇷 Français](README.fr.md) · [🇯🇵 日本語](README.ja.md) · [🇰🇷 한국어](README.ko.md)

---

<div align="center">

# 🛡️ TarsSecureGuard

### The Router & Configurator of the AI Era — with built-in safety belt, desktop client, and pluggable MCP bridge

<p>
<b>Zero-dependency single-file</b> · <b>7 native platforms</b> · <b>Security Core cannot be disabled</b> · <b>Tauri desktop client</b> · <b>auto-include MCP bridge</b> · <b>Local AI that actually works</b>
</p>

<p>
Local AI security gateway (LLM proxy). On the left connects <b>13 AI software clients</b> (Claude Desktop / Cursor / Cline / Continue / Windsurf / Codex / Roo Code / VS Code Copilot / Zed / JetBrains …),<br/>
on the right links <b>24 cloud models + 8 local inference runtimes</b> (OpenAI / Anthropic / Gemini / DeepSeek / Tongyi / Wenxin / GLM / Doubao / Kimi / Hunyuan / Xinghuo / Groq / Ollama / vLLM …),<br/>
outside hangs <b>any MCP bridge</b> (such as ByteDance UI-TARS desktop control), with WAF, prompt injection protection, PII redaction, rate limiting, IP reputation, RBAC, and audit <b>always on by default</b>.
</p>

<p>
<b>v4.11+ ships with a desktop client</b>: system tray / loading window / admin privileges / auto-updater / WebSocket real-time events,<br/>
Windows / macOS / Linux / Android consistent experience — <b>unzip, double-click, browser auto-opens admin panel</b>.
</p>

<p>
<img alt="Version" src="https://img.shields.io/badge/version-4.11.0-success">
<img alt="Go" src="https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white">
<img alt="Deps" src="https://img.shields.io/badge/dependencies-0-brightgreen">
<img alt="Providers" src="https://img.shields.io/badge/providers-13clients%C3%9724cloud-blue">
<img alt="Platforms" src="https://img.shields.io/badge/platforms-7%20native%20targets-blueviolet">
<img alt="MCP" src="https://img.shields.io/badge/MCP-stdio%20%2B%20HTTP%20%2B%20auto--include-22d3ee">
<img alt="Tests" src="https://img.shields.io/badge/tests-race%20green">
<img alt="License" src="https://img.shields.io/badge/license-MIT-orange">
</p>

</div>

---

## 📣 Recommendation

> **When every AI client ships with its own private model ecosystem, TarsSecureGuard lets you connect all models, all clients, and all external MCP tools with just one OpenAI-compatible key — and forces the safety belt on.**
>
> Starting v4.11, TSG is not just a gateway, it is a **gateway + desktop client + MCP bridge** three-piece suite:
>
> - **🖥️ Tauri Desktop Client**: system tray / loading window / admin privileges / auto-updater / WebSocket events — Windows / macOS / Linux / Android consistent experience
> - **🔌 auto-include MCP Bridge**: add one line in `config.json` to mount external MCP servers (ByteDance UI-TARS desktop control / any MCP tool), no TSG code changes needed
> - **🌍 7 Native Platforms**: linux-amd64/arm64 + darwin-amd64/arm64 + windows-amd64.exe/arm64.exe + android-arm64, none missing
> - **🛡️ Security Core Cannot Be Disabled**: WAF / prompt injection / PII / rate limiting / IP reputation / RBAC / audit on by default, **cannot be turned off**
> - **🤝 13 Clients × 24 Models × 8 Runtimes**: Claude / Cursor / Cline / Continue / Windsurf / Codex / Roo Code / Copilot / Zed / JetBrains … pick any
> - **📦 Zero-dependency single-file**: `go.mod` zero third-party deps, no containers, no databases, no external services, **runs from a USB stick**
>
> Not another "heavy gateway" that makes you pull a 1GB image, install MySQL, or set up Python/Node — a **zero-dependency, purely static, runs-from-USB** local AI security gateway + desktop client.

---

## 🌟 Introduction

TarsSecureGuard is a **local-first AI gateway + desktop client**. It stands between you and all AI capabilities: on the left your AI software, on the right 24 cloud models + 8 local inference runtimes, outside ByteDance UI-TARS and other MCP bridges; unified scheduling, governance, and audit internally, OpenAI-compatible endpoint (HTTP or **stdio**) + MCP standard protocol externally.

A home router doesn't make cables or websites — it lets every device get online safely. TarsSecureGuard doesn't make models or lock you into a client — **it lets every AI client safely use every model + every external tool.**

### v4.11 Capability Matrix

| Module | Status | Description |
|---|---|---|
| **Security Core cannot be disabled** | ✅ Since v3.0 | WAF / Prompt injection / PII / Rate limiting / IP reputation / RBAC / Audit / SSRF five red lines / Semantic gray-zone fail-close |
| **Universal Connector router** | ✅ Since v3.2 | 13 clients × 24 providers, add provider by JSON only |
| **Extender configurator** | ✅ Since v3.7 | Detect locally installed AI tools, one-click generate access config |
| **Persona profession system** | ✅ Since v3.8 | 5 profession templates, adaptive module/link/model matching |
| **Multi-agent + device mesh** | ✅ Since v4.1 | Multi-agent collaboration / MCP / distributed device mesh |
| **Kingdom taxonomy architecture** | ✅ Since v4.9 | Kingdom/phylum/class/order/family/genus/species分层, zero-damage compatibility layer |
| **🆕 Tauri Desktop Client** | ✅ v4.11+ | System tray + loading window + admin privileges + auto-updater + WebSocket events + 7 native platforms |
| **🆕 auto-include MCP bridge** | ✅ v4.11+ | One line in config.json mounts external MCP server, tools auto-merge to /tools/list |
| **🆕 360 Security UI** | ✅ v4.11+ | Left nav + right large panel, 360 Security Guard style |
| **🆕 LobeHub multi-device routing** | ✅ v4.11+ | Multi-device collaboration + multi-agent style |
| **🆕 Token usage dashboard** | ✅ v4.11+ | Statistics by provider / app / day, visual dashboard |
| **🆕 vKey virtual key system** | ✅ v4.11+ | Per-user / per-app independent virtual keys + quota + audit + revocation |
| **🆕 Model routing strategy** | ✅ v4.11+ | Simple requests → small models to save money, complex → large models for quality |
| **🆕 ByteDance UI-TARS desktop control** | 🎯 v4.12+ | Integrate UI-TARS-1.5-7B / Doubao vision model, AI calls screenshot/click/type/scroll/open-browser via MCP |

### Six Core Features

| Feature | Description |
|---|---|
| 🔌 **Connect Everything** | 13 clients × 24 cloud providers + 8 local runtimes + any MCP bridge, add provider/tool by config only |
| 📦 **Zero-dependency, unzip-and-run** | Single-file native binary, `go.mod` zero third-party deps, no containers, no databases, no external services, **runs from a USB stick** |
| 🔒 **Security Core Cannot Be Disabled** | WAF / prompt injection / PII redaction / 3D token-bucket rate limiting / IP reputation / RBAC 3-role / hash-chain audit / SSRF five red lines / firewall 3-level联动 / semantic gray-zone fail-close — **no line cut however wide the connection**. "AI can only tighten" one-way merge铁律 |
| 🖥️ **Desktop Client** | Tauri cross-platform client: system tray resident, loading startup window, admin privileges auto-start, auto-updater pulls new versions, WebSocket real-time events, Windows / macOS / Linux / Android consistent experience |
| 🧩 **Pluggable MCP Bridge** | ByteDance UI-TARS desktop control / any MCP server mounts via auto-include with one click, tools automatically appear in /tools/list, no TSG code changes |
| 💻 **Environment Compatible** | One codebase, 7 native platforms (linux / darwin / windows × amd64 / arm64 + android-arm64), `CGO_ENABLED=0` purely static, old kernels, air-gapped networks, copy and run |

### Advanced Capabilities

- **🖥️ Tauri Desktop Client**: system tray resident + loading startup window + admin privileges + WebSocket real-time events + 7 native platforms + auto-updater
- **🔌 auto-include MCP Bridge**: add `auto_include` in `config.json`, gateway auto-discovers and mounts external MCP servers on startup
- **🖱️ ByteDance UI-TARS Desktop Control**: integrates UI-TARS-1.5-7B / Doubao vision models, AI calls screenshot / click / type / scroll / open-browser via MCP — letting AI literally "use your hands" on the desktop
- **🛡️ 360 Security UI**: left navigation + right large panel, 360 Security Guard style layout, security module visualization (WAF logs / interception stats / reputation score / audit chain in one screen)
- **🧠 LobeHub Multi-device Routing**: multi-device collaboration / multi-agent style, AI module supports multi-provider routing + multi-agent collaboration
- **📊 Token Usage Dashboard**: statistics by provider / app / day, visual dashboard
- **🔑 vKey Virtual Key System**: per-user / per-app independent virtual keys, quota + audit + revocation, benchmarked against Qi-Anxin
- **🎯 Model Routing Strategy**: simple requests go to small models to save money, complex requests go to large models for quality, auto-selected

---

## 🚀 One command, unzip and run

No Docker, no Postgres, no Node.js / Python / any runtime, runs from a USB stick.

**macOS / Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
tsg
```

**Windows PowerShell:**

```powershell
irm https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.ps1 | iex
tsg
```

→ Detects system → Downloads binary → SHA256 verified → Installation complete
→ Gateway starts, desktop client auto-launches, browser opens http://127.0.0.1:18889

**Network restricted?** Set domestic mirror (built-in gh-proxy / ghfast fallback):

```bash
TSG_MIRROR=gh-proxy curl -fsSL https://gh-proxy.com/raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
```

---

## 📦 Download v4.11.0 Binaries

7 native platforms + SHA256 checksums included.

| Platform | File | Size |
|---|---|---|
| Linux x86_64 | `tsg-v4.11.0-linux-amd64` | ~12 MB |
| Linux ARM64 | `tsg-v4.11.0-linux-arm64` | ~12 MB |
| macOS Intel | `tsg-v4.11.0-darwin-amd64` | ~12 MB |
| macOS Apple Silicon | `tsg-v4.11.0-darwin-arm64` | ~12 MB |
| Windows x64 | `tsg-v4.11.0-windows-amd64.exe` | ~13 MB |
| Windows ARM64 | `tsg-v4.11.0-windows-arm64.exe` | ~13 MB |
| Android ARM64 | `tsg-v4.11.0-android-arm64` | ~12 MB |

All platforms share [SHA256SUMS.txt](https://github.com/HP-jh/TarsSecureGuard/releases/download/v4.11.0/SHA256SUMS.txt) for verification.

---

## 🆚 Compare with Other AI Gateways

| Gateway | Dependencies | Size | Security Default | MCP | Desktop Client |
|---|---|---|---|---|---|
| **TSG v4.11** | **0** | **~12 MB** | **Cannot be disabled** | **Client + Server + auto-include** | **Tauri 7 platforms** |
| Bifrost (Go) | Go runtime | ~30 MB | Off | ✅ Server | — |
| LiteLLM | Python + Postgres + Redis | ~1 GB | Off | ✅ Server | — |
| Portkey | Node.js + Redis | ~50 MB | Partial | ✅ Server | — |
| OneAPI | Go runtime | ~15 MB | Off | — | — |

Full comparison see [COMPARISON.md](https://github.com/HP-jh/TarsSecureGuard/blob/main/COMPARISON.md).

---

## 💎 Subscription

> **Community edition is completely free and open-source (MIT); Subscription edition is for users who want "peace of mind + compliance + continuous updates".**

| Capability | Community (Free) | **Subscription (Recommended)** |
|---|---|:---:|
| Gateway / Local & cloud models / WAF / Semantic protection / Rate limiting / IP reputation / RBAC / Audit | ✅ | ✅ |
| Tauri desktop client / 7 platforms / auto-include MCP bridge / 360 UI / LobeHub | ✅ | ✅ |
| **One-click update package** (cloud auto-build, no manual work) | — | ✅ |
| **Security rule library continuous updates** (latest prompt injection / jailbreak signatures, IP reputation strategies) | Community pace | **Priority updates** |
| **lm-eval offline evaluation import & tuning advice** | Manual | ✅ Expert tuning |
| Private / air-gapped compliance deployment support | — | ✅ |
| Vendor technical support & SLA | — | ✅ |

Subscription gives you **continuous security updates and peace-of-mind delivery**: just unzip and use, protection, stability and compatibility are continuously backed by the subscription.

---

## 🔗 Related Projects

- **TarsUITarsBridge** (standalone project): ByteDance open-source UI-TARS desktop control MCP-ified → [github.com/HP-jh/TarsUITarsBridge](https://github.com/HP-jh/TarsUITarsBridge)

---

## 🛣️ Roadmap

Detailed planning see [VERSIONING.md](https://github.com/HP-jh/TarsSecureGuard/blob/main/VERSIONING.md). Recent:

- **v4.11.x** — Tauri desktop client / auto-include / 360 UI / LobeHub multi-device / Token dashboard / vKey / model routing
- **v4.12.0** — ByteDance UI-TARS desktop control MCP integration (TSG finale)
- Long-term — Multi-agent collaboration / device mesh / adaptive professions

---

## 🤝 Contributing

Welcome PR / Issue / Discussion. Development flow see [CHANGES.md](https://github.com/HP-jh/TarsSecureGuard/blob/main/CHANGES.md).

---

## 📜 License

MIT — see [LICENSE](https://github.com/HP-jh/TarsSecureGuard/blob/main/LICENSE).

---

<div align="center">

© 2026 TarsSecureGuard · The Router of the AI Era · MIT

</div>
