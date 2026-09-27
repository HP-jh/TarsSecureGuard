<div align="center">

# 🛡️ TarsSecureGuard

**Local AI Security Gateway · Single Binary · Open Source (MIT) · v1.0.3**

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D6)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[中文](README.md) · [Quick Start](#quick-start) · [Build](#build) · [Features](#features)

</div>

TarsSecureGuard is a **local AI security gateway** that sits between your AI clients and backend models — one entry, one auth layer, one WAF, one audit log. Point any OpenAI-compatible client (ChatBox / NextChat / Cursor / etc.) at `http://127.0.0.1:18889/v1` and every request goes through the gateway first.

Everything stays on `127.0.0.1:18889` by default. No accounts, no cloud dependency — your models and your data stay on your machine.

> Built by a young developer learning Go, with AI assistance. Since v1.0.3 it builds on **Windows / Linux / macOS**.

## What's New in v1.0.3

- 🌍 **Cross-platform builds** — Windows / Linux / macOS from the same source (build tags for disk stats & subprocess handling)
- 👥 **Multi-user RBAC** — `admin / user / readonly` roles with per-user API keys; empty `users` falls back to single-admin (100% backward compatible)
- 📜 **Structured audit logs** — config changes, model start/stop, access denials all logged to `logs/audit-*.log`; query via `GET /api/admin/audit-logs`
- 🧠 **Prompt Injection defense** — strict mode blocks jailbreak / ignore-previous-instructions patterns with 403
- 🔏 **PII detection & masking** — phone numbers, emails, credit cards, SSNs are masked to `****` before reaching backends
- 🔑 **Keys via environment** — `TARS_API_KEY` / `TARS_OPENAI_KEY` / `TARS_DEEPSEEK_KEY` / `TARS_SEARCH_KEY` override config; all key fields are masked in API responses

## Features

| Area | What you get |
|---|---|
| 🖥️ **Graphical UI** | Embedded web dashboard: Dashboard, AI Chat, Models, Agents, MCP Tools, Discovery, Security, WAF Logs, Audit Logs, Device, Settings |
| 🤖 **Local models** | Auto-scan hardware, recommended GGUF downloads with progress, bundled llama.cpp |
| ☁️ **Cloud backends** | OpenAI-compatible endpoints with per-service API keys |
| 🔌 **MCP support** | Built-in filesystem + fetch MCP servers, plus a stdio JSON-RPC relay |
| 🔍 **Web search** | Built-in Bing RSS (no key) or Serper |
| 🛡️ **Security** | API key auth (X-API-Key / Bearer), WAF (traversal/SQLi/XSS/PromptInjection/PII), scanner UA blacklist, sensitive-path blocking, rate limiting, path allow-list, CORS allow-list, security headers |
| 👥 **RBAC** | admin / user / readonly roles with per-user keys and audit logging |
| 📦 **Portable** | Single binary with embedded frontend — no runtime install |

## Quick Start

1. Download or build the binary (see below).
2. Run it — the gateway starts and opens the browser at `http://127.0.0.1:18889`.
3. First-run wizard scans hardware and offers a recommended local model.
4. Point your OpenAI-compatible client at `http://127.0.0.1:18889/v1`, API key = `security.apiKey` from `config.json` (default `tars-gateway-key` — **change it**).

Linux / macOS: just `go build` and run — same layout.

## Build

Requirements: [Go](https://go.dev/dl/) 1.22+.

```bash
cd go-app
go build -o tars .                                   # current platform
GOOS=windows GOARCH=amd64 go build -o TarsSecureGuard.exe .
GOOS=linux   GOARCH=amd64 go build -o tars-linux .
GOOS=darwin  GOARCH=amd64 go build -o tars-macos .
```

Or run `build.bat` (Windows). The frontend is embedded via `go:embed`.

## Configuration

`config.json` sits next to the binary (auto-generated on first run). Key sections:

```jsonc
{
  "security": { "apiKey": "tars-gateway-key", "mode": "normal", "wafEnabled": true, "auditLogEnabled": true },
  "users": [
    { "name": "admin1", "apiKey": "...", "role": "admin", "enabled": true },
    { "name": "user1",  "apiKey": "...", "role": "user",   "enabled": true },
    { "name": "guest",  "apiKey": "...", "role": "readonly", "enabled": true }
  ],
  "search": { "engine": "builtin", "apiKey": "" },
  "cloud": { "openai": { "apiKey": "", "baseUrl": "", "name": "" } }
}
```

Env vars override config: `TARS_API_KEY`, `TARS_OPENAI_KEY`, `TARS_DEEPSEEK_KEY`, `TARS_SEARCH_KEY`.

## Security Notes

- All `/api` routes require `X-API-Key` or `Authorization: Bearer <key>`; comparisons are constant-time.
- WAF scans path traversal, SQLi, XSS, prompt injection (strict), oversized bodies, scanner UAs, sensitive paths, and abnormal HTTP methods.
- PII (phone / email / credit card / SSN) is masked in chat traffic before hitting backends.
- CORS echoes back only trusted loopback origins, never `*`.
- Listen address is loopback-only by default.

## License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

## Project Status

Built and maintained by a young developer learning Go, focused on making local LLMs accessible and safe. Feedback, issues and PRs are welcome.
