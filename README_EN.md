# TarsSecureGuard

**Local AI Gateway · Double-click to run · Open Source (MIT) · v1.0.0**

TarsSecureGuard is a local AI gateway that runs on your own computer. It gives you a
graphical, beginner-friendly control panel for:

- Managing **local GGUF models** powered by [llama.cpp](https://github.com/ggerganov/llama.cpp)
- Routing requests to **cloud LLM APIs** (OpenAI-compatible, DeepSeek, etc.)
- Calling **MCP servers** (filesystem, fetch, and your own)
- Searching the web with a built-in engine or Serper
- A **WAF-style security layer** (request scanning, path allow-list, rate limiting, threat intel blocks)

Everything stays on `127.0.0.1:18889` by default. No accounts, no cloud dependency — your
models and your data stay on your machine.

---

## Features

| Area | What you get |
|---|---|
| 🖥️ **Graphical UI** | Embedded web dashboard (dark theme): Dashboard, AI Chat, Models, Agents, MCP Tools, Discovery, Security, WAF Logs, Device, Logs, Settings |
| 🤖 **Local models** | Auto-scan your hardware, get recommended GGUF models, one-click download with progress bar, run via bundled llama.cpp |
| ☁️ **Cloud backends** | OpenAI-compatible endpoints (`cloud.openai`, `cloud.deepseek`, ...) with API keys stored in config |
| 🔌 **MCP support** | Built-in `filesystem` + `fetch` MCP servers, plus a relay to call any registered tool |
| 🔍 **Web search** | Built-in Bing RSS engine (no key) or Serper (with key), usable from chat |
| 🛡️ **Security** | API key auth (X-API-Key / Bearer), WAF request scanning, path allow-list with boundary checks, CORS origin allow-list, security headers, auto fallback between backends |
| 🧠 **Agents** | Built-in agent personas (code assistant, writing, security analyst, translator, ...) |
| 📦 **Portable** | Single `TarsSecureGuard-v1.0.0.exe` — no runtime install needed on Windows |

---

## Quick Start (Windows)

1. Download `TarsSecureGuard-v1.0.0.exe` from the latest release.
2. Double-click it. The gateway starts and opens your browser at `http://127.0.0.1:18889`.
3. First-run wizard helps you scan hardware and download a recommended local model.
4. Put extra GGUF files into the `Models` folder next to the exe, then click **Rescan**.

Default API key: `tars-gateway-key` (change it in **Settings** → API Key).

---

## Build from Source

Requirements: [Go](https://go.dev/) 1.21+ (tested with 1.22+).

```bash
cd go-app
go build -o TarsSecureGuard-v1.0.0.exe .
```

Or just run `build.bat` at the repository root — it also generates a config template.

The frontend (`frontend/index.html`) is embedded into the binary at build time, so the exe
is fully self-contained.

---

## Configuration

`config.json` sits next to the exe. Key sections:

```jsonc
{
  "security": { "apiKey": "tars-gateway-key", "mode": "normal", "wafEnabled": true },
  "search":   { "engine": "builtin", "apiKey": "" },
  "cloud": {
    "openai":   { "apiKey": "", "baseUrl": "", "name": "" },
    "deepseek": { "apiKey": "", "baseUrl": "", "name": "" }
  }
}
```

Most settings are editable from the web UI (**Settings** page). Secrets are masked when
read back over the API.

---

## API Overview

All routes live under `/api` and require the API key:

| Endpoint | Purpose |
|---|---|
| `POST /api/chat/completions` | Chat (OpenAI-compatible request body) |
| `GET  /api/admin/models` | List models |
| `POST /api/admin/model/download` | Download a GGUF by URL (progress at `/api/admin/model/download/status`) |
| `GET  /api/admin/security/status` | Security stats |
| `GET  /api/admin/security/waf-logs` | WAF block log |
| `POST /api/admin/config` | Save config by whitelisted dotted paths (e.g. `security.mode`) |
| `POST /mcp` | Call an MCP tool (`{tool, args}`) |

---

## Security Notes

- All `/api` routes require `X-API-Key` or `Authorization: Bearer <key>`.
- WAF scans requests (path traversal, SQLi patterns, oversized bodies, rate limiting).
- CORS echoes back only trusted origins (never `*`).
- Model download URLs are allow-listed to `huggingface.co` / `hf-mirror.com` / `modelscope.cn`.
- Bind address and port are configurable; default is loopback-only.

---

## License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

---

## Project Status

Built and maintained by a young developer learning Go, with a focus on making local LLMs
accessible to everyone. Feedback, issues and pull requests are welcome.
