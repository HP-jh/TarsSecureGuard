🌐 **Languages**: [🇨🇳 简体中文](README.md) · [🇺🇸 English](README.en.md) · [🇷🇺 Русский](README.ru.md) · [🇸🇦 العربية](README.ar.md) · [🇫🇷 Français](README.fr.md) · [🇯🇵 日本語](README.ja.md) · [🇰🇷 한국어](README.ko.md)

---

<div align="center">

# 🛡️ TarsSecureGuard

### The Router & Configurator of the AI Era — Router and configurator for the AI age, with built-in safety belt

<p>
<b>Unzip and use</b> · <b>High security</b> · <b>No configuration required</b> · <b>Cross-platform compatible</b> · <b>Connect everything</b> · <b>Configure other AI tools for you</b>
</p>

<p>
A zero-dependency, single-file, purely static <b>local AI gateway</b>: On the left side, it connects 13 types of AI software clients (Claude Desktop / Cursor / Cline / Continue / Windsurf / Codex CLI / Warp / Cody / JetBrains / Tabnine / Zed / Roo Code / VS Code Copilot),<br/>
On the right side, it connects to <b>24 cloud model providers + 8 local inference runtimes</b> (OpenAI / Anthropic / Gemini / DeepSeek / Tongyi / Wenxin / GLM / Doubao / Kimi / MiniMax / Hunyuan / Xinghuo / Groq / Ollama / LM Studio / vLLM …),<br/>
In the middle, WAF, semantic protection, hierarchical rate limiting, IP reputation, RBAC, auditing, and PII desensitization are forcibly enabled — <b>Connect more, but defend better</b>.
</p>

<p>
<b>Not just a gateway, but also a configurator (v3.7.0 Extender)</b>: Tired of tedious environment configuration for other AI tools? TSG configures them for you — Built-in detector scans for locally installed <b>OpenClaw / Continue / Aider / Cline / ZooCode / Codex CLI</b>,
Generates access configuration snippets with one click that point the tool to the TSG endpoint (keys can be embedded and fully audited), just copy and paste to complete setup. All targets are MIT / Apache ecosystem, <b>zero GPL contamination, zero external dependencies</b>.
</p>

<p>
<img alt="Version" src="https://img.shields.io/badge/version-3.7.0-success">
<img alt="Go" src="https://img.shields.io/badge/Go-1.22.8-00ADD8?logo=go&logoColor=white">
<img alt="Deps" src="https://img.shields.io/badge/dependencies-0-brightgreen">
<img alt="Providers" src="https://img.shields.io/badge/providers-24%20cloud%20%2B%208%20local-blue">
<img alt="Platforms" src="https://img.shields.io/badge/platform-6%20targets-blueviolet">
<img alt="Tests" src="https://img.shields.io/badge/tests-race%20green">
<img alt="License" src="https://img.shields.io/badge/license-MIT-orange">
</p>

</div>

---

## 📣 Recommendation

> **When every AI client comes with its own private model ecosystem, TarsSecureGuard lets you connect all models, all tools, and all protocols with just one OpenAI-compatible key — and forces you to buckle up the safety belt.**
>
> Download a zip package, unzip it, double-click it — it starts on local port `18889`, and the Chinese admin panel automatically opens in your browser. It is not another "heavy gateway" that requires you to pull a 1GB image or install MySQL, but a **zero-dependency, purely static secure gateway that can even run off a USB drive**.
>
> v3.2.0 takes "connectivity" to the extreme — **One Coding Plan key unlocks all models**; the 50-integration roadmap is already drafted; three integration modes for open source / closed source / CLI tools (**embed / federate / wrap-cli-as-mcp**); for tools that are temporarily unconnectable, you get an actionable integration checklist.
>
> While other gateways still make you configure YAML and debug routing rules, TarsSecureGuard has already buckled your safety belt, connected your clients, and handed you the key.

---

## 🌟 Introduction

TarsSecureGuard is a **local-first AI gateway — the router of the AI era**. It sits between you and all AI capabilities: on the left are your AI software (Claude Desktop, Cursor, Cline, Windsurf, Codex CLI… choose any), on the right are 24 cloud model providers + 8 local inference runtimes (connect any); it exposes an OpenAI-compatible endpoint (HTTP or **stdio**) + MCP externally, and unifies scheduling, governance, and auditing internally.

> A home router doesn't make Ethernet cables or create websites — it lets every device access the internet safely. TarsSecureGuard doesn't produce models or force you to use a specific client — **It lets every AI client safely use every model**. We are committed to doing this perfectly: connect what can be connected, and provide an actionable integration checklist for what can't be connected temporarily (see `docs/v3.2.0-unconnectable.md`).

### v3.2.0 New Feature · Universal Connector Roadmap

> **One Coding Plan subscription key = the key to all models**. TSG hides the differences between any providers behind the OpenAI compatibility layer, no need to rewrite AI clients, no need for users to switch tools.

To integrate all AI software in the world (including open source / closed source / CLI tools that cannot be connected directly) into TSG, there are three **integration modes**:

| Mode | Applicable to | Implementation |
|---|---|---|
| **embed** | Open source libraries (C/C++/Go/Rust/Python)| Compile the code into the TSG process and call directly (e.g. ggml / whisper.cpp / sqlite-vec) |
| **federate** | Remote services / API gateways | Unified scheduling via TSG reverse proxy + protocol adaptation (various MCP Hubs, third-party API platforms) |
| **wrap-cli-as-mcp** | Any command line tool | Zero-code wrapping as an MCP server, AI calls indirectly via TSG (e.g. ripgrep / fd / magika / jq) |

**Current progress**: 24 cloud providers + 8 local runtimes (built-in registration, each with a machine-readable profile), 13 client access guides, 17 temporarily unconnectable items (v3.3.0 target 50 integrations). **Adding a new provider only requires writing configuration, no code changes** — this is why v3.2.0 can take on the role of a "router".

### Five Core Features

| Feature | Description |
|------|------|
| 🔌 **Connect Everything** | v3.2.0 provider-registry: 24 cloud + 8 local runtimes built-in registration (each with a machine-readable profile), 13 types of AI client access guides; adding a new provider **only requires writing configuration, no code changes**. |
| 📦 **Unzip and Use** | No installation required, no containers, no database. Unzip the package, double-click `start.bat` / `start.sh`, the service starts immediately, and the Chinese panel automatically opens in the browser. |
| 🔒 **High Security** | Security Core is forcibly loaded and **cannot be turned off**: WAF (path traversal / command injection / SQLi / XSS / **Prompt injection** / **PII detection**), **semantic detection hierarchical diversion (fail-close)**, **three-dimensional token bucket rate limiting**, **local IP reputation scoring**, three RBAC roles, structured auditing, PII desensitization, five SSRF red lines, three-level firewall linkage. No matter how wide the connection is, the security chain is never weakened. |
| 🚀 **Solid Performance** | Shared connection pool (measured reuse rate 98.5%), provider circuit breaking and degradation, two-level cache (protocol adaptation + tenant-isolated response cache); outbound P99 is **27% ~ 40% lower** than the v3.0.x baseline (reproducible benchmarks are delivered with the source code, see `docs/v3.2.0-performance.md` for details). |
| 💻 **Excellent Environmental Compatibility** | One codebase, builds for six platforms (macOS Intel/Apple Silicon, Linux x86_64/ARM64, Windows x64/ARM64); `CGO_ENABLED=0` purely static, runs immediately after copying on old kernels, old distributions, and isolated intranets. |

### 💎 Subscription Edition

> **The Community Edition is completely free and open source (MIT); the Subscription Edition is for users who want "hassle-free use + compliance + continuous updates".**

| Capability | Community Edition (Free) | **Subscription Edition (Recommended)** |
|------|:---:|:---:|
| Gateway / local and cloud models / WAF / semantic protection / rate limiting / IP reputation / RBAC / auditing | ✅ | ✅ |
| Resource guardian / intelligent routing / model scoring / MCP stdio | ✅ | ✅ |
| Builds for all six platform architectures | ✅ | ✅ |
| **One-click update package** (automatically built latest version on cloud disk, no manual operation required) | — | ✅ |
| **Continuous security rule library updates** (latest prompt injection / jailbreak signatures, IP reputation policies) | Community pace | **Priority updates** |
| **lm-eval offline evaluation data import and optimization suggestions** | Manual | ✅ Expert optimization |
| Private deployment / intranet compliance deployment support | — | ✅ |
| Official technical support and SLA | — | ✅ |

Subscribers get **continuous security protection updates and hassle-free delivery**: you just unzip and use, the subscription continuously covers protection, stability, and compatibility.

---

## 🧩 v3.0.0 Capability Overview ("Your AI's Safety Belt")

### Line A · Resource Guardian (resourceGuardian)
- `GOMEMLIMIT` soft memory limit (min(10% of physical memory, 384MB), 128MB in eco mode, configurable override).
- **L0–L3 hierarchical response**: L1 degrades non-core functions → L2 cuts off high-consumption functions → L3 graceful shutdown (30s drain + audit flush to disk + state save + exit code 42 + cooldown to prevent storms).
- L2/L3 are determined by **RSS metrics**, capturing CGO / external memory leaks; eco resource-saving mode is automatically applied to low-end hardware.

### Line B · Protection Upgrade
- **Semantic detection hierarchical diversion (semanticGuard)**: Static rules run first, gray areas are sent to local 0.5B–1.5B small models for judgment; **fail-close iron rule** — if the engine is unavailable, directly return 503, never let traffic pass; fingerprint cache + gray area rate limit.
- **Three-dimensional token bucket rate limiting (rateLimiter)**: IP × endpoint type / Key × endpoint type / total IP traffic, overlimit returns 429 and deducts reputation points.
- **Local IP reputation (ipReputation)**: Starting score 100, points deducted for WAF violations / scanning / rate limiting, low scores are automatically banned, whitelist supported, 24h automatic recovery, NAT anomaly alert, admin unban.
- "**AI can only tighten rules**" one-way merge iron rule: Security policies can only be made stricter, 100% unit tested + runtime auditing.

### Line C · Two-stage Intelligent Routing
- **smartRouter**: Static rules take priority for fallback + **ε-greedy bandit** (ε decays from 0.1 to 0.02), automatically selects the optimal backend based on success rate / latency history; non-admin feedback is downweighted to prevent forgery.
- **scoreBoard**: Runtime score (success rate × latency) fused with **lm-eval-harness** offline evaluation (relative reference, honest annotation; Python sidecar is optional, not bundled).

### Line D · Ecosystem Niche Upgrade
- **`--mcp-stdio`: JSON-RPC 2.0 over stdio**, any local agent gets full protection after access — core differentiation of this version.
- Tools: `tars_guarded_chat` / `tars_guard_status` / `tars_route_preview` / `tars_model_score` / `tars_module_schema` / `tars_ip_reputation_unban`; management operations require `TSG_ADMIN_KEY`, fully audited.

### Line E · Stability Engineering
- Full panic recovery coverage; Go fuzzing (WAF / configuration parsing / semantic normalization); **8-hour soak test script** (`soak.sh` / `soak.ps1`); unit + httptest integration tests `-race` all pass.

### Platform and Delivery
- Full UI localization in Chinese; **Complete deployment artifacts**: systemd unit, Dockerfile, docker-compose (rootless), K8s sidecar example, macOS LaunchDaemon (see [`deploy/`](./deploy)).
- `go.mod` has zero third-party dependencies, all standard libraries — **zero supply chain attack surface**.

---

## 🏗️ Architecture

```
                 ┌──────────────────────────────────────────────────┐
 OpenAI SDK /    │            Security Core (Mandatory · Cannot be turned off)           │
 Local Agent ───▶ │ WAF → Semantic Diversion → Rate Limiting → IP Reputation → RBAC → Audit → PII │
 (HTTP / stdio)  └─────────────────────────┬────────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    │   Two-stage Intelligent Routing (Static Rules + ε-greedy bandit)  │
                    └──────────────────────┬───────────────────────┘
        ┌────────────┬────────────┬─────────┴────────┬────────────┬────────────┐
        ▼            ▼            ▼                  ▼            ▼            ▼
   Local GGUF      LM Studio    Ollama            Cloud Models      Tools/MCP     Resource Guardian
  (llama.cpp)     :1234        :11434         OpenAI/DeepSeek  Search/Crawl    L0-L3/Scoring
```

---

## 🚀 Quick Start

### One-click Installation (Recommended, automatically identifies system and architecture)
```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
```
```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.ps1 | iex
```
After installation, run `tsg` to start the gateway, the panel automatically opens at `http://127.0.0.1:18889`; run `tsg doctor` for environment self-check. You can also download the unified installation package `tsg-setup.zip` (includes cross-platform installer, automatically adapts after running).

### Run from Source
```sh
git clone https://github.com/HP-jh/TarsSecureGuard && cd TarsSecureGuard
go run .          # or ./start.sh (double-click start.bat on Windows)
```

### Official Demo Site
Lightweight official website (feature overview / one-click installation / version milestones / FAQ): `site/index.html`, enable GitHub Pages to use immediately (Settings → Pages → main / `site` directory).

### UI Upgrade (v3.2.4)
**Governance layer frontend visualization**: Added "Governance" navigation group in the sidebar, four pages: Governance Overview (aggregated governance + OAuth status) / Shared Memory / Shared Information / Audit Chain v2, all connected to real APIs — previously, 8 governance REST endpoints had no frontend coverage and could only be accessed via curl. Audit exports use authenticated blob download (keys are not exposed in URLs); also fixed the sidebar version badge drift that existed since v3.2.2. Playwright + Chromium headless end-to-end tests all pass, frontend has zero privileges, audit visibility is not relaxed. See [docs/v3.2.4-ui.md](./docs/v3.2.4-ui.md) for details.

### Performance Upgrade v2 (v3.2.3)
**WAF single-pass merged regex + ASCII trigger byte pre-screening** (normal/strict each have one merged regex for single-pass fast screening, after matching, back-check to get the rule name, zero semantic change; pure Chinese text skips regex entirely, strict scan speed improved by 99.8%), **PII desensitization single-pass optimization** (four modes merged into one replacement, 15% faster), **response cache 16 shard locks** (FNV-1a fixed sharding, independent mutex+LRU, concurrent get/put 10% faster @ 2 cores) — candidates were evaluated one by one: excluded JSON sync.Pool and audit batch commit (write order is hash chain order, asynchronous modification has chain break risk), disproved SSE path (does not exist in code). See [docs/v3.2.3-performance.md](./docs/v3.2.3-performance.md) for details.

### Governance Layer + Performance Upgrade v1 (v3.2.2)
**Shared Memory** (user → tenant → global three-layer namespace, nearest coverage resolution chain, tenant isolation guaranteed by namespace standardization), **Shared Information** (fact/preference/note/link structured knowledge entries + weighted retrieval), **Context Expansion MCP** (assembles identity and policies + shared information + shared memory into a deterministic context package, injected content and user input go through the same security chain), **OAuth/OIDC Enterprise IdP Access** (Authorization Code + PKCE, handwritten standard library RS256/ES256 signature verification, fail-close, sessions use exactly the same RBAC matrix as local users), **Gatekeeper** (action-level defense before tool execution: security configuration modification prohibited, sensitive path access prohibited, high-risk operations require two-stage confirmation, identity injection forgery prevention, tighten-only configuration), **hash-chain audit v2** (front and back chain SHA256, daily file rotation, chain continuation after restart, full chain recalculation to prevent tampering) — see [docs/v3.2.2-governance.md](./docs/v3.2.2-governance.md) for details. Also includes **Performance Upgrade v1**: log persistent handle pipeline (single line write speed 79% faster), connection pool coverage completion (doctor detection pooling / customToolClient parameter alignment while retaining SSRF isolation), tier1 regex package-level precompilation — see [docs/v3.2.2-performance.md](./docs/v3.2.2-performance.md) for details.

### Desktop Client (Added in v3.2.1, no browser required)
Download the installation package from [Release](../../releases) (Windows `.exe` / macOS `.dmg` / Linux `.deb`·`.AppImage`) → Double-click to install → **Native window** directly opens the Chinese admin console, no browser is opened during the whole process. The shell automatically starts the gateway sidecar, closing the window stops the service with no residual processes; data is stored in the system user data directory. See [docs/v3.2.1-desktop-client.md](./docs/v3.2.1-desktop-client.md) for details.

### MCP stdio Access (Core Differentiation)
```sh
./tarssecureguard --mcp-stdio
# Register this command as an MCP server in a local agent that supports MCP stdio,
# and you will automatically get the full set of protected tools such as tars_guarded_chat.
```

### Build from Source (Six Platforms)
```sh
GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=3.0.0" -o tarssecureguard .
go test -race ./...      # Unit + integration tests
./soak.sh                # 8-hour stability stress test (optional)
```
Complete six-platform build commands and minimum system matrix can be found in [COMPATIBILITY.md](./COMPATIBILITY.md).

> Default management port `18889`, local model port `18890`; default API Key `tars-gateway-key`, please modify it in `config.json` or inject it via environment variable `TARS_API_KEY`; management operations can use `TSG_ADMIN_KEY`.

---

## 🖥️ Cross-platform Compatibility Matrix

| Platform | Minimum System | Status |
|------|----------|:---:|
| macOS Intel (amd64) | macOS 10.15 Catalina | ✅ |
| macOS Apple Silicon (arm64) | macOS 11 Big Sur | ✅ |
| Linux x86_64 | Kernel 2.6.32+ (purely static) | ✅ |
| Linux ARM64 | Kernel 2.632+ (pure static) | ✅ |
| Windows x64 | Windows 10 / 11 | ✅ |
| Windows ARM64 | Windows 10/11 on ARM | ⚠️ Experimental |

See [COMPATIBILITY.md](./COMPATIBILITY.md) for details.

---

## 🥊 Top Competitor Analysis

**Conclusion: The largest competitor that requires the most direct response is LiteLLM** (the de facto standard for open-source AI gateways, with ~60k Stars, strongest ecosystem and mindshare); in the domestic market, **New API / One API** is the mindshare leader for the Go technology stack; **OmniRoute** is the closest in terms of "local-first" positioning.

| Competitor | Strengths | Shortcomings compared to TarsSecureGuard |
|------|------|----------------------------|
| **LiteLLM** (top competitor) | Widest provider coverage, mature ecosystem, complete virtual key/budget/retry mechanisms, leading mindshare overseas | Python tech stack, heavy deployment (requires Postgres + Redis, image size over 500MB, nearly 1GB for the full stack); cloud model-centric; security is not a default selling point; no single-file out-of-the-box support; no semantic fail-close / resource guard |
| **New API / One API** (domestic mindshare leader) | Written in Go, full support for domestic models, complete channel/token/billing/recharge operation workflow | Positioned for "API resale/operation billing", requires MySQL + Redis; overcomplicated parameters; not designed for local model / standalone security scenarios |
| **OmniRoute** (local-first) | Clear local-first positioning, fast Star growth, automatic downgrade and multi-routing policies | Focuses on "multi-vendor aggregated routing", security governance (WAF/semantics/RBAC/rate limiting/IP reputation/audit/PII) is not its core priority; single-file zero-dependency intranet compliance is not its proposition |
| **LM Studio / Ollama + OpenWebUI** ("good enough" alternatives) | Widely installed by users, user-friendly GUI, convenient model discovery | They are **runtimes** rather than governance gateways: they do not provide WAF, semantic protection, rate limiting, IP reputation, RBAC, audit, or resource guard —— TarsSecureGuard exactly manages and complements this layer |

**Differentiation Strategy**: Instead of competing on "number of supported providers", we occupy the overlooked niche that is extremely painful for individual users and intranet scenarios —— **「Zero configuration + single file + security enabled by default + local-first + stdio plug-and-protect」**. Heavy gateways serve large enterprises with dedicated platform teams; TarsSecureGuard serves individuals, tech enthusiasts, and air-gapped intranets who "want to use local AI safely and stably today".

---

## 🏰 Deepest Moat Analysis

**Conclusion: The deepest moat is the trust assets and LLM security defense knowledge base accumulated by the 「Security Core」, continuously reinforced by the zero-attack-surface engineering of the 「zero-dependency single file」; the MCP stdio in v3.0 enables this protection to be automatically distributed with access, further expanding the moat.**

The moat is divided into three layers from shallow to deep:

1. **Engineering Simplicity Layer (easy to replicate, short-term advantage)**: Zero third-party dependencies, pure static single file, support for six platforms, resource guard and intelligent routing. Competitors can imitate it, but it requires long-term restraint and giving up excessive ecosystem expansion —— something most teams cannot do.

2. **Security Knowledge Layer (core barrier, compounding over time)**: The Security Core is a complete set of **LLM-specific defense assets** —— WAF and prompt injection/jailbreak signatures, semantic gray area determination (fail-close), IP reputation behavior fingerprints, three-dimensional rate limiting, PII patterns and desensitization, five SSRF red lines, firewall linkage, audit system, and continuous optimization of the "detection rate vs false positive rate" balance. **More real samples → more accurate rules → lower false positives → more users → more samples**, forming a self-reinforcing flywheel that latecomers cannot catch up with by just copying code once.

3. **Trust and Distribution Layer (deepest, hardest to replicate)**: The ultimate barrier for security products is **the track record of "never having a security incident"** and compliance mindshare; the design commitment that "security can never be turned off / AI policies can only be tightened" precipitates into the default choice for users. The **stdio plug-and-protect** feature in v3.0 means that any local agent inherits the full set of protection once connected —— protection capabilities automatically spread with adoption, forming a **distribution flywheel**. The subscription version monetizes this trust through continuous security updates and SLAs. Trust cannot be built in a single quarter, nor can it be destroyed by price wars.

> **Honest Assessment**: The project is in the growth stage, and the moat is still "widening" —— the functional layer can be replicated. Its actual width is determined by **defense data brought by adoption volume + stdio distribution flywheel + long-term incident-free trust record**. The strategic value of the subscription version is exactly to turn "continuous security updates" into a compoundable, chargeable asset that accumulates trust over time.

---

## 📚 Documentation

- [CHANGES.md](./CHANGES.md) —— Complete changelog for all versions (including v3.2.4 UI upgrade, v3.2.3 Performance Upgrade v2, v3.2.2 Governance Layer + Performance Upgrade v1, v3.2.1 Desktop Client, v3.2.0 Connectivity Major Release)
- [docs/v3.2.4-ui.md](./docs/v3.2.4-ui.md) —— **UI Upgrade**: Four governance layer visualization pages / interaction fixes / Playwright end-to-end validation
- [docs/v3.2.3-performance.md](./docs/v3.2.3-performance.md) —— **Performance Upgrade v2**: WAF single-pass merging + pre-filtering / PII single-pass processing / response cache shard lock / A-B benchmark
- [docs/v3.2.2-governance.md](./docs/v3.2.2-governance.md) —— **Governance Layer**: Shared memory / shared information / context expansion MCP / OAuth/IdP / gatekeeper / audit upgrade
- [docs/v3.2.2-performance.md](./docs/v3.2.2-performance.md) —— **Performance Upgrade v1**: Always-on log handle pipeline / full connection pool coverage / A-B benchmark
- [docs/v3.2.1-desktop-client.md](./docs/v3.2.1-desktop-client.md) —— **Desktop Client**: Tauri shell design decisions, build and acceptance criteria
- [docs/v3.2.0-connectivity.md](./docs/v3.2.0-connectivity.md) —— **Connection Guide**: 13 AI client integrations + 24 cloud providers + 8 local runtimes
- [docs/v3.2.0-performance.md](./docs/v3.2.0-performance.md) —— **Performance Benchmark**: P99 / connection reuse rate / cache hit rate (reproducible)
- [docs/v3.2.0-unconnectable.md](./docs/v3.2.0-unconnectable.md) —— **Temporarily Unsupported List**: 16 entries + draft integration plans for each
- [COMPATIBILITY.md](./COMPATIBILITY.md) —— Cross-platform compatibility matrix and build guide
- [OPTIMIZATION_REPORT.md](./OPTIMIZATION_REPORT.md) —— Optimization report and technology roadmap
- [deploy/](./deploy) —— systemd / Docker / docker-compose / K8s / LaunchDaemon deployment files

## 📄 License

[MIT License](./LICENSE) —— Free to use, modify and share.

<div align="center">

🛡️ **TarsSecureGuard —— Your AI's Safety Belt. Unzip and use, security always on.**

</div>