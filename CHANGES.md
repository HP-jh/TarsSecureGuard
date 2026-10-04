# TarsSecureGuard v3.2.1 · 桌面客户端 —— 本地 Tauri 客户端，不依赖浏览器

> 设计决策、模块拆分、构建与验收说明见 `docs/v3.2.1-desktop-client.md`。
> **CLI / systemd / Docker 部署零变化**：网关仍为单文件零依赖二进制，桌面客户端是叠加的第四种交付形态。

## 一、桌面客户端（Tauri 2 壳，`src-tauri/`）

- **原生窗口，零浏览器依赖**：Tauri 2.12（2.x 当前稳定线）用系统自带 WebView（Windows WebView2 / macOS WKWebView / Linux webkit2gtk）承载窗口，用户无需安装任何浏览器。
- **Sidecar 外嵌模式**：Go 网关按 target-triple 命名（`binaries/tsg-<triple>`）打进安装包，由 Rust 壳以 `--no-browser` 拉起；UI 与业务逻辑 100% 复用网关 embed 的管理台（1040 行单文件前端），壳仅约 250 行 Rust。
- **连接模式**：壳启动先探 `127.0.0.1:18889/health`，已有实例（CLI / systemd 起的）直接复用，不重复拉起、退出不杀外部实例。
- **数据目录**：桌面安装位置（Program Files、/usr/bin、AppImage 只读 squashfs）不可写，壳经环境变量 `TSG_APP_DIR` 把网关数据目录指到系统用户数据目录；不设置该变量时行为与历史版本一致。

## 二、网关最小适配（Go 侧，全部带单测）

- `--no-browser` 启动标记：sidecar 模式抑制"自动打开浏览器"（浏览器窗口由壳承载）。
- `isTrustedOrigin` 信任 Tauri 窗口 origin（`tauri://localhost` / `http(s)://tauri.localhost`）：仅窗口 origin 本身受信，API Key / RBAC / WAF / 审计链照常执行；网关仅监听 127.0.0.1，本机进程本可直连，不扩大远程攻击面。
- `TSG_APP_DIR` 环境变量单点覆盖 `appDir()`：config.json / logs / gateway-key.txt / whitelist-integrity / quota 数据全部跟随。
- 前端 `api()` 增加 API BASE（仅桌面模式指向 `http://127.0.0.1:18889`，浏览器模式为空串零影响）+ 桌面启动遮罩（后端未就绪时的过渡态）。

## 三、构建与分发

- 三平台安装包经 GitHub Actions matrix 出包（`.github/workflows/desktop-release.yml`）：Windows NSIS（currentUser 安装 + WebView2 引导）、macOS universal dmg（amd64+arm64 lipo）、Linux deb + AppImage；`workflow_dispatch` 出 artifacts，推 `v3.2.*` tag 自动挂 Release。
- 安装包体积预估 15～25MB（Go 网关约 10MB + 壳 + 前端 <1MB），Win/macOS 用户无需预装 WebView 运行时。

## 四、明确不在本版范围（留 v3.2.2+）

WebSocket 事件流（维持 3s/5s 轮询）、单实例锁、自动更新（updater）、系统托盘、keychain 存密钥、开机自启、Windows Job Object 兜底（正常关窗已确保无残留进程；壳被强杀时 sidecar 可能残留为已知限制）。

---

# TarsSecureGuard Go v3.2.0 · 连接做到极致 —— AI 软件生态全连接 · 变更说明

> 完整连接指南见 `docs/v3.2.0-connectivity.md`；性能基准见 `docs/v3.2.0-performance.md`；不可连接清单见 `docs/v3.2.0-unconnectable.md`。
> 定位升级：**AI 时代的路由器**——连接一切可连接的 AI 软件与服务，安全链一行不削。

## 一、provider-registry（核心新增，~1150 行）

- **24 云端 + 8 本地运行时**内置注册：每家一个 `providers/<id>.json`（go:embed 进二进制），
  覆盖 OpenAI / Anthropic / Gemini / DeepSeek / Mistral / xAI / 通义 / 文心 / GLM / 豆包 / Kimi / MiniMax /
  OpenRouter / 302.AI / SiliconFlow / Perplexity / HF / 混元 / 星火 / Groq / Together / Cohere / Fireworks / Cerebras
  + Ollama / LM Studio / llama.cpp / vLLM / TGI / LocalAI / Xinference / mlc-llm。
- 新增 provider **只写配置不改核心代码**：模型三级路由（`providerId/model` 前缀 → 裸模型名反查 → legacy 兜底）。
- 密钥参数化红线：只经 config.json `providers.<id>` 或环境变量注入；注册表文件静态扫描禁敏感字样（测试兜底）；
  管理端点只输出 keySet 布尔。

## 二、连接架构升级

- **共享连接池**（pool.go）：单 Transport + httptrace 实测复用计数，复用率 98.5%（800 并发出站）。
- **熔断器**（circuit.go）：closed/open/half-open 三态，连续 5 次失败熔断 30s，恢复探测，状态迁移全审计；
  后台健康 worker 仅探测已配密钥且非 closed 的云端 provider。
- **两级缓存**（adapters.go）：协议适配缓存（LRU 128）+ 租户隔离响应缓存（TTL 300s / LRU 1024，key 含租户）；
  热重载全量失效；缓存命中内容必已过安全链。
- **协议适配器**：openai-compat / anthropic（system 提升）/ gemini（role=model + systemInstruction）/ ollama 原生。

## 三、性能（对照 v3.0.5 基线，可复现基准随源码交付）

出站顺序 P99 中位数 **177µs→107µs（-40%）**，并发 16×50 P99 **2536µs→1855µs（-27%）**；
连接复用率 **98.5%**（目标 ≥60%）；模板型负载缓存命中率 **49%** / 双场景累计 **42.5%**（目标 ≥40%）。
**v3.0.2 从未公开基准数据，基线如实替换为 v3.0.5 同机对照，局限已在报告声明。**

## 四、提示词与文案

- 全部 agent system prompt 重写：补准确性约束（区分事实/推测、不编造引用）、安全一致性措辞
  （security-analyst 不输出攻击利用细节）、扁平结构预留 i18n 空间；安全护栏措辞未削弱。
- README / 介绍语 / tagline 重定位为「The Router of the AI Era」；13 客户端接入指南；不可连接清单 16 项。
- **2026-10-04 二次打磨**：推荐语聚焦"一把密钥连一切"叙事——路由器角色 + Universal Connector + Coding Plan + 50 集成路线 + 三种纳入模式（embed / federate / wrap-cli-as-mcp）写进第一屏；介绍语新增「Universal Connector 路线」章节、含三种纳入模式表；保留"安全带"已有认知资产，强化对比 LiteLLM / New API 的差异化卖点；端口 `18889` 显式化（v3.2.0 起统一）。

## 五、管理端点与配置

- 新增 `/api/admin/v32/providers`（GET）、`/api/admin/v32/providers/probe`（POST，admin.write）、
  `/api/admin/v32/pool`、`/api/admin/v32/cache`；`/api/admin/models` 并入注册表模型。
- config.json 新段：`providers`（apiKey/baseUrl/enabled/models 覆盖）、`circuit`、`responseCache`、`pool`，热重载生效。

## 六、质量门

`go vet` 干净；93 个测试（新增 10 项：注册表形状/无密钥扫描/前缀解析/熔断状态机/三种协议 body/
缓存租户隔离+TTL/httptest 集成/routeChat 端到端/连接池复用/密钥不泄漏）`-race` 全绿。
安全架构 Tier 0-3 零改动：WAF / 认证 / RBAC / 语义分级 / 脱敏 / 硬黑名单全部在缓存与熔断之前执行。

---

# TarsSecureGuard Go v3.0.5 可观测性 · 自诊断 · 变更说明

> 完整升级说明见 `docs/v3.0.5-observability.md`；Grafana 模板见 `grafana/tsg-observability-dashboard.json`。
> 对应任务：自主迭代六轮之第 2 轮。四项交付：Prometheus /metrics、分布式 trace_id 全链路、`tsg doctor`、Grafana dashboard 模板。
> 铁律遵守：**纯观测不改主流程**（观测中间件包裹在既有 gatewayMiddleware 之外，判定链零改动）；token / api key 全链路脱敏；trace_id 关联现有审计行但**不新增持久化存储**；交付云盘不推 GitHub。

## 一、可观测层（observability.go，新增 ~680 行）

- **/metrics**（Prometheus 文本格式 v0.0.4，手写渲染，仍零第三方依赖）：15 个指标族覆盖任务全部要求——QPS（tsg_http_requests_total）、延迟（histogram p50/p95/p99）、WAF hit（tsg_waf_hits_total{rule}）、模型路由分布（tsg_router_decisions_total{backend,result} + explore + 各后端耗时）、资源 tier（tsg_guard_tier L0-L3 + RSS）、模块状态（tsg_module_up / tsg_backend_up 15s 缓存探测）+ 配额/uptime/build_info/trace 计数。端点归 app 类全角色可读（Prometheus 只需一把低权限 readonly key），无 key 401。
- **脱敏双保险**：标签只用低基数枚举（class/method/code/rule/backend/module/tenant），绝无 user/token/key；span 详情经 obsRedact 二次兜底（bearer / sk- / key= / token= / secret= / password= 前缀与 ≥32 位十六进制串 → `***`）。

## 二、分布式 trace_id 全链路

- 最外层中间件生成 crypto/rand 16-hex trace_id → context 传播 + 响应头 `X-Trace-Id` 回显；网关各阶段 obsStage 记 span（request/waf/auth/rbac/quota/route）；出站后端请求（LLaMA/LM Studio/Ollama/云）统一携带 X-Trace-Id 转发（traceHeaderForward，httptest 桩验证有/无 trace 两分支）。
- **关联不重复存储**：trace 明细仅存内存环形缓冲（256 条，同既有 wafLogs 模式，重启即失）；持久关联走**现有**审计/WAF 日志行尾 ` TRACE=<id>` 字段，零新增存储文件。管理查询 `GET /api/admin/traces?limit=N`（admin.read 类）。

## 三、tsg doctor 自诊断 CLI（doctor.go，新增 ~570 行）

- `tsg doctor` / `--json` / `--config <path>`；退出码 0=全过（允许 WARN）/ 2=仅 WARN / 1=有 FAIL，可直接接巡检脚本。
- 7 大类 18 项检查（配置/权限/端口/网络/依赖/资源/运行态），每条非 PASS 项带「→ 下一步」具体建议；配置读取用独立 JSON 解析，doctor 零副作用；运行态探针 key 自动从 gateway-key.txt 或用户表取。
- 主程序新增 `tsg doctor` / `tsg version` 子命令入口（在 MCP stdio 判定之前，不影响既有 stdio 模式）。

## 四、Grafana 模板

- `grafana/tsg-observability-dashboard.json`：Grafana 10+、23 面板、四行布局（核心指标 / WAF 详情 / 模型路由分布 / 资源与模块），`${DS_TSG}` 数据源变量；prometheus.yml 抓取示例（含 X-API-Key 鉴权写法）见升级说明第四节。

## 五、主流程接线（全部为非侵入式）

- `server.Handler = obsMiddleware(gatewayMiddleware(mux))`——观测在最外层，判定链原样。
- chat/router 的路由与后端调用函数改为可变参数 `trace ...string` 透传，既有全部调用点零改动编译通过；WAF/审计在既有日志行追加 TRACE= 后缀，行格式其余不变。

## 六、测试与验收

- `go vet` 0 告警；触碰文件 gofmt 全过；`go test ./...` 全绿：新增 v305_test.go 10 用例 + 既有 v3.0.1~v3.0.4 全量回归。
- 沙箱真进程冒烟（linux-amd64, 18889）：/metrics 401/200 + 15 指标族 + 密钥泄露扫描零命中 ✓；traces 端点 admin 读 / readonly 403 ✓；WAF 拦截行 `TRACE=3422bf78809eaa6b` 与响应头一致 ✓；doctor 人读（11 pass/3 warn/4 info, exit 0）+ --json + 坏配置 exit 1 ✓；计数器分类实测正确（admin.read 200/403、tools 403、waf_hits{rule="路径穿越"}=1）✓。
- **8h 真实环境实测未在本环境执行**——实测清单（六项）见升级说明第五节；完成后本版收口，自动解锁 v3.0.6。

---

# TarsSecureGuard Go v3.0.4 零信任深化 · 多租户 RBAC · 变更说明

> 完整升级说明见 `docs/v3.0.4-zero-trust-multitenant.md`；team 场景示例见 `examples/team-config.example.{yaml,json}`。
> 依据锦衣卫裁定 TSG-ZT-MT-2026-0929 四节红线 + 五个剩余问题（备案方案见升级说明第六节）。
> 铁律遵守：security-core 未动、WAF 规则零改动、未引入新模块（新代码均在 package main：whitelist.go / tenant.go + 既有文件接线）。

## 一、零信任白名单基线（whitelist.go，新增 ~430 行）

审计发现的三类隐式放行全部封堵：默认密钥 "tars-gateway-key" 硬编码兜底（前端 localStorage 兜底一并移除，401 引导输入）、allowedRoots 自动填充（显式绝对路径落盘）、ipReputation.whitelist 无值域校验（禁 CIDR/通配）。

| 红线 | 实现位置 | 要点 |
|---|---|---|
| [ZT_DEFAULT_DENY] | `enforceDefaultKeyChannel`（whitelist.go L366） | 全新安装显式写 defaultKeyAllowed=true；存量默认密钥未显式 allow → 启动自动轮换（gateway-key.txt 0600，审计 WHITELIST_REMOVE + SECURITY_KEY_ROTATED） |
| [ZT_EXPLICIT] | `wlValidateIPList`/`wlValidateFileRoots` + `wlValidateOnLoad` | IP 白名单禁 CIDR/通配；文件根须绝对路径；MCP/sidecar 仅显式 enabled 计入放行集 |
| [ZT_CHANGE_AUDIT] | `wlReconcile` 热重载 diff | WHITELIST_ADD/REMOVE/MODIFY + 前后 SHA-256 |
| [ZT_INTEGRITY] | `whitelist-integrity.json` 基线（0600） | 失配回退基线条目（WHITELIST_INTEGRITY_FAIL/ROLLBACK），拒绝加载不降级 |
| 面板 | `GET /api/admin/whitelist/status` | 动态 4 kinds 完整性状态 + 静态 6 项清单 |

## 二、多租户 RBAC（tenant.go，新增 ~890 行）

- **user/group/role 三层**：users 表带 tenant + groups；tenants 顶层段（GlobalTokenCapPerDay + 租户/组定义）。
- **7 角色**：admin/user/readonly（既有按租户复用，裁定五-5）+ team_lead/auditor（新）+ global_admin/global_auditor（全局独立）。单管理员回退 = global_admin（备案）。
- **rbacMatrix 7×9 端点类逐格硬编码**（[RBAC_NO_INHERIT]），gatewayMiddleware 旧 isAdminRoute/readonly 两段式判定替换为 `rbacCheck`（含写方法二次判定：管理面 auditor/team_lead/readonly 铁拒；业务面 POST 为协议常规用法不误杀）。
- [RBAC_TEAM_LEAD] team_lead 零管理面写权限（防自授权）；[RBAC_AUDITOR_RO] auditor 一切写请求入口层硬拒；单测 100% 覆盖矩阵（7×9×GET/POST=126 格）。
- 端点分类 routeClass：/api/feishu 归 chat 类（原 app 类漏判）。

## 三、配额与策略（[MT_QUOTA]/[MT_ROUTER]/[MT_RATELIMIT]）

- 三层日配额（租户/用户/组）前置 quotaCheck（429 + QUOTA_EXCEEDED）+ 成功 quotaRecord（tokens≈字符/4），持久化 data/quota-usage.json（0600，隔日作废）。
- [MT_QUOTA_HARD] Σ租户配额 ≤ globalTokenCapPerDay；级联收紧 cascadeClampTenants（TEAM_CONFIG_CASCADE_CLAMP，剩余问题 3 备案）。
- 路由偏好：tenantPreferredBackends（组优先于租户，Rule A 无值取全集）接入 routeChatSmartT。
- 限流第 4 维：租户×端点类（tenantClassQuota，只许收紧，校验按全局生效值含默认 60/10/6）。
- [CFG_TEAM_SCHEMA]/[CFG_ATOMIC_SWAP]：租户段校验失败保持上一版本（TEAM_CONFIG_SCHEMA_FAIL）；用户表校验失败回退上一版本（RBAC_USERS_ROLLBACK + RBAC_TENANT_MISMATCH）。

## 四、审计与按组视图（[MT_AUDIT_ISOLATION]）

- auditLogT：审计行带 TENANT=/GROUP= 字段（旧行解析归 "system"）。
- handleAuditLogs 行级强制过滤：admin/auditor 本租户、team_lead 本组、global 全量；?tenant=x 跨租户查询记 AUDIT_CROSS_TENANT_ACCESS。
- 新端点：`GET /api/admin/tenants/status`（租户面板+配额用量）、`GET /api/admin/audit/group-summary`（按组聚合视图）。
- 越权封堵：POST /api/admin/config 白名单不含 tenants/users/security.apiKey/defaultKeyAllowed，试图修改记 CONFIG_REJECTED（不再静默跳过）。

## 五、测试与验收

- `go vet` 0 告警；`go test` 全绿：新增 v304_test.go（矩阵 126 格全测、租户校验 7 例、三层配额、审计过滤/越权 scope、白名单值域、gatewayMiddleware 端到端多租户链路）+ 既有全量回归（m1 集成测试改用显式测试密钥——默认密钥通道零信任后不再隐式鉴权，属预期行为变更）。
- 沙箱真进程冒烟（linux-amd64，18891）：全新安装显式化 ✓、存量升级自动轮换（旧 key 401/新 key 200）✓、角色矩阵 6 组实测 ✓、越权配置路径拒绝+审计 ✓、租户面板/组审计视图 ✓、白名单基线 4 kinds ✓。
- **8h 真实环境实测未在本环境执行**（沙箱无常驻能力）——实测清单：① 存量升级密钥轮换与前端引导；② team 配置热重载（TEAM_CONFIG_APPLY/SCHEMA_FAIL 两分支）；③ 三层配额耗尽 429 与隔日重置；④ 租户限流收紧生效；⑤ 跨租户查询审计；⑥ 六平台启动冒烟。

---

# TarsSecureGuard Go v3.0.1 Tier 1 实装 · sidecarHub 宿主 · 前端汉化收尾 · 变更说明

核心目标（对应任务三项范围）：① Tier 1 系统原生命令探测从规划落地为实装，严格遵循锦衣卫裁定 TSG-TIER1-2026-0929 七条红线；② sidecarHub 外置模块宿主按 v3.0.0 定稿架构（manifest + SHA-256 钉扎 + 低权限代理）实装；③ 前端深层英文提示串全量汉化。**Tier 0 形态不破坏**：Go 单 exe、零第三方依赖、六平台、OS 自带程序不算依赖——以上全部保持。

## 一、Tier 1 系统原生命令探测（实装）

新增 `tier1.go`（655 行）+ `tier1_hwprobe.ps1`（45 行，//go:embed 预置脚本）+ `tier1_unix.go` / `tier1_windows.go`（平台执行器）。`hardware.go` 的 `detectGPU` / `runCmdTimeout` 违规直调（wmic、`powershell -Command`、裸 lspci、nvidia-smi、system_profiler）全部删除，静态硬件属性统一经 `tier1HardwareSnapshot()` 唯一出口。

### 七条红线落实对照（锦衣卫裁定 TSG-TIER1-2026-0929）

| 红线 | 实现位置（tier1.go 为主） | 要点 |
|------|--------------------------|------|
| [TIER1_EXEC_MANDATORY] | `tier1Run`（L217）：exec.Command 数组式 argv，无任何 shell 中介；Windows 唯一形态 `powershell.exe -NoProfile -NonInteractive -OutputFormat XML -ExecutionPolicy RemoteSigned -File <预置脚本>`（L108-127 白名单精确匹配） | `-Command` / 管道 / 重定向一律拒绝 |
| [TIER1_AUDIT_MANDATORY] | `tier1Audit`（L81）+ `tier1Run`（L241-258）：每次调用写 TIER1_COMMAND_EXEC / _FAIL / _TIMEOUT，字段 ts/cmd/argv/caller/exit/dur | 冒烟实测审计样例见第四节 |
| [TIER1_CACHE_DEGRADE] | `tier1CacheTTL`（L62，60-3600 clamp 默认 300）/ `tier1CacheMAC`（L294，HMAC-SHA256 内存密钥）/ `tier1CacheLoad`（L317，篡改→AUDIT_TIER1_CACHE_TAMPER+删除+降级）/ `tier1CacheStore`（L345，0600+先删旧文件防权限继承）/ `tier1CacheInvalidate`（L363，热重载/安全级别变更/开关切换/POLICY_VIOLATION 四种失效） | 仅缓存静态属性（CPU/GPU/主板型号），动态指标每请求现取 |
| [TIER1_TOGGLE] | `tier1Enabled`（L50，nil=默认开启）+ `config.tier1.enabled` 进 `isConfigPathAllowed`（main.go L495）与 `validateConfigValue` 值域校验（handlers.go）；watchConfig 热重载即生效（config.go L417） | 冒烟实测：false→降级 Tier 0、true→立即恢复，无需重启 |
| [TIER1_ALLOWLIST] | `tier1AllowListed`（L108）：Linux `lspci -mm -v` / `dmidecode -t {0,1,2,3,4,17}` / `cat /proc/{cpuinfo,meminfo}`；Windows 仅预置脚本形态；macOS `system_profiler -xml {SPHardware,SPMemory,SPDisplays,SPNVMe}DataType`；禁 sudo/管道/重定向/提权；未命中→POLICY_VIOLATION 审计+拒绝+全量缓存失效（L140-142） | 预置脚本启动与每次执行前均校验 SHA-256（L439-443） |
| [TIER1_PROC_TIMEOUT] | `tier1Run`（L217）：3 秒上限；`tier1BreakerRecord`（L181）连续 3 次失败→熔断+降级审计，60 秒恢复探测（`tier1BreakerAllow` L166）；进程树清理：Unix Setpgid+kill -pgid（tier1_unix.go L16-33），Windows Job Object KILL_ON_JOB_CLOSE（tier1_windows.go，绑定失败降级单进程 Kill） | 熔断期间返回降级错误而非阻塞 |
| [TIER1_PRIVILEGE] | L251-252：权限不足（EPERM 等）按降级处理，绝不自动提权、绝不尝试 sudo | 降级审计带 degrade_reason + fallback_data_source（L206） |

### 附带修复（实施中发现）

- **saveConfig 丢 v3 顶层段**：v3.0.0 的 Config 主结构不承载 v3 段，`saveConfig`（解析成功即回写 + POST 保存）会把 tier1/resource/rateLimit 等段整段丢掉——用户关掉 tier1.enabled 后一次热重载即被静默重置，违反 [TIER1_TOGGLE]。修复：Config 匿名内嵌 V3Config（config.go）+ loadConfig 对 nil **bool 补 &true（防落盘 null 且与读取侧语义一致）。
- PS 5.1 ConvertTo-Json 单元素数组塌缩：GPU 字段用单字符串；-OutputFormat XML 的 CLIXML 包裹：遍历全部 `<S>` 节点取第一个可解析 JSON（防 stderr 噪声）。

## 二、sidecarHub 外置模块宿主（实装）

新增 `sidecarhub.go`（932 行）+ `sidecarhub_unix.go`（59 行）+ `sidecarhub_windows.go`（70 行），按 v3.0.0 定稿协议实装：

- **manifest 发现与校验**：`modules.d/*.json`；artifact 必须落在 `modules.d/<id>/` 内（filepath.Rel 防逃逸）；command 至少一项引用 artifact（argv 数组式、禁 shell）；**SHA-256 钉扎**写入主 config `sidecar.modules.<id>.sha256`——未钉扎拒绝并在审计中给出实测摘要供管理员确认（零信任：宿主不替用户信任任何二进制）；摘要不符拒绝。
- **生命周期监管**：supervisor 循环（bring-up：等 /health 就绪 10 秒 → POST /init → POST /start）；30 秒健康检查；崩溃退避重启 1s→2s→4s…上限 60s；**连续 5 次失败停用** + 审计 + 状态面板告警；优雅停机 POST /stop（3 秒宽限）；changeKey（manifest+钉扎指纹）变更检测，未变化不动（含 disabled 状态保留）。
- **传输与权限**：Unix domain socket（Linux/macOS）/ 127.0.0.1+随机端口+token（Windows，named pipe 需 winio 第三方包违反零依赖铁律故弃用）；每模块独立随机 token（crypto/rand 32 字节，仅经环境变量下发、绝不落盘）；最小环境变量白名单（PATH/HOME/TMPDIR 等，**TARS_*_KEY 绝不透传**）；Unix 按 manifest.user 降权（setuid/setgid，root 网关下生效；非 root 保持当前权限并审计，绝不提权）；Windows Job Object 进程树管理。
- **代理与路由**：`/api/ext/{id}/*` 反向代理（流式 FlushInterval=-1；注入 X-TSG-Token、剥离 Authorization/X-API-Key；全流量过网关 WAF/RBAC/审计；模块非 running 返回 503）；`/api/admin/sidecar/status` 状态面板（含拒绝原因与修复提示）、`/api/admin/sidecar/reload` 全量重载（admin）；配置热重载自动触发增量重扫（sidecarHotRescan）；MCP `tars_module_schema` 并入外置模块 schema（sensitive 字段脱敏）。
- **模块注册**：注册表新增 sidecarHub（tools，默认开，HasWorker）。

## 三、前端深层汉化收尾

`frontend/index.html` 约 160 处剩余英文提示串全量汉化：命令面板 Ctrl+K 全部 20 项（页面 17 + 动作 3）、Agent 卡片 7 张名称与描述、Dashboard 系统信息标签、模型页（Start/Stop/LOCAL/CLOUD/运行时/下载进度）、设备扫描与推荐模型、MCP/搜索/飞书测试面板、设置页表单与 CORS 白名单、日志页操作反馈、新手向导、通用错误与 toast（'Stats refreshed'→'统计已刷新' 等 40+ 条）。JS 语法经 node --check 验证通过。

## 四、验证记录（2026-09-29，Linux 沙箱实测）

- **测试**：新增 `v301_test.go`（232 行）：TTL clamp 边界（0/10/300/99999）、白名单拒绝（nvidia-smi/wmic/powershell -Command/sh -c/sudo/管道/参数不全/白名单外文件/多参数）、缓存 HMAC 篡改检测（改值/加键 MAC 必变）、sidecar 五类拒绝（未钉扎含摘要提示/摘要不符/artifact 逃逸/command 未引用 artifact/非法 manifest）——全部通过；既有测试套件（m1/m2/m3m4/m1_integration）无回归；go vet 干净。
- **六平台构建**：CGO_ENABLED=0 静态编译，`file` 头逐一校验（ELF statically linked stripped ×2 / Mach-O ×2 / PE64 ×2），单产物 6.4-6.7MB。
- **Linux 冒烟实跑**（v3.0.1 二进制 + Python 示例 sidecar 模块）：
  - health 200；
  - Tier 1 硬件评估：CPU 型号实测探测（AMD EPYC 9Y24 96-Core Processor）、缓存命中（二次评估零子进程 spawn）、缓存落盘 0600、config 热重载后缓存失效→重探测→回填；
  - 缓存篡改：改写 GPU 字段后 HMAC 校验失败 → AUDIT_TIER1_CACHE_TAMPER 审计 + 文件删除 + 当轮降级 Tier 0（degradeReason 明示）；
  - tier1 开关：enabled=false 热重载即降级（reason=已关闭）、true 即恢复探测；
  - sidecar：manifest+钉扎校验通过 → /health→/init→/start 生命周期 → running；`/api/ext/hello/api/hello` 反向代理返回模块数据；故意配错摘要 → SIDECAR_LOAD_REJECTED（期望/实测摘要并列）；崩溃模块（坏脚本）连续 5 次 bring-up 失败 → 自动停用 + 状态面板告警 + 修复后 reload 重新纳管；
  - 审计事件实测样例：`TIER1_COMMAND_EXEC ts=... cmd=/usr/bin/cat argv=["/proc/cpuinfo"] caller=hardware-assessment exit=0 dur=0ms`、`SIDECAR_MANIFEST_LOADED ... artifact_sha256=...`、`SIDECAR_MODULE_STARTED ... addr=unix:...`。
- **Windows/macOS 为静态验证**（交叉编译 + vet + 逐平台代码走查：Job Object/CLIXML/Setpgid 分支），实机行为级验证按约定由用户在云电脑完成。Windows PowerShell 探测依赖 PS 5.1+（Win10/11 自带）。

## 五、已知事项与建议

- **tier1 熔断与降级不触发安全模块**：Tier 1 全降级时硬件评估回退 Tier 0 精度（GPU/主板型号缺失），security-core 不受影响——符合"Tier 1 是增强而非依赖"的架构定位。
- **Windows sidecar 传输为 127.0.0.1+token**：本机回环仅本机可达，token 鉴权兜底；若未来要求内核态隔离，需评估 winio（将引入第三方依赖，违反当前铁律，故 v3.0.1 不做）。
- **sidecar 示例模块**：冒烟用 Python 示例未随包分发；建议 v3.0.2 起附一个官方 hello 模块样例（modules.d/ 目录 + 钉扎说明）降低接入门槛。
- **Tier 3（eBPF/ESF）**：按约定本版不实装，v4.0 记账不变。

## 六、升级与兼容

- 配置：旧 config.json 无需迁移——tier1 段缺失按默认（开启、TTL 300）处理；saveConfig 现在会正确持久化 v3 顶层段（含 sidecar 钉扎）。
- 部署：单 exe 替换即升级；新增运行期文件仅 `state/tier1-cache.json`（0600）与 `state/sidecar/*.sock`；`tier1/hwprobe.ps1` 由 Windows 端启动时自动落盘（含 SHA-256 校验），无需手工安装。
- 源码包内含本文件；六平台二进制与源码包一并交付云盘。

---

# TarsSecureGuard Go v2.1.0 跨平台兼容与程序精简 · 变更说明

核心目标：**全平台兼容（macOS 全系 / Linux / Windows 10/11）+ 程序精简**。最低支持矩阵、构建产物矩阵、命名规范与构建命令见 [COMPATIBILITY.md](./COMPATIBILITY.md)。

## 一、兼容缺陷修复（v2.0.0 沙箱实测遗留）

| 缺陷（v2.0.0） | 根因 | v2.1.0 修复 |
|----------------|------|-------------|
| Linux/macOS 硬件评估磁盘分恒为 0（哑分） | `exeDrive()` 非 Windows 硬编码回落 `C:\`，`Statfs("C:\")` 恒失败 | `exeDrive()` 平台感知：Windows 保持盘符根，Unix 返回 exe 所在目录；沙箱实测磁盘 0.000GB → 9.75/8.70GB（与 `df` 一致） |
| GPU 检测单路径、无回退、可能阻塞 | Windows 仅依赖 wmic（Win11 24H2+ 已移除）、Linux 仅 lspci、无超时 | 每平台主探测+回退探测：Windows wmic→PowerShell `Get-CimInstance`；Linux lspci→nvidia-smi；macOS system_profiler 精确匹配 `Chipset Model`；全部经 `runCmdTimeout`（5-8 秒）防挂起 |
| Linux amd64 产物动态链接 glibc | 默认 CGO 构建 | `CGO_ENABLED=0` 全平台纯静态，两个 Linux 产物均 `statically linked`，老发行版即拷即跑 |
| 前端遗留 "v1.0" 版本串 | v1 遗留 | `<title>` 改为 TarsSecureGuard，侧栏徽标更新为 v2.1.0 |

## 二、程序精简

- **构建层**：`-ldflags "-s -w"`（剥离符号与调试信息，`file` 确认 stripped）+ `-trimpath`；六平台产物体积下降 **29.3% ~ 31.2%**（对比表见 COMPATIBILITY.md 第二节）
- **依赖审计**：`go.mod` 零第三方依赖，`go list -deps` 全部为标准库，`go mod tidy` 零变更——零供应链面
- **死代码清理**：移除无引用函数 `isAuthorized`（main.go）、`agentRoleList`（agents.go）、`firstNonGPUIGP`（恒等函数，内联）；版本号 const 改 var 支持构建注入
- **代码量**：净减约 40 行，全部平台分支编译通过

## 三、构建产物矩阵（各平台分别构建）

六平台产物：darwin/amd64（macOS 10.15+，Intel 2012 中之后机型）、darwin/arm64（macOS 11+，M1 起全系）、linux/amd64、linux/arm64（内核 2.6.32+）、windows/amd64（Win10/11）、windows/arm64（**实验性**——编译与代码层面完全可行，但 llama.cpp/LM Studio/Ollama 无官方 Windows ARM64 产物，本地模型功能受限，结论详见 COMPATIBILITY.md）。

## 四、验证记录（2026-09-28）

- 六平台交叉编译 + 六平台 `go vet` 全部通过；产物 `file` 头逐一校验符合（Mach-O/ELF static/PE32+）
- Linux amd64 沙箱实跑最终产物：health 200（v2.1.0）、模块开关 200→503→200、security-core 关闭被拒 400、硬件评估磁盘真实读数
- **新 UI headless Chromium 渲染验证**（v2.0.0 交付时只测过旧 UI 的欠账）：Modules 管理页 18 项模块清单、Security Core LOCKED 徽标、开关状态全部渲染正确，零 JS 错误、零失败请求；Dashboard 硬件评估卡片读数正常
- Windows/macOS 无法在 Linux 沙箱实跑——以上为**静态验证**（编译/vet/文件头/逐平台代码走查），实机验证留待用户侧
- Windows 11 24H2+ 无 wmic 场景：GPU 探测自动回落 PowerShell，代码走查确认参数与解析正确（静态验证）

## 五、升级与兼容

- 配置兼容 v1.x / v2.0.0：无新增必填配置项，旧 config.json 直接沿用
- 升级 Go 工具链注意：Go 1.23 起要求 macOS 11+（Intel 支持面收缩）、Go 1.24 起 Linux 内核最低 3.2——本版锁定 go 1.22.5
- 发布渠道不在本版范围：云盘 zip 由既有外部 AI 定时读取推送 GitHub，各版本已推送过

---

# TarsSecureGuard Go v2.0.0 模块化重构 · 变更说明

基于 v1.0.3 源码进行大规模模块化重构。核心原则：**安全保护模块（Security Core）强制默认加载、不可关闭**，模块开关仅在非安全功能上生效；可选项一律落成 config.json 分选项（默认最优安全档），不在设计阶段替用户拍板。

## 一、用户四点需求落实

| 需求 | 落实方式 | 验证 |
|------|----------|------|
| 1. 用户可自行选择加载某个模块 | 17 个可选模块进注册表（`modules.go`）；config.json `modules.<id>: true/false` 或 `POST /api/admin/modules`，2 秒热重载生效；关闭的模块路由返回 503 + 开启提示 | 关闭 webSearch → `/api/search` 503；开启后 200 |
| 2. 安全模块强制加载不可关闭 | security-core 不进模块注册表、中间件链硬编码；封堵 v1 后门 `security.wafEnabled:false` / `mode:"off"`（启动+热重载两条路径均自动纠正并落 `CONFIG_CORRECTED` 审计，纠正值回写落盘）；POST 值域校验拒绝非法值（`CONFIG_REJECTED`） | 配置后门值实测被纠正；API 关闭 security-core 返回 400 |
| 3. 硬件水平检测 + 提升建议 | `hardware.go` 四维评分（CPU/内存/磁盘/GPU 0-100）+ S/A/B/C/D 评级 + 模型档位推荐（≥32GB→14B+ / ≥16GB→7B-14B / ≥8GB→3B 以下 / 更低→云端路由）+ 每条建议含「现状/建议/理由」；跨平台物理内存探测（Windows GlobalMemoryStatusEx / Linux /proc/meminfo / macOS sysctl）；API `GET /api/admin/hardware/assessment`；前端 Dashboard 新增硬件评估卡片；新工具 `tars_hardware_advisor` | 沙箱实测输出 D 级 + 6 条可执行建议 |
| 4. 更多自定义功能可关掉 | customTools（自定义 HTTP 转发工具，含密钥 env: 引用）、customAgents（自定义角色）、urgentChat、autoStartModel 等模块默认关闭可随时开；防火墙三档 / 直连传输 / WAF 强度全部 config 分选项 | 模块开关热重载实测 ≤3 秒生效 |

## 二、模块框架（modules.go，331 行）

- `Module` 注册表：ID/Name/Description/Category/Default/Deps/HasWorker；17 个可选模块 + security-core（锁定）
- `moduleRoute` 路由包装：模块关闭返回 503 + 开启提示（不泄露内部路由结构）
- 依赖拓扑：开启连带开启依赖（API 与热重载均生效）；关闭被依赖模块——API 路径拒绝（明确告知先关谁），热重载路径自动纠正 + `MODULE_AUTO_ENABLE/MODULE_AUTO_DISABLE` 审计
- 模块工作者生命周期：Start/Stop + context 取消 + 3 秒等待上限，防 goroutine 泄漏（autoStartModel / autoDiscovery 两个后台 worker）
- `GET /api/admin/modules` 返回模块清单（security-core 带 `locked:true` 徽标）

## 三、防火墙三档策略（firewalldriver.go，替代 v1 firewall.go）

config 分选项 `security.firewall.policy`（`security.firewall.banDuration` 可选）：
- **passive**（默认）：被动检测，不动系统防火墙
- **dynamic-ban**：内存封禁表（WAF 命中即封，4096 上限惰性清理，默认 10 分钟）
- **os-link**：系统防火墙联动（Windows netsh / Linux iptables 追加链尾 + nftables 回落 / macOS pfctl 诚实降级）；规则命名空间 `TarsGuard-<实例ID>-` 隔离；启动先清理本实例孤儿规则；仅端口维度规则绝不阻断管理连接；每条 add/remove 落审计
- v1 兼容：空 policy + firewallLock 启用 + Windows → 自动解析为 os-link（保持 v1 行为）

## 四、直连层切换点（direct.go，采纳调研结论「保持 Go 核心」）

- `direct.transport: native | grpc-sidecar`（默认 native）
- grpc-sidecar 为预留切换点：地址仅允许 127.0.0.1/localhost/::1/unix: 前缀；未配地址自动回落 native；为未来 Rust/Python 专精组件预留（不重写现有实现）

## 五、customTools SSRF 五红线（锦衣卫预审 ② 补强）

1. 连接时校验解析后 IP（`ssrfSafeDialContext`：DNS 解析 → 逐一校验公网性 → 用已校验 IP 直连），拒绝 RFC1918/回环/链路本地/云元数据——防 DNS 重绑定
2. 禁用重定向跟随（`CheckRedirect` 返回 `http.ErrUseLastResponse`）
3. 协议白名单：仅 http/https（file/ftp/gopher 拒绝）
4. 超时 30 秒 + 响应大小限制（复用 maxFetchBytes 2MB）
5. 每次调用落 `CUSTOM_TOOL_CALL` 审计（目标 URL + 结果状态）

实测：169.254.169.254 / 127.0.0.1 / file:// 均被拒绝并落审计；公网 URL 正常返回。

## 六、其余安全强化

- `isConfigPathAllowed` 移除 `security.wafEnabled`（保留 `security.mode` 的 normal/strict 切换，拒绝 off 值）；新增 firewall/direct 路径
- 值域校验共享函数 `validateConfigValue`：`POST /api/admin/config` 与 `set_config` 内置工具同一防线
- WAF 命中联动 dynamic-ban 封禁
- 前端：新增 Modules 模块管理页（security-core 锁定徽标）；Dashboard 硬件评估卡片；Security/Settings 页 WAF 开关改为「强制开启 · 不可关闭」锁定态、移除 off 选项、新增防火墙/直连档位选择器

## 七、缺陷修复（实施中发现）

| 缺陷 | 修复 |
|------|------|
| `loadConfig` 在纠正前回写配置，后门值原样落盘 | 回写移到纠正+模块应用之后 |
| `handleConfig` 持写锁调用 `firewallReconcile`（内部取读锁）自死锁 | reconcile 移到解锁后 |
| `handleConfig` 持写锁调用 `auditLog`（内部取读锁）自死锁 | 拒绝项暂存、解锁后落审计 |
| `set_config` 工具无值域校验可写 `mode:"off"` | 共享 `validateConfigValue` 堵上 |

## 八、验证记录（2026-09-27，Linux 沙箱实测）

- `go build` / `go vet` / `GOOS=windows GOARCH=amd64` / `GOOS=darwin GOARCH=arm64` 全部通过
- 后门值自动纠正并落盘（wafEnabled:false→true、mode:off→normal、非法档位→passive）
- 模块关 503 → API 开 → 200 → 文件热重载关 → 503（≤3 秒）
- security-core API 关闭被拒（400）；依赖违例拒绝（关 localModels 被拒并提示先关 modelDownload）
- 硬件评估输出评级 + 建议（含现状/建议/理由三要素）
- 防火墙档位热切换 + 非法值纠正 + `FIREWALL_POLICY_CHANGE` 审计
- SSRF 四场景（元数据 IP/回环/file 协议/公网正常）
- 前端 JS 语法校验通过，新页面/新卡片随二进制 embed 正常服务

## 九、已知事项

- v1 遗留：`loadConfig`/`watchConfig` 对全局 `cfg` 的读写未走 `cfgMu`（数据竞争窗口极小，v1 即如此）；后续版本可加锁收敛
- os-link 档位建议仅用于单实例部署、有管理员在场的环境（文档与前端选项均已标注）
- grpc-sidecar 为预留档位，当前切换后自动回落 native（未实现边车协议）

## 十、升级与兼容

- 配置兼容 v1.x：缺失的 v2 字段自动补默认值；v1 `firewallLock` 行为在 Windows 下保持
- 从 v1.0.3 直接替换可执行文件即可；config.json 首次启动会被规范化回写（后门值自动纠正）

---

# TarsSecureGuard Go v1.0.3 安全与跨平台修复 · 变更说明

基于 TarsSecureGuard Go v1.0.2 源码进行缺陷修复与功能强化。

## 一、文件清单

### 新增文件（5 个）
| 文件 | 说明 |
|------|------|
| `device_windows.go` | Windows 专属磁盘空间查询（`//go:build windows`） |
| `device_other.go` | Linux/macOS/FreeBSD 磁盘空间查询（`//go:build !windows`） |
| `process_windows.go` | Windows 子进程 HideWindow 封装（`//go:build windows`） |
| `process_other.go` | 非 Windows 平台 HideWindow 空实现（`//go:build !windows`） |
| `OPTIMIZATION_REPORT.md` | 优化报告（含 4 点回应 + 调研结论 + 验证方法） |

### 修改文件（6 个）
| 文件 | 变更内容 |
|------|----------|
| `device.go` | 移除 Windows 专属代码，保留跨平台公共代码（`diskUsage` 类型、`getDeviceInfo`、`discoverLocal`） |
| `mcp.go` | 移除直接 `syscall.SysProcAttr{HideWindow: true}` 调用，改为 `applyHiddenWindow(cmd)`；移除未使用的 `syscall` import |
| `models.go` | 同上；新增模型管理端点的审计日志调用（`MODEL_START`/`MODEL_STOP`/`MODEL_DOWNLOAD`） |
| `config.go` | 新增 `Users []User`（RBAC 多用户）、`Security.AuditLogEnabled`（审计开关）；`loadConfig` 支持环境变量覆盖敏感 Key；审计日志默认开启 |
| `main.go` | 新增 RBAC 中间件（`userFromRequest` / `requireRole` / `isAdminRoute`）、审计日志函数 `auditLog`、新增路由 `/api/admin/audit-logs`；`isConfigPathAllowed` 增加 `security.auditLogEnabled`；`sanitizedConfig` 脱敏用户 Key |
| `handlers.go` | 新增 `handleAuditLogs`（仅 admin 可读当日审计日志）；`handleConfig` POST 增加审计日志；GET 返回增加 `users`（脱敏）和 `auditLogEnabled`；增加 `os`/`path/filepath`/`strings` imports |
| `waf.go` | 新增 WAF 规则：`PromptInjection`（prompt injection 防御）、`PII泄漏`（PII 检测）；新增 `maskPII` / `maskPIIInMessages` 函数 |
| `chat.go` | `handleChat` 在路由到后端前对 `messages[].content` 自动执行 PII 脱敏 |

## 二、缺陷修复对照

| 缺陷 | 修复状态 | 验证方法 |
|------|----------|----------|
| Linux build tags 缺失 | ✅ | `go build`（Linux）+ `GOOS=windows GOARCH=amd64 go build` 均通过 |
| API Key 明文存储 | ✅ | 环境变量 `TARS_API_KEY` 可覆盖；`/api/admin/config` 返回 Key 显示为 `***` |
| 单管理员 / 无 RBAC | ✅ | 配置 `users` 后，不同 role 访问 admin/写端点返回 403 |
| 无审计日志 | ✅ | 操作后查看 `logs/audit-YYYY-MM-DD.log` 有结构化记录；GET `/api/admin/audit-logs` 可查询 |
| WAF 无 prompt injection 防御 | ✅ | strict 模式下含 `ignore previous instructions` 的请求返回 403 |
| WAF 无 PII 检测/脱敏 | ✅ | 聊天消息中的手机号/邮箱在后端请求前被替换为 `****` |

## 三、兼容性说明

- 单用户模式：不配置 `users` 时，行为与 v1.0.2 完全一致（回退单管理员 Key）
- 所有既有 API 路由、请求/响应格式不变；新增路由独立存在
- 新增环境变量：`TARS_API_KEY`、`TARS_OPENAI_KEY`、`TARS_DEEPSEEK_KEY`、`TARS_SEARCH_KEY`
- 审计日志默认开启，可通过 API 修改 `security.auditLogEnabled` 关闭

## 四、验证记录

- `go build`（Linux amd64）通过，`go vet` 无告警
- `GOOS=windows GOARCH=amd64 go build` 交叉编译通过
- RBAC 冒烟测试：admin/user/readonly 三种角色权限边界正确
- 审计日志测试：配置修改、模型启停、权限拒绝均有记录
- WAF 测试：prompt injection 特征词在 strict 模式下被拦截；PII 在 normal 模式下被脱敏

## v3.0.0 — "Your AI's Safety Belt"（2026-09-28）

### A 线 · 资源守护器（resourceGuardian）
- GOMEMLIMIT 软内存上限（min(物理 10%, 384MB)，eco 档 128MB，resource.memLimitMB 可覆盖）
- L0-L3 分级响应状态机：L1 降级非核心(60%/30s) → L2 熔断高耗(80%/60s) → L3 优雅停机(90%/120s)
- L3 停机流程：30s drain + 审计刷盘 + 状态保存 + 退出码 42 + 60s 冷却（防重启风暴）
- eco 省资源档：硬件评估 D 档自动套用；锦衣卫附加意见 A：L2/L3 判定采用 RSS 口径（捕捉 CGO/外部泄漏）
- 状态持久化 state/guard.json；管理端点 /api/admin/guard/status

### B 线 · 防护升级（semanticGuard + 限流 + IP 信誉）
- 语义检测分级分流：静态规则先行，灰区送本地 0.5B-1.5B 小模型；「AI 只能加严」单向合并铁律（100% 单测 + 运行时 POLICY_VIOLATION 审计）
- fail-close（锦衣卫裁定 1 全项）：引擎不可用 → 503 SEMANTIC_ENGINE_UNAVAILABLE，fallback_mode 仅 block
- 指纹缓存（SHA-256 归一化，60min TTL）；灰区单 IP 5/分钟上限（附加意见 C）
- 三维令牌桶限流（IP×端点类 / Key×端点类 / IP 总量：chat 60、admin 10、model 6、IP 240 每分钟）
- 本地 IP 信誉评分：起分 100，WAF -30 / 404 扫描 -10（分钟窗去重）/ 限流 -15；<40 动态封禁×2；白名单；24h 自动恢复；NAT 异常告警；admin 解封（裁定 6 全项）

### C 线 · 两阶段智能路由（smartRouter + scoreBoard）
- 静态规则优先 + ε-greedy bandit 优化自动分支（ε 0.1→0.02 衰减）
- 防伪造（附加意见 D）：非 admin 反馈权重 ×0.1；route_preview 仅 admin
- 模型评分榜：运行时分（成功率×时延）融合 lm-eval-harness 离线评测（相对参考，诚实标注；Python 边车按需，不捆绑）

### D 线 · 生态位升维（MCP stdio）
- `--mcp-stdio`：JSON-RPC 2.0 over stdio，任何本地 agent 接入即获全套防护（本版核心差异化）
- 工具：tars_guarded_chat / tars_guard_status / tars_route_preview / tars_model_score / tars_module_schema / tars_ip_reputation_unban
- 文件工具本版不提供（锦衣卫裁定 4 收敛位）；管理操作需 TSG_ADMIN_KEY，全程审计

### E 线 · 稳定性工程
- panic recovery 全覆盖（PANIC_RECOVERED 审计）
- Go fuzzing：FuzzWAFMatch / FuzzParseConfig / FuzzSGNormalize（语料不落盘）
- 8h 循环压测脚本随包交付：soak.sh（Linux/macOS）、soak.ps1（Windows）
- 单元 + httptest 集成测试全绿（-race）；配置热重载审计 CONFIG_HOT_RELOAD

### 平台与交付
- UI 全量中文化（v2.1.0 遗留要求落实）
- Tier 0-3 能力分层：本版全部 Tier 0（单 exe 零依赖）；Tier 1 系统原生命令参数化调用（红线待锦衣卫补充裁定）；Tier 2 Python/MLX 边车按需；Tier 3 eBPF/ESF 仅记账、v4.0 候选
- 部署件：systemd unit / Dockerfile / docker-compose（rootless 兼容）/ K8s sidecar 示例 / macOS LaunchDaemon
- 明确不做：不捆绑 Python；v3.0.0 不做第三套扩展机制，WASM 推迟 v4.0
