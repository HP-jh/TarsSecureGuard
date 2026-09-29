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
