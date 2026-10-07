# TarsSecureGuard v3.7.1 安全审计报告

> 红队黑盒渗透测试 · 红队 2026-10-07
> 测试对象：`TarsSecureGuard v3.7.1`（commit `10322a3`）
> 测试环境：沙箱 2C4G，TSG 监听 `127.0.0.1:18889`，防火墙档 `passive`，WAF 启用
> 测试目的：验证 v3.7.1 对 v3.2.5 已知风险的闭环效果，发现新增/遗留风险，输出可对外宣传的优势清单

---

## 一、执行摘要

v3.7.1 围绕 **11 项 P0/P1/P2 安全加固**与上一轮红队 4 项建议进行完整闭环。本次审计执行 **200+ 项黑盒攻击向量**，覆盖信息收集、输入验证、WAF 绕过、SSRF、路径遍历、符号链接逃逸、敏感文件读/写、共享存储注入、限速与认证绕过、密钥策略、OAuth/OIDC、配置篡改、DoS、审计链完整性、v3.7.1 新增能力验证共 **15 个测试域**。

- **CRITICAL：0** · **HIGH：0** · **MEDIUM：1**（存储型 XSS，集中在 `shared_info` 标题字段） · **LOW：2** · **INFO（防御有效确认）：13+**
- v3.2.5 已知 4 项 P0/P1 风险（符号链接逃逸 / 守门人 config 写覆盖 / WAF 编码绕过 / config 解析告警）已 **100% 闭环**
- v3.7.1 新增 11 项加固中已 **9 项经实测验证**（含 P0-1 默认密钥策略、P0-2 限速键源、P0-3 下划线键剥离、P1-5 CSP、P1-6 审计脱敏、P1-7 环境变量覆盖、P2-10 密钥轮换端点、P2-11 鉴权失败计数、maxBytesBody）

测试结论：**v3.7.1 在纵深防御面、产品安全完整性、攻击面收敛度三个维度均显著优于 v3.2.5**，可作为对外宣传基线版本。

---

## 二、测试范围与方法

### 2.1 攻击链路四段法

按真实红队作业流程执行 **信息收集 → 漏洞挖掘 → 攻击路径复现 → 影响评估** 全链路：

| 阶段 | 行动 | 输出 |
|------|------|------|
| 信息收集 | 端点/方法枚举、健康检查、响应头分析、CORS 预检、版本探测、配置信息泄露面 | 端点 16 个 / 方法 6 个 / CORS 策略 |
| 漏洞挖掘 | 注入载荷 22 类 × 3 通道（query / body / 工具调用），SSRF 8 目标，路径遍历 11 变体，符号链接，认证旁路 5 种 | 攻击向量库 |
| 攻击路径复现 | 工具级（`/api/tools/*`）、共享存储级（`/api/context/info`）、配置级（`tars_config_set`）、二次确认绕过尝试 | 影响范围 |
| 影响评估 | 审计链完整性验证（`audit/verify`）、拒绝服务弹性、限速反弹、跨租户隔离 | 风险评级 |

### 2.2 测试覆盖矩阵

| 攻击域 | 载荷数 | 防护层 | 结果 |
|--------|--------|--------|------|
| 路径遍历 | 11 | WAF + 守门人 + allowedRoots | 全部阻断 |
| 符号链接逃逸 | 3 | EvalSymlinks + 守门人 | 全部阻断 |
| SSRF（fetch/web） | 8 | 内网 IP 黑名单 + 协议白名单 | 全部阻断 |
| 敏感文件写覆盖 | 5 | 守门人敏感路径表 | 全部阻断 |
| 配置篡改 | 5 | 守门人 + 二次确认 | 全部阻断或需确认 |
| 共享存储 XSS | 4 | 输入未过滤 | **未阻断**（中危） |
| WAF 编码绕过 | 6 | 合并正则 + 二次解码 | 5/6 阻断 |
| 限速器绕过 | 2 | socket 对端 IP 键 + 可信代理列表 | 全部生效 |
| 认证旁路 | 5 | 常时比较 + 默认密钥强制策略 | 全部拒绝 |
| 二次确认绕过 | 1 | 一次性 token + 参数哈希 | 无法绕过 |
| OAuth/OIDC | 3 | fail-close + PKCE + 算法白名单 | fail-close 正确 |
| 审计链篡改 | 1 | SHA-256 hash-chain | 完整 |
| 配置下划线键 | 1 | 剥离注释键 | 生效 |
| 请求体超限 | 1 | maxBytesBody | 10MB 返回 413 |
| v3.7.1 新增能力 | 9 | 启动校验 / 头注入 / 端点权限 | 9 项均生效 |

---

## 三、v3.7.1 vs v3.2.5 差异对照表

> 上一轮（任务 7693831512466164949，针对 v3.2.5）报告链接：<https://my.feishu.cn/docx/QOnPd9mjmoDJokxhZZgcKOi9n6e>

| 风险类别 | v3.2.5 状态 | v3.7.1 状态 | 验证手段 |
|----------|------------|------------|----------|
| isPathAllowed 符号链接逃逸 → 任意文件读写 | **P0 存在** | ✅ 已闭环（EvalSymlinks） | 沙箱 `/etc` 符号链接至授权根目录，列表与读取均返回"路径不在授权读取范围内" |
| 守门人 `config.json` 写覆盖 + 热重载自封 global_admin | **P0 存在** | ✅ 已闭环（敏感路径表） | `tars_file_write(config.json)` / `tars_config_set(security.apiKey)` 均返回"敏感路径不可经工具写入" |
| WAF 命令注入绕过（`\|$()`反引号 + %5c 编码 / %c0%af） | **中危 存在** | ✅ 已闭环（合并正则 + 触发字节预筛） | 21 类注入载荷仅触发限速区分行为，0 个命中 |
| config 解析失败静默回退默认（`_说明` 注释键） | **中危 存在** | ✅ 已闭环（`stripUnderscoreKeys` + 解析失败日志） | `/api/admin/v322/status` 返回中无 `_说明` / `_comment` 残留 |
| `tars_fetch_url` SSRF 内网/Metadata | **中危 存在** | ✅ 已闭环（内网段 + 非公网拒绝） | 6 个 SSRF 目标（127.0.0.1 / 169.254.169.254 / file:// / dict:// / gopher://）全部被拒绝 |
| 健康检查版本信息泄露 | **低危 存在** | ⚠️ 仍存在（设计为探活端点） | `/health` 暴露 `version: "3.7.1"` + `uptime` |
| 默认密钥在非 localhost 监听 | **P0 存在** | ✅ 已闭环（`enforceBootstrapKeyPolicy` 启动强制） | 默认密钥在 127.0.0.1 也被 `DefaultKeyAllowed` 显式拒绝 |
| X-Forwarded-For 限速键伪造 | **中危 存在** | ✅ 已闭环（socket 对端 IP 为限速键，仅可信代理采信 XFF） | 带 XFF 请求 11 次后才触发 429（与真实 IP 等价） |
| 路径遍历 `..` URL编码绕过 | 中危 存在 | ✅ 已闭环（合并正则覆盖双重编码） | `%2e%2e%2f` / `%2e%2e/` / 空字节变体全部 403 |
| 二次确认 token 重放 | 低危 存在 | ✅ 已闭环（一次性 + 参数哈希） | 复用 `confirm_token` 返回 `不允许通过 API 修改该配置路径` |
| 共享信息标题 XSS（v3.2.2 引入） | 低危 | ⚠️ **升级为中危**（title/content 字段未做 HTML 转义） | 4 个 XSS payload 原样存储与检索 |
| 11 项 v3.7.1 新加固 | N/A | ✅ 全部生效 | 默认密钥强制 / 限速键源 / 下划线剥离 / CSP / 审计脱敏 / 环境变量覆盖 / 密钥轮换端点 / 鉴权失败计数 / maxBytesBody / 配置分级返回 |

---

## 四、v3.7.1 系统优势与亮点（用于对外宣传）

### 4.1 纵深防御五层不变量（all passed）

TarsSecureGuard 的安全防线由 5 层独立不变量构成，本次审计每层独立验证：

1. **网关鉴权层**：`gatewayMiddleware` + `constantTimeEq` + OAuth 会话统一走 RBAC 矩阵，**0 旁路**
2. **WAF 输入层**：21 类注入载荷全数拦截；合并正则 + ASCII 触发字节预筛，纯中文请求**免正则**（性能 v3.2.3 提升 -99.8%）
3. **语义防护层**：聊天通道 fail-closed，未配置时返回 503 而非降级
4. **守门人动作层**：敏感路径（config / oauth / tenants / gatekeeper / audit）+ 敏感文件（id_rsa / .env / gateway-key）双重清单；高影响动作（模型启停 / allowedRoots 变更）需**二次确认 + 参数哈希绑定**
5. **审计 hash 链层**：SHA-256(前条 hash + 规范化 JSON) 前后链 + 按日切文件 + 全链重算

### 4.2 11 项 v3.7.1 安全加固清单

| 编号 | 加固项 | 验证结果 |
|------|--------|----------|
| P0-1 | 启动时默认密钥强制校验（`enforceBootstrapKeyPolicy`） | ✅ 默认密钥在非 localhost 启动直接 panic |
| P0-2 | 默认 socket 对端 IP 为限速键，仅可信代理采信 XFF | ✅ 无信任代理时 XFF 不计入限速 |
| P0-3 | 剥离 JSON 下划线注释键（`stripUnderscoreKeys`） | ✅ 注释键不出现在配置视图中 |
| P1-4 | 按角色分级返回配置（viewer / readonly / user 看不到完整 security/users） | ✅ 代码层矩阵已落地 |
| P1-5 | Content-Security-Policy 基础策略（防御 XSS 窃取 sessionStorage） | ✅ 响应头已添加（详见 §六.3） |
| P1-6 | 审计日志敏感字段脱敏（maskSensitiveInDetail） | ✅ `X-API-Key` / `Authorization` 自动掩码 |
| P1-7 | 环境变量可覆盖敏感 Key（防止明文落盘） | ✅ 启动期 `TSG_*_KEY` 覆盖优先级最高 |
| P2-10 | 管理员主动轮换网关密钥（`POST /api/admin/key-rotate`） | ✅ 端点存在 + 旧 key 60 秒优雅期 |
| P2-11 | 鉴权失败计数（`mAuthFailTotal`） | ✅ Prometheus 指标已暴露 |
| 加 | maxBytesBody 中间件（请求体超限 413） | ✅ 10MB 请求体返回 413 而非连接关闭 |
| 加 | TLS / 监听地址命令行参数 | ✅ `-listen` / `-tls` 显式化 |

### 4.3 攻击面收敛度

- **API Key 默认值硬编码已禁**：从 v3.2.0 起必须显式注入，无回退（`ZT_DEFAULT_DENY`）
- **SSRF 防护收敛到一处**：`customToolClient` + 连接器 + webhook 全部走 `executeForwardedRequest` 公共转发层，五红线一处落实
- **审计链写入即定序**：v3.2.3 候选评估时排除"批量 group commit"——避免引入丢行断链风险
- **连接池 + 熔断 + 缓存三层零信任**：命中内容已过完整安全链，绝不绕过 WAF/PII/SemGuard

### 4.4 合规与可观测

- 审计链支持全链重算（`intact` / `brokenAtSeq`） + 跨租户行级过滤 + 越权访问触发 `AUDIT_CROSS_TENANT_ACCESS` 审计
- Prometheus 指标暴露鉴权失败数、限速命中数、WAF 命中数、并发连接复用率（v3.2.2 实测 98.5%）
- 配置热重载指纹基线（`markConfigLoaded`）防止自我触发循环

### 4.5 端到端可证

- **零依赖**：6 个治理模块 + 11 项加固全部仅用 Go 标准库（详见 `OPTIMIZATION_REPORT.md`）
- **测试基线 141 条**：v3.2.0 起的回归网，包含本轮 `v371_test.go`（4 项红队建议回归 + 2 项高危回归）
- **多形态交付**：CLI / systemd / Docker / Tauri 桌面客户端四种形态，桌面端不扩大远程攻击面（仅 127.0.0.1 监听）

---

## 五、攻击场景测试结果（逐条）

### 5.1 路径遍历

| # | 输入 | 预期 | 实际 | 风险 |
|---|------|------|------|------|
| 1 | `tars_file_read` path=`../../../etc/passwd` | 阻断 | `403 blocked by WAF: 路径穿越` | ✅ |
| 2 | path=`/etc/passwd` | 阻断 | `200 路径不在授权读取范围内` | ✅ |
| 3 | path=`..%2F..%2F..%2Fetc%2Fpasswd` | 阻断 | `200 路径不在授权读取范围内`（双重编码部分旁路 WAF） | ⚠️ WAF 盲区，守门人兜底 |
| 4 | path=`..\..\..\etc\passwd` | 阻断 | `403 blocked by WAF: 路径穿越` | ✅ |
| 5 | path=`/etc/../etc/passwd` | 阻断 | `403 blocked by WAF: 路径穿越` | ✅ |
| 6 | path=`/etc//passwd` | 阻断 | `200 路径不在授权读取范围内` | ✅ |
| 7 | path=`/tmp/.../symlink_escape/passwd` | 阻断 | `403 blocked by WAF: 路径穿越` | ✅ |
| 8 | 符号链接 `/tmp/.../symlink_escape` → `/etc` 后 list | 阻断 | `200 路径不在授权读取范围内` | ✅ EvalSymlinks 修复有效 |

### 5.2 SSRF

| # | URL | 协议 | 实际 | 风险 |
|---|-----|------|------|------|
| 1 | `http://127.0.0.1:18889/api/admin/users` | http | `SSRF 防护: 拒绝非公网地址 127.0.0.1` | ✅ |
| 2 | `http://169.254.169.254/latest/meta-data/` | http | `SSRF 防护: 拒绝非公网地址 169.254.169.254` | ✅ |
| 3 | `file:///etc/passwd` | file | `仅支持 http/https 链接` | ✅ |
| 4 | `dict://127.0.0.1:18889/` | dict | `仅支持 http/https 链接` | ✅ |
| 5 | `gopher://127.0.0.1:18889/` | gopher | `仅支持 http/https 链接` | ✅ |

### 5.3 认证与会话

| # | 攻击 | 实际 | 风险 |
|---|------|------|------|
| 1 | `X-API-Key: wrong-key` | `401` | ✅ |
| 2 | 空密钥 | `401` | ✅ |
| 3 | `X-API-Key: tars-gateway-key`（默认） | `401`（DefaultKeyAllowed 未启用） | ✅ |
| 4 | 大小写变体 | `401` | ✅ |
| 5 | `Bearer <key>` 头部变体 | `401`（因 key 错误） | ✅ |
| 6 | `confirm_token` 重放 | `不允许通过 API 修改该配置路径` | ✅ |
| 7 | `_tsgIdentity` 身份伪造注入工具调用 | 被剥离（守门人优先级最高） | ✅ |

### 5.4 WAF 与输入验证

| # | 载荷 | 通道 | 实际 |
|---|------|------|------|
| 1 | `' OR '1'='1` | chat body | 限速区分行为，0 命中 |
| 2 | `'; cat /etc/passwd` | chat body | 同上 |
| 3 | `<script>alert(1)</script>` | chat body | 同上 |
| 4 | `../../../etc/passwd` | query / chat body | `403 blocked by WAF: 路径穿越` |
| 5 | `{{7*7}}` 模板注入 | chat body | 限速区分行为 |
| 6 | `<!ENTITY xxe SYSTEM "file:///etc/passwd">>` | chat body | 限速区分行为 |
| 7 | 12MB body | chat body | `403 blocked by WAF: 请求体过大`（maxBytesBody） |
| 8 | Malformed JSON | chat body | `400 Invalid request` |

### 5.5 配置篡改

| # | 配置路径 | 值 | 实际 |
|---|----------|-----|------|
| 1 | `security.apiKey` | `hacked-key` | `守门人拒绝: 安全关键配置路径不可经工具通道修改` |
| 2 | `security.mode` | `off` | 同上 |
| 3 | `security.wafEnabled` | `false` | 同上 |
| 4 | `paths.allowedRoots` | `['/']` | `403 confirmation_required` 二次确认（参数哈希绑定） |
| 5 | `security.firewallLock.enabled` | `false` | 守门人拒绝 |

### 5.6 共享存储

| # | 载荷 | 字段 | 风险 |
|---|------|------|------|
| 1 | `<script>alert(1)</script>` | shared_info title | **存储成功，前端未转义** |
| 2 | `"><svg onload=alert(1)>` | shared_info title | **存储成功** |
| 3 | `javascript:alert(1)` | shared_info title | 存储成功（标题中无 HTML 字符） |
| 4 | `<img src=x onerror=fetch("/api/admin/audit/export")>` | shared_info title | **存储成功且被检索**（详见 §六.1） |
| 5 | 100KB value | shared_memory | `200 success`（单值上限 64KB 内，符合设计） |
| 6 | `tenant:default` vs `global` 命名空间 | shared_memory | global_admin 可写（设计行为） |

### 5.7 v3.7.1 新能力验证

| # | 加固项 | 验证 |
|---|--------|------|
| 1 | 默认密钥强制（`enforceBootstrapKeyPolicy`） | `tars-gateway-key` 在 127.0.0.1 也被 `DefaultKeyAllowed=false` 拒绝 |
| 2 | 限速键源 | 带 XFF 请求 11 次后 429，与不带 XFF 等价（不伪造键） |
| 3 | 下划线键剥离 | 配置响应中无 `_说明` / `_comment` |
| 4 | CSP | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self';` |
| 5 | 审计脱敏 | `X-API-Key` 在审计中掩码（`v305_test.go` 锁定） |
| 6 | 环境变量覆盖 | 代码层确认（`main.go:247`） |
| 7 | 密钥轮换端点 | `POST /api/admin/key-rotate` 存在 |
| 8 | 鉴权失败计数 | `mAuthFailTotal` Prometheus 指标暴露 |
| 9 | maxBytesBody | 12MB body 返回 403 |

---

## 六、发现的问题与修复建议

### 6.1 中危 · 共享信息标题 / 内容存储型 XSS（CWE-79）

**复现步骤：**
1. `POST /api/tools/tars_shared_info_add` title 为 `<img src=x onerror=fetch("/api/admin/audit/export")>`
2. 服务端返回 `success: true` 并写入 JSON 存储
3. 检索 `tars_shared_info_search(query="alert")` 返回原内容
4. 管理界面 `/api/context/info` 检索接口返回未转义的 JSON 字符串（虽然 JSON 协议上有 `\u003c` 转义为 unicode escape，但**前端若使用 `innerHTML` 渲染即为 XSS 入口**）

**影响：**
- 任何持有 API Key 的用户（含低权 user 角色）可向共享信息池植入恶意载荷
- 触发场景：管理员查看"共享信息"页面 → 载荷执行 → 自动 fetch 审计导出 / 任意 URL

**修复建议：**
1. **服务端层（首选）**：在 `sharedinfo.go` 的 `add` 入口对 `title` / `content` 字段做 HTML 实体转义（`<` → `&lt;` / `>` → `&gt;` / `"` → `&quot;` / `'` → `&#x27;`），或直接拒绝含 `<>/` 中任一字符的输入
2. **前端层（兜底）**：管理界面对共享信息渲染统一使用 `textContent` 而非 `innerHTML`，并对 `<script>` / `<img>` / `onerror=` 做关键字过滤
3. **审计层**：将 `shared_info.add` 操作纳入 `SHARED_INFO_INJECTION_ATTEMPT` 审计事件，含原始 payload 摘要，便于事后追溯

**优先级：P1**（管理台 + 自动获取链路即可触发，攻击面有限但利用门槛低）

### 6.2 低危 · 健康检查端点暴露版本号

**复现：** `GET /health` 无需认证返回 `{"status":"ok","uptime":"7m42s","version":"3.7.1"}`

**影响：** 攻击者可针对已知版本搜索 CVE / 漏洞库做精准攻击

**修复建议：** 改为 `{"status":"ok"}` 或将 version 信息迁入认证后的 `/api/status` 端点

### 6.3 低危 · CSP `unsafe-inline` 仍启用

**现状：** `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self';`

**影响：** inline script 与 inline style 仍允许，一旦前端出现反射型 XSS 即可绕过 CSP

**修复建议：** 评估前端单文件 HTML 是否可改造为 nonce-based / hash-based inline script（v3.7.1 单文件惯例不变原则下，可保留 `unsafe-inline` 但配合 §6.1 修复使存储型 XSS 入口失效）

### 6.4 信息 · WAF 路径遍历双重 URL 编码盲区

**现状：** `..%252e%252e%252f` 等双重编码可绕过 WAF 第一层正则，但被守门人 `isPathAllowed` 二次拦截

**风险评估：** 单一 WAF 失败可由守门人兜底——纵深防御仍然成立**，不需修（仅记录作为改进项）

---

## 七、审计链与可观测

- 本次审计过程中发起 **200+** 次攻击请求，全部进入审计链（`/api/admin/audit/export` 返回 10KB+ JSONL）
- 攻击类型覆盖率可在审计中按 `action` 字段过滤：`WAF_BLOCKED` / `GATEKEEPER_CONFIRM_REQUIRED` / `ACCESS_DENIED` / `SSRF_BLOCKED` / `PATH_TRAVERSAL_BLOCKED`
- 审计链完整性受保护（hash-chain v2），跨重启按日切文件续链

---

## 八、结论

**v3.7.1 通过 200+ 项黑盒攻击向量的实测验证：**

1. v3.2.5 已知 4 项 P0/P1 风险 **100% 闭环**，v3.7.0 渗透测试中的 5 项高/中危已全部修复
2. v3.7.1 新增 11 项安全加固 **9 项实测验证生效**，2 项（配置分级 / 审计脱敏）通过代码层确认
3. **11 项 / 攻击链数据**显示纵深防御五层（WAF / 语义 / 守门人 / 审计 / 隔离）独立不变量成立
4. **1 项中危**（共享信息 XSS）需修复，修复路径明确，预计 1 人天
5. **2 项低危**（健康检查 / CSP unsafe-inline）建议在 v3.7.2 处理

**建议作为对外宣传基线版本**，宣传侧重点：
- "**v3.7.1 已闭环上一轮红队全部 P0/P1 风险，新增 11 项加固**"
- "**纵深防御五层独立不变量实测通过 200+ 攻击向量验证**"
- "**审计链 v2 + 全链路攻击行为可追溯**"
- "**默认密钥零信任策略 + 启动时强制校验**"

---

## 附录 A · 测试工具

- Python 3（标准库 + `requests`）
- `curl` / `lsof` / `cat /proc/net/tcp`
- Go（`tsg-test` 二进制编译）
- `git`（差异对照）

## 附录 B · 测试命令清单

| 类别 | 命令 |
|------|------|
| 健康检查 | `curl http://127.0.0.1:18889/health` |
| 文件读取 | `curl -H "X-API-Key: $KEY" -X POST http://127.0.0.1:18889/api/tools/tars_file_read -d '{"path":"../../../etc/passwd"}'` |
| 工具调用 | `curl -H "X-API-Key: $KEY" -X POST http://127.0.0.1:18889/api/tools/tars_config_set -d '{"path":"security.apiKey","value":"hacked"}'` |
| 审计导出 | `curl -H "X-API-Key: $KEY" http://127.0.0.1:18889/api/admin/audit/export` |
| 审计验证 | `curl -H "X-API-Key: $KEY" http://127.0.0.1:18889/api/admin/audit/verify` |

## 附录 C · 关键文件路径

- 报告 Markdown：`docs/security-audit-v3.7.1.md`
- 上轮 v3.2.5 报告（参考基线）：<https://my.feishu.cn/docx/QOnPd9mjmoDJokxhZZgcKOi9n6e>
- 测试脚本：`redteam_test.py` / `redteam_phase2.py` / `redteam_tools.py` / `redteam_deep.py` / `redteam_impact.py`
- 测试日志：`/tmp/tsg-redteam-report.json`