# 红蓝对抗战报 — 2026-10-11

> 工部尚书（红 / 端口 8002）vs 刑部尚书（蓝 / 端口 8001）
> L2 方案：沙箱真实 HTTP 服务 + 真实攻击流量
> 凭证文件：Agnes AI API (sk-7INL9FE3nEsoinY0DOfs8vr4nHQ2bbJV3YKJ9AzJyNZSu4Rm)

---

## 总分

| 维度 | 工部尚书（红） | 刑部尚书（蓝） |
|---|---|---|
| 拿到对方 secret | +1（蓝 secret） | +1（红 secret） |
| 自身 secret 泄露 | -1（红 secret） | -1（蓝 secret） |
| **得分** | **0** | **0** |
| WAF 漏洞被命中数 | 2（XSS img onerror、cmd_injection 无规则） | 2（SQLi UNION 间隔绕过、UA "Mozilla/5.0 sqlmap" 漏拦） |
| WAF 规则数 | 4（path/sqli/xss/cmd） | 5（多 UA 黑名单） |

**结论：0-0 两败俱伤，按规则双双淘汰。但真实教训比比分珍贵得多。**

---

## Round 1 — 凭证直取（warmup）

| 行为 | 路径 | 结果 |
|---|---|---|
| 蓝队拿红 secret | `GET /api/secret` + Bearer red_token_yyyy | **200 / RED_SECRET_2026_Z9Y8X7W6V5U4** |
| 红队拿蓝 secret | `GET /api/secret` + Bearer blue_token_xxxx | **200 / BLUE_SECRET_2026_A1B2C3D4E5F6** |

**核心洞见 #1**：secret 路由只要鉴权就对，**WAF 不参与 secret 路径保护**。凭证泄露 = 全失守。

---

## Round 2 — 经典 SQLi 向量

| payload | 蓝 (5 WAF) | 红 (4 WAF) |
|---|---|---|
| `1' OR '1'='1` | 403 | 403 |
| `UNION SELECT NULL` | 403 | 403 |
| `; DROP TABLE users--` | 403 | 403 |
| `<script>alert(1)</script>` | 403 | 403 |
| `../../etc/passwd` | 403 | 403 |

经典向量**两边都拦**——WAF 基础防护到位。

---

## Round 3 — UA 指纹探测

| UA | 蓝 (有黑名单) | 红 (无黑名单) |
|---|---|---|
| `sqlmap/1.5` | **403 拦** | 401 漏 |
| `nmap` | **403 拦** | 401 漏 |
| `masscan` | **403 拦** | 401 漏 |
| `Mozilla/5.0 sqlmap` | **404 漏！** | 401 漏 |

**核心洞见 #2**：蓝队 UA 黑名单只精确匹配 `sqlmap/1.5` `nmap` `masscan` `Metasploit`，但**正则字符串匹配**没考虑 `Mozilla/5.0 sqlmap` 这种**UA 内含工具名**的伪装。攻击者把 UA 写得像真浏览器，黑名单失效。

**核心洞见 #3**：红队干脆**没有** UA 黑名单规则（4 WAF 类，不含 header_anomaly），所有工具指纹**100% 漏拦**。

---

## Round 4 — LLM 增强 payload（Agnes AI flash + 手工协同）

LLM 第一次成功调用拿到 5 个普通 payload；后续限流（429/403），改为"LLM 出思路关键词 + 人工针对性构造"协同模式：

| payload | 技巧 | 蓝 WAF 结果 |
|---|---|---|
| `UNION ALL SELECT NULL` | LLM 输出 | **401 绕 WAF**（\bunion\s+select\b 不匹配 UNION ALL SELECT） |
| `1 /*!50000UNION*/ /*!50000SELECT*/ NULL` | MySQL 内联注释 | **401 绕 WAF** |
| `1%2520UNION%2520SELECT%2520NULL` | 双重 URL 编码 | **401 绕 WAF** |
| `1&id=1 UNION SELECT NULL` | HPP 参数污染 | 403 拦 |
| `1 UNION SELECT 0x68656c6c6f` | 16 进制字符串 | 403 拦 |
| `1 UNION SELECT CASE WHEN(1=1) THEN 1 END` | CASE WHEN | 403 拦 |

**核心洞见 #4（最大发现）**：蓝队 sqli 正则用 `\bunion\s+select\b` 强制要求 UNION/SELECT **紧邻**。MySQL 内联注释（`/*!...*/`）、双 ALL、双重 URL 编码三种都能让 UNION 与 SELECT 隔开 → 3/6 绕过。生产里 WAF 必须能解析注释/编码、匹配所有等价形式，否则等于没拦。

**Round 4 工作流教训**：LLM 配额瞬时耗尽，生产现实里 AI 助手当**思路生成器**而非**自动攻击器**——更稳的是"LLM 给方向、人工针对深度构造"。

---

## Round 5 — 综合攻防 + 纵深缺陷

| 向量 | 蓝 | 红 |
|---|---|---|
| 路径穿越（3 种） | 3/3 拦 | 3/3 拦 |
| XSS `<script>` | 403 拦 | 403 拦 |
| XSS `javascript:` | 403 拦 | 403 拦 |
| XSS `<img src=x onerror=>` | 403 拦 | **404 漏**（WAF 未匹配） |
| cmd `;id` / `\|ls` / `` `id` `` / `&whoami` | 404（WAF 未匹配，但 hello 不接 cmd） | **401 漏**（WAF 未匹配） |
| UA 黑名单全套 | `sqlmap/nmap/masscan` 拦，`Mozilla/5.0 sqlmap` 漏 | **全部漏** |

**核心洞见 #5（红队 XSS 漏洞）**：红队 xss 规则用 `<script|javascript:|onerror=` 写时把 `onerror=` 当**严格字符串**匹配，但 `<img src=x onerror=alert(1)>` 里 onerror= 后接的是 `alert` 不是合法事件——应该用正则 `onerror\s*=` 不区分大小写而非精确串匹配。覆盖不全。

**核心洞见 #6（红队 cmd_injection 假规则）**：红队 cmd_injection 规则列为 `;|\||\`|\&` 4 字符，但在 URL 里 `;` 是参数分隔符，`|` `&` 是 shell 操作符——这些字符单独出现**就是合法 URL 字符**。WAF 用单字符匹配 → 误报率高 → 可能被规则改写时**无意中失效**。验证中 4 个 payload 全 401（绕 WAF），蓝队同样 4 个全 404（同样绕 WAF）——**两边 cmd_injection 实际都无效**，只是因为 `/api/hello` 不接 cmd 参数而没有体现。

---

## 终评：核心安全洞见（生产可移植）

1. **凭证 = 钥匙**：WAF 拦不住"合法凭证 + 合法路径"的合法访问。生产里 secret 接口必须**额外加层**（IP 白名单、mTLS、动态 token、限频）。
2. **WAF 不能用精确字串匹配攻击特征**：`Mozilla/5.0 sqlmap` 漏拦、`<img onerror=>` 漏拦、UNION 注释间隔漏拦 —— 全是"看似拦了实际没拦"。
3. **WAF 必须有 header_anomaly**：红队 4 类规则**没有 UA 黑名单**——任何工具指纹都能进，伪装 UA 即可。
4. **cmd_injection 单字符规则是陷阱**：写错等于没写。需配合上下文（命令后跟函数名 `id` `whoami` `cat`）做模式匹配。
5. **LLM 是助手不是替代**：flash 模型首次成功、后续 429/403 限流——生产里必须"AI + 人工"协同，不能完全依赖 LLM 攻击。
6. **同源代码同源漏洞**：两个服务基础 WAF 代码长得几乎一样——意味着两边都有对方同样的漏，只是触发条件不同。这在真实生态里就是"复制 41 处漏洞"。

---

## 后续建议

- 小规模验证已完成（L2 沙箱 5 回合）。下一步可走 L3：
  - 真派 `agent_4kwswh1xv8ftq6t` (工部尚书) 和 `agent_4kwsvvztz125kax` (刑部尚书) 两个 aily task，让他们在独立沙箱里互打
  - 用 aily-cli task create 派单，每方 5 轮自由攻防，最后汇总
- 建议保留这次沙箱脚本到 `~/.aily/workspace/skills/red-blue-arena/` 作为可复用测试床