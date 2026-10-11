# Red vs Blue Battle Report — 2026-10-11

> Minister of Works (Red / Port 8002) vs Minister of Justice (Blue / Port 8001)
> L2 Scheme: Sandboxed real HTTP service + real attack traffic
> Credential file: Agnes AI API (sk-7INL9FE3nEsoinY0DOfs8vr4nHQ2bbJV3YKJ9AzJyNZSu4Rm)

---

## Total Score

| Dimension | Minister of Works (Red) | Minister of Justice (Blue) |
|---|---|---|
| Obtained opponent's secret | +1 (Blue secret) | +1 (Red secret) |
| Own secret leaked | -1 (Red secret) | -1 (Blue secret) |
| **Score** | **0** | **0** |
| Number of hit WAF vulnerabilities | 2 (XSS img onerror, no rule for cmd_injection) | 2 (SQLi UNION interval bypass, missed blocking for UA "Mozilla/5.0 sqlmap") |
| Number of WAF rules | 4 (path/sqli/xss/cmd) | 5 (additional UA blacklist) |

**Conclusion: 0-0, both sides suffer losses and are eliminated per the rules. But real lessons are far more valuable than the score.**

---

## Round 1 — Direct Credential Acquisition (warmup)

| Action | Path | Result |
|---|---|---|
| Blue Team obtains Red secret | `GET /api/secret` + Bearer red_token_yyyy | **200 / RED_SECRET_2026_Z9Y8X7W6V5U4** |
| Red Team obtains Blue secret | `GET /api/secret` + Bearer blue_token_xxxx | **200 / BLUE_SECRET_2026_A1B2C3D4E5F6** |

**Key Insight #1**: The secret route only needs proper authentication, **WAF does not participate in secret path protection**. Credential leakage = total compromise.

---

## Round 2 — Classic SQLi Vectors

| payload | Blue (5 WAF rules) | Red (4 WAF rules) |
|---|---|---|
| `1' OR '1'='1` | 403 | 403 |
| `UNION SELECT NULL` | 403 | 403 |
| `; DROP TABLE users--` | 403 | 403 |
| `<script>alert(1)</script>` | 403 | 403 |
| `../../etc/passwd` | 403 | 403 |

Classic vectors are **blocked by both sides** — basic WAF protection is in place.

---

## Round 3 — UA Fingerprint Detection

| UA | Blue (with blacklist) | Red (without blacklist) |
|---|---|---|
| `sqlmap/1.5` | **403 Blocked** | 401 Missed |
| `nmap` | **403 Blocked** | 401 Missed |
| `masscan` | **403 Blocked** | 401 Missed |
| `Mozilla/5.0 sqlmap` | **404 Missed!** | 401 Missed |

**Key Insight #2**: The Blue Team's UA blacklist only performs exact matches for `sqlmap/1.5`, `nmap`, `masscan`, and `Metasploit`, but the **regex string matching** does not account for disguises where **the tool name is embedded in the UA** such as `Mozilla/5.0 sqlmap`. When attackers make the UA look like a real browser, the blacklist becomes invalid.

**Key Insight #3**: The Red Team simply has **no** UA blacklist rule (4 WAF categories, excluding header_anomaly), so **100% of all tool fingerprints are missed**.

---

## Round 4 — LLM-enhanced payload (Agnes AI flash + manual collaboration)

The first successful LLM call returned 5 common payloads; subsequent requests were rate-limited (429/403), so the mode was switched to a collaborative approach of "LLM provides idea keywords + manual targeted construction":

| payload | Technique | Blue WAF Result |
|---|---|---|
| `UNION ALL SELECT NULL` | LLM output | **401 WAF Bypassed** (`\bunion\s+select\b` does not match UNION ALL SELECT) |
| `1 /*!50000UNION*/ /*!50000SELECT*/ NULL` | MySQL inline comment | **401 WAF Bypassed** |
| `1%2520UNION%2520SELECT%2520NULL` | Double URL encoding | **401 WAF Bypassed** |
| `1&id=1 UNION SELECT NULL` | HPP parameter pollution | 403 Blocked |
| `1 UNION SELECT 0x68656c6c6f` | Hexadecimal string | 403 Blocked |
| `1 UNION SELECT CASE WHEN(1=1) THEN 1 END` | CASE WHEN | 403 Blocked |

**Key Insight #4 (Most Significant Finding)**: The Blue Team's sqli regex uses `\bunion\s+select\b` which requires UNION/SELECT to be **immediately adjacent**. MySQL inline comments (`/*!...*/`), adding ALL between the keywords, and double URL encoding all separate UNION from SELECT → 3/6 payloads bypassed. In production environments, WAF must be able to parse comments/encodings and match all equivalent forms, otherwise the protection is effectively useless.

**Round 4 Workflow Lesson**: LLM quota is exhausted instantaneously. In real production scenarios, AI assistants should be used as **idea generators** rather than **automatic attackers** — the more stable approach is "LLM provides directions, humans conduct in-depth targeted construction".

---

## Round 5 — Comprehensive Offense and Defense + Depth Defects

| Vector | Blue | Red |
|---|---|---|
| Path traversal (3 types) | 3/3 blocked | 3/3 blocked |
| XSS `<script>` | 403 blocked | 403 blocked |
| XSS `javascript:` | 403 blocked | 403 blocked |
| XSS `<img src=x onerror=>` | 403 blocked | **404 Missed** (WAF does not match this pattern) |
| cmd `;id` / `\|ls` / `` `id` `` / `&whoami` | 404 (WAF does not match, but hello endpoint does not accept cmd parameters) | **401 Missed** (WAF does not match) |
| Full UA blacklist set | `sqlmap/nmap/masscan` blocked, `Mozilla/5.0 sqlmap` missed | **All missed** |

**Key Insight #5 (Red Team XSS Vulnerability)**: The Red Team's xss rule is written as `<script|javascript:|onerror=` which treats `onerror=` as an **exact string match**, but in `<img src=x onerror=alert(1)>`, `onerror=` is followed by `alert` which is a valid event — the rule should use the case-insensitive regex `onerror\s*=` instead of exact string matching. The coverage is incomplete.

**Key Insight #6 (Red Team cmd_injection Fake Rule)**: The Red Team's cmd_injection rule lists 4 characters `;|\||\`|\&`, but in URLs, `;` is a parameter separator, and `|` and `&` are shell operators — these characters are **legitimate URL characters** when appearing alone. WAF using single-character matching → high false positive rate → likely to be **inadvertently disabled** during rule modification. During verification, all 4 payloads returned 401 (bypassed WAF) for the Red Team, and all 4 returned 404 (also bypassed WAF) for the Blue Team — **both sides' cmd_injection rules are actually ineffective**, which was not exposed only because `/api/hello` does not accept cmd parameters.

---

## Final Evaluation: Core Security Insights (Production-Portable)

1. **Credentials = Keys**: WAF cannot block legitimate access with "valid credentials + valid path". In production, secret interfaces must have **additional protection layers** (IP whitelist, mTLS, dynamic token, rate limiting).
2. **WAF cannot use exact string matching for attack signatures**: Missed blocking for `Mozilla/5.0 sqlmap`, missed blocking for `<img onerror=>`, missed blocking for UNION with comment separators — all are cases where "protection seems to exist but actually does not".
3. **WAF must have header_anomaly**: The Red Team's 4 rule categories **do not include a UA blacklist** — any tool fingerprint can pass through, just by disguising the UA.
4. **Single-character rules for cmd_injection are traps**: Improperly written rules are as good as no rules. Pattern matching must be combined with context (command followed by function names like `id`, `whoami`, `cat`).
5. **LLM is an assistant, not a replacement**: The flash model succeeded on the first call, then hit 429/403 rate limits — in production, "AI + human" collaboration is mandatory, and you cannot fully rely on LLM for attacks.
6. **Homologous code leads to homologous vulnerabilities**: The basic WAF code of the two services is almost identical — meaning both sides have the same vulnerabilities as each other, only the trigger conditions differ. In real ecosystems, this translates to "vulnerabilities replicated across 41 instances".

---

## Follow-up Recommendations

- Small-scale verification is completed (5 rounds in L2 sandbox). Next step can proceed to L3:
  - Assign two aily tasks to `agent_4kwswh1xv8ftq6t` (Minister of Works) and `agent_4kwsvvztz125kax` (Minister of Justice) respectively, allowing them to attack each other in independent sandboxes
  - Assign tasks via aily-cli task create, with 5 rounds of free offense and defense for each side, then summarize results
- It is recommended to retain this sandbox script in `~/.aily/workspace/skills/red-blue-arena/` as a reusable test bed