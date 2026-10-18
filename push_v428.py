#!/usr/bin/env python3
"""GitHub API 树重建推送 v4.28.0"""
import base64, json, os, sys, urllib.request

TOKEN = open(os.path.expanduser("~/.aily/workspace/.github_token")).read().strip()
REPO = "HP-jh/TarsSecureGuard"
BASE_SHA = "4b95412e4253fb785e37f5baf3f1b781f6860a44"
BASE_TREE = "7654a2ae54863407b7f51231e3b1980ea039c7f6"

def api(path, data=None, method=None):
    url = f"https://api.github.com/repos/{REPO}{path}"
    req = urllib.request.Request(url, method=method or ("POST" if data else "GET"))
    req.add_header("Authorization", f"token {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    if data:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTP {e.code}: {body}", file=sys.stderr)
        raise

def mk_blob(path):
    with open(path, "rb") as f:
        content = f.read()
    r = api("/git/blobs", {"content": base64.b64encode(content).decode(), "encoding": "base64"})
    return r["sha"]

os.chdir(os.path.expanduser("~/.aily/workspace/TSG"))

# 创建 blobs
blobs = {
    "fingerprint.go": mk_blob("fingerprint.go"),
    "fingerprint_test.go": mk_blob("fingerprint_test.go"),
    "config.go": mk_blob("config.go"),
    "main.go": mk_blob("main.go"),
    "oauth.go": mk_blob("oauth.go"),
    "CHANGES.md": mk_blob("CHANGES.md"),
    "v325_test.go": mk_blob("v325_test.go"),
    "v321_test.go": mk_blob("v321_test.go"),
    "v371_test.go": mk_blob("v371_test.go"),
    "v380_test.go": mk_blob("v380_test.go"),
    "v390_test.go": mk_blob("v390_test.go"),
    "v464_test.go": mk_blob("v464_test.go"),
    "v465_test.go": mk_blob("v465_test.go"),
    "v466_test.go": mk_blob("v466_test.go"),
    "v471_test.go": mk_blob("v471_test.go"),
    "v472_test.go": mk_blob("v472_test.go"),
    "v473_test.go": mk_blob("v473_test.go"),
    "crownext/security/engine.go": mk_blob("crownext/security/engine.go"),
    "crownext/security/security_test.go": mk_blob("crownext/security/security_test.go"),
    "SHA256SUMS-v4.28.0.txt": mk_blob("SHA256SUMS-v4.28.0.txt"),
}

# 创建新 tree（基于远端 tree，替换/新增/删除文件）
tree_entries = [
    {"path": "fingerprint.go", "mode": "100644", "type": "blob", "sha": blobs["fingerprint.go"]},
    {"path": "fingerprint_test.go", "mode": "100644", "type": "blob", "sha": blobs["fingerprint_test.go"]},
    {"path": "config.go", "mode": "100644", "type": "blob", "sha": blobs["config.go"]},
    {"path": "main.go", "mode": "100644", "type": "blob", "sha": blobs["main.go"]},
    {"path": "oauth.go", "mode": "100644", "type": "blob", "sha": blobs["oauth.go"]},
    {"path": "CHANGES.md", "mode": "100644", "type": "blob", "sha": blobs["CHANGES.md"]},
    {"path": "v325_test.go", "mode": "100644", "type": "blob", "sha": blobs["v325_test.go"]},
    {"path": "v321_test.go", "mode": "100644", "type": "blob", "sha": blobs["v321_test.go"]},
    {"path": "v371_test.go", "mode": "100644", "type": "blob", "sha": blobs["v371_test.go"]},
    {"path": "v380_test.go", "mode": "100644", "type": "blob", "sha": blobs["v380_test.go"]},
    {"path": "v390_test.go", "mode": "100644", "type": "blob", "sha": blobs["v390_test.go"]},
    {"path": "v464_test.go", "mode": "100644", "type": "blob", "sha": blobs["v464_test.go"]},
    {"path": "v465_test.go", "mode": "100644", "type": "blob", "sha": blobs["v465_test.go"]},
    {"path": "v466_test.go", "mode": "100644", "type": "blob", "sha": blobs["v466_test.go"]},
    {"path": "v471_test.go", "mode": "100644", "type": "blob", "sha": blobs["v471_test.go"]},
    {"path": "v472_test.go", "mode": "100644", "type": "blob", "sha": blobs["v472_test.go"]},
    {"path": "v473_test.go", "mode": "100644", "type": "blob", "sha": blobs["v473_test.go"]},
    {"path": "crownext/security/engine.go", "mode": "100644", "type": "blob", "sha": blobs["crownext/security/engine.go"]},
    {"path": "crownext/security/security_test.go", "mode": "100644", "type": "blob", "sha": blobs["crownext/security/security_test.go"]},
    {"path": "SHA256SUMS-v4.28.0.txt", "mode": "100644", "type": "blob", "sha": blobs["SHA256SUMS-v4.28.0.txt"]},
    {"path": "push_v425.py", "mode": "100644", "type": "blob", "sha": None},  # delete
]

tree = api("/git/trees", {"base_tree": BASE_TREE, "tree": tree_entries})
print("tree sha:", tree["sha"])

# 创建 commit
commit = api("/git/commits", {
    "message": "feat: 请求指纹识别，防设备伪造 (v4.28.0)\n\n"
               "- fingerprint.go: 请求指纹识别核心（UA/AL/AE/AC + 前端维度）\n"
               "- fingerprint.go: 指纹评分体系（满分100，阶梯式处置）\n"
               "- fingerprint.go: Hash 快速路径 + 渐进式更新 + 30天过期清理\n"
               "- main.go: fingerprintMiddleware 插入 gatewayMiddleware 外层\n"
               "- main.go: /api/fingerprint/report|status|challenge 端点\n"
               "- oauth.go: 会话注销同步清除指纹绑定\n"
               "- config.go: security.fingerprint 配置段\n"
               "- fingerprint_test.go: 15 项测试覆盖\n"
               "- crownext/security: 版本号同步 4.28.0\n"
               "- main.go: version 4.25.0 -> 4.28.0\n"
               "- CHANGES.md: v4.28.0 条目",
    "parents": [BASE_SHA],
    "tree": tree["sha"],
})
print("commit sha:", commit["sha"])

# 更新 main ref
ref = api("/git/refs/heads/main", {"sha": commit["sha"]}, method="PATCH")
print("ref updated:", ref["ref"])
print("DONE")
