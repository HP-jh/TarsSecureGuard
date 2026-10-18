#!/usr/bin/env python3
"""GitHub API 树重建推送 v4.25.0"""
import base64, json, os, sys, urllib.request

TOKEN = open(os.path.expanduser("~/.aily/workspace/.github_token")).read().strip()
REPO = "HP-jh/TarsSecureGuard"
BASE_SHA = "242f57fbd708ecc85a4de19083925d9c9ddd89dd"
BASE_TREE = "054c791c0cd67dd3bf62de9481ce178b8bde2bde"

def api(path, data=None, method=None):
    url = f"https://api.github.com/repos/{REPO}{path}"
    req = urllib.request.Request(url, method=method or ("POST" if data else "GET"))
    req.add_header("Authorization", f"token {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    if data:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode()
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())

def mk_blob(path):
    with open(path, "rb") as f:
        content = f.read()
    r = api("/git/blobs", {"content": base64.b64encode(content).decode(), "encoding": "base64"})
    return r["sha"]

os.chdir(os.path.expanduser("~/.aily/workspace/TSG"))

# 创建 blobs
changes_sha = mk_blob("CHANGES.md")
main_sha = mk_blob("main.go")
pool_sha = mk_blob("pool.go")
v325_sha = mk_blob("v325_test.go")
sha256_sha = mk_blob("SHA256SUMS-v4.25.0.txt")

# 创建新 tree（基于远端 tree，替换/新增/删除文件）
tree_entries = [
    {"path": "CHANGES.md", "mode": "100644", "type": "blob", "sha": changes_sha},
    {"path": "main.go", "mode": "100644", "type": "blob", "sha": main_sha},
    {"path": "pool.go", "mode": "100644", "type": "blob", "sha": pool_sha},
    {"path": "v325_test.go", "mode": "100644", "type": "blob", "sha": v325_sha},
    {"path": "SHA256SUMS-v4.25.0.txt", "mode": "100644", "type": "blob", "sha": sha256_sha},
    {"path": "push_v415.py", "mode": "100644", "type": "blob", "sha": None},  # delete
    {"path": "push_v4151.py", "mode": "100644", "type": "blob", "sha": None},
    {"path": "push_v4170.py", "mode": "100644", "type": "blob", "sha": None},
]

tree = api("/git/trees", {"base_tree": BASE_TREE, "tree": tree_entries})
print("tree sha:", tree["sha"])

# 创建 commit
commit = api("/git/commits", {
    "message": "v4.25.0 连接池自适应扩缩容 · QPS 驱动 · 5~200 区间\n\n"
               "- pool.go: QPS 监控 + 自适应扩缩容循环（每5秒评估）\n"
               "- pool.go: 扩容阈值 1.2x（激进），缩容阈值 0.5x（保守防抖动）\n"
               "- pool.go: poolStats 新增 adaptiveEnabled / adaptiveRange / 实时 maxIdlePerHost\n"
               "- v325_test.go: 6 项测试（映射/扩容/缩容/开关/字段/版本锁）\n"
               "- main.go: version 4.20.0 -> 4.25.0\n"
               "- CHANGES.md: v4.25.0 条目",
    "parents": [BASE_SHA],
    "tree": tree["sha"],
})
print("commit sha:", commit["sha"])

# 更新 main ref
ref = api("/git/refs/heads/main", {"sha": commit["sha"]}, method="PATCH")
print("ref updated:", ref["ref"])
print("DONE")
