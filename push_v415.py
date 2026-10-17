#!/usr/bin/env python3
"""Push v4.15.0 to GitHub via Git Data API."""
import base64, hashlib, json, os, sys, subprocess, urllib.request, urllib.error

TOKEN = open("/home/gem/.aily/workspace/.github_token").read().strip()
REPO = "HP-jh/TarsSecureGuard"
API_BASE = "https://api.github.com"
LOCAL = "/home/gem/.aily/workspace/TSG"
PARENT_SHA = "c38d76f5b93120fd26550650958df3591fe9f097"  # v4.14.0
BASE_TREE_SHA = "565125923e2c848ce741bab872951faeb80efc9d"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "TSG-Push/4.15.0"
}

SKIP = {
    '.git', '.github', 'dist', 'smoke', 'logs', 'state', 'models',
    '.DS_Store', 'Thumbs.db', '.idea', '.vscode', '.preview',
    'tarssecureguard', 'tarssecureguard.exe', '*.exe', '*.test', '*.out',
    '*.gguf', '*.pid', '*.log',
}
SKIP_EXTS = {'.exe', '.test', '.out', '.gguf', '.pid'}

def api_call(method, path, data=None):
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url, method=method, headers=HEADERS)
    if data is not None:
        req.data = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"HTTP {e.code}: {body[:500]}", file=sys.stderr)
        raise

def get_remote_tree(sha):
    """Recursively fetch tree entries."""
    entries = {}
    def fetch(tree_sha, prefix=""):
        r = api_call("GET", f"/repos/{REPO}/git/trees/{tree_sha}?recursive=1")
        for e in r.get("tree", []):
            path = prefix + e["path"] if prefix else e["path"]
            if e["type"] == "blob":
                entries[path] = e["sha"]
    fetch(sha)
    return entries

def git_hash_object(path):
    """Compute git blob sha for a file."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except (IOError, OSError):
        return None
    header = f"blob {len(data)}\0".encode()
    h = hashlib.sha1(header + data).hexdigest()
    return h

def should_skip(rel_path):
    parts = rel_path.split('/')
    for p in parts:
        if p in SKIP or p.startswith('.'):
            return True
    if any(rel_path.endswith(ext) for ext in SKIP_EXTS):
        return True
    name = os.path.basename(rel_path)
    if name.startswith('tsg-v4.') or name.startswith('tarssecureguard'):
        return True
    return False

def main():
    print("[1/5] Fetching remote v4.14.0 tree...")
    remote = get_remote_tree(BASE_TREE_SHA)
    print(f"  Remote files: {len(remote)}")

    print("[2/5] Scanning local workspace...")
    changed = []
    for root, dirs, files in os.walk(LOCAL):
        # prune skip dirs
        dirs[:] = [d for d in dirs if d not in SKIP and not d.startswith('.')]
        for f in files:
            local_path = os.path.join(root, f)
            rel = os.path.relpath(local_path, LOCAL)
            if should_skip(rel):
                continue
            local_sha = git_hash_object(local_path)
            remote_sha = remote.get(rel)
            if local_sha != remote_sha:
                changed.append(rel)

    print(f"  Changed/new files: {len(changed)}")
    for c in changed[:20]:
        print(f"    {c}")
    if len(changed) > 20:
        print(f"    ... and {len(changed)-20} more")

    if not changed:
        print("No changes detected!")
        return

    print("[3/5] Creating blobs...")
    entries = []
    for rel in changed:
        local_path = os.path.join(LOCAL, rel)
        with open(local_path, "rb") as f:
            data = f.read()
        try:
            text = data.decode("utf-8")
            blob_sha = api_call("POST", f"/repos/{REPO}/git/blobs", {"content": text, "encoding": "utf-8"})["sha"]
        except UnicodeDecodeError:
            blob_sha = api_call("POST", f"/repos/{REPO}/git/blobs", {"content": base64.b64encode(data).decode("ascii"), "encoding": "base64"})["sha"]
        entries.append({"path": rel, "mode": "100644", "type": "blob", "sha": blob_sha})

    print("[4/5] Creating tree + commit...")
    tree_sha = api_call("POST", f"/repos/{REPO}/git/trees", {"base_tree": BASE_TREE_SHA, "tree": entries})["sha"]
    commit_sha = api_call("POST", f"/repos/{REPO}/git/commits", {
        "message": "v4.15.0: Interaction + Documentation + UI\n\n- Interaction: loading skeletons 3-tier, button ripple, route fade+slide, toast stack, shortcuts (/ ?), confirmation modals, progress bars\n- Documentation: 11 docs (architecture, api-reference, configuration, deployment, mcp-integration, security, auto-update, enterprise-interop, performance-tuning, faq, troubleshooting)\n- UI: visual polish, responsive, empty states, error messages",
        "tree": tree_sha,
        "parents": [PARENT_SHA]
    })["sha"]
    print(f"  Commit: {commit_sha}")

    print("[5/5] Updating refs...")
    api_call("PATCH", f"/repos/{REPO}/git/refs/heads/main", {"sha": commit_sha})
    api_call("POST", f"/repos/{REPO}/git/refs", {"ref": "refs/tags/v4.15.0", "sha": commit_sha})
    print("  main & tag v4.15.0 updated")

if __name__ == "__main__":
    main()
