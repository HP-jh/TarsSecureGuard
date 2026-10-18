#!/usr/bin/env python3
"""Push v4.17.0 to GitHub via Git Data API."""
import base64, json, os, subprocess, urllib.request, concurrent.futures, sys

TOKEN = open("/home/gem/.aily/workspace/.github_token").read().strip()
REPO = "HP-jh/TarsSecureGuard"
API_BASE = "https://api.github.com"
LOCAL = "/home/gem/.aily/workspace/TSG"
PARENT_SHA = "6d9c66eb84c905a27573e07e4a59319c4bd180aa"  # remote main v4.16.0
BASE_TREE_SHA = "1ac77871701890716b7edf7b4d32b5ec9b558d9a"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "TSG-Push/4.17.0"
}

SKIP = {'.git', '.github', 'dist', 'smoke', 'logs', 'state', 'models',
        '.DS_Store', 'Thumbs.db', '.idea', '.vscode', '.preview',
        'tarssecureguard', 'tarssecureguard.exe', '*.exe', '*.test', '*.out',
        '*.gguf', '*.pid', '*.log', 'push_v*.py', 'SHA256SUMS*.txt'}
SKIP_EXTS = {'.exe', '.test', '.out', '.gguf', '.pid'}

def api_call(method, path, data=None, retries=3):
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url, method=method, headers=HEADERS)
    if data is not None:
        body = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
        req.data = body
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (502, 503) and attempt < retries - 1:
                import time
                time.sleep(2 ** attempt)
                continue
            print(f"API error {method} {path}: {e.code} {e.read().decode()}", file=sys.stderr)
            raise
        except Exception as e:
            if attempt < retries - 1:
                import time
                time.sleep(2 ** attempt)
                continue
            raise

def create_blob(path):
    with open(path, "rb") as f:
        content = f.read()
    # If binary, base64 encode; else utf-8
    try:
        text = content.decode('utf-8')
        data = {"content": text, "encoding": "utf-8"}
    except UnicodeDecodeError:
        data = {"content": base64.b64encode(content).decode(), "encoding": "base64"}
    resp = api_call("POST", f"/repos/{REPO}/git/blobs", data)
    return resp["sha"]

def should_skip(rel_path, name):
    if name in SKIP:
        return True
    if any(rel_path.startswith(p) for p in SKIP):
        return True
    _, ext = os.path.splitext(name)
    if ext.lower() in SKIP_EXTS:
        return True
    return False

def collect_files():
    files = []
    for root, dirs, names in os.walk(LOCAL):
        # prune skip dirs
        dirs[:] = [d for d in dirs if d not in SKIP and not d.startswith('.')]
        for name in names:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, LOCAL)
            if should_skip(rel, name):
                continue
            files.append((rel, full))
    return files

def create_tree_entries(files):
    blobs = {}
    def do_one(item):
        rel, full = item
        sha = create_blob(full)
        return rel, sha
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for rel, sha in ex.map(do_one, files):
            blobs[rel] = sha
    entries = []
    for rel, sha in blobs.items():
        mode = "100644"
        entries.append({"path": rel, "mode": mode, "type": "blob", "sha": sha})
    return entries

def push():
    files = collect_files()
    print(f"Files to push: {len(files)}")
    entries = create_tree_entries(files)
    print(f"Blobs created: {len(entries)}")

    tree = api_call("POST", f"/repos/{REPO}/git/trees", {
        "base_tree": BASE_TREE_SHA,
        "tree": entries
    })
    print(f"Tree SHA: {tree['sha']}")

    # Get local commit info for exact SHA reproduction
    commit_msg = subprocess.check_output(["git", "-C", LOCAL, "log", "-1", "--pretty=format:%B"]).decode()
    author_name = subprocess.check_output(["git", "-C", LOCAL, "log", "-1", "--pretty=format:%an"]).decode()
    author_email = subprocess.check_output(["git", "-C", LOCAL, "log", "-1", "--pretty=format:%ae"]).decode()
    author_date = subprocess.check_output(["git", "-C", LOCAL, "log", "-1", "--pretty=format:%aI"]).decode()
    committer_name = subprocess.check_output(["git", "-C", LOCAL, "log", "-1", "--pretty=format:%cn"]).decode()
    committer_email = subprocess.check_output(["git", "-C", LOCAL, "log", "-1", "--pretty=format:%ce"]).decode()
    committer_date = subprocess.check_output(["git", "-C", LOCAL, "log", "-1", "--pretty=format:%cI"]).decode()

    commit = api_call("POST", f"/repos/{REPO}/git/commits", {
        "message": commit_msg,
        "tree": tree["sha"],
        "parents": [PARENT_SHA],
        "author": {"name": author_name, "email": author_email, "date": author_date},
        "committer": {"name": committer_name, "email": committer_email, "date": committer_date}
    })
    print(f"Commit SHA: {commit['sha']}")

    api_call("PATCH", f"/repos/{REPO}/git/refs/heads/main", {"sha": commit["sha"]}
    )
    print("main updated.")

    # Tag
    tag_name = "v4.17.0"
    tag_obj = api_call("POST", f"/repos/{REPO}/git/tags", {
        "tag": tag_name,
        "message": tag_name,
        "object": commit["sha"],
        "type": "commit"
    })
    api_call("POST", f"/repos/{REPO}/git/refs", {
        "ref": f"refs/tags/{tag_name}",
        "sha": tag_obj["sha"]
    })
    print(f"Tag {tag_name} created.")

if __name__ == "__main__":
    push()
