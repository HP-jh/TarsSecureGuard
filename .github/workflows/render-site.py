#!/usr/bin/env python3
"""Render site templates with latest release data from GitHub API."""
import argparse, json, os, re, shutil, sys, urllib.request

GITHUB_API = "https://api.github.com/repos/HP-jh/TarsSecureGuard"

def api_get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())

def human_size(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def build_assets_table(release):
    rows = []
    rows.append("<table>")
    rows.append("<tr><th>平台</th><th>文件名</th><th>大小</th><th>下载</th></tr>")
    for asset in release.get("assets", []):
        name = asset["name"]
        if name == "SHA256SUMS.txt":
            continue
        # parse platform from filename like tsg-v4.7.8-linux-amd64
        m = re.search(r'tsg-v[\d.]+-(.+?)(?:\.exe)?$', name)
        platform = m.group(1).replace('-', ' ') if m else name
        size = human_size(asset["size"])
        url = asset["browser_download_url"]
        rows.append(f'<tr><td>{platform}</td><td>{name}</td><td>{size}</td><td><a class="btn" href="{url}" rel="noopener" download>下载</a></td></tr>')
    rows.append("</table>")
    return "\n".join(rows)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="site")
    parser.add_argument("--output", default="_site")
    parser.add_argument("--version", default="")
    parser.add_argument("--date", default="")
    parser.add_argument("--notes", default="")
    parser.add_argument("--sha256sums", default="")
    parser.add_argument("--release-json", default="")
    args = parser.parse_args()

    release = None
    if args.release_json:
        release = json.load(open(args.release_json))
    else:
        release = api_get(f"{GITHUB_API}/releases/latest")

    version = args.version or release["tag_name"].lstrip("v")
    date = args.date or release["published_at"][:10]
    notes = args.notes or (release.get("body") or "").strip()
    if not notes:
        notes = f"Release {release['tag_name']}"

    # Fetch SHA256SUMS content
    checksums = ""
    for asset in release.get("assets", []):
        if asset["name"] == "SHA256SUMS.txt":
            req = urllib.request.Request(asset["browser_download_url"])
            with urllib.request.urlopen(req, timeout=30) as resp:
                checksums = resp.read().decode("utf-8", errors="replace").strip()
            break
    if args.sha256sums:
        checksums = open(args.sha256sums).read().strip()

    assets_table = build_assets_table(release)

    # Render templates
    if os.path.exists(args.output):
        shutil.rmtree(args.output)
    os.makedirs(args.output, exist_ok=True)

    for root, dirs, files in os.walk(args.input):
        rel = os.path.relpath(root, args.input)
        out_dir = os.path.join(args.output, rel)
        os.makedirs(out_dir, exist_ok=True)
        for fname in files:
            src = os.path.join(root, fname)
            dst = os.path.join(out_dir, fname)
            with open(src, "r", encoding="utf-8") as f:
                content = f.read()
            content = content.replace("{{VERSION}}", version)
            content = content.replace("{{RELEASE_DATE}}", date)
            content = content.replace("{{RELEASE_NOTES}}", notes)
            content = content.replace("{{ASSETS_TABLE}}", assets_table)
            content = content.replace("{{CHECKSUMS}}", checksums)
            with open(dst, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Rendered {dst}")

    print(f"Done. Version={version} Date={date}")

if __name__ == "__main__":
    main()
