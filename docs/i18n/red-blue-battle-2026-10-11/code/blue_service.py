#!/usr/bin/env python3
"""
蓝方 service — 刑部尚书保护
监听 127.0.0.1:8001
secret: BLUE_C68213C2FA02034C
token: bt_4e0eeb69
"""
import http.server
import json
import re
import time
import urllib.parse
from collections import defaultdict

BLUE_SECRET = "BLUE_C68213C2FA02034C"
BLUE_TOKEN = "bt_4e0eeb69"
PORT = 8001
HOST = "127.0.0.1"

# WAF 规则
WAF_PATTERNS = {
    "path_traversal": [
        r"\.\./", r"\.\.\\", r"/etc/", r"c:\\", r"/proc/",
        r"\\x[0-9a-f]{2}", r"%2e%2e%2f", r"%c0%ae",
    ],
    "sqli": [
        r"\bunion\s+select\b", r"\bor\s+1\s*=\s*1\b", r"\band\s+1\s*=\s*1\b",
        r"\bdrop\s+table\b", r"\binsert\s+into\b", r"\bdelete\s+from\b",
        r"\bsleep\s*\(", r"\bbenchmark\s*\(", r"\bload_file\s*\b",
        r"'\s*or\s*'", r'"\s*or\s*"', r"--\s*$", r";\s*drop",
    ],
    "xss": [
        r"<\s*script", r"<\s*img\s+[^>]*onerror", r"<\s*svg\s+[^>]*onload",
        r"javascript\s*:", r"\beval\s*\(", r"\bdocument\.cookie\b",
        r"alert\s*\(", r"\bon\w+\s*=",
    ],
    "cmd_injection": [
        r";\s*cat\s+", r"\|\s*cat\s+", r"&&\s*cat\s+", r"`cat\s+",
        r"\$\(.+?\)", r";\s*ls\b", r"\|\s*nc\s+", r"\bsh\s+-i",
        r"curl\s+http", r"wget\s+http",
    ],
    "header_anomaly": [
        r"X-Forwarded-For:\s*<", r"X-Real-IP:\s*'", r"User-Agent:\s*sqlmap",
        r"User-Agent:\s*nmap", r"User-Agent:\s*masscan", r"User-Agent:\s*metasploit",
        r"User-Agent:\s*nikto", r"User-Agent:\s*burp", r"User-Agent:\s*zaproxy",
    ],
}

REQUEST_LOG = []
RATE_LIMIT = defaultdict(list)  # IP -> [timestamps]

def waf_check(method, path, headers, body):
    """WAF 检测 — 返回 (blocked, reason)"""
    full = f"{path} {urllib.parse.unquote(path)} {' '.join(f'{k}:{v}' for k,v in headers.items())} {body or ''}"

    for category, pats in WAF_PATTERNS.items():
        for pat in pats:
            if re.search(pat, full, re.IGNORECASE | re.MULTILINE):
                return True, f"{category} matched: {pat}"

    # Rate limit: 30 req/s per IP
    ip = headers.get("X-Real-IP", headers.get("X-Forwarded-For", "unknown")).split(",")[0].strip()
    now = time.time()
    RATE_LIMIT[ip] = [t for t in RATE_LIMIT[ip] if now - t < 1.0]
    if len(RATE_LIMIT[ip]) >= 30:
        return True, f"rate_limit exceeded ({len(RATE_LIMIT[ip])}/s)"
    RATE_LIMIT[ip].append(now)

    return False, None

class BlueHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # 静默 stderr 输出

    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self):
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {BLUE_TOKEN}"

    def _log(self, method, path, status, blocked=None):
        REQUEST_LOG.append({
            "time": time.time(),
            "method": method,
            "path": path,
            "ip": self.client_address[0],
            "ua": self.headers.get("User-Agent", ""),
            "status": status,
            "blocked_by": blocked,
        })

    def _common(self, method):
        # 读 body
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "ignore") if length else ""

        blocked, reason = waf_check(method, self.path, self.headers, body)
        if blocked:
            self._log(method, self.path, 403, blocked)
            self._send(403, json.dumps({"error": "blocked_by_waf", "reason": reason}).encode())
            return

        # 健康检查 / banner
        if self.path == "/health":
            self._log(method, self.path, 200)
            self._send(200, json.dumps({"status": "ok", "service": "blue", "waf": "enabled"}).encode())
            return

        if self.path == "/" or self.path == "/index":
            self._log(method, self.path, 200)
            self._send(200, b"<h1>Blue Service</h1><p>Try /api/hello (Bearer token required)</p>", "text/html")
            return

        # 受保护 endpoint
        if self.path.startswith("/api/"):
            if not self._check_auth():
                self._log(method, self.path, 401)
                self._send(401, json.dumps({"error": "unauthorized"}).encode())
                return
            if self.path == "/api/hello":
                self._log(method, self.path, 200)
                self._send(200, json.dumps({"msg": "hello from blue", "you_are": "authed"}).encode())
                return
            if self.path == "/api/secret":
                self._log(method, self.path, 200)
                self._send(200, json.dumps({"secret": BLUE_SECRET}).encode())
                return

        self._log(method, self.path, 404)
        self._send(404, json.dumps({"error": "not_found"}).encode())

    def do_GET(self): self._common("GET")
    def do_POST(self): self._common("POST")
    def do_PUT(self): self._common("PUT")
    def do_DELETE(self): self._common("DELETE")

def run():
    server = http.server.HTTPServer((HOST, PORT), BlueHandler)
    print(f"[blue] listening on {HOST}:{PORT} (secret={BLUE_SECRET[:8]}...)")
    server.serve_forever()

if __name__ == "__main__":
    run()