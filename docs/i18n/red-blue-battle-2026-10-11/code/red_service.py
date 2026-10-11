#!/usr/bin/env python3
"""
红方 service — 工部尚书保护
监听 127.0.0.1:8002
secret: RED_EDF6A2FCC99CE301
token: rt_89a38f91
"""
import http.server
import json
import re
import time
import urllib.parse
from collections import defaultdict

RED_SECRET = "RED_EDF6A2FCC99CE301"
RED_TOKEN = "rt_89a38f91"
PORT = 8002
HOST = "127.0.0.1"

# WAF 规则（与 blue 不同——不同强度）
WAF_PATTERNS = {
    "path_traversal": [
        r"\.\./", r"\.\.\\",
    ],
    "sqli": [
        r"\bunion\s+select\b", r"\bor\s+1\s*=\s*1\b",
    ],
    "xss": [
        r"<\s*script", r"javascript\s*:",
    ],
    "cmd_injection": [
        r";\s*cat\s+", r"\|\s*nc\s+",
    ],
}

REQUEST_LOG = []
RATE_LIMIT = defaultdict(list)

def waf_check(method, path, headers, body):
    full = f"{path} {urllib.parse.unquote(path)} {' '.join(f'{k}:{v}' for k,v in headers.items())} {body or ''}"
    for category, pats in WAF_PATTERNS.items():
        for pat in pats:
            if re.search(pat, full, re.IGNORECASE | re.MULTILINE):
                return True, f"{category} matched: {pat}"
    ip = headers.get("X-Real-IP", headers.get("X-Forwarded-For", "unknown")).split(",")[0].strip()
    now = time.time()
    RATE_LIMIT[ip] = [t for t in RATE_LIMIT[ip] if now - t < 1.0]
    if len(RATE_LIMIT[ip]) >= 30:
        return True, "rate_limit"
    RATE_LIMIT[ip].append(now)
    return False, None

class RedHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self):
        return self.headers.get("Authorization", "") == f"Bearer {RED_TOKEN}"

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
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "ignore") if length else ""

        blocked, reason = waf_check(method, self.path, self.headers, body)
        if blocked:
            self._log(method, self.path, 403, blocked)
            self._send(403, json.dumps({"error": "blocked", "reason": reason}).encode())
            return

        if self.path == "/health":
            self._log(method, self.path, 200)
            self._send(200, json.dumps({"status": "ok", "service": "red"}).encode())
            return

        if self.path.startswith("/api/"):
            if not self._check_auth():
                self._log(method, self.path, 401)
                self._send(401, json.dumps({"error": "unauthorized"}).encode())
                return
            if self.path == "/api/hello":
                self._log(method, self.path, 200)
                self._send(200, json.dumps({"msg": "hello from red"}).encode())
                return
            if self.path == "/api/secret":
                self._log(method, self.path, 200)
                self._send(200, json.dumps({"secret": RED_SECRET}).encode())
                return

        self._log(method, self.path, 404)
        self._send(404, json.dumps({"error": "not_found"}).encode())

    def do_GET(self): self._common("GET")
    def do_POST(self): self._common("POST")
    def do_PUT(self): self._common("PUT")
    def do_DELETE(self): self._common("DELETE")

def run():
    server = http.server.HTTPServer((HOST, PORT), RedHandler)
    print(f"[red] listening on {HOST}:{PORT} (secret={RED_SECRET[:8]}...)")
    server.serve_forever()

if __name__ == "__main__":
    run()