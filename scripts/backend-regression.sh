#!/usr/bin/env bash
# Backend Regression Test Script
# Run against a running TSG instance (default http://127.0.0.1:18889)
# Requires: curl, jq (optional but recommended)

set -uo pipefail

BASE="${TSG_BASE:-http://127.0.0.1:18889}"
API_KEY="${TSG_API_KEY:-demo-key}"
ERRORS=0

run() {
  local name="$1"
  local method="$2"
  local path="$3"
  local want_code="$4"
  shift 4
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" "$@" "${BASE}${path}")
  if [[ "$resp" == "$want_code" ]]; then
    echo "[PASS] $name => $resp"
  else
    echo "[FAIL] $name => got $resp, want $want_code"
    ((ERRORS++)) || true
  fi
}

echo "=== Auth Tests ==="
run "Auth with key"     GET  "/api/status" 200 -H "X-API-Key: $API_KEY"
run "Auth without key"  GET  "/api/status" 401
run "Auth bad key"      GET  "/api/status" 401 -H "X-API-Key: bad-key"

echo ""
echo "=== WAF / Path Tests ==="
run "Path traversal"    GET  "/../../etc/passwd" 403 --path-as-is
run "Scanner UA"        GET  "/api/status" 403 -H "User-Agent: sqlmap/1.0"
run "SQLi in query"     GET  "/api/chat?q=1%27%20OR%20%271%27%3D%271" 403 -H "X-API-Key: $API_KEY"

echo ""
echo "=== Honeypot Tests ==="
run "Honeypot .env"     GET  "/.env" 200
run "Honeypot wp-login" GET  "/wp-login.php" 200
run "Honeypot admin.php" GET "/admin.php" 200

echo ""
echo "=== MCP Tools Tests ==="
run "MCP tools/list"    GET  "/mcp/tools/list" 200 -H "X-API-Key: $API_KEY"

echo ""
echo "=== Chat Route Error Tests ==="
run "Chat no body"      POST "/api/chat/completions" 400 -H "X-API-Key: $API_KEY" -H "Content-Type: application/json"
run "Chat bad JSON"     POST "/api/chat/completions" 400 -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d "not-json"

echo ""
echo "=== Health ==="
run "Health"            GET  "/health" 200

if [[ "$ERRORS" -gt 0 ]]; then
  echo ""
  echo "$ERRORS test(s) FAILED"
  exit 1
fi

echo ""
echo "All backend regression tests PASSED"
exit 0
