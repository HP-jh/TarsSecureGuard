#!/usr/bin/env bash
# TarsSecureGuard v3.0.0 E 线：8 小时循环压测脚本（soak test）
# 用法：./soak.sh [时长秒，默认 28800] [BASE_URL，默认 http://127.0.0.1:18889]
# 记录：每 5 分钟一轮请求 + /health 与 /api/admin/guard/status 采样 → soak-report.csv
set -u
DUR="${1:-28800}"; BASE="${2:-http://127.0.0.1:18889}"; KEY="${TSG_API_KEY:-tars-gateway-key}"
OUT="soak-report.csv"; START=$(date +%s)
echo "time,round,ok,fail,guard_tier,rss_mb,goroutines" > "$OUT"
round=0; ok=0; fail=0
while [ $(( $(date +%s) - START )) -lt "$DUR" ]; do
  round=$((round+1))
  for i in $(seq 1 20); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/chat/completions" \
      -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
      -d '{"messages":[{"role":"user","content":"压测第'"$round"'轮第'"$i"'条"}]}' 2>/dev/null)
    case "$code" in 200|403|429|503) ok=$((ok+1));; *) fail=$((fail+1));; esac
  done
  # 403/429/503 计为"防护正常工作"，连接错误计为失败
  g=$(curl -s "$BASE/api/admin/guard/status" -H "X-API-Key: $KEY" 2>/dev/null)
  tier=$(echo "$g" | grep -o '"tier":"[^"]*"' | cut -d'"' -f4)
  rss=$(echo "$g" | grep -o '"rssMB":[0-9]*' | cut -d: -f2)
  goro=$(echo "$g" | grep -o '"goroutines":[0-9]*' | cut -d: -f2)
  echo "$(date +%H:%M:%S),$round,$ok,$fail,${tier:-NA},${rss:-NA},${goro:-NA}" >> "$OUT"
  echo "[soak] 第 $round 轮 ok=$ok fail=$fail tier=${tier:-NA} rss=${rss:-NA}MB"
  sleep 300
done
echo "[soak] 完成：共 $round 轮，ok=$ok fail=$fail，报告已写入 $OUT"
