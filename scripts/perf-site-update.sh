#!/usr/bin/env bash
# perf-site-update.sh — 性能监控站数据更新脚本（v4.7.0）
#
# 在发版时运行：跑完整基准套件，把结果作为新版本数据点追加到
# site/perf-data.json（保留历史版本点，趋势随发版自动累积）。
#
# 用法：
#   ./scripts/perf-site-update.sh v4.7.0 [linux容器环境描述]
#
# 依赖：go、jq（无 jq 时用内置 python3 处理 JSON）。
set -euo pipefail

VERSION="${1:?用法: ./scripts/perf-site-update.sh <版本号如 v4.7.0>}"
ENV_NOTE="${2:-2 vCPU Linux 容器}"
DATA_FILE="$(dirname "$0")/../site/perf-data.json"

cd "$(dirname "$0")/.."

echo "[perf-site] 采集个体基准（500x 迭代 + 内存）…"
IND=$(go test -bench='BenchmarkVault|BenchmarkSecurity|BenchmarkSkylink|BenchmarkAgentMesh|BenchmarkSecretStore' \
  -benchtime=500x -benchmem -run='XXX' ./crownext/bench/ 2>/dev/null | grep -E '^Benchmark' || true)

echo "[perf-site] 采集汇总基准（内层各 1000 次迭代）…"
AGG=$(go test -bench='BenchmarkHarness' -benchtime=1x -run='XXX' ./crownext/bench/ 2>/dev/null | grep -E '^Benchmark' || true)

echo "$IND" | head -3
echo "$AGG" | head -3

GO_VER=$(go version | awk '{print $3}')
CPU=$(lscpu 2>/dev/null | grep 'Model name' | head -1 | cut -d: -f2 | xargs || echo "unknown")
CPU="$CPU（$(nproc) vCPU）"

python3 - "$DATA_FILE" "$VERSION" "$GO_VER" "$CPU" "$ENV_NOTE" <<'PYEOF'
import json, re, sys, datetime

data_file, version, go_ver, cpu, env_note = sys.argv[1:6]

# 个体指标的维度归属与双语文案
META = {
    "VaultDerive":            ("compute",   "密钥派生（服务密钥缓存命中）", "Key derivation (cached service key)"),
    "VaultSealOpen":          ("compute",   "AES-GCM 密封 + 解封一对", "AES-GCM seal + open pair"),
    "SecurityEvaluate":       ("compute",   "安全评分引擎全量评估", "Security score engine full evaluate"),
    "SkylinkEncrypt":         ("network",   "节点消息加密（AES-256-GCM + JSON）", "Peer message encrypt (AES-256-GCM + JSON)"),
    "SkylinkDecrypt":         ("network",   "节点消息解密", "Peer message decrypt"),
    "AgentMeshRegisterLookup":("network",   "Agent 网格注册 + 查找", "Agent mesh register + lookup"),
    "SecretStoreSet":         ("storage",   "密钥库写入（密封后存储）", "Secret store set (sealed)"),
    "SecretStoreGet":         ("storage",   "密钥库读取（解密）", "Secret store get (decrypt)"),
    "HarnessCompute":         ("aggregate", "计算维度汇总（3 项 × 1000 次）", "Compute dimension aggregate (3 × 1000 ops)"),
    "HarnessNetwork":         ("aggregate", "网络维度汇总（3 项 × 1000 次）", "Network dimension aggregate (3 × 1000 ops)"),
    "HarnessStorage":         ("aggregate", "存储维度汇总（2 项 × 1000 次）", "Storage dimension aggregate (2 × 1000 ops)"),
}

def parse(stdout_text):
    out = {}
    for line in stdout_text.splitlines():
        m = re.match(r"^(Benchmark\S+?)-\d+\s+\d+\s+([\d.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op", line.strip())
        if m:
            out[m.group(1)[len("Benchmark"):]] = (float(m.group(2)), int(m.group(3)), int(m.group(4)))
    return out

# 从 stdin 读取两段基准输出（用分隔行隔开）
raw = sys.stdin.read()
ind_text, _, agg_text = raw.partition("===AGG===")
metrics_ind = parse(ind_text)
metrics_agg = parse(agg_text)
all_metrics = dict(metrics_ind); all_metrics.update(metrics_agg)

now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
entry = {
    "version": version,
    "timestamp": now,
    "metrics": []
}
for name, (cat, zh, en) in META.items():
    if name not in all_metrics:
        continue
    ns, b, a = all_metrics[name]
    entry["metrics"].append({
        "name": name, "category": cat, "desc_zh": zh, "desc_en": en,
        "per_op_ns": ns, "allocs_per_op": a, "bytes_per_op": b,
    })

try:
    data = json.load(open(data_file, encoding="utf-8"))
except FileNotFoundError:
    data = {"schema": 1, "generated": now, "environment": {}, "releases": [], "milestones": []}

data["releases"] = [r for r in data["releases"] if r["version"] != version]
data["releases"].append(entry)
data["releases"].sort(key=lambda r: [int(x[1:]) for x in re.findall(r"v\d+", r["version"])])
data["generated"] = now
data["environment"] = {
    "os": "linux", "arch": "amd64", "cpu": cpu, "go": go_ver,
    "method": "go test -bench -benchtime=500x -benchmem（每项 500 次迭代取均值；汇总项为内置 1000 次迭代）",
}
json.dump(data, open(data_file, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(f"[perf-site] 已写入 {data_file}：{len(entry['metrics'])} 项指标，共 {len(data['releases'])} 个版本点")
PYEOF
