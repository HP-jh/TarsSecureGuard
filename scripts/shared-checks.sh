#!/usr/bin/env bash
# shared-checks.sh — 通用检测函数库
# 可被 TSG 网关和 TSGMemOptimizer 等项目的检测脚本 source 使用。
# Usage: source scripts/shared-checks.sh
#
# 提供函数：
#   check_go_binary_header <file>   — 检查 Go 编译二进制的头部魔数
#   check_size <file> [min_bytes]   — 检查文件大小（默认 5MB）
#   check_executable <file>         — 检查可执行权限（跳过 Windows .exe）
#   check_sha256sums <dir>          — 验证 SHA256SUMS.txt 一致性
#   check_naming <file> <pattern>   — 检查文件名匹配正则

set -uo pipefail

# Min size default: 5MB
CHECK_MIN_SIZE="${CHECK_MIN_SIZE:-$((5 * 1024 * 1024))}"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'

sc_pass()  { echo -e "${G}[PASS]${N} $*"; }
sc_fail()  { echo -e "${R}[FAIL]${N} $*"; }
sc_warn()  { echo -e "${Y}[WARN]${N} $*"; }
sc_info()  { echo -e "${C}[INFO]${N} $*"; }

# Check Go binary header magic
check_go_binary_header() {
  local f="$1"
  local name; name=$(basename "$f")
  local header
  header=$(xxd -l 4 "$f" 2>/dev/null | awk '{print $2$3$4$5}')
  case "$name" in
    *windows*.exe)
      if [[ "${header:0:4}" != "4d5a" ]]; then
        sc_fail "$name: PE header missing (got ${header:0:4}, expected 4d5a)"
        return 1
      fi
      sc_pass "$name: PE header OK"
      ;;
    *linux*|*android*)
      if [[ "${header:0:8}" != "7f454c46" ]]; then
        sc_fail "$name: ELF header missing (got ${header:0:8}, expected 7f454c46)"
        return 1
      fi
      sc_pass "$name: ELF header OK"
      ;;
    *darwin*)
      local h2; h2=$(xxd -l 4 "$f" 2>/dev/null | awk '{print $2$3$4$5}')
      if [[ "$h2" == "cffaedfe" || "$h2" == "feedfacf" || "$h2" == "cafebabe" ]]; then
        sc_pass "$name: Mach-O header OK ($h2)"
      else
        sc_warn "$name: Mach-O header unclear (got $h2), manual check advised"
        return 2
      fi
      ;;
    *)
      sc_warn "$name: unknown platform, skipping header check"
      return 2
      ;;
  esac
  return 0
}

# Check file size >= min_bytes
check_size() {
  local f="$1"
  local min="${2:-$CHECK_MIN_SIZE}"
  local name; name=$(basename "$f")
  local size
  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
  if [[ "$size" -lt "$min" ]]; then
    sc_fail "$name: size=$size (< $min bytes)"
    return 1
  fi
  sc_pass "$name: size=$size bytes"
  return 0
}

# Check executable bit (skip Windows)
check_executable() {
  local f="$1"
  local name; name=$(basename "$f")
  case "$name" in
    *windows*.exe) return 0 ;;
  esac
  if [[ ! -x "$f" ]]; then
    sc_warn "$name: not executable (chmod +x advised)"
    return 2
  fi
  return 0
}

# Verify SHA256SUMS.txt against files in directory
check_sha256sums() {
  local dir="$1"
  local shafile="$dir/SHA256SUMS.txt"
  if [[ ! -f "$shafile" ]]; then
    sc_fail "SHA256SUMS.txt not found in $dir"
    return 1
  fi
  local lines
  lines=$(wc -l < "$shafile" | tr -d ' ')
  sc_pass "SHA256SUMS.txt: $lines entries"

  local cwd; cwd=$(pwd)
  cd "$dir"
  local sha_err=0
  while read -r expected_hash filename; do
    [[ -n "$filename" ]] || continue
    if [[ ! -f "$filename" ]]; then
      sc_fail "SHA256SUMS references missing file: $filename"
      ((sha_err++)) || true
      continue
    fi
    local actual_hash
    actual_hash=$(sha256sum "$filename" 2>/dev/null | awk '{print $1}')
    if [[ "$actual_hash" != "$expected_hash" ]]; then
      sc_fail "SHA256 mismatch: $filename"
      ((sha_err++)) || true
    fi
  done < SHA256SUMS.txt
  cd "$cwd"

  if [[ "$sha_err" -gt 0 ]]; then
    sc_fail "$sha_err SHA256 mismatch(es)"
    return 1
  fi
  sc_pass "SHA256SUMS: all hashes verified"
  return 0
}

# Check filename matches regex pattern
check_naming() {
  local f="$1"
  local pattern="$2"
  local name; name=$(basename "$f")
  if [[ ! "$name" =~ $pattern ]]; then
    sc_warn "$name: does not match pattern /$pattern/"
    return 2
  fi
  sc_pass "$name: naming OK"
  return 0
}

# If sourced, do nothing. If executed directly, print help.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "shared-checks.sh — Generic verification functions for Go release binaries"
  echo ""
  echo "Usage: source $(basename "$0")"
  echo ""
  echo "Functions available after sourcing:"
  echo "  check_go_binary_header <file>"
  echo "  check_size <file> [min_bytes]"
  echo "  check_executable <file>"
  echo "  check_sha256sums <dir>"
  echo "  check_naming <file> <regex>"
  echo ""
  echo "Environment:"
  echo "  CHECK_MIN_SIZE  — default minimum file size in bytes (default: 5242880 = 5MB)"
fi
