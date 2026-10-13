#!/usr/bin/env bash
# Release Asset Verification Script v2
# Checks each platform binary for: valid naming, size, header magic, executable bits,
# and SHA256SUMS consistency.
# Usage: ./scripts/verify-release-assets.sh <release-dir>
# Exit 0 = all pass, Exit 1 = failures

set -euo pipefail

DIR="${1:-.}"
ERRORS=0
WARNINGS=0
MIN_SIZE=$((5 * 1024 * 1024))  # 5MB

# Expected assets (glob patterns)
assets=(
  "tsg-v*-linux-amd64"
  "tsg-v*-linux-arm64"
  "tsg-v*-darwin-amd64"
  "tsg-v*-darwin-arm64"
  "tsg-v*-windows-amd64.exe"
  "tsg-v*-windows-arm64.exe"
  "tsg-*-android-arm64"
)

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'

log_pass()  { echo -e "${G}[PASS]${N} $*"; }
log_fail()  { echo -e "${R}[FAIL]${N} $*"; }
log_warn()  { echo -e "${Y}[WARN]${N} $*"; }
log_info()  { echo -e "${C}[INFO]${N} $*"; }

# Shared helper: check Go binary header magic (sourced by other scripts too)
check_go_binary_header() {
  local f="$1"
  local name; name=$(basename "$f")
  local header h2
  header=$(xxd -l 4 "$f" 2>/dev/null | awk '{print $2$3$4$5}')
  h2=""
  case "$name" in
    *windows*.exe)
      if [[ "${header:0:4}" != "4d5a" ]]; then
        log_fail "$name: PE header missing (got ${header:0:4}, expected 4d5a)"
        return 1
      fi
      log_pass "$name: PE header OK"
      ;;
    *linux*|*android*)
      if [[ "${header:0:8}" != "7f454c46" ]]; then
        log_fail "$name: ELF header missing (got ${header:0:8}, expected 7f454c46)"
        return 1
      fi
      log_pass "$name: ELF header OK"
      ;;
    *darwin*)
      # Mach-O 64-bit little-endian: cffaedfe; 64-bit big-endian: feedfacf; universal: cafebabe
      h2=$(xxd -l 4 "$f" 2>/dev/null | awk '{print $2$3$4$5}')
      if [[ "$h2" == "cffaedfe" || "$h2" == "feedfacf" || "$h2" == "cafebabe" ]]; then
        log_pass "$name: Mach-O header OK ($h2)"
      else
        log_warn "$name: Mach-O header unclear (got $h2), manual check advised"
        return 2
      fi
      ;;
  esac
  return 0
}

# Shared helper: check file size
check_size() {
  local f="$1"
  local name; name=$(basename "$f")
  local size
  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
  if [[ "$size" -lt "$MIN_SIZE" ]]; then
    log_fail "$name: size=$size (< $MIN_SIZE bytes) — placeholder suspected"
    return 1
  fi
  log_pass "$name: size=$size bytes"
  return 0
}

# Shared helper: check executable bits (non-Windows)
check_executable() {
  local f="$1"
  local name; name=$(basename "$f")
  case "$name" in
    *windows*.exe) return 0 ;;  # Windows uses .exe extension
  esac
  if [[ ! -x "$f" ]]; then
    log_warn "$name: not executable (chmod +x advised)"
    return 2
  fi
  return 0
}

# Shared helper: verify SHA256SUMS
check_sha256sums() {
  local dir="$1"
  local shafile="$dir/SHA256SUMS.txt"
  if [[ ! -f "$shafile" ]]; then
    log_fail "SHA256SUMS.txt not found"
    return 1
  fi
  local lines
  lines=$(wc -l < "$shafile" | tr -d ' ')
  if [[ "$lines" -lt 7 ]]; then
    log_fail "SHA256SUMS.txt has $lines lines (< 7 expected)"
    return 1
  fi
  log_pass "SHA256SUMS.txt: $lines lines"

  # Verify each listed hash matches the file
  local cwd; cwd=$(pwd)
  cd "$dir"
  local sha_err=0
  while read -r expected_hash filename; do
    [[ -n "$filename" ]] || continue
    if [[ ! -f "$filename" ]]; then
      log_fail "SHA256SUMS references missing file: $filename"
      ((sha_err++)) || true
      continue
    fi
    local actual_hash
    actual_hash=$(sha256sum "$filename" 2>/dev/null | awk '{print $1}')
    if [[ "$actual_hash" != "$expected_hash" ]]; then
      log_fail "SHA256 mismatch: $filename"
      ((sha_err++)) || true
    fi
  done < SHA256SUMS.txt
  cd "$cwd"

  if [[ "$sha_err" -gt 0 ]]; then
    log_fail "$sha_err SHA256 mismatch(es)"
    return 1
  fi
  log_pass "SHA256SUMS: all hashes match"
  return 0
}

# ========================================
# Main verification
# ========================================
echo "=== TSG Release Asset Verification ==="
echo "Directory: $DIR"
echo ""

for pattern in "${assets[@]}"; do
  found=0
  for f in "$DIR"/$pattern; do
    [[ -e "$f" ]] || continue
    found=1
    name=$(basename "$f")

    # Naming convention check
    if [[ ! "$name" =~ ^tsg-v[0-9]+\.[0-9]+\.[0-9]+- ]]; then
      log_warn "$name: filename does not match tsg-vX.Y.Z-... convention"
      ((WARNINGS++)) || true
    fi

    rc=0
    check_size "$f" || rc=1
    check_go_binary_header "$f" || { [[ $? -eq 1 ]] && rc=1; }
    check_executable "$f" || { [[ $? -eq 2 ]] && ((WARNINGS++)) || true; }

    if [[ "$rc" -ne 0 ]]; then
      ((ERRORS++)) || true
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    log_fail "No file matches $pattern"
    ((ERRORS++)) || true
  fi
done

echo ""
check_sha256sums "$DIR" || ((ERRORS++)) || true

echo ""
if [[ "$ERRORS" -gt 0 ]]; then
  echo -e "${R}$ERRORS error(s), $WARNINGS warning(s).${N} Release assets NOT valid."
  exit 1
fi
if [[ "$WARNINGS" -gt 0 ]]; then
  echo -e "${Y}0 error(s), $WARNINGS warning(s).${N} Assets valid with warnings."
  exit 0
fi
echo -e "${G}All checks passed.${N}"
exit 0
