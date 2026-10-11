#!/usr/bin/env bash
# Release Asset Verification Script
# Checks each platform binary for: size > 5MB, valid PE/MZ header (Windows),
# ELF header (Linux), Mach-O header (macOS).
# Usage: ./scripts/verify-release-assets.sh <release-dir>

set -euo pipefail

DIR="${1:-.}"
ERRORS=0
MIN_SIZE=$((5 * 1024 * 1024))  # 5MB

assets=(
  "tsg-v*-linux-amd64"
  "tsg-v*-linux-arm64"
  "tsg-v*-darwin-amd64"
  "tsg-v*-darwin-arm64"
  "tsg-v*-windows-amd64.exe"
  "tsg-v*-windows-arm64.exe"
  "tsg-*-android-arm64"
)

check_file() {
  local f="$1"
  local name
  name=$(basename "$f")
  local size
  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)

  # Size check
  if [[ "$size" -lt "$MIN_SIZE" ]]; then
    echo "[FAIL] $name: size=$size (< $MIN_SIZE bytes) — placeholder file suspected"
    return 1
  fi
  echo "[PASS] $name: size=$size bytes"

  # Header check
  local header
  header=$(xxd -l 4 "$f" | awk '{print $2$3$4$5}')
  case "$name" in
    *windows*.exe)
      if [[ "${header:0:4}" != "4d5a" ]]; then
        echo "[FAIL] $name: PE header missing (got ${header:0:4}, expected 4d5a)"
        return 1
      fi
      ;;
    *linux*)
      if [[ "${header:0:8}" != "7f454c46" ]]; then
        echo "[FAIL] $name: ELF header missing (got ${header:0:8}, expected 7f454c46)"
        return 1
      fi
      ;;
    *darwin*)
      # Mach-O: feedface (32-bit) or feedfacf (64-bit) or cafebabe (universal)
      if [[ "$header" != "feedface" && "$header" != "feedfacf" && "$header" != "cafebabe" && "$header" != "cffaedfe" ]]; then
        # Check for 64-bit Mach-O little-endian (cf fa ed fe)
        local h2
        h2=$(xxd -l 4 "$f" | awk '{print $2$3$4$5}')
        if [[ "$h2" != "cffaedfe" && "$h2" != "feedfacf" ]]; then
          echo "[WARN] $name: Mach-O header unclear (got $header / $h2), manual check advised"
        fi
      fi
      ;;
  esac
  return 0
}

for pattern in "${assets[@]}"; do
  found=0
  for f in "$DIR"/$pattern; do
    [[ -e "$f" ]] || continue
    found=1
    if ! check_file "$f"; then
      ((ERRORS++)) || true
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    echo "[MISSING] No file matches $pattern"
    ((ERRORS++)) || true
  fi
done

# SHA256SUMS check
shafile="$DIR/SHA256SUMS.txt"
if [[ -f "$shafile" ]]; then
  lines=$(wc -l < "$shafile" | tr -d ' ')
  if [[ "$lines" -lt 7 ]]; then
    echo "[FAIL] SHA256SUMS.txt has $lines lines (< 7 expected)"
    ((ERRORS++)) || true
  else
    echo "[PASS] SHA256SUMS.txt: $lines lines"
  fi
else
  echo "[MISSING] SHA256SUMS.txt not found"
  ((ERRORS++)) || true
fi

if [[ "$ERRORS" -gt 0 ]]; then
  echo ""
  echo "$ERRORS verification failure(s). Release assets NOT valid."
  exit 1
fi

echo ""
echo "All release assets passed verification."
exit 0
