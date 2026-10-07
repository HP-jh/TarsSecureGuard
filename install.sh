#!/bin/sh
# TarsSecureGuard 统一安装器（Linux / macOS）
# 自动识别操作系统与 CPU 架构，下载对应二进制并完成安装，无需手动选版本。
#
# 一键安装：
#   curl -fsSL https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
# 或下载统一安装包 tsg-setup.zip 后运行： sh install.sh
#
# 环境变量（均可选）：
#   TSG_VERSION      指定版本（默认 latest）
#   TSG_BASE_URL     下载基地址覆盖（镜像加速 / 本地目录 / file:// 均可）
#   TSG_INSTALL_DIR  安装目录（默认 ~/.tsg/bin）
#   TSG_NO_PATH_MOD  设为 1 时不自动写 shell 配置文件
set -eu

REPO="HP-jh/TarsSecureGuard"
GH="https://github.com/${REPO}/releases"

log()  { printf '\033[36m[tsg]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[tsg]\033[0m %s\n' "$1"; }
die()  { printf '\033[31m[tsg] 错误：\033[0m %s\n' "$1" >&2; exit 1; }

# ---------- 1. 识别操作系统 ----------
OS_RAW="$(uname -s)"
case "$OS_RAW" in
  Linux*)                 TSG_OS=linux ;;
  Darwin*)                TSG_OS=darwin ;;
  MINGW*|MSYS*|Cygwin*)   die "检测到 Windows（Git Bash/MSYS）。请改用 install.ps1：powershell -ExecutionPolicy Bypass -File install.ps1" ;;
  *)                      die "无法识别的操作系统：$OS_RAW（支持 Linux / macOS，Windows 请用 install.ps1）" ;;
esac

# ---------- 2. 识别 CPU 架构 ----------
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64)   TSG_ARCH=amd64 ;;
  aarch64|arm64)  TSG_ARCH=arm64 ;;
  *)              die "暂不支持的 CPU 架构：$ARCH_RAW（当前提供 amd64 / arm64）" ;;
esac

ASSET="tsg-${TSG_OS}-${TSG_ARCH}"
VERSION="${TSG_VERSION:-latest}"

log "检测到 ${TSG_OS}/${TSG_ARCH}，目标组件 ${ASSET}（版本 ${VERSION}）"

# ---------- 3. 确定下载源 ----------
fetch() {
  # $1 = URL 或本地文件路径；$2 = 输出
  case "$1" in
    http://*|https://*)
      command -v curl >/dev/null 2>&1 && curl -fSL "$1" -o "$2" && return 0
      command -v wget >/dev/null 2>&1 && wget -qO "$2" "$1" && return 0
      die "未找到 curl / wget，请先安装其一" ;;
    *)
      [ -f "$1" ] || die "本地文件不存在：$1"
      cp "$1" "$2"; return 0 ;;
  esac
}

if [ -n "${TSG_BASE_URL:-}" ]; then
  SRC="${TSG_BASE_URL%/}/${ASSET}"
  log "使用自定义下载源：$SRC"
else
  if [ "$VERSION" = "latest" ]; then
    SRC="${GH}/latest/download/${ASSET}"
  else
    SRC="${GH}/download/${VERSION}/${ASSET}"
  fi
fi

# ---------- 4. 安装 ----------
INSTALL_DIR="${TSG_INSTALL_DIR:-$HOME/.tsg/bin}"
BIN="$INSTALL_DIR/tsg"
mkdir -p "$INSTALL_DIR"

TMP="$(mktemp "${TMPDIR:-/tmp}/tsg-installer.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

log "下载中：$SRC"
fetch "$SRC" "$TMP"
[ -s "$TMP" ] || die "下载结果为空文件，请检查网络或下载源"
chmod +x "$TMP"

mv -f "$TMP" "$BIN"
trap - EXIT
log "已安装：$BIN"

# ---------- 5. PATH（小白化：默认自动写入 shell 配置）----------
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    if [ "${TSG_NO_PATH_MOD:-0}" != "1" ]; then
      RC=""
      case "$(basename "${SHELL:-sh}")" in
        zsh)  RC="$HOME/.zshrc" ;;
        bash) if [ -f "$HOME/.bashrc" ]; then RC="$HOME/.bashrc"; else RC="$HOME/.profile"; fi ;;
        *)    RC="$HOME/.profile" ;;
      esac
      if [ -n "$RC" ] && [ -f "$RC" ] && ! grep -q 'TarsSecureGuard PATH' "$RC" 2>/dev/null; then
        printf '\n# TarsSecureGuard PATH\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$RC"
        log "已将 $INSTALL_DIR 写入 $RC（重开终端或 source 后生效）"
      fi
    fi
    ;;
esac

# ---------- 6. 快速开始 ----------
log "安装完成！启动方式："
printf '  %s            # 启动网关，面板自动打开 http://127.0.0.1:18889\n' "$BIN"
printf '  %s doctor     # 环境自检\n' "$BIN"
printf '  卸载：删除 %s 即可\n' "$INSTALL_DIR"
