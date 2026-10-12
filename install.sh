#!/bin/sh
# TarsSecureGuard 统一安装器（Linux / macOS）
# 自动识别操作系统与 CPU 架构，下载对应二进制并完成安装，无需手动选版本。
#
# 一键安装：
#   curl -fsSL https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
# 或下载统一安装包 tsg-setup.zip 后运行： sh install.sh
#
# 环境变量（均可选）：
#   TSG_VERSION      指定版本（默认 latest；也可写 v4.7.0 或 4.7.0）
#   TSG_BASE_URL     下载基地址覆盖（镜像加速 / 本地目录 / file:// 均可）
#   TSG_INSTALL_DIR  安装目录（默认 ~/.tsg/bin）
#   TSG_NO_PATH_MOD  设为 1 时不自动写 shell 配置文件
#   TSG_NO_SHORTCUT  设为 1 时不创建桌面/应用菜单快捷方式
#   TSG_NO_VERIFY    设为 1 时跳过 SHA256 校验（不建议）
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

VERSION="${TSG_VERSION:-latest}"

# ---------- 3. 解析版本号（latest → 具体 vX.Y.Z）----------
# Release 资产命名形如 tsg-v4.7.0-linux-amd64，latest 时需先拿到真实版本号。
resolve_latest() {
  # 优先：GitHub API（一次调用，无需认证）
  if command -v curl >/dev/null 2>&1; then
    _tag="$(curl -fsSL --max-time 15 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)" && [ -n "$_tag" ] && { printf '%s' "$_tag"; return 0; }
  fi
  # 兜底：跟随 releases/latest 的 302 跳转，URL 末段即 tag
  if command -v curl >/dev/null 2>&1; then
    _u="$(curl -fsSLI --max-time 15 -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null)" && _tag="${_u##*/}" && case "$_tag" in
      v*.[0-9]*.[0-9]*) printf '%s' "$_tag"; return 0 ;;
    esac
  fi
  return 1
}

case "$VERSION" in
  latest)
    RESOLVED="$(resolve_latest)" || die "无法获取最新版本号（网络受限？）。请手动指定：TSG_VERSION=v4.7.0 sh install.sh"
    VERSION="$RESOLVED" ;;
  v*)  : ;;
  *)   VERSION="v${VERSION}" ;;
esac

ASSET="tsg-${VERSION}-${TSG_OS}-${TSG_ARCH}"
SUMS="SHA256SUMS.txt"
log "检测到 ${TSG_OS}/${TSG_ARCH}，目标组件 ${ASSET}（版本 ${VERSION}）"

# ---------- 4. 确定下载源 ----------
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
  SRC_SUMS="${TSG_BASE_URL%/}/${SUMS}"
  log "使用自定义下载源：$SRC"
else
  SRC="${GH}/download/${VERSION}/${ASSET}"
  SRC_SUMS="${GH}/download/${VERSION}/${SUMS}"
fi

# ---------- 5. 安装 ----------
INSTALL_DIR="${TSG_INSTALL_DIR:-$HOME/.tsg/bin}"
BIN="$INSTALL_DIR/tsg"
mkdir -p "$INSTALL_DIR"

TMP="$(mktemp "${TMPDIR:-/tmp}/tsg-installer.XXXXXX")"
TRAP_RM='rm -f "$TMP" "$TMP.sum"'
trap '$TRAP_RM' EXIT

log "下载中：$SRC"
fetch "$SRC" "$TMP"
[ -s "$TMP" ] || die "下载结果为空文件，请检查网络或下载源"
chmod +x "$TMP"

# ---------- 6. SHA256 校验（防篡改，默认开启）----------
if [ "${TSG_NO_VERIFY:-0}" != "1" ]; then
  TMP_SUMS="$TMP.sum"
  if fetch "$SRC_SUMS" "$TMP_SUMS" 2>/dev/null && [ -s "$TMP_SUMS" ]; then
    WANT="$(sed -n "s/^\([0-9a-fA-F]\{64\}\)[[:space:]].*${ASSET}.*/\1/p" "$TMP_SUMS" | head -n 1)"
    if [ -n "$WANT" ]; then
      if command -v sha256sum >/dev/null 2>&1; then
        GOT="$(sha256sum "$TMP" | cut -d' ' -f1)"
      elif command -v shasum >/dev/null 2>&1; then
        GOT="$(shasum -a 256 "$TMP" | cut -d' ' -f1)"
      else
        warn "系统无 sha256sum / shasum，跳过校验（可设 TSG_NO_VERIFY=1 不再提示）"
        GOT="$WANT"
      fi
      if [ "$GOT" != "$WANT" ]; then
        die "SHA256 校验失败！\n    期望 $WANT\n    实际 $GOT\n    文件可能损坏或被篡改，已中止安装。"
      fi
      log "SHA256 校验通过 ✓"
    else
      warn "SHA256SUMS.txt 中未找到 ${ASSET} 条目，跳过校验"
    fi
  else
    warn "无法下载 SHA256SUMS.txt（网络受限？），跳过校验"
  fi
fi

mv -f "$TMP" "$BIN"
trap - EXIT
log "已安装：$BIN"

# ---------- 7. PATH（小白化：默认自动写入 shell 配置）----------
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

# ---------- 8. 桌面/应用菜单快捷方式（双击即启动面板）----------
if [ "${TSG_NO_SHORTCUT:-0}" != "1" ]; then
  if [ "$TSG_OS" = "linux" ]; then
    APPS_DIR="$HOME/.local/share/applications"
    DESK_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || printf '%s' "$HOME/Desktop")"
    mkdir -p "$APPS_DIR" "$DESK_DIR" 2>/dev/null || true
    make_desktop() {
      cat > "$1" <<EOF
[Desktop Entry]
Type=Application
Name=TarsSecureGuard
Comment=AI 网关 · 路由器与配置器（启动后面板自动打开）
Exec=${BIN}
Terminal=true
Categories=Network;Development;Security;
Keywords=tsg;gateway;ai;proxy;
EOF
    }
    if [ -d "$APPS_DIR" ]; then
      make_desktop "$APPS_DIR/tsg.desktop"
      chmod +x "$APPS_DIR/tsg.desktop" 2>/dev/null || true
      (command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR" 2>/dev/null) || true
      log "已创建应用菜单项：应用列表搜「TarsSecureGuard」即可点开"
    fi
    if [ -d "$DESK_DIR" ] && [ -w "$DESK_DIR" ]; then
      make_desktop "$DESK_DIR/tsg.desktop"
      chmod +x "$DESK_DIR/tsg.desktop" 2>/dev/null || true
      log "已创建桌面快捷方式：$DESK_DIR/tsg.desktop（双击即启动）"
    fi
  elif [ "$TSG_OS" = "darwin" ]; then
    # macOS：生成双击即用的 .command 启动器放到桌面
    DESK_DIR="$HOME/Desktop"
    if [ -d "$DESK_DIR" ] && [ -w "$DESK_DIR" ]; then
      CMD="$DESK_DIR/启动 TarsSecureGuard.command"
      cat > "$CMD" <<EOF
#!/bin/sh
# 双击启动 TarsSecureGuard 网关（面板自动打开 http://127.0.0.1:18889）
exec "${BIN}"
EOF
      chmod +x "$CMD"
      log "已创建桌面快捷方式：$CMD（双击即启动）"
    fi
  fi
fi

# ---------- 9. 快速开始 ----------
log "安装完成！启动方式："
printf '  双击桌面「TarsSecureGuard」快捷方式（或应用菜单）\n'
printf '  %s            # 终端启动网关，面板自动打开 http://127.0.0.1:18889\n' "$BIN"
printf '  %s doctor     # 环境自检\n' "$BIN"
printf '  卸载：删除 %s 即可\n' "$INSTALL_DIR"
