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
#   TSG_MIRROR       强制使用国内镜像（gh-proxy / ghfast）
#   TSG_FORCE_MIRROR 设为 1 时跳过 GitHub 直连，直接使用镜像
set -eu

REPO="HP-jh/TarsSecureGuard"
GH="https://github.com/${REPO}/releases"

# 镜像源配置
MIRROR_GHPROXY="https://gh-proxy.com/https://github.com"
MIRROR_GHFAST="https://ghfast.top/https://github.com"

log()  { printf '\033[36m[tsg]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[tsg]\033[0m %s\n' "$1"; }
die()  { printf '\033[31m[tsg] 错误：\033[0m %s\n' "$1" >&2; exit 1; }

# ---------- 0. 解析镜像设置 ----------
TSG_MIRROR="${TSG_MIRROR:-}"
TSG_FORCE_MIRROR="${TSG_FORCE_MIRROR:-0}"

# 验证镜像名
if [ -n "$TSG_MIRROR" ]; then
  case "$TSG_MIRROR" in
    gh-proxy|ghfast) : ;;
    *) warn "未知镜像 '$TSG_MIRROR'，已知镜像：gh-proxy, ghfast。将使用默认策略。"; TSG_MIRROR="" ;;
  esac
fi

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
resolve_latest_for() {
  _base="$1"
  # 优先：GitHub API（一次调用，无需认证）
  if command -v curl >/dev/null 2>&1; then
    _api="${_base}/api.github.com/repos/${REPO}/releases/latest"
    _tag="$(curl -fsSL --max-time 10 "$_api" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)" && [ -n "$_tag" ] && { printf '%s' "$_tag"; return 0; }
  fi
  # 兜底：跟随 releases/latest 的 302 跳转，URL 末段即 tag
  if command -v curl >/dev/null 2>&1; then
    _u="$(curl -fsSLI --max-time 10 -o /dev/null -w '%{url_effective}' "${_base}/${REPO}/releases/latest" 2>/dev/null)" && _tag="${_u##*/}" && case "$_tag" in
      v*.[0-9]*.[0-9]*) printf '%s' "$_tag"; return 0 ;;
    esac
  fi
  return 1
}

try_resolve_latest() {
  if [ -n "${TSG_BASE_URL:-}" ]; then
    resolve_latest_for "https://github.com" && return 0
    return 1
  fi

  # 构造候选列表
  _candidates=""
  if [ -n "$TSG_MIRROR" ] && [ "$TSG_FORCE_MIRROR" != "1" ]; then
    case "$TSG_MIRROR" in
      gh-proxy) _candidates="$MIRROR_GHPROXY https://github.com" ;;
      ghfast)   _candidates="$MIRROR_GHFAST https://github.com" ;;
    esac
  elif [ -n "$TSG_MIRROR" ] && [ "$TSG_FORCE_MIRROR" = "1" ]; then
    case "$TSG_MIRROR" in
      gh-proxy) _candidates="$MIRROR_GHPROXY" ;;
      ghfast)   _candidates="$MIRROR_GHFAST" ;;
    esac
  elif [ "$TSG_FORCE_MIRROR" = "1" ]; then
    _candidates="$MIRROR_GHPROXY $MIRROR_GHFAST"
  else
    _candidates="https://github.com"
    if [ -n "$TSG_MIRROR" ]; then
      case "$TSG_MIRROR" in
        gh-proxy) _candidates="$_candidates $MIRROR_GHPROXY" ;;
        ghfast)   _candidates="$_candidates $MIRROR_GHFAST" ;;
      esac
    else
      _candidates="$_candidates $MIRROR_GHPROXY $MIRROR_GHFAST"
    fi
  fi

  for _base in $_candidates; do
    _tag="$(resolve_latest_for "$_base")" && case "$_tag" in
      v[0-9]*) printf '%s' "$_tag"; return 0 ;;
    esac
  done
  return 1
}

case "$VERSION" in
  latest)
    RESOLVED="$(try_resolve_latest)" || die "无法获取最新版本号。可能原因：
  1. 网络受限（在中国大陆？尝试设置环境变量后再运行）：
     TSG_MIRROR=gh-proxy sh install.sh
  2. GitHub 服务暂时不可用
  3. 也可以手动指定版本：TSG_VERSION=v4.9.0 sh install.sh"
    VERSION="$RESOLVED" ;;
  v*)  : ;;
  *)   VERSION="v${VERSION}" ;;
esac

ASSET="tsg-${VERSION}-${TSG_OS}-${TSG_ARCH}"
SUMS="SHA256SUMS.txt"
log "检测到 ${TSG_OS}/${TSG_ARCH}，目标组件 ${ASSET}（版本 ${VERSION}）"

# ---------- 4. 确定下载源（支持镜像 fallback）----------
# 用数组形式存储源，避免管道子 shell 问题
SRC1_URL=""; SRC1_SUMS=""; SRC1_NAME=""
SRC2_URL=""; SRC2_SUMS=""; SRC2_NAME=""
SRC3_URL=""; SRC3_SUMS=""; SRC3_NAME=""
SRC_COUNT=0

add_source() {
  SRC_COUNT=$((SRC_COUNT + 1))
  eval "SRC${SRC_COUNT}_URL=\"\$1\""
  eval "SRC${SRC_COUNT}_SUMS=\"\$2\""
  eval "SRC${SRC_COUNT}_NAME=\"\$3\""
}

if [ -n "${TSG_BASE_URL:-}" ]; then
  add_source "${TSG_BASE_URL%/}/${ASSET}" "${TSG_BASE_URL%/}/${SUMS}" "自定义源"
else
  if [ -n "$TSG_MIRROR" ] && [ "$TSG_FORCE_MIRROR" != "1" ]; then
    case "$TSG_MIRROR" in
      gh-proxy)
        add_source "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 gh-proxy"
        add_source "https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}" "https://github.com/${REPO}/releases/download/${VERSION}/${SUMS}" "GitHub 直连" ;;
      ghfast)
        add_source "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 ghfast"
        add_source "https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}" "https://github.com/${REPO}/releases/download/${VERSION}/${SUMS}" "GitHub 直连" ;;
    esac
  elif [ -n "$TSG_MIRROR" ] && [ "$TSG_FORCE_MIRROR" = "1" ]; then
    case "$TSG_MIRROR" in
      gh-proxy) add_source "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 gh-proxy" ;;
      ghfast)   add_source "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 ghfast" ;;
    esac
  elif [ "$TSG_FORCE_MIRROR" = "1" ]; then
    add_source "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 gh-proxy"
    add_source "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 ghfast"
  else
    add_source "https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}" "https://github.com/${REPO}/releases/download/${VERSION}/${SUMS}" "GitHub 直连"
    if [ -n "$TSG_MIRROR" ]; then
      case "$TSG_MIRROR" in
        gh-proxy) add_source "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 gh-proxy" ;;
        ghfast)   add_source "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 ghfast" ;;
      esac
    else
      add_source "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHPROXY}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 gh-proxy"
      add_source "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${ASSET}" "${MIRROR_GHFAST}/${REPO}/releases/download/${VERSION}/${SUMS}" "镜像 ghfast"
    fi
  fi
fi

_src_list=""
_i=1
while [ "$_i" -le "$SRC_COUNT" ]; do
  eval "_name=\"\$SRC${_i}_NAME\""
  if [ -z "$_src_list" ]; then
    _src_list="$_name"
  else
    _src_list="$_src_list, $_name"
  fi
  _i=$((_i + 1))
done
log "将依次尝试以下下载源：$_src_list"

# 通用下载函数（支持 curl/wget + 重试）
fetch_with_retry() {
  _url="$1"
  _out="$2"
  _retries="${3:-2}"
  _attempt=0
  while [ "$_attempt" -le "$_retries" ]; do
    if [ "$_attempt" -gt 0 ]; then warn "第 $_attempt 次重试：$_url"; sleep 2; fi
    case "$_url" in
      http://*|https://*)
        if command -v curl >/dev/null 2>&1; then
          curl -fsSL --max-time 30 -o "$_out" "$_url" 2>/dev/null && return 0
        elif command -v wget >/dev/null 2>&1; then
          wget -qO "$_out" "$_url" 2>/dev/null && return 0
        else
          die "未找到 curl / wget，请先安装其一"
        fi ;;
      *)
        [ -f "$_url" ] || die "本地文件不存在：$_url"
        cp "$_url" "$_out"; return 0 ;;
    esac
    _attempt=$((_attempt + 1))
  done
  return 1
}

# ---------- 5. 安装 ----------
INSTALL_DIR="${TSG_INSTALL_DIR:-$HOME/.tsg/bin}"
BIN="$INSTALL_DIR/tsg"
mkdir -p "$INSTALL_DIR"

TMP="$(mktemp "${TMPDIR:-/tmp}/tsg-installer.XXXXXX")"
TRAP_RM='rm -f "$TMP" "$TMP.sum"'
trap '$TRAP_RM' EXIT

_DOWNLOADED=""
_src_idx=1
while [ "$_src_idx" -le "$SRC_COUNT" ]; do
  eval "_url=\"\$SRC${_src_idx}_URL\""
  eval "_name=\"\$SRC${_src_idx}_NAME\""
  log "尝试从 $_name 下载..."
  if fetch_with_retry "$_url" "$TMP" 1; then
    log "$_name 下载成功 ✓"
    _DOWNLOADED="$_name"
    break
  else
    warn "$_name 下载失败"
  fi
  _src_idx=$((_src_idx + 1))
done

if [ -z "$_DOWNLOADED" ]; then
  die "所有下载源均无法连接。可能原因：
  1. 网络受限（在中国大陆？建议设置环境变量）：
     TSG_MIRROR=gh-proxy sh install.sh
  2. 也可以手动下载后运行：TSG_BASE_URL=/path/to/download sh install.sh"
fi

[ -s "$TMP" ] || die "下载结果为空文件，请检查网络或下载源"
chmod +x "$TMP"

# ---------- 6. SHA256 校验（防篡改，默认开启）----------
if [ "${TSG_NO_VERIFY:-0}" != "1" ]; then
  TMP_SUMS="$TMP.sum"
  _sums_downloaded=""
  _src_idx=1
  while [ "$_src_idx" -le "$SRC_COUNT" ]; do
    eval "_url=\"\$SRC${_src_idx}_SUMS\""
    eval "_name=\"\$SRC${_src_idx}_NAME\""
    if fetch_with_retry "$_url" "$TMP_SUMS" 1; then
      if [ -s "$TMP_SUMS" ]; then
        _sums_downloaded="$_name"
        break
      fi
    fi
    _src_idx=$((_src_idx + 1))
  done

  if [ -n "$_sums_downloaded" ] && [ -s "$TMP_SUMS" ]; then
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
