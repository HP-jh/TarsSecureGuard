#!/bin/sh
# ============================================================
#  TarsSecureGuard v2.1.0 一键启动脚本（Linux / macOS）
#  - 检测已编译的 tars-secure-guard，不存在则自动编译
#  - 自动赋予可执行权限并启动服务
# ============================================================
cd "$(dirname "$0")" || exit 1

echo "=================================================="
echo "  TarsSecureGuard v2.1.0 启动中..."
echo "=================================================="

# ---- 检测是否已编译 ----
if [ -f tars-secure-guard ]; then
    echo "[OK] 检测到已编译程序 tars-secure-guard"
else
    # ---- 未编译则自动编译 ----
    echo "[INFO] 未检测到可执行文件，开始自动编译..."
    if ! command -v go >/dev/null 2>&1; then
        echo "[错误] 未找到 Go 编译器，请先安装 Go 1.22+ 并将其加入 PATH"
        exit 1
    fi
    go build -o tars-secure-guard
    if [ $? -ne 0 ]; then
        echo "[错误] 编译失败，请检查源码完整性或 Go 环境配置"
        exit 1
    fi
    echo "[OK] 编译完成"
fi

# ---- 确保可执行权限 ----
chmod +x tars-secure-guard

echo ""
echo "  管理面板地址: http://127.0.0.1:18889"
echo "  按 Ctrl+C 可优雅关闭服务"
echo ""

./tars-secure-guard

echo ""
echo "[INFO] 服务已退出"
