@echo off
rem ============================================================
rem  TarsSecureGuard v2.1.0 一键启动脚本（Windows）
rem  - 检测已编译的 tars-secure-guard.exe，不存在则自动编译
rem  - 启动服务并显示管理面板地址
rem ============================================================
chcp 65001 >nul
title TarsSecureGuard v2.1.0
cd /d "%~dp0"

echo ==================================================
echo   TarsSecureGuard v2.1.0 启动中...
echo ==================================================

rem ---- 检测是否已编译 ----
if exist tars-secure-guard.exe (
    echo [OK] 检测到已编译程序 tars-secure-guard.exe
    goto :run
)

rem ---- 未编译则自动编译 ----
echo [INFO] 未检测到可执行文件，开始自动编译...
where go >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 Go 编译器，请先安装 Go 1.22+ 并将其加入 PATH
    pause
    exit /b 1
)
go build -o tars-secure-guard.exe
if errorlevel 1 (
    echo [错误] 编译失败，请检查源码完整性或 Go 环境配置
    pause
    exit /b 1
)
echo [OK] 编译完成

:run
echo.
echo   管理面板地址: http://127.0.0.1:18889
echo   浏览器将自动打开；如未打开请手动访问上述地址
echo   按 Ctrl+C 可优雅关闭服务
echo.

tars-secure-guard.exe

echo.
echo [INFO] 服务已退出
pause
