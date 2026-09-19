@echo off
setlocal
cd /d "%~dp0"
echo ============================================
echo   TarsSecureGuard - One-click Build (v1.0.0)
echo ============================================
echo.

where go >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Go 未安装或不在 PATH 中。
  echo         请先从 https://go.dev/dl/ 下载并安装 Go，然后重试。
  exit /b 1
)

if not exist dist mkdir dist

echo [1/3] 编译 go-app（多文件模块化）...
cd go-app
go build -o "..\dist\TarsSecureGuard.exe" .
if errorlevel 1 (
  echo [ERROR] 编译失败，请检查上面的错误信息。
  exit /b 1
)
cd ..

if not exist dist\config.json (
  echo [2/3] 生成初始配置文件 dist\config.json ...
  echo {"security":{"wafEnabled":true,"mode":"normal"},"search":{"engine":"builtin"},"mcp":{"externalServers":[]}}> dist\config.json
) else (
  echo [2/3] dist\config.json 已存在，跳过生成。
)

echo [3/3] 完成！
echo.
echo   输出文件: dist\TarsSecureGuard.exe
echo   双击运行后访问: http://127.0.0.1:18889
echo.
pause
