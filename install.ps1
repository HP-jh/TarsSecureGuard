# TarsSecureGuard 统一安装器（Windows）
# 自动识别 CPU 架构，下载对应二进制并完成安装，无需手动选版本。
#
# 一键安装（PowerShell）：
#   irm https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.ps1 | iex
# 或下载统一安装包 tsg-setup.zip 后运行：
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# 可选参数：-Version <tag>（默认 latest）、-BaseUrl <镜像/本地目录>、-InstallDir <目录>
param(
  [string]$Version = "latest",
  [string]$BaseUrl = "",
  [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"
$Repo = "HP-jh/TarsSecureGuard"
$Gh = "https://github.com/$Repo/releases"

function Write-Info($msg) { Write-Host "[tsg] $msg" -ForegroundColor Cyan }
function Write-Die($msg)  { Write-Host "[tsg] 错误：$msg" -ForegroundColor Red; exit 1 }

# ---------- 1. 识别 CPU 架构 ----------
switch ($env:PROCESSOR_ARCHITECTURE) {
  "AMD64" { $Arch = "amd64" }
  "ARM64" { $Arch = "arm64" }
  default { Write-Die "暂不支持的 CPU 架构：$($env:PROCESSOR_ARCHITECTURE)（当前提供 amd64 / arm64）" }
}

$Asset = "tsg-windows-$Arch.exe"
Write-Info "检测到 windows/$Arch，目标组件 $Asset（版本 $Version）"

# ---------- 2. 确定下载源 ----------
if ($BaseUrl -ne "") {
  $Src = "$($BaseUrl.TrimEnd('/'))/$Asset"
} elseif ($Version -eq "latest") {
  $Src = "$Gh/latest/download/$Asset"
} else {
  $Src = "$Gh/download/$Version/$Asset"
}
Write-Info "使用下载源：$Src"

# ---------- 3. 安装 ----------
if ($InstallDir -eq "") { $InstallDir = Join-Path $env:LOCALAPPDATA "TarsSecureGuard" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Bin = Join-Path $InstallDir "tsg.exe"

if ($Src -match '^https?://') {
  try {
    Invoke-WebRequest -Uri $Src -OutFile $Bin -UseBasicParsing
  } catch {
    Write-Die "下载失败：$($_.Exception.Message)"
  }
} else {
  # 本地目录 / file:// （离线安装统一安装包场景）
  $local = $Src -replace '^file://', ''
  if (Test-Path $local) { Copy-Item $local $Bin -Force }
  else { Write-Die "本地文件不存在：$local" }
}

if ((Get-Item $Bin).Length -eq 0) { Write-Die "下载结果为空文件，请检查网络或下载源" }
Write-Info "已安装：$Bin"

# ---------- 4. 写入用户 PATH（幂等）----------
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
  Write-Info "已将 $InstallDir 加入用户 PATH（重开终端后生效）"
}

# ---------- 5. 快速开始 ----------
Write-Info "安装完成！启动方式："
Write-Host "  tsg            # 启动网关，面板自动打开 http://127.0.0.1:18889"
Write-Host "  tsg doctor     # 环境自检"
Write-Host "  卸载：删除 $InstallDir 即可"
