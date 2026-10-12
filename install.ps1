# TarsSecureGuard 统一安装器（Windows）
# 自动识别 CPU 架构，下载对应二进制并完成安装，无需手动选版本。
#
# 一键安装（PowerShell）：
#   irm https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.ps1 | iex
# 或下载统一安装包 tsg-setup.zip 后运行：
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# 可选参数：
#   -Version <tag>     指定版本（默认 latest；可写 v4.7.0 或 4.7.0）
#   -BaseUrl <镜像/本地目录>
#   -InstallDir <目录>
#   -NoShortcut        不创建桌面快捷方式
#   -NoVerify          跳过 SHA256 校验（不建议）
param(
  [string]$Version = "latest",
  [string]$BaseUrl = "",
  [string]$InstallDir = "",
  [switch]$NoShortcut,
  [switch]$NoVerify
)

$ErrorActionPreference = "Stop"
$Repo = "HP-jh/TarsSecureGuard"
$Gh = "https://github.com/$Repo/releases"

function Write-Info($msg) { Write-Host "[tsg] $msg" -ForegroundColor Cyan }
function Write-Warn2($msg) { Write-Host "[tsg] $msg" -ForegroundColor Yellow }
function Write-Die($msg)  { Write-Host "[tsg] 错误：$msg" -ForegroundColor Red; exit 1 }

# ---------- 1. 识别 CPU 架构 ----------
switch ($env:PROCESSOR_ARCHITECTURE) {
  "AMD64" { $Arch = "amd64" }
  "ARM64" { $Arch = "arm64" }
  default { Write-Die "暂不支持的 CPU 架构：$($env:PROCESSOR_ARCHITECTURE)（当前提供 amd64 / arm64）" }
}

# ---------- 2. 解析版本号（latest → 具体 vX.Y.Z）----------
# Release 资产命名形如 tsg-v4.7.0-windows-amd64.exe，latest 时需先拿到真实版本号。
if ($Version -eq "latest") {
  try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing -TimeoutSec 20
    $Version = $rel.tag_name
  } catch {
    try {
      # 兜底：跟随 releases/latest 的 302 跳转，URL 末段即 tag
      $resp = [System.Net.HttpWebRequest]::Create("$Gh/latest")
      $resp.AllowAutoRedirect = $false
      $resp.Timeout = 20000
      $loc = $resp.GetResponse().Headers["Location"]
      $Version = ($loc -split "/")[-1]
    } catch {
      Write-Die "无法获取最新版本号（网络受限？）。请手动指定：install.ps1 -Version v4.7.0"
    }
  }
}
if ($Version -notmatch '^v') { $Version = "v$Version" }

$Asset = "tsg-$Version-windows-$Arch.exe"
$SumsAsset = "SHA256SUMS.txt"
Write-Info "检测到 windows/$Arch，目标组件 $Asset（版本 $Version）"

# ---------- 3. 确定下载源 ----------
if ($BaseUrl -ne "") {
  $Src = "$($BaseUrl.TrimEnd('/'))/$Asset"
  $SrcSums = "$($BaseUrl.TrimEnd('/'))/$SumsAsset"
} else {
  $Src = "$Gh/download/$Version/$Asset"
  $SrcSums = "$Gh/download/$Version/$SumsAsset"
}
Write-Info "使用下载源：$Src"

# ---------- 4. 安装 ----------
if ($InstallDir -eq "") { $InstallDir = Join-Path $env:LOCALAPPDATA "TarsSecureGuard" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Bin = Join-Path $InstallDir "tsg.exe"
$Tmp = Join-Path $env:TEMP "tsg-installer-$PID.exe"

function Fetch-It($url, $out) {
  if ($url -match '^https?://') {
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
  } else {
    $local = $url -replace '^file://', ''
    if (Test-Path $local) { Copy-Item $local $out -Force }
    else { Write-Die "本地文件不存在：$local" }
  }
}

try {
  Fetch-It $Src $Tmp
} catch {
  Write-Die "下载失败：$($_.Exception.Message)"
}
if ((Test-Path $Tmp) -and (Get-Item $Tmp).Length -eq 0) { Write-Die "下载结果为空文件，请检查网络或下载源" }

# ---------- 5. SHA256 校验（防篡改，默认开启）----------
if (-not $NoVerify) {
  $TmpSums = Join-Path $env:TEMP "tsg-sums-$PID.txt"
  $ok = $true
  try { Fetch-It $SrcSums $TmpSums } catch { $ok = $false; Write-Warn2 "无法下载 SHA256SUMS.txt（网络受限？），跳过校验" }
  if ($ok -and (Test-Path $TmpSums)) {
    $want = $null
    foreach ($line in (Get-Content $TmpSums)) {
      if ($line -match '^([0-9a-fA-F]{64})\s.*' + [regex]::Escape($Asset)) { $want = $Matches[1]; break }
    }
    if ($want) {
      $got = (Get-FileHash -Algorithm SHA256 -Path $Tmp).Hash.ToLower()
      if ($got -ne $want.ToLower()) {
        Remove-Item $Tmp -Force -ErrorAction SilentlyContinue
        Remove-Item $TmpSums -Force -ErrorAction SilentlyContinue
        Write-Die "SHA256 校验失败！`n    期望 $want`n    实际 $got`n    文件可能损坏或被篡改，已中止安装。"
      }
      Write-Info "SHA256 校验通过 ✓"
    } else {
      Write-Warn2 "SHA256SUMS.txt 中未找到 $Asset 条目，跳过校验"
    }
  }
  Remove-Item $TmpSums -Force -ErrorAction SilentlyContinue
}

Move-Item -Path $Tmp -Destination $Bin -Force
Write-Info "已安装：$Bin"

# ---------- 6. 写入用户 PATH（幂等）----------
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
  Write-Info "已将 $InstallDir 加入用户 PATH（重开终端后生效）"
}

# ---------- 7. 桌面快捷方式（双击即启动面板）----------
if (-not $NoShortcut) {
  try {
    $WshShell = New-Object -ComObject WScript.Shell
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $Lnk = $WshShell.CreateShortcut((Join-Path $Desktop "TarsSecureGuard.lnk"))
    $Lnk.TargetPath = $Bin
    $Lnk.WorkingDirectory = $InstallDir
    $Lnk.Description = "AI 网关 · 路由器与配置器（启动后面板自动打开）"
    $Lnk.Save()
    Write-Info "已创建桌面快捷方式：$Desktop\TarsSecureGuard.lnk（双击即启动）"
  } catch {
    Write-Warn2 "桌面快捷方式创建失败（$($_.Exception.Message)），可手动运行 tsg 启动"
  }
}

# ---------- 8. 快速开始 ----------
Write-Info "安装完成！启动方式："
Write-Host "  双击桌面「TarsSecureGuard」快捷方式"
Write-Host "  tsg            # 启动网关，面板自动打开 http://127.0.0.1:18889"
Write-Host "  tsg doctor     # 环境自检"
Write-Host "  卸载：删除 $InstallDir 即可"
