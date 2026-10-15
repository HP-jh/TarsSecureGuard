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
#
# 环境变量（可选，中国大陆用户推荐）：
#   $env:TSG_MIRROR="gh-proxy"      强制使用国内镜像（gh-proxy / ghfast）
#   $env:TSG_FORCE_MIRROR=1         跳过 GitHub 直连，直接使用镜像
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

# ---------- 0. 强制 TLS 1.2（Windows 默认 1.0 会连不上 GitHub）----------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Info($msg)  { Write-Host "[tsg] $msg" -ForegroundColor Cyan }
function Write-Warn2($msg) { Write-Host "[tsg] $msg" -ForegroundColor Yellow }
function Write-Die($msg)   { Write-Host "[tsg] 错误：$msg" -ForegroundColor Red; exit 1 }

# ---------- 镜像源配置 ----------
$Mirrors = @{
  "gh-proxy" = "https://gh-proxy.com/https://github.com"
  "ghfast"   = "https://ghfast.top/https://github.com"
}
$MirrorKeys = @("gh-proxy", "ghfast")

$EnvMirror = $env:TSG_MIRROR
$ForceMirror = ($env:TSG_FORCE_MIRROR -eq "1")

if ($EnvMirror -and -not $Mirrors.ContainsKey($EnvMirror)) {
  Write-Warn2 "未知镜像 '$EnvMirror'，已知镜像：$($MirrorKeys -join ', ')。将使用默认策略。"
  $EnvMirror = ""
}

# ---------- 1. 识别 CPU 架构 ----------
switch ($env:PROCESSOR_ARCHITECTURE) {
  "AMD64" { $Arch = "amd64" }
  "ARM64" { $Arch = "arm64" }
  default { Write-Die "暂不支持的 CPU 架构：$($env:PROCESSOR_ARCHITECTURE)（当前提供 amd64 / arm64）" }
}

# ---------- 2. 解析版本号（latest → 具体 vX.Y.Z）----------
function Resolve-Latest($base) {
  $api = "$base/api.github.com/repos/$Repo/releases/latest"
  try {
    $rel = Invoke-RestMethod -Uri $api -UseBasicParsing -TimeoutSec 10
    return $rel.tag_name
  } catch {
    # 兜底：跟随 releases/latest 的 302 跳转
    try {
      $resp = [System.Net.HttpWebRequest]::Create("$base/$Repo/releases/latest")
      $resp.AllowAutoRedirect = $false
      $resp.Timeout = 10000
      $loc = $resp.GetResponse().Headers["Location"]
      return ($loc -split "/")[-1]
    } catch { return $null }
  }
}

function Try-Resolve-Latest() {
  $candidates = @()
  if ($BaseUrl -ne "") {
    # 用户指定了自定义源
    return Resolve-Latest "https://github.com"
  }
  if ($EnvMirror -and -not $ForceMirror) {
    $candidates += $Mirrors[$EnvMirror]
    $candidates += "https://github.com"
  } elseif ($EnvMirror -and $ForceMirror) {
    $candidates += $Mirrors[$EnvMirror]
  } elseif ($ForceMirror) {
    foreach ($k in $MirrorKeys) { $candidates += $Mirrors[$k] }
  } else {
    $candidates += "https://github.com"
    if ($EnvMirror) { $candidates += $Mirrors[$EnvMirror] }
    else { foreach ($k in $MirrorKeys) { $candidates += $Mirrors[$k] } }
  }

  foreach ($base in $candidates) {
    $tag = Resolve-Latest $base
    if ($tag -and ($tag -match '^v[0-9]')) { return $tag }
  }
  return $null
}

if ($Version -eq "latest") {
  $Version = Try-Resolve-Latest
  if (-not $Version) {
    Write-Die @"
无法获取最新版本号。可能原因：
  1. 网络受限（在中国大陆？尝试设置环境变量后再运行）：
     `$env:TSG_MIRROR="gh-proxy"; irm ... | iex`
  2. GitHub 服务暂时不可用
  3. 也可以手动指定版本：install.ps1 -Version v4.9.0
"@
  }
}
if ($Version -notmatch '^v') { $Version = "v$Version" }

$Asset = "tsg-$Version-windows-$Arch.exe"
$SumsAsset = "SHA256SUMS.txt"
Write-Info "检测到 windows/$Arch，目标组件 $Asset（版本 $Version）"

# ---------- 3. 确定下载源（支持镜像 fallback）----------
function Make-Urls($base) {
  $assetUrl = "$base/$Repo/releases/download/$Version/$Asset"
  $sumsUrl  = "$base/$Repo/releases/download/$Version/$SumsAsset"
  return @{ Asset = $assetUrl; Sums = $sumsUrl }
}

function Get-Sources() {
  $list = @()
  if ($BaseUrl -ne "") {
    $list += @{ Asset = "$($BaseUrl.TrimEnd('/'))/$Asset"; Sums = "$($BaseUrl.TrimEnd('/'))/$SumsAsset"; Name = "自定义源" }
    return $list
  }
  if ($EnvMirror -and -not $ForceMirror) {
    $list += (Make-Urls $Mirrors[$EnvMirror]); $list[-1].Name = "镜像 $($EnvMirror)"
    $list += (Make-Urls "https://github.com"); $list[-1].Name = "GitHub 直连"
  } elseif ($EnvMirror -and $ForceMirror) {
    $list += (Make-Urls $Mirrors[$EnvMirror]); $list[-1].Name = "镜像 $($EnvMirror)"
  } elseif ($ForceMirror) {
    foreach ($k in $MirrorKeys) { $list += (Make-Urls $Mirrors[$k]); $list[-1].Name = "镜像 $($k)" }
  } else {
    $list += (Make-Urls "https://github.com"); $list[-1].Name = "GitHub 直连"
    if ($EnvMirror) { $list += (Make-Urls $Mirrors[$EnvMirror]); $list[-1].Name = "镜像 $($EnvMirror)" }
    else { foreach ($k in $MirrorKeys) { $list += (Make-Urls $Mirrors[$k]); $list[-1].Name = "镜像 $($k)" } }
  }
  return $list
}

$Sources = Get-Sources
Write-Info "将依次尝试以下下载源：$($Sources.Name -join ' → ')"

# ---------- 4. 下载（带重试和镜像 fallback）----------
if ($InstallDir -eq "") { $InstallDir = Join-Path $env:LOCALAPPDATA "TarsSecureGuard" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Bin = Join-Path $InstallDir "tsg.exe"
$Tmp = Join-Path $env:TEMP "tsg-installer-$PID.exe"

function Fetch-WithRetry($url, $out, $name, $retries = 2) {
  $lastErr = $null
  for ($i = 0; $i -le $retries; $i++) {
    try {
      if ($i -gt 0) { Write-Warn2 "第 $i 次重试：$name" }
      if ($url -match '^https?://') {
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 30
      } else {
        $local = $url -replace '^file://', ''
        if (Test-Path $local) { Copy-Item $local $out -Force }
        else { throw "本地文件不存在：$local" }
      }
      return $true
    } catch {
      $lastErr = $_
      if ($i -lt $retries) { Start-Sleep -Seconds 2 }
    }
  }
  return $lastErr
}

$Downloaded = $false
$UsedSource = $null
foreach ($src in $Sources) {
  Write-Info "尝试从 $($src.Name) 下载..."
  $result = Fetch-WithRetry $src.Asset $Tmp $src.Name
  if ($result -eq $true) {
    $Downloaded = $true
    $UsedSource = $src
    Write-Info "$($src.Name) 下载成功 ✓"
    break
  } else {
    Write-Warn2 "$($src.Name) 下载失败：$($result.Exception.Message)"
  }
}

if (-not $Downloaded) {
  Write-Die @"
所有下载源均无法连接。可能原因：
  1. 网络受限（在中国大陆？建议设置环境变量）：
     `$env:TSG_MIRROR="gh-proxy"; irm ... | iex`
  2. 也可以手动下载后运行：install.ps1 -BaseUrl "file:///C:/Users/你/Downloads"
"@
}

if ((Test-Path $Tmp) -and (Get-Item $Tmp).Length -eq 0) { Write-Die "下载结果为空文件，请检查网络或下载源" }

# ---------- 5. SHA256 校验（防篡改，默认开启）----------
if (-not $NoVerify) {
  $TmpSums = Join-Path $env:TEMP "tsg-sums-$PID.txt"
  $ok = $false
  foreach ($src in $Sources) {
    $result = Fetch-WithRetry $src.Sums $TmpSums "SHA256SUMS ($($src.Name))" 1
    if ($result -eq $true) { $ok = $true; break }
  }
  if ($ok -and (Test-Path $TmpSums) -and (Get-Item $TmpSums).Length -gt 0) {
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
  } else {
    Write-Warn2 "无法下载 SHA256SUMS.txt（网络受限？），跳过校验"
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
