# =============================================================
# TarsSecureGuard v3.0.1 - Tier 1 Windows hardware probe
# 锦衣卫裁定 TSG-TIER1-2026-0929 [TIER1_EXEC_MANDATORY]/[TIER1_ALLOWLIST]:
#   本脚本是 Windows 平台唯一允许的 Tier 1 探测形态
#   （powershell.exe -File + 预置脚本，SHA-256 由宿主校验）。
#   只读静态硬件属性，不写任何状态、不联网、不提权。
#   输出：单个 JSON 字符串（经 -OutputFormat XML 的 CLIXML <S> 节点包裹）
# =============================================================
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

$r = [ordered]@{
    gpu         = ''
    cpuModel    = ''
    systemModel = ''
    board       = ''
}

try {
    $g = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue |
         Where-Object { $_.Name -and $_.Name -notmatch 'Microsoft Basic Display Adapter' } |
         Select-Object -First 1
    $r.gpu = [string]$g.Name
} catch {}

try {
    $c = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue |
         Select-Object -First 1
    $r.cpuModel = [string]$c.Name
} catch {}

try {
    $s = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue |
         Select-Object -First 1
    $r.systemModel = ([string]$s.Manufacturer + ' ' + [string]$s.Model).Trim()
} catch {}

try {
    $b = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue |
         Select-Object -First 1
    $r.board = ([string]$b.Manufacturer + ' ' + [string]$b.Product).Trim()
} catch {}

Write-Output ($r | ConvertTo-Json -Compress)
