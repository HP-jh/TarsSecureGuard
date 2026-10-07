# TarsSecureGuard v3.0.0 E 线：Windows PowerShell 8 小时循环压测脚本
# 用法：.\soak.ps1 [-DurationSec 28800] [-Base http://127.0.0.1:18889]
param([int]$DurationSec = 28800, [string]$Base = "http://127.0.0.1:18889")
$Key = if ($env:TSG_API_KEY) { $env:TSG_API_KEY } else { "tars-gateway-key" }
$Out = "soak-report.csv"; $Start = Get-Date
"time,round,ok,fail,guard_tier,rss_mb,goroutines" | Set-Content $Out
$round = 0; $ok = 0; $fail = 0
while (((Get-Date) - $Start).TotalSeconds -lt $DurationSec) {
  $round++
  for ($i = 1; $i -le 20; $i++) {
    try {
      $body = @{messages = @(@{role = "user"; content = "压测第${round}轮第${i}条"})} | ConvertTo-Json -Depth 5
      $r = Invoke-WebRequest -Uri "$Base/api/chat/completions" -Method Post -Headers @{"X-API-Key" = $Key} -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 10
      if ($r.StatusCode -in 200, 403, 429, 503) { $ok++ } else { $fail++ }
    } catch { $fail++ }
  }
  try {
    $g = Invoke-RestMethod -Uri "$Base/api/admin/guard/status" -Headers @{"X-API-Key" = $Key} -TimeoutSec 10
    "$((Get-Date).ToString('HH:mm:ss')),$round,$ok,$fail,$($g.tier),$($g.rssMB),$($g.goroutines)" | Add-Content $Out
    Write-Host "[soak] 第 $round 轮 ok=$ok fail=$fail tier=$($g.tier) rss=$($g.rssMB)MB"
  } catch { Write-Host "[soak] 第 $round 轮 ok=$ok fail=$fail guard 状态不可达" }
  Start-Sleep -Seconds 300
}
Write-Host "[soak] 完成：共 $round 轮，ok=$ok fail=$fail，报告已写入 $Out"
