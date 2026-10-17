# Auto-update 工作原理

## 1. 概述

TSG v4.15.0 引入自动更新系统，支持：

- 启动时自动检查新版本（非阻塞）
- CLI 手动检查/应用/回退
- 24 小时周期守护检查
- SHA256SUMS 校验 + 原子替换
- GitHub API 失败时回退 `stable_versions.json`

## 2. 更新流程

```
┌──────────────┐
│  检查新版本   │ ← GitHub API /latest
└──────┬───────┘
       │ 发现新版本
       ▼
┌──────────────┐
│  下载二进制   │ ← release-assets.githubusercontent.com
│  + SHA256SUMS │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  SHA256 校验  │ ← 比对 SHA256SUMS.txt
└──────┬───────┘
       │ 校验通过
       ▼
┌──────────────┐
│  备份旧二进制 │ ← 重命名为 .backup
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  原子替换     │ ← .new → 原文件
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  自重启       │ ← fork+exec (Unix) / PowerShell helper (Win)
└──────────────┘
```

## 3. 回退机制

```bash
# 命令行回退
./tsg update rollback

# 手动恢复
mv tsg.backup tsg
```

## 4. Stable Versions 回退

当 GitHub API 不可用时：

1. 读取 `~/.tars/stable_versions.json`
2. 使用本地缓存的最新稳定版本
3. 仍尝试下载该版本（CDN 可能可用）

## 5. 跨仓库同步

`stable_versions.json` 同时记录 6 个仓库的稳定版本：

```json
{
  "TarsSecureGuard": "v4.15.0",
  "TarsEnterprise": "v0.3.0",
  "TarsWingGuard": "v0.2.0",
  "TarsOpenClawSandbox": "v0.2.0",
  "TarsVoiceCorrection": "v0.2.0",
  "TarsUITarsBridge": "v0.2.0",
  "_last_sync": "2026-10-17T21:00:00+08:00"
}
```

## 6. 安全考虑

- 所有下载经 SHA256 校验
- 旧二进制保留 `.backup` 7 天
- 校验失败自动中止，不替换
- 极致档 (v4.17.x) 升级需 2FA 确认

## 7. API 参考

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/admin/update/status` | 当前版本 + 稳定版 |
| GET | `/api/admin/update/check` | 检查新版本 |
| POST | `/api/admin/update/apply` | 应用并重启 |
| POST | `/api/admin/update/rollback` | 回退版本 |
