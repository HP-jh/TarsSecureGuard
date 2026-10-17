# Release 模板

> 本模板供维护者在 GitHub Actions 自动生成 release notes 后，补充「用户视角」说明用。
> 不替代自动生成的 commit/PR 列表，而是叠加在之上。

---

## 🚀 本次更新亮点

（一句话概括本次版本的核心价值，面向非技术用户）

---

## ✨ 新功能

- 

## 🔐 安全修复

- 

## ⚡ 性能改进

- 

## 🐛 Bug 修复

- 

## 📚 文档与引导

- 

---

## ⬆️ 升级指引

### 全新安装

```bash
# Linux / macOS
curl -fsSL https://hp-jh.github.io/TarsSecureGuard/install.sh | bash

# Windows
irm https://hp-jh.github.io/TarsSecureGuard/install.ps1 | iex
```

### 存量升级

直接替换二进制即可，config.json 自动兼容。升级前建议备份配置：

```bash
cp config.json config.json.bak
```

### 验证安装

```bash
./tsg version        # 应显示 vX.Y.Z
./tsg doctor         # 全过为正常
```

---

## 📦 资产清单

| 平台 | 文件名 | 说明 |
|------|--------|------|
| Linux amd64 | `tsg-vX.Y.Z-linux-amd64` | 主流服务器/桌面 |
| Linux arm64 | `tsg-vX.Y.Z-linux-arm64` | 树莓派/ARM 服务器 |
| macOS Intel | `tsg-vX.Y.Z-darwin-amd64` | Intel Mac |
| macOS Apple Silicon | `tsg-vX.Y.Z-darwin-arm64` | M1/M2/M3/M4 |
| Windows x64 | `tsg-vX.Y.Z-windows-amd64.exe` | Win10/11 |
| Windows ARM64 | `tsg-vX.Y.Z-windows-arm64.exe` | Snapdragon X 等 |
| Android ARM64 | `tsg-vX.Y.Z-android-arm64` | Android 终端 |
| 校验文件 | `SHA256SUMS.txt` | 全资产 SHA-256 |

> `darwin` / `windows.exe` 默认 unsigned（无 codesign/EV 凭证）。

---

## 🔗 相关链接

- 完整变更日志：[CHANGELOG.md](../../CHANGELOG.md)
- 版本规范：[VERSIONING.md](../../VERSIONING.md)
- 官方介绍站：https://hp-jh.github.io/TarsSecureGuard/
- 一键下载页：https://hp-jh.github.io/TarsSecureGuard/download.html
