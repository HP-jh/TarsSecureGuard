# TarsSecureGuard 版本规范

> 本文档定义 TarsSecureGuard 的版本号语义、发布流程与分支策略。
> 生效日期：2026-10-15，从此版本起严格执行。历史已发布版本保持不动。

---

## SemVer 规范

本项目遵循 [Semantic Versioning 2.0.0](https://semver.org/lang/zh-CN/)：

| 级别 | 含义 | 示例 |
|------|------|------|
| **主版本（MAJOR）** | 大架构变更、破坏性 API 修改、协议升级 | v4.x → v5.x Kingdom 架构重写 |
| **次版本（MINOR）** | 新增功能模块、显著能力扩展 | v4.8 LangProbe / v4.9 Kingdom |
| **修订版本（PATCH）** | Bug 修复、安全补丁、兼容性修复、性能优化 | v4.7.8 release 修复 |

版本号格式：`v{MAJOR}.{MINOR}.{PATCH}`，示例：`v4.9.0`、`v4.7.8`。

---

## 历史版本号整改说明

2026-10-15 之前的版本存在以下不规范现象，**已发布的 tag 与 Release 资产不重命名、不删除**，仅从下一版本起严格执行：

| 问题 | 整改前 | 整改后 |
|------|--------|--------|
| 版本号跳跃 | v4.7.6 → v4.7.8（跳过 .7） | 连续递增，禁止跳号 |
| B 系列标记写入 tag/release 标题 | `v4.7.6 — B18 性能：...` | B 系列标记改为 GitHub Topics / Label / Milestone 管理，不再写入 tag 名或 release 标题 |
| 命名风格混用 | 既有 `v4.7.6 — B18...` 又有 `v4.9.0 — Kingdom...` | 统一为 `vX.Y.Z` 或简短的变更主题 |

---

## 发布流程

```
开发完成 → 更新版本号（main / 版本锁测试 / 前端徽章同步）→ 本地验证（go test -race ./...）
  → 打 tag（git tag -a vX.Y.Z）→ push tag（git push origin vX.Y.Z）
  → GitHub Actions 自动构建多平台二进制 + Tauri 客户端 + Android
  → Actions 自动生成 Release Notes（基于 commit + PR 标签）
  → 维护者补充人工视角说明（使用 .github/RELEASE_TEMPLATE.md）
  → CHANGELOG.md 自动追加新节（Actions 触发）
  → Bitable「版本」表同步（webhook 或 Actions）
```

### 版本号锁定检查清单

- [ ] `main.go` 中的 `version` 常量/var
- [ ] 前端 `frontend/index.html` 版本徽章
- [ ] `vXXX_test.go` 版本锁测试（如存在）
- [ ] `go.mod` 的 `go` 版本行（工具链升级时）
- [ ] `docs/` 中对应版本的文档文件已创建

---

## 分支策略

| 分支/标签 | 用途 | 规则 |
|-----------|------|------|
| `main` | 主开发分支 | 永远可构建，`go test -race ./...` 全绿才可 push |
| `vX.Y.Z` tag | 发布点 | 不可变，一旦推送不 force-delete；发现严重问题打新 PATCH tag |
| 无长期维护分支 | — | 旧版本不单独 backport，安全修复走最新 PATCH |

---

## 与周边系统衔接

- **GitHub Releases**：单一可信源，所有二进制资产由此分发
- **GitHub Pages 介绍站**（`site/`）：`pages.yml` 在 release published 时自动重新部署
- **Bitable「TSG 项目中枢」**：每次 release 通过 webhook 或 Actions 向「版本」表写入一条记录
- **CHANGELOG.md**：本仓库根目录单文件，Keep a Changelog 格式，Actions 自动维护
