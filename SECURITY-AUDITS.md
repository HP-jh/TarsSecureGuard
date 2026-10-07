# TarsSecureGuard 安全审计索引

本仓库所有第三方安全审计报告的索引。报告内容覆盖红队黑盒渗透测试、自动化攻击向量验证、修复对照、对外宣传基线数据。

## 审计报告列表

| 版本 | 报告链接 | 审计日期 | 测试范围 | 关键结论 |
|------|---------|---------|---------|---------|
| **v3.7.1** | [docs/security-audit-v3.7.1.md](docs/security-audit-v3.7.1.md) | 2026-10-07 | 200+ 攻击向量 / 15 个测试域 | v3.2.5 已知 4 项 P0/P1 风险 100% 闭环 · 11 项新增加固 9 项实测生效 · 0 个 CRITICAL/HIGH · 1 个 MEDIUM（共享信息 XSS） |
| v3.7.0 | （内部评估） | 2026-10-06 | isPathAllowed EvalSymlinks / 守门人 config 写覆盖 / WAF 编码绕过 / config 解析告警 / tars_fetch_url SSRF | 5 项 P0/P1 修复建议 |
| v3.2.5 | <https://my.feishu.cn/docx/QOnPd9mjmoDJokxhZZgcKOi9n6e> | 2026-09 | 红队初轮黑盒 | 4 项 P0/P1 + 5 项低优 |

## 当前基线版本

**v3.7.1** —— 已是宣传基线版本：

- 纵深防御五层独立不变量（WAF / 语义 / 守门人 / 审计 / 隔离）实测通过
- 默认密钥零信任 + 启动时强制校验（`enforceBootstrapKeyPolicy`）
- 限速键基于 socket 对端 IP（`trusted_proxies` 列表之外的 X-Forwarded-For 不计入）
- 审计链 v2 SHA-256 hash-chain + 按日切文件 + 全链重算
- 11 项安全加固 9 项经实测验证生效

## 待修项（v3.7.2 候选）

- 共享信息 title/content 字段 HTML 转义（CWE-79，P1）
- 健康检查端点去除版本号（低危）
- CSP `unsafe-inline` 评估收敛（低危）

## 测试脚本归档

所有审计配套的渗透测试脚本归档在 `docs/security-audit/<version>/` 目录，可独立重放。