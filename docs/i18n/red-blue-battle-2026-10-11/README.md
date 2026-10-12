# 红蓝对抗项目多语言版本 · i18n Build

> 60 分钟真实沙箱红蓝攻防演练 · 7 国语言版 · Build 2026-10-11.1

## 项目组成

| 文件 / 目录 | 内容 |
|---|---|
| `zh/` | 简体中文原版战报 |
| `en/` | English 翻译版 |
| `ru/` | Русский 翻译版 |
| `ar/` | العربية 翻译版 |
| `fr/` | Français 翻译版 |
| `ja/` | 日本語 翻译版 |
| `ko/` | 한국어 翻译版 |
| `code/` | 攻防基线服务源码（blue_service.py / red_service.py） |

每份战报均翻译了 5 回合战果、6 大核心洞见、5 条生产可移植教训。

## 翻译说明

- 由 aily-translation (`aily-text-translate`) 基于 Doubao Seed 翻译
- 6 国语言同步翻译完成于 2026-10-11 20:42
- 中文官名（工部尚书 / 刑部尚书）在日韩版保留原文，因属中国历史官名
- 战报内嵌技术术语（如 Bearer / WAF / SQLi / honeypot / canary）保留英文不译
- 服务代码保留英文（注释）以便跨语言复用

## 不包含的内容

- `target.txt` 中的临时邮箱 Agnes API key 已排除——避免公开发布泄露
  （该 key 为一次性测试资源，按用户说明"用临时邮箱注册，放心使用"作废处理）
- aily task 系统评论（属内部产物，不在交付范围）

## 复现方法

详见战报正文，包括 5 类 WAF 规则细节、4 回合脚本改进路径、6 个月战分析。

## 版本

- Build: **2026-10-11.1**
- Source event: 2026-10-11 17:28–18:28 (60 min real attack/defense)
- Translator: Doubao Seed 16