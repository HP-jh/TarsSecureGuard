# TSG Kingdom — 动物分类学架构

## 分类层级（7层，超过5层要求）

```
界 Kingdom    → TarsSecureGuard 系统整体
├─ 门 Phylum   → 4大系统层
│  ├─ 防护层 Protectiva
│  ├─ 功能层 Functionalis
│  ├─ 前端层 Frontend
│  └─ 后端层 Backend
│
├─ 纲 Class    → 大类划分（如网络安全、数据安全、应用安全、系统安全）
├─ 目 Order    → 子类划分（如外网防护、MCP安全、WAF、动态防御）
├─ 科 Family   → 模块族（如URL拦截科、MCP扫描科、规则引擎科）
├─ 属 Genus    → 具体模块（如静态扫描属、动态扫描属）
└─ 种 Species  → 策略实例/职业适配（如AI调用扫描种、开发者防护种）
```

## 目录映射

```
kingdom/
├── phylum/
│   ├── protectiva/     # 防护层 — 按纲/目/科/属/种组织
│   ├── functionalis/   # 功能层
│   ├── frontend/       # 前端层（千问级UI）
│   └── backend/        # 后端层
├── taxonomy.go         # 分类学核心接口
└── registry.go         # 模块注册中心
```

## 防护层深入（Protectiva Phylum）

```
防护层 Protectiva
├─ 纲 Classis-NetSecurity      网络安全
│  ├─ 目 Ordo-Extranet          外网防护
│  │  ├─ 科 Fam-URLBlock        URL拦截
│  │  │  ├─ 属 Gen-URLFilter    域名过滤
│  │  │  └─ 属 Gen-URLScan      URL扫描
│  │  └─ 科 Fam-DNSGuard        DNS防护
│  ├─ 目 Ordo-Intranet          内网隔离
│  └─ 目 Ordo-MCPSecurity       MCP工具安全 ← 重点
│     ├─ 科 Fam-MCPScan         MCP扫描
│     │  ├─ 属 Gen-StaticScan   静态扫描
│     │  └─ 属 Gen-DynamicScan  动态扫描
│     ├─ 科 Fam-MCPCategory     MCP分类
│     └─ 科 Fam-MCPMatch        MCP任务匹配
│
├─ 纲 Classis-DataSecurity     数据安全
│  ├─ 目 Ordo-TransitEncrypt   传输加密
│  ├─ 目 Ordo-StorageEncrypt   存储加密
│  └─ 目 Ordo-PIIProtect       PII防护
│
├─ 纲 Classis-AppSecurity      应用安全
│  ├─ 目 Ordo-WAF              WAF
│  ├─ 目 Ordo-SemanticGuard    语义检测
│  └─ 目 Ordo-RBAC             RBAC
│
└─ 纲 Classis-SysSecurity      系统安全
   ├─ 目 Ordo-AuditChain       审计链
   ├─ 目 Ordo-RealtimeMonitor  实时监控
   └─ 目 Ordo-DynamicDefense   动态防御
      ├─ 科 Fam-RuleAdapt      规则自适应
      ├─ 科 Fam-MLThreat       ML威胁情报
      └─ 科 Fam-HotReload      实时参数热重载
```

## 职业→防护策略映射

| 职业 | 主要目(Order)防护重点 | 关键模块开关 |
|------|----------------------|------------|
| Developer | MCP安全、WAF、语义检测 | 代码扫描、依赖检查 |
| Admin | 系统安全、审计链、动态防御 | 全模块可见 |
| Analyst | 数据安全、PII防护 | 数据脱敏、导出审计 |
| User | 外网防护、基础WAF | 简化界面，自动模式 |
| AI-Operator | MCP安全（重点）、外网防护 | AI调用专用规则 |

## 多语言利用

| 层级 | Go | Python | PowerShell | Node.js | eBPF/C |
|------|----|--------|-----------|---------|--------|
| 核心网关 | ★ | | | | |
| WAF/路由 | ★ | | | | |
| MCP扫描 | ★ | ★ | ★ | | |
| 防火墙 | ★ | ★(Linux) | ★(Win) | | |
| 实时监控 | ★ | | | | ★(Linux) |
| 动态防御 | ★ | ★(ML) | | | ★(内核) |
| 前端UI | | | | ★ | |
| 日志分析 | ★ | ★ | ★(Win) | | |
