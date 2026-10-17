# TarsSecureGuard 配置项详解

配置文件路径: `config.json`（默认在二进制同级目录）

## 顶层字段

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `apiKey` | string | `"tars-gateway-key"` | 网关 API 密钥 |
| `modules` | object | 全部 true | 模块开关 |
| `providers` | object | 空 | 云端模型 provider 配置 |
| `roles` | object | 内置 3 角色 | RBAC 角色定义 |
| `guard` | object | 默认规则 | WAF / 防护规则 |
| `v32Config` | object | 默认池配置 | 连接池 / 缓存 |

## modules 字段

```json
{
  "chatApi": true,
  "webSearch": true,
  "mcpExternal": true,
  "security360": true,
  "localModels": true,
  "cloudModels": true,
  "stats": true,
  "sidecarHub": true,
  "autoDiscovery": true,
  "builtinTools": true,
  "urgentChat": true,
  "hardwareAdvisor": true,
  "contextGov": true,
  "mcpSecurity": true
}
```

关闭的模块经 `moduleRoute` 包装后返回 503。

## providers 字段

```json
{
  "openai": {
    "baseURL": "https://api.openai.com/v1",
    "apiKey": "sk-xxx",
    "models": ["gpt-4", "gpt-3.5-turbo"]
  }
}
```

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `baseURL` | string | Provider API 根地址 |
| `apiKey` | string | 认证密钥（配置读取后脱敏） |
| `models` | []string | 支持的模型列表 |

## roles 字段

```json
{
  "global_admin": {"permissions": ["*"]},
  "admin": {"permissions": ["admin.read", "admin.write"]},
  "user": {"permissions": ["chat", "search"]}
}
```

## guard 字段

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `wafEnabled` | bool | true | WAF 总开关 |
| `maxBodyBytes` | int | 5242880 | 请求体上限 (5MB) |
| `rateLimitWindow` | int | 10 | 限速窗口 (秒) |
| `rateLimitMax` | int | 120 | 窗口内最大请求数 |

## v32Config 字段

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `pool.maxIdleConnsPerHost` | int | 32 | 每主机最大空闲连接 |
| `cache.enabled` | bool | true | 响应缓存开关 |
| `cache.ttlSeconds` | int | 300 | 缓存 TTL |

## 热重载

修改 `config.json` 后 3 秒内自动重载，无需重启。
