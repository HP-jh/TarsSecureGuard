# TarsSecureGuard API 参考

## 通用规范

- **Base URL**: `http://127.0.0.1:18889`
- **鉴权**: 请求头 `Authorization: Bearer <apiKey>`（默认 `tars-gateway-key`）
- **内容类型**: `application/json`

---

## 1. Chat API

### POST /api/chat/completions
OpenAI 兼容的聊天补全端点。

**请求体**
```json
{
  "model": "gpt-4",
  "messages": [{"role": "user", "content": "hello"}],
  "temperature": 0.7,
  "stream": false
}
```

**响应**
```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "choices": [{
    "message": {"role": "assistant", "content": "Hi there!"}
  }]
}
```

**错误码**
| 状态码 | 说明 |
|--------|------|
| 401 | API Key 无效 |
| 503 | 模块已关闭 |
| 429 | 速率限制 |

---

## 2. Admin API

### GET /api/admin/logs
获取系统日志。

**参数**: `?level=INFO&limit=100`

**响应**
```json
{"logs": ["[INFO] TarsSecureGuard v4.15.0 starting..."]}
```

### GET /api/admin/config
获取当前配置（密钥脱敏）。

### POST /api/admin/config
更新配置。

### GET /api/admin/modules
获取模块状态列表。

### POST /api/admin/modules
启用/禁用模块。

---

## 3. 安全中心 API

### GET /api/admin/security/status
安全总览（威胁数、WAF 拦截数、健康度）。

### POST /api/admin/security/scan
执行安全扫描。

### GET /api/admin/security/waf-logs
WAF 拦截日志。

---

## 4. 知识库 API

### POST /api/kb/ingest
摄入文档。

**请求体**
```json
{"title": "doc1", "content": "..."}
```

### POST /api/kb/query
查询知识库。

**请求体**
```json
{"query": "什么是 TSG"}
```

### GET /api/kb/docs
列出已摄入文档。

---

## 5. Obsidian API

### POST /api/obsidian/sync
同步整个 Vault。

**请求体**
```json
{"vault_path": "/path/to/vault"}
```

### POST /api/obsidian/parse
解析单条笔记。

---

## 6. 语音纠错 API

### POST /api/voicecorrection/correct
纠正语音输入文本。

**请求体**
```json
{"text": "今天的天气真不错"}
```

---

## 7. 企业互操作 API

### POST /api/v1/interop/receive-command
接收 TarsEnterprise 指令。

**请求体**
```json
{
  "command": "sync_role",
  "target": "admin",
  "payload": {"role_id": "admin"},
  "source": "tars-enterprise"
}
```

### GET /api/v1/interop/events
SSE 实时事件流。

---

## 8. 自动更新 API

### GET /api/admin/update/status
更新状态。

### GET /api/admin/update/check
检查新版本。

### POST /api/admin/update/apply
应用更新（自动重启）。

### POST /api/admin/update/rollback
回退到上一版本。
