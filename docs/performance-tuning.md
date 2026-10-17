# 性能调优指南

## 1. 概述

TSG 在默认配置下已针对通用场景优化。本文档指导如何在特定负载下进一步提升性能。

## 2. 基准数据

| 指标 | 默认值 | 优化后 | 测试条件 |
|------|--------|--------|---------|
| WAF 严格模式 | 474 µs | 0.99 µs | 纯中文 payload |
| 日志写入 | 4004 ns | 832 ns | 热路径 |
| 响应缓存 | — | -10% | 2 核，>1000 RPS |
| PII 检测 | — | -15% | 四模式单遍 |

## 3. WAF 优化

### 3.1 正则合并

合并同类规则减少回溯：

```go
// 优化前：独立编译
waf.AddRule("sql1", "(?i)union\\s+select")
waf.AddRule("sql2", "(?i)insert\\s+into")

// 优化后：合并正则
waf.AddRule("sql_all", "(?i)(?:union\\s+select|insert\\s+into|delete\\s+from)")
```

### 3.2 ASCII 预筛选

启用字节级快速否决：

```json
{
  "waf": {
    "ascii_prefilter": true,
    "prefilter_threshold": 3
  }
}
```

仅当 payload 中可疑 ASCII 字符 ≥3 个时才进入正则匹配。

## 4. 缓存策略

### 4.1 响应缓存

```json
{
  "cache": {
    "enabled": true,
    "ttl": "5m",
    "shards": 16,
    "max_size": "100MB"
  }
}
```

- `shards`：与 CPU 核数对齐（默认 16，适合 2~8 核）
- `ttl`：静态内容可设为 10m+，API 响应建议 30s~2m

### 4.2 配置热加载

```bash
# 避免频繁重启
kill -HUP $(pgrep tsg)
```

## 5. 连接管理

### 5.1 连接池

```json
{
  "upstream": {
    "pool": {
      "max_idle": 100,
      "max_active": 500,
      "idle_timeout": "90s"
    }
  }
}
```

### 5.2 超时设置

```json
{
  "timeouts": {
    "read": "30s",
    "write": "30s",
    "idle": "120s",
    "shutdown": "10s"
  }
}
```

## 6. 日志优化

### 6.1 异步日志

已默认启用：日志写入走独立 goroutine + 缓冲通道。

### 6.2 日志级别

生产环境建议：

```json
{
  "log": {
    "level": "warn",
    "output": "file",
    "file": "/var/log/tsg/tsg.log",
    "rotation": "daily"
  }
}
```

## 7. 内存调优

### 7.1 GOGC

```bash
# 内存充足时降低 GC 频率
export GOGC=200

# 内存紧张时提高 GC 频率
export GOGC=50
```

### 7.2 内存剖析

```bash
# 开启 pprof（默认关闭）
./tsg --pprof=:6060

# 导出内存 profile
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

## 8. 监控与告警

### 8.1 关键指标

| 指标 | 健康阈值 | 告警阈值 |
|------|---------|---------|
| P99 延迟 | < 50ms | > 200ms |
| CPU 使用率 | < 60% | > 85% |
| 内存使用 | < 70% | > 90% |
| 错误率 | < 0.1% | > 1% |
| WAF 拦截率 | < 5% | > 20% |

### 8.2 内置端点

```
GET /api/admin/metrics      # Prometheus 格式
GET /api/admin/health       # 健康检查
GET /api/admin/status       # 运行状态摘要
```

## 9. 平台特定调优

### Linux

```bash
# 文件描述符
echo "fs.file-max = 65536" >> /etc/sysctl.conf

# TCP 连接复用
echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
sysctl -p
```

### macOS

```bash
# 文件描述符
ulimit -n 65536
```

### Windows

```powershell
# 注册表调整 TCP 参数
# 或使用 TSG 配置：windows.tcp_optimizations = true
```
