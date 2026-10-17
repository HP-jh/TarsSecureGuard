# 故障排查指南

## 1. 启动失败

### 1.1 端口占用

**现象**：`bind: address already in use`

**排查**：
```bash
# Linux/macOS
lsof -i :18889
# Windows
netstat -ano | findstr :18889
```

**解决**：
- 修改 `config.json` 中的 `port`
- 或终止占用进程：`kill -9 <PID>`

### 1.2 配置错误

**现象**：启动即 panic 或立即退出

**排查**：
```bash
# 验证 JSON 语法
python3 -m json.tool config.json
# 或使用 jq
jq . config.json
```

**常见错误**：
- 末尾多余逗号
- 字符串未加引号
- 嵌套括号不匹配
- `providers._说明` 等非法键名（Go 结构体解析失败）

**解决**：修复 JSON 语法，或删除 `config.json` 让 TSG 重新生成默认配置。

### 1.3 权限不足

**现象**：`permission denied` 或无法创建日志文件

**排查**：
```bash
ls -la ~/.tars/
# 检查目录权限
touch ~/.tars/test && rm ~/.tars/test
```

**解决**：
```bash
# Linux/macOS
chmod 755 ~/.tars
chown $(whoami) ~/.tars

# 或使用其他端口（非特权端口 >1024）
```

## 2. MCP 工具调用失败

### 2.1 超时

**现象**：MCP 工具响应慢或超时

**排查**：
- 检查工具进程是否存活：`ps aux | grep <tool_name>`
- 检查网络连通性：`curl <tool_endpoint>`
- 查看 TSG 日志中 MCP 相关错误

**解决**：
- 增加 `mcp.timeout` 配置
- 检查工具依赖是否完整
- 重启 TSG 重新初始化 MCP 连接

### 2.2 拒绝连接

**现象**：`connection refused` 或 `ECONNREFUSED`

**排查**：
- 工具服务端是否启动
- 端口是否正确
- 防火墙是否放行

**解决**：
- 手动启动工具服务端
- 核对 `config.json` 中 MCP 配置

### 2.3 格式错误

**现象**：`invalid JSON` 或 `malformed request`

**排查**：
- 检查请求体是否符合 MCP 协议规范
- 查看工具服务端日志

**解决**：
- 使用 TSG 内置 MCP 测试页验证
- 更新 MCP 工具到兼容版本

## 3. 性能下降

### 3.1 高 CPU

**现象**：CPU 使用率持续 >80%

**排查**：
```bash
# 开启 pprof
curl http://localhost:6060/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof
```

**常见原因**：
- WAF 正则回溯（复杂规则）
- 日志级别设为 debug
- 无缓存，每个请求重新计算

**解决**：
- 启用 WAF ASCII 预筛选
- 提升日志级别至 warn
- 启用响应缓存

### 3.2 内存泄漏

**现象**：内存持续增长，不回落

**排查**：
```bash
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

**常见原因**：
- SSE 订阅未清理（已修复 v4.15.0）
- 缓存未设上限
- goroutine 泄漏

**解决**：
- 设置 `cache.max_size`
- 重启 TSG（短期缓解）
- 提交 issue 附带 heap profile

### 3.3 慢查询

**现象**：特定端点响应时间 >1s

**排查**：
- 检查是否命中慢 WAF 规则
- 检查上游服务是否慢
- 检查数据库/文件 IO 瓶颈

**解决**：
- 参考 `docs/performance-tuning.md`
- 启用连接池
- 增加缓存 TTL

## 4. 安全拦截误报

### 4.1 WAF 规则误拦截

**现象**：正常请求被 403 拦截

**排查**：
- 查看响应头 `X-TSG-WAF-Rule`
- 查看审计日志中的拦截原因

**解决**：
- 临时禁用特定规则：`waf.rules.<name>.enabled = false`
- 调整规则敏感度：`waf.mode = "passive"`
- 将客户端 IP 加入白名单

### 4.2 路径限制误报

**现象**：文件读取/写入被 403

**排查**：
- 检查请求路径是否在 `security.allowed_paths` 内
- 检查是否包含 `..` 或符号链接

**解决**：
- 扩展允许路径列表
- 使用绝对路径（已解析 symlink）

## 5. 升级失败

### 5.1 Checksum 校验失败

**现象**：`SHA256 mismatch`

**排查**：
- 下载是否完整（网络中断）
- GitHub Release 的 SHA256SUMS 是否正确

**解决**：
- 手动重新下载
- 检查网络代理是否篡改内容
- 回退到旧版本：`./tsg update rollback`

### 5.2 网络中断

**现象**：下载中途失败

**排查**：
- 测试 GitHub 连通性：`curl -I https://github.com`
- 检查代理配置

**解决**：
- 配置代理后重试
- 使用 `stable_versions.json` 本地缓存版本
- 手动下载并替换二进制

### 5.3 回退失败

**现象**：`backup not found`

**排查**：
- `.backup` 文件是否存在
- 是否被系统清理

**解决**：
- 从 GitHub Release 重新下载对应版本
- 保留 `.backup` 文件（7 天自动清理，建议额外备份）

## 6. UI 异常

### 6.1 白屏

**现象**：管理界面空白

**排查**：
- 浏览器控制台（F12）查看 JS 错误
- 检查网络请求是否 404/500
- 清除浏览器缓存

**解决**：
- 刷新页面（Ctrl+F5）
- 检查 TSG 后端是否正常运行
- 降级到稳定版本验证

### 6.2 卡顿

**现象**：界面响应迟缓

**排查**：
- 浏览器性能面板（Performance）
- 检查 SSE 连接是否过多
- 检查 DOM 节点数量

**解决**：
- 减少同时打开的 SSE 连接
- 关闭不必要的页面
- 升级浏览器

### 6.3 样式错位

**现象**：布局错乱、文字重叠

**排查**：
- 浏览器缩放比例是否为 100%
- 是否使用了浏览器插件（如暗色模式插件）

**解决**：
- 重置浏览器缩放
- 禁用相关插件
- 强制刷新（Ctrl+Shift+R）

## 7. 诊断工具

### 内置端点

```
GET /api/admin/health        # 健康状态
GET /api/admin/status        # 运行摘要
GET /api/admin/metrics       # Prometheus 指标
GET /api/admin/update/status # 版本信息
```

### 日志位置

- 默认：`stdout`
- 文件模式：`~/.tars/logs/tsg.log`
- 审计日志：`~/.tars/audit/`

### 调试模式

```bash
./tsg --debug
# 或
export TSG_DEBUG=1
```
