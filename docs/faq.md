# 常见问题（FAQ）

## 安装

**Q1: 支持哪些操作系统？**
A: Linux (amd64/arm64)、macOS (amd64/arm64)、Windows (amd64/arm64)、Android (arm64)。

**Q2: 最低系统要求？**
A: 512MB RAM、1 CPU 核心、50MB 磁盘空间。推荐 2GB RAM / 2 核。

**Q3: 需要安装 Go 吗？**
A: 使用预编译二进制不需要。从源码构建需要 Go 1.23+。

**Q4: 如何快速启动？**
A: 下载对应平台二进制，执行 `./tsg` 即可。首次启动自动生成 `config.json`。

**Q5: Docker 镜像在哪？**
A: 暂未提供官方镜像，建议基于 `golang:1.23-alpine` 自行构建。

## 启动

**Q6: 启动报错 "bind: address already in use"？**
A: 端口 18889 被占用。修改 `config.json` 中 `port` 字段或杀掉占用进程。

**Q7: 启动后浏览器打不开管理界面？**
A: 检查防火墙是否放行端口。默认地址 `http://localhost:18889`。

**Q8: 如何后台运行？**
A: Linux/macOS: `nohup ./tsg &`。Windows: 使用 NSSM 注册为服务。

**Q9: 如何查看启动日志？**
A: 默认输出到 stdout。配置文件可指定 `log.output = "file"`。

**Q10: 首次启动卡住？**
A: 可能是 MCP 工具初始化慢。检查 `config.json` 中 MCP 配置是否正确。

## 配置

**Q11: config.json 在哪里？**
A: 默认路径：`~/.tars/config.json`（Linux/macOS）或 `%USERPROFILE%\.tars\config.json`（Windows）。

**Q12: 修改配置后需要重启吗？**
A: 大部分配置支持热重载（发送 HUP 信号或管理界面点击重载）。部分核心参数（端口、TLS）需重启。

**Q13: 如何备份配置？**
A: 复制 `config.json` 即可。建议配合版本控制（Git）管理。

**Q14: 配置项太多，有示例吗？**
A: 见 `docs/configuration.md`，含每个字段的类型、默认值、范围、示例。

**Q15: 环境变量可以覆盖配置吗？**
A: 暂不支持。计划 v4.16.x 引入 `TSG_` 前缀环境变量覆盖。

## 网络

**Q16: 如何配置上游代理？**
A: 在 `config.json` 中设置 `upstream.proxy_url`。

**Q17: 支持 HTTPS 吗？**
A: 支持。配置 `tls.cert` 和 `tls.key` 路径，或启用自动证书（Let's Encrypt）。

**Q18: 支持 WebSocket 吗？**
A: TSG 本身作为网关支持透传 WebSocket。管理界面使用 SSE 而非 WebSocket。

**Q19: 如何限制访问 IP？**
A: 配置 `security.allowed_ips` 白名单，或启用 RBAC 的 IP 绑定。

**Q20: NAT/内网如何暴露？**
A: 建议使用反向代理（Nginx/Caddy）或内网穿透工具（frp/ngrok）。

## 性能

**Q21: 高并发下延迟增加？**
A: 参考 `docs/performance-tuning.md`，检查连接池、缓存、WAF 配置。

**Q22: 内存占用高？**
A: 降低 `cache.max_size`，减少 MCP 工具缓存，或调低 `GOGC`。

**Q23: CPU 占用高？**
A: 检查 WAF 规则是否过于复杂，或日志级别是否设为 debug。

**Q24: 如何查看实时性能指标？**
A: 管理界面「仪表盘」页，或访问 `/api/admin/metrics`（Prometheus 格式）。

## 兼容

**Q25: 与 TarsEnterprise 如何协作？**
A: 见 `docs/enterprise-interop.md`，配置 `interop.enabled = true`。

**Q26: MCP 工具兼容性？**
A: 支持标准 MCP 协议（SSE/stdio）。见 `docs/mcp-integration.md`。

**Q27: 旧版本配置能迁移吗？**
A: v3.x → v4.x 自动迁移。v4.x 之间配置向前兼容。

**Q28: 移动端能用吗？**
A: 管理界面响应式适配。Android 有独立 App（v4.2.0+）。

## 升级

**Q29: 如何升级到最新版？**
A: v4.15.0+ 内置自动更新：管理界面「自动更新」页点击检查/应用。或手动下载替换二进制。

**Q30: 升级失败如何回退？**
A: CLI 执行 `./tsg update rollback`，或手动将 `.backup` 文件恢复。

**Q31: 自动更新安全吗？**
A: 所有下载经 SHA256SUMS 校验。校验失败自动中止，保留旧版本。

**Q32: 可以关闭自动更新吗？**
A: 可以。设置 `update.enabled = false`。

**Q33: 更新检查频率？**
A: 默认启动时检查一次 + 每 24 小时检查一次。可配置 `update.interval`。

## 其他

**Q34: 如何报告 Bug？**
A: GitHub Issues: https://github.com/HP-jh/TarsSecureGuard/issues

**Q35: 如何贡献代码？**
A: Fork → 分支 → PR。需通过 `go test -race ./...`。

**Q36: 许可证？**
A: MIT License。
