# TarsSecureGuard Go v1.0.2 功能强化 · 变更说明

基于 TarsSecureGuard Go v1.0.2 源码（15 个唯一文件）进行功能强化，
**不改动现有功能逻辑，仅新增 / 强化**，全部新增代码带中文注释。

## 一、文件清单

### 修改的文件（5 个）
| 文件 | 变更内容 |
|------|----------|
| main.go | ① 新增全局统计量 respTotalMs/respSamples（平均响应时间）；② 中间件新增按小时请求量统计 recordHourlyRequest 与响应耗时计时 recordResponseTime；③ 注册新路由 /health、/api/stats、/api/stats/history；④ isPublicRoute 放行 /health；⑤ logMsg 同步落盘 logs/tars-YYYY-MM-DD.log；⑥ 启动流程新增：initFileLogging()、后台模型自动发现 goroutine（5s 首测、每 60s 刷新）、配置热重载 goroutine watchConfig() |
| waf.go | ① 新增扫描器 User-Agent 黑名单检测（21 种工具特征）；② 新增敏感路径探测检测（/.env、/.git、/wp-admin、/phpmyadmin 等 21 类特征，本系统自身路由豁免以保证兼容）；③ 新增大文件上传检测（Content-Length > 5MB 拦截）；④ 新增异常 HTTP 方法检测（仅放行 GET/POST/PUT/DELETE/OPTIONS/HEAD）；⑤ blockRequest 将 WAF 日志同步写入 logs/waf-YYYY-MM-DD.log（含时间、IP、原因、请求路径） |
| config.go | ① 新增配置热重载：watchConfig() 每 2 秒轮询 config.json 的 SHA-256 指纹，变化且文件可完整解析时自动 loadConfig（半写状态自动跳过，避免误载）；② loadConfig 末尾 markConfigLoaded() 记录基线，回写后指纹为新基线，杜绝自我触发循环 |
| models.go | ① 新增模型自动发现模块：探测 LM Studio（127.0.0.1:1234/v1/models）、Ollama（127.0.0.1:11434/api/tags）、本地 llama.cpp（默认端口 127.0.0.1:8080/v1/models）；② discoveredModels 缓存 + refreshDiscoveredModels() 定期刷新，发现新模型记录日志；③ getModels() 合并自动发现结果（按 ID 去重） |
| handlers.go | ① 新增 GET /api/stats：totalRequests、successRate、wafBlocks、avgResponseTime、uptime、activeModel、memoryUsage；② 新增 GET /api/stats/history：最近 24 小时每小时请求量（24 个小时桶）；③ 新增 GET /health：{ status, version, uptime } |

### 新增的文件（3 个）
| 文件 | 说明 |
|------|------|
| logging.go | 日志文件持久化模块：运行日志 logs/tars-YYYY-MM-DD.log、WAF 日志 logs/waf-YYYY-MM-DD.log，按天轮转；内存仍保留最近 500 条供 API 查询 |
| start.bat | Windows 双击启动脚本：检测 exe → 无则自动 go build → 启动并显示管理面板地址 http://127.0.0.1:18889 → Ctrl+C 优雅关闭提示；UTF-8 编码（chcp 65001）中文输出 |
| start.sh | Linux/macOS 启动脚本：同上逻辑，自动 chmod +x 可执行权限 |

### 未修改的文件
chat.go、tools.go、web.go、mcp.go、device.go、firewall.go、memory.go、go.mod、config.json、frontend/index.html（仅由根目录 frontend_index.html 移入 frontend/ 子目录，go:embed 要求此布局，否则无法编译）

## 二、功能强化对照（8 项全部完成）

1. **Windows 双击启动脚本 start.bat** ✅ 自动检测/编译/启动/面板地址/关闭提示/UTF-8 中文
2. **Linux/macOS 启动脚本 start.sh** ✅ 同上 + chmod +x
3. **WAF 检测规则增强** ✅ UA 黑名单 / 敏感路径 / 大文件上传 / 异常方法，命中均记 WAF 日志（时间、IP、原因、路径）
4. **日志文件持久化** ✅ logs/tars-YYYY-MM-DD.log + logs/waf-YYYY-MM-DD.log 按天轮转，内存保留 500 条
5. **模型自动发现** ✅ LM Studio + Ollama + llama.cpp 默认端口，后台每 60s 刷新，自动更新模型列表
6. **统计面板 API** ✅ /api/stats + /api/stats/history（24 小时逐时请求量）
7. **配置热重载** ✅ 轮询 + SHA-256 指纹检测（2 秒粒度，无外部依赖），重载记日志
8. **健康检查端点** ✅ GET /health（免鉴权）

## 三、兼容性说明

- 所有既有 API 路由、请求/响应格式不变；新增路由独立存在
- /admin、/api/admin/* 等本系统自身路由已加入敏感路径豁免清单，WAF 强化不影响面板与 API 正常使用
- PATCH 等方法按需求白名单外被拦截（GET/POST/PUT/DELETE/OPTIONS/HEAD 放行）
- 配置热重载对"编辑器保存中的半写文件"有预检，不会把不完整配置载入

## 四、验证记录

- `GOOS=windows GOARCH=amd64 go build` 编译通过，`go vet` 无告警
- Linux 桩环境运行时冒烟测试全部通过：
  - /health 返回 {status:ok, version:1.0.2, uptime}
  - /api/stats 七项指标齐全；activeModel 正确显示自动发现的模型
  - /api/stats/history 返回 24 个小时桶
  - WAF：sqlmap UA、/.env、/wp-admin、TRACE 方法、6MB 请求体均被拦截（403 + 原因）；正常路由 /、/admin、/api/status 均 200
  - 日志文件 logs/tars-2026-09-22.log、logs/waf-2026-09-22.log 正确生成，内容含时间/IP/原因/路径
  - 修改 config.json 后 2 秒内自动重载（mode: normal→strict 生效），日志记录，无循环重载
  - 假 LM Studio / Ollama 后端启动后自动发现 2 个模型并记日志
