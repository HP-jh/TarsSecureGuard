# TarsSecureGuard v2.1.0 跨平台兼容矩阵与构建指南

本版目标：**全平台兼容 + 程序精简**。本文件是各平台最低支持矩阵、构建产物矩阵、命名规范与构建命令的唯一权威出处。

依据：Go 1.22 官方支持矩阵（[Go 1.22 Release Notes](https://go.dev/doc/go1.22) / [Go Wiki: Minimum Requirements](https://go.dev/wiki/MinimumRequirements) / [Go Wiki: Go on Darwin](https://go.dev/wiki/Darwin) / [Go 下载页](https://go.dev/dl/)）与 Apple 官方 macOS Catalina 支持机型列表（[Apple 支持文档](https://support.apple.com/zh-cn/118458)）。

---

## 一、各平台最低支持矩阵

| 平台 | GOOS/GOARCH | 最低系统版本 | 最低芯片/机型基线 | 支持状态 |
|------|-------------|--------------|-------------------|----------|
| macOS (Intel) | darwin/amd64 | **macOS 10.15 Catalina**（Go 1.22 是支持 Catalina 的最后一个 Go 版本） | 能安装 Catalina 的 Intel Mac：MacBook (2015 初)+ / MacBook Air (2012 中)+ / MacBook Pro (2012 中)+ / Mac mini (2012 末)+ / iMac (2012 末)+ / Mac Pro (2013 末)+（即最低约 3 代酷睿 Ivy Bridge） | ✅ 正式支持 |
| macOS (Apple Silicon) | darwin/arm64 | **macOS 11 Big Sur** | Apple Silicon 全系：M1 (2020) / M1 Pro/Max/Ultra / M2 系 / M3 系 / M4 系 | ✅ 正式支持 |
| Linux (x86_64) | linux/amd64 | 内核 **2.6.32+**（Go 1.22 最低要求；任何 2010 年后的发行版均满足） | 任意 x86-64 CPU（GOAMD64=v1 基线，全量 64 位 x86 可跑） | ✅ 正式支持 |
| Linux (ARM64) | linux/arm64 | 内核 2.6.32+ | ARMv8-A（树莓派 4/5、AWS Graviton、飞腾/鲲鹏等） | ✅ 正式支持 |
| Windows x64 | windows/amd64 | **Windows 10** 与 **Windows 11**（Go 1.21 起不再支持 Win7/8；Server 2016+ 同内核可用） | 任意 x64 CPU | ✅ 正式支持 |
| Windows ARM64 | windows/arm64 | Windows 10 on ARM / Windows 11 on ARM | Snapdragon X / SQ 系 | ⚠️ **实验性**（见下） |

**过旧芯片版本明确不支持的（按需求"可不用管"）：**
- macOS：无法安装 Catalina 的 Intel Mac（2012 年前的 MacBook Pro / iMac、Core 2 Duo 及更早机型）——它们最高只能到 Mojave 10.14，而 Go 1.21+ 已放弃 10.14。
- Linux：非 64 位 x86（无 amd64 的老 Pentium/Atom）、32 位 ARM。
- Windows：Windows 7 / 8 / 8.1（Go 1.21+ 起不支持），32 位 x86。

**升级注意**：Go 1.23 起要求 macOS 11+（Intel 矩阵将收缩到 Big Sur）；Go 1.24 起 Linux 内核最低要求升到 3.2。本版锁定 go 1.22.5，若未来升级工具链需重新评估本矩阵。

### Windows ARM64 可行性结论（实验性）

- **编译可行性**：交叉编译通过（PE32+ Aarch64），`go vet` 无告警；Go 自 1.17 起官方支持 windows/arm64。
- **代码可行性**：全部系统调用（`GetDiskFreeSpaceExW` / `GlobalMemoryStatusEx` / `netsh`）在 ARM64 Windows 上均存在且语义一致；无 cgo、无 amd64 专属指令，`CGO_ENABLED=0` 静态产物不依赖任何本机运行库。
- **运行时生态受限**：llama.cpp 无官方 Windows ARM64 预编译产物，LM Studio / Ollama 亦无官方 ARM64 Windows 版——**网关本身、WAF、云端路由、模块管理在 ARM64 Windows 上可用，但"本地 GGUF 模型"功能需用户自行编译 llama-server**。
- **结论**：随本版提供 `tars-enhanced-v2.1.0-windows-arm64.exe`，标注实验性；主推 matrix 为 windows/amd64。

---

## 二、构建产物矩阵与命名规范

命名规范：`tars-enhanced-v<版本>-<goos>-<goarch>[.exe]`

| 产物文件 | 平台 | v2.0.0 体积（默认构建） | v2.1.0 体积（精简构建） | 缩减 |
|----------|------|------------------------|------------------------|-------|
| tars-enhanced-v2.1.0-darwin-amd64 | macOS Intel | 9,375,664 B (8.94 MB) | 6,628,800 B (6.33 MB) | **-29.3%** |
| tars-enhanced-v2.1.0-darwin-arm64 | macOS Apple Silicon | 9,045,058 B (8.62 MB) | 6,391,602 B (6.09 MB) | **-29.3%** |
| tars-enhanced-v2.1.0-linux-amd64 | Linux x86_64 | 9,400,325 B (8.96 MB) | 6,463,640 B (6.16 MB) | **-31.2%** |
| tars-enhanced-v2.1.0-linux-arm64 | Linux ARM64 | 9,026,333 B (8.60 MB) | 6,291,608 B (5.99 MB) | **-30.3%** |
| tars-enhanced-v2.1.0-windows-amd64.exe | Windows 10/11 x64 | 9,489,920 B (9.05 MB) | 6,668,800 B (6.35 MB) | **-29.7%** |
| tars-enhanced-v2.1.0-windows-arm64.exe | Windows ARM64（实验） | 8,976,384 B (8.56 MB) | 6,274,560 B (5.98 MB) | **-30.1%** |

精简构建三要素（全平台一致）：
1. `-ldflags "-s -w"`：剥离符号表与 DWARF 调试信息（`file` 输出确认 `stripped`）；
2. `-trimpath`：去除构建机绝对路径（体积与可复现性双收益）；
3. `CGO_ENABLED=0`：纯 Go 静态链接——Linux 产物不再依赖 glibc（v2.0.0 的 amd64 产物动态链接 `/lib64/ld-linux-x86-64.so.2`，在老发行版上有 glibc 版本风险；v2.1.0 两个 Linux 产物均 `statically linked`，任意发行版即拷即跑）。

版本号经 `-ldflags "-X main.version=2.1.0"` 注入（v2.1.0 起 `version` 由 const 改为 var）。

## 三、构建命令清单（复制即用）

```sh
# 在源码目录（go.mod 所在处）执行；需 Go 1.22.5+
mkdir -p dist
GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=2.1.0" -o dist/tars-enhanced-v2.1.0-darwin-amd64
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=2.1.0" -o dist/tars-enhanced-v2.1.0-darwin-arm64
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=2.1.0" -o dist/tars-enhanced-v2.1.0-linux-amd64
GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=2.1.0" -o dist/tars-enhanced-v2.1.0-linux-arm64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=2.1.0" -o dist/tars-enhanced-v2.1.0-windows-amd64.exe
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=2.1.0" -o dist/tars-enhanced-v2.1.0-windows-arm64.exe
```

一键全平台（含 vet 门禁）：

```sh
for t in "darwin amd64" "darwin arm64" "linux amd64" "linux arm64" "windows amd64" "windows arm64"; do
  set -- $t
  GOOS=$1 GOARCH=$2 CGO_ENABLED=0 go vet ./... || exit 1
  GOOS=$1 GOARCH=$2 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=2.1.0" \
    -o "dist/tars-enhanced-v2.1.0-$1-$2$([ "$1" = windows ] && echo .exe)" || exit 1
done
```

依赖审计结论：`go.mod` 无任何第三方 require，`go list -deps` 的 17 个依赖全部为 Go 标准库，`go mod tidy` 零变更——**零外部依赖**，无供应链面。

## 四、部署须知（按平台）

- **macOS**：首次运行被 Gatekeeper 拦时，在终端执行 `xattr -d com.apple.quarantine ./tars-enhanced-v2.1.0-darwin-*`（或系统设置 → 隐私与安全性 → 仍要打开）。Intel/Apple Silicon 双架构不通用，按机型取对应产物。
- **Linux**：`chmod +x` 后直接运行（静态产物，无运行库要求）；`./start.sh` 首次会自动编译，也可直接用 dist 内产物。
- **Windows**：双击 `start.bat` 或直接运行 exe；Windows 11 24H2+ 已移除 wmic，v2.1.0 的 GPU 探测已自动回落 PowerShell `Get-CimInstance`，无需干预。

## 五、验证记录（2026-09-28，Linux 沙箱）

| 验证项 | 方法 | 结果 |
|--------|------|------|
| 六平台交叉编译 | 构建命令清单逐平台执行 | 全部通过 |
| 六平台 go vet | `GOOS/GOARCH go vet ./...` | 无告警 |
| 产物文件头 | `file` 逐一校验 | Mach-O x86_64/arm64、ELF x86-64/aarch64（statically linked, stripped）、PE32+ x86-64/Aarch64，全部符合 |
| Linux amd64 实跑冒烟 | 沙箱运行最终产物 | `/health` 200（version 2.1.0）；模块开关 webSearch 200→关→503（含开启提示）→开→200；security-core 关闭被拒 400；硬件评估磁盘 9.75/8.70GB（与 `df` 一致，v2.0.0 同机为 0.000 哑分） |
| 新 UI（Modules 管理页） | headless Chromium（Playwright + 系统 Chromium 1440×900） | Dashboard/Modules 页渲染正常：模块清单 18 项、Security Core 带 LOCKED 徽标、开关状态正确；页面零 JS 错误、零失败请求 |
| Windows / macOS 实机 | 无法在 Linux 沙箱实跑 | **静态验证**：交叉编译 + vet + 文件头 + 逐平台代码走查（getDiskUsage/detectGPU/物理内存/防火墙联动各平台实现均有 build tag 分支且编译通过）；实机运行留待用户侧验证 |
