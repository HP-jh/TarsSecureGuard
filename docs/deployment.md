# TarsSecureGuard 部署指南

## 1. 二进制部署（推荐）

### Linux / macOS
```bash
# 下载对应平台二进制
curl -L -o tsg https://github.com/HP-jh/TarsSecureGuard/releases/latest/download/tsg-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
chmod +x tsg
./tsg
```

### Windows
```powershell
# 下载 exe 后双击运行，或使用 PowerShell
.\tsg.exe
```

### 后台运行
```bash
# Linux (systemd)
sudo tee /etc/systemd/system/tsg.service << 'EOF'
[Unit]
Description=TarsSecureGuard
After=network.target

[Service]
Type=simple
ExecStart=/opt/tsg/tsg
WorkingDirectory=/opt/tsg
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now tsg
```

## 2. Docker 部署

```bash
docker run -d \
  -p 18889:18889 \
  -v $(pwd)/config.json:/app/config.json \
  -v $(pwd)/data:/app/data \
  ghcr.io/hp-jh/tarssecureguard:latest
```

## 3. 源码部署

```bash
git clone https://github.com/HP-jh/TarsSecureGuard.git
cd TarsSecureGuard
go build -ldflags "-X main.version=$(git describe --tags)" -o tsg .
./tsg
```

## 4. 首次启动

1. 访问 `http://127.0.0.1:18889`
2. 默认 API Key: `tars-gateway-key`
3. 进入 Settings 修改密钥和添加 Provider

## 5. 目录结构

```
/opt/tsg/
├── tsg                    ← 主二进制
├── config.json            ← 配置文件
├── data/                  ← 运行时数据
│   ├── logs/              ← 日志
│   ├── guard-state.json   ← 守护器状态
│   └── quota-usage.json   ← 配额用量
├── knowledge/             ← 知识库文档
└── logs/                  ← 持久化日志
```

## 6. 防火墙配置

| 端口 | 用途 | 暴露范围 |
|------|------|----------|
| 18889 | HTTP 网关 | 按需 |
| 18890 | 本地模型服务 | localhost |

## 7. 自动更新

```bash
# 检查更新
./tsg update check

# 应用更新
./tsg update apply

# 回退
./tsg update rollback
```

## 8. 各平台说明

| 平台 | 二进制名 | 备注 |
|------|----------|------|
| Linux amd64 | `tsg-v*-linux-amd64` | 主流服务器 |
| Linux arm64 | `tsg-v*-linux-arm64` | ARM 服务器 / 树莓派 |
| macOS amd64 | `tsg-v*-darwin-amd64` | Intel Mac |
| macOS arm64 | `tsg-v*-darwin-arm64` | Apple Silicon |
| Windows amd64 | `tsg-v*-windows-amd64.exe` | x64 PC |
| Windows arm64 | `tsg-v*-windows-arm64.exe` | ARM PC |
| Android arm64 | `tsg-v*-android-arm64` | 需 Termux |
