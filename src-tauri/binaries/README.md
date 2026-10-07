# sidecar 二进制放置目录

构建时（本地或 CI）把 Go 网关按 Tauri target-triple 命名放到本目录，
`tauri.conf.json` 的 `bundle.externalBin: ["binaries/tsg"]` 会自动匹配：

- Windows:  `tsg-x86_64-pc-windows-msvc.exe`
- macOS:    `tsg-universal-apple-darwin`（amd64 + arm64 lipo 合并）
- Linux:    `tsg-x86_64-unknown-linux-gnu`

CI（.github/workflows/desktop-release.yml）在 `tauri build` 之前完成编译与放置；
本目录不提交二进制，仅保留此说明文件。
