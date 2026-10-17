//go:build !windows

package main

// 非 Windows 平台：安全软件兼容检测为空实现（Linux/macOS 安全软件生态不同）
func scanAVCompatPlatform(status *AVCompatStatus) {
	// Linux/macOS 当前不做主动兼容处理
	// 如需 future 扩展（如 macOS Gatekeeper / Linux ClamAV），可在此添加
	status.Recommendations = append(status.Recommendations,
		"当前平台为 "+status.Platform+"，安全软件兼容模块主要面向 Windows。如遇到误删问题，请将本程序添加到安全软件白名单")
}
