// v4.6.0 客户端下载器主线：Go 网关 ↔ Tauri 桌面客户端桥接
//
// 职责：
// 1. 检测本地是否已安装 Tauri 桌面客户端（各平台注册表/配置目录扫描）
// 2. 通过已注册协议（tsg://）调起本地客户端
// 3. 为 --launch-client 标志提供决策：优先客户端 → 回退浏览器
// 4. 各平台安装路径探测（注册表、Applications、.desktop 等）

package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// v4.6.0：--launch-client 扫描结果（true = 优先尝试调起本地客户端）
var launchClient = false

// v4.6.0：客户端已安装缓存（启动时探测一次，避免重复 IO）
var clientInstalledCache *bool

// scanLaunchClientFlag 扫描 os.Args 中的 --launch-client 标记
func scanLaunchClientFlag(args []string) bool {
	for _, a := range args {
		if a == "--launch-client" || a == "-launch-client" {
			return true
		}
	}
	return false
}

// detectDesktopClient 探测本地是否安装了 Tauri 桌面客户端
// 各平台探测策略：
//   Windows: 注册表 HKCU\Software\Classes\tsg 协议键
//   macOS:   ~/Applications/TarsSecureGuard.app 或 /Applications/TarsSecureGuard.app
//   Linux:   ~/.local/share/applications/tarssecureguard.desktop 或 /usr/share/applications/
func detectDesktopClient() bool {
	if clientInstalledCache != nil {
		return *clientInstalledCache
	}
	installed := false
	switch runtime.GOOS {
	case "windows":
		installed = detectWindowsClient()
	case "darwin":
		installed = detectDarwinClient()
	default: // linux + 其他 unix
		installed = detectLinuxClient()
	}
	clientInstalledCache = &installed
	return installed
}

// detectWindowsClient Windows 客户端探测（注册表 + 安装目录）
func detectWindowsClient() bool {
	// ① 协议注册表键（NSIS 安装器会写入）
	if checkWindowsRegKey(`HKCU\Software\Classes\tsg`) {
		return true
	}
	// ② 常见安装路径
	paths := []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), "TarsSecureGuard", "TarsSecureGuard.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "TarsSecureGuard", "TarsSecureGuard.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "TarsSecureGuard", "TarsSecureGuard.exe"),
	}
	for _, p := range paths {
		if fileExists(p) {
			return true
		}
	}
	return false
}

// checkWindowsRegKey 通过 reg.exe 查询注册表键是否存在
func checkWindowsRegKey(key string) bool {
	cmd := exec.Command("reg", "query", key, "/ve")
	cmd.SysProcAttr = hideWindowAttr()
	err := cmd.Run()
	return err == nil
}

// detectDarwinClient macOS 客户端探测（Applications 目录）
func detectDarwinClient() bool {
	paths := []string{
		filepath.Join(os.Getenv("HOME"), "Applications", "TarsSecureGuard.app"),
		"/Applications/TarsSecureGuard.app",
	}
	for _, p := range paths {
		if dirExists(p) {
			return true
		}
	}
	// 检查 tsg:// 协议是否已注册（通过 LSRegisterCopyURLSchemes 太难，退到路径探测）
	return false
}

// detectLinuxClient Linux 客户端探测（.desktop + AppImage + 安装目录）
func detectLinuxClient() bool {
	home := os.Getenv("HOME")
	paths := []string{
		filepath.Join(home, ".local/share/applications/tarssecureguard.desktop"),
		"/usr/share/applications/tarssecureguard.desktop",
		"/usr/local/share/applications/tarssecureguard.desktop",
		filepath.Join(home, ".local/bin/TarsSecureGuard"),
		"/usr/bin/TarsSecureGuard",
		"/usr/local/bin/TarsSecureGuard",
		filepath.Join(home, "Applications/TarsSecureGuard.AppImage"),
	}
	for _, p := range paths {
		if fileExists(p) || dirExists(p) {
			return true
		}
	}
	return false
}

// launchDesktopClient 通过 tsg://open 协议调起本地客户端
// 各平台调起方式：
//   Windows: start tsg://open
//   macOS:   open tsg://open
//   Linux:   xdg-open tsg://open
func launchDesktopClient() bool {
	url := "tsg://open"
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
		cmd.SysProcAttr = hideWindowAttr()
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		logMsg(fmt.Sprintf("[client-launcher] 调起本地客户端失败: %v", err))
		return false
	}
	logMsg("[client-launcher] 已通过 tsg://open 调起本地客户端")
	return true
}

// openBrowserOrClient v4.6.0 智能打开：优先本地客户端 → 回退浏览器
// 逻辑：
//   1. --launch-client 显式传入 → 尝试客户端 → 失败则浏览器
//   2. 未传 --launch-client 但检测到客户端已安装 → 尝试客户端 → 失败则浏览器
//   3. 未检测到客户端 → 直接浏览器
func openBrowserOrClient(targetURL string) {
	tryClient := launchClient || detectDesktopClient()
	if tryClient {
		if launchDesktopClient() {
			return
		}
		logMsg("[client-launcher] 客户端调起失败，回退到浏览器")
	}
	openBrowser(targetURL)
}

// dirExists 目录存在性检查
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// isDesktopClientMode 判断当前是否运行在 Tauri 壳内（由 sidecar 拉起时 TSG_APP_DIR 已设置）
func isDesktopClientMode() bool {
	return os.Getenv("TSG_APP_DIR") != ""
}

// ===================== v4.6.0 新增：安装器元信息 API =====================

// installerInfo 供前端查询的安装器信息
type installerInfo struct {
	HasDesktopClient bool   `json:"hasDesktopClient"`
	Platform         string `json:"platform"`
	Arch             string `json:"arch"`
	ClientVersion    string `json:"clientVersion,omitempty"`
}

// handleInstallerInfo HTTP handler：供前端"打开本地客户端"按钮决策
func handleInstallerInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	info := installerInfo{
		HasDesktopClient: detectDesktopClient(),
		Platform:         runtime.GOOS,
		Arch:             runtime.GOARCH,
	}
	writeJSON(w, info)
}
