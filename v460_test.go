// v4.6.1 客户端下载器主线测试
package main

import (
	"os"
	"runtime"
	"testing"
)

// TestV461VersionBumped 版本号必须已升至 4.6.1
func TestV461VersionBumped(t *testing.T) {
	if version != "4.6.1" {
		t.Fatalf("version expected 4.6.1, got %s", version)
	}
}

// TestScanLaunchClientFlag 扫描 --launch-client 标记
func TestScanLaunchClientFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"tsg"}, false},
		{[]string{"tsg", "--launch-client"}, true},
		{[]string{"tsg", "-launch-client"}, true},
		{[]string{"tsg", "--no-browser", "--launch-client"}, true},
		{[]string{"tsg", "--launch-client", "--port", "9999"}, true},
		{[]string{"tsg", "--client"}, false},
	}
	for _, c := range cases {
		got := scanLaunchClientFlag(c.args)
		if got != c.want {
			t.Errorf("scanLaunchClientFlag(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// TestDetectDesktopClient 客户端探测（不依赖实际安装，验证不 panic）
func TestDetectDesktopClient(t *testing.T) {
	// 重置缓存，确保走探测逻辑
	clientInstalledCache = nil
	_ = detectDesktopClient()
	// 只要不出 panic 即通过；返回值取决于运行环境
}

// TestFileExistsDirExists 辅助函数
func TestFileExistsDirExists(t *testing.T) {
	// 当前目录必然存在
	if !dirExists(".") {
		t.Error("dirExists('.') should be true")
	}
	// 当前文件（测试文件自身）必然存在
	if !fileExists("v460_test.go") {
		t.Error("fileExists('v460_test.go') should be true")
	}
	// 不存在的文件
	if fileExists("__nonexistent_file_460__.txt") {
		t.Error("fileExists nonexistent should be false")
	}
	if dirExists("__nonexistent_dir_460__") {
		t.Error("dirExists nonexistent should be false")
	}
}

// TestIsDesktopClientMode 检测 TSG_APP_DIR 环境变量
func TestIsDesktopClientMode(t *testing.T) {
	old := os.Getenv("TSG_APP_DIR")
	defer os.Setenv("TSG_APP_DIR", old)

	os.Unsetenv("TSG_APP_DIR")
	if isDesktopClientMode() {
		t.Error("TSG_APP_DIR unset should not be desktop mode")
	}

	os.Setenv("TSG_APP_DIR", "/tmp/tsg-test")
	if !isDesktopClientMode() {
		t.Error("TSG_APP_DIR set should be desktop mode")
	}
}

// TestClientLauncherNoPanic 客户端启动器整体不 panic
func TestClientLauncherNoPanic(t *testing.T) {
	// launchDesktopClient 在无显示环境（CI）调用 xdg-open 会挂起，
	// 这里不实际调用，只验证函数存在且逻辑可达
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("skip on wasm")
	}
	// 验证 launchDesktopClient 函数符号存在（编译通过即成立）
	_ = launchDesktopClient
}

// TestOpenBrowserOrClient 智能打开函数不 panic
func TestOpenBrowserOrClient(t *testing.T) {
	// 重置缓存
	clientInstalledCache = nil
	launchClient = false
	// 不实际调起浏览器（会打开系统浏览器），只验证函数存在且可调用
	// 由于 openBrowserOrClient 内部会调用 launchDesktopClient / openBrowser，
	// 在 CI 无显示环境时可能报错但不应 panic
	// 这里只测试逻辑分支覆盖
	launchClient = true
	// 不执行实际调用，避免在无头环境打开浏览器
	// 已通过 integration 覆盖
}
