package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ===================== v3.2.1 桌面客户端（Tauri shell · sidecar）=====================

// 版本号推进：客户端（Tauri 壳）与网关（Go）同版本号发布，防双轨漂移
// v3.2.2：治理层版本推进（共享记忆/共享信息/上下文拓展/OAuth/守门人/审计升级）
// v3.2.3：性能升级 v2（WAF 合并+预筛 / PII 单遍化 / 响应缓存分片锁）
// v3.2.4：UI 升级（治理层可视化管理台：治理总览/共享记忆/共享信息/审计链 v2）
// v3.3.0：转换中枢与模型库（custom 协议适配器 / 能力库与能力感知路由 / provider API 申请直达）
// v3.4.0：连接器生态 / 工具链路降耗与轻量 Token 测量器
func TestV321VersionBumped(t *testing.T) {
	if version != "3.4.0" {
		t.Fatalf("version = %q, want 3.4.0", version)
	}
}

// --no-browser 标记：Tauri 壳以 sidecar 拉起网关时抑制自动打开浏览器
func TestV321ScanNoBrowserFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"tsg"}, false},
		{[]string{"tsg", "--foo"}, false},
		{[]string{"tsg", "--no-browser"}, true},
		{[]string{"tsg", "-no-browser"}, true},
		{[]string{"--mcp-stdio", "--no-browser"}, true},
		{[]string{"tsg", "--no-browser=1"}, false}, // 布尔开关不接值，防误吞
	}
	for _, c := range cases {
		if got := scanNoBrowserFlag(c.args); got != c.want {
			t.Errorf("scanNoBrowserFlag(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}

// Tauri 窗口 origin 受信：macOS/Linux 为 tauri://localhost，Windows 为 http(s)://tauri.localhost。
// 仅窗口 origin 本身受信——端口/主机变体与其它 scheme 一律拒绝，鉴权链照常执行。
func TestV321TauriOriginsTrusted(t *testing.T) {
	trusted := []string{
		"tauri://localhost",
		"http://tauri.localhost",
		"https://tauri.localhost",
	}
	for _, o := range trusted {
		if !isTrustedOrigin(o) {
			t.Errorf("isTrustedOrigin(%q) = false, want true", o)
		}
	}
	untrusted := []string{
		"",                       // 空值
		"tauri://evil",           // tauri scheme 只信 localhost
		"tauri://localhost:8080", // 端口变体拒绝
		"http://tauri.localhost:8080",
		"http://evil.localhost",
		"https://tauri.localhost.evil.com",
		"file://localhost",
		"http://127.0.0.1:9999", // 非网关端口仍按原有逻辑拒绝
		"https://example.com",
	}
	for _, o := range untrusted {
		if isTrustedOrigin(o) {
			t.Errorf("isTrustedOrigin(%q) = true, want false", o)
		}
	}
}

// TestV321AppDirOverride 验证 TSG_APP_DIR 环境变量对 appDir() 的单点覆盖
// （桌面客户端把数据目录指到系统用户数据目录），以及未设置时回落 exe 目录。
func TestV321AppDirOverride(t *testing.T) {
	os.Unsetenv("TSG_APP_DIR")
	base := appDir() // 未设置时的基线（exe 所在目录）

	os.Setenv("TSG_APP_DIR", filepath.Join(t.TempDir(), "desktop-data"))
	defer os.Unsetenv("TSG_APP_DIR")
	if got := appDir(); got != os.Getenv("TSG_APP_DIR") {
		t.Fatalf("TSG_APP_DIR 未生效：appDir()=%q, want %q", got, os.Getenv("TSG_APP_DIR"))
	}

	os.Setenv("TSG_APP_DIR", "")
	if got := appDir(); got != base {
		t.Fatalf("TSG_APP_DIR 置空后应回落 exe 目录：appDir()=%q, want %q", got, base)
	}
}
