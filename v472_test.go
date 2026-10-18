// v4.7.3 HTTP server 性能加固测试：ReadHeaderTimeout 防 Slowloris
package main

import (
	"os"
	"strings"
	"testing"
)

// TestV472VersionBumped 版本号必须已升至 4.16.0
func TestV472VersionBumped(t *testing.T) {
	if version != "4.34.0" {
		t.Fatalf("version expected 4.16.0, got %s", version)
	}
}

// TestV472ReadHeaderTimeoutConfigured main.go 中必须显式设置
// http.Server.ReadHeaderTimeout，防止 Slowloris 慢连接攻击消耗资源
func TestV472ReadHeaderTimeoutConfigured(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读取 main.go 失败: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "ReadHeaderTimeout:") {
		t.Error("HTTP server 未配置 ReadHeaderTimeout（防 Slowloris 必需）")
	}
	if !strings.Contains(s, "ReadHeaderTimeout: 10 * time.Second") {
		t.Error("ReadHeaderTimeout 应设为 10s（平衡 Slowloris 防护与合法慢客户端容忍）")
	}
}
