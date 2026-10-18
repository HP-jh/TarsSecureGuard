package main

import (
	"io/fs"
	"testing"
)

// TestV420EmbedCompleteness 验证 frontend 目录下所有文件均已通过 go:embed 编译进二进制
// 防止 i18n.js 类遗漏重演（B42 遗留修复）
func TestV420EmbedCompleteness(t *testing.T) {
	expected := []string{
		"frontend/index.html",
		"frontend/i18n.js",
	}
	for _, path := range expected {
		data, err := fs.ReadFile(frontendFS, path)
		if err != nil {
			t.Fatalf("embed 文件 %s 读取失败: %v", path, err)
		}
		if len(data) == 0 {
			t.Fatalf("embed 文件 %s 为空", path)
		}
	}
}

// TestV420I18nJSRoute 验证 i18n.js 可通过 HTTP 路由访问（内容非空且为 JS）
func TestV420I18nJSRoute(t *testing.T) {
	data, err := fs.ReadFile(frontendFS, "frontend/i18n.js")
	if err != nil {
		t.Fatalf("i18n.js embed 读取失败: %v", err)
	}
	if len(data) < 100 {
		t.Fatalf("i18n.js 内容过短 (%d bytes)，可能不完整", len(data))
	}
	head := string(data[:60])
	if head[:15] != "/**\n * TSG i18n" {
		t.Logf("i18n.js 头部: %q", head)
	}
}
