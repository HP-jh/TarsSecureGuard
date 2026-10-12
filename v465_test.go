// v4.6.5 UI 修复测试：版本徽章动态化 + 内联 favicon
package main

import (
	"strings"
	"testing"
)

// TestV465VersionBumped 版本号必须已升至 4.7.1
func TestV465VersionBumped(t *testing.T) {
	if version != "4.7.1" {
		t.Fatalf("version expected 4.7.1, got %s", version)
	}
}

// TestV465DynamicVersionBadge 侧边栏版本徽章必须动态化（id=ver-badge + syncVerBadge），
// 禁止再出现写死的 ver">vX.Y.Z——该漂移自 v4.6.0 起连续三个版本未更新徽章
func TestV465DynamicVersionBadge(t *testing.T) {
	html, err := frontendFS.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatalf("读取前端资源失败: %v", err)
	}
	s := string(html)

	if !strings.Contains(s, `id="ver-badge"`) {
		t.Error("侧边栏版本徽章缺少 id=\"ver-badge\"，无法动态更新")
	}
	if !strings.Contains(s, "function syncVerBadge()") {
		t.Error("缺少 syncVerBadge() 动态版本同步函数")
	}
	// 回归防线：不允许再出现写死的版本徽章（class="ver">vX.Y.Z 形式，紧跟版本号即静态写死）
	if strings.Contains(s, `class="ver">v`) {
		i := strings.Index(s, `class="ver">v`)
		t.Errorf("版本徽章仍是静态写死: %q", s[i:i+40])
	}
	// DOMContentLoaded 时应触发一次版本同步
	if !strings.Contains(s, "syncVerBadge();") {
		t.Error("DOMContentLoaded 未挂接 syncVerBadge()，首次进入页面徽章不刷新")
	}
}

// TestV465InlineFavicon 前端必须内置 favicon（内联 SVG data URI），
// 消除浏览器自动请求 /favicon.ico 造成的 404 噪音
func TestV465InlineFavicon(t *testing.T) {
	html, err := frontendFS.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatalf("读取前端资源失败: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `rel="icon"`) {
		t.Error("缺少 <link rel=\"icon\"> favicon 声明")
	}
	if !strings.Contains(s, "data:image/svg+xml,") {
		t.Error("favicon 应为内联 SVG data URI，避免外部请求")
	}
}
