// v4.7.3 B15 客户端稳定性提升测试
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestV470VersionBumped(t *testing.T) {
	if version != "4.16.0" {
		t.Fatalf("version expected 4.16.0, got %s", version)
	}
}

// TestV470I18nExists i18n 模块必须存在且能兜底
func TestV470I18nExists(t *testing.T) {
	// 中文兜底
	if m := i18nT("zh", "err.unauthorized"); m == "" || m == "err.unauthorized" {
		t.Error("i18n zh err.unauthorized 未命中或返回空")
	}
	// 英文存在
	if m := i18nT("en", "err.unauthorized"); m == "" || m == "err.unauthorized" {
		t.Error("i18n en err.unauthorized 未命中或返回空")
	}
	// 未知语言回退中文
	if m := i18nT("xx", "err.unauthorized"); m == "" {
		t.Error("i18n 未知语言未回退到中文兜底")
	}
	// 未知 key 返回 key 自身（非空兜底）
	if m := i18nT("zh", "unknown.key"); m != "unknown.key" {
		t.Errorf("i18n 未知 key 应返回自身，got %q", m)
	}
	// 语言列表至少包含 zh + en
	langs := i18nListLanguages()
	if len(langs) < 2 {
		t.Errorf("i18n 语言列表不足 2 个: %v", langs)
	}
}

// TestV470SelfProtectStatusEndpoint 防自关保护状态端点必须可访问
func TestV470SelfProtectStatusEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/selfprotect/status", nil)
	handleSelfProtectStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("selfprotect/status 返回 %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "active") {
		t.Error("selfprotect/status 响应缺少 active 字段")
	}
	if !strings.Contains(body, "isAdmin") {
		t.Error("selfprotect/status 响应缺少 isAdmin 字段")
	}
}

// TestV470ShutdownEndpointRequiresAuth 关闭网关 API 必须鉴权
func TestV470ShutdownEndpointRequiresAuth(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/shutdown", nil)
	handleShutdown(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("shutdown 无鉴权应返回 401，got %d", rec.Code)
	}
}

// TestV470AVCompatStatusEndpoint 安全软件兼容状态端点必须可访问
func TestV470AVCompatStatusEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/av-compat/status", nil)
	handleAVCompatStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("av-compat/status 返回 %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "platform") {
		t.Error("av-compat/status 响应缺少 platform 字段")
	}
}

// TestV470FrontendHasI18nAndShutdown 前端必须包含多语言和关闭网关相关代码
func TestV470FrontendHasI18nAndShutdown(t *testing.T) {
	html, err := frontendFS.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatalf("读取前端资源失败: %v", err)
	}
	s := string(html)
	// 多语言
	if !strings.Contains(s, "I18N_MSGS") {
		t.Error("前端缺少 I18N_MSGS 多语言映射")
	}
	if !strings.Contains(s, "function currentLang()") {
		t.Error("前端缺少 currentLang() 函数")
	}
	if !strings.Contains(s, "function setLang(") {
		t.Error("前端缺少 setLang() 函数")
	}
	// 关闭网关按钮
	if !strings.Contains(s, "shutdownGateway(") {
		t.Error("前端缺少 shutdownGateway() 函数")
	}
	// 安全软件兼容
	if !strings.Contains(s, "loadAVCompat(") {
		t.Error("前端缺少 loadAVCompat() 函数")
	}
	// 语言选择器
	if !strings.Contains(s, "st-lang") {
		t.Error("前端缺少语言选择器 st-lang")
	}
}
