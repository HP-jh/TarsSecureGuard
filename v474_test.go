// v4.7.4 B16 小白化（错误消息多语言 + 401 引导）测试
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestV474VersionBumped(t *testing.T) {
	if version != "4.8.0" {
		t.Fatalf("version expected 4.7.6, got %s", version)
	}
}

// TestV474UnauthorizedHintZh 中文 401 响应必须带 hint 字段并指向密钥文件
func TestV474UnauthorizedHintZh(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Accept-Language", "zh-CN")
	// 直接调用 i18nErrorJSONWithHint 走端到端
	i18nErrorJSONWithHint(rec, req, http.StatusUnauthorized, "err.unauthorized", "err.unauthorized.hint")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v / %q", err, rec.Body.String())
	}
	if body["lang"] != "zh" {
		t.Errorf("lang 应为 zh, got %q", body["lang"])
	}
	if body["key"] != "err.unauthorized" {
		t.Errorf("key 应为 err.unauthorized, got %q", body["key"])
	}
	if body["hint"] == "" {
		t.Error("hint 字段缺失")
	}
	// hint 至少要提到 X-API-Key 和 gateway-key.txt
	if !strings.Contains(body["hint"], "X-API-Key") {
		t.Error("中文 hint 应提到 X-API-Key")
	}
	if !strings.Contains(body["hint"], "gateway-key.txt") {
		t.Error("中文 hint 应提到 gateway-key.txt 文件位置")
	}
	if !strings.Contains(body["error"], "未授权") {
		t.Errorf("中文 error 应含「未授权」, got %q", body["error"])
	}
}

// TestV474UnauthorizedHintEn 英文 401 响应必须返回英文 hint
func TestV474UnauthorizedHintEn(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Accept-Language", "en-US")
	i18nErrorJSONWithHint(rec, req, http.StatusUnauthorized, "err.unauthorized", "err.unauthorized.hint")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if body["lang"] != "en" {
		t.Errorf("lang 应为 en, got %q", body["lang"])
	}
	if body["hint"] == "" {
		t.Error("hint 字段缺失")
	}
	// 英文 hint 应为英文
	if strings.ContainsAny(body["hint"], "未授权密钥") {
		t.Error("英文 hint 不应含中文字符")
	}
	if !strings.Contains(body["hint"], "X-API-Key") {
		t.Error("英文 hint 应提到 X-API-Key")
	}
	if !strings.Contains(body["hint"], "gateway-key.txt") {
		t.Error("英文 hint 应提到 gateway-key.txt")
	}
	if !strings.Contains(body["error"], "Unauthorized") {
		t.Errorf("英文 error 应含 Unauthorized, got %q", body["error"])
	}
}

// TestV474UnauthorizedNoHintHintKeyEmpty hintKey 为空时不附加 hint 字段
func TestV474UnauthorizedNoHintHintKeyEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	i18nErrorJSONWithHint(rec, req, http.StatusBadRequest, "err.badrequest", "")
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if _, ok := body["hint"]; ok {
		t.Errorf("hintKey 为空时不应有 hint 字段, got %q", body["hint"])
	}
	if body["error"] == "" {
		t.Error("error 字段不应为空")
	}
}

// TestV474InvalidConfigI18n 错配置走 i18n（中文 Accept-Language）
func TestV474InvalidConfigI18n(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/config", strings.NewReader("{not json"))
	req.Header.Set("Accept-Language", "zh-CN")
	i18nErrorJSON(rec, req, http.StatusBadRequest, "err.invalidconfig")
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if body["lang"] != "zh" {
		t.Errorf("lang 应为 zh, got %q", body["lang"])
	}
	if !strings.Contains(body["error"], "配置") {
		t.Errorf("中文 err.invalidconfig 应含「配置」, got %q", body["error"])
	}
}

// TestV474InvalidRequestI18nEn 错请求走 i18n（英文 Accept-Language）
func TestV474InvalidRequestI18nEn(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/search", strings.NewReader("bad"))
	req.Header.Set("Accept-Language", "en-GB")
	i18nErrorJSON(rec, req, http.StatusBadRequest, "err.invalidrequest")
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if body["lang"] != "en" {
		t.Errorf("lang 应为 en, got %q", body["lang"])
	}
	if !strings.Contains(body["error"], "malformed") {
		t.Errorf("英文 err.invalidrequest 应含 malformed, got %q", body["error"])
	}
}

// TestV474I18nUnknownKeyFallsBack 未知 key 应回退到 key 自身
func TestV474I18nUnknownKeyFallsBack(t *testing.T) {
	if m := i18nT("zh", "totally.unknown.key"); m != "totally.unknown.key" {
		t.Errorf("未知 key 应回退到自身, got %q", m)
	}
}

// TestV474I18nAllBuiltinKeysPresent 内置消息的 key 必须 zh/en 对齐（小白化底线：不能只有一半）
func TestV474I18nAllBuiltinKeysPresent(t *testing.T) {
	zh := builtinMessages["zh"]
	en := builtinMessages["en"]
	if len(zh) == 0 || len(en) == 0 {
		t.Fatal("zh / en 内置消息不能为空")
	}
	// 关键错误键必须两语言都有
	criticalKeys := []string{
		"err.unauthorized", "err.unauthorized.hint", "err.forbidden",
		"err.notfound", "err.ratelimit", "err.internal", "err.badrequest",
		"err.invalidconfig", "err.invalidrequest",
		"err.shutdown.denied", "err.shutdown.adminonly",
	}
	for _, k := range criticalKeys {
		if _, ok := zh[k]; !ok {
			t.Errorf("zh 缺少关键 key: %s", k)
		}
		if _, ok := en[k]; !ok {
			t.Errorf("en 缺少关键 key: %s", k)
		}
	}
}
