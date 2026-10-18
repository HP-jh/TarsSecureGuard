package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestV4193BuildInfoInStatus /api/status 必须包含 build 字段（commit/time/by）
func TestV4193BuildInfoInStatus(t *testing.T) {
	// 准备 mux 并注册 /api/status
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", handleStatus)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("/api/status 状态码: got %d, want 200", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	build, ok := body["build"].(map[string]interface{})
	if !ok {
		t.Fatalf("/api/status 缺少 build 字段")
	}
	for _, k := range []string{"commit", "time", "by"} {
		if _, ok := build[k].(string); !ok {
			t.Errorf("build.%s 应为字符串", k)
		}
	}
	// ldflags 未注入时默认值应为 "unknown"
	if build["commit"] != "unknown" {
		t.Logf("build.commit 已注入: %v（预期：unknown 或实际 commit SHA）", build["commit"])
	}
}
