package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestV435VersionLocked 验证版本号已正确升级到 4.35.0
func TestV435VersionLocked(t *testing.T) {
	if version != "4.35.0" {
		t.Fatalf("expected version 4.35.0, got %s", version)
	}
}

// TestV435HealthRuntimeMetrics 验证 health 端点包含运行时指标字段
func TestV435HealthRuntimeMetrics(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal health response: %v", err)
	}

	required := []string{"status", "version", "uptime", "first_run",
		"goroutines", "cpus", "memory_mb", "memory_sys_mb", "gc_count"}
	for _, k := range required {
		if _, ok := body[k]; !ok {
			t.Errorf("health response missing key %q", k)
		}
	}

	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %v", body["status"])
	}
	if body["version"] != "4.35.0" {
		t.Errorf("expected version 4.35.0, got %v", body["version"])
	}

	// 验证数值字段类型合理
	if g, ok := body["goroutines"].(float64); !ok || g < 1 {
		t.Errorf("goroutines should be >=1, got %v", body["goroutines"])
	}
	if c, ok := body["cpus"].(float64); !ok || c < 1 {
		t.Errorf("cpus should be >=1, got %v", body["cpus"])
	}
	if mem, ok := body["memory_mb"].(float64); !ok || mem < 0 {
		t.Errorf("memory_mb should be >=0, got %v", body["memory_mb"])
	}
}
