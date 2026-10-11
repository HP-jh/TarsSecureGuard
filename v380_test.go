// v3.8.0 职业系统专项测试
// 覆盖：内置职业列表 / 职业切换 / 全局记忆写入 / 模型矩阵 / 调用链优化状态
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestV380VersionBumped(t *testing.T) {
	if version != "4.6.0" {
		t.Fatalf("version = %q, want 3.9.0", version)
	}
}

func TestV380PersonaList(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/v38/personas", nil)
	req.Header.Set("X-API-Key", cfg.Security.APIKey)
	rec := httptest.NewRecorder()
	handleV38Personas(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	var resp struct {
		Personas []Persona `json:"personas"`
		Current  string    `json:"current"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(resp.Personas) != 5 {
		t.Fatalf("职业数 = %d, want 5", len(resp.Personas))
	}
	ids := map[string]bool{}
	for _, p := range resp.Personas {
		ids[p.ID] = true
	}
	for _, want := range []string{"student", "writer", "developer", "researcher", "general"} {
		if !ids[want] {
			t.Errorf("缺少职业 %s", want)
		}
	}
}

func TestV380PersonaSelectAndCurrent(t *testing.T) {
	// 切换到学生
	body := strings.NewReader(`{"id":"student"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/v38/persona/select", body)
	req.Header.Set("X-API-Key", cfg.Security.APIKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleV38PersonaSelect(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("select 状态码 = %d, body=%s", rec.Code, rec.Body.String())
	}
	var sel struct {
		Success bool    `json:"success"`
		Persona Persona `json:"persona"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sel); err != nil {
		t.Fatalf("select 解析失败: %v", err)
	}
	if !sel.Success || sel.Persona.ID != "student" {
		t.Fatalf("select 失败: %+v", sel)
	}

	// 验证 current
	req2 := httptest.NewRequest(http.MethodGet, "/api/admin/v38/persona/current", nil)
	req2.Header.Set("X-API-Key", cfg.Security.APIKey)
	rec2 := httptest.NewRecorder()
	handleV38PersonaCurrent(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("current 状态码 = %d", rec2.Code)
	}
	var cur struct {
		Persona Persona      `json:"persona"`
		State   PersonaState `json:"state"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &cur); err != nil {
		t.Fatalf("current 解析失败: %v", err)
	}
	if cur.Persona.ID != "student" {
		t.Errorf("current persona = %s, want student", cur.Persona.ID)
	}
	if cur.State.CurrentID != "student" {
		t.Errorf("state currentId = %s, want student", cur.State.CurrentID)
	}

	// 切回通用（恢复状态）
	body3 := strings.NewReader(`{"id":"general"}`)
	req3 := httptest.NewRequest(http.MethodPost, "/api/admin/v38/persona/select", body3)
	req3.Header.Set("X-API-Key", cfg.Security.APIKey)
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	handleV38PersonaSelect(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("恢复通用失败: %d, %s", rec3.Code, rec3.Body.String())
	}
}

func TestV380ModelMatrix(t *testing.T) {
	// 先切到 writer（有 required caps）
	body := strings.NewReader(`{"id":"writer"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/v38/persona/select", body)
	req.Header.Set("X-API-Key", cfg.Security.APIKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleV38PersonaSelect(rec, req)

	req2 := httptest.NewRequest(http.MethodGet, "/api/admin/v38/model-matrix", nil)
	req2.Header.Set("X-API-Key", cfg.Security.APIKey)
	rec2 := httptest.NewRecorder()
	handleV38ModelMatrix(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("matrix 状态码 = %d", rec2.Code)
	}
	var resp struct {
		Persona string `json:"persona"`
		Matrix  []struct {
			ModelMatrixEntry
			Suitable bool `json:"suitable"`
		} `json:"matrix"`
		Summary map[string]interface{} `json:"summary"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("matrix 解析失败: %v", err)
	}
	if resp.Persona != "writer" {
		t.Errorf("persona = %s, want writer", resp.Persona)
	}
	// 恢复
	body3 := strings.NewReader(`{"id":"general"}`)
	req3 := httptest.NewRequest(http.MethodPost, "/api/admin/v38/persona/select", body3)
	req3.Header.Set("X-API-Key", cfg.Security.APIKey)
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	handleV38PersonaSelect(rec3, req3)
}

func TestV380ChainOptStatus(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/v38/chainopt/status", nil)
	req.Header.Set("X-API-Key", cfg.Security.APIKey)
	rec := httptest.NewRecorder()
	handleV38ChainOptStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chainopt 状态码 = %d", rec.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("chainopt 解析失败: %v", err)
	}
	if resp["persona"] == nil {
		t.Error("缺少 persona 字段")
	}
}

func TestV380PersonaModuleRegistered(t *testing.T) {
	found := false
	for _, m := range moduleRegistry {
		if m.ID == "persona" {
			found = true
			if !m.Default {
				t.Error("persona 模块应为默认开启")
			}
		}
	}
	if !found {
		t.Error("persona 模块未注册到 moduleRegistry")
	}
}

func TestV380BuiltInPersonasComplete(t *testing.T) {
	if len(builtInPersonas) != 5 {
		t.Fatalf("内置职业数 = %d, want 5", len(builtInPersonas))
	}
	for _, p := range builtInPersonas {
		if p.ID == "" || p.Name == "" || p.MemoryPrompt == "" {
			t.Errorf("职业 %s 配置不完整", p.ID)
		}
		if p.ResourceStrategy.MaxConcurrent < 1 {
			t.Errorf("职业 %s MaxConcurrent 无效", p.ID)
		}
	}
}
