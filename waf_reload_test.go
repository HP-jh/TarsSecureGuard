package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadWAFRules_Success 验证从 JSON 文件加载自定义规则成功
func TestLoadWAFRules_Success(t *testing.T) {
	dir := t.TempDir()
	oldFile := wafRulesFile
	oldPath := configPath
	defer func() {
		wafRulesFile = oldFile
		configPath = oldPath
	}()

	configPath = filepath.Join(dir, "config.json")
	wafRulesFile = filepath.Join(dir, "waf-rules.json")
	content := `{"rules":[{"name":"测试规则","pattern":"(?i)test","strict":false}]}`
	if err := os.WriteFile(wafRulesFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	if err := loadWAFRules(); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	wafRulesMu.RLock()
	defer wafRulesMu.RUnlock()
	if len(wafRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(wafRules))
	}
	if wafRules[0].name != "测试规则" {
		t.Fatalf("unexpected rule name: %s", wafRules[0].name)
	}
}

// TestLoadWAFRules_InvalidJSON 验证 JSON 解析失败时保留旧规则
func TestLoadWAFRules_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	oldFile := wafRulesFile
	oldPath := configPath
	defer func() {
		wafRulesFile = oldFile
		configPath = oldPath
	}()

	configPath = filepath.Join(dir, "config.json")
	wafRulesFile = filepath.Join(dir, "waf-rules.json")

	// 先写入有效规则并加载
	os.WriteFile(wafRulesFile, []byte(`{"rules":[{"name":"有效规则","pattern":"abc","strict":false}]}`), 0644)
	if err := loadWAFRules(); err != nil {
		t.Fatal(err)
	}

	// 再写入无效 JSON
	os.WriteFile(wafRulesFile, []byte(`{invalid}`), 0644)
	if err := loadWAFRules(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	// 旧规则应保留
	wafRulesMu.RLock()
	defer wafRulesMu.RUnlock()
	if len(wafRules) != 1 || wafRules[0].name != "有效规则" {
		t.Fatalf("old rules should be preserved, got: %+v", wafRules)
	}
}

// TestLoadWAFRules_InvalidRegex 验证正则编译失败时保留旧规则
func TestLoadWAFRules_InvalidRegex(t *testing.T) {
	dir := t.TempDir()
	oldFile := wafRulesFile
	oldPath := configPath
	defer func() {
		wafRulesFile = oldFile
		configPath = oldPath
	}()

	configPath = filepath.Join(dir, "config.json")
	wafRulesFile = filepath.Join(dir, "waf-rules.json")
	os.WriteFile(wafRulesFile, []byte(`{"rules":[{"name":"坏正则","pattern":"[","strict":false}]}`), 0644)

	if err := loadWAFRules(); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

// TestLoadWAFRules_MissingFile 验证文件不存在时回退到内置规则
func TestLoadWAFRules_MissingFile(t *testing.T) {
	dir := t.TempDir()
	oldFile := wafRulesFile
	oldPath := configPath
	defer func() {
		wafRulesFile = oldFile
		configPath = oldPath
	}()

	configPath = filepath.Join(dir, "config.json")
	wafRulesFile = filepath.Join(dir, "nonexistent.json")
	if err := loadWAFRules(); err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}

	wafRulesMu.RLock()
	defer wafRulesMu.RUnlock()
	if len(wafRules) != len(wafBuiltinRules) {
		t.Fatalf("expected builtin rules (%d), got %d", len(wafBuiltinRules), len(wafRules))
	}
}

// TestLoadWAFRules_EmptyRules 验证空规则数组时保留旧规则
func TestLoadWAFRules_EmptyRules(t *testing.T) {
	dir := t.TempDir()
	oldFile := wafRulesFile
	oldPath := configPath
	defer func() {
		wafRulesFile = oldFile
		configPath = oldPath
	}()

	configPath = filepath.Join(dir, "config.json")
	wafRulesFile = filepath.Join(dir, "waf-rules.json")
	os.WriteFile(wafRulesFile, []byte(`{"rules":[]}`), 0644)

	if err := loadWAFRules(); err == nil {
		t.Fatal("expected error for empty rules")
	}
}

// TestWafMatchWithReload 验证热重载后新规则生效
func TestWafMatchWithReload(t *testing.T) {
	dir := t.TempDir()
	oldFile := wafRulesFile
	oldPath := configPath
	defer func() {
		wafRulesFile = oldFile
		configPath = oldPath
	}()

	configPath = filepath.Join(dir, "config.json")
	wafRulesFile = filepath.Join(dir, "waf-rules.json")
	os.WriteFile(wafRulesFile, []byte(`{"rules":[{"name":"关键词拦截","pattern":"(?i)badword","strict":false}]}`), 0644)
	if err := loadWAFRules(); err != nil {
		t.Fatal(err)
	}

	if wafMatch("this has badword in it", false) != "关键词拦截" {
		t.Fatal("expected new rule to match")
	}
	if wafMatch("clean text", false) != "" {
		t.Fatal("expected no match for clean text")
	}
}

// TestWafRulesHash 验证文件哈希计算
func TestWafRulesHash(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.json")

	if h := wafRulesHash(p); h != "" {
		t.Fatalf("expected empty hash for missing file, got: %s", h)
	}

	os.WriteFile(p, []byte(`{"rules":[]}`), 0644)
	h1 := wafRulesHash(p)
	if h1 == "" {
		t.Fatal("expected non-empty hash")
	}

	os.WriteFile(p, []byte(`{"rules":[{"name":"x","pattern":"y","strict":false}]}`), 0644)
	h2 := wafRulesHash(p)
	if h1 == h2 {
		t.Fatal("expected different hash for different content")
	}
}
