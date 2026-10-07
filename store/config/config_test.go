package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMissingFileReturnsDefaultsWithWarning(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	if c.Security.Mode != ModeNormal || c.Listen.Addr != ":18889" {
		t.Fatalf("defaults wrong: %+v", c)
	}
	if len(c.Warnings()) == 0 {
		t.Fatal("missing file must produce a warning")
	}
}

func TestParseInvalidJSONErrorsLoudly(t *testing.T) {
	// v3.8.0 P0：解析失败必须显式报错，绝不静默回退默认
	if _, err := Parse([]byte(`{"listen": `)); err == nil {
		t.Fatal("want error for invalid JSON")
	}
	if _, err := Parse([]byte(`[1,2,3]`)); err == nil {
		t.Fatal("want error for non-object top level")
	}
}

func TestUnderscoreAnnotationKeysTolerated(t *testing.T) {
	// 复现 v3.8.0 事故场景：providers._说明 字符串键
	src := `{
		"_注释": "顶层注释键",
		"listen": {"addr": ":1234"},
		"providers": {
			"_说明": "这里放 provider 配置",
			"openai": {"base_url": "https://example.invalid/v1"}
		}
	}`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("annotation keys must not break parsing: %v", err)
	}
	if c.Listen.Addr != ":1234" {
		t.Fatalf("listen not parsed: %+v", c.Listen)
	}
	if _, ok := c.Providers["openai"]; !ok {
		t.Fatal("provider entry lost")
	}
	if _, ok := c.Providers["_说明"]; !ok {
		t.Fatal("annotation entry must be preserved raw")
	}
	if _, ok := c.Unknown["_注释"]; !ok {
		t.Fatal("top-level annotation must be preserved in Unknown")
	}
	if len(c.Warnings()) == 0 {
		t.Fatal("annotation keys must produce warnings")
	}
}

func TestProviderEntryMustBeObject(t *testing.T) {
	src := `{"providers": {"openai": "just-a-string"}}`
	if _, err := Parse([]byte(src)); err == nil {
		t.Fatal("want error for non-object provider entry")
	}
}

func TestSecurityFloorCorrection(t *testing.T) {
	c, err := Parse([]byte(`{"security": {"mode": "off"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Security.Mode != ModeNormal {
		t.Fatalf("mode off must be corrected to normal, got %q", c.Security.Mode)
	}
	joined := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(joined, "CONFIG_CORRECTED") {
		t.Fatalf("correction must be warned: %v", c.Warnings())
	}
	// strict 合法，不被纠正
	c2, err := Parse([]byte(`{"security": {"mode": "strict"}}`))
	if err != nil || c2.Security.Mode != ModeStrict {
		t.Fatalf("strict must be kept: %v %+v", err, c2)
	}
}

func TestUnknownSectionPreservedOnSaveRoundTrip(t *testing.T) {
	src := `{
		"listen": {"addr": ":9"},
		"security": {"mode": "strict"},
		"customThing": {"a": 1, "b": [true, false]}
	}`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "saved.json")
	if err := c.Save(out); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Listen.Addr != ":9" || c2.Security.Mode != ModeStrict {
		t.Fatalf("typed sections lost: %+v", c2)
	}
	raw, ok := c2.Unknown["customThing"]
	if !ok {
		t.Fatal("unknown section lost on round trip")
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["a"] != float64(1) {
		t.Fatalf("unknown section content altered: %v", m)
	}
	if len(c2.Warnings()) == 0 {
		t.Fatal("unknown section must warn on re-load")
	}
}

func TestSavePermissionsAndAtomicity(t *testing.T) {
	c := Default()
	out := filepath.Join(t.TempDir(), "config.json")
	if err := c.Save(out); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("want 0600, got %o", perm)
	}
	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file must not survive")
	}
	// 覆盖已有文件仍是原子替换
	if err := c.Save(out); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownSectionErrorsLoudly(t *testing.T) {
	// listen 段类型错误：必须报错
	if _, err := Parse([]byte(`{"listen": {"addr": 123}}`)); err == nil {
		t.Fatal("want error for typed section mismatch")
	}
	// security 段类型错误：必须报错
	if _, err := Parse([]byte(`{"security": {"mode": {"bad": true}}}`)); err == nil {
		t.Fatal("want error for security section mismatch")
	}
}
