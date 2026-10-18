package main

import (
	"strings"
	"testing"
)

// TestMaskPIIPhone 测试中国大陆手机号脱敏（3 档强度）
func TestMaskPIIPhone(t *testing.T) {
	cases := []struct {
		input    string
		lvl      string
		expected string
	}{
		{"手机号 13800138000 测试", "full", "手机号 **** 测试"},
		{"手机号 13800138000 测试", "partial", "手机号 138****8000 测试"},
		{"手机号 13800138000 测试", "hash", "手机号 " + hashPrefix8("13800138000") + " 测试"},
	}
	for _, c := range cases {
		// 临时修改全局配置（测试隔离）
		cfg.Security.PIIMaskLevel = c.lvl
		got := maskPII(c.input)
		if got != c.expected {
			t.Errorf("maskPII(%q, lvl=%q) = %q, want %q", c.input, c.lvl, got, c.expected)
		}
	}
	cfg.Security.PIIMaskLevel = "full" // 恢复默认
}

// TestMaskPIIEmail 测试邮箱脱敏
func TestMaskPIIEmail(t *testing.T) {
	cases := []struct {
		input    string
		lvl      string
		expected string
	}{
		{"联系 admin@example.com 谢谢", "full", "联系 **** 谢谢"},
		{"联系 admin@example.com 谢谢", "partial", "联系 a****@example.com 谢谢"},
	}
	for _, c := range cases {
		cfg.Security.PIIMaskLevel = c.lvl
		got := maskPII(c.input)
		if got != c.expected {
			t.Errorf("maskPII(%q, lvl=%q) = %q, want %q", c.input, c.lvl, got, c.expected)
		}
	}
	cfg.Security.PIIMaskLevel = "full"
}

// TestMaskPIIIDCard 测试身份证号脱敏
func TestMaskPIIIDCard(t *testing.T) {
	id := "110101199001011234"
	cases := []struct {
		lvl      string
		expected string
	}{
		{"full", "****"},
		{"partial", "110***********1234"},
	}
	for _, c := range cases {
		cfg.Security.PIIMaskLevel = c.lvl
		got := maskPII(id)
		if got != c.expected {
			t.Errorf("maskPII(%q, lvl=%q) = %q, want %q", id, c.lvl, got, c.expected)
		}
	}
	cfg.Security.PIIMaskLevel = "full"
}

// TestMaskPIIIp 测试 IPv4 脱敏
func TestMaskPIIIp(t *testing.T) {
	cases := []struct {
		input    string
		lvl      string
		expected string
	}{
		{"服务器 192.168.1.1 在线", "full", "服务器 **** 在线"},
		{"服务器 192.168.1.1 在线", "partial", "服务器 192.168.****.1 在线"},
	}
	for _, c := range cases {
		cfg.Security.PIIMaskLevel = c.lvl
		got := maskPII(c.input)
		if got != c.expected {
			t.Errorf("maskPII(%q, lvl=%q) = %q, want %q", c.input, c.lvl, got, c.expected)
		}
	}
	cfg.Security.PIIMaskLevel = "full"
}

// TestMaskPIICreditCard 测试信用卡脱敏
func TestMaskPIICreditCard(t *testing.T) {
	cc := "1234 5678 9012 3456"
	got := maskPII(cc)
	if got != "****" {
		t.Errorf("maskPII(credit card) = %q, want ****", got)
	}
}

// TestMaskPIISSN 测试 SSN 脱敏
func TestMaskPIISSN(t *testing.T) {
	ssn := "123-45-6789"
	cases := []struct {
		lvl      string
		expected string
	}{
		{"full", "****"},
		{"partial", "***-**-****"},
	}
	for _, c := range cases {
		cfg.Security.PIIMaskLevel = c.lvl
		got := maskPII(ssn)
		if got != c.expected {
			t.Errorf("maskPII(%q, lvl=%q) = %q, want %q", ssn, c.lvl, got, c.expected)
		}
	}
	cfg.Security.PIIMaskLevel = "full"
}

// TestMaskPIIMultiple 测试多种 PII 混合文本
func TestMaskPIIMultiple(t *testing.T) {
	input := "用户 13800138000，邮箱 user@test.com，IP 10.0.0.1"
	got := maskPII(input)
	if strings.Contains(got, "13800138000") {
		t.Error("手机号未脱敏")
	}
	if strings.Contains(got, "user@test.com") {
		t.Error("邮箱未脱敏")
	}
	if strings.Contains(got, "10.0.0.1") {
		t.Error("IP 未脱敏")
	}
}

// TestMaskPIIInJSONBody 测试 JSON 响应体脱敏（模拟响应流出场景）
func TestMaskPIIInJSONBody(t *testing.T) {
	input := `{"message":"我的手机号是 13800138000","email":"a@b.com"}`
	got := maskPII(input)
	if strings.Contains(got, "13800138000") {
		t.Error("JSON 中的手机号未脱敏")
	}
	if strings.Contains(got, "a@b.com") {
		t.Error("JSON 中的邮箱未脱敏")
	}
	// JSON 结构应保持完整
	if !strings.Contains(got, `"message"`) || !strings.Contains(got, `"email"`) {
		t.Error("JSON 键名被破坏")
	}
}

// TestPIIMaskLevelDefault 测试非法配置回退 full
func TestPIIMaskLevelDefault(t *testing.T) {
	cfg.Security.PIIMaskLevel = "invalid"
	if lvl := piiMaskLevel(); lvl != "full" {
		t.Errorf("piiMaskLevel() = %q, want full", lvl)
	}
	cfg.Security.PIIMaskLevel = "full"
}

// TestPIIMaskEnabled 测试开关读取
func TestPIIMaskEnabled(t *testing.T) {
	cfg.Security.PIIMaskEnabled = true
	if !piiMaskEnabled() {
		t.Error("piiMaskEnabled() should be true")
	}
	cfg.Security.PIIMaskEnabled = false
	if piiMaskEnabled() {
		t.Error("piiMaskEnabled() should be false")
	}
	cfg.Security.PIIMaskEnabled = true
}
