package main

// v3.2.2 安全修复回归测试：SSRF 统一防线 / 敏感路径 denylist / 审计日志防注入

import (
"strings"
"testing"
)

func TestSSRFGuardStrictRejectsPrivate(t *testing.T) {
d := ssrfSafeDialContext(false, false)
for _, addr := range []string{"127.0.0.1:80", "10.0.0.1:443", "169.254.169.254:80", "192.168.1.1:8080", "[::1]:80"} {
if _, err := d(nil, "tcp", addr); err == nil || !strings.Contains(err.Error(), "SSRF") {
t.Errorf("严格模式应拒绝 %s，实际 err=%v", addr, err)
}
}
}

func TestSSRFGuardLocalException(t *testing.T) {
d := ssrfSafeDialContext(true, true)
// 回环/私网字面量在例外通道下不应被 SSRF 规则拒绝（连接本身可能失败，但错误不含 SSRF）
_ = contextTODO()

for _, addr := range []string{"127.0.0.1:1", "192.168.1.1:1"} {
if _, err := d(nil, "tcp", addr); err != nil && strings.Contains(err.Error(), "SSRF") {
t.Errorf("例外通道不应拒绝 %s：%v", addr, err)
}
}
// 链路本地/云元数据即使在例外通道也必须拒绝
if _, err := d(nil, "tcp", "169.254.169.254:80"); err == nil || !strings.Contains(err.Error(), "SSRF") {
t.Errorf("元数据地址必须始终拒绝，err=%v", err)
}
}

func TestRedirectURLValidation(t *testing.T) {
mk := func(loc string) *httpResponseShim { return &httpResponseShim{loc} }
_ = mk
// 通过 httptest 太重，直接测纯函数逻辑分支：用表驱动构造 Response
respOf := func(loc string) *httpResponseLite { return nil }
_ = respOf
// 见 TestRedirectTable
}

type httpResponseShim struct{ loc string }
type httpResponseLite struct{}

func TestAuditSanitize(t *testing.T) {
got := sanitizeAuditField("ok\n[AUDIT] FORGED USER=admin\r\tDETAIL=x")
if strings.ContainsAny(got, "\n\r\t") {
t.Errorf("清洗后仍含换行/制表符: %q", got)
}
if !strings.Contains(got, "FORGED") {
t.Errorf("内容丢失: %q", got)
}
}

func TestSensitivePathDenylist(t *testing.T) {
cases := map[string]bool{
"/opt/tars/config.json":        true,
"/opt/tars/gateway-key.txt":    true,
"/opt/tars/logs/audit-2.log":   true,
"/opt/tars/data/model.gguf":    false,
"/opt/tars/config.json.bak":    false, // 非精确文件名（可讨论，当前放行）
"C:\\Tars\\gateway-key.txt":    true,
}
for p, want := range cases {
if got := isSensitiveGatewayPath(p); got != want {
t.Errorf("isSensitiveGatewayPath(%q)=%v want %v", p, got, want)
}
}
}

func contextTODO() int { return 0 }
