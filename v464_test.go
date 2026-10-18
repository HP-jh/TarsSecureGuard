// v4.6.4 安全头纵深防御 + 版本漂移修复测试
package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"tarssecureguard-v41/crownext/security"
)

// TestV464VersionBumped 版本号必须已升至 4.16.0
func TestV464VersionBumped(t *testing.T) {
	if version != "4.19.2" {
		t.Fatalf("version expected 4.16.0, got %s", version)
	}
}

// TestV464SecurityHeaders setSecurityHeaders 必须输出 CSP 与 Permissions-Policy
func TestV464SecurityHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	setSecurityHeaders(w, httptest.NewRequest("GET", "/", nil))
	h := w.Header()

	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("缺少 Content-Security-Policy 响应头")
	}
	// 关键指令逐一断言：外联封堵 / 插件禁用 / 基础地址锁定 / 嵌套框架禁止
	for _, want := range []string{
		"default-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP 缺少指令 %q，实际值: %s", want, csp)
		}
	}
	// connect-src 只放行自身与本机回环，不得出现任意外部 https 通配
	if strings.Contains(csp, "https://*") || strings.Contains(csp, "connect-src *") {
		t.Errorf("CSP connect-src 不得放行外部通配: %s", csp)
	}

	pp := h.Get("Permissions-Policy")
	if pp == "" {
		t.Fatal("缺少 Permissions-Policy 响应头")
	}
	for _, want := range []string{"camera=()", "microphone=()", "geolocation=()"} {
		if !strings.Contains(pp, want) {
			t.Errorf("Permissions-Policy 缺少 %q，实际值: %s", want, pp)
		}
	}

	// 既有三件套不回退
	for _, k := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if h.Get(k) == "" {
			t.Errorf("既有安全响应头 %s 丢失", k)
		}
	}
}

// TestV464SecurityEngineVersionSync 安全评分引擎版本号必须与网关主版本同步
// （v4.6.4 修复：此前引擎硬编码 4.6.2，评分页展示旧版本号）
func TestV464SecurityEngineVersionSync(t *testing.T) {
	// v4.19.2 修复：EngineVersion 改为运行时注入，测试前对齐到当前网关版本
	security.EngineVersion = version
	e := security.NewScoreEngine()
	e.RegisterEvaluator(&v464FakeEvaluator{name: "A", weight: 1.0, score: 90})
	rep, err := e.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	if rep.Version != version {
		t.Errorf("安全评分报告版本 %s 与网关版本 %s 不同步（历史漂移回归）", rep.Version, version)
	}
}

type v464FakeEvaluator struct {
	name   string
	weight float64
	score  float64
}

func (f *v464FakeEvaluator) Name() string              { return f.name }
func (f *v464FakeEvaluator) Weight() float64           { return f.weight }
func (f *v464FakeEvaluator) Evaluate(ctx context.Context) (security.Dimension, error) {
	return security.Dimension{Name: f.name, Score: f.score, Weight: f.weight}, nil
}
