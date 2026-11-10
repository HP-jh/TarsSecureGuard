package kernel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSchedulerExecute(t *testing.T) {
	// 构造一个 3 阶段管道：auth → waf → rate-limit
	s := NewScheduler(
		&AuthStage{
			IsPublicRoute: func(p string) bool { return p == "/public" },
			Authenticate: func(r *http.Request) (string, string, string, []string, bool) {
				if r.Header.Get("Authorization") == "Bearer valid" {
					return "user1", "tenant1", "admin", []string{"g1"}, true
				}
				return "", "", "", nil, false
			},
		},
		&WAFStage{
			Detect: func(r *http.Request) string {
				if r.URL.Path == "/malicious" {
					return "SQL注入"
				}
				return ""
			},
			OnBlock: func(w http.ResponseWriter, r *http.Request, reason string) {
				w.WriteHeader(http.StatusForbidden)
			},
		},
	)

	// 测试 1：合法请求通过
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer valid")
	halted := s.Execute(context.Background(), rec, req)
	if halted {
		t.Error("合法请求不应被拦截")
	}

	// 测试 2：未授权请求被拦截
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	halted2 := s.Execute(context.Background(), rec2, req2)
	if !halted2 {
		t.Error("未授权请求应被拦截")
	}
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("期望 401，得到 %d", rec2.Code)
	}

	// 测试 3：公共路由放行
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/public", nil)
	halted3 := s.Execute(context.Background(), rec3, req3)
	if halted3 {
		t.Error("公共路由应放行")
	}

	// 测试 4：WAF 拦截
	rec4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodGet, "/malicious", nil)
	req4.Header.Set("Authorization", "Bearer valid")
	halted4 := s.Execute(context.Background(), rec4, req4)
	if !halted4 {
		t.Error("恶意请求应被 WAF 拦截")
	}
}

func TestSecuritySubsystem(t *testing.T) {
	sec := NewSecuritySubsystem(
		&IPBanStage{
			IsBanned: func(ip string) bool { return ip == "1.2.3.4" },
			OnBlock:  func(w http.ResponseWriter, r *http.Request, reason string) {
				w.WriteHeader(http.StatusForbidden)
			},
		},
		&WAFStage{
			Detect: func(r *http.Request) string { return "" },
		},
	)

	// 封禁 IP 被拦截
	rec := httptest.NewRecorder()
	rc := &RequestCtx{RemoteIP: "1.2.3.4"}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	result := sec.Check(context.Background(), rc, rec, req)
	if result != Halt {
		t.Error("封禁 IP 应被拦截")
	}

	// 正常 IP 通过
	rec2 := httptest.NewRecorder()
	rc2 := &RequestCtx{RemoteIP: "5.6.7.8"}
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	result2 := sec.Check(context.Background(), rc2, rec2, req2)
	if result2 != Continue {
		t.Error("正常 IP 应通过")
	}
}

func TestKernelBootShutdown(t *testing.T) {
	k := NewKernel()
	k.ConfigStore = NewConfigStore(nil)
	k.Memory = NewMemoryManager()
	k.Identity = NewIdentitySubsystem()
	k.Observer = NewObserver()

	if err := k.Boot(); err != nil {
		t.Fatalf("Boot failed: %v", err)
	}
	if k.Uptime() <= 0 {
		t.Error("Uptime should be positive after boot")
	}
	k.Shutdown()
}

func TestFailClosePanic(t *testing.T) {
	s := NewScheduler(StageFunc{
		StageName: "panic-stage",
		Fn: func(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
			panic("test panic")
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	halted := s.Execute(context.Background(), rec, req)
	if !halted {
		t.Error("panic 应导致 Halt (fail-close)")
	}
}
