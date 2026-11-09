package pipeline

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPipelineContinueAndHalt(t *testing.T) {
	// 两个 Continue 阶段 + handler
	executed := false
	p := New(
		StageFunc{StageName: "pass1", Fn: func(_ context.Context, _ *RequestContext, _ http.ResponseWriter, _ *http.Request) StageResult {
			return Continue
		}},
		StageFunc{StageName: "pass2", Fn: func(_ context.Context, _ *RequestContext, _ http.ResponseWriter, _ *http.Request) StageResult {
			executed = true
			return Continue
		}},
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	rc := &RequestContext{}

	halted := p.Execute(w, r, rc)
	if halted {
		t.Fatal("expected not halted")
	}
	if !executed {
		t.Fatal("expected second stage to execute")
	}
	if len(rc.Stages) != 2 {
		t.Fatalf("expected 2 stage metrics, got %d", len(rc.Stages))
	}
}

func TestPipelineHalt(t *testing.T) {
	reachedThird := false
	p := New(
		StageFunc{StageName: "block", Fn: func(_ context.Context, _ *RequestContext, w http.ResponseWriter, _ *http.Request) StageResult {
			w.WriteHeader(http.StatusForbidden)
			return Halt
		}},
		StageFunc{StageName: "never", Fn: func(_ context.Context, _ *RequestContext, _ http.ResponseWriter, _ *http.Request) StageResult {
			reachedThird = true
			return Continue
		}},
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	rc := &RequestContext{}

	halted := p.Execute(w, r, rc)
	if !halted {
		t.Fatal("expected halted")
	}
	if reachedThird {
		t.Fatal("third stage should not have been reached")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestPipelinePanicRecovery(t *testing.T) {
	reachedAfter := false
	p := New(
		StageFunc{StageName: "panic", Fn: func(_ context.Context, _ *RequestContext, _ http.ResponseWriter, _ *http.Request) StageResult {
			panic("test panic")
		}},
		StageFunc{StageName: "after", Fn: func(_ context.Context, _ *RequestContext, _ http.ResponseWriter, _ *http.Request) StageResult {
			// 管道因 panic 阶段返回 Halt 而终止，不会到达这里
			reachedAfter = true
			return Continue
		}},
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	rc := &RequestContext{}

	halted := p.Execute(w, r, rc)
	if !halted {
		t.Fatal("expected halted after panic")
	}
	if reachedAfter {
		t.Fatal("stage after panic should not have been reached")
	}
	// 验证 panic 阶段记录了错误
	found := false
	for _, m := range rc.Stages {
		if m.Name == "panic" && m.Error != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected panic stage to record error")
	}
}

func TestIPBanCheckStage(t *testing.T) {
	stage := IPBanCheckStage{
		IsBanned: func(ip string) bool { return ip == "1.2.3.4" },
	}

	// 测试被封禁的 IP
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/test", nil)
	rc := &RequestContext{ClientIP: "1.2.3.4"}
	result := stage.Execute(r.Context(), rc, w, r)
	if result != Halt {
		t.Fatal("expected Halt for banned IP")
	}
	if !rc.IPBanned {
		t.Fatal("expected IPBanned flag")
	}

	// 测试正常 IP
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/test", nil)
	rc2 := &RequestContext{ClientIP: "5.6.7.8"}
	result2 := stage.Execute(r2.Context(), rc2, w2, r2)
	if result2 != Continue {
		t.Fatal("expected Continue for normal IP")
	}
}

func TestWAFCheckStage(t *testing.T) {
	stage := WAFCheckStage{
		Check: func(r *http.Request) string {
			if r.URL.Path == "/evil" {
				return "路径穿越"
			}
			return ""
		},
	}

	// 恶意路径
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/evil", nil)
	rc := &RequestContext{}
	result := stage.Execute(r.Context(), rc, w, r)
	if result != Halt {
		t.Fatal("expected Halt for WAF hit")
	}
	if rc.WAFHit != "路径穿越" {
		t.Fatalf("expected WAFHit='路径穿越', got %q", rc.WAFHit)
	}

	// 正常路径
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/status", nil)
	rc2 := &RequestContext{}
	result2 := stage.Execute(r2.Context(), rc2, w2, r2)
	if result2 != Continue {
		t.Fatal("expected Continue for safe path")
	}
}

func TestAuthStage(t *testing.T) {
	stage := AuthStage{
		IsPublicRoute: func(p string) bool { return p == "/health" },
		Authenticate: func(r *http.Request) (*Identity, bool) {
			if r.Header.Get("Authorization") == "Bearer valid-key" {
				return &Identity{Name: "admin", Role: "admin"}, true
			}
			return nil, false
		},
	}

	// 公共路由
	rc := &RequestContext{}
	r := httptest.NewRequest("GET", "/health", nil)
	result := stage.Execute(r.Context(), rc, httptest.NewRecorder(), r)
	if result != Continue {
		t.Fatal("expected Continue for public route")
	}

	// 有效认证
	rc2 := &RequestContext{}
	r2 := httptest.NewRequest("GET", "/api/status", nil)
	r2.Header.Set("Authorization", "Bearer valid-key")
	result2 := stage.Execute(r2.Context(), rc2, httptest.NewRecorder(), r2)
	if result2 != Continue {
		t.Fatal("expected Continue for valid auth")
	}
	if !rc2.Authed || rc2.UserID != "admin" {
		t.Fatal("expected auth context to be filled")
	}

	// 无效认证
	rc3 := &RequestContext{}
	r3 := httptest.NewRequest("GET", "/api/status", nil)
	w3 := httptest.NewRecorder()
	result3 := stage.Execute(r3.Context(), rc3, w3, r3)
	if result3 != Halt {
		t.Fatal("expected Halt for invalid auth")
	}
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w3.Code)
	}
}

func TestPipelineStagesList(t *testing.T) {
	p := New(
		StageFunc{StageName: "a"},
		StageFunc{StageName: "b"},
		StageFunc{StageName: "c"},
	)
	names := p.Stages()
	if len(names) != 3 || names[0] != "a" || names[1] != "b" || names[2] != "c" {
		t.Fatalf("unexpected stages: %v", names)
	}
}

func TestInsertStageBefore(t *testing.T) {
	p := New(
		StageFunc{StageName: "a"},
		StageFunc{StageName: "c"},
	)
	err := p.InsertStageBefore("c", StageFunc{StageName: "b"})
	if err != nil {
		t.Fatal(err)
	}
	names := p.Stages()
	if len(names) != 3 || names[1] != "b" {
		t.Fatalf("expected [a,b,c], got %v", names)
	}

	// 插入不存在的阶段
	err = p.InsertStageBefore("z", StageFunc{StageName: "x"})
	if err == nil {
		t.Fatal("expected error for non-existent stage")
	}
}
