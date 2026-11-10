package kernel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	rc := &RequestCtx{RemoteIP: "1.2.3.4", APCHandle: NewAPCQueue()}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	result := sec.Check(context.Background(), rc, rec, req)
	if result != Halt {
		t.Error("封禁 IP 应被拦截")
	}

	// 正常 IP 通过
	rec2 := httptest.NewRecorder()
	rc2 := &RequestCtx{RemoteIP: "5.6.7.8", APCHandle: NewAPCQueue()}
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
	k.Scheduler = NewScheduler()

	if err := k.Boot(); err != nil {
		t.Fatalf("Boot failed: %v", err)
	}
	if k.Uptime() <= 0 {
		t.Error("Uptime should be positive after boot")
	}
	k.Shutdown()
	// Shutdown 幂等
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
	if BugcheckCount() == 0 {
		t.Error("Bugcheck 应被计数")
	}
}

// ===================== 深度内核化测试 =====================

// TestIRPStackPushPop 测试 I/O Stack Location 栈帧链
func TestIRPStackPushPop(t *testing.T) {
	stack := NewIRPStack(16)

	// Push 3 个栈位置
	for i := 0; i < 3; i++ {
		_, err := stack.Push(IOStackLocation{StageName: "stage-" + string(rune('A'+i))})
		if err != nil {
			t.Fatalf("Push %d failed: %v", i, err)
		}
	}
	if stack.Depth() != 3 {
		t.Errorf("栈深度应为 3，实际 %d", stack.Depth())
	}

	// 栈顶应是最后一个 Push 的
	if top := stack.Current(); top == nil || top.StageName != "stage-C" {
		t.Error("栈顶应为 stage-C")
	}

	// Pop 3 个
	for i := 0; i < 3; i++ {
		loc, err := stack.Pop()
		if err != nil {
			t.Fatalf("Pop %d failed: %v", i, err)
		}
		if loc.CompletedAt.IsZero() {
			t.Error("Pop 后 CompletedAt 应已设置")
		}
	}
	if stack.Depth() != 0 {
		t.Errorf("Pop 后栈深度应为 0，实际 %d", stack.Depth())
	}
}

// TestIRPStackOverflow 测试栈溢出 Bugcheck
func TestIRPStackOverflow(t *testing.T) {
	stack := NewIRPStack(2) // 很浅的栈

	stack.Push(IOStackLocation{StageName: "s1"})
	stack.Push(IOStackLocation{StageName: "s2"})
	_, err := stack.Push(IOStackLocation{StageName: "s3"})
	if err == nil {
		t.Error("第三次 Push 应返回栈溢出错误")
	}
}

// TestProtectionRings 测试保护环权限
func TestProtectionRings(t *testing.T) {
	// Ring0 能 bypass Ring3
	if !Ring0.CanBypass(Ring3) {
		t.Error("Ring0 应能 bypass Ring3")
	}
	// Ring3 不能 bypass Ring0
	if Ring3.CanBypass(Ring0) {
		t.Error("Ring3 不应能 bypass Ring0")
	}
	// Ring 字符串表示
	if Ring0.String() != "Ring0(kernel)" {
		t.Errorf("Ring0 字符串错误: %s", Ring0.String())
	}
}

// TestSyscallTable 测试系统调用表
func TestSyscallTable(t *testing.T) {
	tbl := NewSyscallTable()
	tbl.Register(SysWAFCheck, "waf_check", Ring0, func(rc *RequestCtx, args interface{}) (StageResult, error) {
		return Continue, nil
	})
	tbl.Register(SysConfigSnapshot, "config_snapshot", Ring0, func(rc *RequestCtx, args interface{}) (StageResult, error) {
		return Continue, nil
	})

	// Ring3 不能调用 Ring0 syscall
	rc := &RequestCtx{APCHandle: NewAPCQueue()}
	result, err := tbl.Invoke(Ring3, SysWAFCheck, rc, nil)
	if err == nil {
		t.Error("Ring3 不应能调用 Ring0 syscall")
	}
	if result != Halt {
		t.Error("Ring3 调用 Ring0 syscall 应返回 Halt")
	}

	// Ring0 可以调用自己的 syscall
	result, err = tbl.Invoke(Ring0, SysWAFCheck, rc, nil)
	if err != nil {
		t.Errorf("Ring0 调用 syscall 失败: %v", err)
	}
	if result != Continue {
		t.Error("Ring0 syscall 应返回 Continue")
	}

	// 未知 syscall 号
	_, err = tbl.Invoke(Ring0, SyscallNumber(999), rc, nil)
	if err == nil {
		t.Error("未知 syscall 号应返回错误")
	}
}

// TestObjectManager 测试内核对象管理器 + 引用计数
func TestObjectManager(t *testing.T) {
	mgr := NewObjectManager()

	// 创建对象
	h := mgr.Create(ObjConfigSnapshot, "snap-1", map[string]string{"mode": "strict"})
	if h == InvalidHandle {
		t.Fatal("Create 返回了无效句柄")
	}

	// 获取对象
	obj, ok := mgr.Get(h)
	if !ok {
		t.Fatal("Get 失败")
	}
	if obj.RefCount() != 1 {
		t.Errorf("初始引用计数应为 1，实际 %d", obj.RefCount())
	}

	// 引用 +1
	mgr.Reference(h)
	if obj.RefCount() != 2 {
		t.Errorf("引用后应为 2，实际 %d", obj.RefCount())
	}

	// 解除引用
	mgr.Dereference(h)
	if obj.RefCount() != 1 {
		t.Errorf("解除后应为 1，实际 %d", obj.RefCount())
	}

	// 最后引用归零 → 回收
	mgr.Dereference(h)
	if mgr.Count() != 0 {
		t.Errorf("引用归零后应回收，Count=%d", mgr.Count())
	}
}

// TestAPCQueue 测试 APC 队列
func TestAPCQueue(t *testing.T) {
	q := NewAPCQueue()

	// 投递 3 个不同优先级的 APC
	q.Enqueue(APC{ID: 1, Reason: "low", Priority: APCNormal})
	q.Enqueue(APC{ID: 2, Reason: "urgent", Priority: APCUrgent})
	q.Enqueue(APC{ID: 3, Reason: "kernel", Priority: APCKernel})

	if q.Pending() != 3 {
		t.Errorf("Pending 应为 3，实际 %d", q.Pending())
	}

	// 高优先级先出队
	apc, ok := q.Dequeue()
	if !ok || apc.Priority != APCUrgent {
		t.Errorf("最高优先级应先出队，实际 %v", apc)
	}

	apc2, ok := q.Dequeue()
	if !ok || apc2.Priority != APCKernel {
		t.Errorf("次高优先级应出队，实际 %v", apc2)
	}
}

// TestDirtyTracker 测试 Gecko dirty bits + incremental reflow
func TestDirtyTracker(t *testing.T) {
	dt := NewDirtyTracker()
	stages := []string{"waf", "auth", "rbac", "rate-limit"}

	// 全部标记 dirty
	dt.MarkAllDirty(stages)
	dirty := dt.Reflow(stages)
	if len(dirty) != 4 {
		t.Errorf("首次 reflow 应有 4 个 dirty，实际 %d", len(dirty))
	}

	// 只标记 waf 为 dirty
	dt.MarkDirty("waf")
	dirty = dt.Reflow(stages)
	if len(dirty) != 1 || dirty[0] != "waf" {
		t.Errorf("增量 reflow 应只有 waf，实际 %v", dirty)
	}
	if dt.ReflowCount() != 2 {
		t.Errorf("Reflow 次数应为 2，实际 %d", dt.ReflowCount())
	}
}

// TestFrameManager 测试 Gecko frame construction
func TestFrameManager(t *testing.T) {
	fm := NewFrameManager()

	// 构建 3 个 Frame
	fm.BuildFrame("waf", "5.1.0", Ring0)
	fm.BuildFrame("auth", "5.1.0", Ring0)
	fm.BuildFrame("chat", "5.1.0", Ring3)

	if len(fm.Frames()) != 3 {
		t.Errorf("应有 3 个 Frame，实际 %d", len(fm.Frames()))
	}

	// 标记 waf dirty 并重建
	fm.MarkFrameDirty("waf")
	rebuilt := fm.RebuildDirty()
	if len(rebuilt) != 1 || rebuilt[0] != "waf" {
		t.Errorf("应重建 waf，实际 %v", rebuilt)
	}

	// 再次重建（无 dirty）
	rebuilt = fm.RebuildDirty()
	if len(rebuilt) != 0 {
		t.Errorf("无 dirty 时不应重建，实际 %d", len(rebuilt))
	}
}

// TestBugcheckHandler 测试 Bugcheck 回调
func TestBugcheckHandler(t *testing.T) {
	called := false
	s := NewScheduler(StageFunc{
		StageName: "panic-stage",
		Fn: func(ctx context.Context, rc *RequestCtx, w http.ResponseWriter, r *http.Request) StageResult {
			panic("bugcheck test")
		},
	})
	s.SetBugcheckHandler(func(data BugcheckData) {
		called = true
		if data.Code != BugcheckPanic {
			t.Errorf("Bugcheck code 应为 Panic，实际 %s", data.Code)
		}
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	s.Execute(context.Background(), rec, req)
	if !called {
		t.Error("Bugcheck handler 应被调用")
	}
}

// TestContentSink 测试 Gecko ContentSink 增量推送
func TestContentSink(t *testing.T) {
	events := []string{}
	sink := &testSink{events: &events}

	s := NewScheduler(
		&AuthStage{
			IsPublicRoute: func(p string) bool { return true },
		},
	)
	s.SetContentSink(sink)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	s.Execute(context.Background(), rec, req)

	// 应有 OnStageResult + OnComplete
	if len(events) < 2 {
		t.Errorf("应至少有 2 个事件（stage result + complete），实际 %d: %v", len(events), events)
	}
}

type testSink struct{ events *[]string }

func (s *testSink) OnStageResult(name string, r StageResult, rc *RequestCtx) {
	*s.events = append(*s.events, "stage:"+name)
}
func (s *testSink) OnWAFHit(rc *RequestCtx, rule string) {
	*s.events = append(*s.events, "waf:"+rule)
}
func (s *testSink) OnAuthResult(rc *RequestCtx, authed bool, userID string) {
	*s.events = append(*s.events, "auth:"+userID)
}
func (s *testSink) OnComplete(rc *RequestCtx, halted bool) {
	*s.events = append(*s.events, "complete")
}

// TestAPCInterrupt 测试 APC 中断请求
func TestAPCInterrupt(t *testing.T) {
	s := NewScheduler(
		&AuthStage{
			IsPublicRoute: func(p string) bool { return true },
		},
	)

	// 手动构造带 APC 的请求上下文
	rc := &RequestCtx{
		TraceID:   "test-apc",
		StartTime: time.Now(),
		RemoteIP:  "1.2.3.4",
		APCHandle: NewAPCQueue(),
	}
	// 投递一个内核级 APC（模拟 IP 封禁中断）
	rc.APCHandle.Enqueue(APC{
		ID:       1,
		Reason:   "IP封禁",
		Priority: APCKernel,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	halted := s.ExecuteWithCtx(context.Background(), rc, rec, req)
	if !halted {
		t.Error("APC 中断应导致 Halt")
	}
}
