package crown

import (
	"fmt"
	"sync"
	"testing"
)

// fakeModule 记录 Start/Stop 调用序列，用于验证拓扑序与回滚。
type fakeModule struct {
	id      string
	deps    []string
	startFn func() error
	mu      sync.Mutex
	stopped int
}

func (m *fakeModule) ModuleID() string { return m.id }
func (m *fakeModule) Deps() []string   { return m.deps }
func (m *fakeModule) Start() error {
	if m.startFn != nil {
		return m.startFn()
	}
	return nil
}
func (m *fakeModule) Stop() {
	m.mu.Lock()
	m.stopped++
	m.mu.Unlock()
}

func TestBusRegisterRejectsInvalid(t *testing.T) {
	b := NewBus()
	if err := b.Register(nil); err == nil {
		t.Error("nil module: want error")
	}
	if err := b.Register(&fakeModule{id: ""}); err == nil {
		t.Error("empty id: want error")
	}
	if err := b.Register(&fakeModule{id: "a"}); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := b.Register(&fakeModule{id: "a"}); err == nil {
		t.Error("duplicate id: want error")
	}
}

func TestBusValidateDeps(t *testing.T) {
	cases := []struct {
		name    string
		modules []*fakeModule
		wantErr bool
	}{
		{"missing dep", []*fakeModule{{id: "a", deps: []string{"ghost"}}}, true},
		{"self dep", []*fakeModule{{id: "a", deps: []string{"a"}}}, true},
		{"cycle", []*fakeModule{{id: "a", deps: []string{"b"}}, {id: "b", deps: []string{"a"}}}, true},
		{"closed", []*fakeModule{{id: "a"}, {id: "b", deps: []string{"a"}}}, false},
	}
	for _, c := range cases {
		b := NewBus()
		for _, m := range c.modules {
			if err := b.Register(m); err != nil {
				t.Fatalf("%s: register: %v", c.name, err)
			}
		}
		err := b.Validate()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v, got %v", c.name, c.wantErr, err)
		}
	}
}

func TestBusStartAllTopologicalOrder(t *testing.T) {
	var mu sync.Mutex
	var startOrder []string
	mk := func(id string, deps ...string) *fakeModule {
		return &fakeModule{id: id, deps: deps, startFn: func() error {
			mu.Lock()
			startOrder = append(startOrder, id)
			mu.Unlock()
			return nil
		}}
	}
	b := NewBus()
	// 注册顺序故意打乱：依赖在后、被依赖在前混排
	for _, m := range []*fakeModule{mk("audit", "store"), mk("store"), mk("waf", "store"), mk("gateway", "waf", "audit")} {
		if err := b.Register(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAll(); err != nil {
		t.Fatal(err)
	}
	pos := map[string]int{}
	for i, id := range startOrder {
		pos[id] = i
	}
	if !(pos["store"] < pos["audit"] && pos["store"] < pos["waf"] && pos["waf"] < pos["gateway"] && pos["audit"] < pos["gateway"]) {
		t.Fatalf("topo order violated: %v", startOrder)
	}
	if got := b.Started(); len(got) != 4 {
		t.Fatalf("want 4 started, got %v", got)
	}
	// 确定性：同级（无依赖可并行档）按字典序——store 必先于其它
	if startOrder[0] != "store" {
		t.Fatalf("want store first, got %v", startOrder)
	}
}

func TestBusStartAllFailureRollsBack(t *testing.T) {
	a := &fakeModule{id: "a"}
	bm := &fakeModule{id: "b", deps: []string{"a"}}
	c := &fakeModule{id: "c", deps: []string{"b"}, startFn: func() error { return fmt.Errorf("boom") }}
	d := &fakeModule{id: "d", deps: []string{"c"}}

	bus := NewBus()
	for _, m := range []*fakeModule{a, bm, c, d} {
		if err := bus.Register(m); err != nil {
			t.Fatal(err)
		}
	}
	err := bus.StartAll()
	if err == nil {
		t.Fatal("want start failure")
	}
	// c 失败：a、b 已启动须被反向停止；d 从未启动
	a.mu.Lock()
	aStopped := a.stopped
	a.mu.Unlock()
	bm.mu.Lock()
	bStopped := bm.stopped
	bm.mu.Unlock()
	c.mu.Lock()
	cStopped := c.stopped
	c.mu.Unlock()
	d.mu.Lock()
	dStopped := d.stopped
	d.mu.Unlock()
	if aStopped != 1 || bStopped != 1 {
		t.Fatalf("started modules must be stopped once: a=%d b=%d", aStopped, bStopped)
	}
	if cStopped != 0 || dStopped != 0 {
		t.Fatalf("failed/unstarted modules must not be stopped: c=%d d=%d", cStopped, dStopped)
	}
	if got := bus.Started(); len(got) != 0 {
		t.Fatalf("after rollback Started must be empty, got %v", got)
	}
}

func TestBusStopAllReverseOrder(t *testing.T) {
	var mu sync.Mutex
	var stopOrder []string
	mk := func(id string, deps ...string) *stopRecorder {
		return &stopRecorder{
			fakeModule: &fakeModule{id: id, deps: deps},
			id:         id,
			record: func(s string) {
				mu.Lock()
				stopOrder = append(stopOrder, s)
				mu.Unlock()
			},
		}
	}
	b := NewBus()
	for _, m := range []*stopRecorder{mk("a"), mk("b", "a"), mk("c", "b")} {
		if err := b.Register(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.StartAll(); err != nil {
		t.Fatal(err)
	}
	b.StopAll()
	if len(stopOrder) != 3 || stopOrder[0] != "c" || stopOrder[1] != "b" || stopOrder[2] != "a" {
		t.Fatalf("want reverse stop order [c b a], got %v", stopOrder)
	}
}

// stopRecorder 在 fakeModule 之上记录 Stop 顺序。
type stopRecorder struct {
	*fakeModule
	id     string
	record func(string)
}

func (s *stopRecorder) Stop() {
	s.record(s.id)
	s.fakeModule.Stop()
}
