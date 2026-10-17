package kingdom

import (
	"context"
	"testing"
)

type fakeHandler struct {
	started bool
}

func (f *fakeHandler) Init(ctx context.Context, cfg map[string]any) error { return nil }
func (f *fakeHandler) Start(ctx context.Context) error {
	f.started = true
	return nil
}
func (f *fakeHandler) Stop(ctx context.Context) error  { return nil }
func (f *fakeHandler) Status(ctx context.Context) (ModuleStatus, error) {
	return ModuleStatus{State: "running"}, nil
}
func (f *fakeHandler) UpdateConfig(ctx context.Context, cfg map[string]any) error { return nil }

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("registry nil")
	}
	root := r.Taxonomy().Root()
	if root.ID != "tsg" {
		t.Fatal("root id wrong")
	}
	// 验证预置分类树有内容
	flat := r.Taxonomy().Flatten()
	if len(flat) < 10 {
		t.Fatalf("taxonomy too small: %d", len(flat))
	}
}

func TestRegistryEnableDisable(t *testing.T) {
	r := NewRegistry()
	// ordo_extranet 是可选模块
	if err := r.Disable("ordo_extranet"); err != nil {
		t.Fatalf("disable extranet: %v", err)
	}
	tx, _ := r.Get("ordo_extranet")
	if tx.Enabled {
		t.Fatal("extranet should be disabled")
	}
	if err := r.Enable("ordo_extranet"); err != nil {
		t.Fatalf("enable extranet: %v", err)
	}
	if !tx.Enabled {
		t.Fatal("extranet should be enabled")
	}
	// required 模块不可禁用
	if err := r.Disable("ordo_waf"); err == nil {
		t.Fatal("waf is required, disable should fail")
	}
}

func TestRegistryStartAll(t *testing.T) {
	r := NewRegistry()
	fh := &fakeHandler{}
	_ = r.RegisterHandler("ordo_waf", fh)
	ctx := context.Background()
	if err := r.StartAll(ctx); err != nil {
		t.Fatalf("start all: %v", err)
	}
	if !fh.started {
		t.Fatal("handler not started")
	}
}

func TestRegistryMigrate(t *testing.T) {
	r := NewRegistry()
	modules := map[string]bool{"ordo_extranet": false}
	if err := r.MigrateFromV4(modules, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	tx, _ := r.Get("ordo_extranet")
	if tx.Enabled {
		t.Fatal("extranet should be disabled after migrate")
	}
	legacy := r.ToLegacyModules()
	if len(legacy) == 0 {
		t.Fatal("legacy map empty")
	}
}
