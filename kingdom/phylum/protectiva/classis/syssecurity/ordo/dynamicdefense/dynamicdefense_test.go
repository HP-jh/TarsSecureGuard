package dynamicdefense

import (
	"context"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	cfg := &Config{Enabled: true}
	e := NewEngine(cfg)
	if e == nil {
		t.Fatal("engine nil")
	}
	if !e.Config().Enabled {
		t.Fatal("should be enabled")
	}
}

func TestEngineHotReload(t *testing.T) {
	cfg := &Config{Enabled: true}
	e := NewEngine(cfg)
	v1 := e.Version()
	newCfg := &Config{Enabled: false}
	if err := e.HotReload(newCfg); err != nil {
		t.Fatalf("hot reload: %v", err)
	}
	if e.Version() <= v1 {
		t.Fatal("version should increment")
	}
	if e.Config().Enabled {
		t.Fatal("should be disabled after reload")
	}
}

func TestEngineRecordShadowHit(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		ShadowRules: []ShadowRule{
			{ID: "s1", Name: "test", Enabled: true, AutoPromote: true},
		},
	}
	e := NewEngine(cfg)
	e.RecordShadowHit("s1", false)
	e.RecordShadowHit("s1", true)
	status := e.Status()
	if status["shadow_rules"] != 1 {
		t.Fatalf("shadow_rules = %v, want 1", status["shadow_rules"])
	}
}

func TestEngineStartStop(t *testing.T) {
	cfg := &Config{Enabled: true}
	e := NewEngine(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}
