package assistant

import (
	"context"
	"testing"
	"time"
)

func TestModelRouterRegister(t *testing.T) {
	r := NewModelRouter(time.Minute)
	p := &ProviderConfig{Name: "p1", BaseURL: "http://localhost:8080", Model: "gpt-4", Weight: 1.0, Healthy: true, LastCheck: time.Now()}
	r.Register(p)
	if len(r.List()) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(r.List()))
	}
}

func TestModelRouterSelectManual(t *testing.T) {
	r := NewModelRouter(time.Minute)
	r.Register(&ProviderConfig{Name: "p1", BaseURL: "http://a", Model: "m1", Healthy: true, LastCheck: time.Now()})
	p, err := r.SelectManual("p1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "p1" {
		t.Fatalf("expected p1, got %s", p.Name)
	}
	_, err = r.SelectManual("missing")
	if err == nil {
		t.Fatal("expected error for missing provider")
	}
}

func TestModelRouterSelectAuto(t *testing.T) {
	r := NewModelRouter(time.Minute)
	// No providers
	_, err := r.SelectAuto(nil)
	if err == nil {
		t.Fatal("expected error with no providers")
	}
	// One provider
	r.Register(&ProviderConfig{Name: "p1", BaseURL: "http://a", Model: "m1", Weight: 1.0, Healthy: true, LastLatency: 100 * time.Millisecond, LastCheck: time.Now()})
	p, err := r.SelectAuto(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "p1" {
		t.Fatalf("expected p1, got %s", p.Name)
	}
}

func TestModelRouterScore(t *testing.T) {
	r := NewModelRouter(time.Minute)
	p := &ProviderConfig{Name: "p1", Weight: 1.0, Healthy: true, LastLatency: 100 * time.Millisecond, LastCheck: time.Now(), Capabilities: []string{"chat", "vision"}}
	s := r.Score(p, []string{"chat"})
	if s <= 0 {
		t.Fatalf("expected positive score, got %f", s)
	}
	// Unhealthy => negative
	p.Healthy = false
	s = r.Score(p, nil)
	if s >= 0 {
		t.Fatalf("expected negative score for unhealthy, got %f", s)
	}
}

func TestModelRouterHealthCheck(t *testing.T) {
	r := NewModelRouter(time.Minute)
	// Use a non-routable address that will fail quickly
	r.Register(&ProviderConfig{Name: "bad", BaseURL: "http://127.0.0.1:1", APIKey: "x", Healthy: true, LastCheck: time.Now()})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r.HealthCheck(ctx)
	p := r.List()[0]
	if p.Healthy {
		t.Fatal("expected unhealthy for bad address")
	}
}

func TestSelectionAudit(t *testing.T) {
	a := NewSelectionAudit(3)
	a.Record(SelectionRecord{Provider: "p1"})
	a.Record(SelectionRecord{Provider: "p2"})
	a.Record(SelectionRecord{Provider: "p3"})
	a.Record(SelectionRecord{Provider: "p4"})
	logs := a.List(10)
	if len(logs) != 3 {
		t.Fatalf("expected cap 3, got %d", len(logs))
	}
	if logs[0].Provider != "p4" {
		t.Fatal("expected newest first")
	}
}
