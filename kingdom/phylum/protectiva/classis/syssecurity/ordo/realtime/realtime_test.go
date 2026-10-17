package realtime

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewMonitor(t *testing.T) {
	m := NewMonitor()
	if m == nil {
		t.Fatal("monitor nil")
	}
	if !m.enabled.Load() {
		t.Fatal("should be enabled")
	}
}

func TestMonitorRecord(t *testing.T) {
	m := NewMonitor()
	m.Record(Event{Type: "file", Action: "read", Target: "/tmp/test"})
	m.Record(Event{Type: "network", Action: "connect", Target: "1.2.3.4"})
	events := m.Events(10)
	if len(events) != 2 {
		t.Fatalf("events len = %d, want 2", len(events))
	}
}

func TestMonitorOnEvent(t *testing.T) {
	m := NewMonitor()
	var called atomic.Bool
	m.OnEvent(func(e Event) {
		called.Store(true)
	})
	m.Record(Event{Type: "process", Action: "exec", Target: "test"})
	time.Sleep(50 * time.Millisecond)
	if !called.Load() {
		t.Fatal("handler not called")
	}
}

func TestMonitorStartStop(t *testing.T) {
	m := NewMonitor()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestMonitorStats(t *testing.T) {
	m := NewMonitor()
	m.Record(Event{Type: "file", Action: "read", Target: "/a"})
	m.Record(Event{Type: "file", Action: "write", Target: "/b"})
	stats := m.Stats()
	if stats["total"] != 2 {
		t.Fatalf("total = %v, want 2", stats["total"])
	}
}
