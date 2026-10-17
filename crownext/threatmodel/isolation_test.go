package threatmodel

import (
	"testing"
	"time"
)

func TestIsolatorQuarantineBlock(t *testing.T) {
	i := NewIsolator(time.Hour, 5)
	i.Quarantine("peer1", "bad cert", IsolationBlock, nil)
	if err := i.Check("peer1"); err == nil {
		t.Fatal("expected block")
	}
}

func TestIsolatorQuarantineRateLimit(t *testing.T) {
	i := NewIsolator(time.Hour, 2)
	i.Quarantine("peer1", "suspicious", IsolationRateLimit, nil)
	if err := i.Check("peer1"); err != nil {
		t.Fatalf("first call should pass: %v", err)
	}
	if err := i.Check("peer1"); err != nil {
		t.Fatalf("second call should pass: %v", err)
	}
	if err := i.Check("peer1"); err == nil {
		t.Fatal("third call should be rate limited")
	}
}

func TestIsolatorLift(t *testing.T) {
	i := NewIsolator(time.Hour, 5)
	i.Quarantine("peer1", "test", IsolationBlock, nil)
	i.Lift("peer1")
	if err := i.Check("peer1"); err != nil {
		t.Fatalf("expected no error after lift: %v", err)
	}
}

func TestIsolatorEscalation(t *testing.T) {
	i := NewIsolator(time.Hour, 1)
	i.RecordViolation("peer1", "first")
	rec, _ := i.GetRecord("peer1")
	if rec.Level != IsolationRateLimit {
		t.Fatalf("expected rate_limit, got %s", rec.Level)
	}
	for j := 0; j < 4; j++ {
		i.RecordViolation("peer1", "repeat")
	}
	rec, _ = i.GetRecord("peer1")
	if rec.Level != IsolationQuarantine {
		t.Fatalf("expected quarantine after escalation, got %s", rec.Level)
	}
}

func TestIsolatorPrune(t *testing.T) {
	i := NewIsolator(1*time.Millisecond, 5)
	i.Quarantine("peer1", "old", IsolationBlock, nil)
	time.Sleep(10 * time.Millisecond)
	removed := i.Prune()
	if removed != 1 {
		t.Fatalf("expected 1 pruned, got %d", removed)
	}
	if _, ok := i.GetRecord("peer1"); ok {
		t.Fatal("expected record gone after prune")
	}
}

func TestIsolatorList(t *testing.T) {
	i := NewIsolator(time.Hour, 5)
	i.Quarantine("p1", "a", IsolationBlock, nil)
	i.Quarantine("p2", "b", IsolationQuarantine, nil)
	list := i.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 records, got %d", len(list))
	}
}
