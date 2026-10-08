package skylink

import (
	"context"
	"testing"
	"time"
)

func TestCoordPutGet(t *testing.T) {
	c := NewCoordClient()
	ctx := context.Background()
	if err := c.Put(ctx, "k1", "v1"); err != nil {
		t.Fatal(err)
	}
	v, err := c.Get(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if v != "v1" {
		t.Fatalf("value mismatch: %s", v)
	}
}

func TestCoordLease(t *testing.T) {
	c := NewCoordClient()
	ctx := context.Background()
	c.PutWithLease(ctx, "k1", "v1", 50*time.Millisecond)
	v, err := c.Get(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if v != "v1" {
		t.Fatal("value mismatch")
	}
	time.Sleep(60 * time.Millisecond)
	_, err = c.Get(ctx, "k1")
	if err == nil {
		t.Fatal("expected expired lease error")
	}
}

func TestCoordWatch(t *testing.T) {
	c := NewCoordClient()
	ctx := context.Background()
	called := make(chan string, 1)
	c.Watch("pre", func(key, value string) {
		called <- key
	})
	c.Put(ctx, "prefix_key", "val")
	select {
	case k := <-called:
		if k != "prefix_key" {
			t.Fatalf("expected prefix_key, got %s", k)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("watch callback not called")
	}
}

func TestCoordList(t *testing.T) {
	c := NewCoordClient()
	ctx := context.Background()
	c.Put(ctx, "app/a", "1")
	c.Put(ctx, "app/b", "2")
	c.Put(ctx, "other/c", "3")
	res, err := c.List(ctx, "app/")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 items, got %d", len(res))
	}
}

func TestCoordCompact(t *testing.T) {
	c := NewCoordClient()
	ctx := context.Background()
	c.PutWithLease(ctx, "k1", "v1", 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	removed := c.Compact()
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
}

func TestCoordElection(t *testing.T) {
	c := NewCoordClient()
	ctx := context.Background()
	e1 := NewCoordElection(c, "/leader", "node1")
	won, err := e1.Campaign(ctx, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !won {
		t.Fatal("expected node1 to win")
	}
	leader, err := e1.Leader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if leader != "node1" {
		t.Fatalf("expected leader node1, got %s", leader)
	}

	e2 := NewCoordElection(c, "/leader", "node2")
	won2, _ := e2.Campaign(ctx, 100*time.Millisecond)
	if won2 {
		t.Fatal("expected node2 to lose")
	}

	if err := e1.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(ctx, "/leader")
	if err == nil {
		t.Fatal("expected key gone after resign")
	}
}
