package agentmesh

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestPatternSupervisor(t *testing.T) {
	reg := NewRegistry()
	d := NewDispatcher(reg)

	for i := 0; i < 3; i++ {
		card := &AgentCard{AgentID: "worker" + string(rune('0'+i)), Version: "1.0", RBACRole: "user", Accepts: []TaskType{TaskChat}}
		reg.RegisterLocal(card)
		d.RegisterHandler(card.AgentID, func(ctx context.Context, task *TaskEnvelope) ([]byte, error) {
			return []byte("result-" + task.ToAgent), nil
		})
	}

	ps := &PatternSupervisor{}
	task := &TaskEnvelope{
		TaskID:    "super1",
		TaskType:  TaskChat,
		FromAgent: "boss",
		Payload:   []byte("work"),
		Metadata:  map[string]string{"worker_count": "3"},
	}
	res, err := ps.Execute(context.Background(), task, reg, d)
	if err != nil {
		t.Fatalf("supervisor execute failed: %v", err)
	}
	if res.State != TaskCompleted {
		t.Fatalf("expected completed state, got %v", res.State)
	}
}

func TestPatternP2P(t *testing.T) {
	reg := NewRegistry()
	d := NewDispatcher(reg)
	card := &AgentCard{AgentID: "agentB", Version: "1.0", RBACRole: "user", Accepts: []TaskType{TaskChat}}
	reg.RegisterLocal(card)
	d.RegisterHandler("agentB", func(ctx context.Context, task *TaskEnvelope) ([]byte, error) {
		return []byte("pong"), nil
	})

	p2p := &PatternP2P{}
	task := &TaskEnvelope{
		TaskID:    "p2p1",
		TaskType:  TaskChat,
		FromAgent: "agentA",
		ToAgent:   "agentB",
		Payload:   []byte("ping"),
	}
	res, err := p2p.Execute(context.Background(), task, reg, d)
	if err != nil {
		t.Fatalf("p2p execute failed: %v", err)
	}

	// P2P returns immediately; poll for completion
	for i := 0; i < 50; i++ {
		st, ok := d.GetTask(res.TaskID)
		if ok && st.State == TaskCompleted {
			if string(st.Result) != "pong" {
				t.Fatalf("expected pong, got %s", string(st.Result))
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("p2p task did not complete in time")
}

func TestPatternBroadcast(t *testing.T) {
	reg := NewRegistry()
	d := NewDispatcher(reg)
	var mu sync.Mutex
	count := 0
	for i := 0; i < 3; i++ {
		card := &AgentCard{AgentID: "peer" + string(rune('0'+i)), Version: "1.0", RBACRole: "user", Accepts: []TaskType{TaskChat}}
		reg.RegisterLocal(card)
		d.RegisterHandler(card.AgentID, func(ctx context.Context, task *TaskEnvelope) ([]byte, error) {
			mu.Lock()
			count++
			mu.Unlock()
			return []byte("ack"), nil
		})
	}

	bc := &PatternBroadcast{}
	task := &TaskEnvelope{
		TaskID:    "bc1",
		TaskType:  TaskChat,
		FromAgent: "sender",
		Payload:   []byte("hello all"),
	}
	_, err := bc.Execute(context.Background(), task, reg, d)
	if err != nil {
		t.Fatalf("broadcast failed: %v", err)
	}

	// Allow async handlers to run
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	if count != 3 {
		t.Fatalf("expected 3 handler calls, got %d", count)
	}
	mu.Unlock()
}

func TestDefaultPatterns(t *testing.T) {
	pp := DefaultPatterns()
	if len(pp) != 3 {
		t.Fatalf("expected 3 patterns, got %d", len(pp))
	}
	names := map[string]bool{}
	for _, p := range pp {
		names[p.Name()] = true
	}
	if !names["supervisor"] || !names["p2p"] || !names["broadcast"] {
		t.Fatalf("missing expected pattern names: %v", names)
	}
}
