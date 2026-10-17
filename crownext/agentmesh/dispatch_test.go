package agentmesh

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDispatcherLocalExecution(t *testing.T) {
	reg := NewRegistry()
	d := NewDispatcher(reg)

	card := &AgentCard{AgentID: "agent1", Version: "1.0", RBACRole: "user", Accepts: []TaskType{TaskChat}}
	reg.RegisterLocal(card)

	called := false
	d.RegisterHandler("agent1", func(ctx context.Context, task *TaskEnvelope) ([]byte, error) {
		called = true
		return []byte("ok"), nil
	})

	task := &TaskEnvelope{
		TaskID:    "t1",
		TaskType:  TaskChat,
		FromAgent: "agent2",
		Payload:   []byte("hello"),
	}
	if err := d.Dispatch(context.Background(), task); err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if !called {
		t.Fatal("handler not called")
	}

	t2, ok := d.GetTask("t1")
	if !ok || t2.State != TaskCompleted {
		t.Fatalf("expected completed state, got %v", t2.State)
	}
}

func TestDispatcherNoAgent(t *testing.T) {
	reg := NewRegistry()
	d := NewDispatcher(reg)

	task := &TaskEnvelope{
		TaskID:    "t1",
		TaskType:  TaskChat,
		FromAgent: "agent2",
	}
	if err := d.Dispatch(context.Background(), task); err == nil {
		t.Fatal("expected error for missing agent")
	}
}

func TestDispatcherCancel(t *testing.T) {
	reg := NewRegistry()
	d := NewDispatcher(reg)
	card := &AgentCard{AgentID: "agent1", Version: "1.0", RBACRole: "user", Accepts: []TaskType{TaskChat}}
	reg.RegisterLocal(card)

	d.RegisterHandler("agent1", func(ctx context.Context, task *TaskEnvelope) ([]byte, error) {
		time.Sleep(50 * time.Millisecond)
		return []byte("ok"), nil
	})

	task := &TaskEnvelope{
		TaskID:    "t1",
		TaskType:  TaskChat,
		FromAgent: "agent2",
	}
	go d.Dispatch(context.Background(), task)
	time.Sleep(5 * time.Millisecond)
	if !d.Cancel("t1") {
		t.Fatal("expected cancel to succeed")
	}
}

func TestDispatcherHandlerError(t *testing.T) {
	reg := NewRegistry()
	d := NewDispatcher(reg)
	card := &AgentCard{AgentID: "agent1", Version: "1.0", RBACRole: "user", Accepts: []TaskType{TaskChat}}
	reg.RegisterLocal(card)

	d.RegisterHandler("agent1", func(ctx context.Context, task *TaskEnvelope) ([]byte, error) {
		return nil, errors.New("boom")
	})

	task := &TaskEnvelope{
		TaskID:    "t1",
		TaskType:  TaskChat,
		FromAgent: "agent2",
	}
	if err := d.Dispatch(context.Background(), task); err == nil {
		t.Fatal("expected error from handler")
	}
	t2, _ := d.GetTask("t1")
	if t2.State != TaskFailed {
		t.Fatalf("expected failed state, got %v", t2.State)
	}
}
