package agentmesh

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CollaborationPattern defines how tasks are distributed among agents.
type CollaborationPattern interface {
	Name() string
	Execute(ctx context.Context, task *TaskEnvelope, registry *Registry, dispatcher *Dispatcher) (*TaskEnvelope, error)
}

// PatternSupervisor implements the supervisor/worker pattern.
type PatternSupervisor struct{}

func (p *PatternSupervisor) Name() string { return "supervisor" }

// Execute splits a task into subtasks, dispatches to workers, and aggregates results.
func (p *PatternSupervisor) Execute(ctx context.Context, task *TaskEnvelope, registry *Registry, dispatcher *Dispatcher) (*TaskEnvelope, error) {
	if task.Metadata == nil || task.Metadata["worker_count"] == "" {
		return nil, fmt.Errorf("agentmesh: supervisor pattern requires worker_count in metadata")
	}

	// Find capable workers.
	workers := registry.Lookup(LookupCriteria{
		TaskType: task.TaskType,
	})
	if len(workers) == 0 {
		return nil, fmt.Errorf("agentmesh: no workers available")
	}

	// Create subtasks for each worker.
	var wg sync.WaitGroup
	results := make([][]byte, len(workers))
	errs := make([]error, len(workers))

	for i, worker := range workers {
		wg.Add(1)
		go func(idx int, w *AgentCard) {
			defer wg.Done()
			sub := &TaskEnvelope{
				TaskID:    fmt.Sprintf("%s-sub-%d", task.TaskID, idx),
				ParentID:  task.TaskID,
				TaskType:  task.TaskType,
				Payload:   task.Payload,
				FromAgent: task.FromAgent,
				ToAgent:   w.AgentID,
				Pattern:   "supervisor",
				Deadline:  task.Deadline,
			}
			if err := dispatcher.Dispatch(ctx, sub); err != nil {
				errs[idx] = err
				return
			}
			// Poll for completion (simplified; production uses event-driven).
			for {
				select {
				case <-ctx.Done():
					errs[idx] = ctx.Err()
					return
				case <-time.After(100 * time.Millisecond):
					st, ok := dispatcher.GetTask(sub.TaskID)
					if !ok {
						continue
					}
					if st.State == TaskCompleted {
						results[idx] = st.Result
						return
					}
					if st.State == TaskFailed || st.State == TaskCancelled {
						errs[idx] = fmt.Errorf("subtask %s failed: %s", sub.TaskID, st.Error)
						return
					}
				}
			}
		}(i, worker)
	}

	wg.Wait()

	// Aggregate results (simple concatenation; can be customised).
	var agg []byte
	for i, res := range results {
		if errs[i] != nil {
			continue
		}
		agg = append(agg, res...)
		agg = append(agg, '\n')
	}

	task.Result = agg
	task.State = TaskCompleted
	task.UpdatedAt = time.Now()
	return task, nil
}

// PatternP2P implements peer-to-peer direct delegation.
type PatternP2P struct{}

func (p *PatternP2P) Name() string { return "p2p" }

// Execute delegates the task directly to a single peer agent.
func (p *PatternP2P) Execute(ctx context.Context, task *TaskEnvelope, registry *Registry, dispatcher *Dispatcher) (*TaskEnvelope, error) {
	if task.ToAgent == "" {
		candidates := registry.Lookup(LookupCriteria{
			TaskType: task.TaskType,
		})
		if len(candidates) == 0 {
			return nil, fmt.Errorf("agentmesh: p2p pattern: no peer available")
		}
		task.ToAgent = candidates[0].AgentID
	}
	task.Pattern = "p2p"
	if err := dispatcher.Dispatch(ctx, task); err != nil {
		return nil, err
	}
	return task, nil
}

// PatternBroadcast implements broadcast to all capable agents.
type PatternBroadcast struct{}

func (p *PatternBroadcast) Name() string { return "broadcast" }

// Execute sends the task to all agents capable of handling it.
func (p *PatternBroadcast) Execute(ctx context.Context, task *TaskEnvelope, registry *Registry, dispatcher *Dispatcher) (*TaskEnvelope, error) {
	agents := registry.Lookup(LookupCriteria{
		TaskType: task.TaskType,
	})
	if len(agents) == 0 {
		return nil, fmt.Errorf("agentmesh: broadcast pattern: no agents available")
	}

	var wg sync.WaitGroup
	for _, agent := range agents {
		wg.Add(1)
		go func(a *AgentCard) {
			defer wg.Done()
			sub := &TaskEnvelope{
				TaskID:    fmt.Sprintf("%s-bcast-%s", task.TaskID, a.AgentID),
				ParentID:  task.TaskID,
				TaskType:  task.TaskType,
				Payload:   task.Payload,
				FromAgent: task.FromAgent,
				ToAgent:   a.AgentID,
				Pattern:   "broadcast",
				Deadline:  task.Deadline,
			}
			_ = dispatcher.Dispatch(ctx, sub) // best-effort broadcast
		}(agent)
	}

	// Broadcast returns immediately; callers poll subtasks for results.
	wg.Wait()
	task.State = TaskRunning
	task.UpdatedAt = time.Now()
	return task, nil
}

// DefaultPatterns returns the built-in collaboration patterns.
func DefaultPatterns() []CollaborationPattern {
	return []CollaborationPattern{
		&PatternSupervisor{},
		&PatternP2P{},
		&PatternBroadcast{},
	}
}
