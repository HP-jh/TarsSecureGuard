package agentmesh

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TaskState tracks the lifecycle of a dispatched task.
type TaskState string

const (
	TaskPending   TaskState = "pending"
	TaskRunning   TaskState = "running"
	TaskCompleted TaskState = "completed"
	TaskFailed    TaskState = "failed"
	TaskCancelled TaskState = "cancelled"
)

// TaskEnvelope carries a task request through the agent mesh.
type TaskEnvelope struct {
	TaskID      string                 `json:"task_id"`
	ParentID    string                 `json:"parent_id,omitempty"`
	TaskType    TaskType               `json:"task_type"`
	Payload     []byte                 `json:"payload"`
	FromAgent   string                 `json:"from_agent"`
	ToAgent     string                 `json:"to_agent,omitempty"`
	Pattern     string                 `json:"pattern"` // supervisor | p2p | broadcast
	State       TaskState              `json:"state"`
	Result      []byte                 `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Deadline    *time.Time             `json:"deadline,omitempty"`
	SubTasks    []string               `json:"sub_tasks,omitempty"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
}

// Dispatcher routes tasks to agents and tracks their execution.
type Dispatcher struct {
	registry *Registry
	mu       sync.RWMutex
	tasks    map[string]*TaskEnvelope
	handlers map[string]TaskHandler // agentID -> handler
}

// TaskHandler is invoked when a task is dispatched to a local agent.
type TaskHandler func(ctx context.Context, task *TaskEnvelope) ([]byte, error)

// NewDispatcher creates a dispatcher bound to a registry.
func NewDispatcher(registry *Registry) *Dispatcher {
	return &Dispatcher{
		registry: registry,
		tasks:    make(map[string]*TaskEnvelope),
		handlers: make(map[string]TaskHandler),
	}
}

// RegisterHandler binds a local agent ID to its task handler.
func (d *Dispatcher) RegisterHandler(agentID string, h TaskHandler) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.handlers[agentID]; ok {
		return fmt.Errorf("agentmesh: handler already registered for %s", agentID)
	}
	d.handlers[agentID] = h
	return nil
}

// Dispatch routes a task envelope to the appropriate agent.
// If ToAgent is empty, it uses the registry to find a suitable agent.
func (d *Dispatcher) Dispatch(ctx context.Context, task *TaskEnvelope) error {
	if task.TaskID == "" {
		return fmt.Errorf("agentmesh: TaskID required")
	}
	if task.FromAgent == "" {
		return fmt.Errorf("agentmesh: FromAgent required")
	}

	task.State = TaskPending
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()

	d.mu.Lock()
	d.tasks[task.TaskID] = task
	d.mu.Unlock()

	// If no target specified, lookup a capable agent.
	if task.ToAgent == "" {
		candidates := d.registry.Lookup(LookupCriteria{
			TaskType: task.TaskType,
		})
		if len(candidates) == 0 {
			d.updateState(task.TaskID, TaskFailed, nil, "no capable agent found")
			return fmt.Errorf("agentmesh: no capable agent for task %s", task.TaskID)
		}
		// Simple round-robin: pick the first capable agent.
		task.ToAgent = candidates[0].AgentID
	}

	// Check if target is local.
	d.mu.RLock()
	_, isLocal := d.handlers[task.ToAgent]
	d.mu.RUnlock()

	if isLocal {
		return d.executeLocal(ctx, task)
	}
	// Remote execution would go through skylink transport.
	return d.executeRemote(ctx, task)
}

// executeLocal runs the task on a local agent handler.
func (d *Dispatcher) executeLocal(ctx context.Context, task *TaskEnvelope) error {
	d.mu.RLock()
	h, ok := d.handlers[task.ToAgent]
	d.mu.RUnlock()
	if !ok {
		d.updateState(task.TaskID, TaskFailed, nil, "local handler not found")
		return fmt.Errorf("agentmesh: no local handler for %s", task.ToAgent)
	}

	d.updateState(task.TaskID, TaskRunning, nil, "")

	result, err := h(ctx, task)
	if err != nil {
		d.updateState(task.TaskID, TaskFailed, nil, err.Error())
		return err
	}
	d.updateState(task.TaskID, TaskCompleted, result, "")
	return nil
}

// executeRemote is a stub for remote agent execution via skylink.
func (d *Dispatcher) executeRemote(ctx context.Context, task *TaskEnvelope) error {
	// Remote dispatch would serialize the task envelope and send it
	// over libp2p to the target device. For now, mark as pending
	// until the transport layer is integrated.
	return fmt.Errorf("agentmesh: remote execution not yet implemented for agent %s", task.ToAgent)
}

func (d *Dispatcher) updateState(taskID string, state TaskState, result []byte, errStr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.tasks[taskID]; ok {
		t.State = state
		t.UpdatedAt = time.Now()
		if result != nil {
			t.Result = result
		}
		if errStr != "" {
			t.Error = errStr
		}
	}
}

// GetTask returns the current state of a task.
func (d *Dispatcher) GetTask(taskID string) (*TaskEnvelope, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	t, ok := d.tasks[taskID]
	return t, ok
}

// Cancel marks a task as cancelled.
func (d *Dispatcher) Cancel(taskID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.tasks[taskID]; ok {
		if t.State == TaskPending || t.State == TaskRunning {
			t.State = TaskCancelled
			t.UpdatedAt = time.Now()
			return true
		}
	}
	return false
}
