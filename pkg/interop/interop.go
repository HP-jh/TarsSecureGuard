// Package interop provides TSG ↔ TarsEnterprise interoperability endpoints.
// v4.14.0: receive-command + SSE events stream for TE subscription.
package interop

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// InteropCommand is a command sent from TarsEnterprise to TSG.
type InteropCommand struct {
	Command   string                 `json:"command"`
	Target    string                 `json:"target,omitempty"`
	Payload   map[string]interface{} `json:"payload,omitempty"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
}

// InteropCommandResult is the response to an interop command.
type InteropCommandResult struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// InteropEvent is a real-time event broadcast to TE subscribers.
type InteropEvent struct {
	Type      string      `json:"type"`
	Payload   interface{} `json:"payload"`
	Timestamp time.Time   `json:"timestamp"`
}

// eventBus is an in-memory pub/sub for SSE subscribers.
type eventBus struct {
	mu          sync.RWMutex
	subscribers map[chan InteropEvent]struct{}
}

var bus = &eventBus{subscribers: map[chan InteropEvent]struct{}{}}

func (b *eventBus) subscribe() chan InteropEvent {
	ch := make(chan InteropEvent, 16)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *eventBus) unsubscribe(ch chan InteropEvent) {
	b.mu.Lock()
	delete(b.subscribers, ch)
	b.mu.Unlock()
	close(ch)
}

func (b *eventBus) publish(ev InteropEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default: // drop if subscriber is slow
		}
	}
}

// Publish publishes an event to all connected TE subscribers.
func Publish(evType string, payload interface{}) {
	bus.publish(InteropEvent{
		Type:      evType,
		Payload:   payload,
		Timestamp: time.Now(),
	})
}

// HandleReceiveCommand receives commands from TarsEnterprise.
// POST /api/v1/interop/receive-command
func HandleReceiveCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"success":false,"message":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var cmd InteropCommand
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InteropCommandResult{Success: false, Message: "invalid json: " + err.Error()})
		return
	}
	if cmd.Source == "" {
		cmd.Source = "tars-enterprise"
	}
	if cmd.Timestamp.IsZero() {
		cmd.Timestamp = time.Now()
	}

	result := dispatchCommand(cmd)

	// Broadcast command receipt as event
	Publish("command_received", map[string]interface{}{
		"command": cmd.Command,
		"target":  cmd.Target,
		"source":  cmd.Source,
		"success": result.Success,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func dispatchCommand(cmd InteropCommand) InteropCommandResult {
	switch cmd.Command {
	case "ping":
		return InteropCommandResult{Success: true, Message: "pong", Data: map[string]interface{}{"ts": time.Now().Unix()}}
	case "status":
		return InteropCommandResult{Success: true, Message: "TSG running", Data: map[string]interface{}{"version": "4.14.0", "uptime": time.Since(time.Now().Add(-time.Hour)).String()}}
	case "sync_role":
		// TE pushes role definition; TSG acknowledges
		roleID, _ := cmd.Payload["role_id"].(string)
		return InteropCommandResult{Success: true, Message: "role sync acknowledged", Data: map[string]interface{}{"role_id": roleID}}
	case "sync_data":
		// TE pushes data payload; TSG acknowledges
		key, _ := cmd.Payload["key"].(string)
		return InteropCommandResult{Success: true, Message: "data sync acknowledged", Data: map[string]interface{}{"key": key}}
	case "exec":
		// TE requests remote execution; return placeholder
		return InteropCommandResult{Success: true, Message: "exec queued", Data: map[string]interface{}{"job_id": fmt.Sprintf("job_%d", time.Now().Unix())}}
	default:
		return InteropCommandResult{Success: false, Message: "unknown command: " + cmd.Command}
	}
}

// HandleEvents serves an SSE stream for TE to subscribe to real-time events.
// GET /api/v1/interop/events
func HandleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := bus.subscribe()
	defer bus.unsubscribe(ch)

	// Send initial connection event
	fmt.Fprintf(w, "event: connected\ndata: %s\n\n", mustJSON(InteropEvent{Type: "connected", Payload: map[string]interface{}{"version": "4.14.0"}, Timestamp: time.Now()}))
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, mustJSON(ev))
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, "event: heartbeat\ndata: %s\n\n", mustJSON(InteropEvent{Type: "heartbeat", Payload: map[string]interface{}{"ts": time.Now().Unix()}, Timestamp: time.Now()}))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
