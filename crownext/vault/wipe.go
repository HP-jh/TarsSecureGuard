// wipe.go — EmergencyWipe: secure key destruction on threat detection.
package vault

import (
	"sync"
	"time"
)

// EmergencyWipe coordinates secure destruction of sensitive state.
type EmergencyWipe struct {
	mu       sync.Mutex
	targets  []WipeTarget
	delay    time.Duration
}

// WipeTarget is anything that can be securely wiped.
type WipeTarget interface {
	Wipe()
}

// NewEmergencyWipe creates a wipe coordinator.
func NewEmergencyWipe(delay time.Duration) *EmergencyWipe {
	return &EmergencyWipe{delay: delay}
}

// Register adds a target.
func (e *EmergencyWipe) Register(t WipeTarget) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.targets = append(e.targets, t)
}

// Trigger initiates wipe after the configured delay.
func (e *EmergencyWipe) Trigger(reason string) {
	go func() {
		if e.delay > 0 {
			time.Sleep(e.delay)
		}
		e.Execute(reason)
	}()
}

// Execute performs immediate wipe.
func (e *EmergencyWipe) Execute(reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.targets {
		t.Wipe()
	}
}

// WipeFunc allows registering a plain function as a target.
type WipeFunc func()

func (f WipeFunc) Wipe() { f() }
