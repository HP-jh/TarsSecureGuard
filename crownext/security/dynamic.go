// dynamic.go — Dynamic Protection: runtime anomaly detection and rate limiting.
package security

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DynamicProtector performs runtime anomaly detection and adaptive rate limiting.
type DynamicProtector struct {
	mu           sync.RWMutex
	window       time.Duration
	threshold    int           // requests per window before anomaly flag
	buckets      map[string]*rateBucket
	events       []AnomalyEvent
	eventsHead   int           // ring buffer head for O(1) rotation
	eventsCap    int
}

type rateBucket struct {
	count  int
	start  time.Time
	locked bool
}

// AnomalyEvent records a detected anomaly.
type AnomalyEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Type      string    `json:"type"`
	Detail    string    `json:"detail"`
	Severity  string    `json:"severity"` // low/medium/high/critical
}

// NewDynamicProtector creates a protector with a sliding time window.
func NewDynamicProtector(window time.Duration, threshold, eventsCap int) *DynamicProtector {
	return &DynamicProtector{
		window:    window,
		threshold: threshold,
		buckets:   make(map[string]*rateBucket),
		eventsCap: eventsCap,
	}
}

// Record increments the counter for a source key.
func (p *DynamicProtector) Record(source string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	b, ok := p.buckets[source]
	if !ok || now.Sub(b.start) > p.window {
		p.buckets[source] = &rateBucket{count: 1, start: now}
		return
	}
	b.count++
	if b.count > p.threshold && !b.locked {
		b.locked = true
		p.addEvent(AnomalyEvent{
			Timestamp: now,
			Source:    source,
			Type:      "rate_limit_exceeded",
			Detail:    fmt.Sprintf("source %s hit %d requests in %v", source, b.count, p.window),
			Severity:  "medium",
		})
	}
}

// IsAnomalous returns true if the source is currently flagged.
func (p *DynamicProtector) IsAnomalous(source string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	b, ok := p.buckets[source]
	if !ok {
		return false
	}
	if time.Since(b.start) > p.window {
		return false
	}
	return b.locked
}

// Reset clears all state.
func (p *DynamicProtector) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buckets = make(map[string]*rateBucket)
	p.events = nil
	p.eventsHead = 0
}

// Events returns recent anomaly events in chronological order.
func (p *DynamicProtector) Events() []AnomalyEvent {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.events) < p.eventsCap {
		out := make([]AnomalyEvent, len(p.events))
		copy(out, p.events)
		return out
	}
	// Ring buffer: reorder from head so output is chronological
	out := make([]AnomalyEvent, p.eventsCap)
	for i := 0; i < p.eventsCap; i++ {
		out[i] = p.events[(p.eventsHead+i)%p.eventsCap]
	}
	return out
}

// Snapshot returns current stats for scoring.
func (p *DynamicProtector) Snapshot() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	anomalies := 0
	for _, b := range p.buckets {
		if b.locked {
			anomalies++
		}
	}
	return map[string]interface{}{
		"activeBuckets": len(p.buckets),
		"anomalies":     anomalies,
		"events":        len(p.events),
		"threshold":     p.threshold,
		"windowSec":     p.window.Seconds(),
	}
}

func (p *DynamicProtector) addEvent(e AnomalyEvent) {
	if len(p.events) < p.eventsCap {
		p.events = append(p.events, e)
		return
	}
	// O(1) ring-buffer rotation — no allocation, no copy
	p.events[p.eventsHead] = e
	p.eventsHead = (p.eventsHead + 1) % p.eventsCap
}

// DynamicEvaluator implements the Evaluator interface for dynamic protection.
type DynamicEvaluator struct {
	protector *DynamicProtector
}

// NewDynamicEvaluator wraps a DynamicProtector as an Evaluator.
func NewDynamicEvaluator(p *DynamicProtector) *DynamicEvaluator {
	return &DynamicEvaluator{protector: p}
}

func (e *DynamicEvaluator) Name() string  { return "动态防护" }
func (e *DynamicEvaluator) Weight() float64 { return 0.35 }

func (e *DynamicEvaluator) Evaluate(ctx context.Context) (Dimension, error) {
	snap := e.protector.Snapshot()
	anomalies := snap["anomalies"].(int)
	events := snap["events"].(int)

	// Score: 100 if no anomalies, decay with count
	score := 100.0 - float64(anomalies)*15.0 - float64(events)*2.0
	score = NormalizeScore(score)

	desc := fmt.Sprintf("当前异常源 %d 个，历史事件 %d 条", anomalies, events)
	if anomalies == 0 && events == 0 {
		desc = "动态防护正常，无异常流量"
	}

	return Dimension{
		Name:        e.Name(),
		Score:       score,
		Weight:      e.Weight(),
		Description: desc,
		Details:     fmt.Sprintf("threshold=%v window=%v", snap["threshold"], snap["windowSec"]),
	}, nil
}
