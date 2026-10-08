package threatmodel

import (
	"fmt"
	"sync"
	"time"
)

// IsolationLevel defines how strictly an untrusted device is constrained.
type IsolationLevel string

const (
	IsolationNone      IsolationLevel = "none"
	IsolationRateLimit IsolationLevel = "rate_limit"
	IsolationQuarantine IsolationLevel = "quarantine"
	IsolationBlock     IsolationLevel = "block"
)

// QuarantineRecord tracks an isolated device.
type QuarantineRecord struct {
	PeerID        string         `json:"peer_id"`
	Level         IsolationLevel `json:"level"`
	Reason        string         `json:"reason"`
	Since         time.Time      `json:"since"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
	RequestCount  int            `json:"request_count"`
	LastViolation time.Time      `json:"last_violation"`
}

// Isolator manages untrusted device isolation.
type Isolator struct {
	mu          sync.RWMutex
	records     map[string]*QuarantineRecord
	rateLimits  map[string]chan struct{} // peerID -> token bucket
	defaultTTL  time.Duration
	maxRequests int
}

// NewIsolator creates an isolator with default quarantine TTL.
func NewIsolator(defaultTTL time.Duration, maxRequests int) *Isolator {
	return &Isolator{
		records:     make(map[string]*QuarantineRecord),
		rateLimits:  make(map[string]chan struct{}),
		defaultTTL:  defaultTTL,
		maxRequests: maxRequests,
	}
}

// Quarantine places a peer under quarantine.
func (i *Isolator) Quarantine(peerID, reason string, level IsolationLevel, ttl *time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()
	exp := time.Now().Add(i.defaultTTL)
	if ttl != nil {
		exp = time.Now().Add(*ttl)
	}
	i.records[peerID] = &QuarantineRecord{
		PeerID:        peerID,
		Level:         level,
		Reason:        reason,
		Since:         time.Now(),
		ExpiresAt:     &exp,
		LastViolation: time.Now(),
	}
	if level == IsolationRateLimit {
		i.rateLimits[peerID] = make(chan struct{}, i.maxRequests)
	}
}

// Lift removes a peer from quarantine.
func (i *Isolator) Lift(peerID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.records, peerID)
	delete(i.rateLimits, peerID)
}

// Check evaluates whether a peer is allowed to proceed.
func (i *Isolator) Check(peerID string) error {
	i.mu.RLock()
	rec, ok := i.records[peerID]
	i.mu.RUnlock()
	if !ok {
		return nil
	}
	if rec.ExpiresAt != nil && time.Now().After(*rec.ExpiresAt) {
		i.Lift(peerID)
		return nil
	}
	switch rec.Level {
	case IsolationBlock:
		return fmt.Errorf("threatmodel: peer %s is blocked: %s", peerID, rec.Reason)
	case IsolationQuarantine:
		return fmt.Errorf("threatmodel: peer %s is quarantined: %s", peerID, rec.Reason)
	case IsolationRateLimit:
		return i.checkRateLimit(peerID)
	default:
		return nil
	}
}

func (i *Isolator) checkRateLimit(peerID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	bucket, ok := i.rateLimits[peerID]
	if !ok {
		return nil
	}
	select {
	case bucket <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("threatmodel: peer %s rate limited", peerID)
	}
}

// RecordViolation logs a violation and escalates isolation if needed.
func (i *Isolator) RecordViolation(peerID, reason string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	rec, ok := i.records[peerID]
	if !ok {
		// First violation -> rate limit
		exp := time.Now().Add(i.defaultTTL)
		i.records[peerID] = &QuarantineRecord{
			PeerID:        peerID,
			Level:         IsolationRateLimit,
			Reason:        reason,
			Since:         time.Now(),
			ExpiresAt:     &exp,
			LastViolation: time.Now(),
		}
		i.rateLimits[peerID] = make(chan struct{}, i.maxRequests)
		return
	}
	rec.RequestCount++
	rec.LastViolation = time.Now()
	// Escalation: rate_limit -> quarantine -> block
	if rec.Level == IsolationRateLimit && rec.RequestCount > i.maxRequests*3 {
		rec.Level = IsolationQuarantine
		rec.Reason = "escalated: " + reason
	} else if rec.Level == IsolationQuarantine && rec.RequestCount > i.maxRequests*5 {
		rec.Level = IsolationBlock
		rec.Reason = "escalated: " + reason
	}
}

// GetRecord returns the quarantine record for a peer.
func (i *Isolator) GetRecord(peerID string) (*QuarantineRecord, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	r, ok := i.records[peerID]
	return r, ok
}

// List returns all active quarantine records.
func (i *Isolator) List() []*QuarantineRecord {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]*QuarantineRecord, 0, len(i.records))
	for _, r := range i.records {
		out = append(out, r)
	}
	return out
}

// Prune removes expired records.
func (i *Isolator) Prune() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	removed := 0
	for pid, rec := range i.records {
		if rec.ExpiresAt != nil && now.After(*rec.ExpiresAt) {
			delete(i.records, pid)
			delete(i.rateLimits, pid)
			removed++
		}
	}
	return removed
}
