package skylink

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CoordClient is a lightweight distributed coordination client.
// In production this wraps etcd/clientv3, Consul, or ZooKeeper.
// The interface is intentionally narrow to allow swapping backends.
type CoordClient struct {
	mu      sync.RWMutex
	store   map[string]string          // key -> value
	leases  map[string]time.Time       // key -> expiry
	watches map[string][]WatchCallback // key -> callbacks
}

// WatchCallback is invoked when a watched key changes.
type WatchCallback func(key, value string)

// NewCoordClient creates an in-memory coordination client (stub backend).
func NewCoordClient() *CoordClient {
	return &CoordClient{
		store:   make(map[string]string),
		leases:  make(map[string]time.Time),
		watches: make(map[string][]WatchCallback),
	}
}

// Put sets a key-value pair.
func (c *CoordClient) Put(ctx context.Context, key, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = value
	c.notifyWatchers(key, value)
	return nil
}

// PutWithLease sets a key-value pair that expires after ttl.
func (c *CoordClient) PutWithLease(ctx context.Context, key, value string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = value
	c.leases[key] = time.Now().Add(ttl)
	c.notifyWatchers(key, value)
	return nil
}

// Get returns the value for a key.
func (c *CoordClient) Get(ctx context.Context, key string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if expiry, ok := c.leases[key]; ok && time.Now().After(expiry) {
		return "", fmt.Errorf("skylink: key %s lease expired", key)
	}
	v, ok := c.store[key]
	if !ok {
		return "", fmt.Errorf("skylink: key %s not found", key)
	}
	return v, nil
}

// Delete removes a key.
func (c *CoordClient) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, key)
	delete(c.leases, key)
	c.notifyWatchers(key, "")
	return nil
}

// Watch registers a callback for changes to a key prefix.
// In a real etcd backend this uses the Watch API; here it is in-memory.
func (c *CoordClient) Watch(prefix string, cb WatchCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.watches[prefix] = append(c.watches[prefix], cb)
}

// notifyWatchers invokes callbacks for matching prefixes.
func (c *CoordClient) notifyWatchers(key, value string) {
	for prefix, cbs := range c.watches {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			for _, cb := range cbs {
				go cb(key, value) // async to avoid blocking
			}
		}
	}
}

// KeepAlive refreshes the lease for a key, extending its TTL.
func (c *CoordClient) KeepAlive(ctx context.Context, key string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.store[key]; !ok {
		return fmt.Errorf("skylink: key %s not found", key)
	}
	c.leases[key] = time.Now().Add(ttl)
	return nil
}

// List returns all keys with a given prefix.
func (c *CoordClient) List(ctx context.Context, prefix string) (map[string]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string)
	now := time.Now()
	for k, v := range c.store {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			if expiry, ok := c.leases[k]; ok && now.After(expiry) {
				continue
			}
			out[k] = v
		}
	}
	return out, nil
}

// Compact removes expired lease keys.
func (c *CoordClient) Compact() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	removed := 0
	for k, expiry := range c.leases {
		if now.After(expiry) {
			delete(c.store, k)
			delete(c.leases, k)
			removed++
		}
	}
	return removed
}

// CoordElection provides leader election primitives.
type CoordElection struct {
	client   *CoordClient
	key      string
	leaderID string
}

// NewCoordElection creates an election on a coordination key.
func NewCoordElection(client *CoordClient, key, leaderID string) *CoordElection {
	return &CoordElection{client: client, key: key, leaderID: leaderID}
}

// Campaign attempts to become leader by setting the key with a lease.
func (e *CoordElection) Campaign(ctx context.Context, ttl time.Duration) (bool, error) {
	// Naive CAS: if key absent or lease expired, win.
	_, err := e.client.Get(ctx, e.key)
	if err != nil {
		// Key missing => we can win
		_ = e.client.PutWithLease(ctx, e.key, e.leaderID, ttl)
		return true, nil
	}
	return false, nil
}

// Leader returns the current leader ID.
func (e *CoordElection) Leader(ctx context.Context) (string, error) {
	return e.client.Get(ctx, e.key)
}

// Resign deletes the leader key if we hold it.
func (e *CoordElection) Resign(ctx context.Context) error {
	v, err := e.client.Get(ctx, e.key)
	if err != nil {
		return nil
	}
	if v == e.leaderID {
		return e.client.Delete(ctx, e.key)
	}
	return nil
}
