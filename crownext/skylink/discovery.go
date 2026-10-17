package skylink

import (
	"fmt"
	"sync"
	"time"
)

// Discovery manages the set of known devices.
type Discovery struct {
	mu       sync.RWMutex
	devices  map[string]*DeviceProfile // peerID -> profile
	trusted  map[string]bool           // peerID -> trusted
	lastSeen map[string]time.Time
}

// NewDiscovery creates an empty discovery table.
func NewDiscovery() *Discovery {
	return &Discovery{
		devices:  make(map[string]*DeviceProfile),
		trusted:  make(map[string]bool),
		lastSeen: make(map[string]time.Time),
	}
}

// Register adds or updates a device profile.
func (d *Discovery) Register(profile *DeviceProfile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.devices[profile.PeerID] = profile
	d.lastSeen[profile.PeerID] = time.Now()
	return nil
}

// MarkTrusted marks a peer as trusted.
func (d *Discovery) MarkTrusted(peerID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trusted[peerID] = true
	if dev, ok := d.devices[peerID]; ok {
		dev.Trusted = true
	}
}

// IsTrusted reports whether a peer is in the trusted set.
func (d *Discovery) IsTrusted(peerID string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.trusted[peerID]
}

// Get returns a device profile by PeerID.
func (d *Discovery) Get(peerID string) (*DeviceProfile, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.devices[peerID]
	return p, ok
}

// List returns all known device profiles.
func (d *Discovery) List() []*DeviceProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*DeviceProfile, 0, len(d.devices))
	for _, p := range d.devices {
		out = append(out, p)
	}
	return out
}

// ListTrusted returns only trusted devices.
func (d *Discovery) ListTrusted() []*DeviceProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*DeviceProfile, 0)
	for pid, p := range d.devices {
		if d.trusted[pid] {
			out = append(out, p)
		}
	}
	return out
}

// Remove deletes a device from discovery.
func (d *Discovery) Remove(peerID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.devices, peerID)
	delete(d.trusted, peerID)
	delete(d.lastSeen, peerID)
}

// Prune removes devices not seen within the given duration.
func (d *Discovery) Prune(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	d.mu.Lock()
	defer d.mu.Unlock()
	removed := 0
	for pid, t := range d.lastSeen {
		if t.Before(cutoff) {
			delete(d.devices, pid)
			delete(d.trusted, pid)
			delete(d.lastSeen, pid)
			removed++
		}
	}
	return removed
}

// Count returns the number of known devices.
func (d *Discovery) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.devices)
}

// CountTrusted returns the number of trusted devices.
func (d *Discovery) CountTrusted() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	count := 0
	for pid := range d.devices {
		if d.trusted[pid] {
			count++
		}
	}
	return count
}

// FindByCapability returns devices that advertise a capability.
func (d *Discovery) FindByCapability(cap string) []*DeviceProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []*DeviceProfile
	for _, p := range d.devices {
		for _, c := range p.Capabilities {
			if c == cap {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// FindByType returns devices of a given type.
func (d *Discovery) FindByType(dt DeviceType) []*DeviceProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []*DeviceProfile
	for _, p := range d.devices {
		if p.DeviceType == dt {
			out = append(out, p)
		}
	}
	return out
}

// UpdateStatus updates the status of a device.
func (d *Discovery) UpdateStatus(peerID string, status DeviceStatus, load float64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.devices[peerID]
	if !ok {
		return fmt.Errorf("skylink: device %s not found", peerID)
	}
	p.Status = status
	p.Load = load
	p.LastSeen = time.Now()
	d.lastSeen[peerID] = time.Now()
	return nil
}
