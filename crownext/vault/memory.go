// memory.go — MemoryProtector: XOR masking + mlock for in-memory key protection.
package vault

import (
	"crypto/rand"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// MemoryProtector XORs sensitive bytes with a periodically rotated mask.
type MemoryProtector struct {
	mu        sync.RWMutex
	data      []byte // XORed data
	mask      []byte // current mask
	interval  time.Duration
	ticker    *time.Ticker
	stop      chan struct{}
}

// NewMemoryProtector creates a protector with the given rotation interval.
func NewMemoryProtector(interval time.Duration) *MemoryProtector {
	return &MemoryProtector{
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Protect stores data in XOR-masked form and starts mask rotation.
func (m *MemoryProtector) Protect(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = make([]byte, len(data))
	copy(m.data, data)
	m.mask = make([]byte, len(data))
	if _, err := rand.Read(m.mask); err != nil {
		return err
	}
	// XOR in place
	for i := range m.data {
		m.data[i] ^= m.mask[i]
	}

	// Attempt mlock (best effort; may fail on some systems)
	_ = mlock(m.data)
	_ = mlock(m.mask)

	if m.interval > 0 {
		m.ticker = time.NewTicker(m.interval)
		go m.rotateLoop()
	}
	return nil
}

// Reveal returns the plaintext (creates a copy).
func (m *MemoryProtector) Reveal() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.data) == 0 {
		return nil
	}
	out := make([]byte, len(m.data))
	copy(out, m.data)
	for i := range out {
		out[i] ^= m.mask[i]
	}
	return out
}

// Stop halts rotation and wipes memory.
func (m *MemoryProtector) Stop() {
	close(m.stop)
	if m.ticker != nil {
		m.ticker.Stop()
	}
	m.Wipe()
}

// Wipe securely clears protected memory.
func (m *MemoryProtector) Wipe() {
	m.mu.Lock()
	defer m.mu.Unlock()
	zeroBytes(m.data)
	zeroBytes(m.mask)
	m.data = nil
	m.mask = nil
}

func (m *MemoryProtector) rotateLoop() {
	for {
		select {
		case <-m.ticker.C:
			m.rotate()
		case <-m.stop:
			return
		}
	}
}

func (m *MemoryProtector) rotate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.data) == 0 {
		return
	}
	// First XOR back to plaintext with old mask
	for i := range m.data {
		m.data[i] ^= m.mask[i]
	}
	// Generate new mask
	newMask := make([]byte, len(m.data))
	if _, err := rand.Read(newMask); err != nil {
		return
	}
	// XOR with new mask
	for i := range m.data {
		m.data[i] ^= newMask[i]
	}
	zeroBytes(m.mask)
	m.mask = newMask
	_ = mlock(m.mask)
}

func mlock(b []byte) error {
	// Best-effort memory locking to prevent swap
	return syscall.Mlock(b)
}

func init() {
	// Ensure finalizers run promptly
	runtime.GOMAXPROCS(runtime.NumCPU())
}
