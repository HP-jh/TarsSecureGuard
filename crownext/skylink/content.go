package skylink

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// CID is a content identifier (simplified; production uses multihash + multicodec).
type CID struct {
	Hash string `json:"hash"`
	Size int    `json:"size"`
}

// String returns the CID as a hex string.
func (c CID) String() string { return c.Hash }

// ContentStore is a lightweight CAS (Content Addressable Storage).
type ContentStore struct {
	mu        sync.RWMutex
	blocks    map[string][]byte // hash -> data
	pins      map[string]int    // hash -> pin count
	providers map[string][]string // hash -> peerIDs
}

// NewContentStore creates an empty content store.
func NewContentStore() *ContentStore {
	return &ContentStore{
		blocks:    make(map[string][]byte),
		pins:      make(map[string]int),
		providers: make(map[string][]string),
	}
}

// Put stores data and returns its CID.
func (s *ContentStore) Put(data []byte) (CID, error) {
	h := sha256.Sum256(data)
	hash := hex.EncodeToString(h[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocks[hash] = data

	return CID{Hash: hash, Size: len(data)}, nil
}

// Get retrieves data by CID.
func (s *ContentStore) Get(c CID) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.blocks[c.Hash]
	if !ok {
		return nil, fmt.Errorf("skylink: content %s not found", c.Hash)
	}
	return data, nil
}

// Pin prevents a CID from being garbage collected.
func (s *ContentStore) Pin(c CID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.blocks[c.Hash]; !ok {
		return fmt.Errorf("skylink: cannot pin unknown content %s", c.Hash)
	}
	s.pins[c.Hash]++
	return nil
}

// Unpin decrements the pin count; when it reaches zero the block may be GC'd.
func (s *ContentStore) Unpin(c CID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pins[c.Hash] > 0 {
		s.pins[c.Hash]--
	}
	return nil
}

// RegisterProvider records that a peer can provide a CID.
func (s *ContentStore) RegisterProvider(c CID, peerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.providers[c.Hash] {
		if p == peerID {
			return
		}
	}
	s.providers[c.Hash] = append(s.providers[c.Hash], peerID)
}

// FindProviders returns peers that have advertised a CID.
func (s *ContentStore) FindProviders(c CID) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.providers[c.Hash]))
	copy(out, s.providers[c.Hash])
	return out
}

// GC removes unpinned blocks.
func (s *ContentStore) GC() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for hash := range s.blocks {
		if s.pins[hash] == 0 {
			delete(s.blocks, hash)
			delete(s.providers, hash)
			removed++
		}
	}
	return removed
}

// Has checks whether a CID exists locally.
func (s *ContentStore) Has(c CID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.blocks[c.Hash]
	return ok
}

// Stats returns store statistics.
func (s *ContentStore) Stats() (blocks, pinned int, totalBytes int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for h, data := range s.blocks {
		blocks++
		totalBytes += int64(len(data))
		if s.pins[h] > 0 {
			pinned++
		}
	}
	return
}

// ContentRecord is a serialisable record of content metadata.
type ContentRecord struct {
	CID        CID       `json:"cid"`
	Name       string    `json:"name,omitempty"`
	MIMEType   string    `json:"mime_type,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	OwnerPeer  string    `json:"owner_peer"`
	Version    int       `json:"version"`
	PrevCID    *CID      `json:"prev_cid,omitempty"`
}
