package agentmesh

import (
	"sync"
	"time"
)

// LookupCriteria defines filters for agent lookups.
type LookupCriteria struct {
	Capability string
	Domain     string
	TaskType   TaskType
	DeviceID   string
}

// Registry maintains a thread-safe collection of local and remote agents.
type Registry struct {
	mu       sync.RWMutex
	local    map[string]*AgentCard
	remote   map[string]*AgentCard // key: agentID
	byDevice map[string][]string   // deviceID -> agentIDs
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		local:    make(map[string]*AgentCard),
		remote:   make(map[string]*AgentCard),
		byDevice: make(map[string][]string),
	}
}

// RegisterLocal registers an agent running on the local device.
func (r *Registry) RegisterLocal(card *AgentCard) error {
	if err := card.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.local[card.AgentID] = card
	r.indexByDeviceLocked(card)
	card.UpdatedAt = time.Now()
	return nil
}

// RegisterRemote registers an agent discovered on a remote device.
func (r *Registry) RegisterRemote(card *AgentCard) error {
	if err := card.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remote[card.AgentID] = card
	r.indexByDeviceLocked(card)
	card.UpdatedAt = time.Now()
	return nil
}

// Unregister removes an agent by ID from both local and remote.
func (r *Registry) Unregister(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if card, ok := r.local[agentID]; ok {
		delete(r.local, agentID)
		r.unindexByDeviceLocked(card)
	}
	if card, ok := r.remote[agentID]; ok {
		delete(r.remote, agentID)
		r.unindexByDeviceLocked(card)
	}
}

// Lookup returns all agents matching the criteria.
func (r *Registry) Lookup(criteria LookupCriteria) []*AgentCard {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*AgentCard
	check := func(card *AgentCard) {
		if criteria.Capability != "" && !card.HasCapability(criteria.Capability) {
			return
		}
		if criteria.Domain != "" {
			found := false
			for _, d := range card.Domains {
				if d == criteria.Domain {
					found = true
					break
				}
			}
			if !found {
				return
			}
		}
		if criteria.TaskType != "" && !card.CanAccept(criteria.TaskType) {
			return
		}
		if criteria.DeviceID != "" && card.DeviceID != criteria.DeviceID {
			return
		}
		out = append(out, card)
	}

	for _, card := range r.local {
		check(card)
	}
	for _, card := range r.remote {
		check(card)
	}
	return out
}

// Get returns a specific agent by ID.
func (r *Registry) Get(agentID string) (*AgentCard, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if card, ok := r.local[agentID]; ok {
		return card, true
	}
	if card, ok := r.remote[agentID]; ok {
		return card, true
	}
	return nil, false
}

// LocalIDs returns all local agent IDs.
func (r *Registry) LocalIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.local))
	for id := range r.local {
		ids = append(ids, id)
	}
	return ids
}

// RemoteIDs returns all remote agent IDs.
func (r *Registry) RemoteIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.remote))
	for id := range r.remote {
		ids = append(ids, id)
	}
	return ids
}

// All returns all registered agents (local first, then remote).
func (r *Registry) All() []*AgentCard {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*AgentCard, 0, len(r.local)+len(r.remote))
	for _, c := range r.local {
		out = append(out, c)
	}
	for _, c := range r.remote {
		out = append(out, c)
	}
	return out
}

func (r *Registry) indexByDeviceLocked(card *AgentCard) {
	if card.DeviceID == "" {
		return
	}
	r.byDevice[card.DeviceID] = append(r.byDevice[card.DeviceID], card.AgentID)
}

func (r *Registry) unindexByDeviceLocked(card *AgentCard) {
	if card.DeviceID == "" {
		return
	}
	ids := r.byDevice[card.DeviceID]
	filtered := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != card.AgentID {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		delete(r.byDevice, card.DeviceID)
	} else {
		r.byDevice[card.DeviceID] = filtered
	}
}

// Count returns the total number of registered agents.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.local) + len(r.remote)
}
