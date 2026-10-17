// Package agentmesh provides multi-agent collaboration primitives.
package agentmesh

import (
	"encoding/json"
	"fmt"
	"time"
)

// TaskType defines the kinds of tasks an agent can accept.
type TaskType string

const (
	TaskChat     TaskType = "chat"
	TaskToolCall TaskType = "tool_call"
	TaskFileOp   TaskType = "file_op"
	TaskAudit    TaskType = "audit"
)

// AgentQuota defines resource limits for an agent.
type AgentQuota struct {
	CallsPerMin   int `json:"calls_per_min"`
	TokensPerHour int `json:"tokens_per_hour"`
	ToolsPerDay   int `json:"tools_per_day"`
}

// AgentCard is the identity and capability manifest for an agent.
// Every agent (local or remote) must publish an AgentCard to participate
// in the agent mesh.
type AgentCard struct {
	AgentID      string            `json:"agent_id"`
	Version      string            `json:"version"`
	Capabilities []string          `json:"capabilities"`
	Tools        []string          `json:"tools"`
	Domains      []string          `json:"domains"`
	Accepts      []TaskType        `json:"accepts"`
	Endpoint     string            `json:"endpoint"`
	DeviceID     string            `json:"device_id"`
	RBACRole     string            `json:"rbac_role"`
	Quota        AgentQuota        `json:"quota"`
	UpdatedAt    time.Time         `json:"updated_at"`
	Attrs        map[string]string `json:"attrs,omitempty"`
}

// Validate checks that the AgentCard has required fields.
func (c *AgentCard) Validate() error {
	if c.AgentID == "" {
		return fmt.Errorf("agentmesh: AgentID required")
	}
	if c.Version == "" {
		return fmt.Errorf("agentmesh: Version required")
	}
	if c.RBACRole == "" {
		return fmt.Errorf("agentmesh: RBACRole required")
	}
	return nil
}

// CanAccept reports whether the agent can handle the given task type.
func (c *AgentCard) CanAccept(tt TaskType) bool {
	for _, a := range c.Accepts {
		if a == tt {
			return true
		}
	}
	return false
}

// HasCapability reports whether the agent claims a capability.
func (c *AgentCard) HasCapability(cap string) bool {
	for _, cc := range c.Capabilities {
		if cc == cap {
			return true
		}
	}
	return false
}

// ToJSON serialises the card to JSON.
func (c *AgentCard) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

// AgentCardFromJSON deserialises an AgentCard from JSON.
func AgentCardFromJSON(data []byte) (*AgentCard, error) {
	var c AgentCard
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
