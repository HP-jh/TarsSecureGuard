package agentmesh

import (
	"testing"
	"time"
)

func TestAgentCardValidate(t *testing.T) {
	c := &AgentCard{AgentID: "a1", Version: "1.0", RBACRole: "user"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid card rejected: %v", err)
	}

	invalid := []*AgentCard{
		{Version: "1.0", RBACRole: "user"},
		{AgentID: "a1", RBACRole: "user"},
		{AgentID: "a1", Version: "1.0"},
	}
	for i, card := range invalid {
		if err := card.Validate(); err == nil {
			t.Fatalf("case %d: expected error, got nil", i)
		}
	}
}

func TestAgentCardCanAccept(t *testing.T) {
	c := &AgentCard{AgentID: "a1", Version: "1.0", RBACRole: "user", Accepts: []TaskType{TaskChat, TaskToolCall}}
	if !c.CanAccept(TaskChat) {
		t.Fatal("expected CanAccept(chat)=true")
	}
	if c.CanAccept(TaskAudit) {
		t.Fatal("expected CanAccept(audit)=false")
	}
}

func TestAgentCardHasCapability(t *testing.T) {
	c := &AgentCard{AgentID: "a1", Version: "1.0", RBACRole: "user", Capabilities: []string{"nlp", "vision"}}
	if !c.HasCapability("nlp") {
		t.Fatal("expected HasCapability(nlp)=true")
	}
	if c.HasCapability("audio") {
		t.Fatal("expected HasCapability(audio)=false")
	}
}

func TestAgentCardJSON(t *testing.T) {
	c := &AgentCard{
		AgentID: "a1", Version: "1.0", RBACRole: "admin",
		Capabilities: []string{"nlp"},
		UpdatedAt:    time.Now().UTC(),
	}
	data, err := c.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := AgentCardFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if c2.AgentID != c.AgentID {
		t.Fatalf("AgentID mismatch: %s vs %s", c2.AgentID, c.AgentID)
	}
}
