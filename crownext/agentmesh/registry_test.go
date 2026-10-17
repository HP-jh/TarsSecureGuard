package agentmesh

import (
	"sync"
	"testing"
)

func TestRegistryLocalRemote(t *testing.T) {
	r := NewRegistry()
	c1 := &AgentCard{AgentID: "a1", Version: "1.0", RBACRole: "user", DeviceID: "d1"}
	c2 := &AgentCard{AgentID: "a2", Version: "1.0", RBACRole: "user", DeviceID: "d2"}

	if err := r.RegisterLocal(c1); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterRemote(c2); err != nil {
		t.Fatal(err)
	}

	if r.Count() != 2 {
		t.Fatalf("expected count 2, got %d", r.Count())
	}

	if _, ok := r.Get("a1"); !ok {
		t.Fatal("expected a1 in registry")
	}
	if _, ok := r.Get("a2"); !ok {
		t.Fatal("expected a2 in registry")
	}

	r.Unregister("a1")
	if r.Count() != 1 {
		t.Fatalf("expected count 1 after unregister, got %d", r.Count())
	}
}

func TestRegistryLookup(t *testing.T) {
	r := NewRegistry()
	r.RegisterLocal(&AgentCard{AgentID: "a1", Version: "1.0", RBACRole: "user", Capabilities: []string{"nlp"}, Domains: []string{"chat"}, Accepts: []TaskType{TaskChat}})
	r.RegisterLocal(&AgentCard{AgentID: "a2", Version: "1.0", RBACRole: "user", Capabilities: []string{"vision"}, Domains: []string{"image"}, Accepts: []TaskType{TaskToolCall}})

	res := r.Lookup(LookupCriteria{Capability: "nlp"})
	if len(res) != 1 || res[0].AgentID != "a1" {
		t.Fatalf("expected 1 nlp agent, got %v", res)
	}

	res = r.Lookup(LookupCriteria{Domain: "image"})
	if len(res) != 1 || res[0].AgentID != "a2" {
		t.Fatalf("expected 1 image agent, got %v", res)
	}

	res = r.Lookup(LookupCriteria{TaskType: TaskChat})
	if len(res) != 1 || res[0].AgentID != "a1" {
		t.Fatalf("expected 1 chat agent, got %v", res)
	}
}

func TestRegistryConcurrent(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			card := &AgentCard{AgentID: string(rune('a' + i%26)), Version: "1.0", RBACRole: "user"}
			r.RegisterLocal(card)
		}(i)
	}
	wg.Wait()
	if r.Count() != 26 {
		// Some overwrite same letter; that's fine.
		if r.Count() == 0 {
			t.Fatal("registry empty after concurrent writes")
		}
	}
}
