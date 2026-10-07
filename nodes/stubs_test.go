package nodes

import (
	"testing"

	"tarssecureguard/crown"
)

func TestNewAllSatisfiesPipeline(t *testing.T) {
	p, err := crown.NewPipeline(NewAll())
	if err != nil {
		t.Fatalf("NewAll must satisfy canonical order: %v", err)
	}
	env := crown.NewEnvelope()
	if err := p.Run(env); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, id := range crown.CanonicalOrder() {
		if _, ok := env.Attr(VisitedKey(id)); !ok {
			t.Errorf("node %s not visited", id)
		}
	}
}

func TestNamesNonEmpty(t *testing.T) {
	for _, n := range NewAll() {
		if n.Name() == "" {
			t.Errorf("node %s has empty name", n.ID())
		}
	}
}
