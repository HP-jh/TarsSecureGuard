package crown

import (
	"errors"
	"testing"
)

// fakeNode 是测试用节点：可按需中止流水线或返回错误。
type fakeNode struct {
	id      NodeID
	onRun   func(env *Envelope)
	failErr error
	ran     *[]NodeID
}

func (f *fakeNode) ID() NodeID   { return f.id }
func (f *fakeNode) Name() string { return string(f.id) }
func (f *fakeNode) Handle(env *Envelope) error {
	if f.ran != nil {
		*f.ran = append(*f.ran, f.id)
	}
	if f.onRun != nil {
		f.onRun(env)
	}
	return f.failErr
}

func stubSet(order []NodeID) []Node {
	nodes := make([]Node, len(order))
	for i, id := range order {
		nodes[i] = &fakeNode{id: id}
	}
	return nodes
}

func TestNewPipelineAcceptsCanonicalOrder(t *testing.T) {
	p, err := NewPipeline(stubSet(CanonicalOrder()))
	if err != nil {
		t.Fatalf("want valid pipeline, got %v", err)
	}
	if len(p.Nodes()) != 12 {
		t.Fatalf("want 12 nodes, got %d", len(p.Nodes()))
	}
}

func TestNewPipelineRejectsViolations(t *testing.T) {
	swapped := CanonicalOrder()
	swapped[1], swapped[2] = swapped[2], swapped[1] // N2/N3 乱序

	cases := []struct {
		name  string
		nodes []Node
	}{
		{"swapped order", stubSet(swapped)},
		{"missing one", stubSet(CanonicalOrder()[:11])},
		{"extra one", append(stubSet(CanonicalOrder()), &fakeNode{id: "N13_EXTRA"})},
		{"nil entry", func() []Node { ns := stubSet(CanonicalOrder()); ns[5] = nil; return ns }()},
		{"wrong id at position", func() []Node { ns := stubSet(CanonicalOrder()); ns[0] = &fakeNode{id: N2Identity}; return ns }()},
	}
	for _, c := range cases {
		if _, err := NewPipeline(c.nodes); err == nil {
			t.Errorf("%s: want error, got nil", c.name)
		}
	}
}

func TestPipelineRunsInCanonicalOrder(t *testing.T) {
	var ran []NodeID
	nodes := make([]Node, 12)
	for i, id := range CanonicalOrder() {
		id := id
		nodes[i] = &fakeNode{id: id, ran: &ran}
	}
	p, err := NewPipeline(nodes)
	if err != nil {
		t.Fatal(err)
	}
	env := NewEnvelope()
	if err := p.Run(env); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := CanonicalOrder()
	if len(ran) != len(want) {
		t.Fatalf("want %d nodes ran, got %d", len(want), len(ran))
	}
	for i := range want {
		if ran[i] != want[i] {
			t.Fatalf("position %d: want %s, got %s", i, want[i], ran[i])
		}
	}
	if env.Stage != N12Audit {
		t.Fatalf("final stage: want %s, got %s", N12Audit, env.Stage)
	}
}

func TestPipelineStopsOnAbort(t *testing.T) {
	var ran []NodeID
	nodes := make([]Node, 12)
	abortErr := errors.New("security chain rejected request")
	for i, id := range CanonicalOrder() {
		id := id
		fn := &fakeNode{id: id, ran: &ran}
		if i == 3 { // N4 中止
			fn.onRun = func(env *Envelope) { env.Abort(abortErr) }
		}
		nodes[i] = fn
	}
	p, _ := NewPipeline(nodes)
	err := p.Run(NewEnvelope())
	if !errors.Is(err, abortErr) {
		t.Fatalf("want abort error, got %v", err)
	}
	if len(ran) != 4 {
		t.Fatalf("want 4 nodes ran before abort, got %d (%v)", len(ran), ran)
	}
}

func TestPipelineStopsOnNodeError(t *testing.T) {
	var ran []NodeID
	nodes := make([]Node, 12)
	nodeErr := errors.New("node exploded")
	for i, id := range CanonicalOrder() {
		fn := &fakeNode{id: id, ran: &ran}
		if i == 6 { // N7 出错
			fn.failErr = nodeErr
		}
		nodes[i] = fn
	}
	p, _ := NewPipeline(nodes)
	err := p.Run(NewEnvelope())
	if !errors.Is(err, nodeErr) {
		t.Fatalf("want node error, got %v", err)
	}
	if len(ran) != 7 {
		t.Fatalf("want 7 nodes ran, got %d", len(ran))
	}
}

func TestPipelineNilEnvelope(t *testing.T) {
	p, _ := NewPipeline(stubSet(CanonicalOrder()))
	if err := p.Run(nil); err == nil {
		t.Fatal("want error for nil envelope")
	}
}
