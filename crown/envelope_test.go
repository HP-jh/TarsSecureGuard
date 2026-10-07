package crown

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestEnvelopeAttrsConcurrent(t *testing.T) {
	env := NewEnvelope()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k := fmt.Sprintf("k-%d-%d", w, i)
				env.SetAttr(k, "v")
				if _, ok := env.Attr(k); !ok {
					t.Errorf("attr %s not found after set", k)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestEnvelopeAbortSemantics(t *testing.T) {
	env := NewEnvelope()
	if env.Aborted() != nil {
		t.Fatal("new envelope must not be aborted")
	}
	env.Abort(nil) // 无效调用必须被忽略
	if env.Aborted() != nil {
		t.Fatal("Abort(nil) must be ignored")
	}
	err := errors.New("deny")
	env.Abort(err)
	if !errors.Is(env.Aborted(), err) {
		t.Fatalf("want %v, got %v", err, env.Aborted())
	}
}

func TestCanonicalOrderIsACopy(t *testing.T) {
	a := CanonicalOrder()
	a[0] = "TAMPERED"
	b := CanonicalOrder()
	if b[0] != N1Ingress {
		t.Fatalf("CanonicalOrder returned shared backing array; got %s", b[0])
	}
	if len(b) != 12 {
		t.Fatalf("want 12 nodes, got %d", len(b))
	}
}
