package skylink

import (
	"testing"
)

func TestContentStorePutGet(t *testing.T) {
	s := NewContentStore()
	data := []byte("hello world")
	cid, err := s.Put(data)
	if err != nil {
		t.Fatal(err)
	}
	if cid.Size != len(data) {
		t.Fatalf("size mismatch")
	}
	got, err := s.Get(cid)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("data mismatch")
	}
}

func TestContentStorePinGC(t *testing.T) {
	s := NewContentStore()
	cid, _ := s.Put([]byte("pinned"))
	cid2, _ := s.Put([]byte("unpinned"))
	s.Pin(cid)
	// cid remains pinned; cid2 is unpinned

	removed := s.GC()
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
	if !s.Has(cid) {
		t.Fatal("expected pinned content to survive GC")
	}
	if s.Has(cid2) {
		t.Fatal("expected unpinned content to be GC'd")
	}
}

func TestContentStoreProviders(t *testing.T) {
	s := NewContentStore()
	cid, _ := s.Put([]byte("shared"))
	s.RegisterProvider(cid, "peer1")
	s.RegisterProvider(cid, "peer2")
	s.RegisterProvider(cid, "peer1") // duplicate
	provs := s.FindProviders(cid)
	if len(provs) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(provs))
	}
}

func TestContentStoreStats(t *testing.T) {
	s := NewContentStore()
	s.Put([]byte("a"))
	s.Put([]byte("bb"))
	blocks, pinned, bytes := s.Stats()
	if blocks != 2 {
		t.Fatalf("expected 2 blocks, got %d", blocks)
	}
	if bytes != 3 {
		t.Fatalf("expected 3 bytes, got %d", bytes)
	}
	if pinned != 0 {
		t.Fatalf("expected 0 pinned, got %d", pinned)
	}
}
