package skylink

import (
	"testing"
	"time"
)

func TestDiscoveryRegister(t *testing.T) {
	d := NewDiscovery()
	p := &DeviceProfile{PeerID: "p1", DeviceType: DeviceServer}
	if err := d.Register(p); err != nil {
		t.Fatal(err)
	}
	if d.Count() != 1 {
		t.Fatalf("expected count 1, got %d", d.Count())
	}
}

func TestDiscoveryTrusted(t *testing.T) {
	d := NewDiscovery()
	d.Register(&DeviceProfile{PeerID: "p1", DeviceType: DeviceServer})
	d.MarkTrusted("p1")
	if !d.IsTrusted("p1") {
		t.Fatal("expected p1 trusted")
	}
	if d.CountTrusted() != 1 {
		t.Fatalf("expected 1 trusted, got %d", d.CountTrusted())
	}
}

func TestDiscoveryPrune(t *testing.T) {
	d := NewDiscovery()
	d.Register(&DeviceProfile{PeerID: "p1", DeviceType: DeviceServer})
	time.Sleep(50 * time.Millisecond)
	d.Register(&DeviceProfile{PeerID: "p2", DeviceType: DeviceServer})
	removed := d.Prune(30 * time.Millisecond)
	if removed != 1 {
		t.Fatalf("expected 1 pruned, got %d", removed)
	}
	if d.Count() != 1 {
		t.Fatalf("expected count 1 after prune, got %d", d.Count())
	}
}

func TestDiscoveryFindByCapability(t *testing.T) {
	d := NewDiscovery()
	d.Register(&DeviceProfile{PeerID: "p1", DeviceType: DeviceServer, Capabilities: []string{"gpu", "storage"}})
	d.Register(&DeviceProfile{PeerID: "p2", DeviceType: DevicePhone, Capabilities: []string{"camera"}})
	res := d.FindByCapability("gpu")
	if len(res) != 1 || res[0].PeerID != "p1" {
		t.Fatalf("expected p1 for gpu, got %v", res)
	}
}

func TestDiscoveryFindByType(t *testing.T) {
	d := NewDiscovery()
	d.Register(&DeviceProfile{PeerID: "p1", DeviceType: DeviceServer})
	d.Register(&DeviceProfile{PeerID: "p2", DeviceType: DevicePhone})
	res := d.FindByType(DevicePhone)
	if len(res) != 1 || res[0].PeerID != "p2" {
		t.Fatalf("expected p2 for phone, got %v", res)
	}
}
