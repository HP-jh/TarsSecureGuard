package skylink

import (
	"testing"
)

func TestDeviceProfileValidate(t *testing.T) {
	p := &DeviceProfile{PeerID: "p1", DeviceType: DeviceServer}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}

	if err := (&DeviceProfile{}).Validate(); err == nil {
		t.Fatal("expected error for empty profile")
	}
	if err := (&DeviceProfile{PeerID: "p1"}).Validate(); err == nil {
		t.Fatal("expected error for missing DeviceType")
	}
}

func TestDeviceProfileJSON(t *testing.T) {
	p := &DeviceProfile{PeerID: "p1", DeviceType: DevicePhone, Status: StatusOnline}
	data, err := p.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := DeviceProfileFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if p2.PeerID != p.PeerID {
		t.Fatalf("PeerID mismatch")
	}
}
