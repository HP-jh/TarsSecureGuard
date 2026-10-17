package threatmodel

import (
	"testing"
	"time"
)

func TestDeviceAuthManagerIssueVerify(t *testing.T) {
	m, err := NewDeviceAuthManager()
	if err != nil {
		t.Fatal(err)
	}
	id, privPEM, err := m.IssueDeviceCert("peer1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id.PeerID != "peer1" {
		t.Fatalf("peerID mismatch")
	}
	if len(privPEM) == 0 {
		t.Fatal("expected private key PEM")
	}
	if err := m.VerifyPeer("peer1", id.CertPEM); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestDeviceAuthManagerWrongPeer(t *testing.T) {
	m, _ := NewDeviceAuthManager()
	id, _, _ := m.IssueDeviceCert("peer1", time.Hour)
	if err := m.VerifyPeer("peer2", id.CertPEM); err == nil {
		t.Fatal("expected verification failure for wrong peer")
	}
}

func TestDeviceAuthManagerExpired(t *testing.T) {
	m, _ := NewDeviceAuthManager()
	id, _, _ := m.IssueDeviceCert("peer1", -time.Hour)
	if err := m.VerifyPeer("peer1", id.CertPEM); err == nil {
		t.Fatal("expected verification failure for expired cert")
	}
}

func TestDeviceAuthManagerFingerprint(t *testing.T) {
	m, _ := NewDeviceAuthManager()
	fp := m.CAFingerprint()
	if len(fp) == 0 {
		t.Fatal("expected non-empty fingerprint")
	}
}
