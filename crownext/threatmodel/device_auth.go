package threatmodel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// DeviceIdentity holds a device's long-term cryptographic identity.
type DeviceIdentity struct {
	PeerID    string
	PublicKey *ecdsa.PublicKey
	CertPEM   []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// DeviceAuthManager handles mutual authentication between devices.
type DeviceAuthManager struct {
	caPrivate *ecdsa.PrivateKey
	caPublic  *ecdsa.PublicKey
}

// NewDeviceAuthManager creates an auth manager with an ephemeral CA.
// In production the CA key is loaded from HSM or secure enclave.
func NewDeviceAuthManager() (*DeviceAuthManager, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DeviceAuthManager{caPrivate: priv, caPublic: &priv.PublicKey}, nil
}

// IssueDeviceCert creates a device certificate signed by the CA.
func (m *DeviceAuthManager) IssueDeviceCert(peerID string, validity time.Duration) (*DeviceIdentity, []byte, error) {
	devicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial := big.NewInt(0).SetBytes([]byte(peerID))
	if serial.Sign() <= 0 {
		serial = big.NewInt(1)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Subject: pkix.Name{
			CommonName: peerID,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &devicePriv.PublicKey, m.caPrivate)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(devicePriv)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	id := &DeviceIdentity{
		PeerID:    peerID,
		PublicKey: &devicePriv.PublicKey,
		CertPEM:   certPEM,
		IssuedAt:  template.NotBefore,
		ExpiresAt: template.NotAfter,
	}
	return id, privPEM, nil
}

// VerifyPeer verifies that a peer's certificate was signed by our CA
// and matches the claimed peerID.
func (m *DeviceAuthManager) VerifyPeer(peerID string, certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("threatmodel: failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("threatmodel: invalid certificate: %w", err)
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("threatmodel: certificate expired")
	}

	// Verify CA signature.
	pool := x509.NewCertPool()
	caDER, _ := x509.MarshalPKIXPublicKey(m.caPublic)
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: caDER}))
	// For the stub we do a raw signature check since we don't have a real CA cert chain.
	h := sha256.Sum256(cert.RawTBSCertificate)
	if !ecdsa.VerifyASN1(m.caPublic, h[:], cert.Signature) {
		return fmt.Errorf("threatmodel: CA signature invalid")
	}

	// Verify peerID matches subject.
	if cert.Subject.CommonName != peerID {
		return fmt.Errorf("threatmodel: peerID mismatch %s vs %s", cert.Subject.CommonName, peerID)
	}
	return nil
}

// CAFingerprint returns the SHA-256 fingerprint of the CA public key.
func (m *DeviceAuthManager) CAFingerprint() string {
	pubDER, _ := x509.MarshalPKIXPublicKey(m.caPublic)
	h := sha256.Sum256(pubDER)
	return fmt.Sprintf("%x", h[:])
}
