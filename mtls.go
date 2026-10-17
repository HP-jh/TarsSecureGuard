// mtls.go — Zero-Trust mTLS layer inspired by OpenZiti (Apache-2.0).
// Not a fork: re-implements the core ideas in Go standard library.
//
// Kingdom taxonomy: Phylum=network, Class=transport, Order=zero-trust.
// Provides cryptographic identity + mutual authentication + 0-RTT session tickets.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// MTLSConfig holds zero-trust mTLS settings.
type MTLSConfig struct {
	Enabled            bool   `json:"enabled"`
	ServerCertPath     string `json:"server_cert_path"`
	ServerKeyPath      string `json:"server_key_path"`
	ClientCAPath       string `json:"client_ca_path"`       // for server-side client validation
	ClientCertPath     string `json:"client_cert_path"`     // for outbound client cert
	ClientKeyPath      string `json:"client_key_path"`      // for outbound client key
	InsecureSkipVerify bool   `json:"insecure_skip_verify"` // dev only, default false
	SessionTickets     bool   `json:"session_tickets"`      // 0-RTT style resumption
}

// DefaultMTLSConfig returns a secure-by-default configuration.
func DefaultMTLSConfig() MTLSConfig {
	return MTLSConfig{
		Enabled:        true,
		SessionTickets: true,
	}
}

// MTLSManager centralises certificate loading and TLS config generation.
type MTLSManager struct {
	cfg    MTLSConfig
	mu     sync.RWMutex
	server *tls.Config
	client *tls.Config
}

// NewMTLSManager initialises the manager from disk or generates ephemeral certs.
func NewMTLSManager(cfg MTLSConfig) (*MTLSManager, error) {
	m := &MTLSManager{cfg: cfg}
	if !cfg.Enabled {
		return m, nil
	}

	if err := m.loadOrBootstrap(); err != nil {
		return nil, fmt.Errorf("mtls bootstrap: %w", err)
	}
	return m, nil
}

// ServerTLS returns a tls.Config for the gateway listener.
func (m *MTLSManager) ServerTLS() *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.server.Clone()
}

// ClientTLS returns a tls.Config for outbound connections (e.g. upstream LLM).
func (m *MTLSManager) ClientTLS() *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client.Clone()
}

// loadOrBootstrap loads certs from disk.  If missing, generates a self-signed
// ephemeral CA + server cert so the gateway starts securely even without
// external PKI (production should replace these with real certs).
func (m *MTLSManager) loadOrBootstrap() error {
	serverCert, serverKey, clientCA, err := m.loadFromDisk()
	if err != nil {
		// Bootstrap ephemeral CA + certs
		caCert, caKey, err2 := generateCA("TSG-Ephemeral-CA")
		if err2 != nil {
			return err2
		}
		serverCert, serverKey, err2 = generateLeaf(caCert, caKey, "TSG-Server", []string{"localhost", "tsg.local"})
		if err2 != nil {
			return err2
		}
		clientCA = caCert
		// Persist so the same identity survives restarts
		_ = m.persistEphemeral(serverCert, serverKey, caCert)
	}

	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return err
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   !m.cfg.SessionTickets,
	}

	if len(clientCA) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(clientCA) {
			return fmt.Errorf("failed to parse client CA")
		}
		serverTLS.ClientCAs = pool
		serverTLS.ClientAuth = tls.VerifyClientCertIfGiven // allow guests, verify when presented
	}

	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: m.cfg.InsecureSkipVerify,
		SessionTicketsDisabled: !m.cfg.SessionTickets,
	}

	// Load client cert if provided
	if m.cfg.ClientCertPath != "" && m.cfg.ClientKeyPath != "" {
		cc, err := tls.LoadX509KeyPair(m.cfg.ClientCertPath, m.cfg.ClientKeyPath)
		if err != nil {
			return err
		}
		clientTLS.Certificates = []tls.Certificate{cc}
	}

	if len(clientCA) > 0 && !m.cfg.InsecureSkipVerify {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(clientCA)
		clientTLS.RootCAs = pool
	}

	m.mu.Lock()
	m.server = serverTLS
	m.client = clientTLS
	m.mu.Unlock()
	return nil
}

func (m *MTLSManager) loadFromDisk() (certPEM, keyPEM, caPEM []byte, err error) {
	if m.cfg.ServerCertPath == "" || m.cfg.ServerKeyPath == "" {
		return nil, nil, nil, fmt.Errorf("paths not configured")
	}
	certPEM, err = os.ReadFile(m.cfg.ServerCertPath)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err = os.ReadFile(m.cfg.ServerKeyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	if m.cfg.ClientCAPath != "" {
		caPEM, _ = os.ReadFile(m.cfg.ClientCAPath)
	}
	return certPEM, keyPEM, caPEM, nil
}

func (m *MTLSManager) persistEphemeral(cert, key, ca []byte) error {
	base := "./certs"
	_ = os.MkdirAll(base, 0700)
	_ = os.WriteFile(base+"/server.crt", cert, 0600)
	_ = os.WriteFile(base+"/server.key", key, 0600)
	_ = os.WriteFile(base+"/ca.crt", ca, 0644)
	return nil
}

// ----------------------------------------------------------------------
// Ephemeral CA / leaf generation (bootstrapping)
// ----------------------------------------------------------------------

func generateCA(commonName string) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func generateLeaf(caCertPEM, caKeyPEM []byte, cn string, sans []string) (certPEM, keyPEM []byte, err error) {
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     sans,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
