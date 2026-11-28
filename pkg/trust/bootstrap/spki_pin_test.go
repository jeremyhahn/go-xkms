package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

func newSPKIPinTestCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestPinTLSConfig_KeepsClientCertificate(t *testing.T) {
	cert, key := newSPKIPinTestCert(t)
	pin := spkipin.ComputeSPKIPin(cert)
	clientCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}
	orig := &tls.Config{Certificates: []tls.Certificate{clientCert}, NextProtos: []string{"h3"}}

	cfg := PinTLSConfig(orig, pin)
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h3" {
		t.Errorf("NextProtos = %v, want [h3]", cfg.NextProtos)
	}
	if !cfg.InsecureSkipVerify || !cfg.SessionTicketsDisabled {
		t.Errorf("InsecureSkipVerify=%v SessionTicketsDisabled=%v, want both true", cfg.InsecureSkipVerify, cfg.SessionTicketsDisabled)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err != nil {
		t.Errorf("VerifyConnection: %v", err)
	}
	if orig.InsecureSkipVerify || orig.VerifyConnection != nil || orig.MinVersion != 0 || orig.SessionTicketsDisabled {
		t.Errorf("PinTLSConfig mutated its input config")
	}
}

func TestPinTLSConfig_WithRootCAsKeepsChainValidation(t *testing.T) {
	cert, _ := newSPKIPinTestCert(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	cfg := PinTLSConfig(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, spkipin.ComputeSPKIPin(cert))
	if cfg.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = true with RootCAs set")
	}
	if cfg.RootCAs != pool {
		t.Errorf("RootCAs not kept")
	}
	if cfg.VerifyConnection == nil {
		t.Errorf("VerifyConnection not set")
	}
}

func TestPinTLSConfig_NilConfig(t *testing.T) {
	cert, _ := newSPKIPinTestCert(t)
	cfg := PinTLSConfig(nil, spkipin.ComputeSPKIPin(cert))
	if cfg == nil {
		t.Fatal("nil config")
	}
	if !cfg.InsecureSkipVerify || !cfg.SessionTicketsDisabled || cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("nil cfg: InsecureSkipVerify=%v SessionTicketsDisabled=%v MinVersion=%x", cfg.InsecureSkipVerify, cfg.SessionTicketsDisabled, cfg.MinVersion)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err != nil {
		t.Errorf("VerifyConnection: %v", err)
	}
}

func TestSPKIPinVerifyConnection(t *testing.T) {
	leaf, _ := newSPKIPinTestCert(t)
	other, _ := newSPKIPinTestCert(t)
	verify := SPKIPinVerifyConnection(spkipin.ComputeSPKIPin(leaf))

	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, other}}); err != nil {
		t.Errorf("leaf pin rejected: %v", err)
	}

	// A pin that matches only the second certificate must be rejected: the
	// leaf alone is pinned.
	verifyOther := SPKIPinVerifyConnection(spkipin.ComputeSPKIPin(other))
	err := verifyOther(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, other}})
	if !errors.Is(err, spkipin.ErrSPKIPinMismatch) {
		t.Errorf("second-cert pin: err = %v, want ErrSPKIPinMismatch", err)
	}

	if err := verify(tls.ConnectionState{}); !errors.Is(err, spkipin.ErrNoCertificates) {
		t.Errorf("no certs: err = %v, want ErrNoCertificates", err)
	}
}
