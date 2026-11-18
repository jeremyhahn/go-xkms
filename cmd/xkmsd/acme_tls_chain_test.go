package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	nativeca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// intermediateIssuer issues from an intermediate under a root and returns
// what CA.IssueCertificateForKey returns: the leaf in CertificatePEM, the
// CA bundle (intermediate, root) in CACertificatePEM and no ChainPEM.
type intermediateIssuer struct {
	nativeca.CAIssuer
	root, inter   *x509.Certificate
	interKey      *ecdsa.PrivateKey
	rootPEM, iPEM []byte
}

func newIntermediateIssuer(t *testing.T) *intermediateIssuer {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, interKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	return &intermediateIssuer{
		root: root, inter: inter, interKey: interKey,
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		iPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}),
	}
}

func (i *intermediateIssuer) IssueCertificateForKey(_ context.Context, req *nativeca.CertificateRequest, pub crypto.PublicKey) (*nativeca.IssuedCertificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: req.Subject.CommonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: req.KeyUsage, ExtKeyUsage: req.ExtKeyUsage, DNSNames: req.SANS.DNS,
	}
	for _, ip := range req.SANS.IPs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.inter, pub, i.interKey)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &nativeca.IssuedCertificate{
		Certificate:      leaf,
		CertificatePEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CACertificatePEM: append(append([]byte(nil), i.iPEM...), i.rootPEM...),
		NotAfter:         leaf.NotAfter,
	}, nil
}

// TestACMEListenerCert_IntermediateIssuerChainVerifiesAgainstRoot pins that
// a listener certificate issued by an intermediate is written with that
// intermediate, so a TLS client that trusts only the root can connect.
func TestACMEListenerCert_IntermediateIssuerChainVerifiesAgainstRoot(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.ACMEConfig{ExternalURL: "https://acme.example.com", HTTPSAddr: "127.0.0.1:0"}
	cfg.TLS.CertFile, cfg.TLS.KeyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	issuer := newIntermediateIssuer(t)
	if err := ensureACMEListenerCert(context.Background(), issuer, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("ensureACMEListenerCert: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		t.Fatalf("load written pair: %v", err)
	}
	hasInter := false
	for _, der := range pair.Certificate[1:] {
		if bytes.Equal(der, issuer.inter.Raw) {
			hasInter = true
		}
		if bytes.Equal(der, issuer.root.Raw) {
			t.Error("listener chain carries the self-signed root; clients take it from their trust store")
		}
	}
	if !hasInter {
		t.Errorf("listener chain has %d certificate(s) and no intermediate", len(pair.Certificate))
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.(*tls.Conn).Handshake()
		_ = c.Close()
	}()
	roots := x509.NewCertPool()
	roots.AddCert(issuer.root)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "acme.example.com", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("TLS client trusting only the root: %v", err)
	}
	_ = conn.Close()
}
