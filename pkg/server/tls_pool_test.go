// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// writeTLSPoolTestCA emits a self-signed CA PEM into path and returns
// the parsed certificate so tests can verify pool membership.
func writeTLSPoolTestCA(t *testing.T, path, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

func TestLoadClientCAsUnion_NoInputs(t *testing.T) {
	pool, err := loadClientCAsUnion()
	if err != nil {
		t.Fatalf("no inputs: %v", err)
	}
	if pool != nil {
		t.Fatalf("no inputs: expected nil pool")
	}

	pool, err = loadClientCAsUnion(nil, []string{}, []string{""})
	if err != nil {
		t.Fatalf("blanks: %v", err)
	}
	if pool != nil {
		t.Fatalf("blanks: expected nil pool")
	}
}

func TestLoadClientCAsUnion_TwoSlices(t *testing.T) {
	dir := t.TempDir()
	primaryPath := filepath.Join(dir, "primary.pem")
	extraPath := filepath.Join(dir, "extra.pem")
	primary := writeTLSPoolTestCA(t, primaryPath, "primary-ca")
	extra := writeTLSPoolTestCA(t, extraPath, "extra-ca")

	pool, err := loadClientCAsUnion([]string{primaryPath}, []string{extraPath})
	if err != nil {
		t.Fatalf("union: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	for _, c := range []*x509.Certificate{primary, extra} {
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			t.Fatalf("missing %s: %v", c.Subject.CommonName, err)
		}
	}
}

func TestLoadClientCAsUnion_DedupAcrossSlices(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	cert := writeTLSPoolTestCA(t, caPath, "shared")

	relForm := filepath.Join(dir, ".", "ca.pem")
	pool, err := loadClientCAsUnion(
		[]string{caPath, caPath},
		[]string{relForm},
	)
	if err != nil {
		t.Fatalf("union: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("dedup pool missing cert: %v", err)
	}
}

func TestLoadClientCAsUnion_MissingFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.pem")

	_, err := loadClientCAsUnion([]string{missing})
	if err == nil {
		t.Fatal("expected error")
	}
	var fileErr *ErrFileRead
	if !errors.As(err, &fileErr) {
		t.Fatalf("expected *ErrFileRead, got %T (%v)", err, err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected wrapped os.ErrNotExist, got %v", err)
	}
}

func TestLoadClientCAsUnion_MalformedPEM(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadClientCAsUnion([]string{bad})
	if err == nil {
		t.Fatal("expected error")
	}
	var parseErr *ErrCertParse
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *ErrCertParse, got %T (%v)", err, err)
	}
}

// TestServer_BuildTLSConfig_ListenerWiring ensures buildTLSConfig
// merges TLS.CAFile and TLS.ClientCAs into a single deduplicated
// ClientCAs pool on the resulting tls.Config (the listener-facing
// surface).
func TestServer_BuildTLSConfig_ListenerWiring(t *testing.T) {
	dir := t.TempDir()
	primaryPath := filepath.Join(dir, "primary.pem")
	extraPath := filepath.Join(dir, "extra.pem")
	primary := writeTLSPoolTestCA(t, primaryPath, "primary-ca")
	extra := writeTLSPoolTestCA(t, extraPath, "extra-ca")

	// Reuse the existing test fixture helper for the server cert/key
	// pair so we can run buildTLSConfig end-to-end against a real
	// keypair.
	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.CAFile = primaryPath
	// Include duplicate plus a dedicated extra so dedup is exercised.
	cfg.TLS.ClientCAs = []string{primaryPath, extraPath}

	srv, err := newServerWithCleanup(t, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

	tlsCfg, err := srv.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if tlsCfg.ClientCAs == nil {
		t.Fatal("expected ClientCAs on tls.Config")
	}
	for _, c := range []*x509.Certificate{primary, extra} {
		if _, err := c.Verify(x509.VerifyOptions{Roots: tlsCfg.ClientCAs}); err != nil {
			t.Fatalf("ClientCAs missing %s: %v", c.Subject.CommonName, err)
		}
	}
}

func TestServer_BuildTLSConfig_MalformedPrimaryCAReturnsLegacySentinel(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	certFile, keyFile, _ := createTestTLSFiles(t)

	srv := newTLSTestServer(t, &config.Config{
		TLS: config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile, CAFile: bad},
	})

	_, err := srv.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for malformed primary CA")
	}
	if !errors.Is(err, ErrCAParseCert) {
		t.Fatalf("expected wrapped ErrCAParseCert, got %v", err)
	}
}
