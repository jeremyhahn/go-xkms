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

package apiharness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// testCA is a CA and one server certificate it issued for 127.0.0.1.
type testCA struct {
	pem  []byte
	leaf tls.Certificate
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name + " server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leaf: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// switchingServer mimics xkmsd across its unseal: the sealed window serves
// a certificate from the bootstrap CA (KEYSTORE_TLS_CA); the unseal persists
// the serving CA to the unified-TLS data dir and every later handshake
// presents a certificate that serving CA issued.
type switchingServer struct {
	bootstrap, serving testCA
	unifiedCA          string
	unsealed           atomic.Bool
}

func (s *switchingServer) config(*tls.ClientHelloInfo) (*tls.Config, error) {
	cert := s.bootstrap.leaf
	if s.unsealed.Load() {
		cert = s.serving.leaf
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, nil
}

func (s *switchingServer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/barrier/status":
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"sealed":true,"initialized":true}`))
	case "/v1/barrier/unseal":
		if err := os.MkdirAll(filepath.Dir(s.unifiedCA), 0o700); err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(s.unifiedCA, s.serving.pem, 0o600); err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.unsealed.Store(true)
		// The sealed window closes: the client dials the full server anew.
		rw.Header().Set("Connection", "close")
		rw.WriteHeader(http.StatusNoContent)
	case "/health/ready":
		if s.unsealed.Load() {
			rw.WriteHeader(http.StatusOK)
			return
		}
		rw.WriteHeader(http.StatusServiceUnavailable)
	default:
		rw.WriteHeader(http.StatusNotFound)
	}
}

// startSwitchingServer lays out the compose paths in a temp dir: the
// bootstrap CA beside nothing else (/etc/xkms/certs/ca.crt), the ceremony
// root and the unified-TLS bundle under a separate data dir, absent until the
// unseal writes it.
func startSwitchingServer(t *testing.T) *switchingServer {
	t.Helper()
	dir := t.TempDir()
	s := &switchingServer{
		bootstrap: newTestCA(t, "bootstrap CA"),
		serving:   newTestCA(t, "serving CA"),
		unifiedCA: filepath.Join(dir, "xkms-data", "xkms", "unified-tls", "ca-bundle.pem"),
	}
	caFile := filepath.Join(dir, "etc", "xkms", "certs", "ca.crt")
	writeFile(t, caFile, s.bootstrap.pem)
	ceremony := filepath.Join(dir, "xkms-data", "xkms", "ca-bundle.pem")
	writeFile(t, ceremony, s.bootstrap.pem)
	t.Setenv(caFileEnv, caFile)
	t.Setenv(ceremonyCAEnv, ceremony)
	t.Setenv(unifiedCAEnv, s.unifiedCA)
	return s
}

func (s *switchingServer) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(s)
	srv.TLS = &tls.Config{GetConfigForClient: s.config, MinVersion: tls.VersionTLS13}
	// Handshakes a client refuses are the failure under test, not noise.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestOpen_TrustsServingCAAfterUnsealSwitchesCertificate: Open reaches the
// sealed window on the bootstrap CA, and after the unseal switches the server
// to a certificate from a distinct serving CA persisted under the data dir,
// AwaitReady still verifies it and Open returns.
func TestOpen_TrustsServingCAAfterUnsealSwitchesCertificate(t *testing.T) {
	s := startSwitchingServer(t)
	srv := s.serve(t)

	done := make(chan error, 1)
	go func() { done <- Open(srv.URL) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Open = %v, want nil", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Open did not verify the serving CA's certificate after the unseal")
	}
}

// TestTrustBundleFile_RefreshesServingCA: the bundle the CLI probes pass as
// --tls-ca picks up the serving CA the server persists at unseal, even when
// it was first written before the unseal.
func TestTrustBundleFile_RefreshesServingCA(t *testing.T) {
	s := startSwitchingServer(t)

	before, err := TrustBundleFile()
	if err != nil {
		t.Fatalf("TrustBundleFile before unseal = %v", err)
	}
	if verifiesLeaf(t, before, s.serving.leaf) {
		t.Fatal("bundle trusts the serving CA before the server persisted it")
	}
	writeFile(t, s.unifiedCA, s.serving.pem)

	after, err := TrustBundleFile()
	if err != nil {
		t.Fatalf("TrustBundleFile after unseal = %v", err)
	}
	if !verifiesLeaf(t, after, s.serving.leaf) {
		t.Fatal("bundle does not trust the serving CA after the unseal")
	}
	if !verifiesLeaf(t, after, s.bootstrap.leaf) {
		t.Fatal("bundle dropped the bootstrap CA")
	}
}

func verifiesLeaf(t *testing.T, bundlePath string, leaf tls.Certificate) bool {
	t.Helper()
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		t.Fatalf("bundle %s holds no certificate", bundlePath)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool})
	return err == nil
}
