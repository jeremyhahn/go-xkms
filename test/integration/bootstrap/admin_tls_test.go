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

//go:build integration

package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestNewSDKTransportPresentsAdminCertToForeignCAServer checks that the
// suite's REST client presents the first-boot admin certificate even when
// the server advertises a client CA that did not issue it (tls.server_cn
// unset: the server's client-CA list lacks the first-boot TrustedCA).
func TestNewSDKTransportPresentsAdminCertToForeignCAServer(t *testing.T) {
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "foreign test CA B"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}

	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	caFile := filepath.Join(dir, "ca.pem")
	writePEM(t, certFile, "CERTIFICATE", leafDER)
	writePEM(t, keyFile, "EC PRIVATE KEY", leafKeyDER)

	var (
		mu   sync.Mutex
		seen [][]byte
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			seen = append(seen, r.TLS.PeerCertificates[0].Raw)
		} else {
			seen = append(seen, nil)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy","version":"test"}`))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// Advertise only the httptest CA, never CA B.
	advertised := x509.NewCertPool()
	advertised.AddCert(srv.Certificate())
	srv.TLS.ClientCAs = advertised

	writePEM(t, caFile, "CERTIFICATE", srv.Certificate().Raw)

	t.Setenv(EnvServerURL, srv.URL)
	t.Setenv(EnvTLSCA, caFile)
	t.Setenv(EnvAdminCert, certFile)
	t.Setenv(EnvAdminKey, keyFile)

	_ = newSDKTransport(t)

	mu.Lock()
	defer mu.Unlock()
	for _, raw := range seen {
		if bytes.Equal(raw, leafDER) {
			return
		}
	}
	t.Fatalf("server saw %d request(s), none with the admin certificate: "+
		"the client withheld it because its issuer is not in the server's advertised CAs", len(seen))
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
