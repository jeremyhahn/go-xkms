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

package rest

import (
	"bytes"
	"context"
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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// clientCertTestCA is a throwaway CA used to issue (or not issue) the client
// certificate in TestConnect_PresentsConfiguredClientCertificate.
type clientCertTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newClientCertTestCA(t *testing.T, cn string) *clientCertTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &clientCertTestCA{cert: cert, key: key}
}

// issueClient returns the DER leaf and PEM cert/key for a client certificate.
func (ca *clientCertTestCA) issueClient(t *testing.T, cn string) (der, certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return der, certPEM, keyPEM
}

// TestConnect_PresentsConfiguredClientCertificate proves the REST transport
// offers its configured mTLS certificate even when the server's certificate
// request names acceptable CAs that did not issue it. The server, not the
// client, decides whether the certificate is acceptable: the bootstrap
// listener asks for a certificate with a ClientCAs pool that need not hold
// the admin certificate's issuer, and a silent omission surfaces as
// "no client certificate provided".
func TestConnect_PresentsConfiguredClientCertificate(t *testing.T) {
	advertised := newClientCertTestCA(t, "advertised-ca")
	issuer := newClientCertTestCA(t, "unadvertised-ca")
	leafDER, certPEM, keyPEM := issuer.issueClient(t, "admin")

	var (
		mu   sync.Mutex
		seen [][]byte
	)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			seen = append(seen, r.TLS.PeerCertificates[0].Raw)
		} else {
			seen = append(seen, nil)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(advertised.cert)
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS13,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client.key")
	caFile := filepath.Join(dir, "server-ca.pem")
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	for path, data := range map[string][]byte{certFile: certPEM, keyFile: keyPEM, caFile: serverPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	cfg := transport.DefaultConfig()
	cfg.Address = ts.URL
	cfg.TLSEnabled = true
	if err := transport.WithMTLS(certFile, keyFile, caFile)(cfg); err != nil {
		t.Fatalf("WithMTLS: %v", err)
	}
	tr, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tr.Connect(ctx); err != nil {
		t.Fatalf("Connect with a configured client certificate the server's CA list does not name: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("server handler was never reached")
	}
	for i, got := range seen {
		if got == nil {
			t.Fatalf("request %d: server saw no client certificate", i)
		}
		if !bytes.Equal(got, leafDER) {
			t.Fatalf("request %d: server saw a client certificate other than the configured leaf", i)
		}
	}
}
