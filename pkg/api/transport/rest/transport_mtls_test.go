// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package rest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMTLSTestCA returns a self-signed P-256 CA certificate and its key.
func newMTLSTestCA(t *testing.T, cn string, serial int64) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, der, key
}

// TestConnect_MTLSPresentsClientCertToServerAdvertisingOtherCA checks that
// the file-based mTLS pair reaches a server whose CertificateRequest names
// a CA other than the pair's issuer (xkmsd advertises its configured CA,
// not the first-boot TrustedCA that issues the admin pair).
func TestConnect_MTLSPresentsClientCertToServerAdvertisingOtherCA(t *testing.T) {
	caCert, caDER, caKey := newMTLSTestCA(t, "Test CA", 1)
	otherCA, _, _ := newMTLSTestCA(t, "Other CA", 10)

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)
	srvCertParsed, err := x509.ParseCertificate(srvDER)
	require.NoError(t, err)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))
	clientCertFile := filepath.Join(tmpDir, "client.pem")
	require.NoError(t, os.WriteFile(clientCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o600))
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	clientKeyFile := filepath.Join(tmpDir, "client-key.pem")
	require.NoError(t, os.WriteFile(clientKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER}), 0o600))

	// The server advertises only Other CA but does not reject an
	// unverified certificate, so the test observes what the client sends.
	otherPool := x509.NewCertPool()
	otherPool.AddCert(otherCA)

	var (
		mu        sync.Mutex
		peerCount = -1
		peerCN    string
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		peerCount = len(r.TLS.PeerCertificates)
		if peerCount > 0 {
			peerCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{srvDER},
			PrivateKey:  srvKey,
			Leaf:        srvCertParsed,
		}},
		ClientCAs:  otherPool,
		ClientAuth: tls.RequestClientCert,
	}
	srv.StartTLS()
	defer srv.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = srv.URL
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile
	cfg.TLSCertFile = clientCertFile
	cfg.TLSKeyFile = clientKeyFile

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer func() { _ = tr.Close() }()

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, peerCount, "server must see exactly one client certificate")
	assert.Equal(t, "test-client", peerCN)
}
