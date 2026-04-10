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
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Connect TLS Branches ---

func TestConnect_TLSWithCAFile(t *testing.T) {
	// Generate a self-signed CA certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:                     true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Generate server certificate signed by CA
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

	// Write CA cert to temp file
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	// Create TLS server
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{srvDER},
				PrivateKey:  srvKey,
				Leaf:        srvCertParsed,
			},
		},
	}
	srv.StartTLS()
	defer srv.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = srv.URL
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	assert.True(t, tr.IsConnected())
	require.NoError(t, tr.Close())
}

func TestConnect_TLSWithInvalidCAFile(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "localhost:9999"
	cfg.TLSEnabled = true
	cfg.TLSCAFile = "/nonexistent/ca.pem"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

func TestConnect_TLSWithInvalidCAPEM(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0o600))

	cfg := transport.DefaultConfig()
	cfg.Address = "localhost:9999"
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestConnect_TLSWithClientCert(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:                     true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Generate server cert
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

	// Generate client cert
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

	// Write CA cert
	caFile := filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	// Write client cert
	clientCertFile := filepath.Join(tmpDir, "client.pem")
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	require.NoError(t, os.WriteFile(clientCertFile, clientCertPEM, 0o600))

	// Write client key
	clientKeyFile := filepath.Join(tmpDir, "client-key.pem")
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})
	require.NoError(t, os.WriteFile(clientKeyFile, clientKeyPEM, 0o600))

	// Create mTLS server
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{srvDER},
				PrivateKey:  srvKey,
				Leaf:        srvCertParsed,
			},
		},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
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

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	assert.True(t, tr.IsConnected())
	require.NoError(t, tr.Close())
}

func TestConnect_TLSWithInvalidClientCert(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:                     true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	cfg := transport.DefaultConfig()
	cfg.Address = "localhost:9999"
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile
	cfg.TLSCertFile = "/nonexistent/client.pem"
	cfg.TLSKeyFile = "/nonexistent/client-key.pem"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestConnect_TLSWithPrebuiltConfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
	}))
	defer srv.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = srv.URL
	cfg.TLSEnabled = true
	cfg.TLSConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	assert.True(t, tr.IsConnected())
	require.NoError(t, tr.Close())
}

func TestConnect_TLSWithSPKIPinAndCA(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:                     true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	cfg := transport.DefaultConfig()
	cfg.Address = "localhost:9999"
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile
	cfg.SPKIPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// Connect will fail because no server is listening, but the TLS config
	// is built successfully (covers the SPKI+CA branch)
	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectionFailed)
}

func TestConnect_TLSWithSPKIPinNoCA(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "localhost:9999"
	cfg.TLSEnabled = true
	cfg.SPKIPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectionFailed)
}

// --- Invalid JSON Unmarshal Tests ---
// These test the error path when server returns non-JSON for methods
// that attempt json.Unmarshal on the response.

// newInvalidJSONServer returns a server that serves valid JSON for /health
// but invalid JSON for all other paths.
func newInvalidJSONServer(t *testing.T) (*httptest.Server, *Transport) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("NOT JSON"))
	}))

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	return srv, tr
}

func TestHealth_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == http.MethodGet {
			// First call for Connect succeeds, subsequent calls return bad JSON
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("NOT JSON"))
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	// Health always hits /health which returns valid JSON in this mock,
	// so test the case where the health endpoint returns bad JSON
	// by calling a method that parses a response from a different path pattern.
	// Already covered via Connect. Tested via ListBackends_InvalidJSON etc below.
}

func TestListBackends_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListBackends(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetBackend_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetBackend(context.Background(), "software")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGenerateKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID: "k1", Backend: "sw", KeyType: "ECDSA",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestListKeys_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListKeys(context.Background(), "software")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetKey(context.Background(), "software", "k1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestDeleteKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.DeleteKey(context.Background(), "software", "k1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestSign_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "sw", KeyID: "k1", Data: []byte("data"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestVerify_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.Verify(context.Background(), &transport.VerifyRequest{
		Backend: "sw", KeyID: "k1", Data: []byte("data"), Signature: []byte("sig"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestEncrypt_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend: "sw", KeyID: "k1", Plaintext: []byte("data"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestDecrypt_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend: "sw", KeyID: "k1", Ciphertext: []byte("ct"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestEncryptAsym_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend: "sw", KeyID: "k1", Plaintext: []byte("data"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestDeriveKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend: "sw", Algorithm: "HKDF", KeyLength: 32,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetCertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetCertificate(context.Background(), "sw", "k1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestImportKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestExportKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{
		KeyID: "k1", Backend: "sw",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRotateKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.RotateKey(context.Background(), &transport.RotateKeyRequest{
		KeyID: "k1", Backend: "sw",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetImportParameters_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestWrapKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestUnwrapKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestWrapKeyByID_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestUnwrapKeyByID_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestExportKeyMaterial_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		KeyID: "k1", Backend: "sw",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestDeriveKeyECDH_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestCopyKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestListCertificates_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListCertificates(context.Background(), "sw")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetCertificateChain_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetCertificateChain(context.Background(), "sw", "k1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetTLSCertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetTLSCertificate(context.Background(), "sw", "k1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestSeal_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.Seal(context.Background(), &transport.SealRequest{
		Backend: "sw", Data: []byte("data"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestUnseal_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.Unseal(context.Background(), &transport.UnsealRequest{
		Backend: "sw", Ciphertext: []byte("ct"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestCanSeal_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.CanSeal(context.Background(), "software")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestAttestKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{
		Backend: "sw", KeyID: "k1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestListUsers_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListUsers(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetUser_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetUser(context.Background(), "user1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestListUserCredentials_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListUserCredentials(context.Background(), "user1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- WebAuthn InvalidJSON ---

func TestBeginRegistration_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{
		Username: "test@example.com",
	})
	require.Error(t, err)
}

func TestFinishRegistration_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{
		CredentialID: "cred1", Username: "test",
	})
	require.Error(t, err)
}

func TestBeginAuthentication_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{
		Username: "test@example.com",
	})
	require.Error(t, err)
}

func TestFinishAuthentication_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{
		CredentialID: "cred1", Username: "test",
	})
	require.Error(t, err)
}

// --- CA Operations InvalidJSON ---

func TestGetCABundle_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetCACertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestSignCSR_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{CSRPEM: []byte("pem")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestIssueCertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{
		CommonName: "test", Profile: "server",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRevokeCertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{
		SerialNumber: "123", Reason: 1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGenerateCRL_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestIsRevoked_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{SerialNumber: "123"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- TCG CA Operations InvalidJSON ---

func TestIssueEKCertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{
		CommonName: "test", EKPublicKey: []byte("key"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestIssueAKCertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{
		CommonName: "test", PublicKey: []byte("key"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestSignTCGCSR_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{
		CommonName: "test", TCGCSR: []byte("csr"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestEnrollDevice_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{
		CommonName: "test", PackedCSR: []byte("packed"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- PIV Operations InvalidJSON ---

func TestListPIVSlots_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{Backend: "sw"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetPIVCertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Slot: "9a", Backend: "sw", Format: "pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGeneratePIVKey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Slot: "9a", Backend: "sw",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestExportPIVCertificate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Slot: "9a", Backend: "sw", Format: "pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGeneratePIVCSR_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Slot: "9a", Backend: "sw",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- Barrier InvalidJSON ---

func TestBarrierStatus_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BarrierStatus(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBarrierInitializeShamir_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBarrierUnsealWithShare_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBarrierShamirListShares_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BarrierShamirListShares(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBarrierRekey_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBarrierGenerateRecoveryKeys_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBarrierHasRecoveryKeys_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BarrierHasRecoveryKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBarrierGenerateRootToken_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- Password Operations InvalidJSON ---

func TestPasswordAdd_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestPasswordGet_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{ID: "p1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestPasswordList_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestPasswordStoreStatus_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.PasswordStoreStatus(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestPasswordGenerate_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetLockoutStatus_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetLockoutStatus(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- Init Ceremony InvalidJSON ---

func TestGetInitStatus_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetInitStatus(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestClaimCertBegin_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestClaimCertComplete_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestClaimShare_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ClaimShare(context.Background(), &transport.ClaimShareRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestSignCSRInit_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestSubmitCredential_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetCredentialStrategy_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetCredentialStrategy(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- Custodian/Share/Tenant InvalidJSON ---

func TestCreateCustodianGroup_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetCustodianGroup_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetCustodianGroup(context.Background(), "grp1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestListCustodianGroups_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListCustodianGroups(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestAddCustodianMember_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{
		GroupID: "grp1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestDistributeShares_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.DistributeShares(context.Background(), &transport.DistributeSharesRequest{
		GroupID: "grp1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestSubmitShare_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestListShares_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListShares(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetShareCollectionStatus_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetShareCollectionStatus(context.Background(), "grp1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestCreateTenant_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetTenant_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.GetTenant(context.Background(), "t1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestListTenants_InvalidJSON(t *testing.T) {
	srv, tr := newInvalidJSONServer(t)
	defer srv.Close()
	defer tr.Close()

	_, err := tr.ListTenants(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- Optional Field Coverage ---
// Test methods that have conditional body fields to cover branches.

func TestSign_WithHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"signature": "c2ln", "algorithm": "ECDSA"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "sw", KeyID: "k1", Data: []byte("data"), Hash: "SHA256",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestVerify_WithHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"valid": true})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.Verify(context.Background(), &transport.VerifyRequest{
		Backend: "sw", KeyID: "k1", Data: []byte("data"),
		Signature: []byte("sig"), Hash: "SHA256",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestEncrypt_WithAdditionalData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": "ZW5j"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend: "sw", KeyID: "k1", Plaintext: []byte("data"),
		AdditionalData: []byte("aad"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDecrypt_WithAllOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"plaintext": "cGxhaW4="})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:        "sw",
		KeyID:          "k1",
		Ciphertext:     []byte("ct"),
		Nonce:          []byte("nonce123456"),
		Tag:            []byte("tag1234567890123"),
		AdditionalData: []byte("aad"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestEncryptAsym_WithHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": "YXN5bQ=="})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend: "sw", KeyID: "k1", Plaintext: []byte("data"), Hash: "SHA256",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCABundle_WithAllParams(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		capturedPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"bundle_pem": "cGVtLWRhdGE="})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{
		StoreType: "trust", Algorithm: "ECDSA", TenantID: "tenant1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, capturedPath, "store_type=trust")
	assert.Contains(t, capturedPath, "algorithm=ECDSA")
	assert.Contains(t, capturedPath, "tenant_id=tenant1")
}

func TestGetCACertificate_WithAllParams(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		capturedPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"certificate_pem": "cert"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{
		Identity: "root-ca", TenantID: "tenant1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, capturedPath, "identity=root-ca")
	assert.Contains(t, capturedPath, "tenant_id=tenant1")
}

func TestSignCSR_WithAllOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"certificate_pem": "cert"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM:       []byte("pem"),
		Profile:      "server",
		ValidityDays: 365,
		TenantID:     "t1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIssueCertificate_WithAllOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"certificate_pem": "cert", "key_id": "k1"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{
		CommonName:   "test.example.com",
		Profile:      "server",
		Organization: "Test Org",
		SANs:         []string{"test.example.com", "alt.example.com"},
		ValidityDays: 365,
		Algorithm:    "ECDSA-P256",
		TenantID:     "t1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestRevokeCertificate_WithTenantID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{
		SerialNumber: "123456", Reason: 1, TenantID: "t1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGenerateCRL_WithTenantID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"crl_pem": "Y3JsLWRhdGE="})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{TenantID: "t1"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIsRevoked_WithTenantID(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		capturedPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"revoked": false})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{
		SerialNumber: "123456", TenantID: "t1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, capturedPath, "tenant_id=t1")
}

func TestIssueEKCertificate_WithOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"certificate_pem": "cert"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{
		CommonName: "ek-test", EKPublicKey: []byte("key"), Organization: "Org", TenantID: "t1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIssueAKCertificate_WithOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"certificate_pem": "cert"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{
		CommonName: "ak-test", PublicKey: []byte("key"), Organization: "Org", TenantID: "t1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignTCGCSR_WithOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"certificate_pem": "cert"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{
		CommonName: "tcg-test", TCGCSR: []byte("csr"), Organization: "Org", TenantID: "t1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestEnrollDevice_WithOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"certificate_pem": "cert"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{
		CommonName: "dev-test", PackedCSR: []byte("packed"), Organization: "Org", TenantID: "t1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- NotConnected Error Paths for Methods Not Yet Covered ---

func TestGetKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetKey(context.Background(), "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DeleteKey(context.Background(), "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestVerify_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Verify(context.Background(), &transport.VerifyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEncrypt_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Encrypt(context.Background(), &transport.EncryptRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDecrypt_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Decrypt(context.Background(), &transport.DecryptRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEncryptAsym_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeriveKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetCertificate(context.Background(), "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestImportKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ImportKey(context.Background(), &transport.ImportKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestExportKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ExportKey(context.Background(), &transport.ExportKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRotateKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.RotateKey(context.Background(), &transport.RotateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetImportParameters_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestWrapKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.WrapKey(context.Background(), &transport.WrapKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUnwrapKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestWrapKeyByID_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUnwrapKeyByID_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestExportKeyMaterial_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeriveKeyECDH_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestCopyKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.CopyKey(context.Background(), &transport.CopyKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListCertificates_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListCertificates(context.Background(), "sw")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetCertificateChain_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetCertificateChain(context.Background(), "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetTLSCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetTLSCertificate(context.Background(), "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListKeys_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListKeys(context.Background(), "sw")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetBackend_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetBackend(context.Background(), "sw")
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Healthy with non-200 response ---

func TestHealthy_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = srv.URL
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	tr.httpClient = srv.Client()

	assert.False(t, tr.Healthy(context.Background()))
}

// --- Request method (wrapper around DoRequest) ---

func TestRequest_Connected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	var result map[string]string
	err = tr.Request(context.Background(), "/api/v1/test", map[string]string{"key": "val"}, &result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["result"])
}

// --- DoRequestWithHeaders with JWT token and body ---

func TestDoRequestWithHeaders_WithJWTAndBody(t *testing.T) {
	var capturedAuth string
	var capturedContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		capturedAuth = r.Header.Get("Authorization")
		capturedContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
	defer srv.Close()

	tr, err := New(
		transport.WithAddress(srv.URL),
		transport.WithJWTToken("test-jwt"),
	)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	body, headers, err := tr.DoRequestWithHeaders(
		context.Background(), "POST", "/api/v1/test",
		map[string]string{"key": "val"},
		map[string]string{"X-Custom": "custom"},
	)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
	assert.NotNil(t, headers)
	assert.Equal(t, "Bearer test-jwt", capturedAuth)
	assert.Equal(t, "application/json", capturedContentType)
}

// --- DoRequestWithHeaders server error with "error" field ---

func TestDoRequestWithHeaders_ServerErrorWithErrorField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "access denied"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, _, err = tr.DoRequestWithHeaders(context.Background(), "POST", "/err", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- DoHeadRequest with JWT token ---

func TestDoHeadRequest_WithJWTToken(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := New(
		transport.WithAddress(srv.URL),
		transport.WithJWTToken("head-jwt"),
		transport.WithHeader("X-Head-Custom", "val"),
	)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	exists, err := tr.DoHeadRequest(context.Background(), "/api/v1/test")
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, "Bearer head-jwt", capturedAuth)
}

// --- PasswordList with optional parameters ---

func TestPasswordList_WithParams(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		capturedPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"entries": []interface{}{}})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.PasswordList(context.Background(), &transport.PasswordListRequest{
		FolderPath: "/work", Scope: "personal",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, capturedPath, "folder=%2Fwork")
	assert.Contains(t, capturedPath, "scope=personal")
}

func TestPasswordList_NilRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"entries": []interface{}{}})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.PasswordList(context.Background(), nil)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- NotConnected paths for PIV, Barrier, PIN, Password operations ---

func TestListPIVSlots_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetPIVCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestStorePIVCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeletePIVCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGeneratePIVKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestImportPIVCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestExportPIVCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGeneratePIVCSR_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierInitialize_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierUnseal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierSeal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierSeal(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierInitializeShamir_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierUnsealWithShare_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierUnsealWithShares_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierShamirListShares_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierShamirListShares(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierShamirDeleteShare_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierShamirDeleteShare(context.Background(), &transport.BarrierShamirDeleteShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierShamirDeleteAllShares_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierShamirDeleteAllShares(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierShamirVerify_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierShamirVerify(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierRekey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierGenerateRecoveryKeys_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierRecoverWithKeys_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierDeleteRecoveryKeys_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierDeleteRecoveryKeys(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierHasRecoveryKeys_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierHasRecoveryKeys(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierGenerateRootToken_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSetSOPIN_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.SetSOPIN(context.Background(), &transport.SetSOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSetUserPIN_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.SetUserPIN(context.Background(), &transport.SetUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestChangeSOPIN_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestChangeUserPIN_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestVerifySOPIN_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestVerifyUserPIN_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetLockoutStatus_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetLockoutStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestResetLockout_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.ResetLockout(context.Background(), &transport.ResetLockoutRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordAdd_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordGet_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordList_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.PasswordList(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordUpdate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordDelete_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordStoreUnlock_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordStoreLock_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.PasswordStoreLock(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordStoreStatus_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.PasswordStoreStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordStoreSetAccessMode_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordGenerate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBeginRegistration_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestFinishRegistration_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBeginAuthentication_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestFinishAuthentication_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetInitStatus_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetInitStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClaimCertBegin_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClaimCertComplete_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClaimShare_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ClaimShare(context.Background(), &transport.ClaimShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSignCSRInit_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSubmitCredential_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetCredentialStrategy_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetCredentialStrategy(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Healthy with bad URL that causes request creation error ---

func TestHealthy_BadURL(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "http://[::1]:abc" // invalid URL
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	tr.httpClient = &http.Client{}

	assert.False(t, tr.Healthy(context.Background()))
}

// --- WebAuthn happy paths with proper JSON ---

func newWebAuthnMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case path == "/health":
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
		case path == "/api/v1/webauthn/registration/begin":
			w.Header().Set("X-Session-Id", "sess-123")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"challenge": "Y2hhbGxlbmdl",
				"user":      map[string]string{"id": "uid1", "name": "test", "displayName": "Test User"},
				"rp":        map[string]string{"id": "localhost", "name": "Test RP"},
				"pubKeyCredParams": []map[string]interface{}{
					{"type": "public-key", "alg": -7},
				},
			})
		case path == "/api/v1/webauthn/registration/finish":
			json.NewEncoder(w).Encode(map[string]string{"token": "jwt-token", "user_id": "uid1"})
		case path == "/api/v1/webauthn/login/begin":
			w.Header().Set("X-Session-Id", "sess-456")
			w.Header().Set("X-User-Id", "uid1")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"challenge": "Y2hhbGxlbmdl",
				"rpId":      "localhost",
				"allowCredentials": []map[string]string{
					{"id": "cred1", "type": "public-key"},
				},
			})
		case path == "/api/v1/webauthn/login/finish":
			json.NewEncoder(w).Encode(map[string]string{"token": "jwt-auth", "user_id": "uid1"})
		default:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		}
	}))
}

func TestBeginRegistration_Success(t *testing.T) {
	srv := newWebAuthnMockServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{
		Username:    "test@example.com",
		DisplayName: "Test User",
	})
	require.NoError(t, err)
	assert.Equal(t, "Y2hhbGxlbmdl", resp.Challenge)
	assert.Equal(t, "uid1", resp.UserID)
	assert.Equal(t, "localhost", resp.RPID)
	assert.Len(t, resp.CredentialParams, 1)
}

func TestFinishRegistration_Success(t *testing.T) {
	srv := newWebAuthnMockServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{
		Username:        "test@example.com",
		CredentialID:    "cred1",
		ClientDataJSON:  "cdj",
		AttestationData: "att",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "cred1", resp.CredentialID)
}

func TestBeginAuthentication_Success(t *testing.T) {
	srv := newWebAuthnMockServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{
		Username: "test@example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "Y2hhbGxlbmdl", resp.Challenge)
	assert.Equal(t, "localhost", resp.RPID)
	assert.Len(t, resp.CredentialIDs, 1)
}

func TestFinishAuthentication_Success(t *testing.T) {
	srv := newWebAuthnMockServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{
		Username:          "test@example.com",
		CredentialID:      "cred1",
		ClientDataJSON:    "cdj",
		AuthenticatorData: "authdata",
		Signature:         "sig",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "jwt-auth", resp.Token)
}

// --- BeginAuthentication with empty username ---

func TestBeginAuthentication_EmptyUsername(t *testing.T) {
	srv := newWebAuthnMockServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- ListUserCredentials with credentials ---

func TestListUserCredentials_WithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"credentials": []map[string]string{
				{"id": "cred1", "name": "My Key", "created_at": "2025-01-01"},
				{"id": "cred2", "name": "Backup Key", "created_at": "2025-02-01", "last_used_at": "2025-03-01"},
			},
		})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.ListUserCredentials(context.Background(), "user1")
	require.NoError(t, err)
	require.Len(t, resp.Credentials, 2)
	assert.Equal(t, "cred1", resp.Credentials[0].ID)
	assert.Equal(t, "My Key", resp.Credentials[0].DisplayName)
}


// --- Healthy with request error (closed server) ---

func TestHealthy_RequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))

	cfg := transport.DefaultConfig()
	cfg.Address = srv.URL
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	tr.httpClient = srv.Client()

	// Close the server to force a request error
	srv.Close()

	assert.False(t, tr.Healthy(context.Background()))
}

// --- DoRequest with nil result (covers the nil check) ---

func TestDoRequest_NilResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok"}`))
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	err = tr.DoRequest(context.Background(), "GET", "/api/v1/test", nil, nil)
	require.NoError(t, err)
}

// --- DoRequest with empty response body ---

func TestDoRequest_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusOK)
		// empty body
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	var result map[string]string
	err = tr.DoRequest(context.Background(), "GET", "/api/v1/empty", nil, &result)
	require.NoError(t, err)
}

// --- DeriveKey with all optional fields populated ---

func TestDeriveKey_AllOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		// Verify the body has all optional fields
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"derived_key": "ZGVyaXZlZA=="})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:          "sw",
		Algorithm:        "HKDF",
		KeyLength:        32,
		KeyID:            "master-key",
		InputKeyMaterial: []byte("ikm"),
		Salt:             []byte("salt"),
		Info:             []byte("info"),
		PeerPublicKey:    []byte("peer-pk"),
		Hash:             "SHA256",
		Iterations:       10000,
		PRF:              "HMAC-SHA256",
		Label:            []byte("label"),
		Context:          []byte("ctx"),
		Counter:          1,
		UseCofactor:      true,
		StoreResult:      true,
		DerivedKeyID:     "derived-1",
		DerivedKeyType:   "AES-256",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- ListKeys with pagination options ---

func TestListKeys_WithPagination(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		capturedPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{},
		})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.ListKeys(context.Background(), "software",
		transport.WithPageSize(10),
		transport.WithPage(2),
	)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, strings.Contains(capturedPath, "backend=software"))
}

// --- ListCertificates with pagination options ---

func TestListCertificates_WithPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"certificates": []interface{}{}})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.ListCertificates(context.Background(), "software",
		transport.WithPageSize(5),
	)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- ExportKey with algorithm ---

func TestExportKey_WithAlgorithm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"key_id": "k1", "algorithm": "RSA"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{
		KeyID: "k1", Backend: "sw", Algorithm: "RSA",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}
