// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// newErrTransport creates a QUIC transport backed by a server returning 500 errors.
func newErrTransport(t *testing.T) (*Transport, func()) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal failure"})
	}))

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	return tr, srv.Close
}

// --- Connect error tests ---

func TestConnect_BadCAFile(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = "/nonexistent/ca.pem"
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

func TestConnect_BadCACertContent(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a cert"), 0644))

	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = caFile
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestConnect_BadClientCert(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSCertFile = "/nonexistent/cert.pem"
	cfg.TLSKeyFile = "/nonexistent/key.pem"
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestConnect_SPKIPinNoCA(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.SPKIPin = "sha256/abc123"
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// Will fail at health check but exercises the SPKI pin branch
	err = tr.Connect(context.Background())
	require.Error(t, err)
}

func TestConnect_SPKIPinWithCA(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, testCAPEM(), 0644))

	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = caFile
	cfg.SPKIPin = "sha256/abc123"
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// Will fail at health check but exercises the SPKI+CA branch
	err = tr.Connect(context.Background())
	require.Error(t, err)
}

func TestConnect_HealthCheckFails(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectionFailed)
}

// --- Accessor tests ---

func TestConn_ReturnsHTTPClient(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.NotNil(t, tr.Conn())
}

func TestHTTPClient_ReturnsClient(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.NotNil(t, tr.HTTPClient())
}

func TestBaseURL_ReturnsURL(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.NotEmpty(t, tr.BaseURL())
}

func TestIsConnected_True(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.True(t, tr.IsConnected())
}

func TestIsConnected_False(t *testing.T) {
	tr := newDisconnected(t)
	assert.False(t, tr.IsConnected())
}

func TestConfig_ReturnsConfig(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.NotNil(t, tr.Config())
}

func TestHealthy_True(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.True(t, tr.Healthy(context.Background()))
}

func TestHealthy_NilHTTPClient(t *testing.T) {
	tr := newDisconnected(t)
	assert.False(t, tr.Healthy(context.Background()))
}

func TestHealthy_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	assert.False(t, tr.Healthy(context.Background()))
}

func TestClose_WithH3Transport(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	err := tr.Close()
	require.NoError(t, err)
	assert.False(t, tr.connected)
}

func TestClose_NilHTTPClient(t *testing.T) {
	tr := newDisconnected(t)
	err := tr.Close()
	require.NoError(t, err)
}

func TestRequest_Disconnected(t *testing.T) {
	tr := newDisconnected(t)
	err := tr.Request(context.Background(), "/test", nil, nil)
	require.ErrorIs(t, err, ErrNotConnected)
}

func TestRequestStream_Unsupported(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	_, err := tr.RequestStream(context.Background(), "/test", nil)
	require.ErrorIs(t, err, transport.ErrStreamNotSupported)
}

// --- Server error tests ---

func TestHealth_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Health(context.Background())
	require.Error(t, err)
}

func TestListBackends_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListBackends(context.Background())
	require.Error(t, err)
}

func TestGetBackend_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetBackend(context.Background(), "s")
	require.Error(t, err)
}

func TestGenerateKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{})
	require.Error(t, err)
}

func TestListKeys_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListKeys(context.Background(), "s")
	require.Error(t, err)
}

func TestGetKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetKey(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestDeleteKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.DeleteKey(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestSign_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Sign(context.Background(), &transport.SignRequest{})
	require.Error(t, err)
}

func TestVerify_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Verify(context.Background(), &transport.VerifyRequest{})
	require.Error(t, err)
}

func TestEncrypt_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{})
	require.Error(t, err)
}

func TestDecrypt_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{})
	require.Error(t, err)
}

func TestEncryptAsym_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{})
	require.Error(t, err)
}

func TestRotateKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.RotateKey(context.Background(), &transport.RotateKeyRequest{})
	require.Error(t, err)
}

func TestGetImportParameters_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{})
	require.Error(t, err)
}

func TestWrapKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{})
	require.Error(t, err)
}

func TestUnwrapKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{})
	require.Error(t, err)
}

func TestImportKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{})
	require.Error(t, err)
}

func TestExportKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{})
	require.Error(t, err)
}

func TestExportKeyMaterial_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{})
	require.Error(t, err)
}

func TestCopyKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{})
	require.Error(t, err)
}

func TestDeriveKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{})
	require.Error(t, err)
}

func TestDeriveKeyECDH_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{})
	require.Error(t, err)
}

func TestGetCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCertificate(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestSaveCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{})
	require.Error(t, err)
}

func TestDeleteCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.DeleteCertificate(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestListCertificates_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListCertificates(context.Background(), "s")
	require.Error(t, err)
}

func TestSaveCertificateChain_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{})
	require.Error(t, err)
}

func TestGetCertificateChain_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCertificateChain(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestGetTLSCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetTLSCertificate(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestSeal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Seal(context.Background(), &transport.SealRequest{})
	require.Error(t, err)
}

func TestUnseal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Unseal(context.Background(), &transport.UnsealRequest{})
	require.Error(t, err)
}

func TestCanSeal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.CanSeal(context.Background(), "s")
	require.Error(t, err)
}

func TestAttestKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{})
	require.Error(t, err)
}

func TestBarrierInitialize_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	require.Error(t, err)
}

func TestBarrierUnseal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	require.Error(t, err)
}

func TestBarrierSeal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.BarrierSeal(context.Background())
	require.Error(t, err)
}

func TestBarrierStatus_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.BarrierStatus(context.Background())
	require.Error(t, err)
}

func TestGetCABundle_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.Error(t, err)
}

func TestGetCACertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.Error(t, err)
}

func TestSignCSR_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{})
	require.Error(t, err)
}

func TestIssueCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{})
	require.Error(t, err)
}

func TestRevokeCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{})
	require.Error(t, err)
}

func TestGenerateCRL_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.Error(t, err)
}

func TestIsRevoked_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{})
	require.Error(t, err)
}

func TestPasswordAdd_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{})
	require.Error(t, err)
}

func TestPasswordGet_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{})
	require.Error(t, err)
}

func TestPasswordList_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.Error(t, err)
}

func TestPasswordUpdate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{})
	require.Error(t, err)
}

func TestPasswordDelete_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{})
	require.Error(t, err)
}

func TestPasswordStoreStatus_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordStoreStatus(context.Background())
	require.Error(t, err)
}

func TestPasswordGenerate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{})
	require.Error(t, err)
}

func TestDoHeadRequest_NotConnected(t *testing.T) {
	tr := newDisconnected(t)
	_, err := tr.DoHeadRequest(context.Background(), "/test")
	require.ErrorIs(t, err, ErrNotConnected)
}

func TestDoHeadRequest_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	exists, err := tr.DoHeadRequest(context.Background(), "/test")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestDoRawRequest_MarshalError(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	// channels are not JSON-marshalable
	_, err := tr.DoRawRequest(context.Background(), http.MethodPost, "/test", make(chan int))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal request body")
}

func TestDoRequest_UnmarshalError(t *testing.T) {
	// Server returns invalid JSON
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	var result map[string]string
	err := tr.DoRequest(context.Background(), http.MethodGet, "/test", nil, &result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- DoRawRequest error response formats ---

func TestDoRawRequest_ErrorWithMessage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "bad request detail"})
	}))
	defer srv.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	_, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/test", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad request detail")
}

func TestDoRawRequest_ErrorNonJSON(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("plain error text"))
	}))
	defer srv.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	_, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/test", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plain error text")
}

// testCAPEM generates a minimal self-signed CA cert for testing.
func testCAPEM() []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}
