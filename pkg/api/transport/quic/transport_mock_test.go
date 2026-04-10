// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package quic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHandler returns a router that responds with JSON for all QUIC transport endpoints.
func mockHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		respond := func(data interface{}) {
			json.NewEncoder(w).Encode(data)
		}

		switch {
		case path == "/health":
			respond(map[string]string{"status": "healthy", "version": "1.0.0"})
		case path == "/api/v1/backends" && r.Method == http.MethodGet:
			respond(transport.ListBackendsResponse{
				Backends: []transport.BackendInfo{{ID: "software", Type: "software"}},
			})
		case strings.HasPrefix(path, "/api/v1/backends/"):
			respond(transport.BackendInfo{ID: "software", Type: "software"})
		case path == "/api/v1/keys" && r.Method == http.MethodPost:
			respond(transport.GenerateKeyResponse{KeyID: "key-1", KeyType: "ECDSA", PublicKeyPEM: "pem"})
		case path == "/api/v1/keys" && r.Method == http.MethodGet:
			respond(transport.ListKeysResponse{
				Keys: []transport.KeyInfo{{KeyID: "key-1", KeyType: "ECDSA", Algorithm: "P-256", Backend: "software"}},
			})
		case strings.Contains(path, "/keys/wrap-by-id"):
			respond(map[string]interface{}{"wrapped_key": "d3JhcHBlZA==", "algorithm": "AES"})
		case strings.Contains(path, "/keys/unwrap-by-id"):
			respond(map[string]interface{}{"success": true, "key_id": "key-1"})
		case strings.Contains(path, "/keys/wrap"):
			respond(transport.WrapKeyResponse{WrappedKeyMaterial: []byte("wrapped"), Algorithm: "AES"})
		case strings.Contains(path, "/keys/unwrap"):
			respond(transport.UnwrapKeyResponse{KeyMaterial: []byte("unwrapped")})
		case strings.Contains(path, "/keys/import-params"):
			respond(transport.GetImportParametersResponse{
				WrappingPublicKey: []byte("wpk"), ImportToken: []byte("tok"), Algorithm: "RSA-OAEP",
			})
		case strings.Contains(path, "/keys/import"):
			respond(transport.ImportKeyResponse{Success: true, KeyID: "key-1"})
		case strings.HasSuffix(path, "/export-material"):
			respond(transport.ExportKeyMaterialResponse{KeyMaterial: []byte("raw"), KeyType: "aes256"})
		case strings.HasSuffix(path, "/export"):
			respond(transport.ExportKeyResponse{KeyID: "key-1", WrappedKeyMaterial: []byte("wrapped")})
		case strings.Contains(path, "/keys/copy"):
			respond(transport.CopyKeyResponse{Success: true, KeyID: "dest-key"})
		case strings.Contains(path, "/keys/derive-ecdh"):
			respond(transport.DeriveKeyECDHResponse{DerivedKey: []byte("ecdh-key")})
		case strings.Contains(path, "/keys/derive"):
			respond(transport.DeriveKeyResponse{DerivedKey: []byte("derived"), Algorithm: "HKDF", KeyLength: 32})
		case strings.HasSuffix(path, "/sign"):
			respond(transport.SignResponse{Signature: []byte("sig")})
		case strings.HasSuffix(path, "/verify"):
			respond(transport.VerifyResponse{Valid: true, Message: "valid"})
		case strings.HasSuffix(path, "/encrypt-asym"):
			respond(transport.EncryptAsymResponse{Ciphertext: []byte("asym")})
		case strings.HasSuffix(path, "/encrypt"):
			respond(transport.EncryptResponse{Ciphertext: []byte("ct"), Nonce: []byte("n"), Tag: []byte("t")})
		case strings.HasSuffix(path, "/decrypt"):
			respond(transport.DecryptResponse{Plaintext: []byte("pt")})
		case strings.HasSuffix(path, "/rotate"):
			respond(transport.RotateKeyResponse{Success: true, KeyID: "key-1"})
		case strings.HasSuffix(path, "/attest"):
			respond(transport.AttestKeyResponse{AttestationData: []byte("attest"), Format: "tpm2"})
		case strings.HasPrefix(path, "/api/v1/keys/") && r.Method == http.MethodDelete:
			respond(transport.DeleteKeyResponse{Success: true, Message: "deleted"})
		case strings.HasPrefix(path, "/api/v1/keys/"):
			respond(transport.GetKeyResponse{
				KeyInfo: transport.KeyInfo{KeyID: "key-1", KeyType: "ECDSA", Algorithm: "P-256", Backend: "software"},
				PublicKeyPEM: "pem",
			})
		case strings.HasPrefix(path, "/api/v1/certs") && strings.HasSuffix(path, "/chain"):
			if r.Method == http.MethodPost {
				respond(map[string]bool{"success": true})
			} else {
				respond(transport.GetCertificateChainResponse{ChainPEM: []string{"cert-pem"}})
			}
		case strings.HasPrefix(path, "/api/v1/tls/"):
			respond(transport.GetTLSCertificateResponse{CertificatePEM: "cert", PrivateKeyPEM: "key", ChainPEM: "chain"})
		case strings.HasPrefix(path, "/api/v1/certs") && strings.HasSuffix(path, "/exists"):
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(path, "/api/v1/certs") && r.Method == http.MethodGet && !strings.HasSuffix(path, "/certs"):
			respond(transport.GetCertificateResponse{KeyID: "key-1", CertificatePEM: "cert-pem"})
		case path == "/api/v1/certs" && r.Method == http.MethodPost:
			respond(map[string]bool{"success": true})
		case path == "/api/v1/certs":
			respond(transport.ListCertificatesResponse{
				Certificates: []transport.CertificateInfo{{KeyID: "key-1", Subject: "CN=test"}},
			})
		case path == "/api/v1/seal":
			respond(transport.SealResponse{Ciphertext: []byte("sealed")})
		case path == "/api/v1/unseal":
			respond(transport.UnsealResponse{Plaintext: []byte("unsealed")})
		case strings.Contains(path, "/seal/capability"):
			respond(transport.CanSealResponse{CanSeal: true})
		case strings.Contains(path, "/barrier/status"):
			respond(transport.BarrierStatusResponse{Sealed: false, InitializedAt: "2024-01-01"})
		case strings.Contains(path, "/barrier/initialize-shamir"):
			respond(transport.BarrierInitializeShamirResponse{Shares: []string{"s1", "s2"}, Threshold: 2, TotalShares: 3})
		case strings.Contains(path, "/barrier/rekey"):
			respond(transport.BarrierRekeyResponse{Shares: []string{"s1"}, Threshold: 2})
		case strings.Contains(path, "/barrier"):
			w.WriteHeader(http.StatusOK)
			respond(map[string]bool{"success": true})
		case strings.Contains(path, "/ca/bundle"):
			respond(transport.GetCABundleResponse{BundlePEM: []byte("bundle")})
		case strings.Contains(path, "/ca/certificate"):
			respond(transport.GetCACertificateResponse{CertificatePEM: []byte("ca-cert")})
		case strings.Contains(path, "/ca/sign-csr"):
			respond(transport.SignCSRResponse{CertificatePEM: []byte("signed")})
		case strings.Contains(path, "/ca/issue"):
			respond(transport.IssueCertificateResponse{CertificatePEM: []byte("issued")})
		case strings.Contains(path, "/ca/revoke"):
			respond(transport.RevokeCertificateResponse{Success: true})
		case strings.Contains(path, "/ca/crl"):
			respond(transport.GenerateCRLResponse{CRLPEM: []byte("crl")})
		case strings.Contains(path, "/ca/is-revoked"):
			respond(transport.IsRevokedResponse{Revoked: false})
		case strings.Contains(path, "/passwords/generate"):
			respond(transport.PasswordGenerateResponse{Password: "gen-pw"})
		case strings.Contains(path, "/passwords/status"):
			respond(transport.PasswordStoreStatusResponse{AccessMode: "private", PasswordCount: 5})
		case strings.Contains(path, "/passwords/unlock"), strings.Contains(path, "/passwords/lock"):
			w.WriteHeader(http.StatusOK)
		case path == "/api/v1/passwords" && r.Method == http.MethodGet:
			respond(transport.PasswordListResponse{
				Passwords: []transport.PasswordGetResponse{{ID: "pw-1", Name: "test"}},
			})
		case strings.HasPrefix(path, "/api/v1/passwords") && r.Method == http.MethodPost:
			respond(transport.PasswordAddResponse{ID: "pw-1", Name: "test"})
		case strings.HasPrefix(path, "/api/v1/passwords"):
			respond(transport.PasswordGetResponse{ID: "pw-1", Name: "test"})
		default:
			respond(map[string]bool{"success": true})
		}
	})
}

// newMockTransport creates a QUIC transport backed by a mock HTTPS server.
func newMockTransport(t *testing.T) (*Transport, func()) {
	t.Helper()

	srv := httptest.NewTLSServer(mockHandler())

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	return tr, srv.Close
}

// --- Connected tests ---

func TestHealth_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
}

func TestListBackends_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.ListBackends(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Backends, 1)
}

func TestGetBackend_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.GetBackend(context.Background(), "software")
	require.NoError(t, err)
	assert.Equal(t, "software", resp.ID)
}

func TestGenerateKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID: "key-1", Backend: "software", KeyType: "ECDSA",
	})
	require.NoError(t, err)
	assert.Equal(t, "key-1", resp.KeyID)
}

func TestListKeys_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.ListKeys(context.Background(), "software")
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
}

func TestGetKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.GetKey(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.Equal(t, "key-1", resp.KeyInfo.KeyID)
}

func TestDeleteKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.DeleteKey(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestSign_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		KeyID: "key-1", Backend: "software", Data: []byte("data"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Signature)
}

func TestVerify_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.Verify(context.Background(), &transport.VerifyRequest{
		KeyID: "key-1", Backend: "software", Data: []byte("data"), Signature: []byte("sig"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestEncrypt_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{
		KeyID: "key-1", Backend: "software", Plaintext: []byte("pt"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestDecrypt_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{
		KeyID: "key-1", Backend: "software", Ciphertext: []byte("ct"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Plaintext)
}

func TestSeal_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.Seal(context.Background(), &transport.SealRequest{Backend: "software", Data: []byte("secret")})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestUnseal_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.Unseal(context.Background(), &transport.UnsealRequest{Backend: "software", Ciphertext: []byte("sealed")})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Plaintext)
}

func TestCanSeal_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	resp, err := tr.CanSeal(context.Background(), "software")
	require.NoError(t, err)
	assert.True(t, resp.CanSeal)
}

// --- Helper method tests ---

func TestDoRequest_Connected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	var result map[string]interface{}
	err := tr.DoRequest(context.Background(), http.MethodGet, "/health", nil, &result)
	require.NoError(t, err)
	assert.Equal(t, "healthy", result["status"])
}

func TestDoRawRequest_Connected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	data, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/health", nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "healthy")
}

func TestDoRawRequest_WithBody(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	body := map[string]string{"test": "value"}
	data, err := tr.DoRawRequest(context.Background(), http.MethodPost, "/api/v1/keys", body)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestDoRawRequest_WithJWTToken(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	tr.config.JWTToken = "test-token"

	data, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/health", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestDoRawRequest_WithCustomHeaders(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	tr.config.Headers = map[string]string{"X-Custom": "test"}

	data, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/health", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestDoHeadRequest_Connected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	exists, err := tr.DoHeadRequest(context.Background(), "/health")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestDoRawRequest_ServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "test error"})
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
	assert.Contains(t, err.Error(), "test error")
}

func TestDoRawRequest_ServerErrorMessage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "bad request"})
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
	assert.Contains(t, err.Error(), "bad request")
}

func TestDoRawRequest_ServerErrorPlainText(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
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
	assert.Contains(t, err.Error(), "403")
}

func TestRequest_Connected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	var resp map[string]interface{}
	err := tr.Request(context.Background(), "/health", nil, &resp)
	require.NoError(t, err)
}

func TestRequestStream_NotSupported_Mock(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	_, err := tr.RequestStream(context.Background(), "/test", nil)
	assert.ErrorIs(t, err, transport.ErrStreamNotSupported)
}

func TestHealthy_Connected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	assert.True(t, tr.Healthy(context.Background()))
}

func TestHealthy_Disconnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	assert.False(t, tr.Healthy(context.Background()))
}

func TestConn_Connected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.NotNil(t, tr.Conn())
}

func TestHTTPClient_Connected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.NotNil(t, tr.HTTPClient())
}

func TestBaseURL_Mock(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.NotEmpty(t, tr.BaseURL())
}

func TestIsConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	assert.True(t, tr.IsConnected())
}

func TestClose_MockConnected(t *testing.T) {
	tr := &Transport{
		config:    transport.DefaultConfig(),
		connected: true,
	}
	require.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}

// --- ErrNotSupported stub methods ---

func TestErrNotSupported_StubMethods(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"ListUsers", func() error { _, err := tr.ListUsers(context.Background()); return err }},
		{"GetUser", func() error { _, err := tr.GetUser(context.Background(), "u"); return err }},
		{"DeleteUser", func() error { return tr.DeleteUser(context.Background(), "u") }},
		{"EnableUser", func() error { return tr.EnableUser(context.Background(), "u") }},
		{"DisableUser", func() error { return tr.DisableUser(context.Background(), "u") }},
		{"ListUserCredentials", func() error { _, err := tr.ListUserCredentials(context.Background(), "u"); return err }},
		{"BeginRegistration", func() error { _, err := tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{}); return err }},
		{"FinishRegistration", func() error { _, err := tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{}); return err }},
		{"BeginAuthentication", func() error { _, err := tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{}); return err }},
		{"FinishAuthentication", func() error { _, err := tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{}); return err }},
		{"SealStorePut", func() error { return tr.SealStorePut(context.Background(), &transport.SealStorePutRequest{}) }},
		{"SealStoreGet", func() error { _, err := tr.SealStoreGet(context.Background(), &transport.SealStoreGetRequest{}); return err }},
		{"SealStoreDelete", func() error { return tr.SealStoreDelete(context.Background(), &transport.SealStoreDeleteRequest{}) }},
		{"SealStoreList", func() error { _, err := tr.SealStoreList(context.Background()); return err }},
		{"SealStoreReseal", func() error { return tr.SealStoreReseal(context.Background(), &transport.SealStoreResealRequest{}) }},
		{"SealStoreStatus", func() error { _, err := tr.SealStoreStatus(context.Background()); return err }},
		{"PolicyCreate", func() error { _, err := tr.PolicyCreate(context.Background(), &transport.PolicyCreateRequest{}); return err }},
		{"PolicyGet", func() error { _, err := tr.PolicyGet(context.Background(), &transport.PolicyGetRequest{}); return err }},
		{"PolicyList", func() error { _, err := tr.PolicyList(context.Background()); return err }},
		{"PolicyDelete", func() error { return tr.PolicyDelete(context.Background(), &transport.PolicyDeleteRequest{}) }},
		{"PolicyRefresh", func() error { _, err := tr.PolicyRefresh(context.Background(), &transport.PolicyRefreshRequest{}); return err }},
		{"PolicyVerify", func() error { _, err := tr.PolicyVerify(context.Background(), &transport.PolicyVerifyRequest{}); return err }},
		{"PolicyExport", func() error { _, err := tr.PolicyExport(context.Background(), &transport.PolicyExportRequest{}); return err }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, tc.fn(), ErrNotSupported)
		})
	}
}

func TestDoRequest_NilResult(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	err := tr.DoRequest(context.Background(), http.MethodGet, "/health", nil, nil)
	require.NoError(t, err)
}

func TestEncryptAsym_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		KeyID: "key-1", Backend: "software", Plaintext: []byte("pt"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestRotateKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.RotateKey(context.Background(), &transport.RotateKeyRequest{KeyID: "key-1", Backend: "software"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestImportKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{KeyID: "key-1", Backend: "software"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestExportKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{KeyID: "key-1", Backend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKeyMaterial)
}

func TestCopyKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "software", SourceKeyID: "key-1", DestBackend: "software", DestKeyID: "key-2",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestGetCertificate_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.GetCertificate(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestSaveCertificate_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	err := tr.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{KeyID: "key-1", CertificatePEM: "cert"})
	require.NoError(t, err)
}

func TestDeleteCertificate_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	err := tr.DeleteCertificate(context.Background(), "software", "key-1")
	require.NoError(t, err)
}

func TestCertificateExists_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	exists, err := tr.CertificateExists(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestListCertificates_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.ListCertificates(context.Background(), "software")
	require.NoError(t, err)
	require.Len(t, resp.Certificates, 1)
}

func TestGetCertificateChain_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.GetCertificateChain(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ChainPEM)
}

func TestGetTLSCertificate_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.GetTLSCertificate(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestSaveCertificateChain_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	err := tr.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend: "software", KeyID: "key-1", ChainPEM: []string{"cert"},
	})
	require.NoError(t, err)
}

func TestAttestKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{Backend: "software", KeyID: "key-1"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AttestationData)
}

func TestDeriveKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend: "software", KeyID: "key-1", Algorithm: "HKDF", KeyLength: 32,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.DerivedKey)
}

func TestDeriveKeyECDH_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		Backend: "software", KeyID: "key-1",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.DerivedKey)
}

func TestWrapKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{KeyMaterial: []byte("key"), Algorithm: "AES"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKeyMaterial)
}

func TestUnwrapKey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{WrappedKeyMaterial: []byte("wrapped")})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyMaterial)
}

func TestWrapKeyByID_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{WrappingKeyBackend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKey)
}

func TestUnwrapKeyByID_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{UnwrappingKeyBackend: "software"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestExportKeyMaterial_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{KeyID: "key-1", Backend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyMaterial)
}

func TestGetImportParameters_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{Backend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Algorithm)
}

func TestBarrierInitialize_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{}))
}

func TestBarrierUnseal_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{}))
}

func TestBarrierSeal_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierSeal(context.Background()))
}

func TestBarrierStatus_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierStatus(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.InitializedAt)
}

func TestBarrierInitializeShamir_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{Threshold: 2, TotalShares: 3})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Shares)
}

func TestBarrierRekey_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{Threshold: 2, Total: 3})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Shares)
}

func TestGetCABundle_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.BundlePEM)
}

func TestGetCACertificate_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestSignCSR_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{CSRPEM: []byte("csr")})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestIssueCertificate_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{CommonName: "test"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestRevokeCertificate_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{SerialNumber: "ABCD"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestGenerateCRL_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CRLPEM)
}

func TestIsRevoked_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{SerialNumber: "ABCD"})
	require.NoError(t, err)
	assert.False(t, resp.Revoked)
}

func TestPasswordAdd_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{Name: "pw", Username: "u", Password: "p"})
	require.NoError(t, err)
	assert.Equal(t, "pw-1", resp.ID)
}

func TestPasswordGenerate_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{Length: 16})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Password)
}

func TestPasswordStoreStatus_MockConnected(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.PasswordStoreStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "private", resp.AccessMode)
}
