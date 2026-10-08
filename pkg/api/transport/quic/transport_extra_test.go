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

	wire "github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullMockHandler extends the mock handler to cover ALL REST endpoints.
func fullMockHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		respond := func(data interface{}) {
			json.NewEncoder(w).Encode(data)
		}

		switch {
		// TCG CA
		case strings.Contains(path, "/ca/tcg/ek"):
			respond(transport.IssueEKCertificateResponse{CertificatePEM: []byte("ek-cert"), SerialNumber: "EK1234"})
		case strings.Contains(path, "/ca/tcg/ak"):
			respond(transport.IssueAKCertificateResponse{CertificatePEM: []byte("ak-cert"), SerialNumber: "AK1234"})
		case strings.Contains(path, "/ca/tcg/sign-csr"):
			respond(transport.SignTCGCSRResponse{IAKCertDER: []byte("iak"), IDevIDCertDER: []byte("idevid")})
		case strings.Contains(path, "/ca/tcg/enroll"):
			respond(transport.EnrollDeviceResponse{IAKCertDER: []byte("iak"), IDevIDCertDER: []byte("idevid")})

		// PIV
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/generate"):
			respond(transport.GeneratePIVKeyResponse{PublicKey: []byte("pubkey"), Slot: "9a"})
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/import"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/export"):
			respond(transport.GetPIVCertificateResponse{Certificate: []byte("cert"), Slot: "9a"})
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/csr"):
			respond(transport.GeneratePIVCSRResponse{CSR: []byte("csr"), Slot: "9a"})
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/certificate"):
			switch r.Method {
			case http.MethodDelete:
				w.WriteHeader(http.StatusOK)
			case http.MethodPost:
				w.WriteHeader(http.StatusOK)
			default:
				respond(transport.GetPIVCertificateResponse{Certificate: []byte("cert"), Slot: "9a"})
			}
		case strings.Contains(path, "/piv/slots"):
			respond(transport.ListPIVSlotsResponse{
				Slots: []transport.PIVSlotStatus{{Slot: "9a", Name: "Authentication", HasCert: true}},
			})

		// Barrier ops

		// PIN management
		case strings.Contains(path, "/pin/so") && strings.Contains(path, "set"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/so") && strings.Contains(path, "change"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/so") && strings.Contains(path, "verify"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/user") && strings.Contains(path, "set"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/user") && strings.Contains(path, "change"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/user") && strings.Contains(path, "verify"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/lockout") && r.Method == http.MethodGet:
			respond(transport.LockoutStatusResponse{IsLocked: false})
		case strings.Contains(path, "/pin/lockout") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)

		// Custodian groups

		// Shares

		// Tenants

		case strings.Contains(path, "/tenants") && r.Method == http.MethodPost:
			respond(map[string]interface{}{"id": "t1", "name": "test-tenant"})
		case strings.Contains(path, "/tenants") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case path == "/api/v1/tenants":
			respond(transport.ListTenantsResponse{
				Tenants: []transport.TenantInfo{{ID: "t1", Name: "test-tenant"}},
			})
		case strings.HasPrefix(path, "/api/v1/tenants/"):
			respond(map[string]interface{}{"id": "t1", "name": "test-tenant"})

		// Init / Credentials

		case strings.Contains(path, "/credentials/strategy"):
			respond(transport.CredentialStrategyResponse{Strategy: "manual"})
		case strings.Contains(path, "/credentials/submit"):
			respond(map[string]bool{"accepted": true})

		// Passwords
		case strings.Contains(path, "/passwords/generate"):
			respond(transport.PasswordGenerateResponse{Password: "gen-pw"})
		case strings.Contains(path, "/password-vault/session"):
			respond(transport.PasswordStoreStatusResponse{AccessMode: "private", PasswordCount: 5})
		case strings.Contains(path, "/password-vault/unlock"), strings.Contains(path, "/password-vault/lock"):
			w.WriteHeader(http.StatusOK)
		case path == "/api/v1/passwords" && r.Method == http.MethodGet:
			respond(transport.PasswordListResponse{
				Passwords: []transport.PasswordGetResponse{{ID: "pw-1", Name: "test"}},
			})
		case strings.HasPrefix(path, "/api/v1/passwords") && r.Method == http.MethodPost:
			respond(transport.PasswordAddResponse{ID: "pw-1", Name: "test"})
		case strings.HasPrefix(path, "/api/v1/passwords") && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(path, "/api/v1/passwords") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(path, "/api/v1/passwords"):
			respond(transport.PasswordGetResponse{ID: "pw-1", Name: "test"})

		// CA
		case strings.Contains(path, "/ca/bundle"):
			respond(transport.GetCABundleResponse{BundlePEM: []byte("bundle")})
		case strings.Contains(path, "/ca/certificate"):
			respond(transport.GetCACertificateResponse{CertificatePEM: []byte("ca-cert")})
		case strings.Contains(path, "/ca/sign-csr"):
			respond(transport.SignCSRResponse{CertificatePEM: []byte("signed")})
		case strings.Contains(path, "/ca/issue"):
			respond(transport.IssueCertificateResponse{CertificatePEM: []byte("issued"), SerialNumber: "1234"})
		case strings.Contains(path, "/ca/revoke"):
			respond(transport.RevokeCertificateResponse{Success: true})
		case strings.Contains(path, "/ca/crl"):
			respond(transport.GenerateCRLResponse{CRLPEM: []byte("crl")})
		case strings.Contains(path, "/ca/is-revoked"):
			respond(transport.IsRevokedResponse{Revoked: false})

		// Keys
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
			respond(wire.WrapKeyResponse{WrappedKey: []byte("wrapped"), Algorithm: "AES"})
		case strings.Contains(path, "/keys/unwrap"):
			respond(transport.UnwrapKeyResponse{KeyMaterial: []byte("unwrapped")})
		case strings.Contains(path, "/keys/import-params"):
			respond(wire.GetImportParametersResponse{WrappingPublicKeyPEM: testWrappingPublicKeyPEM(), ImportToken: []byte("tok"), Algorithm: "RSA-OAEP"})
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
				KeyInfo:      transport.KeyInfo{KeyID: "key-1", KeyType: "ECDSA", Algorithm: "P-256", Backend: "software"},
				PublicKeyPEM: "pem",
			})

		// Certs
		case strings.HasPrefix(path, "/api/v1/certs") && strings.HasSuffix(path, "/chain"):
			if r.Method == http.MethodPost {
				respond(map[string]bool{"success": true})
			} else {
				respond(transport.GetCertificateChainResponse{ChainPEM: []string{"cert-pem"}})
			}
		case strings.HasPrefix(path, "/api/v1/tls/"):
			respond(transport.GetTLSCertificateResponse{CertificatePEM: "cert", ChainPEM: []string{"chain"}})
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
		case strings.HasPrefix(path, "/api/v1/seal"):
			respond(transport.SealResponse{Ciphertext: []byte("sealed")})
		case strings.HasPrefix(path, "/api/v1/unseal"):
			respond(transport.UnsealResponse{Plaintext: []byte("unsealed")})
		case strings.Contains(path, "/seal/capability"):
			respond(transport.CanSealResponse{CanSeal: true})

		default:
			respond(map[string]bool{"success": true})
		}
	})
}

// newFullMockTransport creates a QUIC transport backed by a comprehensive mock server.
func newFullMockTransport(t *testing.T) (*Transport, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(fullMockHandler())
	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}
	return tr, srv.Close
}

// --- TCG CA tests ---

func TestIssueEKCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{CommonName: "test", Organization: "org", EKPublicKey: []byte("ek")})
	require.NoError(t, err)
	assert.Equal(t, "EK1234", resp.SerialNumber)
}

func TestIssueAKCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{CommonName: "test", Organization: "org", PublicKey: []byte("ak")})
	require.NoError(t, err)
	assert.Equal(t, "AK1234", resp.SerialNumber)
}

func TestSignTCGCSR_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{CommonName: "test", Organization: "org", TCGCSR: []byte("csr")})
	require.NoError(t, err)
	assert.NotNil(t, resp.IAKCertDER)
}

func TestEnrollDevice_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{CommonName: "test", Organization: "org", PackedCSR: []byte("csr")})
	require.NoError(t, err)
	assert.NotNil(t, resp.IAKCertDER)
}

// --- PIV tests ---

func TestListPIVSlots_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{Backend: "software"})
	require.NoError(t, err)
	require.Len(t, resp.Slots, 1)
}

func TestGetPIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
	assert.Equal(t, "9a", resp.Slot)
}

func TestStorePIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
}

func TestDeletePIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
}

func TestGeneratePIVKey_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
	assert.Equal(t, "9a", resp.Slot)
}

func TestImportPIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
}

func TestExportPIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
	assert.Equal(t, "9a", resp.Slot)
}

// --- Barrier Shamir tests ---

// --- PIN management tests ---

func TestSetSOPIN_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.SetSOPIN(context.Background(), &transport.SetSOPINRequest{})
	require.NoError(t, err)
}

func TestSetUserPIN_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.SetUserPIN(context.Background(), &transport.SetUserPINRequest{})
	require.NoError(t, err)
}

func TestChangeSOPIN_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{})
	require.NoError(t, err)
}

func TestChangeUserPIN_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{})
	require.NoError(t, err)
}

func TestVerifySOPIN_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{})
	require.NoError(t, err)
}

func TestVerifyUserPIN_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{})
	require.NoError(t, err)
}

func TestGetLockoutStatus_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetLockoutStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, resp.IsLocked)
}

func TestResetLockout_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.ResetLockout(context.Background(), &transport.ResetLockoutRequest{})
	require.NoError(t, err)
}

// --- Custodian Group tests ---

// --- Share tests ---

// --- Tenant tests ---

func TestCreateTenant_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{Name: "test"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetTenant_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetTenant(context.Background(), "t1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestListTenants_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.ListTenants(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Tenants, 1)
}

func TestDeleteTenant_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.DeleteTenant(context.Background(), "t1")
	require.NoError(t, err)
}

// --- Init / Credential tests ---

func TestSubmitCredential_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCredentialStrategy_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetCredentialStrategy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "manual", resp.Strategy)
}

// --- CA connected tests ---

func TestGetCABundle_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp.BundlePEM)
}

func TestGetCACertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignCSR_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{CSRPEM: []byte("csr")})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIssueCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{CommonName: "test"})
	require.NoError(t, err)
	assert.Equal(t, "1234", resp.SerialNumber)
}

func TestRevokeCertificate_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{SerialNumber: "1234"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestGenerateCRL_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp.CRLPEM)
}

func TestIsRevoked_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{SerialNumber: "1234"})
	require.NoError(t, err)
	assert.False(t, resp.Revoked)
}

// --- Password connected tests ---

func TestPasswordStoreUnlock_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)
}

func TestPasswordStoreLock_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.PasswordStoreLock(context.Background())
	require.NoError(t, err)
}
