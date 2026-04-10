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
		case strings.Contains(path, "/tcg-ca/issue-ek-cert"):
			respond(transport.IssueEKCertificateResponse{CertificatePEM: []byte("ek-cert"), SerialNumber: "EK1234"})
		case strings.Contains(path, "/tcg-ca/issue-ak-cert"):
			respond(transport.IssueAKCertificateResponse{CertificatePEM: []byte("ak-cert"), SerialNumber: "AK1234"})
		case strings.Contains(path, "/tcg-ca/sign-tcg-csr"):
			respond(transport.SignTCGCSRResponse{IAKCertDER: []byte("iak"), IDevIDCertDER: []byte("idevid")})
		case strings.Contains(path, "/tcg-ca/enroll-device"):
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
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
			} else if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
			} else {
				respond(transport.GetPIVCertificateResponse{Certificate: []byte("cert"), Slot: "9a"})
			}
		case strings.Contains(path, "/piv/slots"):
			respond(transport.ListPIVSlotsResponse{
				Slots: []transport.PIVSlotStatus{{Slot: "9a", Name: "Authentication", HasCert: true}},
			})

		// Barrier ops
		case strings.Contains(path, "/barrier/shamir/shares") && r.Method == http.MethodDelete && strings.Contains(path, "/"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/barrier/shamir/shares"):
			respond(transport.BarrierShamirSharesResponse{Count: 2, Threshold: 2, Total: 3})
		case strings.Contains(path, "/barrier/shamir/verify"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/barrier/initialize-shamir"):
			respond(transport.BarrierInitializeShamirResponse{Shares: []string{"s1", "s2"}, Threshold: 2, TotalShares: 3})
		case strings.Contains(path, "/barrier/unseal-share") && !strings.HasSuffix(path, "s"):
			respond(map[string]interface{}{"required": 2, "submitted": 1, "complete": false})
		case strings.Contains(path, "/barrier/unseal-shares"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/barrier/rekey"):
			respond(transport.BarrierRekeyResponse{Shares: []string{"s1"}, Threshold: 2})
		case strings.Contains(path, "/barrier/recovery-keys") && r.Method == http.MethodPost:
			respond(map[string]interface{}{"shares": []string{"r1"}, "threshold": 2})
		case strings.Contains(path, "/barrier/recovery-keys") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/barrier/recovery-keys") && r.Method == http.MethodGet:
			respond(map[string]bool{"has_recovery_keys": true})
		case strings.Contains(path, "/barrier/has-recovery-keys"):
			respond(map[string]bool{"has_recovery_keys": true})
		case strings.Contains(path, "/barrier/recover"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/barrier/root-token"):
			respond(transport.BarrierRootTokenResponse{Token: "root-token"})
		case strings.Contains(path, "/barrier/status"):
			respond(transport.BarrierStatusResponse{Sealed: false, InitializedAt: "2024-01-01"})
		case strings.Contains(path, "/barrier"):
			w.WriteHeader(http.StatusOK)

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
		case strings.Contains(path, "/custodian") && strings.Contains(path, "/members") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/custodian") && strings.Contains(path, "/members"):
			respond(map[string]interface{}{"member": map[string]string{"user_id": "u1"}})
		case strings.Contains(path, "/custodian") && strings.Contains(path, "/distribute"):
			respond(transport.DistributeSharesResponse{Distributed: 3})
		case strings.Contains(path, "/custodian") && r.Method == http.MethodPost:
			respond(map[string]interface{}{"id": "g1", "name": "test-group", "threshold": 2})
		case strings.Contains(path, "/custodian") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case path == "/api/v1/custodian/groups" && r.Method == http.MethodGet:
			respond(transport.ListCustodianGroupsResponse{
				Groups: []transport.CustodianGroupInfo{{ID: "g1", Name: "test-group"}},
			})
		case strings.HasPrefix(path, "/api/v1/custodian/groups/"):
			respond(map[string]interface{}{"id": "g1", "name": "test-group"})

		// Shares
		case strings.HasPrefix(path, "/api/v1/shares/status"):
			respond(transport.ShareCollectionStatus{GroupID: "g1", Collected: 1, Threshold: 2})
		case strings.HasPrefix(path, "/api/v1/shares") && r.Method == http.MethodPost:
			respond(transport.SubmitShareResponse{Accepted: true})
		case strings.HasPrefix(path, "/api/v1/shares"):
			respond(transport.ListSharesResponse{
				Shares: []transport.ShareInfo{{GroupID: "g1", ShareIndex: 0}},
			})

		// Tenants
		case strings.Contains(path, "/tenants") && strings.Contains(path, "/barrier/init"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/tenants") && strings.Contains(path, "/barrier/unseal"):
			w.WriteHeader(http.StatusOK)
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
		case strings.Contains(path, "/init/status"):
			respond(transport.InitStatusResponse{State: "initialized"})
		case strings.Contains(path, "/init/claim-cert/begin"):
			respond(transport.ClaimCertBeginResponse{Nonce: "abc"})
		case strings.Contains(path, "/init/claim-cert/complete"):
			respond(map[string]string{"certificate_pem": "cert"})
		case strings.Contains(path, "/init/claim-share"):
			respond(map[string]interface{}{"share": "encoded-share-data"})
		case strings.Contains(path, "/init/sign-csr"):
			respond(map[string]string{"certificate_pem": "cert"})
		case strings.Contains(path, "/credentials/strategy"):
			respond(transport.CredentialStrategyResponse{Strategy: "manual"})
		case strings.Contains(path, "/credentials/submit"):
			respond(map[string]bool{"accepted": true})

		// Passwords
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
			respond(transport.WrapKeyResponse{WrappedKeyMaterial: []byte("wrapped"), Algorithm: "AES"})
		case strings.Contains(path, "/keys/unwrap"):
			respond(transport.UnwrapKeyResponse{KeyMaterial: []byte("unwrapped")})
		case strings.Contains(path, "/keys/import-params"):
			respond(transport.GetImportParametersResponse{WrappingPublicKey: []byte("wpk"), ImportToken: []byte("tok"), Algorithm: "RSA-OAEP"})
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

func TestBarrierInitializeShamir_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{Threshold: 2, TotalShares: 3})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Threshold)
}

func TestBarrierUnsealWithShare_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{Share: "share-1"})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Required)
}

func TestBarrierUnsealWithShares_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{Shares: []string{"s1", "s2"}})
	require.NoError(t, err)
}

func TestBarrierShamirListShares_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierShamirListShares(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Count)
}

func TestBarrierShamirDeleteShare_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.BarrierShamirDeleteShare(context.Background(), &transport.BarrierShamirDeleteShareRequest{Index: 0})
	require.NoError(t, err)
}

func TestBarrierShamirDeleteAllShares_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.BarrierShamirDeleteAllShares(context.Background())
	require.NoError(t, err)
}

func TestBarrierShamirVerify_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.BarrierShamirVerify(context.Background())
	require.NoError(t, err)
}

func TestBarrierRekey_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{Threshold: 2, Total: 3})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Threshold)
}

func TestBarrierGenerateRecoveryKeys_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierRecoverWithKeys_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{Keys: []string{"k1"}})
	require.NoError(t, err)
}

func TestBarrierDeleteRecoveryKeys_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.BarrierDeleteRecoveryKeys(context.Background())
	require.NoError(t, err)
}

func TestBarrierHasRecoveryKeys_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierHasRecoveryKeys(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierGenerateRootToken_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{Shares: []string{"s1"}})
	require.NoError(t, err)
	assert.Equal(t, "root-token", resp.Token)
}

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

func TestCreateCustodianGroup_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{Name: "test"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCustodianGroup_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetCustodianGroup(context.Background(), "g1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestListCustodianGroups_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.ListCustodianGroups(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Groups, 1)
}

func TestDeleteCustodianGroup_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.DeleteCustodianGroup(context.Background(), "g1")
	require.NoError(t, err)
}

func TestAddCustodianMember_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{GroupID: "g1"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestRemoveCustodianMember_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.RemoveCustodianMember(context.Background(), &transport.RemoveCustodianMemberRequest{GroupID: "g1", UserID: "u1"})
	require.NoError(t, err)
}

func TestDistributeShares_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.DistributeShares(context.Background(), &transport.DistributeSharesRequest{GroupID: "g1"})
	require.NoError(t, err)
	assert.Equal(t, 3, resp.Distributed)
}

// --- Share tests ---

func TestSubmitShare_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{GroupID: "g1"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestListShares_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.ListShares(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Shares, 1)
}

func TestGetShareCollectionStatus_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetShareCollectionStatus(context.Background(), "g1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

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

func TestTenantBarrierInit_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.TenantBarrierInit(context.Background(), &transport.TenantBarrierInitRequest{TenantID: "t1"})
	require.NoError(t, err)
}

func TestTenantBarrierUnseal_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	err := tr.TenantBarrierUnseal(context.Background(), &transport.TenantBarrierUnsealRequest{TenantID: "t1"})
	require.NoError(t, err)
}

// --- Init / Credential tests ---

func TestGetInitStatus_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.GetInitStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimCertBegin_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimCertComplete_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimShare_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.ClaimShare(context.Background(), &transport.ClaimShareRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp.Share)
}

func TestSignCSRInit_Connected(t *testing.T) {
	tr, cleanup := newFullMockTransport(t)
	defer cleanup()
	resp, err := tr.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

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
