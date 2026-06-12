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

// newBadJSONTransport creates a Transport backed by a server that returns 200
// responses with invalid (non-JSON) bodies, triggering json.Unmarshal errors.
func newBadJSONTransport(t *testing.T) (*Transport, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-valid-json{{{"))
	}))
	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}
	return tr, srv.Close
}

// gapMockHandler extends mockHandler with additional endpoints needed to hit
// branches that were previously uncovered.
func gapMockHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		respond := func(data interface{}) {
			json.NewEncoder(w).Encode(data)
		}

		switch {
		// CA — optional query params
		case strings.Contains(path, "/ca/bundle"):
			respond(transport.GetCABundleResponse{BundlePEM: []byte("bundle")})
		case strings.Contains(path, "/ca/certificate"):
			respond(transport.GetCACertificateResponse{CertificatePEM: []byte("ca-cert")})
		case strings.Contains(path, "/ca/revoke"):
			respond(transport.RevokeCertificateResponse{Success: true})
		case strings.Contains(path, "/ca/crl"):
			respond(transport.GenerateCRLResponse{CRLPEM: []byte("crl")})
		case strings.Contains(path, "/ca/revoked"):
			respond(transport.IsRevokedResponse{Revoked: false})
		case strings.Contains(path, "/ca/sign-csr"):
			respond(transport.SignCSRResponse{CertificatePEM: []byte("signed")})
		case strings.Contains(path, "/ca/issue"):
			respond(transport.IssueCertificateResponse{CertificatePEM: []byte("issued")})

		// TCG CA
		case strings.Contains(path, "/tcg-ca/issue-ek-cert"):
			respond(transport.IssueEKCertificateResponse{CertificatePEM: []byte("ek-cert")})
		case strings.Contains(path, "/tcg-ca/issue-ak-cert"):
			respond(transport.IssueAKCertificateResponse{CertificatePEM: []byte("ak-cert")})
		case strings.Contains(path, "/tcg-ca/sign-tcg-csr"):
			respond(transport.SignTCGCSRResponse{IAKCertDER: []byte("iak")})
		case strings.Contains(path, "/tcg-ca/enroll-device"):
			respond(transport.EnrollDeviceResponse{IAKCertDER: []byte("iak")})

		// PIV
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/certificate") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/certificate") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/certificate"):
			respond(transport.GetPIVCertificateResponse{Certificate: []byte("cert"), Slot: "9a"})
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/generate"):
			respond(transport.GeneratePIVKeyResponse{PublicKey: []byte("pubkey"), Slot: "9a"})
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/import"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/export"):
			respond(transport.GetPIVCertificateResponse{Certificate: []byte("cert"), Slot: "9a"})
		case strings.Contains(path, "/piv/slots") && strings.HasSuffix(path, "/csr"):
			respond(transport.GeneratePIVCSRResponse{CSR: []byte("csr"), Slot: "9a"})
		case strings.Contains(path, "/piv/slots"):
			respond(transport.ListPIVSlotsResponse{Slots: []transport.PIVSlotStatus{{Slot: "9a"}}})

		// Barrier
		case strings.Contains(path, "/barrier/status"):
			respond(transport.BarrierStatusResponse{Sealed: false})
		case strings.Contains(path, "/barrier/initialize-shamir"):
			respond(transport.BarrierInitializeShamirResponse{Threshold: 2, TotalShares: 3, ShareCount: 3})
		case strings.Contains(path, "/barrier/unseal-share"):
			respond(map[string]interface{}{"required": 2, "submitted": 1, "complete": false})
		case strings.Contains(path, "/barrier/unseal-shares"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/barrier/rekey"):
			respond(transport.BarrierRekeyResponse{Threshold: 2, TotalShares: 3, ShareCount: 3})
		case strings.Contains(path, "/barrier/recovery-keys/generate"):
			respond(map[string]interface{}{"threshold": 2, "total_shares": 3, "share_count": 3})
		case strings.Contains(path, "/barrier/recovery-keys/recover"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/barrier/recovery-keys") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/barrier/recovery-keys"):
			respond(map[string]bool{"has_recovery_keys": true})
		case strings.Contains(path, "/barrier/root-token"):
			respond(transport.BarrierRootTokenResponse{Token: "rt-abc"})
		case strings.Contains(path, "/barrier"):
			w.WriteHeader(http.StatusOK)

		// PIN
		case strings.Contains(path, "/pin/so-pin/change"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/user-pin/change"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/so-pin/verify"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/user-pin/verify"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/so-pin"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/user-pin"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/lockout/reset"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/pin/lockout"):
			respond(transport.LockoutStatusResponse{FailedAttempts: 0, IsLocked: false})

		// Password - with optional query params
		case strings.Contains(path, "/passwords/status"):
			respond(transport.PasswordStoreStatusResponse{AccessMode: "private"})
		case strings.Contains(path, "/passwords/unlock"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/passwords/lock"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/passwords/generate"):
			respond(transport.PasswordGenerateResponse{Password: "gen-pw"})
		case strings.Contains(path, "/passwords/access-mode"):
			w.WriteHeader(http.StatusOK)
		case path == "/api/v1/passwords" && r.Method == http.MethodGet:
			respond(transport.PasswordListResponse{
				Passwords: []transport.PasswordGetResponse{{ID: "pw-1", Name: "test"}},
			})
		case strings.HasPrefix(path, "/api/v1/passwords") && r.Method == http.MethodPost:
			respond(transport.PasswordAddResponse{ID: "pw-1", Name: "test"})
		case strings.HasPrefix(path, "/api/v1/passwords") && r.Method == http.MethodGet:
			respond(transport.PasswordGetResponse{ID: "pw-1", Name: "test"})
		case strings.HasPrefix(path, "/api/v1/passwords") && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(path, "/api/v1/passwords") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

		// Custodian
		case strings.Contains(path, "/custodian/groups") && strings.Contains(path, "/members") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/custodian/groups") && strings.Contains(path, "/distribute"):
			respond(transport.DistributeSharesResponse{Distributed: 2})
		case strings.Contains(path, "/custodian/groups") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/custodian/groups") && strings.Contains(path, "/members"):
			respond(map[string]interface{}{"id": "g1"})
		case strings.Contains(path, "/custodian/groups") && r.Method == http.MethodPost:
			respond(map[string]interface{}{"id": "g1", "name": "test-group", "threshold": 2})
		case strings.Contains(path, "/custodian/groups") && r.Method == http.MethodGet && strings.Count(path, "/") > 3:
			respond(map[string]interface{}{"id": "g1", "name": "test-group"})
		case strings.Contains(path, "/custodian/groups"):
			respond(transport.ListCustodianGroupsResponse{Groups: []transport.CustodianGroupInfo{{ID: "g1", Name: "test-group"}}})

		// Shares
		case strings.Contains(path, "/shares/submit"):
			respond(transport.SubmitShareResponse{Accepted: true})
		case strings.Contains(path, "/shares/status"):
			respond(transport.ShareCollectionStatus{})
		case strings.Contains(path, "/shares"):
			respond(transport.ListSharesResponse{Shares: []transport.ShareInfo{{GroupID: "g1", ShareIndex: 0}}})

		// Tenants
		case strings.Contains(path, "/tenants") && strings.Contains(path, "/barrier/init"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/tenants") && strings.Contains(path, "/barrier/unseal"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/tenants") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case strings.Contains(path, "/tenants") && r.Method == http.MethodPost:
			respond(map[string]interface{}{"id": "t1", "name": "test-tenant"})
		case strings.Contains(path, "/tenants") && r.Method == http.MethodGet && strings.Count(path, "/") > 3:
			respond(map[string]interface{}{"id": "t1", "name": "test-tenant"})
		case strings.Contains(path, "/tenants"):
			respond(transport.ListTenantsResponse{Tenants: []transport.TenantInfo{{ID: "t1", Name: "test-tenant"}}})

		// Init
		case strings.Contains(path, "/init/status"):
			respond(transport.InitStatusResponse{State: "initialized"})
		case strings.Contains(path, "/init/claim-cert/begin"):
			respond(transport.ClaimCertBeginResponse{Nonce: "abc"})
		case strings.Contains(path, "/init/claim-cert/complete"):
			respond(transport.ClaimCertCompleteResponse{CertPEM: "cert", CACertPEM: "ca"})
		case strings.Contains(path, "/init/claim-share"):
			respond(transport.ClaimShareResponse{Share: json.RawMessage(`"share"`)})
		case strings.Contains(path, "/init/sign-csr"):
			respond(transport.SignCSRInitResponse{CertPEM: "cert"})

		// Credentials
		case strings.Contains(path, "/credentials/submit"):
			respond(transport.CredentialSubmitResponse{Status: "ok"})
		case strings.Contains(path, "/credentials/strategy"):
			respond(transport.CredentialStrategyResponse{Strategy: "manual"})

		// Health (fallback)
		case path == "/health":
			respond(map[string]string{"status": "healthy"})

		default:
			respond(map[string]bool{"success": true})
		}
	})
}

// newGapMockTransport creates a Transport backed by the gap-filling mock server.
func newGapMockTransport(t *testing.T) (*Transport, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(gapMockHandler())
	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}
	return tr, srv.Close
}

// ============================================================
// CA — optional query param branches
// ============================================================

func TestGetCABundle_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.GetCABundleRequest
	}{
		{"with_store_type", &transport.GetCABundleRequest{StoreType: "software"}},
		{"with_algorithm", &transport.GetCABundleRequest{Algorithm: "rsa"}},
		{"with_tenant", &transport.GetCABundleRequest{TenantID: "t1"}},
		{"all_params", &transport.GetCABundleRequest{StoreType: "software", Algorithm: "ec", TenantID: "t1"}},
		{"empty", &transport.GetCABundleRequest{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.GetCABundle(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.BundlePEM)
		})
	}
}

func TestGetCACertificate_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.GetCACertificateRequest
	}{
		{"with_identity", &transport.GetCACertificateRequest{Identity: "admin"}},
		{"with_tenant", &transport.GetCACertificateRequest{TenantID: "t1"}},
		{"both", &transport.GetCACertificateRequest{Identity: "admin", TenantID: "t1"}},
		{"empty", &transport.GetCACertificateRequest{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.GetCACertificate(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.CertificatePEM)
		})
	}
}

func TestSignCSR_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.SignCSRRequest
	}{
		{"minimal", &transport.SignCSRRequest{CSRPEM: []byte("csr")}},
		{"with_profile", &transport.SignCSRRequest{CSRPEM: []byte("csr"), Profile: "server"}},
		{"with_validity", &transport.SignCSRRequest{CSRPEM: []byte("csr"), ValidityDays: 365}},
		{"with_tenant", &transport.SignCSRRequest{CSRPEM: []byte("csr"), TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.SignCSR(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.CertificatePEM)
		})
	}
}

func TestIssueCertificate_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.IssueCertificateRequest
	}{
		{"minimal", &transport.IssueCertificateRequest{CommonName: "test"}},
		{"with_org", &transport.IssueCertificateRequest{CommonName: "test", Organization: "Org"}},
		{"with_sans", &transport.IssueCertificateRequest{CommonName: "test", SANs: []string{"test.local"}}},
		{"with_validity", &transport.IssueCertificateRequest{CommonName: "test", ValidityDays: 90}},
		{"with_algorithm", &transport.IssueCertificateRequest{CommonName: "test", Algorithm: "ecdsa"}},
		{"with_tenant", &transport.IssueCertificateRequest{CommonName: "test", TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.IssueCertificate(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.CertificatePEM)
		})
	}
}

func TestRevokeCertificate_WithTenant(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.RevokeCertificateRequest
	}{
		{"without_tenant", &transport.RevokeCertificateRequest{SerialNumber: "ABCD", Reason: 0}},
		{"with_tenant", &transport.RevokeCertificateRequest{SerialNumber: "ABCD", Reason: 0, TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.RevokeCertificate(context.Background(), tc.req)
			require.NoError(t, err)
			assert.True(t, resp.Success)
		})
	}
}

func TestGenerateCRL_WithTenant(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.GenerateCRLRequest
	}{
		{"without_tenant", &transport.GenerateCRLRequest{}},
		{"with_tenant", &transport.GenerateCRLRequest{TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.GenerateCRL(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.CRLPEM)
		})
	}
}

func TestIsRevoked_WithTenant(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.IsRevokedRequest
	}{
		{"without_tenant", &transport.IsRevokedRequest{SerialNumber: "ABCD"}},
		{"with_tenant", &transport.IsRevokedRequest{SerialNumber: "ABCD", TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.IsRevoked(context.Background(), tc.req)
			require.NoError(t, err)
			assert.False(t, resp.Revoked)
		})
	}
}

// ============================================================
// TCG CA — optional field branches
// ============================================================

func TestIssueEKCertificate_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.IssueEKCertificateRequest
	}{
		{"minimal", &transport.IssueEKCertificateRequest{CommonName: "ek", EKPublicKey: []byte("pk")}},
		{"with_org", &transport.IssueEKCertificateRequest{CommonName: "ek", EKPublicKey: []byte("pk"), Organization: "Org"}},
		{"with_tenant", &transport.IssueEKCertificateRequest{CommonName: "ek", EKPublicKey: []byte("pk"), TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.IssueEKCertificate(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.CertificatePEM)
		})
	}
}

func TestIssueAKCertificate_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.IssueAKCertificateRequest
	}{
		{"minimal", &transport.IssueAKCertificateRequest{CommonName: "ak", PublicKey: []byte("pk")}},
		{"with_org", &transport.IssueAKCertificateRequest{CommonName: "ak", PublicKey: []byte("pk"), Organization: "Org"}},
		{"with_tenant", &transport.IssueAKCertificateRequest{CommonName: "ak", PublicKey: []byte("pk"), TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.IssueAKCertificate(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.CertificatePEM)
		})
	}
}

func TestSignTCGCSR_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.SignTCGCSRRequest
	}{
		{"minimal", &transport.SignTCGCSRRequest{CommonName: "dev", TCGCSR: []byte("csr")}},
		{"with_org", &transport.SignTCGCSRRequest{CommonName: "dev", TCGCSR: []byte("csr"), Organization: "Org"}},
		{"with_tenant", &transport.SignTCGCSRRequest{CommonName: "dev", TCGCSR: []byte("csr"), TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.SignTCGCSR(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.IAKCertDER)
		})
	}
}

func TestEnrollDevice_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.EnrollDeviceRequest
	}{
		{"minimal", &transport.EnrollDeviceRequest{CommonName: "dev", PackedCSR: []byte("csr")}},
		{"with_org", &transport.EnrollDeviceRequest{CommonName: "dev", PackedCSR: []byte("csr"), Organization: "Org"}},
		{"with_tenant", &transport.EnrollDeviceRequest{CommonName: "dev", PackedCSR: []byte("csr"), TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.EnrollDevice(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.IAKCertDER)
		})
	}
}

// ============================================================
// PIV — GeneratePIVCSR connected path (not covered elsewhere)
// ============================================================

func TestGeneratePIVCSR_Connected(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()
	resp, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{Slot: "9a"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CSR)
}

// ============================================================
// Password — optional query param branches and update/delete
// ============================================================

func TestPasswordGet_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.PasswordGetRequest
	}{
		{"minimal", &transport.PasswordGetRequest{ID: "pw-1"}},
		{"decrypt", &transport.PasswordGetRequest{ID: "pw-1", Decrypt: true}},
		{"user_pin", &transport.PasswordGetRequest{ID: "pw-1", UserPIN: "1234"}},
		{"tenant", &transport.PasswordGetRequest{ID: "pw-1", TenantID: "t1"}},
		{"all", &transport.PasswordGetRequest{ID: "pw-1", Decrypt: true, UserPIN: "1234", TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.PasswordGet(context.Background(), tc.req)
			require.NoError(t, err)
			assert.Equal(t, "pw-1", resp.ID)
		})
	}
}

func TestPasswordList_WithParams(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.PasswordListRequest
	}{
		{"nil_req", nil},
		{"empty_req", &transport.PasswordListRequest{}},
		{"folder", &transport.PasswordListRequest{FolderPath: "work"}},
		{"tenant", &transport.PasswordListRequest{TenantID: "t1"}},
		{"scope", &transport.PasswordListRequest{Scope: "personal"}},
		{"all_params", &transport.PasswordListRequest{FolderPath: "work", TenantID: "t1", Scope: "all"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.PasswordList(context.Background(), tc.req)
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestPasswordUpdate_Connected(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()
	err := tr.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{ID: "pw-1"})
	require.NoError(t, err)
}

func TestPasswordDelete_WithTenant(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.PasswordDeleteRequest
	}{
		{"without_tenant", &transport.PasswordDeleteRequest{ID: "pw-1"}},
		{"with_tenant", &transport.PasswordDeleteRequest{ID: "pw-1", TenantID: "t1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tr.PasswordDelete(context.Background(), tc.req)
			require.NoError(t, err)
		})
	}
}

func TestPasswordStoreSetAccessMode_Connected(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()
	err := tr.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{Mode: "shared"})
	require.NoError(t, err)
}

// ============================================================
// Close — with non-http3 transport (covers non-http3 branch)
// ============================================================

func TestClose_WithNonHTTP3Transport(t *testing.T) {
	// The Close method has a branch: if transport is NOT http3.Transport, no-op close.
	// Use the mock TLS server's plain http.Transport to hit that path.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(), // uses *http.Transport, not *http3.Transport
		baseURL:    srv.URL,
		connected:  true,
	}

	err := tr.Close()
	require.NoError(t, err)
	assert.False(t, tr.connected)
}

// ============================================================
// User operations (ErrNotSupported stubs)
// ============================================================

func TestUserOps_NotSupported(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"CreateUser", func() error {
			_, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{})
			return err
		}},
		{"ListUsers", func() error {
			_, err := tr.ListUsers(context.Background())
			return err
		}},
		{"GetUser", func() error {
			_, err := tr.GetUser(context.Background(), "u1")
			return err
		}},
		{"DeleteUser", func() error { return tr.DeleteUser(context.Background(), "u1") }},
		{"EnableUser", func() error { return tr.EnableUser(context.Background(), "u1") }},
		{"DisableUser", func() error { return tr.DisableUser(context.Background(), "u1") }},
		{"BindUserCert", func() error { return tr.BindUserCert(context.Background(), "u1", "cert", 1) }},
		{"ListUserCredentials", func() error {
			_, err := tr.ListUserCredentials(context.Background(), "u1")
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, tc.fn(), ErrNotSupported)
		})
	}
}

// ============================================================
// Barrier — basic connected paths not covered by extra_test
// ============================================================

func TestBarrierInitialize_Connected(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()
	err := tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	require.NoError(t, err)
}

func TestBarrierUnseal_Connected(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()
	err := tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	require.NoError(t, err)
}

func TestBarrierSeal_Connected(t *testing.T) {
	tr, cleanup := newGapMockTransport(t)
	defer cleanup()
	err := tr.BarrierSeal(context.Background())
	require.NoError(t, err)
}

// ============================================================
// DeriveKey — optional field branches
// ============================================================

func TestDeriveKey_OptionalFields(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(transport.DeriveKeyResponse{DerivedKey: []byte("derived"), Algorithm: "HKDF", KeyLength: 32})
	}))
	defer srv.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	tests := []struct {
		name string
		req  *transport.DeriveKeyRequest
	}{
		{"minimal", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32}},
		{"with_key_id", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32, KeyID: "k1"}},
		{"with_ikm", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32, InputKeyMaterial: []byte("ikm")}},
		{"with_salt", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32, Salt: []byte("salt")}},
		{"with_info", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32, Info: []byte("info")}},
		{"with_peer_pub_key", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32, PeerPublicKey: []byte("pk")}},
		{"with_hash", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32, Hash: "sha256"}},
		{"with_iterations", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "PBKDF2", KeyLength: 32, Iterations: 1000}},
		{"with_prf", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "PBKDF2", KeyLength: 32, PRF: "hmac-sha256"}},
		{"with_label", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "KBKDF", KeyLength: 32, Label: []byte("label")}},
		{"with_context", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "KBKDF", KeyLength: 32, Context: []byte("ctx")}},
		{"with_counter", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "KBKDF", KeyLength: 32, Counter: 1}},
		{"with_cofactor", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "ECDH", KeyLength: 32, UseCofactor: true}},
		{"with_store_result", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32, StoreResult: true, DerivedKeyID: "dk1"}},
		{"with_derived_key_type", &transport.DeriveKeyRequest{Backend: "software", Algorithm: "HKDF", KeyLength: 32, DerivedKeyType: "aes256"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.DeriveKey(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.DerivedKey)
		})
	}
}

// ============================================================
// NotConnected guards — functions not yet covered by coverage_test
// ============================================================

func TestBarrierInitialize_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierUnseal_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierSeal_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierSeal(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUnseal_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).Unseal(context.Background(), &transport.UnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestCanSeal_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).CanSeal(context.Background(), "software")
	assert.ErrorIs(t, err, ErrNotConnected)
}

// ============================================================
// Server-error paths for PIV methods (doRawRequest error branch)
// ============================================================

func TestListPIVSlots_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{Backend: "piv"})
	require.Error(t, err)
}

func TestGetPIVCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Slot: "9a", Backend: "piv"})
	require.Error(t, err)
}

func TestGeneratePIVKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{Slot: "9a"})
	require.Error(t, err)
}

func TestExportPIVCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Slot: "9a", Backend: "piv"})
	require.Error(t, err)
}

func TestGeneratePIVCSR_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{Slot: "9a"})
	require.Error(t, err)
}

func TestStorePIVCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{Slot: "9a", Certificate: []byte("cert")})
	require.Error(t, err)
}

func TestDeletePIVCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{Slot: "9a", Backend: "piv"})
	require.Error(t, err)
}

func TestImportPIVCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{Slot: "9a", Certificate: []byte("cert")})
	require.Error(t, err)
}

func TestPasswordStoreSetAccessMode_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{Mode: "shared"})
	require.Error(t, err)
}

// ============================================================
// IssueEKCertificate / IssueAKCertificate / SignTCGCSR / EnrollDevice
// server-error paths (doRawRequest error branch)
// ============================================================

func TestIssueEKCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{CommonName: "ek", EKPublicKey: []byte("pk")})
	require.Error(t, err)
}

func TestIssueAKCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{CommonName: "ak", PublicKey: []byte("pk")})
	require.Error(t, err)
}

func TestSignTCGCSR_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{CommonName: "dev", TCGCSR: []byte("csr")})
	require.Error(t, err)
}

func TestEnrollDevice_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{CommonName: "dev", PackedCSR: []byte("csr")})
	require.Error(t, err)
}

// ============================================================
// Optional field branches for Sign, Verify, Encrypt, Decrypt,
// EncryptAsym — use existing mockTransport which handles these
// ============================================================

func TestSign_WithHash(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		KeyID:   "k1",
		Backend: "software",
		Data:    []byte("data"),
		Hash:    "sha256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Signature)
}

func TestVerify_WithHash(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.Verify(context.Background(), &transport.VerifyRequest{
		KeyID:     "k1",
		Backend:   "software",
		Data:      []byte("data"),
		Signature: []byte("sig"),
		Hash:      "sha256",
	})
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestEncrypt_WithAdditionalData(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{
		KeyID:          "k1",
		Backend:        "software",
		Plaintext:      []byte("hello"),
		AdditionalData: []byte("aad"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestDecrypt_WithNonceTagAAD(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		req  *transport.DecryptRequest
	}{
		{"with_nonce", &transport.DecryptRequest{
			KeyID:      "k1",
			Backend:    "software",
			Ciphertext: []byte("ct"),
			Nonce:      []byte("nonce"),
		}},
		{"with_tag", &transport.DecryptRequest{
			KeyID:      "k1",
			Backend:    "software",
			Ciphertext: []byte("ct"),
			Tag:        []byte("tag"),
		}},
		{"with_aad", &transport.DecryptRequest{
			KeyID:          "k1",
			Backend:        "software",
			Ciphertext:     []byte("ct"),
			AdditionalData: []byte("aad"),
		}},
		{"all_optional", &transport.DecryptRequest{
			KeyID:          "k1",
			Backend:        "software",
			Ciphertext:     []byte("ct"),
			Nonce:          []byte("nonce"),
			Tag:            []byte("tag"),
			AdditionalData: []byte("aad"),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tr.Decrypt(context.Background(), tc.req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.Plaintext)
		})
	}
}

func TestEncryptAsym_WithHash(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	resp, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		KeyID:     "k1",
		Backend:   "software",
		Plaintext: []byte("hello"),
		Hash:      "sha256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

// ============================================================
// JWTToken / Headers optional branches in DoRawRequest
// ============================================================

func TestDoRawRequest_WithJWTAndHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	cfg := transport.DefaultConfig()
	cfg.JWTToken = "test-token"
	cfg.Headers = map[string]string{"X-Custom": "value"}

	tr := &Transport{
		config:     cfg,
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	data, err := tr.DoRawRequest(context.Background(), "GET", "/health", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// ============================================================
// Bad-JSON transport tests — trigger json.Unmarshal error paths
// ============================================================

func TestBarrierInitializeShamir_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{})
	require.Error(t, err)
}

func TestBarrierUnsealWithShare_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{})
	require.Error(t, err)
}

func TestBarrierRekey_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{})
	require.Error(t, err)
}

func TestBarrierGenerateRecoveryKeys_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{})
	require.Error(t, err)
}

func TestBarrierHasRecoveryKeys_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.BarrierHasRecoveryKeys(context.Background())
	require.Error(t, err)
}

func TestBarrierGenerateRootToken_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{})
	require.Error(t, err)
}

func TestGetLockoutStatus_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GetLockoutStatus(context.Background())
	require.Error(t, err)
}

func TestGetInitStatus_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GetInitStatus(context.Background())
	require.Error(t, err)
}

func TestClaimCertBegin_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	require.Error(t, err)
}

func TestClaimCertComplete_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	require.Error(t, err)
}

func TestClaimShare_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.ClaimShare(context.Background(), &transport.ClaimShareRequest{})
	require.Error(t, err)
}

func TestSignCSRInit_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	require.Error(t, err)
}

func TestSubmitCredential_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	require.Error(t, err)
}

func TestGetCredentialStrategy_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GetCredentialStrategy(context.Background())
	require.Error(t, err)
}

func TestListPIVSlots_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{Backend: "piv"})
	require.Error(t, err)
}

func TestGetPIVCertificate_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Slot: "9a", Backend: "piv"})
	require.Error(t, err)
}

func TestGeneratePIVKey_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{Slot: "9a"})
	require.Error(t, err)
}

func TestExportPIVCertificate_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Slot: "9a", Backend: "piv"})
	require.Error(t, err)
}

func TestGeneratePIVCSR_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{Slot: "9a"})
	require.Error(t, err)
}

func TestIssueEKCertificate_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{CommonName: "ek", EKPublicKey: []byte("pk")})
	require.Error(t, err)
}

func TestIssueAKCertificate_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{CommonName: "ak", PublicKey: []byte("pk")})
	require.Error(t, err)
}

func TestSignTCGCSR_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{CommonName: "dev", TCGCSR: []byte("csr")})
	require.Error(t, err)
}

func TestEnrollDevice_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{CommonName: "dev", PackedCSR: []byte("csr")})
	require.Error(t, err)
}

func TestUnseal_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.Unseal(context.Background(), &transport.UnsealRequest{Backend: "software"})
	require.Error(t, err)
}

func TestGetCABundle_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.Error(t, err)
}

func TestGetCACertificate_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.Error(t, err)
}

func TestSignCSR_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{CSRPEM: []byte("csr")})
	require.Error(t, err)
}

func TestIssueCertificate_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{CommonName: "test"})
	require.Error(t, err)
}

func TestRevokeCertificate_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{SerialNumber: "ABCD"})
	require.Error(t, err)
}

func TestGenerateCRL_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.Error(t, err)
}

func TestIsRevoked_BadJSON(t *testing.T) {
	tr, cleanup := newBadJSONTransport(t)
	defer cleanup()
	_, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{SerialNumber: "ABCD"})
	require.Error(t, err)
}
