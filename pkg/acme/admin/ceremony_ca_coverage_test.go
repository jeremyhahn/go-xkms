//go:build codec_json

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

package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// stubCeremonyClient is an in-memory CeremonyClient for testing.
// ==========================================================================

type stubCeremonyClient struct {
	initResp            *db.CeremonyInitializeResponse
	initErr             error
	statusResp          *db.CeremonyStatusResponse
	statusErr           error
	claimBeginResp      *db.ClaimCertBeginResponse
	claimBeginErr       error
	claimCompleteResp   *db.ClaimCertCompleteResponse
	claimCompleteErr    error
	claimBeginShareResp *db.BeginClaimShareResponse
	claimShareResp      *db.CompleteClaimShareResponse
	claimShareErr       error
	signCSRResp         *db.SignCSRInitResponse
	signCSRErr          error
}

func newStubCeremonyClient() *stubCeremonyClient {
	return &stubCeremonyClient{
		initResp: &db.CeremonyInitializeResponse{
			State:      "initialized",
			ShareCount: 3,
			SPKIPin:    "sha256:abcdef",
		},
		statusResp: &db.CeremonyStatusResponse{
			State:   "initialized",
			SPKIPin: "sha256:abcdef",
		},
		claimBeginResp: &db.ClaimCertBeginResponse{
			NonceHex:  "deadbeef",
			ExpiresAt: "2025-12-31T00:00:00Z",
		},
		claimCompleteResp: &db.ClaimCertCompleteResponse{
			CertPEM:   "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
			CACertPEM: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
		},
		claimBeginShareResp: &db.BeginClaimShareResponse{
			NonceHex:  "deadbeef",
			ExpiresAt: "2025-12-31T00:00:00Z",
		},
		claimShareResp: &db.CompleteClaimShareResponse{
			ShareIndex: 1,
			ShareJSON:  `{"index":1,"value":"abc"}`,
		},
		signCSRResp: &db.SignCSRInitResponse{
			CertPEM: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
		},
	}
}

func (s *stubCeremonyClient) CeremonyInitialize(_ context.Context, _ *db.CeremonyInitializeRequest) (*db.CeremonyInitializeResponse, error) {
	return s.initResp, s.initErr
}
func (s *stubCeremonyClient) CeremonyStatus(_ context.Context) (*db.CeremonyStatusResponse, error) {
	return s.statusResp, s.statusErr
}
func (s *stubCeremonyClient) CeremonyClaimCertBegin(_ context.Context, _ *db.ClaimCertBeginRequest) (*db.ClaimCertBeginResponse, error) {
	return s.claimBeginResp, s.claimBeginErr
}
func (s *stubCeremonyClient) CeremonyClaimCertComplete(_ context.Context, _ *db.ClaimCertCompleteRequest) (*db.ClaimCertCompleteResponse, error) {
	return s.claimCompleteResp, s.claimCompleteErr
}
func (s *stubCeremonyClient) CeremonyBeginClaimShare(_ context.Context, _ *db.BeginClaimShareRequest) (*db.BeginClaimShareResponse, error) {
	return s.claimBeginShareResp, s.claimShareErr
}
func (s *stubCeremonyClient) CeremonyCompleteClaimShare(_ context.Context, _ *db.CompleteClaimShareRequest) (*db.CompleteClaimShareResponse, error) {
	return s.claimShareResp, s.claimShareErr
}
func (s *stubCeremonyClient) CeremonySignCSR(_ context.Context, _ *db.SignCSRInitRequest) (*db.SignCSRInitResponse, error) {
	return s.signCSRResp, s.signCSRErr
}
func (s *stubCeremonyClient) CeremonyClaimShareBegin(_ context.Context, _ *db.CeremonyClaimShareBeginRequest) (*db.CeremonyClaimShareBeginResponse, error) {
	return nil, nil
}
func (s *stubCeremonyClient) CeremonyClaimShareComplete(_ context.Context, _ *db.CeremonyClaimShareCompleteRequest) (*db.CeremonyCustodianInfo, error) {
	return nil, nil
}
func (s *stubCeremonyClient) CeremonySubmitUnsealShare(_ context.Context, _ *db.CeremonySubmitUnsealShareRequest) (*db.CeremonySubmitUnsealShareResponse, error) {
	return nil, nil
}
func (s *stubCeremonyClient) CeremonyEnrollExternalOfficer(_ context.Context, _ *db.EnrollExternalOfficerRequest) (*db.EnrollExternalOfficerResponse, error) {
	return nil, nil
}

// Compile-time check.
var _ db.CeremonyClient = (*stubCeremonyClient)(nil)

// ==========================================================================
// ceremonyService error types
// ==========================================================================

func TestCeremonyErrors(t *testing.T) {
	t.Run("CeremonyNotAvailableError", func(t *testing.T) {
		err := &CeremonyNotAvailableError{Operation: "initialize"}
		assert.Contains(t, err.Error(), "initialize")
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("CeremonyError wraps underlying error", func(t *testing.T) {
		inner := errors.New("rpc error")
		err := &CeremonyError{Operation: "status", Err: inner}
		assert.Contains(t, err.Error(), "status")
		assert.Contains(t, err.Error(), "rpc error")
		assert.Equal(t, inner, err.Unwrap())
	})
}

// ==========================================================================
// ceremonyService — all operations with nil client (CeremonyNotAvailableError)
// ==========================================================================

func TestCeremonyService_NilClient_AllOps(t *testing.T) {
	svc := NewCeremonyService(nil, nil, slog.Default())
	ctx := context.Background()

	t.Run("InitializeCeremony returns CeremonyNotAvailableError", func(t *testing.T) {
		_, err := svc.InitializeCeremony(ctx, &CeremonyInitializeRequest{SOPin: "pin"})
		require.Error(t, err)
		var e *CeremonyNotAvailableError
		assert.True(t, errors.As(err, &e))
	})

	t.Run("CeremonyStatus returns CeremonyNotAvailableError", func(t *testing.T) {
		_, err := svc.CeremonyStatus(ctx)
		require.Error(t, err)
		var e *CeremonyNotAvailableError
		assert.True(t, errors.As(err, &e))
	})

	t.Run("BeginClaimCert returns CeremonyNotAvailableError", func(t *testing.T) {
		_, err := svc.BeginClaimCert(ctx, &ClaimCertBeginRequest{Username: "alice"})
		require.Error(t, err)
		var e *CeremonyNotAvailableError
		assert.True(t, errors.As(err, &e))
	})

	t.Run("CompleteClaimCert returns CeremonyNotAvailableError", func(t *testing.T) {
		_, err := svc.CompleteClaimCert(ctx, &ClaimCertCompleteRequest{Username: "alice"})
		require.Error(t, err)
		var e *CeremonyNotAvailableError
		assert.True(t, errors.As(err, &e))
	})

	t.Run("BeginClaimShare returns CeremonyNotAvailableError", func(t *testing.T) {
		_, err := svc.BeginClaimShare(ctx, &BeginClaimShareRequest{Username: "alice"})
		require.Error(t, err)
		var e *CeremonyNotAvailableError
		assert.True(t, errors.As(err, &e))
	})

	t.Run("CompleteClaimShare returns CeremonyNotAvailableError", func(t *testing.T) {
		_, err := svc.CompleteClaimShare(ctx, &CompleteClaimShareRequest{Username: "alice"})
		require.Error(t, err)
		var e *CeremonyNotAvailableError
		assert.True(t, errors.As(err, &e))
	})

	t.Run("SignCSR returns CeremonyNotAvailableError", func(t *testing.T) {
		_, err := svc.SignCSR(ctx, &SignCSRRequest{Username: "alice"})
		require.Error(t, err)
		var e *CeremonyNotAvailableError
		assert.True(t, errors.As(err, &e))
	})

	t.Run("CAAdapter returns nil when no CA provided", func(t *testing.T) {
		adapter := svc.CAAdapter()
		assert.Nil(t, adapter)
	})
}

// ==========================================================================
// ceremonyService — success and error paths with real stub client
// ==========================================================================

func TestCeremonyService_InitializeCeremony_Success(t *testing.T) {
	stub := newStubCeremonyClient()
	svc := NewCeremonyService(stub, nil, slog.Default())

	resp, err := svc.InitializeCeremony(context.Background(), &CeremonyInitializeRequest{
		SOPin:     "so-pin",
		UserPin:   "user-pin",
		Threshold: 2,
		Officers: []CeremonyOfficerRequest{
			{Username: "officer1", CSRPEM: "pem1"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "initialized", resp.State)
	assert.Equal(t, 3, resp.ShareCount)
}

func TestCeremonyService_InitializeCeremony_Error(t *testing.T) {
	stub := newStubCeremonyClient()
	stub.initErr = errors.New("ceremony failed")
	svc := NewCeremonyService(stub, nil, slog.Default())

	_, err := svc.InitializeCeremony(context.Background(), &CeremonyInitializeRequest{
		SOPin: "pin",
	})
	require.Error(t, err)
	var ce *CeremonyError
	assert.True(t, errors.As(err, &ce))
	assert.Equal(t, "initialize", ce.Operation)
}

func TestCeremonyService_CeremonyStatus_Success(t *testing.T) {
	stub := newStubCeremonyClient()
	svc := NewCeremonyService(stub, nil, slog.Default())

	resp, err := svc.CeremonyStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "initialized", resp.State)
}

func TestCeremonyService_CeremonyStatus_Error(t *testing.T) {
	stub := newStubCeremonyClient()
	stub.statusErr = errors.New("status failed")
	svc := NewCeremonyService(stub, nil, slog.Default())

	_, err := svc.CeremonyStatus(context.Background())
	require.Error(t, err)
	var ce *CeremonyError
	assert.True(t, errors.As(err, &ce))
}

func TestCeremonyService_BeginClaimCert_Success(t *testing.T) {
	stub := newStubCeremonyClient()
	svc := NewCeremonyService(stub, nil, slog.Default())

	resp, err := svc.BeginClaimCert(context.Background(), &ClaimCertBeginRequest{Username: "alice"})
	require.NoError(t, err)
	assert.Equal(t, "deadbeef", resp.NonceHex)
}

func TestCeremonyService_BeginClaimCert_Error(t *testing.T) {
	stub := newStubCeremonyClient()
	stub.claimBeginErr = errors.New("claim begin failed")
	svc := NewCeremonyService(stub, nil, slog.Default())

	_, err := svc.BeginClaimCert(context.Background(), &ClaimCertBeginRequest{Username: "alice"})
	require.Error(t, err)
	var ce *CeremonyError
	assert.True(t, errors.As(err, &ce))
}

func TestCeremonyService_CompleteClaimCert_Success(t *testing.T) {
	stub := newStubCeremonyClient()
	svc := NewCeremonyService(stub, nil, slog.Default())

	resp, err := svc.CompleteClaimCert(context.Background(), &ClaimCertCompleteRequest{
		Username:  "alice",
		NonceHex:  "deadbeef",
		Signature: "sig",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertPEM)
}

func TestCeremonyService_CompleteClaimCert_Error(t *testing.T) {
	stub := newStubCeremonyClient()
	stub.claimCompleteErr = errors.New("complete failed")
	svc := NewCeremonyService(stub, nil, slog.Default())

	_, err := svc.CompleteClaimCert(context.Background(), &ClaimCertCompleteRequest{
		Username: "alice",
	})
	require.Error(t, err)
	var ce *CeremonyError
	assert.True(t, errors.As(err, &ce))
}

func TestCeremonyService_ClaimShare_Success(t *testing.T) {
	stub := newStubCeremonyClient()
	svc := NewCeremonyService(stub, nil, slog.Default())

	begun, err := svc.BeginClaimShare(context.Background(), &BeginClaimShareRequest{Username: "alice"})
	require.NoError(t, err)
	assert.NotEmpty(t, begun.NonceHex)

	resp, err := svc.CompleteClaimShare(context.Background(), &CompleteClaimShareRequest{
		Username:  "alice",
		NonceHex:  begun.NonceHex,
		Signature: []byte("sig"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ShareJSON)
}

func TestCeremonyService_ClaimShare_Error(t *testing.T) {
	stub := newStubCeremonyClient()
	stub.claimShareErr = errors.New("claim share failed")
	svc := NewCeremonyService(stub, nil, slog.Default())

	_, err := svc.BeginClaimShare(context.Background(), &BeginClaimShareRequest{Username: "alice"})
	require.Error(t, err)

	resp, err := svc.CompleteClaimShare(context.Background(), &CompleteClaimShareRequest{Username: "alice"})
	require.Error(t, err)
	assert.Nil(t, resp, "no share material may accompany a refusal")
}

func TestCeremonyService_SignCSR_Success(t *testing.T) {
	stub := newStubCeremonyClient()
	svc := NewCeremonyService(stub, nil, slog.Default())

	resp, err := svc.SignCSR(context.Background(), &SignCSRRequest{
		Username: "alice",
		SOPin:    "pin",
		Role:     "officer",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertPEM)
}

func TestCeremonyService_SignCSR_Error(t *testing.T) {
	stub := newStubCeremonyClient()
	stub.signCSRErr = errors.New("sign csr failed")
	svc := NewCeremonyService(stub, nil, slog.Default())

	_, err := svc.SignCSR(context.Background(), &SignCSRRequest{Username: "alice"})
	require.Error(t, err)
}

// makeTestCSRPEM generates a PEM-encoded CSR for testing.
func makeTestCSRPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rawASN1, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test Cert"}},
	})
	require.NoError(t, err)

	tmpl := &x509.CertificateRequest{
		RawSubject: rawASN1,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// ==========================================================================
// caAdapter tests — use the real CA from createTestInfrastructure
// ==========================================================================

func TestCAAdapter_CACertificate(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	adapter := newCAAdapter(testCA)
	cert, err := adapter.CACertificate()
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestCAAdapter_CABundle(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	adapter := newCAAdapter(testCA)
	bundle, err := adapter.CABundle()
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
	assert.Contains(t, string(bundle), "CERTIFICATE")
}

func TestCAAdapter_SignCSR_Success(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	adapter := newCAAdapter(testCA)
	csrPEM := makeTestCSRPEM(t)
	cert, err := adapter.SignCSR(context.Background(), csrPEM, &qrdbsdk.SignCSROptions{
		ValidityDays: 30,
	})
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestCAAdapter_IssueCertificate_Success(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	adapter := newCAAdapter(testCA)
	issued, err := adapter.IssueCertificate(context.Background(), &qrdbsdk.IssueCertRequest{
		CommonName:   "test.example.com",
		ValidityDays: 30,
		SANs:         []string{"test.example.com"},
	})
	require.NoError(t, err)
	assert.NotNil(t, issued)
	assert.NotNil(t, issued.Certificate)
	assert.NotEmpty(t, issued.CertPEM)
	// KeyPEM may be empty if the CA stores private keys internally rather than returning them.
}

func TestCAAdapter_IssueCertificate_WithoutSANs(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	adapter := newCAAdapter(testCA)
	issued, err := adapter.IssueCertificate(context.Background(), &qrdbsdk.IssueCertRequest{
		CommonName:   "no-sans.example.com",
		ValidityDays: 30,
	})
	require.NoError(t, err)
	assert.NotNil(t, issued)
}

// ==========================================================================
// NewCeremonyService — with trustedCAProvider exercised through the real CA
// ==========================================================================

func TestCeremonyService_CAAdapter_WithRealCA(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	stub := newStubCeremonyClient()
	// testCA is *ca.CA cast to ca.TCGCA. The trustedCAProvider interface requires a
	// TrustedCA() method, which *ca.CA does not implement directly — so the caAdapter
	// will not be wired. This test exercises the branch where a non-nil CA is passed
	// but does not satisfy trustedCAProvider (adapter remains nil).
	svc := NewCeremonyService(stub, testCA, slog.Default())
	_ = svc // service is constructed without error; adapter is nil because *ca.CA is not trustedCAProvider
}

func TestCeremonyService_CAAdapter_NilCA(t *testing.T) {
	// When no CA is provided, CAAdapter returns nil.
	svc := NewCeremonyService(newStubCeremonyClient(), nil, slog.Default())
	assert.Nil(t, svc.CAAdapter())
}

func TestCeremonyService_CAAdapter_WithoutProvider(t *testing.T) {
	// When no CA is provided, CAAdapter returns nil.
	svc := NewCeremonyService(newStubCeremonyClient(), nil, slog.Default())
	assert.Nil(t, svc.CAAdapter())
}

// ==========================================================================
// Handlers — ListAuditLogs and GetAlgorithms
// ==========================================================================

// TestHandlers_ListAuditLogs_RouteWithoutTrail verifies the registered route
// reports that no audit trail is configured. Trail-backed coverage lives in
// handlers_audit_algorithms_test.go.
func TestHandlers_ListAuditLogs_RouteWithoutTrail(t *testing.T) {
	testCA, storageFactory, cleanup := createTestInfrastructure(t)
	defer cleanup()

	svc := NewAdminService(testCA, storageFactory, slog.Default(), "1.0.0")
	h := NewHandlers(svc, slog.Default())

	router := mux.NewRouter()
	h.RegisterRoutes(router, nil, newPermissiveGate())

	tests := []struct {
		name  string
		query string
	}{
		{"default pagination", "/admin/audit"},
		{"with pagination", "/admin/audit?page=2&per_page=10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := authenticated(httptest.NewRequest(http.MethodGet, tt.query, nil))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotImplemented, w.Code)

			var problem ProblemDetail
			require.NoError(t, json.NewDecoder(w.Body).Decode(&problem))
			assert.Equal(t, http.StatusNotImplemented, problem.Status)
		})
	}
}

func TestHandlers_GetAlgorithms(t *testing.T) {
	testCA, storageFactory, cleanup := createTestInfrastructure(t)
	defer cleanup()

	svc := NewAdminService(testCA, storageFactory, slog.Default(), "1.0.0")
	h := NewHandlers(svc, slog.Default())

	router := mux.NewRouter()
	h.RegisterRoutes(router, nil, newPermissiveGate())

	req := authenticated(httptest.NewRequest(http.MethodGet, "/admin/algorithms", nil))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp AlgorithmsResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Signing)
	assert.NotNil(t, resp.KeyEncapsulation)

	// createTestInfrastructure configures exactly one backend, so the default
	// discoverer must report that backend and no other.
	for _, info := range resp.Signing {
		assert.Equal(t, []string{"software"}, info.Backends,
			"algorithm %s must be reported against the configured backend only", info.Algorithm)
	}
}
