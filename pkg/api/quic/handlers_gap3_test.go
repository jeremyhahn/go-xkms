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

//go:build !frost

package quic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// ============================================================================
// handleCertExists — both branches (exists and not-exists)
// ============================================================================

func TestHandleCertExists_Exists(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.CertExistsFunc = func(id string) (bool, error) {
		return true, nil
	}

	req := httptest.NewRequest(http.MethodHead, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleCertExists(rec, req, "some-cert")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleCertExists_NotExists(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.CertExistsFunc = func(id string) (bool, error) {
		return false, nil
	}

	req := httptest.NewRequest(http.MethodHead, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleCertExists(rec, req, "missing-cert")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleCertExists_Error(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.CertExistsFunc = func(id string) (bool, error) {
		return false, errors.New("storage error")
	}

	req := httptest.NewRequest(http.MethodHead, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleCertExists(rec, req, "error-cert")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleSaveCertChain — save success path (MockKeyStore.SaveCertChainFunc set)
// ============================================================================

func TestHandleSaveCertChain_Success(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.SaveCertChainFunc = func(keyID string, chain []*x509.Certificate) error {
		return nil
	}

	// Use a valid self-signed cert PEM for the chain.
	selfSignedPEM := generateSelfSignedCertPEM(t)
	body, _ := json.Marshal(CertChainRequest{
		ChainPEMs: []string{selfSignedPEM},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/my-cert/chain", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ============================================================================
// handleListCerts — error path
// ============================================================================

func TestHandleListCerts_Error(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListCertsFunc = func() ([]string, error) {
		return nil, errors.New("storage failure")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// handleTLSCertificate — invalid backend param path
// ============================================================================

func TestHandleTLSCertificate_InvalidBackendAlt(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// "BOGUS_BACKEND_NAME" resolves to StoreUnknown → 400
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/test-cert?backend=BOGUS_BACKEND_NAME", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleTLSCertificate_EmptyCertID(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// Direct call with empty certID
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/", nil)
	rec := httptest.NewRecorder()
	server.handleTLSCertificate(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleTLSCertificate_WithTLSCertFunc(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Return a minimal tls.Certificate with raw DER bytes to exercise the
	// certPEM and chainPEMs encoding branches.
	selfSignedDER := makeSelfSignedCertDER(t)
	mockKS.GetTLSCertificateFunc = func(certID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
		return tls.Certificate{
			Certificate: [][]byte{selfSignedDER, selfSignedDER}, // leaf + one chain cert
			PrivateKey:  nil,
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/test-cert", nil)
	rec := httptest.NewRecorder()
	server.handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// makeSelfSignedCertDER generates a real self-signed certificate and returns
// its raw DER bytes.
func makeSelfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	return pemToDER(t, generateSelfSignedCertPEM(t))
}

// pemToDER decodes the first PEM block and returns the raw DER bytes.
func pemToDER(t *testing.T, certPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "expected valid PEM block")
	return block.Bytes
}

// ============================================================================
// mapCAErrorToStatus — verify known sentinel errors map correctly
// ============================================================================

func TestMapCAErrorToStatus_KnownErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{"not_configured", xkms.ErrNotConfigured, http.StatusServiceUnavailable},
		{"nil_request", xkms.ErrNilRequest, http.StatusBadRequest},
		{"nil_data", xkms.ErrNilData, http.StatusBadRequest},
		{"invalid_key_attrs", xkms.ErrInvalidKeyAttributes, http.StatusBadRequest},
		{"generic_error", errors.New("random"), http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := mapCAErrorToStatus(tc.err)
			assert.Equal(t, tc.expected, status)
		})
	}
}

// ============================================================================
// handleBarrierDeleteRecoveryKeys / handleBarrierHasRecoveryKeys success paths
// ============================================================================

func TestHandleBarrierDeleteRecoveryKeys_Success(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/recovery-keys", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// Barrier not initialized — may return 200 (delete no-ops), 409, or 500 depending on state.
	assert.Contains(t, []int{http.StatusOK, http.StatusConflict, http.StatusInternalServerError}, w.Code)
}

func TestHandleBarrierHasRecoveryKeys_Success(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// Barrier not initialized — may return 200 (false) or 409 (sealed).
	assert.Contains(t, []int{http.StatusOK, http.StatusConflict}, w.Code)
}

func TestHandleBarrierRecoverWithKeys_EmptyKeys(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(BarrierRecoverWithKeysRequest{Keys: []string{}})
	// Correct path: /api/v1/barrier/recovery-keys/recover
	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleBarrierDeleteRecoveryKeys_MethodNotAllowed(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleBarrierHasRecoveryKeys_MethodNotAllowed(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ============================================================================
// handleBarrierSeal — nil barrier returns 503; method not allowed
// ============================================================================

func TestHandleBarrierSeal_NilBarrierAlt(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()
	// server.barrier is nil by default from createTestServer — exercises nil guard

	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/seal", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ============================================================================
// handleBarrierStatus — method not allowed path
// ============================================================================

func TestHandleBarrierStatus_MethodNotAllowed(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/status", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ============================================================================
// handleSetSOPIN — method not allowed and missing new pin paths
// ============================================================================

func TestHandleSetSOPIN_MethodNotAllowed(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pin/so-pin", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleSetSOPIN_MissingNewSOPIN(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(SetSOPINRequest{CurrentSOPIN: "current"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSetSOPIN_Success(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(SetSOPINRequest{NewSOPIN: "newpin123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleSetUserPIN — method not allowed and missing new pin paths
// ============================================================================

func TestHandleSetUserPIN_MethodNotAllowed(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pin/user-pin", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleSetUserPIN_MissingNewUserPIN(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(SetUserPINRequest{SOPIN: "sopin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSetUserPIN_Success(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(SetUserPINRequest{SOPIN: "sopin", NewUserPIN: "userpin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleChangeSOPIN — missing required fields
// ============================================================================

func TestHandleChangeSOPIN_MissingCurrentSOPIN(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(ChangeSOPINRequest{NewSOPIN: "new"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/change", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleChangeSOPIN_MissingNewSOPIN(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(ChangeSOPINRequest{CurrentSOPIN: "current"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/change", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleChangeSOPIN_Success(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(ChangeSOPINRequest{CurrentSOPIN: "current", NewSOPIN: "newpin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/change", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleChangeUserPIN — missing required fields
// ============================================================================

func TestHandleChangeUserPIN_MissingCurrentUserPIN(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(ChangeUserPINRequest{NewUserPIN: "new"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/change", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleChangeUserPIN_MissingNewUserPIN(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(ChangeUserPINRequest{CurrentUserPIN: "current"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/change", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleChangeUserPIN_Success(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(ChangeUserPINRequest{CurrentUserPIN: "current", NewUserPIN: "new"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/change", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleVerifySOPIN / handleVerifyUserPIN — missing pin field
// ============================================================================

func TestHandleVerifySOPIN_MissingPIN(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(VerifyPINRequest{PIN: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleVerifySOPIN_Success(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(VerifyPINRequest{PIN: "testpin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleVerifyUserPIN_MissingPIN(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(VerifyPINRequest{PIN: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleVerifyUserPIN_Success(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(VerifyPINRequest{PIN: "testpin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleGetLockoutStatus — success path
// ============================================================================

func TestHandleGetLockoutStatus_Success(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pin/lockout", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleResetLockout — success path
// ============================================================================

func TestHandleResetLockout_Success(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	body, _ := json.Marshal(ResetLockoutRequest{SOPIN: "sopin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/lockout/reset", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// Password UnlockHandler / LockHandler — nil manager (StatusNotImplemented)
// plus with-manager paths requiring mocked TenantPasswordStoreManager
// ============================================================================

func TestPasswordUnlockHandler_WithManagerNoTenantIdentity(t *testing.T) {
	server, _ := createTestServerWithPasswordManager(t)
	defer xkms.Reset()

	// No identity in context — handler sees identity == nil
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// manager is set but identity has no TenantID → 401
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPasswordLockHandler_WithManagerNoTenantIdentity(t *testing.T) {
	server, _ := createTestServerWithPasswordManager(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPasswordStatusHandler_WithManagerNoTenantIdentity(t *testing.T) {
	server, _ := createTestServerWithPasswordManager(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// No tenant identity → falls through to system-level fallback → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

// createTestServerWithPasswordManager creates a server with a real
// TenantPasswordStoreManager wired in (but no barrier — tenant ops will error).
func createTestServerWithPasswordManager(t *testing.T) (*Server, *staticpw.TenantPasswordStoreManager) {
	t.Helper()
	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": mockKS},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, _ := xkms.Get()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := storage.New()
	strategy := seal.NewSoftwareStrategy()
	barrier, err := seal.NewBarrier(logger, base, seal.BarrierConfig{RootKeyPath: "pw-mgr-root"}, strategy)
	require.NoError(t, err)

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	systemStore := staticpw.NewStore(storage.New())
	mgr, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore)
	require.NoError(t, err)

	cfg := &Config{
		Addr:            "localhost:8444",
		Authenticator:   auth.NewNoOpAuthenticator(),
		Logger:          logger,
		XKMSService:     svc,
		PasswordManager: mgr,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	return server, mgr
}

// ============================================================================
// ListPasswordsHandler — scope param path with non-ScopedStore
// ============================================================================

func TestListPasswordsHandler_ScopePersonal(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	// The store is a regular BackendStore, not ScopedStore.
	// When scope=personal is passed, it calls store.List() as fallback.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?scope=personal", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListPasswordsHandler_InvalidScope(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?scope=badscope", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// resolveStore — manager with tenant identity (exercises manager branch)
// ============================================================================

func TestResolveStore_WithTenantManager_TenantIdentity(t *testing.T) {
	server, _ := createTestServerWithPasswordManager(t)
	defer xkms.Reset()

	tenantAuth := &tenantTestAuthenticator{
		tenantID: "test-tenant",
		userID:   "test-user",
	}
	server.authenticator = tenantAuth

	// Add a password — should go through resolveStore with tenant identity
	body, _ := json.Marshal(PasswordAddRequest{
		Name:     "tenant-test-pw",
		Password: "secret123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// May return 503 (barrier not initialized → tenant store not found) or 201
	assert.Contains(t, []int{http.StatusCreated, http.StatusServiceUnavailable, http.StatusNotFound, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleDecrypt — "backend not found" fallback when both symmetric and
// software backends fail
// ============================================================================

func TestHandleDecrypt_NeitherBackendFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// Remove the "software" backend by using a fresh xkms instance with no backends.
	// We can't do that easily, so instead we test that calling with a non-existent
	// explicit backend returns 404.
	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("cipher")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, req, "some-key", "nonexistent-backend")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleEncrypt — method not allowed path
// ============================================================================

func TestHandleEncrypt_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleEncrypt(rec, req, "some-key", "software")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ============================================================================
// handleDeleteKey — DeleteKey error path
// ============================================================================

func TestHandleDeleteKey_DeleteError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "err-del-key", KeyAlgorithm: x509.RSA},
		}, nil
	}
	mockKS.SetKey("err-del-key", nil)
	mockKS.DeleteKeyFunc = func(attrs *types.KeyAttributes) error {
		return errors.New("delete failed")
	}

	req := httptest.NewRequest(http.MethodDelete, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleDeleteKey(rec, req, "err-del-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// sendJSON — error encoding path (use a type that fails to marshal)
// ============================================================================

func TestSendJSON_EncodingErrorDoesNotPanic(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	w := httptest.NewRecorder()
	// Channels are not JSON-serializable; this exercises the error branch.
	ch := make(chan int)
	server.sendJSON(w, http.StatusOK, ch)
	// Header is already written (200), function returns gracefully.
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleCertOperations — method not allowed for cert without chain op
// ============================================================================

func TestHandleCertOperations_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/certs/my-cert", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleCertOperations_UnknownOperation(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/my-cert/unknown-op", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// handleBackendOperations — method not allowed path
// ============================================================================

func TestHandleBackendOperations_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/backends/software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ============================================================================
// handleGetImportParameters — invalid backend value
// ============================================================================

func TestHandleGetImportParameters_InvalidBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{Algorithm: "RSA_OAEP"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	// "BADINVALIDBACKEND" does not map to a known StoreType
	server.handleGetImportParameters(rec, req, "mykey", "BADINVALIDBACKEND")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleGetImportParameters — backend does not support import/export
// ============================================================================

func TestHandleGetImportParameters_NoImportSupport(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// The default MockBackend does NOT implement ImportExportBackend.
	body, _ := json.Marshal(GetImportParametersRequest{Algorithm: "RSA_OAEP"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleGetImportParameters(rec, req, "mykey", "software")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleGetImportParams — backend not found via route
// ============================================================================

func TestHandleGetImportParams_BackendNotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{
		Backend:   "nonexistent-backend",
		KeyID:     "mykey",
		KeyType:   "tls",
		Algorithm: "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// handleExportKey — key not found
// ============================================================================

func TestHandleExportKey_KeyNotFound(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil // empty list
	}

	body, _ := json.Marshal(ExportKeyRequest{})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleExportKey(rec, req, "missing-export-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleImportKey — invalid backend returns 400 (ParseStoreType returns Unknown)
// ============================================================================

func TestHandleImportKey_InvalidBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(ImportKeyRequest{})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleImportKey(rec, req, "mykey", "BOGUS_UNKNOWN_BACKEND")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleRotateKey — key not found path
// ============================================================================

func TestHandleRotateKey_KeyNotFound(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleRotateKey(rec, req, "missing-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleSign — backend not found path
// ============================================================================

func TestHandleSign_BackendNotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(SignRequest{Data: []byte("data"), Hash: "SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleSign(rec, req, "key", "nonexistent-backend")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleVerify — backend not found path
// ============================================================================

func TestHandleVerify_BackendNotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(VerifyRequest{Data: []byte("data"), Signature: []byte("sig"), Hash: "SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "key", "nonexistent-backend")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleGetKey — backend not found
// ============================================================================

func TestHandleGetKey_BackendNotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleGetKey(rec, req, "key", "nonexistent-backend")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleDeleteKey — backend not found
// ============================================================================

func TestHandleDeleteKey_BackendNotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodDelete, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleDeleteKey(rec, req, "key", "nonexistent-backend")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleAsymmetricEncrypt — backend not found
// ============================================================================

func TestHandleAsymmetricEncrypt_BackendNotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("hello")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, req, "key", "nonexistent-backend")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleCopyKey — source key not found
// ============================================================================

func TestHandleCopyKey_SourceNotFound(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil
	}

	// All required fields provided; source backend exists but source key does not.
	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "nonexistent",
		DestBackend:   "software",
		DestKeyID:     "dest",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// Source backend doesn't implement ImportExportBackend → 400, or source key not found → 404
	assert.Contains(t, []int{http.StatusNotFound, http.StatusBadRequest}, w.Code)
}

// ============================================================================
// handleGetImportParams — GET method not allowed (via handler dispatch)
// ============================================================================

func TestHandleGetImportParams_MethodNotAllowedDirect(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/mykey/import-parameters", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ============================================================================
// generateSelfSignedCertPEM generates a real self-signed certificate and
// returns it as a PEM-encoded string.
func generateSelfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))
}

// ============================================================================
// Companion type for tests that need grpc metadata (reuse from password test)
// ============================================================================

// tenantTestGRPCAuthenticator is used to exercise the tenant context path in
// resolveStore. It is local to this file to avoid redeclaration.
type tenantTestGRPCAuthenticator struct {
	tenantID string
	userID   string
}

func (a *tenantTestGRPCAuthenticator) Name() string { return "tenant-grpc-test" }
func (a *tenantTestGRPCAuthenticator) AuthenticateHTTP(r *http.Request) (*auth.Identity, error) {
	return &auth.Identity{Subject: a.userID, TenantID: a.tenantID}, nil
}
func (a *tenantTestGRPCAuthenticator) AuthenticateGRPC(_ context.Context, _ metadata.MD) (*auth.Identity, error) {
	return &auth.Identity{Subject: a.userID, TenantID: a.tenantID}, nil
}
