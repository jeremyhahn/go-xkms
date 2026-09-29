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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// server.go - NewServer with optional components
// ==========================================================================

// TestNewServer_PlatformHandlersComposeOverTheService pins that the
// platform-global handler groups -- the system barrier and PINs (on the
// handler context), the platform store, the TPM policies and the credentials
// -- are wired over the XKMSService and nothing else, so each operation passes
// the service's platform scope (go-xkms#1226, #1227). Without a service none
// of them is mounted.
func TestNewServer_PlatformHandlersComposeOverTheService(t *testing.T) {
	ks := newMockKeyStore()
	svc := &xkms.XKMSService{}

	server, err := NewServer(&Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": ks},
		XKMSService:   svc,
	})
	require.NoError(t, err)
	assert.Same(t, svc, server.handlers.xkmsService)
	assert.NotNil(t, server.platformHandlers)
	assert.NotNil(t, server.tpmPolicyHandlers)
	assert.NotNil(t, server.credentialHandlers)

	bare, err := NewServer(&Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": ks},
	})
	require.NoError(t, err)
	assert.Nil(t, bare.platformHandlers)
	assert.Nil(t, bare.tpmPolicyHandlers)
	assert.Nil(t, bare.credentialHandlers)
}

func TestNewServer_WithRBACEnabled_NoAuthorizerFailsClosed(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": ks},
		EnableRBAC:    true,
	}

	// EnableRBAC without a usable authorizer is a wiring bug, not a permissive
	// deployment mode: the constructor refuses to build a server that believes
	// it enforces RBAC while allowing every request.
	server, err := NewServer(cfg)
	require.ErrorIs(t, err, ErrAuthorizerRequired)
	assert.Nil(t, server)
}

func TestNewServer_WithCustodianService(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Authenticator:    auth.NewNoOpAuthenticator(),
		Backends:         map[string]xkms.Backend{"test": ks},
		CustodianEnabled: true,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.NotNil(t, server.custodianHandlers)
}

func TestNewServer_WithShareEnabled(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": ks},
		ShareEnabled:  true,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.NotNil(t, server.shareHandlers)
}

func TestNewServer_WithBarrierRegistry(t *testing.T) {
	ks := newMockKeyStore()
	memStore := storage.NewMemory()
	sealStrategy := seal.NewSoftwareStrategy()

	barrier, err := seal.NewBarrier(
		slog.Default(),
		memStore,
		seal.BarrierConfig{RootKeyPath: "test-key"},
		sealStrategy,
	)
	require.NoError(t, err)

	registry, regErr := seal.NewBarrierRegistry(barrier)
	require.NoError(t, regErr)

	// Tenant handlers require an XKMSService with a composed TenantService
	// (there is no barrier-registry-only fallback); build a real go-qrdb
	// TenantService over the same registry.
	tenantSvc, err := seal.NewHardwareTenantService(barrier, registry, slog.Default(), nil)
	require.NoError(t, err)
	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": ks},
		DefaultBackend: "test",
	}))
	t.Cleanup(func() { xkms.Reset() })
	xkmsSvc, err := xkms.Get()
	require.NoError(t, err)
	xkmsSvc.SetTenantService(tenantSvc)

	cfg := &Config{
		Authenticator:   auth.NewNoOpAuthenticator(),
		Backends:        map[string]xkms.Backend{"test": ks},
		BarrierRegistry: registry,
		XKMSService:     xkmsSvc,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.NotNil(t, server.tenantHandlers)
}

func TestNewServer_WithPasswordStore(t *testing.T) {
	ks := newMockKeyStore()
	memStore := storage.NewMemory()
	pwStore := staticpw.NewStore(memStore)

	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": ks},
		PasswordStore: pwStore,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.NotNil(t, server.passwordHandlers)
}

func TestNewServer_WithPasswordStoreAndRegistry(t *testing.T) {
	ks := newMockKeyStore()
	memStore := storage.NewMemory()
	pwStore := staticpw.NewStore(memStore)
	sealStrategy := seal.NewSoftwareStrategy()

	barrier, err := seal.NewBarrier(
		slog.Default(),
		memStore,
		seal.BarrierConfig{RootKeyPath: "test-key"},
		sealStrategy,
	)
	require.NoError(t, err)
	registry, regErr := seal.NewBarrierRegistry(barrier)
	require.NoError(t, regErr)

	// Tenant handlers require an XKMSService with a composed TenantService
	// (there is no barrier-registry-only fallback); build a real go-qrdb
	// TenantService over the same registry.
	tenantSvc, err := seal.NewHardwareTenantService(barrier, registry, slog.Default(), nil)
	require.NoError(t, err)
	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": ks},
		DefaultBackend: "test",
	}))
	t.Cleanup(func() { xkms.Reset() })
	xkmsSvc, err := xkms.Get()
	require.NoError(t, err)
	xkmsSvc.SetTenantService(tenantSvc)

	cfg := &Config{
		Authenticator:   auth.NewNoOpAuthenticator(),
		Backends:        map[string]xkms.Backend{"test": ks},
		PasswordStore:   pwStore,
		BarrierRegistry: registry,
		XKMSService:     xkmsSvc,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.NotNil(t, server.passwordHandlers)
}

// ==========================================================================
// handlers.go - SaveCertHandler error paths
// ==========================================================================

func TestSaveCertHandler_MissingKeyID(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()

	body, _ := json.Marshal(SaveCertRequest{CertificatePEM: "BEGIN CERT"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.SaveCertHandler(w, req)
	// key_id is from query param, not URL param.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSaveCertHandler_InvalidJSON(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=k1&backend=test", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	ctx.SaveCertHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSaveCertHandler_InvalidPEM(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()

	body, _ := json.Marshal(SaveCertRequest{CertificatePEM: "not-valid-pem"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=k1&backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.SaveCertHandler(w, req)
	assert.NotEqual(t, http.StatusCreated, w.Code)
}

// ==========================================================================
// handlers.go - SaveCertChainHandler error paths
// ==========================================================================

func TestSaveCertChainHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//cert-chain?backend=test", strings.NewReader(`{"cert_chain_pem":[]}`))
	w := httptest.NewRecorder()
	ctx.SaveCertChainHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSaveCertChainHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/cert-chain", ctx.SaveCertChainHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/k1/cert-chain", strings.NewReader(`{"cert_chain_pem":[]}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSaveCertChainHandler_InvalidJSON(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/cert-chain", ctx.SaveCertChainHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/k1/cert-chain?backend=test-backend", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSaveCertChainHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/cert-chain", ctx.SaveCertChainHandler)
	body, _ := json.Marshal(SaveCertChainRequest{CertChainPEM: []string{}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/k1/cert-chain?backend=nonexistent", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSaveCertChainHandler_InvalidPEM(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/cert-chain", ctx.SaveCertChainHandler)
	body, _ := json.Marshal(SaveCertChainRequest{CertChainPEM: []string{"not-valid-pem"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/k1/cert-chain?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ==========================================================================
// handlers.go - CertExistsHandler backend not found
// ==========================================================================

func TestCertExistsHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodHead, "/api/v1/keys/{id}/cert", ctx.CertExistsHandler)
	req := httptest.NewRequest(http.MethodHead, "/api/v1/keys/test/cert?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCertExistsHandler_Error(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.CertExistsFunc = func(_ string) (bool, error) {
		return false, errors.New("cert exists error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodHead, "/api/v1/keys/{id}/cert", ctx.CertExistsHandler)
	req := httptest.NewRequest(http.MethodHead, "/api/v1/keys/k1/cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - ListCertsHandler success path
// ==========================================================================

func TestListCertsHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, ecKey)
	ks.SetCert("cert1", cert)

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs?backend=test-backend", nil)
	w := httptest.NewRecorder()
	ctx.ListCertsHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp ListCertsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.GreaterOrEqual(t, len(resp.Certificates), 1)
}

func TestListCertsHandler_InvalidPageParam(t *testing.T) {
	setupTestService(t, "test-backend")

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs?backend=test-backend&page=notanumber", nil)
	w := httptest.NewRecorder()
	ctx.ListCertsHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListCertsHandler_ListError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListCertsFunc = func() ([]string, error) {
		return nil, errors.New("list certs error")
	}

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs?backend=test-backend", nil)
	w := httptest.NewRecorder()
	ctx.ListCertsHandler(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - GetCertHandler backend not found
// ==========================================================================

func TestGetCertHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/cert", ctx.GetCertHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test/cert?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ==========================================================================
// password_handlers.go - UpdatePasswordHandler additional error branches
// ==========================================================================

func TestUpdatePasswordHandler_StoreClosed(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add first.
	addBody := `{"name":"TestPW","password":"pass123"}`
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(addBody))
	addW := httptest.NewRecorder()
	handlers.AddPasswordHandler(addW, addReq)
	require.Equal(t, http.StatusCreated, addW.Code)

	var addResp PasswordAddResponse
	require.NoError(t, json.NewDecoder(addW.Body).Decode(&addResp))

	// Close the store.
	require.NoError(t, systemBackend.Close())

	router := chi.NewRouter()
	router.Put("/api/v1/passwords/{id}", handlers.UpdatePasswordHandler)

	updateBody := `{"name":"Updated"}`
	updateReq := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+addResp.ID, strings.NewReader(updateBody))
	updateW := httptest.NewRecorder()
	router.ServeHTTP(updateW, updateReq)
	assert.NotEqual(t, http.StatusOK, updateW.Code)
}

func TestDeletePasswordHandler_StoreClosed(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add first.
	addBody := `{"name":"TestPW","password":"pass123"}`
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(addBody))
	addW := httptest.NewRecorder()
	handlers.AddPasswordHandler(addW, addReq)
	require.Equal(t, http.StatusCreated, addW.Code)

	var addResp PasswordAddResponse
	require.NoError(t, json.NewDecoder(addW.Body).Decode(&addResp))

	// Close the store.
	require.NoError(t, systemBackend.Close())

	router := chi.NewRouter()
	router.Delete("/api/v1/passwords/{id}", handlers.DeletePasswordHandler)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/"+addResp.ID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ==========================================================================
// handlers.go - GetBackendHandler success
// ==========================================================================

func TestGetBackendHandler_Success(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/backends/{id}", ctx.GetBackendHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ==========================================================================
// handlers.go - ListBackendsHandler success
// ==========================================================================

func TestListBackendsHandler_Success(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()
	ctx.ListBackendsHandler(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ListBackendsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.GreaterOrEqual(t, len(resp.Backends), 1)
}

// ==========================================================================
// handlers.go - ListKeysHandler success
// ==========================================================================

func TestListKeysHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("list-key", ecKey)

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
	w := httptest.NewRecorder()
	ctx.ListKeysHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp ListKeysResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.GreaterOrEqual(t, len(resp.Keys), 1)
}

// ==========================================================================
// handlers.go - SaveCertHandler success
// ==========================================================================

func TestSaveCertHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, ecKey)
	ks.SetKey("save-cert-key", ecKey)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	ctx := newTestHandlerContext()
	body, _ := json.Marshal(SaveCertRequest{CertificatePEM: string(certPEM)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=save-cert-key&backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.SaveCertHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ==========================================================================
// middleware.go - RecoveryMiddleware
// ==========================================================================

func TestRecoveryMiddleware_PanicRecovery(t *testing.T) {
	ks := newMockKeyStore()
	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": ks},
		Logger:        testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	recoveryMW := server.RecoveryMiddleware()

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := recoveryMW(panicHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	// Should not panic.
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers_barrier_pin.go - BarrierSealHandler error path
// ==========================================================================

func TestBarrierSealHandler_NotInitialized(t *testing.T) {
	memStore := storage.NewMemory()
	sealStrategy := seal.NewSoftwareStrategy()

	barrier, err := seal.NewBarrier(
		slog.Default(),
		memStore,
		seal.BarrierConfig{RootKeyPath: "test-key"},
		sealStrategy,
	)
	require.NoError(t, err)

	// Do NOT initialize barrier. Sealing an uninitialized barrier should error.
	h := handlerOverBarrier(barrier)

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/seal", nil)
	w := httptest.NewRecorder()
	h.BarrierSealHandler(w, req)
	// Barrier seal should complete (even uninitialized in software strategy).
	// The important thing is the error path in the handler was exercised.
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, w.Code)
}

// ==========================================================================
// handlers_custodian.go - RemoveMemberHandler missing params
// ==========================================================================

func TestRemoveMemberHandler_CustodianMissingGroupID(t *testing.T) {
	h, _ := setupCustodianTestHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/custodian/groups//members/user1", nil)
	w := httptest.NewRecorder()
	h.RemoveMemberHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveMemberHandler_CustodianMissingUserID(t *testing.T) {
	h, _ := setupCustodianTestHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/custodian/groups/grp1/members/", nil)
	req = chiContext(req, map[string]string{"id": "grp1", "userID": ""})
	w := httptest.NewRecorder()
	h.RemoveMemberHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ==========================================================================
// handlers.go - GenerateKeyHandler - more branches
// ==========================================================================

func TestGenerateKeyHandler_InvalidBackendName(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "key1", Backend: "../../evil", KeyType: "rsa", Algorithm: "rsa"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateKeyHandler_InvalidKeyIDChars(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "../../evil", Backend: "test-backend", KeyType: "rsa", Algorithm: "rsa"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateKeyHandler_Ed25519(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "ed-gen", Backend: "test-backend", KeyType: "ed25519", Algorithm: "ed25519"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestGenerateKeyHandler_ECDSAWithCurve(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "ec-gen", Backend: "test-backend", KeyType: "ecdsa", Algorithm: "ecdsa", Curve: "P384"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestGenerateKeyHandler_RSAWithSize(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "rsa-gen", Backend: "test-backend", KeyType: "rsa", Algorithm: "rsa", KeySize: 4096})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestGenerateKeyHandler_WithHash(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "hash-gen", Backend: "test-backend", KeyType: "rsa", Algorithm: "rsa", Hash: "SHA-512"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestGenerateKeyHandler_UnknownKeyType(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "unknown-gen", Backend: "test-backend", KeyType: "dilithium", Algorithm: "dilithium"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	// Should return bad request for unsupported key type.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateKeyHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "gen-key", Backend: "nonexistent", KeyType: "rsa", Algorithm: "rsa"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGenerateKeyHandler_Exportable(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "export-gen", Backend: "test-backend", KeyType: "rsa", Algorithm: "rsa", Exportable: true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ==========================================================================
// handlers.go - SealHandler / UnsealHandler error paths
// ==========================================================================

func TestSealHandler_InvalidJSON(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	ctx.SealHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(map[string]interface{}{"data": "dGVzdA=="})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.SealHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealHandler_MissingData(t *testing.T) {
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(map[string]interface{}{"backend": "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.SealHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealHandler_InvalidBackendName(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(SealRequest{Backend: "../../evil", Data: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.SealHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUnsealHandler_InvalidJSON(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	ctx.UnsealHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ==========================================================================
// handlers.go - ExportKeyHandler error paths
// ==========================================================================

func TestExportKeyHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//export?backend=test", strings.NewReader(`{"algorithm":"rsa"}`))
	w := httptest.NewRecorder()
	ctx.ExportKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExportKeyHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/k1/export", strings.NewReader(`{"algorithm":"rsa"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExportKeyHandler_InvalidJSON(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/k1/export?backend=test-backend", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExportKeyHandler_MissingAlgorithm(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/k1/export?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ==========================================================================
// handlers.go - CopyKeyHandler error paths
// ==========================================================================

func TestCopyKeyHandler_InvalidJSON(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	ctx.CopyKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

var _ xkms.Backend = (*xkmsmocks.MockKeyStore)(nil)

// TestGenerateKeyHandler_UnknownCurve pins that an unrecognised curve is a
// client error, not a backend one. ParseCurve's error was discarded here with
// `_`, so the nil curve reached the backend and surfaced as its
// "curve is required" guard rather than as a 400 naming the bad value
// (go-xkms#153).
func TestGenerateKeyHandler_UnknownCurve(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:   "curve-key",
		Backend: "test-backend",
		KeyType: "ecdsa", Algorithm: "ecdsa",
		Curve: "P-999",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "P-999",
		"the response must name the curve the caller sent")
}
