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
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testUserPIN is the PIN the stub servicer treats as provisioned and correct.
const testUserPIN = "123456"

// unlockServicerStub stands in for *xkms.XKMSService in password handler tests.
// It reproduces XKMSService.PasswordStoreUnlock's contract: the user PIN is
// verified before the tenant store is unlocked, and every rejection path
// returns the same typed sentinel the real servicer returns. The real PIN
// verification itself is covered in pkg/xkms; what these tests must pin is
// that the handler routes through the servicer at all, so that a rejection
// leaves the store locked.
type unlockServicerStub struct {
	manager *staticpw.TenantPasswordStoreManager

	// provisionedPIN is the PIN the deployment has set. An empty value models
	// a deployment with no PIN backend or no user PIN.
	provisionedPIN string

	// called records whether the handler delegated to the servicer at all.
	called bool
}

func (s *unlockServicerStub) PasswordStoreSetAccessMode(_ context.Context, _ *transport.PasswordStoreSetAccessModeRequest) error {
	return nil
}

func (s *unlockServicerStub) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	s.called = true

	if s.provisionedPIN == "" {
		return xkms.ErrPasswordStoreUserPINNotProvisioned
	}
	if req.UserPIN == "" {
		return xkms.ErrPasswordStoreUserPINRequired
	}
	if req.UserPIN != s.provisionedPIN {
		return errors.New("pin: verification failed, 2 attempts remaining")
	}

	identity := auth.GetIdentity(ctx)
	if identity == nil || identity.TenantID == "" {
		return staticpw.ErrInvalidTenantID
	}
	return s.manager.UnlockTenant(identity.TenantID)
}

// PasswordStoreLock mirrors XKMSService.PasswordStoreLock: locking needs no
// credential, so it delegates to the manager directly once a tenant identity
// is established.
func (s *unlockServicerStub) PasswordStoreLock(ctx context.Context) error {
	identity := auth.GetIdentity(ctx)
	if identity == nil || identity.TenantID == "" {
		return staticpw.ErrInvalidTenantID
	}
	return s.manager.LockTenant(identity.TenantID)
}

// PasswordStoreStatus mirrors XKMSService.PasswordStoreStatus: a tenant
// identity gets that tenant's status through the manager, and its absence
// gets the system-level fallback.
func (s *unlockServicerStub) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	identity := auth.GetIdentity(ctx)
	if identity != nil && identity.TenantID != "" {
		status, err := s.manager.TenantStoreStatus(identity.TenantID)
		if err != nil {
			return nil, err
		}
		return &transport.PasswordStoreStatusResponse{
			AccessMode:    "tenant",
			IsLocked:      status.IsLocked,
			BarrierSealed: status.BarrierSealed,
			PasswordCount: status.PasswordCount,
		}, nil
	}

	return &transport.PasswordStoreStatusResponse{
		AccessMode:   "direct",
		IsLocked:     false,
		AutoUnsealed: true,
	}, nil
}

// newUnlockHandlers builds password handlers wired to a stub servicer holding
// a provisioned PIN, which is the configuration a real deployment has.
func newUnlockHandlers(store staticpw.Store, manager *staticpw.TenantPasswordStoreManager) (*PasswordHandlers, *unlockServicerStub) {
	servicer := &unlockServicerStub{manager: manager, provisionedPIN: testUserPIN}
	handlers := NewPasswordHandlers(store, manager)
	handlers.SetServicer(servicer)
	return handlers, servicer
}

// unlockBody renders an unlock request body carrying the given PIN.
func unlockBody(pin string) string {
	return `{"user_pin":"` + pin + `"}`
}

// unlockTenantForTest opens the tenant store as a test precondition. Tests
// whose subject is some other handler use this instead of driving
// UnlockHandler, so they do not have to model the unlock credential flow that
// UnlockHandler's own tests cover.
func unlockTenantForTest(t *testing.T, manager *staticpw.TenantPasswordStoreManager, tenantID string) {
	t.Helper()
	require.NoError(t, manager.UnlockTenant(tenantID))
}

// testPasswordSetup creates a BarrierRegistry with one registered, initialized,
// and unsealed tenant. Returns the registry, the system store, and the manager.
func testPasswordSetup(t *testing.T) (*seal.BarrierRegistry, staticpw.Store, *staticpw.TenantPasswordStoreManager) {
	t.Helper()

	// Create a system barrier with a software strategy.
	sysBackend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	sysBarrier, err := seal.NewBarrier(
		slog.Default(),
		sysBackend,
		seal.BarrierConfig{
			RootKeyPath:     "root-key",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	sysCreds := seal.MustCredentials([]byte("test-pw"))
	defer sysCreds.Secret.Destroy()
	err = sysBarrier.Initialize(ctx, sysCreds)
	require.NoError(t, err)

	// Create a registry and register a tenant.
	registry, err := seal.NewBarrierRegistry(sysBarrier)
	require.NoError(t, err)

	_, err = registry.RegisterTenant("tenant-1")
	require.NoError(t, err)
	tenantCreds := seal.MustCredentials([]byte("tenant-pw"))
	defer tenantCreds.Secret.Destroy()
	err = registry.InitializeTenant(ctx, "tenant-1", tenantCreds)
	require.NoError(t, err)

	// Create a system password store.
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)

	// Create the manager.
	manager, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore)
	require.NoError(t, err)

	return registry, systemStore, manager
}

// requestWithTenantIdentity creates an HTTP request with a tenant identity in context.
func requestWithTenantIdentity(method, url string, body string, tenantID string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, url, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	identity := &auth.Identity{Subject: "test-user", TenantID: tenantID}
	ctx := auth.WithIdentity(req.Context(), identity)
	return req.WithContext(ctx)
}

// passwordIDPath constructs a URL-safe path for a password ID. The IDs
// generated by staticpw.GenerateID may contain spaces or other characters
// that are not valid in raw URL paths, so they must be percent-encoded.
func passwordIDPath(base, id string) string {
	return base + url.PathEscape(id)
}

// --- UnlockHandler tests ---

func TestUnlockHandler_Success(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody(testUserPIN), "tenant-1")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.False(t, resp.IsLocked)
	assert.False(t, resp.BarrierSealed)
	assert.Equal(t, "Store unlocked successfully", resp.Message)
}

func TestUnlockHandler_NoManager(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", "", "tenant-1")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "server integration")
}

func TestUnlockHandler_NoIdentity(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// No identity in context.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "Tenant identity required")
}

func TestUnlockHandler_TenantSealed(t *testing.T) {
	registry, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// Seal the tenant's barrier so unlock fails.
	err := registry.SealTenant("tenant-1")
	require.NoError(t, err)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody(testUserPIN), "tenant-1")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]string
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "sealed")
}

func TestUnlockHandler_AlreadyUnlocked(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// First unlock.
	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody(testUserPIN), "tenant-1")
	w := httptest.NewRecorder()
	handlers.UnlockHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Second unlock should return conflict (already unlocked).
	req2 := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody(testUserPIN), "tenant-1")
	w2 := httptest.NewRecorder()
	handlers.UnlockHandler(w2, req2)

	assert.Equal(t, http.StatusConflict, w2.Code)

	var resp map[string]string
	err := json.NewDecoder(w2.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "already unlocked")
}

// TestUnlockHandler_NoPINIsRejected is the regression test for the unlock
// bypass: the handler used to call TenantPasswordStoreManager.UnlockTenant
// directly, so any authenticated tenant user could open the tenant password
// store with no credential whatsoever. The handler must now route through the
// servicer, and a rejected unlock must leave the store locked.
func TestUnlockHandler_NoPINIsRejected(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, servicer := newUnlockHandlers(systemStore, manager)

	// No body at all: an unlock attempt carrying no PIN.
	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", "", "tenant-1")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.True(t, servicer.called, "handler must delegate to the servicer, not unlock directly")

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "User PIN is required")

	// The critical assertion: the store must still be locked.
	status, err := manager.TenantStoreStatus("tenant-1")
	require.NoError(t, err)
	assert.True(t, status.IsLocked, "a rejected unlock must leave the store locked")
}

// TestUnlockHandler_WrongPINIsRejected proves a bad PIN is reported as an
// authentication failure and does not leak the PIN backend's message, which
// can carry retry counters and lockout state.
func TestUnlockHandler_WrongPINIsRejected(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody("999999"), "tenant-1")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "User PIN verification failed", resp["error"])
	assert.NotContains(t, resp["error"], "attempts remaining")

	status, err := manager.TenantStoreStatus("tenant-1")
	require.NoError(t, err)
	assert.True(t, status.IsLocked, "a rejected unlock must leave the store locked")
}

// TestUnlockHandler_UnprovisionedPINIsRejected proves a deployment with no
// user PIN reports the condition instead of unlocking without a credential.
func TestUnlockHandler_UnprovisionedPINIsRejected(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	servicer := &unlockServicerStub{manager: manager} // no provisioned PIN
	handlers := NewPasswordHandlers(systemStore, manager)
	handlers.SetServicer(servicer)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody(testUserPIN), "tenant-1")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusPreconditionFailed, w.Code)

	status, err := manager.TenantStoreStatus("tenant-1")
	require.NoError(t, err)
	assert.True(t, status.IsLocked, "a rejected unlock must leave the store locked")
}

// TestUnlockHandler_NoServicerDoesNotUnlock proves the handler fails closed
// when the composition root did not wire the service layer: it must report
// "requires server integration" rather than falling back to the uncredentialed
// manager path.
func TestUnlockHandler_NoServicerDoesNotUnlock(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager) // servicer deliberately unset

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody(testUserPIN), "tenant-1")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)

	status, err := manager.TenantStoreStatus("tenant-1")
	require.NoError(t, err)
	assert.True(t, status.IsLocked, "an unwired servicer must not unlock the store")
}

func TestUnlockHandler_TenantNotFound(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// Use a tenant ID that is not registered in the registry.
	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody(testUserPIN), "nonexistent-tenant")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "Tenant not found")
}

func TestUnlockHandler_EmptyTenantID(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// Identity with empty TenantID.
	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", "", "")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUnlockHandler_SystemTenantIDRejected proves the password store unlock
// path treats a "system"-tenant caller the same as an empty-tenant caller: it
// has no per-tenant password store to unlock, so it is rejected rather than
// attempting (and mis-resolving) a scoped store for the reserved system
// tenant. This is the opposite polarity from the tenant *scope gates*
// (middleware_tenant.go, interceptor_tenant.go): those pass a system-scoped
// caller through, this rejects it, because a concrete tenant store is
// required here.
func TestUnlockHandler_SystemTenantIDRejected(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/unlock", unlockBody(testUserPIN), "system")
	w := httptest.NewRecorder()

	handlers.UnlockHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- LockHandler tests ---

func TestLockHandler_Success(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// Unlock first (precondition; the unlock credential flow itself is covered
	// by UnlockHandler's own tests).
	unlockTenantForTest(t, manager, "tenant-1")

	// Now lock.
	req2 := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/lock", "", "tenant-1")
	w2 := httptest.NewRecorder()
	handlers.LockHandler(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)

	var resp PasswordStoreStatusResponse
	err := json.NewDecoder(w2.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.True(t, resp.IsLocked)
	assert.Equal(t, "Store locked successfully", resp.Message)
}

// TestLockHandler_NoServicer proves the handler reports the precise
// capability error rather than a generic failure when the composition root
// did not wire the service layer at all.
func TestLockHandler_NoServicer(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/lock", "", "tenant-1")
	w := httptest.NewRecorder()

	handlers.LockHandler(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "server integration")
}

// TestLockHandler_ManagerWithoutServicer proves that a locally-held
// TenantPasswordStoreManager with no servicer wired does not, on its own,
// make lock available: the handler must go through the servicer, which is
// the single source of truth for session state (see UnlockHandler).
func TestLockHandler_ManagerWithoutServicer(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager) // servicer deliberately unset

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/lock", "", "tenant-1")
	w := httptest.NewRecorder()

	handlers.LockHandler(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestLockHandler_AlreadyLocked(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// Tenant starts locked. Locking again should return conflict.
	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/lock", "", "tenant-1")
	w := httptest.NewRecorder()

	handlers.LockHandler(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "already locked")
}

// TestLockHandler_SystemTenantIDRejected mirrors
// TestUnlockHandler_SystemTenantIDRejected for the lock path.
func TestLockHandler_SystemTenantIDRejected(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/lock", "", "system")
	w := httptest.NewRecorder()

	handlers.LockHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLockHandler_NoIdentity(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	w := httptest.NewRecorder()

	handlers.LockHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLockHandler_TenantNotFound(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/lock", "", "nonexistent-tenant")
	w := httptest.NewRecorder()

	handlers.LockHandler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- StatusHandler tests ---

func TestStatusHandler_WithTenant(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	req := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords/status", "", "tenant-1")
	w := httptest.NewRecorder()

	handlers.StatusHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.True(t, resp.IsLocked) // starts locked
	assert.False(t, resp.BarrierSealed)
	assert.Equal(t, "Password store status retrieved", resp.Message)
}

// TestStatusHandler_NoServicer proves the handler falls back to a generic
// "available" answer, rather than erroring, when the composition root did
// not wire the service layer at all.
func TestStatusHandler_NoServicer(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
	w := httptest.NewRecorder()

	handlers.StatusHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.Equal(t, "Password store is available", resp.Message)
}

// TestStatusHandler_NoTenant proves that, with a servicer wired, a caller
// with no tenant identity gets the servicer's system-level status rather
// than the generic no-servicer fallback message.
func TestStatusHandler_NoTenant(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// No identity in context triggers system fallback.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
	w := httptest.NewRecorder()

	handlers.StatusHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.False(t, resp.IsLocked)
	assert.Equal(t, "Password store status retrieved", resp.Message)
}

func TestStatusHandler_SystemFallbackEmptyTenantID(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	// Identity with empty TenantID uses system fallback.
	req := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords/status", "", "")
	w := httptest.NewRecorder()

	handlers.StatusHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.False(t, resp.IsLocked)
	assert.Equal(t, "Password store status retrieved", resp.Message)
}

func TestStatusHandler_TenantNotFound(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers, _ := newUnlockHandlers(systemStore, manager)

	req := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords/status", "", "nonexistent")
	w := httptest.NewRecorder()

	handlers.StatusHandler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "Tenant not found")
}

// --- AddPasswordHandler tests ---

func TestAddPasswordHandler_WithTenant(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)

	// Unlock tenant first (precondition; the unlock credential flow itself is
	// covered by UnlockHandler's own tests).
	unlockTenantForTest(t, manager, "tenant-1")

	// Add a password.
	body := `{"name":"MyLogin","username":"user@example.com","password":"s3cr3t!"}`
	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords", body, "tenant-1")
	w := httptest.NewRecorder()

	handlers.AddPasswordHandler(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp PasswordAddResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "MyLogin", resp.Name)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "Password added successfully", resp.Message)
}

func TestAddPasswordHandler_StoreLocked(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)

	// Do not unlock. Store is locked by default.
	body := `{"name":"MyLogin","username":"user@example.com","password":"s3cr3t!"}`
	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords", body, "tenant-1")
	w := httptest.NewRecorder()

	handlers.AddPasswordHandler(w, req)

	assert.Equal(t, http.StatusLocked, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "locked")
}

func TestAddPasswordHandler_InvalidBody(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader("invalid-json"))
	w := httptest.NewRecorder()

	handlers.AddPasswordHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddPasswordHandler_EmptyName(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	body := `{"name":"","password":"s3cr3t!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body))
	w := httptest.NewRecorder()

	handlers.AddPasswordHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "Name is required")
}

func TestAddPasswordHandler_EmptyPassword(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	body := `{"name":"MyLogin","password":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body))
	w := httptest.NewRecorder()

	handlers.AddPasswordHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "Password is required")
}

func TestAddPasswordHandler_Duplicate(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	body := `{"name":"MyLogin","password":"s3cr3t!"}`
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body))
	w1 := httptest.NewRecorder()
	handlers.AddPasswordHandler(w1, req1)
	require.Equal(t, http.StatusCreated, w1.Code)

	// Add the same entry again.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body))
	w2 := httptest.NewRecorder()
	handlers.AddPasswordHandler(w2, req2)

	assert.Equal(t, http.StatusConflict, w2.Code)
}

// --- resolveStore tests ---

func TestResolveStore_SystemFallback(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// No manager, no identity. Falls back to system store.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
	w := httptest.NewRecorder()

	handlers.ListPasswordsHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordListResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Total)
}

func TestResolveStore_TenantWithManager(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)

	// Unlock the tenant first (precondition; the unlock credential flow itself
	// is covered by UnlockHandler's own tests).
	unlockTenantForTest(t, manager, "tenant-1")

	// List should use tenant store (empty).
	req := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords", "", "tenant-1")
	w := httptest.NewRecorder()

	handlers.ListPasswordsHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordListResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Total)
}

func TestResolveStore_NoStoreConfigured(t *testing.T) {
	handlers := NewPasswordHandlers(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
	w := httptest.NewRecorder()

	handlers.ListPasswordsHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "not configured")
}

// --- ListPasswordsHandler tests ---

func TestListPasswordsHandler_Success(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add entries.
	body := `{"name":"Entry1","password":"pass1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body))
	w := httptest.NewRecorder()
	handlers.AddPasswordHandler(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	body2 := `{"name":"Entry2","password":"pass2"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body2))
	w2 := httptest.NewRecorder()
	handlers.AddPasswordHandler(w2, req2)
	require.Equal(t, http.StatusCreated, w2.Code)

	// List.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
	listW := httptest.NewRecorder()
	handlers.ListPasswordsHandler(listW, listReq)

	assert.Equal(t, http.StatusOK, listW.Code)

	var resp PasswordListResponse
	err := json.NewDecoder(listW.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Passwords, 2)
}

func TestListPasswordsHandler_EmptyList(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
	w := httptest.NewRecorder()
	handlers.ListPasswordsHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordListResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Total)
}

func TestListPasswordsHandler_ByFolder(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add entries to different folders.
	body1 := `{"name":"WorkEntry","password":"pass1","folder_path":"work"}`
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body1))
	w1 := httptest.NewRecorder()
	handlers.AddPasswordHandler(w1, req1)
	require.Equal(t, http.StatusCreated, w1.Code)

	body2 := `{"name":"PersonalEntry","password":"pass2","folder_path":"personal"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body2))
	w2 := httptest.NewRecorder()
	handlers.AddPasswordHandler(w2, req2)
	require.Equal(t, http.StatusCreated, w2.Code)

	// List by folder.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?folder=work", nil)
	listW := httptest.NewRecorder()
	handlers.ListPasswordsHandler(listW, listReq)

	assert.Equal(t, http.StatusOK, listW.Code)

	var resp PasswordListResponse
	err := json.NewDecoder(listW.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, "WorkEntry", resp.Passwords[0].Name)
}

// --- GetPasswordHandler tests ---

func TestGetPasswordHandler_Success(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add an entry first.
	body := `{"name":"MyLogin","username":"user@example.com","password":"s3cr3t!","url":"https://example.com","notes":"test notes"}`
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body))
	addW := httptest.NewRecorder()
	handlers.AddPasswordHandler(addW, addReq)
	require.Equal(t, http.StatusCreated, addW.Code)

	var addResp PasswordAddResponse
	err := json.NewDecoder(addW.Body).Decode(&addResp)
	require.NoError(t, err)

	// Get the entry via chi router.
	router := chi.NewRouter()
	router.Get("/api/v1/passwords/{id}", handlers.GetPasswordHandler)

	getReq := httptest.NewRequest(http.MethodGet, passwordIDPath("/api/v1/passwords/", addResp.ID), nil)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)

	assert.Equal(t, http.StatusOK, getW.Code)

	var getResp PasswordDetailResponse
	err = json.NewDecoder(getW.Body).Decode(&getResp)
	require.NoError(t, err)
	assert.Equal(t, "MyLogin", getResp.Name)
	assert.Equal(t, "user@example.com", getResp.Username)
	assert.Equal(t, "s3cr3t!", getResp.Password)
	assert.Equal(t, "https://example.com", getResp.URL)
	assert.Equal(t, "test notes", getResp.Notes)
}

func TestGetPasswordHandler_NotFound(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	router := chi.NewRouter()
	router.Get("/api/v1/passwords/{id}", handlers.GetPasswordHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- UpdatePasswordHandler tests ---

func TestUpdatePasswordHandler_Success(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add an entry first.
	addBody := `{"name":"Original","username":"user","password":"pass123"}`
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(addBody))
	addW := httptest.NewRecorder()
	handlers.AddPasswordHandler(addW, addReq)
	require.Equal(t, http.StatusCreated, addW.Code)

	var addResp PasswordAddResponse
	err := json.NewDecoder(addW.Body).Decode(&addResp)
	require.NoError(t, err)

	// Update the entry.
	router := chi.NewRouter()
	router.Put("/api/v1/passwords/{id}", handlers.UpdatePasswordHandler)

	updateBody := `{"name":"Updated","password":"new-pass"}`
	updateReq := httptest.NewRequest(http.MethodPut, passwordIDPath("/api/v1/passwords/", addResp.ID), strings.NewReader(updateBody))
	updateW := httptest.NewRecorder()
	router.ServeHTTP(updateW, updateReq)

	assert.Equal(t, http.StatusOK, updateW.Code)

	var updateResp PasswordUpdateResponse
	err = json.NewDecoder(updateW.Body).Decode(&updateResp)
	require.NoError(t, err)
	assert.Equal(t, "Updated", updateResp.Name)
	assert.Equal(t, "Password updated successfully", updateResp.Message)
}

func TestUpdatePasswordHandler_NotFound(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	router := chi.NewRouter()
	router.Put("/api/v1/passwords/{id}", handlers.UpdatePasswordHandler)

	body := `{"name":"Updated"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/nonexistent", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- DeletePasswordHandler tests ---

func TestDeletePasswordHandler_Success(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add an entry first.
	addBody := `{"name":"ToDelete","password":"pass123"}`
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(addBody))
	addW := httptest.NewRecorder()
	handlers.AddPasswordHandler(addW, addReq)
	require.Equal(t, http.StatusCreated, addW.Code)

	var addResp PasswordAddResponse
	err := json.NewDecoder(addW.Body).Decode(&addResp)
	require.NoError(t, err)

	// Delete the entry.
	router := chi.NewRouter()
	router.Delete("/api/v1/passwords/{id}", handlers.DeletePasswordHandler)

	deleteReq := httptest.NewRequest(http.MethodDelete, passwordIDPath("/api/v1/passwords/", addResp.ID), nil)
	deleteW := httptest.NewRecorder()
	router.ServeHTTP(deleteW, deleteReq)

	assert.Equal(t, http.StatusOK, deleteW.Code)

	var deleteResp PasswordDeleteResponse
	err = json.NewDecoder(deleteW.Body).Decode(&deleteResp)
	require.NoError(t, err)
	assert.Equal(t, "Password deleted successfully", deleteResp.Message)
}

func TestDeletePasswordHandler_NotFound(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	router := chi.NewRouter()
	router.Delete("/api/v1/passwords/{id}", handlers.DeletePasswordHandler)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- GeneratePasswordHandler tests ---

func TestGeneratePasswordHandler_Success(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	body := `{"length":32}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", strings.NewReader(body))
	w := httptest.NewRecorder()

	handlers.GeneratePasswordHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordGenerateResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Len(t, resp.Password, 32)
	assert.Equal(t, 32, resp.Length)
}

func TestGeneratePasswordHandler_DefaultLength(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", strings.NewReader(body))
	w := httptest.NewRecorder()

	handlers.GeneratePasswordHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordGenerateResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, staticpw.DefaultLength, resp.Length)
	assert.Len(t, resp.Password, staticpw.DefaultLength)
}

func TestGeneratePasswordHandler_InvalidLength(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	body := `{"length":3}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", strings.NewReader(body))
	w := httptest.NewRecorder()

	handlers.GeneratePasswordHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGeneratePasswordHandler_InvalidBody(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", strings.NewReader("bad-json"))
	w := httptest.NewRecorder()

	handlers.GeneratePasswordHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- SetAccessModeHandler tests ---

// accessModeHandlers builds password handlers backed by a real XKMSService so
// the endpoint is exercised through the service layer rather than a mock.
func accessModeHandlers(t *testing.T) *PasswordHandlers {
	t.Helper()

	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)

	backendStore, ok := systemStore.(*staticpw.BackendStore)
	require.True(t, ok)

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	t.Cleanup(xkms.Reset)

	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetPasswordStore(backendStore)
	svc.SetPasswordStoreManager(manager)
	handlers.SetServicer(svc)

	return handlers
}

func TestSetAccessModeHandler_SetsSessionModeForTenant(t *testing.T) {
	handlers := accessModeHandlers(t)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/access-mode",
		`{"mode": "session_based"}`, "tenant-1")
	w := httptest.NewRecorder()

	handlers.SetAccessModeHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreAccessModeResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, string(staticpw.AccessSessionBased), resp.Mode)

	// The service layer agrees the tenant store is in the mode just set.
	svc, err := xkms.Get()
	require.NoError(t, err)
	mode, err := svc.PasswordAccessMode(req.Context())
	require.NoError(t, err)
	assert.Equal(t, staticpw.AccessSessionBased, mode)
}

// TestSetAccessModeHandler_NoLongerHardcodedNotImplemented pins the defect
// that the endpoint answered every request with 501 regardless of input.
func TestSetAccessModeHandler_NoLongerHardcodedNotImplemented(t *testing.T) {
	handlers := accessModeHandlers(t)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/access-mode",
		`{"mode": "session_based"}`, "tenant-1")
	w := httptest.NewRecorder()

	handlers.SetAccessModeHandler(w, req)

	assert.NotEqual(t, http.StatusNotImplemented, w.Code)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetAccessModeHandler_InvalidMode(t *testing.T) {
	handlers := accessModeHandlers(t)

	for _, mode := range []string{"banana", "session-based", "direct"} {
		req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/access-mode",
			`{"mode": "`+mode+`"}`, "tenant-1")
		w := httptest.NewRecorder()

		handlers.SetAccessModeHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "mode %q", mode)
		assert.Contains(t, w.Body.String(), "Invalid access mode")
	}
}

func TestSetAccessModeHandler_MissingMode(t *testing.T) {
	handlers := accessModeHandlers(t)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/access-mode", `{}`, "tenant-1")
	w := httptest.NewRecorder()

	handlers.SetAccessModeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetAccessModeHandler_InvalidJSON(t *testing.T) {
	handlers := accessModeHandlers(t)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/access-mode", `not-json`, "tenant-1")
	w := httptest.NewRecorder()

	handlers.SetAccessModeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// A mode the wired store cannot enforce is a capability boundary, reported as
// 501 with an explanation rather than silently accepted.
func TestSetAccessModeHandler_UnsupportedModeReportsBoundary(t *testing.T) {
	handlers := accessModeHandlers(t)

	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords/access-mode",
		`{"mode": "pin_per_operation"}`, "tenant-1")
	w := httptest.NewRecorder()

	handlers.SetAccessModeHandler(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Contains(t, w.Body.String(), "cannot enforce the requested access mode")
}

func TestSetAccessModeHandler_SystemScopeReportsBoundary(t *testing.T) {
	handlers := accessModeHandlers(t)

	// No tenant identity: the request addresses the system store, which has
	// no session or PIN strategy.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/access-mode",
		strings.NewReader(`{"mode": "session_based"}`))
	w := httptest.NewRecorder()

	handlers.SetAccessModeHandler(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestSetAccessModeHandler_ServicerNotWired(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/access-mode",
		strings.NewReader(`{"mode": "session_based"}`))
	w := httptest.NewRecorder()

	handlers.SetAccessModeHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestSetAccessModeHandler_PasswordStoreNotConfigured(t *testing.T) {
	handlers := NewPasswordHandlers(nil, nil)

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	t.Cleanup(xkms.Reset)

	svc, err := xkms.Get()
	require.NoError(t, err)
	handlers.SetServicer(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/access-mode",
		strings.NewReader(`{"mode": "session_based"}`))
	w := httptest.NewRecorder()

	handlers.SetAccessModeHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// --- passwordHandleAccessModeError tests ---

func TestPasswordHandleAccessModeError_Mapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"invalid mode", xkms.ErrInvalidAccessMode, http.StatusBadRequest},
		{"nil request", xkms.ErrNilRequest, http.StatusBadRequest},
		{"not configured", xkms.ErrNotConfigured, http.StatusServiceUnavailable},
		{"capability boundary", xkms.ErrOperationNotSupported, http.StatusNotImplemented},
		{"store locked falls through to the store mapper", staticpw.ErrStoreLocked, http.StatusLocked},
		{"unknown error", errors.New("boom"), http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			passwordHandleAccessModeError(w, tc.err)
			assert.Equal(t, tc.want, w.Code)
		})
	}
}

// --- passwordHandleStoreError tests ---

func TestPasswordHandleStoreError_StoreLocked(t *testing.T) {
	w := httptest.NewRecorder()
	passwordHandleStoreError(w, staticpw.ErrStoreLocked)
	assert.Equal(t, http.StatusLocked, w.Code)
}

func TestPasswordHandleStoreError_TenantSealed(t *testing.T) {
	w := httptest.NewRecorder()
	passwordHandleStoreError(w, seal.ErrTenantSealed)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestPasswordHandleStoreError_TenantNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	passwordHandleStoreError(w, seal.ErrTenantNotFound)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPasswordHandleStoreError_NotConfigured(t *testing.T) {
	w := httptest.NewRecorder()
	passwordHandleStoreError(w, staticpw.ErrNotConfigured)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestPasswordHandleStoreError_NotOwner(t *testing.T) {
	w := httptest.NewRecorder()
	passwordHandleStoreError(w, staticpw.ErrNotOwner)
	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "Not the owner")
}

// --- passwordWriteJSONError tests ---

func TestPasswordWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	passwordWriteJSONError(w, "test error message", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "test error message", resp["error"])
}

// --- NewPasswordHandlers tests ---

func TestNewPasswordHandlers_WithManager(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)

	assert.NotNil(t, handlers)
	assert.Equal(t, systemStore, handlers.store)
	assert.Equal(t, manager, handlers.manager)
}

func TestNewPasswordHandlers_WithoutManager(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	assert.NotNil(t, handlers)
	assert.Equal(t, systemStore, handlers.store)
	assert.Nil(t, handlers.manager)
}

// --- Scope/Shared password tests ---

// unlockTenantHelper unlocks tenant-1 as a precondition for tests whose
// subject is some other handler. It opens the store through the manager rather
// than driving UnlockHandler, so these tests do not have to model the unlock
// credential flow that UnlockHandler's own tests cover.
func unlockTenantHelper(t *testing.T, handlers *PasswordHandlers) {
	t.Helper()
	require.NotNil(t, handlers.manager)
	require.NoError(t, handlers.manager.UnlockTenant("tenant-1"))
}

// addPasswordViaTenant adds a password through the REST handler with tenant identity
// and returns the PasswordAddResponse.
func addPasswordViaTenant(t *testing.T, handlers *PasswordHandlers, body string) PasswordAddResponse {
	t.Helper()
	req := requestWithTenantIdentity(http.MethodPost, "/api/v1/passwords", body, "tenant-1")
	w := httptest.NewRecorder()
	handlers.AddPasswordHandler(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var resp PasswordAddResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	return resp
}

// getPasswordViaTenant retrieves a password by ID through a chi router with tenant identity.
func getPasswordViaTenant(t *testing.T, handlers *PasswordHandlers, id string) PasswordDetailResponse {
	t.Helper()
	router := chi.NewRouter()
	router.Get("/api/v1/passwords/{id}", handlers.GetPasswordHandler)

	getReq := requestWithTenantIdentity(http.MethodGet, passwordIDPath("/api/v1/passwords/", id), "", "tenant-1")
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)
	require.Equal(t, http.StatusOK, getW.Code)

	var resp PasswordDetailResponse
	err := json.NewDecoder(getW.Body).Decode(&resp)
	require.NoError(t, err)
	return resp
}

func TestAddPasswordHandler_SharedFlag(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)
	unlockTenantHelper(t, handlers)

	// Add a shared password.
	addResp := addPasswordViaTenant(t, handlers, `{"name":"TeamAWS","password":"secret","shared":true}`)
	assert.NotEmpty(t, addResp.ID)
	assert.Equal(t, "TeamAWS", addResp.Name)

	// Retrieve and verify shared flag and owner.
	detail := getPasswordViaTenant(t, handlers, addResp.ID)
	assert.True(t, detail.Shared)
	assert.Equal(t, "test-user", detail.OwnerID)
}

func TestAddPasswordHandler_PersonalDefault(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)
	unlockTenantHelper(t, handlers)

	// Add a personal password (no shared field).
	addResp := addPasswordViaTenant(t, handlers, `{"name":"MyGmail","password":"secret"}`)
	assert.NotEmpty(t, addResp.ID)
	assert.Equal(t, "MyGmail", addResp.Name)

	// Retrieve and verify personal defaults.
	detail := getPasswordViaTenant(t, handlers, addResp.ID)
	assert.False(t, detail.Shared)
	assert.Equal(t, "test-user", detail.OwnerID)
}

func TestListPasswordsHandler_WithScope(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)
	unlockTenantHelper(t, handlers)

	// Add a shared password.
	addPasswordViaTenant(t, handlers, `{"name":"SharedPW","password":"p","shared":true}`)

	// Add a personal password.
	addPasswordViaTenant(t, handlers, `{"name":"PersonalPW","password":"p"}`)

	// List with scope=shared.
	sharedReq := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords?scope=shared", "", "tenant-1")
	sharedW := httptest.NewRecorder()
	handlers.ListPasswordsHandler(sharedW, sharedReq)
	assert.Equal(t, http.StatusOK, sharedW.Code)

	var sharedResp PasswordListResponse
	err := json.NewDecoder(sharedW.Body).Decode(&sharedResp)
	require.NoError(t, err)
	assert.Equal(t, 1, sharedResp.Total)
	require.Len(t, sharedResp.Passwords, 1)
	assert.Equal(t, "SharedPW", sharedResp.Passwords[0].Name)
	assert.True(t, sharedResp.Passwords[0].Shared)

	// List with scope=personal.
	personalReq := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords?scope=personal", "", "tenant-1")
	personalW := httptest.NewRecorder()
	handlers.ListPasswordsHandler(personalW, personalReq)
	assert.Equal(t, http.StatusOK, personalW.Code)

	var personalResp PasswordListResponse
	err = json.NewDecoder(personalW.Body).Decode(&personalResp)
	require.NoError(t, err)
	assert.Equal(t, 1, personalResp.Total)
	require.Len(t, personalResp.Passwords, 1)
	assert.Equal(t, "PersonalPW", personalResp.Passwords[0].Name)
	assert.False(t, personalResp.Passwords[0].Shared)

	// List with scope=all.
	allReq := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords?scope=all", "", "tenant-1")
	allW := httptest.NewRecorder()
	handlers.ListPasswordsHandler(allW, allReq)
	assert.Equal(t, http.StatusOK, allW.Code)

	var allResp PasswordListResponse
	err = json.NewDecoder(allW.Body).Decode(&allResp)
	require.NoError(t, err)
	assert.Equal(t, 2, allResp.Total)
}

func TestListPasswordsHandler_InvalidScope(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)
	unlockTenantHelper(t, handlers)

	// List with an invalid scope value.
	req := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords?scope=invalid", "", "tenant-1")
	w := httptest.NewRecorder()
	handlers.ListPasswordsHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "Invalid scope")
}

func TestListPasswordsHandler_ScopeOnNonScopedStore(t *testing.T) {
	// Use a simple system store with no manager (non-scoped).
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add two entries via system store (no tenant identity needed).
	body1 := `{"name":"Entry1","password":"pass1"}`
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body1))
	w1 := httptest.NewRecorder()
	handlers.AddPasswordHandler(w1, req1)
	require.Equal(t, http.StatusCreated, w1.Code)

	body2 := `{"name":"Entry2","password":"pass2"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body2))
	w2 := httptest.NewRecorder()
	handlers.AddPasswordHandler(w2, req2)
	require.Equal(t, http.StatusCreated, w2.Code)

	// List with scope=personal on a non-scoped store. Should fall back to List()
	// and return all entries.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?scope=personal", nil)
	listW := httptest.NewRecorder()
	handlers.ListPasswordsHandler(listW, listReq)

	assert.Equal(t, http.StatusOK, listW.Code)

	var resp PasswordListResponse
	err := json.NewDecoder(listW.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Passwords, 2)
}

func TestGetPasswordHandler_SharedAndOwnerFields(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)
	unlockTenantHelper(t, handlers)

	// Add a shared password.
	addResp := addPasswordViaTenant(t, handlers, `{"name":"SharedCred","password":"s3cret","shared":true}`)

	// Retrieve it and verify both OwnerID and Shared.
	detail := getPasswordViaTenant(t, handlers, addResp.ID)
	assert.Equal(t, "test-user", detail.OwnerID)
	assert.True(t, detail.Shared)
	assert.Equal(t, "SharedCred", detail.Name)
	assert.Equal(t, "s3cret", detail.Password)
}

func TestListPasswordsHandler_OwnerAndSharedInListResponse(t *testing.T) {
	_, systemStore, manager := testPasswordSetup(t)
	handlers := NewPasswordHandlers(systemStore, manager)
	unlockTenantHelper(t, handlers)

	// Add a shared password.
	addPasswordViaTenant(t, handlers, `{"name":"ListSharedPW","password":"pw","shared":true}`)

	// List all passwords.
	listReq := requestWithTenantIdentity(http.MethodGet, "/api/v1/passwords", "", "tenant-1")
	listW := httptest.NewRecorder()
	handlers.ListPasswordsHandler(listW, listReq)
	assert.Equal(t, http.StatusOK, listW.Code)

	var resp PasswordListResponse
	err := json.NewDecoder(listW.Body).Decode(&resp)
	require.NoError(t, err)
	require.Equal(t, 1, resp.Total)
	require.Len(t, resp.Passwords, 1)

	// Verify OwnerID and Shared are present in the list PasswordInfo.
	assert.Equal(t, "test-user", resp.Passwords[0].OwnerID)
	assert.True(t, resp.Passwords[0].Shared)
	assert.Equal(t, "ListSharedPW", resp.Passwords[0].Name)
}
