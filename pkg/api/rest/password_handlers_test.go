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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tenants and users the password tests act as.
const (
	tenantA = "tenant-1"
	tenantB = "tenant-2"
	userA   = "alice"
	userB   = "bob"
)

// testPasswordSetup creates a BarrierRegistry whose system barrier and two
// tenant barriers (tenantA, tenantB) are initialized and unsealed. Returns the
// registry, the system store, and a manager over both.
func testPasswordSetup(t *testing.T) (*seal.BarrierRegistry, *staticpw.BackendStore, *staticpw.TenantPasswordStoreManager) {
	t.Helper()

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
	require.NoError(t, sysBarrier.Initialize(ctx, sysCreds))

	registry, err := seal.NewBarrierRegistry(sysBarrier)
	require.NoError(t, err)

	for _, tenant := range []string{tenantA, tenantB} {
		_, err = registry.RegisterTenant(tenant)
		require.NoError(t, err)
		tenantCreds := seal.MustCredentials([]byte(tenant + "-pw"))
		require.NoError(t, registry.InitializeTenant(ctx, tenant, tenantCreds))
		tenantCreds.Secret.Destroy()
	}

	systemStore := staticpw.NewStore(storage.NewMemory())
	manager, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore)
	require.NoError(t, err)

	return registry, systemStore, manager
}

// passwordFixture is a real XKMSService wired with a real
// TenantPasswordStoreManager over a real BarrierRegistry, and the REST
// password routes mounted over it.
type passwordFixture struct {
	svc      *xkms.XKMSService
	registry *seal.BarrierRegistry
	manager  *staticpw.TenantPasswordStoreManager
	router   chi.Router
}

// newPasswordFixture builds a passwordFixture.
func newPasswordFixture(t *testing.T) *passwordFixture {
	t.Helper()

	registry, systemStore, manager := testPasswordSetup(t)

	svc := &xkms.XKMSService{}
	svc.SetPasswordStore(systemStore)
	svc.SetPasswordStoreManager(manager)

	return &passwordFixture{
		svc:      svc,
		registry: registry,
		manager:  manager,
		router:   passwordRouter(NewPasswordHandlers(svc)),
	}
}

// passwordRouter mounts every password route the way routes.go does.
func passwordRouter(h *PasswordHandlers) chi.Router {
	router := chi.NewRouter()
	router.Route("/api/v1/passwords", func(r chi.Router) {
		r.Post("/", h.AddPasswordHandler)
		r.Get("/", h.ListPasswordsHandler)
		r.Post("/unlock", h.UnlockHandler)
		r.Post("/lock", h.LockHandler)
		r.Get("/status", h.StatusHandler)
		r.Post("/access-mode", h.SetAccessModeHandler)
		r.Post("/generate", h.GeneratePasswordHandler)
		r.Get("/vault", h.VaultStatusHandler)
		r.Post("/vault/factors", h.VaultEnrollHandler)
		r.Put("/vault/factors/{id}", h.VaultRotateHandler)
		r.Delete("/vault/factors/{id}", h.VaultRemoveFactorHandler)
		r.Post("/vault/recover", h.VaultRecoverHandler)
		r.Get("/{id}", h.GetPasswordHandler)
		r.Put("/{id}", h.UpdatePasswordHandler)
		r.Delete("/{id}", h.DeletePasswordHandler)
	})
	return router
}

// user returns the identity of subject in tenantID.
func user(tenantID, subject string) *auth.Identity {
	return &auth.Identity{Subject: subject, TenantID: tenantID}
}

// do serves one request through the fixture's router as identity (nil for
// a request without an identity).
func (f *passwordFixture) do(t *testing.T, identity *auth.Identity, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if identity != nil {
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// entryPath returns the URL of the entry with id; generated IDs may contain
// characters that must be percent-encoded.
func entryPath(id string) string {
	return "/api/v1/passwords/" + url.PathEscape(id)
}

// passkeyFor returns identity's test passkey. Passkeys unwrap with HKDF,
// which keeps the many session opens of this suite cheap; the passphrase
// (Argon2id) path has its own tests.
func passkeyFor(identity *auth.Identity) transport.PasswordVaultCredential {
	return vaulttest.Passkey(identity.TenantID + "/" + identity.Subject)
}

// jsonBody marshals v for a request body.
func jsonBody(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return string(data)
}

// vaultStatus reads identity's vault status through the handler.
func (f *passwordFixture) vaultStatus(t *testing.T, identity *auth.Identity) transport.PasswordVaultStatusResponse {
	t.Helper()
	w := f.do(t, identity, http.MethodGet, "/api/v1/passwords/vault", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp transport.PasswordVaultStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// unlock opens identity's personal session through the handlers with the
// identity's passkey: the first time it enrolls the passkey, which
// initializes the vault and opens the session; afterwards it unlocks.
func (f *passwordFixture) unlock(t *testing.T, identity *auth.Identity) {
	t.Helper()
	if !f.vaultStatus(t, identity).Initialized {
		w := f.do(t, identity, http.MethodPost, "/api/v1/passwords/vault/factors", jsonBody(t, passkeyFor(identity)))
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		return
	}
	w := f.do(t, identity, http.MethodPost, "/api/v1/passwords/unlock", jsonBody(t, passkeyFor(identity)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// lock closes identity's personal session through the handler.
func (f *passwordFixture) lock(t *testing.T, identity *auth.Identity) {
	t.Helper()
	w := f.do(t, identity, http.MethodPost, "/api/v1/passwords/lock", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// add creates an entry as identity and returns its ID.
func (f *passwordFixture) add(t *testing.T, identity *auth.Identity, name string, shared bool) string {
	t.Helper()
	body, err := json.Marshal(PasswordAddRequest{Name: name, Password: name + "-secret", Title: name + "-title", Shared: shared})
	require.NoError(t, err)
	w := f.do(t, identity, http.MethodPost, "/api/v1/passwords/", string(body))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp PasswordAddResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp.ID)
	return resp.ID
}

// get fetches an entry as identity, returning the recorder.
func (f *passwordFixture) get(t *testing.T, identity *auth.Identity, id string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, identity, http.MethodGet, entryPath(id), "")
}

// detail fetches an entry as identity and decodes it, requiring 200.
func (f *passwordFixture) detail(t *testing.T, identity *auth.Identity, id string) PasswordDetailResponse {
	t.Helper()
	w := f.get(t, identity, id)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp PasswordDetailResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// list lists entries as identity with the given query and decodes them.
func (f *passwordFixture) list(t *testing.T, identity *auth.Identity, query string) PasswordListResponse {
	t.Helper()
	w := f.do(t, identity, http.MethodGet, "/api/v1/passwords/"+query, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp PasswordListResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// names returns the entry names in resp.
func names(resp PasswordListResponse) []string {
	out := make([]string, 0, len(resp.Passwords))
	for _, pw := range resp.Passwords {
		out = append(out, pw.Name)
	}
	return out
}

// errorMessage decodes the error field of a JSON error response.
func errorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp["error"]
}

// status reads identity's store status through the handler.
func (f *passwordFixture) status(t *testing.T, identity *auth.Identity) PasswordStoreStatusResponse {
	t.Helper()
	w := f.do(t, identity, http.MethodGet, "/api/v1/passwords/status", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp PasswordStoreStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// --- UnlockHandler ---

func TestUnlockHandler_OpensCallersSession(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)
	f.lock(t, alice)

	w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/unlock", jsonBody(t, passkeyFor(alice)))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp PasswordStoreStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Available)
	assert.False(t, resp.IsLocked)
	assert.Equal(t, "Store unlocked successfully", resp.Message)

	locked, err := f.manager.IsUserLocked(tenantA, userA)
	require.NoError(t, err)
	assert.False(t, locked)
}

func TestUnlockHandler_RejectionsLeaveSessionLocked(t *testing.T) {
	t.Parallel()

	alice := user(tenantA, userA)
	wrongSecret := passkeyFor(alice)
	wrongSecret.Secret = make([]byte, 32)

	cases := []struct {
		name        string
		enrolled    bool
		body        string
		wantStatus  int
		wantMessage string
	}{
		{"no credential", true, `{}`, http.StatusBadRequest, "Invalid vault credential"},
		{"no body", true, ``, http.StatusBadRequest, "Invalid vault credential"},
		{"short passkey secret", true, `{"factor":"passkey","credential_id":"Y3JlZA==","secret":"AAEC"}`, http.StatusBadRequest, "Invalid vault credential"},
		{"recovery code", true, `{"factor":"recovery","secret":"AAEC"}`, http.StatusBadRequest, "recovery code"},
		{"wrong passkey secret", true, jsonBody(t, wrongSecret), http.StatusUnauthorized, "Credential rejected"},
		{"no factor enrolled", false, jsonBody(t, passkeyFor(alice)), http.StatusPreconditionFailed, "enroll a passphrase or passkey first"},
		{"malformed body", true, `{bad`, http.StatusBadRequest, "Invalid request body"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newPasswordFixture(t)
			if tc.enrolled {
				f.unlock(t, alice)
				f.lock(t, alice)
			}

			w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/unlock", tc.body)

			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Contains(t, errorMessage(t, w), tc.wantMessage)

			locked, err := f.manager.IsUserLocked(tenantA, userA)
			require.NoError(t, err)
			assert.True(t, locked)
		})
	}
}

func TestUnlockHandler_AlreadyUnlocked(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)

	w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/unlock", jsonBody(t, passkeyFor(alice)))

	assert.Equal(t, http.StatusConflict, w.Code)
}

// A request without an identity has no personal session to open.
func TestUnlockHandler_NoIdentityIsNotImplemented(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)

	w := f.do(t, nil, http.MethodPost, "/api/v1/passwords/unlock", jsonBody(t, passkeyFor(user("", "nobody"))))

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

// The system tenant has its own store now, so a system-tenant user unlocks
// its own personal session like any tenant user.
func TestUnlockHandler_SystemTenantUserUnlocks(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	admin := user(qrdbsdk.SystemTenantID, "admin")

	f.unlock(t, admin)

	locked, err := f.manager.IsUserLocked(qrdbsdk.SystemTenantID, "admin")
	require.NoError(t, err)
	assert.False(t, locked)
}

func TestUnlockHandler_TenantErrors(t *testing.T) {
	t.Parallel()

	t.Run("sealed tenant", func(t *testing.T) {
		t.Parallel()

		f := newPasswordFixture(t)
		require.NoError(t, f.registry.SealTenant(tenantA))

		alice := user(tenantA, userA)

		w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/unlock", jsonBody(t, passkeyFor(alice)))

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("unknown tenant", func(t *testing.T) {
		t.Parallel()

		f := newPasswordFixture(t)

		w := f.do(t, user("no-such-tenant", userA), http.MethodPost, "/api/v1/passwords/unlock", jsonBody(t, passkeyFor(user("no-such-tenant", userA))))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("no password store configured", func(t *testing.T) {
		t.Parallel()

		router := passwordRouter(NewPasswordHandlers(&xkms.XKMSService{}))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", strings.NewReader(`{"factor":"passphrase","passphrase":"correct horse"}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// --- LockHandler ---

func TestLockHandler_ClosesCallersSession(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)

	w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/lock", "")

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp PasswordStoreStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.IsLocked)
	assert.Equal(t, "Store locked successfully", resp.Message)
}

func TestLockHandler_Errors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		identity   *auth.Identity
		wantStatus int
	}{
		{"already locked", user(tenantA, userA), http.StatusConflict},
		{"no identity", nil, http.StatusNotImplemented},
		{"unknown tenant", user("no-such-tenant", userA), http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newPasswordFixture(t)

			w := f.do(t, tc.identity, http.MethodPost, "/api/v1/passwords/lock", "")

			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// --- StatusHandler ---

func TestStatusHandler_ReportsCallersView(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.add(t, alice, "shared-one", true)

	locked := f.status(t, alice)
	assert.True(t, locked.Available)
	assert.True(t, locked.IsLocked)
	assert.Equal(t, 1, locked.PasswordCount, "shared entries are readable while locked")

	f.unlock(t, alice)
	f.add(t, alice, "personal-one", false)

	open := f.status(t, alice)
	assert.False(t, open.IsLocked)
	assert.Equal(t, 2, open.PasswordCount)
	assert.Equal(t, "Password store status retrieved", open.Message)
}

func TestStatusHandler_Errors(t *testing.T) {
	t.Parallel()

	t.Run("unknown tenant", func(t *testing.T) {
		t.Parallel()

		f := newPasswordFixture(t)

		w := f.do(t, user("no-such-tenant", userA), http.MethodGet, "/api/v1/passwords/status", "")

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("no password store configured", func(t *testing.T) {
		t.Parallel()

		router := passwordRouter(NewPasswordHandlers(&xkms.XKMSService{}))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil))

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// --- AddPasswordHandler ---

func TestAddPasswordHandler_Success(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)

	w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/", `{"name":"gmail","password":"s3cret","title":"Mail"}`)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp PasswordAddResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "gmail", resp.Name)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "Password added successfully", resp.Message)

	got := f.detail(t, alice, resp.ID)
	assert.Equal(t, "Mail", got.Title)
	assert.Equal(t, userA, got.OwnerID)
	assert.False(t, got.Shared)
}

func TestAddPasswordHandler_Errors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"malformed body", `not-json`, http.StatusBadRequest},
		{"empty name", `{"name":"","password":"x","shared":true}`, http.StatusBadRequest},
		{"empty password", `{"name":"n","password":"","shared":true}`, http.StatusBadRequest},
		{"personal entry while locked", `{"name":"n","password":"x"}`, http.StatusLocked},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newPasswordFixture(t)

			w := f.do(t, user(tenantA, userA), http.MethodPost, "/api/v1/passwords/", tc.body)

			assert.Equal(t, tc.wantStatus, w.Code, w.Body.String())
		})
	}
}

func TestAddPasswordHandler_Duplicate(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.add(t, alice, "dup", true)

	w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/", `{"name":"dup","password":"x","shared":true}`)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestAddPasswordHandler_NotConfigured(t *testing.T) {
	t.Parallel()

	router := passwordRouter(NewPasswordHandlers(&xkms.XKMSService{}))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/passwords/", strings.NewReader(`{"name":"n","password":"x"}`)))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// --- ListPasswordsHandler ---

func TestListPasswordsHandler_ReturnsEntryFields(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	id := f.add(t, alice, "shared-entry", true)

	resp := f.list(t, alice, "")

	require.Equal(t, 1, resp.Total)
	info := resp.Passwords[0]
	assert.Equal(t, id, info.ID)
	assert.Equal(t, "shared-entry", info.Name)
	assert.Equal(t, "shared-entry-title", info.Title)
	assert.Equal(t, userA, info.OwnerID)
	assert.True(t, info.Shared)
	assert.NotEmpty(t, info.CreatedAt)
	assert.NotEmpty(t, info.UpdatedAt)
}

func TestListPasswordsHandler_Filters(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)
	f.add(t, alice, "shared-entry", true)
	f.add(t, alice, "personal-entry", false)
	w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/", `{"name":"work-entry","password":"x","folder_path":"/work","shared":true}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	assert.ElementsMatch(t, []string{"personal-entry"}, names(f.list(t, alice, "?scope=personal")))
	assert.ElementsMatch(t, []string{"shared-entry", "work-entry"}, names(f.list(t, alice, "?scope=shared")))
	assert.ElementsMatch(t, []string{"shared-entry", "personal-entry", "work-entry"}, names(f.list(t, alice, "?scope=all")))
	assert.ElementsMatch(t, []string{"work-entry"}, names(f.list(t, alice, "?folder=/work")))
}

func TestListPasswordsHandler_InvalidScope(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)

	w := f.do(t, user(tenantA, userA), http.MethodGet, "/api/v1/passwords/?scope=bogus", "")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, errorMessage(t, w), "Invalid scope")
}

func TestListPasswordsHandler_SealedTenant(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	require.NoError(t, f.registry.SealTenant(tenantA))

	w := f.do(t, user(tenantA, userA), http.MethodGet, "/api/v1/passwords/", "")

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// --- GetPasswordHandler ---

func TestGetPasswordHandler_Success(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	id := f.add(t, alice, "entry", true)

	got := f.detail(t, alice, id)

	assert.Equal(t, id, got.ID)
	assert.Equal(t, "entry", got.Name)
	assert.Equal(t, "entry-title", got.Title)
	assert.Equal(t, "entry-secret", got.Password)
	assert.Equal(t, userA, got.OwnerID)
	assert.True(t, got.Shared)
	assert.NotEmpty(t, got.CreatedAt)
}

func TestGetPasswordHandler_Errors(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)

	assert.Equal(t, http.StatusNotFound, f.get(t, alice, "missing").Code)

	// Called without a chi route context, the {id} parameter is empty.
	w := httptest.NewRecorder()
	NewPasswordHandlers(f.svc).GetPasswordHandler(w, httptest.NewRequest(http.MethodGet, "/api/v1/passwords/", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- UpdatePasswordHandler ---

func TestUpdatePasswordHandler_Success(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	id := f.add(t, alice, "entry", true)

	w := f.do(t, alice, http.MethodPut, entryPath(id), `{"name":"renamed","title":"New","password":"new-secret"}`)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp PasswordUpdateResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "renamed", resp.Name)
	// Renaming re-keys the entry; the response reports the ID it now has.
	assert.NotEqual(t, id, resp.ID)

	got := f.detail(t, alice, resp.ID)
	assert.Equal(t, "renamed", got.Name)
	assert.Equal(t, "New", got.Title)
	assert.Equal(t, "new-secret", got.Password)
}

// A partial update reports the entry's unchanged name.
func TestUpdatePasswordHandler_PartialKeepsName(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	id := f.add(t, alice, "entry", true)

	w := f.do(t, alice, http.MethodPut, entryPath(id), `{"notes":"n"}`)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp PasswordUpdateResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "entry", resp.Name)
	assert.Equal(t, "n", f.detail(t, alice, id).Notes)
}

func TestUpdatePasswordHandler_Errors(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)
	id := f.add(t, alice, "entry", true)

	assert.Equal(t, http.StatusNotFound, f.do(t, alice, http.MethodPut, entryPath("missing"), `{"name":"x"}`).Code)
	assert.Equal(t, http.StatusBadRequest, f.do(t, alice, http.MethodPut, entryPath(id), `{bad`).Code)
	assert.Equal(t, http.StatusBadRequest, f.do(t, alice, http.MethodPut, entryPath(id), `{"password":""}`).Code)

	w := httptest.NewRecorder()
	NewPasswordHandlers(f.svc).UpdatePasswordHandler(w, httptest.NewRequest(http.MethodPut, "/api/v1/passwords/", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- DeletePasswordHandler ---

func TestDeletePasswordHandler_Success(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)
	id := f.add(t, alice, "entry", true)

	w := f.do(t, alice, http.MethodDelete, entryPath(id), "")

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, http.StatusNotFound, f.get(t, alice, id).Code)
}

func TestDeletePasswordHandler_Errors(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	f.unlock(t, alice)

	assert.Equal(t, http.StatusNotFound, f.do(t, alice, http.MethodDelete, entryPath("missing"), "").Code)

	w := httptest.NewRecorder()
	NewPasswordHandlers(f.svc).DeletePasswordHandler(w, httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Isolation: users, tenants, and the system tenant ---

// (a) A tenant user sees another tenant user's shared entry.
func TestPasswordIsolation_SharedEntryVisibleToTenantUsers(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice, bob := user(tenantA, userA), user(tenantA, userB)
	id := f.add(t, bob, "team-wifi", true)

	assert.Contains(t, names(f.list(t, alice, "")), "team-wifi")
	got := f.detail(t, alice, id)
	assert.Equal(t, "team-wifi-secret", got.Password)
	assert.Equal(t, userB, got.OwnerID)
}

// (b) A user cannot see or modify another user's personal entry.
func TestPasswordIsolation_PersonalEntryPrivateToOwner(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice, bob := user(tenantA, userA), user(tenantA, userB)
	f.unlock(t, alice)
	f.unlock(t, bob)
	id := f.add(t, bob, "bob-bank", false)

	assert.NotContains(t, names(f.list(t, alice, "")), "bob-bank")
	assert.Equal(t, http.StatusNotFound, f.get(t, alice, id).Code)
	assert.Equal(t, http.StatusNotFound, f.do(t, alice, http.MethodPut, entryPath(id), `{"password":"stolen"}`).Code)
	assert.Equal(t, http.StatusNotFound, f.do(t, alice, http.MethodDelete, entryPath(id), "").Code)

	got := f.detail(t, bob, id)
	assert.Equal(t, "bob-bank", got.Name)
	assert.Equal(t, "bob-bank-secret", got.Password)
}

// (c) A user cannot update or delete another user's shared entry.
func TestPasswordIsolation_SharedEntryModifiableOnlyByOwner(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice, bob := user(tenantA, userA), user(tenantA, userB)
	id := f.add(t, bob, "team-wifi", true)

	update := f.do(t, alice, http.MethodPut, entryPath(id), `{"password":"stolen"}`)
	assert.Equal(t, http.StatusForbidden, update.Code)
	assert.Contains(t, errorMessage(t, update), "Not the owner")

	del := f.do(t, alice, http.MethodDelete, entryPath(id), "")
	assert.Equal(t, http.StatusForbidden, del.Code)

	got := f.detail(t, bob, id)
	assert.Equal(t, "team-wifi-secret", got.Password)

	// The owner can still modify it.
	assert.Equal(t, http.StatusOK, f.do(t, bob, http.MethodPut, entryPath(id), `{"password":"rotated"}`).Code)
}

// (d) One tenant cannot reach another tenant's entries.
func TestPasswordIsolation_TenantsAreSeparate(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	mallory := user(tenantB, userA) // same subject, different tenant
	f.unlock(t, alice)
	f.unlock(t, mallory)
	sharedID := f.add(t, alice, "a-shared", true)
	personalID := f.add(t, alice, "a-personal", false)

	assert.Empty(t, f.list(t, mallory, "").Passwords)
	for _, id := range []string{sharedID, personalID} {
		assert.Equal(t, http.StatusNotFound, f.get(t, mallory, id).Code)
		assert.Equal(t, http.StatusNotFound, f.do(t, mallory, http.MethodPut, entryPath(id), `{"password":"x"}`).Code)
		assert.Equal(t, http.StatusNotFound, f.do(t, mallory, http.MethodDelete, entryPath(id), "").Code)
	}
	assert.ElementsMatch(t, []string{"a-shared", "a-personal"}, names(f.list(t, alice, "")))
}

// (e) A system-tenant identity gets the system tenant's own store.
func TestPasswordIsolation_SystemTenantHasOwnStore(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	admin := user(qrdbsdk.SystemTenantID, "admin")
	alice := user(tenantA, userA)
	f.add(t, alice, "a-shared", true)

	w := f.do(t, admin, http.MethodPost, "/api/v1/passwords/", `{"name":"sys-shared","password":"x","shared":true}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "Tenant not found")
	f.unlock(t, admin)
	f.add(t, admin, "sys-personal", false)

	assert.ElementsMatch(t, []string{"sys-shared", "sys-personal"}, names(f.list(t, admin, "")))
	assert.ElementsMatch(t, []string{"a-shared"}, names(f.list(t, alice, "")))
	assert.False(t, f.status(t, admin).IsLocked)
}

// (f) Sessions are per user: one user's unlock and lock never affect another's.
func TestPasswordIsolation_PerUserSessions(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice, bob := user(tenantA, userA), user(tenantA, userB)
	f.unlock(t, bob)
	bobID := f.add(t, bob, "bob-personal", false)
	require.Equal(t, http.StatusOK, f.do(t, bob, http.MethodPost, "/api/v1/passwords/lock", "").Code)

	// Alice unlocking does not open Bob's personal entries.
	f.unlock(t, alice)
	assert.Equal(t, http.StatusLocked, f.get(t, bob, bobID).Code)
	assert.True(t, f.status(t, bob).IsLocked)

	// Bob unlocks; Alice locking does not lock Bob.
	f.unlock(t, bob)
	require.Equal(t, http.StatusOK, f.do(t, alice, http.MethodPost, "/api/v1/passwords/lock", "").Code)
	assert.Equal(t, "bob-personal", f.detail(t, bob, bobID).Name)
	assert.False(t, f.status(t, bob).IsLocked)

	// Locked Alice: shared entries stay usable, personal add is refused.
	sharedID := f.add(t, alice, "shared-while-locked", true)
	assert.Equal(t, "shared-while-locked", f.detail(t, alice, sharedID).Name)
	locked := f.do(t, alice, http.MethodPost, "/api/v1/passwords/", `{"name":"p","password":"x"}`)
	assert.Equal(t, http.StatusLocked, locked.Code)
	assert.Contains(t, errorMessage(t, locked), "locked")
}

// A request without an identity is served by the unscoped system store,
// which no tenant user sees.
func TestPasswordHandlers_NoIdentityUsesSystemStore(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	id := f.add(t, nil, "internal", false)

	assert.Equal(t, "internal", f.detail(t, nil, id).Name)
	assert.Empty(t, f.list(t, user(tenantA, userA), "").Passwords)
	assert.Empty(t, f.list(t, user(qrdbsdk.SystemTenantID, "admin"), "").Passwords)
}

func TestPasswordHandlers_StoreClosed(t *testing.T) {
	t.Parallel()

	store := staticpw.NewStore(storage.NewMemory())
	svc := &xkms.XKMSService{}
	svc.SetPasswordStore(store)
	router := passwordRouter(NewPasswordHandlers(svc))
	require.NoError(t, store.Close())

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/passwords/", nil))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

// --- GeneratePasswordHandler ---

func TestGeneratePasswordHandler(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)

	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantLength int
	}{
		{"custom length", `{"length":24}`, http.StatusOK, 24},
		{"default length", `{}`, http.StatusOK, staticpw.DefaultLength},
		{"invalid length", `{"length":2}`, http.StatusBadRequest, 0},
		{"named charset", `{"length":20,"charset":"alphanumeric"}`, http.StatusOK, 20},
		{"literal charset", `{"length":10,"charset":"xy"}`, http.StatusOK, 10},
		{"malformed body", `{bad`, http.StatusBadRequest, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := f.do(t, nil, http.MethodPost, "/api/v1/passwords/generate", tc.body)

			require.Equal(t, tc.wantStatus, w.Code)
			if tc.wantStatus != http.StatusOK {
				return
			}
			var resp PasswordGenerateResponse
			require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Len(t, resp.Password, tc.wantLength)
			assert.Equal(t, tc.wantLength, resp.Length)
		})
	}
}

// TestGeneratePasswordHandler_GoesThroughTheServicer proves generation is the
// service layer's: a literal charset is honoured, and with no password store
// wired the servicer's not-configured answer is the handler's.
func TestGeneratePasswordHandler_GoesThroughTheServicer(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	w := f.do(t, nil, http.MethodPost, "/api/v1/passwords/generate", `{"length":16,"charset":"ab"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp PasswordGenerateResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Regexp(t, `^[ab]{16}$`, resp.Password)

	bare := passwordRouter(NewPasswordHandlers(&xkms.XKMSService{}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	bare.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// --- SetAccessModeHandler ---

func TestSetAccessModeHandler_SetsSessionModeForTenant(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)

	w := f.do(t, alice, http.MethodPost, "/api/v1/passwords/access-mode", `{"mode": "session_based"}`)

	require.Equal(t, http.StatusOK, w.Code)
	var resp PasswordStoreAccessModeResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, string(staticpw.AccessSessionBased), resp.Mode)

	mode, err := f.svc.PasswordAccessMode(auth.WithIdentity(context.Background(), alice))
	require.NoError(t, err)
	assert.Equal(t, staticpw.AccessSessionBased, mode)
}

func TestSetAccessModeHandler_Errors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		identity    *auth.Identity
		body        string
		wantStatus  int
		wantMessage string
	}{
		{"invalid mode", user(tenantA, userA), `{"mode":"banana"}`, http.StatusBadRequest, "Invalid access mode"},
		{"missing mode", user(tenantA, userA), `{}`, http.StatusBadRequest, "Missing access mode"},
		{"malformed body", user(tenantA, userA), `not-json`, http.StatusBadRequest, "Invalid request body"},
		// A mode the wired store cannot enforce is a capability boundary.
		{"unsupported mode", user(tenantA, userA), `{"mode":"pin_per_operation"}`, http.StatusNotImplemented, "cannot enforce the requested access mode"},
		// No identity addresses the unscoped system store, which has no session.
		{"system store", nil, `{"mode":"session_based"}`, http.StatusNotImplemented, "cannot enforce"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newPasswordFixture(t)

			w := f.do(t, tc.identity, http.MethodPost, "/api/v1/passwords/access-mode", tc.body)

			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Contains(t, errorMessage(t, w), tc.wantMessage)
		})
	}
}

func TestSetAccessModeHandler_NotConfigured(t *testing.T) {
	t.Parallel()

	router := passwordRouter(NewPasswordHandlers(&xkms.XKMSService{}))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/passwords/access-mode", strings.NewReader(`{"mode":"session_based"}`)))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// --- error mapping ---

func TestPasswordHandleAccessModeError_Mapping(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			w := httptest.NewRecorder()
			passwordHandleAccessModeError(w, tc.err)
			assert.Equal(t, tc.want, w.Code)
		})
	}
}

func TestPasswordWriteServiceError_Mapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want int
	}{
		{staticpw.ErrPasswordNotFound, http.StatusNotFound},
		{staticpw.ErrPasswordExists, http.StatusConflict},
		{staticpw.ErrInvalidName, http.StatusBadRequest},
		{staticpw.ErrEmptyPassword, http.StatusBadRequest},
		{staticpw.ErrInvalidScope, http.StatusBadRequest},
		{staticpw.ErrInvalidFolderPath, http.StatusBadRequest},
		{staticpw.ErrFolderPathTooDeep, http.StatusBadRequest},
		{staticpw.ErrInvalidUserID, http.StatusBadRequest},
		{xkms.ErrNilRequest, http.StatusBadRequest},
		{staticpw.ErrPasswordReadOnly, http.StatusForbidden},
		{staticpw.ErrNotOwner, http.StatusForbidden},
		{staticpw.ErrStoreLocked, http.StatusLocked},
		{staticpw.ErrStoreClosed, http.StatusServiceUnavailable},
		{seal.ErrTenantSealed, http.StatusServiceUnavailable},
		{seal.ErrTenantNotFound, http.StatusNotFound},
		{staticpw.ErrNoSystemBarrier, http.StatusServiceUnavailable},
		{staticpw.ErrNotConfigured, http.StatusServiceUnavailable},
		{xkms.ErrNotConfigured, http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			passwordWriteServiceError(w, errors.Join(errors.New("context"), tc.err), "fallback")
			assert.Equal(t, tc.want, w.Code)
			assert.NotEqual(t, "fallback", errorMessage(t, w))
		})
	}

	t.Run("unknown error uses the fallback", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		passwordWriteServiceError(w, errors.New("boom"), "Failed to add password")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "Failed to add password", errorMessage(t, w))
	})
}

func TestPasswordWriteUnlockError_Mapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want int
	}{
		{staticpw.ErrVaultInvalidCredential, http.StatusBadRequest},
		{staticpw.ErrVaultRecoveryFactor, http.StatusBadRequest},
		{staticpw.ErrVaultNotInitialized, http.StatusPreconditionFailed},
		{staticpw.ErrVaultCredentialRejected, http.StatusUnauthorized},
		{staticpw.ErrStoreNotLocked, http.StatusConflict},
		{staticpw.ErrInvalidUserID, http.StatusBadRequest},
		{seal.ErrTenantSealed, http.StatusServiceUnavailable},
		{seal.ErrTenantNotFound, http.StatusNotFound},
		{staticpw.ErrNoSystemBarrier, http.StatusServiceUnavailable},
		{xkms.ErrNilRequest, http.StatusBadRequest},
		{xkms.ErrNotConfigured, http.StatusServiceUnavailable},
		{xkms.ErrOperationNotSupported, http.StatusNotImplemented},
		{errors.New("backend detail: disk offline"), http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			passwordWriteUnlockError(w, tc.err)
			assert.Equal(t, tc.want, w.Code)
			assert.NotContains(t, errorMessage(t, w), "disk offline", "an unclassified error's detail must not leak")
		})
	}
}

func TestPasswordWriteLockError_Mapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want int
	}{
		{staticpw.ErrStoreAlreadyLocked, http.StatusConflict},
		{xkms.ErrOperationNotSupported, http.StatusNotImplemented},
		{xkms.ErrNotConfigured, http.StatusServiceUnavailable},
		{seal.ErrTenantNotFound, http.StatusNotFound},
		{staticpw.ErrInvalidUserID, http.StatusBadRequest},
		{errors.New("boom"), http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			passwordWriteLockError(w, tc.err)
			assert.Equal(t, tc.want, w.Code)
		})
	}
}

func TestPasswordWriteJSONError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	passwordWriteJSONError(w, "test error message", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "test error message", errorMessage(t, w))
}
