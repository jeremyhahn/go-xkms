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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/kdftest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Tenants and users the password tests act as.
const (
	pwTenantA = "tenant-1"
	pwTenantB = "tenant-2"
	pwUserA   = "alice"
	pwUserB   = "bob"
)

// passwordTestRegistry builds a BarrierRegistry whose system barrier and two
// tenant barriers (pwTenantA, pwTenantB) are initialized and unsealed, plus
// the system store and a TenantPasswordStoreManager over them.
func passwordTestRegistry(t *testing.T) (*seal.BarrierRegistry, *staticpw.BackendStore, *staticpw.TenantPasswordStoreManager) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sysBackend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	sysBarrier, err := seal.NewBarrier(
		logger,
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
	for _, tenant := range []string{pwTenantA, pwTenantB} {
		_, err = registry.RegisterTenant(tenant)
		require.NoError(t, err)
		creds := seal.MustCredentials([]byte(tenant + "-pw"))
		require.NoError(t, registry.InitializeTenant(ctx, tenant, creds))
		creds.Secret.Destroy()
	}

	systemStore := staticpw.NewStore(storage.New())
	manager, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore, staticpw.WithPasskeyRelyingParty("kms.example.com"), staticpw.WithPassphraseKDFParams(kdftest.CheapPassphraseParams))
	require.NoError(t, err)
	return registry, systemStore, manager
}

// passwordServer is an MCP server over a real XKMSService wired with a real
// TenantPasswordStoreManager and BarrierRegistry. It holds no package-global
// state, so tests using it may run in parallel.
type passwordServer struct {
	*Server
	registry *seal.BarrierRegistry
	manager  *staticpw.TenantPasswordStoreManager
}

// newPasswordServer builds a passwordServer.
func newPasswordServer(t *testing.T) *passwordServer {
	t.Helper()

	registry, systemStore, manager := passwordTestRegistry(t)

	svc := &xkms.XKMSService{}
	svc.SetPasswordStore(systemStore)
	svc.SetPasswordStoreManager(manager)

	return &passwordServer{
		Server:   &Server{xkmsService: svc},
		registry: registry,
		manager:  manager,
	}
}

// pwCtx returns a context carrying subject's identity in tenantID.
func pwCtx(tenantID, subject string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: subject, TenantID: tenantID})
}

// pwRPC builds a JSON-RPC request for method carrying params (nil for none).
func pwRPC(t *testing.T, method string, params interface{}) *JSONRPCRequest {
	t.Helper()
	req := &JSONRPCRequest{JSONRPC: "2.0", Method: method, ID: 1}
	if params != nil {
		raw, err := json.Marshal(params)
		require.NoError(t, err)
		req.Params = raw
	}
	return req
}

// pwPasskey returns subject's test passkey. Passkeys unwrap with HKDF,
// which keeps the many session opens of this suite cheap; the passphrase
// (Argon2id) path has its own tests.
func pwPasskey(subject string) transport.PasswordVaultCredential {
	return vaulttest.Passkey(subject)
}

// ctxPasskey returns the test passkey of the identity on ctx.
func ctxPasskey(ctx context.Context) transport.PasswordVaultCredential {
	return pwPasskey(auth.GetIdentity(ctx).Subject)
}

// unlock opens ctx's personal session with the caller's passkey: the first
// time it enrolls the passkey, which initializes the vault and opens the
// session; afterwards it unlocks.
func (s *passwordServer) unlock(t *testing.T, ctx context.Context) {
	t.Helper()
	result, err := s.handlePasswordVaultStatus(ctx, pwRPC(t, "password.vault.status", nil))
	require.NoError(t, err)
	if !result.(*transport.PasswordVaultStatusResponse).Initialized {
		_, err = s.handlePasswordVaultEnroll(ctx, pwRPC(t, "password.vault.enroll", ctxPasskey(ctx)))
		require.NoError(t, err)
		return
	}
	_, err = s.handlePasswordUnlock(ctx, pwRPC(t, "password.unlock", ctxPasskey(ctx)))
	require.NoError(t, err)
}

// lock closes ctx's personal session.
func (s *passwordServer) lock(t *testing.T, ctx context.Context) {
	t.Helper()
	_, err := s.handlePasswordLock(ctx, pwRPC(t, "password.lock", nil))
	require.NoError(t, err)
}

// add creates an entry as ctx and returns its ID.
func (s *passwordServer) add(t *testing.T, ctx context.Context, name string, shared bool) string {
	t.Helper()
	result, err := s.handlePasswordAdd(ctx, pwRPC(t, "password.add", PasswordAddParams{
		Name: name, Password: name + "-secret", Title: name + "-title", Shared: shared,
	}))
	require.NoError(t, err)
	added, ok := result.(PasswordAddResult)
	require.True(t, ok)
	require.NotEmpty(t, added.ID)
	return added.ID
}

// get fetches an entry as ctx.
func (s *passwordServer) get(t *testing.T, ctx context.Context, id string) (PasswordDetailResult, error) {
	t.Helper()
	result, err := s.handlePasswordGet(ctx, pwRPC(t, "password.get", PasswordGetParams{ID: id}))
	if err != nil {
		return PasswordDetailResult{}, err
	}
	detail, ok := result.(PasswordDetailResult)
	require.True(t, ok)
	return detail, nil
}

// list lists entries as ctx and returns their names.
func (s *passwordServer) list(t *testing.T, ctx context.Context, params PasswordListParams) []string {
	t.Helper()
	result, err := s.handlePasswordList(ctx, pwRPC(t, "password.list", params))
	require.NoError(t, err)
	listed, ok := result.(PasswordListResult)
	require.True(t, ok)
	require.Equal(t, len(listed.Passwords), listed.Total)
	out := make([]string, 0, len(listed.Passwords))
	for _, pw := range listed.Passwords {
		out = append(out, pw.Name)
	}
	return out
}

// update changes an entry's password as ctx.
func (s *passwordServer) update(t *testing.T, ctx context.Context, id, password string) error {
	t.Helper()
	_, err := s.handlePasswordUpdate(ctx, pwRPC(t, "password.update", PasswordUpdateParams{ID: id, Password: &password}))
	return err
}

// remove deletes an entry as ctx.
func (s *passwordServer) remove(t *testing.T, ctx context.Context, id string) error {
	t.Helper()
	_, err := s.handlePasswordDelete(ctx, pwRPC(t, "password.delete", PasswordDeleteParams{ID: id}))
	return err
}

// status reads ctx's store status.
func (s *passwordServer) status(t *testing.T, ctx context.Context) PasswordStoreStatusResult {
	t.Helper()
	result, err := s.handlePasswordStatus(ctx, pwRPC(t, "password.status", nil))
	require.NoError(t, err)
	st, ok := result.(PasswordStoreStatusResult)
	require.True(t, ok)
	return st
}

// requireCode asserts err is a *KeyOpError carrying code.
func requireCode(t *testing.T, err error, code int) {
	t.Helper()
	require.Error(t, err)
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, code, keyErr.Code, err.Error())
}

// --- handlers without a wired service ---

func TestPasswordHandlers_NoService(t *testing.T) {
	t.Parallel()

	bare := &Server{}
	ctx := pwCtx(pwTenantA, pwUserA)
	calls := map[string]func() (interface{}, error){
		"add": func() (interface{}, error) {
			return bare.handlePasswordAdd(ctx, pwRPC(t, "password.add", PasswordAddParams{Name: "n"}))
		},
		"get": func() (interface{}, error) {
			return bare.handlePasswordGet(ctx, pwRPC(t, "password.get", PasswordGetParams{ID: "x"}))
		},
		"list": func() (interface{}, error) {
			return bare.handlePasswordList(ctx, pwRPC(t, "password.list", PasswordListParams{}))
		},
		"update": func() (interface{}, error) {
			return bare.handlePasswordUpdate(ctx, pwRPC(t, "password.update", PasswordUpdateParams{ID: "x"}))
		},
		"delete": func() (interface{}, error) {
			return bare.handlePasswordDelete(ctx, pwRPC(t, "password.delete", PasswordDeleteParams{ID: "x"}))
		},
		"unlock": func() (interface{}, error) { return bare.handlePasswordUnlock(ctx, pwRPC(t, "password.unlock", nil)) },
		"lock":   func() (interface{}, error) { return bare.handlePasswordLock(ctx, pwRPC(t, "password.lock", nil)) },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			_, err := call()
			requireCode(t, err, ErrCodeServiceUnavailable)
			assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
		})
	}

	t.Run("status reports unavailable", func(t *testing.T) {
		result, err := bare.handlePasswordStatus(ctx, pwRPC(t, "password.status", nil))
		require.NoError(t, err)
		st, ok := result.(PasswordStoreStatusResult)
		require.True(t, ok)
		assert.False(t, st.Available)
		assert.Equal(t, "Password store not configured", st.Message)
	})
}

// A service with no password store wired answers "not configured" too.
func TestPasswordHandlers_ServiceWithoutStore(t *testing.T) {
	t.Parallel()

	server := &Server{xkmsService: &xkms.XKMSService{}}
	ctx := pwCtx(pwTenantA, pwUserA)

	_, err := server.handlePasswordAdd(ctx, pwRPC(t, "password.add", PasswordAddParams{Name: "n", Password: "p"}))
	requireCode(t, err, ErrCodeServiceUnavailable)

	_, err = server.handlePasswordLock(ctx, pwRPC(t, "password.lock", nil))
	requireCode(t, err, ErrCodeServiceUnavailable)

	result, err := server.handlePasswordStatus(ctx, pwRPC(t, "password.status", nil))
	require.NoError(t, err)
	assert.False(t, result.(PasswordStoreStatusResult).Available)
}

// --- CRUD ---

func TestHandlePasswordAdd(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)

	t.Run("adds a shared entry", func(t *testing.T) {
		result, err := s.handlePasswordAdd(alice, pwRPC(t, "password.add", PasswordAddParams{Name: "svc", Password: "p", Shared: true}))
		require.NoError(t, err)
		added := result.(PasswordAddResult)
		assert.Equal(t, "svc", added.Name)
		assert.NotEmpty(t, added.ID)
		assert.Equal(t, "Password added successfully", added.Message)
	})

	cases := []struct {
		name   string
		params interface{}
		code   int
	}{
		{"empty name", PasswordAddParams{Password: "p", Shared: true}, ErrCodeInvalidParams},
		{"empty password", PasswordAddParams{Name: "n", Shared: true}, ErrCodeInvalidParams},
		{"duplicate", PasswordAddParams{Name: "svc", Password: "p", Shared: true}, sdkssh.JSONRPCCodeDuplicate},
		{"personal entry while locked", PasswordAddParams{Name: "mine", Password: "p"}, ErrCodeInternalError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.handlePasswordAdd(alice, pwRPC(t, "password.add", tc.params))
			requireCode(t, err, tc.code)
		})
	}

	t.Run("malformed params", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: json.RawMessage(`invalid`), ID: 1}
		_, err := s.handlePasswordAdd(alice, req)
		requireCode(t, err, ErrCodeInvalidParams)
	})
}

func TestHandlePasswordGet(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	s.unlock(t, alice)
	id := s.add(t, alice, "entry", true)

	t.Run("returns every field", func(t *testing.T) {
		got, err := s.get(t, alice, id)
		require.NoError(t, err)
		assert.Equal(t, id, got.ID)
		assert.Equal(t, "entry", got.Name)
		assert.Equal(t, "entry-title", got.Title)
		assert.Equal(t, "entry-secret", got.Password)
		assert.Equal(t, pwUserA, got.OwnerID)
		assert.True(t, got.Shared)
		assert.NotEmpty(t, got.CreatedAt)
		assert.NotEmpty(t, got.UpdatedAt)
	})

	t.Run("missing entry is not found", func(t *testing.T) {
		_, err := s.get(t, alice, "missing")
		requireCode(t, err, sdkssh.JSONRPCCodeNotFound)
		assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
	})

	t.Run("empty id is invalid", func(t *testing.T) {
		_, err := s.get(t, alice, "")
		requireCode(t, err, ErrCodeInvalidParams)
		assert.ErrorIs(t, err, ErrPasswordIDRequired)
	})
}

func TestHandlePasswordList(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	s.unlock(t, alice)
	s.add(t, alice, "shared-entry", true)
	s.add(t, alice, "personal-entry", false)
	_, err := s.handlePasswordAdd(alice, pwRPC(t, "password.add", PasswordAddParams{Name: "work-entry", Password: "p", FolderPath: "/work", Shared: true}))
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"shared-entry", "personal-entry", "work-entry"}, s.list(t, alice, PasswordListParams{}))
	assert.ElementsMatch(t, []string{"personal-entry"}, s.list(t, alice, PasswordListParams{Scope: "personal"}))
	assert.ElementsMatch(t, []string{"shared-entry", "work-entry"}, s.list(t, alice, PasswordListParams{Scope: "shared"}))
	assert.ElementsMatch(t, []string{"work-entry"}, s.list(t, alice, PasswordListParams{Folder: "/work"}))

	_, err = s.handlePasswordList(alice, pwRPC(t, "password.list", PasswordListParams{Scope: "bogus"}))
	requireCode(t, err, ErrCodeInvalidParams)
	assert.ErrorIs(t, err, staticpw.ErrInvalidScope)
}

func TestHandlePasswordUpdate(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	s.unlock(t, alice)

	t.Run("partial update keeps id and name", func(t *testing.T) {
		id := s.add(t, alice, "keep", true)
		notes := "n"
		result, err := s.handlePasswordUpdate(alice, pwRPC(t, "password.update", PasswordUpdateParams{ID: id, Notes: &notes}))
		require.NoError(t, err)
		updated := result.(PasswordUpdateResult)
		assert.Equal(t, id, updated.ID)
		assert.Equal(t, "keep", updated.Name)

		got, err := s.get(t, alice, id)
		require.NoError(t, err)
		assert.Equal(t, "n", got.Notes)
	})

	t.Run("rename reports the re-keyed id", func(t *testing.T) {
		id := s.add(t, alice, "old-name", true)
		name, title := "new-name", "New"
		result, err := s.handlePasswordUpdate(alice, pwRPC(t, "password.update", PasswordUpdateParams{ID: id, Name: &name, Title: &title}))
		require.NoError(t, err)
		updated := result.(PasswordUpdateResult)
		assert.Equal(t, "new-name", updated.Name)
		assert.NotEqual(t, id, updated.ID)

		got, err := s.get(t, alice, updated.ID)
		require.NoError(t, err)
		assert.Equal(t, "New", got.Title)
	})

	t.Run("missing entry is not found", func(t *testing.T) {
		requireCode(t, s.update(t, alice, "missing", "x"), sdkssh.JSONRPCCodeNotFound)
	})

	t.Run("empty id is invalid", func(t *testing.T) {
		requireCode(t, s.update(t, alice, "", "x"), ErrCodeInvalidParams)
	})

	t.Run("empty password is invalid", func(t *testing.T) {
		id := s.add(t, alice, "blank", true)
		requireCode(t, s.update(t, alice, id, ""), ErrCodeInvalidParams)
	})
}

func TestHandlePasswordDelete(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	s.unlock(t, alice)
	id := s.add(t, alice, "entry", true)

	result, err := s.handlePasswordDelete(alice, pwRPC(t, "password.delete", PasswordDeleteParams{ID: id}))
	require.NoError(t, err)
	assert.Equal(t, "Password deleted successfully", result.(PasswordDeleteResult).Message)
	_, err = s.get(t, alice, id)
	requireCode(t, err, sdkssh.JSONRPCCodeNotFound)

	requireCode(t, s.remove(t, alice, "missing"), sdkssh.JSONRPCCodeNotFound)
	requireCode(t, s.remove(t, alice, ""), ErrCodeInvalidParams)
}

// A request without an identity is served by the unscoped system store,
// which no tenant user sees.
func TestPasswordHandlers_NoIdentityUsesSystemStore(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	id := s.add(t, context.Background(), "internal", false)

	got, err := s.get(t, context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "internal", got.Name)
	assert.Empty(t, s.list(t, pwCtx(pwTenantA, pwUserA), PasswordListParams{}))
	assert.Empty(t, s.list(t, pwCtx(qrdbsdk.SystemTenantID, "admin"), PasswordListParams{}))

	st := s.status(t, context.Background())
	assert.True(t, st.Available)
	assert.Equal(t, 1, st.PasswordCount)
}

// --- sessions ---

func TestHandlePasswordLock(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)

	t.Run("already locked", func(t *testing.T) {
		_, err := s.handlePasswordLock(alice, pwRPC(t, "password.lock", nil))
		requireCode(t, err, ErrCodeInternalError)
		assert.ErrorIs(t, err, staticpw.ErrStoreAlreadyLocked)
	})

	t.Run("locks the caller's open session", func(t *testing.T) {
		s.unlock(t, alice)
		result, err := s.handlePasswordLock(alice, pwRPC(t, "password.lock", nil))
		require.NoError(t, err)
		st := result.(PasswordStoreStatusResult)
		assert.True(t, st.IsLocked)
		assert.Equal(t, "Store locked successfully", st.Message)
	})

	t.Run("no identity has no session", func(t *testing.T) {
		_, err := s.handlePasswordLock(context.Background(), pwRPC(t, "password.lock", nil))
		requireCode(t, err, ErrCodeMethodNotFound)
		assert.ErrorIs(t, err, xkms.ErrOperationNotSupported)
	})

	t.Run("unknown tenant", func(t *testing.T) {
		_, err := s.handlePasswordLock(pwCtx("no-such-tenant", pwUserA), pwRPC(t, "password.lock", nil))
		requireCode(t, err, sdkssh.JSONRPCCodeNotFound)
		assert.ErrorIs(t, err, seal.ErrTenantNotFound)
	})
}

func TestHandlePasswordUnlock_Errors(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)

	t.Run("no identity has no session", func(t *testing.T) {
		_, err := s.handlePasswordUnlock(context.Background(), pwRPC(t, "password.unlock", pwPasskey(pwUserA)))
		requireCode(t, err, ErrCodeMethodNotFound)
		assert.ErrorIs(t, err, xkms.ErrOperationNotSupported)
	})

	t.Run("unknown tenant", func(t *testing.T) {
		_, err := s.handlePasswordUnlock(pwCtx("no-such-tenant", pwUserA), pwRPC(t, "password.unlock", pwPasskey(pwUserA)))
		requireCode(t, err, sdkssh.JSONRPCCodeNotFound)
	})

	t.Run("already unlocked", func(t *testing.T) {
		alice := pwCtx(pwTenantA, pwUserA)
		s.unlock(t, alice)
		_, err := s.handlePasswordUnlock(alice, pwRPC(t, "password.unlock", pwPasskey(pwUserA)))
		requireCode(t, err, ErrCodeInternalError)
		assert.ErrorIs(t, err, staticpw.ErrStoreNotLocked)
	})

	t.Run("sealed tenant", func(t *testing.T) {
		require.NoError(t, s.registry.SealTenant(pwTenantB))
		_, err := s.handlePasswordUnlock(pwCtx(pwTenantB, pwUserA), pwRPC(t, "password.unlock", pwPasskey(pwUserA)))
		requireCode(t, err, ErrCodeInternalError)
		assert.ErrorIs(t, err, seal.ErrTenantSealed)
	})
}

func TestHandlePasswordStatus(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	s.add(t, alice, "shared-one", true)

	locked := s.status(t, alice)
	assert.True(t, locked.Available)
	assert.True(t, locked.IsLocked)
	assert.Equal(t, 1, locked.PasswordCount, "shared entries are readable while locked")

	s.unlock(t, alice)
	s.add(t, alice, "personal-one", false)
	open := s.status(t, alice)
	assert.False(t, open.IsLocked)
	assert.Equal(t, 2, open.PasswordCount)
	assert.Equal(t, "Password store status retrieved", open.Message)

	_, err := s.handlePasswordStatus(pwCtx("no-such-tenant", pwUserA), pwRPC(t, "password.status", nil))
	requireCode(t, err, sdkssh.JSONRPCCodeNotFound)
}

// --- isolation: users, tenants, and the system tenant ---

// (a) A tenant user sees another tenant user's shared entry.
func TestPasswordIsolation_SharedEntryVisibleToTenantUsers(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice, bob := pwCtx(pwTenantA, pwUserA), pwCtx(pwTenantA, pwUserB)
	id := s.add(t, bob, "team-wifi", true)

	assert.Contains(t, s.list(t, alice, PasswordListParams{}), "team-wifi")
	got, err := s.get(t, alice, id)
	require.NoError(t, err)
	assert.Equal(t, "team-wifi-secret", got.Password)
	assert.Equal(t, pwUserB, got.OwnerID)
}

// (b) A user cannot see or modify another user's personal entry.
func TestPasswordIsolation_PersonalEntryPrivateToOwner(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice, bob := pwCtx(pwTenantA, pwUserA), pwCtx(pwTenantA, pwUserB)
	s.unlock(t, alice)
	s.unlock(t, bob)
	id := s.add(t, bob, "bob-bank", false)

	assert.NotContains(t, s.list(t, alice, PasswordListParams{}), "bob-bank")
	_, err := s.get(t, alice, id)
	requireCode(t, err, sdkssh.JSONRPCCodeNotFound)
	requireCode(t, s.update(t, alice, id, "stolen"), sdkssh.JSONRPCCodeNotFound)
	requireCode(t, s.remove(t, alice, id), sdkssh.JSONRPCCodeNotFound)

	got, err := s.get(t, bob, id)
	require.NoError(t, err)
	assert.Equal(t, "bob-bank-secret", got.Password)
}

// (c) A user cannot update or delete another user's shared entry.
func TestPasswordIsolation_SharedEntryModifiableOnlyByOwner(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice, bob := pwCtx(pwTenantA, pwUserA), pwCtx(pwTenantA, pwUserB)
	id := s.add(t, bob, "team-wifi", true)

	err := s.update(t, alice, id, "stolen")
	requireCode(t, err, ErrCodeForbidden)
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)
	err = s.remove(t, alice, id)
	requireCode(t, err, ErrCodeForbidden)
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)

	got, err := s.get(t, bob, id)
	require.NoError(t, err)
	assert.Equal(t, "team-wifi-secret", got.Password)

	// The owner can still modify it.
	require.NoError(t, s.update(t, bob, id, "rotated"))
}

// (d) One tenant cannot reach another tenant's entries.
func TestPasswordIsolation_TenantsAreSeparate(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	mallory := pwCtx(pwTenantB, pwUserA) // same subject, different tenant
	s.unlock(t, alice)
	s.unlock(t, mallory)
	sharedID := s.add(t, alice, "a-shared", true)
	personalID := s.add(t, alice, "a-personal", false)

	assert.Empty(t, s.list(t, mallory, PasswordListParams{}))
	for _, id := range []string{sharedID, personalID} {
		_, err := s.get(t, mallory, id)
		requireCode(t, err, sdkssh.JSONRPCCodeNotFound)
		requireCode(t, s.update(t, mallory, id, "x"), sdkssh.JSONRPCCodeNotFound)
		requireCode(t, s.remove(t, mallory, id), sdkssh.JSONRPCCodeNotFound)
	}
	assert.ElementsMatch(t, []string{"a-shared", "a-personal"}, s.list(t, alice, PasswordListParams{}))
}

// (e) A system-tenant identity gets the system tenant's own store.
func TestPasswordIsolation_SystemTenantHasOwnStore(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	admin := pwCtx(qrdbsdk.SystemTenantID, "admin")
	alice := pwCtx(pwTenantA, pwUserA)
	s.add(t, alice, "a-shared", true)

	s.add(t, admin, "sys-shared", true)
	s.unlock(t, admin)
	s.add(t, admin, "sys-personal", false)

	assert.ElementsMatch(t, []string{"sys-shared", "sys-personal"}, s.list(t, admin, PasswordListParams{}))
	assert.ElementsMatch(t, []string{"a-shared"}, s.list(t, alice, PasswordListParams{}))
	assert.False(t, s.status(t, admin).IsLocked)
	s.lock(t, admin)
	assert.True(t, s.status(t, admin).IsLocked)
}

// (f) Sessions are per user: one user's unlock and lock never affect another's.
func TestPasswordIsolation_PerUserSessions(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice, bob := pwCtx(pwTenantA, pwUserA), pwCtx(pwTenantA, pwUserB)
	s.unlock(t, bob)
	bobID := s.add(t, bob, "bob-personal", false)
	s.lock(t, bob)

	// Alice unlocking does not open Bob's personal entries.
	s.unlock(t, alice)
	_, err := s.get(t, bob, bobID)
	assert.ErrorIs(t, err, staticpw.ErrStoreLocked)
	assert.True(t, s.status(t, bob).IsLocked)

	// Bob unlocks; Alice locking does not lock Bob.
	s.unlock(t, bob)
	s.lock(t, alice)
	got, err := s.get(t, bob, bobID)
	require.NoError(t, err)
	assert.Equal(t, "bob-personal", got.Name)
	assert.False(t, s.status(t, bob).IsLocked)

	// Locked Alice: shared entries stay usable, personal add is refused.
	sharedID := s.add(t, alice, "shared-while-locked", true)
	_, err = s.get(t, alice, sharedID)
	require.NoError(t, err)
	_, err = s.handlePasswordAdd(alice, pwRPC(t, "password.add", PasswordAddParams{Name: "p", Password: "x"}))
	requireCode(t, err, ErrCodeInternalError)
	assert.ErrorIs(t, err, staticpw.ErrStoreLocked)
}

// --- generate ---

func TestHandlePasswordGenerate(t *testing.T) {
	t.Parallel()
	server := newPasswordServer(t).Server
	ctx := context.Background()

	t.Run("goes through the service layer", func(t *testing.T) {
		_, err := (&Server{}).handlePasswordGenerate(ctx, pwRPC(t, "password.generate", PasswordGenerateParams{}))
		requireCode(t, err, ErrCodeServiceUnavailable)
	})

	t.Run("generates password with defaults", func(t *testing.T) {
		result, err := server.handlePasswordGenerate(ctx, pwRPC(t, "password.generate", PasswordGenerateParams{}))
		require.NoError(t, err)
		gen := result.(PasswordGenerateResult)
		assert.Len(t, gen.Password, staticpw.DefaultLength)
		assert.Equal(t, staticpw.DefaultLength, gen.Length)
	})

	t.Run("generates password with custom length and charset", func(t *testing.T) {
		result, err := server.handlePasswordGenerate(ctx, pwRPC(t, "password.generate", PasswordGenerateParams{Length: 32, Charset: staticpw.CharsetAlphanumeric}))
		require.NoError(t, err)
		gen := result.(PasswordGenerateResult)
		assert.Len(t, gen.Password, 32)
	})

	t.Run("rejects an invalid length", func(t *testing.T) {
		_, err := server.handlePasswordGenerate(ctx, pwRPC(t, "password.generate", PasswordGenerateParams{Length: 2}))
		requireCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.generate", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handlePasswordGenerate(ctx, req)
		requireCode(t, err, ErrCodeInvalidParams)
	})
}

// --- setAccessMode ---

// TestHandlePasswordSetAccessMode exercises the password.setAccessMode
// handler added for go-xkms#753: it must delegate to
// XKMSService.PasswordStoreSetAccessMode and translate the servicer's
// sentinels onto the JSON-RPC codes pkg/api/rest/password_handlers.go's
// SetAccessModeHandler already reports for the same conditions.
func TestHandlePasswordSetAccessMode(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)

	setMode := func(t *testing.T, server *Server, ctx context.Context, mode string) (interface{}, error) {
		t.Helper()
		return server.handlePasswordSetAccessMode(ctx, pwRPC(t, "password.setAccessMode", transport.PasswordStoreSetAccessModeRequest{Mode: mode}))
	}

	t.Run("fails when xkms service not configured", func(t *testing.T) {
		_, err := setMode(t, &Server{}, alice, "session_based")
		requireCode(t, err, ErrCodeServiceUnavailable)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("fails with invalid JSON params as InvalidParams", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.setAccessMode", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := s.handlePasswordSetAccessMode(alice, req)
		requireCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("fails with empty mode as InvalidParams", func(t *testing.T) {
		_, err := setMode(t, s.Server, alice, "")
		requireCode(t, err, ErrCodeInvalidParams)
		assert.ErrorIs(t, err, xkms.ErrInvalidAccessMode)
	})

	t.Run("fails with an out-of-vocabulary mode as InvalidParams", func(t *testing.T) {
		_, err := setMode(t, s.Server, alice, "bogus")
		requireCode(t, err, ErrCodeInvalidParams)
		assert.ErrorIs(t, err, xkms.ErrInvalidAccessMode)
	})

	t.Run("fails switching to an unsupported mode as MethodNotFound", func(t *testing.T) {
		// A tenant store is session based; requesting the other valid mode
		// asks the wired store to change its enforced strategy, which
		// PasswordStoreSetAccessMode refuses.
		_, err := setMode(t, s.Server, alice, "pin_per_operation")
		requireCode(t, err, ErrCodeMethodNotFound)
		assert.ErrorIs(t, err, xkms.ErrOperationNotSupported)
	})

	t.Run("succeeds requesting the mode already in force", func(t *testing.T) {
		result, err := setMode(t, s.Server, alice, "session_based")
		require.NoError(t, err)
		modeResult := result.(PasswordAccessModeResult)
		assert.Equal(t, "session_based", modeResult.Mode)
		assert.NotEmpty(t, modeResult.Message)
	})
}

// TestHandlePasswordSetAccessMode_RBACDenied is the explicit RBAC-deny
// regression for go-xkms#753: an authenticated caller without passwords:write
// must be denied before the handler ever runs, exactly like every other
// password.* method (see TestAuthorizeMethod_EveryPrivilegedMethod, which
// also walks this method generically).
func TestHandlePasswordSetAccessMode_RBACDenied(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	rbac := newFakeRBAC() // no grants
	server := newRBACServer(t, svc, rbac)

	paramsJSON, err := json.Marshal(transport.PasswordStoreSetAccessModeRequest{Mode: "session_based"})
	require.NoError(t, err)
	resp := invokeRequest(server, authedCtx(), &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "password.setAccessMode",
		Params:  paramsJSON,
		ID:      1,
	})

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error, "caller without passwords:write must be denied")
	assert.Equal(t, ErrCodeForbidden, resp.Error.Code)
	assert.Equal(t, "passwords:write", rbac.lastCall())
	assert.Nil(t, resp.Result)
}

// --- error mapping ---

func TestMapPasswordError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input error
		code  int
		want  error
	}{
		{"ErrInvalidName", staticpw.ErrInvalidName, ErrCodeInvalidParams, ErrPasswordNameRequired},
		{"ErrEmptyPassword", staticpw.ErrEmptyPassword, ErrCodeInvalidParams, ErrPasswordRequired},
		{"ErrInvalidLength", staticpw.ErrInvalidLength, ErrCodeInvalidParams, staticpw.ErrInvalidLength},
		{"ErrInvalidCharset", staticpw.ErrInvalidCharset, ErrCodeInvalidParams, staticpw.ErrInvalidCharset},
		{"ErrInvalidTenantID", staticpw.ErrInvalidTenantID, ErrCodeInvalidParams, staticpw.ErrInvalidTenantID},
		{"ErrInvalidFolderPath", staticpw.ErrInvalidFolderPath, ErrCodeInvalidParams, staticpw.ErrInvalidFolderPath},
		{"ErrFolderPathTooDeep", staticpw.ErrFolderPathTooDeep, ErrCodeInvalidParams, staticpw.ErrFolderPathTooDeep},
		{"ErrPasswordExists", staticpw.ErrPasswordExists, sdkssh.JSONRPCCodeDuplicate, staticpw.ErrPasswordExists},
		{"ErrStoreClosed", staticpw.ErrStoreClosed, ErrCodeServiceUnavailable, staticpw.ErrStoreClosed},
		{"ErrPasswordNotFound", staticpw.ErrPasswordNotFound, sdkssh.JSONRPCCodeNotFound, staticpw.ErrPasswordNotFound},
		{"ErrPasswordReadOnly", staticpw.ErrPasswordReadOnly, ErrCodeForbidden, staticpw.ErrPasswordReadOnly},
		{"ErrNotOwner", staticpw.ErrNotOwner, ErrCodeForbidden, staticpw.ErrNotOwner},
		// Store resolution errors fall through to mapPasswordStoreError.
		{"ErrStoreLocked", staticpw.ErrStoreLocked, ErrCodeInternalError, staticpw.ErrStoreLocked},
		{"xkms.ErrNotConfigured", xkms.ErrNotConfigured, ErrCodeServiceUnavailable, ErrPasswordStoreNotConfigured},
		{"ErrTenantNotFound", seal.ErrTenantNotFound, sdkssh.JSONRPCCodeNotFound, seal.ErrTenantNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mapPasswordError(tc.input)
			requireCode(t, err, tc.code)
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("classifies an unknown error as internal, not bare", func(t *testing.T) {
		// Pins go-xkms#912: an unrecognised password error must come back as
		// a *KeyOpError carrying the original error, not the bare sentinel
		// pkg/apimodule's dispatcher cannot classify.
		unknownErr := errors.New("something else")
		err := mapPasswordError(unknownErr)
		requireCode(t, err, ErrCodeInternalError)
		assert.ErrorIs(t, err, unknownErr)
	})
}

func TestMapPasswordStoreError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input error
		code  int
		want  error
	}{
		{"ErrStoreLocked", staticpw.ErrStoreLocked, ErrCodeInternalError, staticpw.ErrStoreLocked},
		{"ErrTenantSealed", seal.ErrTenantSealed, ErrCodeInternalError, seal.ErrTenantSealed},
		{"ErrTenantNotFound", seal.ErrTenantNotFound, sdkssh.JSONRPCCodeNotFound, seal.ErrTenantNotFound},
		{"staticpw.ErrNotConfigured", staticpw.ErrNotConfigured, ErrCodeServiceUnavailable, ErrPasswordStoreNotConfigured},
		{"xkms.ErrNotConfigured", xkms.ErrNotConfigured, ErrCodeServiceUnavailable, ErrPasswordStoreNotConfigured},
		{"ErrNoSystemBarrier", staticpw.ErrNoSystemBarrier, ErrCodeServiceUnavailable, ErrPasswordStoreNotConfigured},
		{"ErrNilRequest", xkms.ErrNilRequest, ErrCodeInvalidParams, xkms.ErrNilRequest},
		{"ErrInvalidUserID", staticpw.ErrInvalidUserID, ErrCodeInvalidParams, staticpw.ErrInvalidUserID},
		{"ErrNotOwner", staticpw.ErrNotOwner, ErrCodeForbidden, staticpw.ErrNotOwner},
		{"ErrInvalidScope", staticpw.ErrInvalidScope, ErrCodeInvalidParams, staticpw.ErrInvalidScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mapPasswordStoreError(tc.input)
			requireCode(t, err, tc.code)
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("classifies an unknown error as internal, not bare", func(t *testing.T) {
		unknownErr := errors.New("something else")
		err := mapPasswordStoreError(unknownErr)
		requireCode(t, err, ErrCodeInternalError)
		assert.ErrorIs(t, err, unknownErr)
	})
}

func TestMapPasswordLockError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input error
		code  int
		want  error
	}{
		{"no identity", xkms.ErrOperationNotSupported, ErrCodeMethodNotFound, xkms.ErrOperationNotSupported},
		{"already locked", staticpw.ErrStoreAlreadyLocked, ErrCodeInternalError, staticpw.ErrStoreAlreadyLocked},
		{"not configured", xkms.ErrNotConfigured, ErrCodeServiceUnavailable, ErrPasswordStoreNotConfigured},
		{"tenant not found", seal.ErrTenantNotFound, sdkssh.JSONRPCCodeNotFound, seal.ErrTenantNotFound},
		{"invalid user", staticpw.ErrInvalidUserID, ErrCodeInvalidParams, staticpw.ErrInvalidUserID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mapPasswordLockError(tc.input)
			requireCode(t, err, tc.code)
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("an already-locked session is client-facing", func(t *testing.T) {
		code, message := ClientError(mapPasswordLockError(staticpw.ErrStoreAlreadyLocked))
		assert.Equal(t, ErrCodeInternalError, code)
		assert.Contains(t, message, "already locked")
	})
}
