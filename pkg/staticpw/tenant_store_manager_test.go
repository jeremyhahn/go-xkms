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

package staticpw

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cheapKDFParams is the Argon2id cost this package's vault tests wrap
// passphrase factors with: the vault tests enroll and unlock many times, and
// the production cost (kdf.DefaultParams: 64 MiB, t=3) would make every
// derivation dominate the suite. The cost is recorded on each factor, so the
// code path exercised is the production one.
func cheapKDFParams() *kdf.KDFParams {
	return &kdf.KDFParams{Algorithm: kdf.AlgorithmArgon2id, Memory: 64, Time: 1, Threads: 1, KeyLength: 32}
}

// newTestManager creates a TenantPasswordStoreManager over in-memory tenant
// stores, with a system store, and returns the stores to seal and inspect.
func newTestManager(t *testing.T) (*TenantPasswordStoreManager, *testutil.TenantStores) {
	t.Helper()
	stores := testutil.NewTenantStores()
	systemStore := newTestStore(t)
	mgr, err := NewTenantPasswordStoreManager(stores, systemStore, WithPasskeyRelyingParty(testRelyingParty), WithPassphraseKDFParams(cheapKDFParams))
	require.NoError(t, err)
	return mgr, stores
}

// testRelyingParty is the WebAuthn relying party the test managers create
// vault passkeys for.
const testRelyingParty = "kms.example.com"

// --- NewTenantPasswordStoreManager ---

func TestNewTenantPasswordStoreManager_Success(t *testing.T) {
	systemStore := newTestStore(t)

	mgr, err := NewTenantPasswordStoreManager(testutil.NewTenantStores(), systemStore)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Same(t, systemStore, mgr.SystemStore())
}

func TestNewTenantPasswordStoreManager_NilTenantStores(t *testing.T) {
	systemStore := newTestStore(t)

	mgr, err := NewTenantPasswordStoreManager(nil, systemStore)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrNilTenantStores)
}

func TestNewTenantPasswordStoreManager_NilStore(t *testing.T) {
	mgr, err := NewTenantPasswordStoreManager(testutil.NewTenantStores(), nil)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrNilStore)
}

func TestNewTenantPasswordStoreManager_BothNil(t *testing.T) {
	mgr, err := NewTenantPasswordStoreManager(nil, nil)
	assert.Nil(t, mgr)
	// The tenant stores are checked first.
	assert.ErrorIs(t, err, ErrNilTenantStores)
}

// --- helpers ---

// scoped resolves userID's store in tenantID and asserts it is a ScopedStore.
func scoped(t *testing.T, mgr *TenantPasswordStoreManager, tenantID, userID string) *ScopedStore {
	t.Helper()
	store, err := mgr.ResolveScopedStore(t.Context(), tenantID, userID)
	require.NoError(t, err)
	s, ok := store.(*ScopedStore)
	require.True(t, ok, "expected *ScopedStore, got %T", store)
	return s
}

// pass returns userID's test passphrase credential.
func pass(t *testing.T, userID string) VaultCredential {
	t.Helper()
	return VaultCredential{Type: FactorPassphrase, Secret: testSecret(t, []byte("passphrase-of-"+userID))}
}

// testSecret seals b into a *secure.Secret for a test fixture.
func testSecret(t *testing.T, b []byte) *secure.Secret {
	t.Helper()
	secret, err := secure.NewSecret(t.Context(), b)
	require.NoError(t, err)
	return secret
}

// unlocked opens userID's session in tenantID -- enrolling its passphrase
// on first use -- and returns its store.
func unlocked(t *testing.T, mgr *TenantPasswordStoreManager, tenantID, userID string) *ScopedStore {
	t.Helper()
	ctx := context.Background()
	status, err := mgr.VaultStatus(ctx, tenantID, userID)
	require.NoError(t, err)
	switch {
	case !status.Initialized:
		_, err = mgr.EnrollFactor(ctx, tenantID, userID, pass(t, userID))
		require.NoError(t, err)
	case !status.Unlocked:
		require.NoError(t, mgr.UnlockUser(ctx, tenantID, userID, pass(t, userID)))
	}
	s := scoped(t, mgr, tenantID, userID)
	require.False(t, s.PersonalLocked())
	return s
}

// entry returns a password entry named name.
func entry(name string, shared bool) *StaticPassword {
	return &StaticPassword{Name: name, Password: "pw-" + name, Shared: shared}
}

// --- ResolveScopedStore ---

func TestResolveScopedStore_NoIdentityGetsSystemStore(t *testing.T) {
	mgr, _ := newTestManager(t)
	store, err := mgr.ResolveScopedStore(t.Context(), "", "alice")
	require.NoError(t, err)
	assert.Same(t, mgr.SystemStore(), store)
}

func TestResolveScopedStore_Refusals(t *testing.T) {
	mgr, _ := newTestManager(t)

	_, err := mgr.ResolveScopedStore(t.Context(), "bad/tenant", "alice")
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = mgr.ResolveScopedStore(t.Context(), "tenant-a", "bad/user")
	assert.ErrorIs(t, err, ErrInvalidUserID)
}

func TestResolveScopedStore_NoUserGetsSharedOnly(t *testing.T) {
	mgr, _ := newTestManager(t)
	store, err := mgr.ResolveScopedStore(t.Context(), "tenant-a", "")
	require.NoError(t, err)
	_, isScoped := store.(*ScopedStore)
	assert.False(t, isScoped, "no subject means the shared store alone")
	require.NoError(t, store.Add(entry("s", true)))
}

func TestResolveScopedStore_SessionsStartLocked(t *testing.T) {
	mgr, _ := newTestManager(t)
	s := scoped(t, mgr, "tenant-a", "alice")
	assert.True(t, s.PersonalLocked())
	assert.ErrorIs(t, s.Add(entry("mine", false)), ErrStoreLocked)
	locked, err := mgr.IsUserLocked(t.Context(), "tenant-a", "alice")
	require.NoError(t, err)
	assert.True(t, locked)
}

// --- the owner's rule: shared entries for every tenant user, personal ones
// for their owner only ---

func TestSharedEntries_VisibleToEveryTenantUserWhileLocked(t *testing.T) {
	mgr, _ := newTestManager(t)

	alice := scoped(t, mgr, "tenant-a", "alice")
	require.NoError(t, alice.Add(entry("wiki", true)))

	bob := scoped(t, mgr, "tenant-a", "bob")
	require.True(t, bob.PersonalLocked(), "bob never unlocked")
	got, err := bob.Get("wiki")
	require.NoError(t, err)
	assert.Equal(t, "alice", got.OwnerID)
	all, err := bob.List()
	require.NoError(t, err)
	require.Len(t, all, 1)
}

func TestPersonalEntries_PrivateToTheirOwner(t *testing.T) {
	mgr, _ := newTestManager(t)

	alice := unlocked(t, mgr, "tenant-a", "alice")
	secret := entry("alice-bank", false)
	require.NoError(t, alice.Add(secret))

	bob := unlocked(t, mgr, "tenant-a", "bob")
	_, err := bob.Get(secret.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
	_, err = bob.Get("alice-bank")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
	assert.ErrorIs(t, bob.Delete(secret.ID), ErrPasswordNotFound)
	mine, err := bob.ListByScope(ScopePersonal)
	require.NoError(t, err)
	assert.Empty(t, mine)

	// alice's entry is untouched.
	got, err := alice.Get(secret.ID)
	require.NoError(t, err)
	assert.Equal(t, "pw-alice-bank", got.Password)
}

// --- per-user sessions ---

func TestUserSessions_AreIndependent(t *testing.T) {
	mgr, _ := newTestManager(t)

	unlocked(t, mgr, "tenant-a", "alice")
	bobLocked, err := mgr.IsUserLocked(t.Context(), "tenant-a", "bob")
	require.NoError(t, err)
	assert.True(t, bobLocked, "alice unlocking must not unlock bob")

	unlocked(t, mgr, "tenant-a", "bob")
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	bobLocked, err = mgr.IsUserLocked(t.Context(), "tenant-a", "bob")
	require.NoError(t, err)
	assert.False(t, bobLocked, "alice locking must not lock bob")
	assert.False(t, scoped(t, mgr, "tenant-a", "bob").PersonalLocked())
	assert.True(t, scoped(t, mgr, "tenant-a", "alice").PersonalLocked())
}

func TestUserSessions_LockHidesPersonalEntries(t *testing.T) {
	mgr, _ := newTestManager(t)

	alice := unlocked(t, mgr, "tenant-a", "alice")
	personal := entry("mine", false)
	require.NoError(t, alice.Add(personal))
	require.NoError(t, alice.Add(entry("ours", true)))

	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	locked := scoped(t, mgr, "tenant-a", "alice")
	_, err := locked.Get(personal.ID)
	assert.ErrorIs(t, err, ErrStoreLocked)
	all, err := locked.List()
	require.NoError(t, err)
	require.Len(t, all, 1, "a locked listing holds the shared entries only")
	assert.Equal(t, "ours", all[0].Name)
	_, err = locked.ListByScope(ScopePersonal)
	assert.ErrorIs(t, err, ErrStoreLocked)

	// Unlocking again restores them.
	again := unlocked(t, mgr, "tenant-a", "alice")
	got, err := again.Get(personal.ID)
	require.NoError(t, err)
	assert.Equal(t, "mine", got.Name)
}

func TestUserSessions_Errors(t *testing.T) {
	mgr, _ := newTestManager(t)
	ctx := context.Background()

	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", pass(t, "alice")), ErrVaultNotInitialized)
	unlocked(t, mgr, "tenant-a", "alice")
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", pass(t, "alice")), ErrStoreNotLocked)
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	assert.ErrorIs(t, mgr.LockUser("tenant-a", "alice"), ErrStoreAlreadyLocked)

	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "bad/user", pass(t, "x")), ErrInvalidUserID)
	assert.ErrorIs(t, mgr.LockUser("tenant-a", ""), ErrInvalidUserID)
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "bad/tenant", "alice", pass(t, "alice")), ErrInvalidTenantID)
	assert.ErrorIs(t, mgr.LockUser("bad/tenant", "alice"), ErrInvalidTenantID)
	_, err := mgr.IsUserLocked(t.Context(), "bad/tenant", "alice")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestUserSessions_SealingEndsThem(t *testing.T) {
	mgr, stores := newTestManager(t)
	unlocked(t, mgr, "tenant-a", "alice")

	stores.Seal("tenant-a")
	_, err := mgr.ResolveScopedStore(t.Context(), "tenant-a", "alice")
	assert.ErrorIs(t, err, seal.ErrTenantSealed)
	assert.ErrorIs(t, mgr.UnlockUser(context.Background(), "tenant-a", "alice", pass(t, "alice")), seal.ErrTenantSealed)
	locked, err := mgr.IsUserLocked(t.Context(), "tenant-a", "alice")
	require.NoError(t, err)
	assert.True(t, locked)

	stores.Unseal("tenant-a")
	assert.True(t, scoped(t, mgr, "tenant-a", "alice").PersonalLocked(), "an unseal must not resume a session the seal ended")
}

// A tenant store that fails to resolve for any reason but a seal is a
// *StoreError naming the tenant.
func TestResolveScopedStore_ResolveFailure(t *testing.T) {
	mgr, err := NewTenantPasswordStoreManager(failingTenantStores{}, newTestStore(t))
	require.NoError(t, err)

	_, err = mgr.ResolveScopedStore(t.Context(), "tenant-a", "alice")
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "resolve", storeErr.Op)
	assert.Equal(t, "tenant-a", storeErr.Key)
	assert.ErrorIs(t, err, errReadFailed)
}

// failingTenantStores resolves no tenant.
type failingTenantStores struct{}

func (failingTenantStores) Resolve(context.Context, string) (qrdbsdk.KVStore, error) {
	return nil, errReadFailed
}

// --- tenant and system isolation ---

func TestTenants_AreIsolated(t *testing.T) {
	mgr, _ := newTestManager(t)

	a := unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, a.Add(entry("a-shared", true)))
	require.NoError(t, a.Add(entry("a-personal", false)))

	// The alice of tenant B shares the subject and sees nothing of tenant A.
	b := unlocked(t, mgr, "tenant-b", "alice")
	all, err := b.List()
	require.NoError(t, err)
	assert.Empty(t, all)
	_, err = b.Get("a-shared")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestSystemTenant_HasItsOwnStore(t *testing.T) {
	mgr, stores := newTestManager(t)

	root := unlocked(t, mgr, scope.SystemTenant, "root")
	require.NoError(t, root.Add(entry("sys-shared", true)))
	require.NoError(t, root.Add(entry("sys-personal", false)))

	// Another system user sees the system tenant's shared entry only.
	ops := scoped(t, mgr, scope.SystemTenant, "ops")
	all, err := ops.List()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "sys-shared", all[0].Name)

	// Tenants and the unscoped system store see none of it.
	tenantUser := unlocked(t, mgr, "tenant-a", "root")
	tenantAll, err := tenantUser.List()
	require.NoError(t, err)
	assert.Empty(t, tenantAll)
	flat, err := mgr.SystemStore().List()
	require.NoError(t, err)
	assert.Empty(t, flat)

	// Sealing the system tenant closes the system tenant's store.
	stores.Seal(scope.SystemTenant)
	_, err = mgr.ResolveScopedStore(t.Context(), scope.SystemTenant, "root")
	assert.ErrorIs(t, err, seal.ErrTenantSealed)
}

// --- UserStoreStatus ---

func TestUserStoreStatus_CountsWhatTheUserCanRead(t *testing.T) {
	mgr, _ := newTestManager(t)

	alice := unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, alice.Add(entry("shared", true)))
	require.NoError(t, alice.Add(entry("personal", false)))

	status, err := mgr.UserStoreStatus(t.Context(), "tenant-a", "alice")
	require.NoError(t, err)
	assert.Equal(t, TenantStoreStatus{IsLocked: false, PasswordCount: 2}, *status)

	status, err = mgr.UserStoreStatus(t.Context(), "tenant-a", "bob")
	require.NoError(t, err)
	assert.Equal(t, TenantStoreStatus{IsLocked: true, PasswordCount: 1}, *status)
}

func TestUserStoreStatus_SealedAndInvalid(t *testing.T) {
	mgr, stores := newTestManager(t)
	stores.Seal("tenant-a")

	status, err := mgr.UserStoreStatus(t.Context(), "tenant-a", "alice")
	require.NoError(t, err)
	assert.Equal(t, TenantStoreStatus{IsLocked: true, BarrierSealed: true}, *status)

	_, err = mgr.UserStoreStatus(t.Context(), "bad/tenant", "alice")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
	_, err = mgr.UserStoreStatus(t.Context(), "tenant-a", "bad/user")
	assert.Error(t, err)
}

// --- caching and Close ---

func TestResolveScopedStore_SharesTheSession(t *testing.T) {
	mgr, _ := newTestManager(t)
	first := unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, first.Add(entry("mine", false)))

	second := scoped(t, mgr, "tenant-a", "alice")
	got, err := second.Get("mine")
	require.NoError(t, err, "every resolution serves the one open session")
	assert.Equal(t, "pw-mine", got.Password)
}

func TestClose_EndsSessions(t *testing.T) {
	mgr, _ := newTestManager(t)
	s := unlocked(t, mgr, "tenant-a", "alice")

	require.NoError(t, mgr.Close())
	assert.ErrorIs(t, s.personal.Add(entry("late", false)), ErrStoreLocked,
		"a personal store held past Close has no key to seal with")
	locked, err := mgr.IsUserLocked(t.Context(), "tenant-a", "alice")
	require.NoError(t, err)
	assert.True(t, locked, "Close ends every session")

	empty, _ := newTestManager(t)
	require.NoError(t, empty.Close())
}
