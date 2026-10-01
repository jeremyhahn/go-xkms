// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// passkey returns a passkey credential: a credential ID, the PRF salt the
// authenticator evaluated hmac-secret over, and its 32-byte output.
func passkey(t *testing.T, id string, output byte) VaultCredential {
	t.Helper()
	return VaultCredential{
		Type:         FactorPasskey,
		CredentialID: []byte(id),
		PRFSalt:      bytes.Repeat([]byte{0x5a}, PRFSaltLength),
		Secret:       testSecret(t, bytes.Repeat([]byte{output}, PasskeySecretLength)),
		Label:        "key " + id,
		RelyingParty: testRelyingParty,
	}
}

// vaultFixture is a manager with tenant-a registered and the tenant's raw
// barrier backend, to inspect what is stored.
func vaultFixture(t *testing.T) (*TenantPasswordStoreManager, *seal.BarrierRegistry, storage.Backend) {
	t.Helper()
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "tenant-a")
	tb, err := reg.Tenant("tenant-a")
	require.NoError(t, err)
	return mgr, reg, seal.NewBarrierBackend(tb.Barrier())
}

func TestVault_FirstEnrollmentInitializesAndIssuesRecoveryCode(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()

	status, err := mgr.VaultStatus(ctx, "tenant-a", "alice")
	require.NoError(t, err)
	assert.False(t, status.Initialized)

	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", pass(t, "alice"))
	require.NoError(t, err)
	assert.Regexp(t, `^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$`, res.RecoveryCode)
	assert.Equal(t, FactorPassphrase, res.Factor.Type)

	status, err = mgr.VaultStatus(ctx, "tenant-a", "alice")
	require.NoError(t, err)
	assert.True(t, status.Initialized)
	assert.True(t, status.Unlocked, "the first enrollment opens the session")
	types := []FactorType{}
	for _, f := range status.Factors {
		types = append(types, f.Type)
	}
	assert.ElementsMatch(t, []FactorType{FactorPassphrase, FactorRecovery}, types)
}

// TestVault_TenantKeyAloneCannotReadPersonalEntries is the owner's rule: a
// personal entry is sealed with the user's DEK before it reaches the tenant
// barrier, so everything the barrier holds for it -- the entry and the
// wrapped DEKs -- is opaque without one of the user's factors.
func TestVault_TenantKeyAloneCannotReadPersonalEntries(t *testing.T) {
	mgr, _, raw := vaultFixture(t)
	ctx := context.Background()
	alice := unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, alice.Add(&StaticPassword{Name: "bank", Username: "alice", Password: "correct horse battery staple"}))

	personal, err := scope.PersonalPrefix("tenant-a", Feature, "alice")
	require.NoError(t, err)
	found := 0
	require.NoError(t, raw.Scan(ctx, personal, func(key string, value []byte) error {
		found++
		assert.NotContains(t, string(value), "correct horse", "entry %s is readable with the tenant key", key)
		assert.NotContains(t, string(value), "bank")
		return nil
	}))
	require.Equal(t, 1, found)

	vault, err := scope.PersonalPrefix("tenant-a", VaultFeature, "alice")
	require.NoError(t, err)
	require.NoError(t, raw.Scan(ctx, vault, func(_ string, value []byte) error {
		assert.NotContains(t, string(value), "passphrase-of-alice")
		return nil
	}))

	// And the entry reads back through the user's own session.
	got, err := alice.Get("bank")
	require.NoError(t, err)
	assert.Equal(t, "correct horse battery staple", got.Password)
}

func TestVault_UnlockWithPassphrase(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	alice := unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, alice.Add(entry("mine", false)))
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))

	wrong := VaultCredential{Type: FactorPassphrase, Secret: testSecret(t, []byte("not-alice's-passphrase"))}
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", wrong), ErrVaultCredentialRejected)
	assert.True(t, scoped(t, mgr, "tenant-a", "alice").PersonalLocked())

	require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", pass(t, "alice")))
	got, err := scoped(t, mgr, "tenant-a", "alice").Get("mine")
	require.NoError(t, err)
	assert.Equal(t, "pw-mine", got.Password)
}

func TestVault_PasskeyFactor(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()

	// A passkey can be the first factor.
	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", passkey(t, "cred-1", 0x11))
	require.NoError(t, err)
	require.NotEmpty(t, res.RecoveryCode)
	assert.Equal(t, []byte("cred-1"), res.Factor.CredentialID)
	assert.Len(t, res.Factor.PRFSalt, PRFSaltLength, "the client reads the salt back to evaluate hmac-secret")
	require.NoError(t, scoped(t, mgr, "tenant-a", "alice").Add(entry("mine", false)))

	_, err = mgr.EnrollFactor(ctx, "tenant-a", "alice", passkey(t, "cred-1", 0x22))
	assert.ErrorIs(t, err, ErrVaultPasskeyExists)
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))

	wrongOutput := passkey(t, "cred-1", 0x99)
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", wrongOutput), ErrVaultCredentialRejected)
	unknown := passkey(t, "cred-2", 0x11)
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", unknown), ErrVaultCredentialRejected)

	require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", passkey(t, "cred-1", 0x11)))
	_, err = scoped(t, mgr, "tenant-a", "alice").Get("mine")
	require.NoError(t, err)
}

func TestVault_BothFactorsOpenTheSameEntries(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	alice := unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, alice.Add(entry("mine", false)))

	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", passkey(t, "cred-1", 0x11))
	require.NoError(t, err)
	assert.Empty(t, res.RecoveryCode, "only the first enrollment issues a recovery code")

	for _, cred := range []VaultCredential{pass(t, "alice"), passkey(t, "cred-1", 0x11)} {
		require.NoError(t, mgr.LockUser("tenant-a", "alice"))
		require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", cred), string(cred.Type))
		got, gerr := scoped(t, mgr, "tenant-a", "alice").Get("mine")
		require.NoError(t, gerr, string(cred.Type))
		assert.Equal(t, "pw-mine", got.Password)
	}
}

func TestVault_LaterEnrollmentNeedsTheSession(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))

	_, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", passkey(t, "cred-1", 0x11))
	assert.ErrorIs(t, err, ErrStoreLocked, "a locked user cannot add a factor: nobody else may enroll into their vault")
}

func TestVault_RotateFactorKeepsTheDEK(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	alice := unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, alice.Add(entry("mine", false)))

	status, err := mgr.VaultStatus(ctx, "tenant-a", "alice")
	require.NoError(t, err)
	var passID string
	for _, f := range status.Factors {
		if f.Type == FactorPassphrase {
			passID = f.ID
		}
	}
	require.NotEmpty(t, passID)

	next := VaultCredential{Type: FactorPassphrase, Secret: testSecret(t, []byte("a brand new passphrase"))}
	_, err = mgr.RotateFactor(ctx, "tenant-a", "alice", passID, passkey(t, "cred-1", 0x11))
	assert.ErrorIs(t, err, ErrVaultInvalidCredential, "rotation keeps the factor's type")
	res, err := mgr.RotateFactor(ctx, "tenant-a", "alice", passID, next)
	require.NoError(t, err)
	assert.NotEqual(t, passID, res.Factor.ID)

	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", pass(t, "alice")), ErrVaultCredentialRejected)
	require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", next))
	got, err := scoped(t, mgr, "tenant-a", "alice").Get("mine")
	require.NoError(t, err, "the DEK never changes, so entries sealed before rotation still open")
	assert.Equal(t, "pw-mine", got.Password)

	_, err = mgr.RotateFactor(ctx, "tenant-a", "alice", "missing", next)
	assert.ErrorIs(t, err, ErrVaultFactorNotFound)
}

func TestVault_RemoveFactor(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	unlocked(t, mgr, "tenant-a", "alice")
	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", passkey(t, "cred-1", 0x11))
	require.NoError(t, err)

	status, err := mgr.VaultStatus(ctx, "tenant-a", "alice")
	require.NoError(t, err)
	var passID, recoveryID string
	for _, f := range status.Factors {
		switch f.Type {
		case FactorPassphrase:
			passID = f.ID
		case FactorRecovery:
			recoveryID = f.ID
		}
	}

	assert.ErrorIs(t, mgr.RemoveFactor(ctx, "tenant-a", "alice", recoveryID), ErrVaultRecoveryFactor)
	assert.ErrorIs(t, mgr.RemoveFactor(ctx, "tenant-a", "alice", "missing"), ErrVaultFactorNotFound)
	require.NoError(t, mgr.RemoveFactor(ctx, "tenant-a", "alice", passID))
	assert.ErrorIs(t, mgr.RemoveFactor(ctx, "tenant-a", "alice", res.Factor.ID), ErrVaultLastFactor)

	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", pass(t, "alice")), ErrVaultCredentialRejected)
	assert.ErrorIs(t, mgr.RemoveFactor(ctx, "tenant-a", "alice", res.Factor.ID), ErrStoreLocked)
}

func TestVault_RecoveryIsOneTime(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", pass(t, "alice"))
	require.NoError(t, err)
	require.NoError(t, scoped(t, mgr, "tenant-a", "alice").Add(entry("mine", false)))
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))

	// The code does not unlock; it recovers.
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", VaultCredential{Type: FactorRecovery, Secret: testSecret(t, []byte(res.RecoveryCode))}), ErrVaultRecoveryFactor)

	newPass := VaultCredential{Type: FactorPassphrase, Secret: testSecret(t, []byte("remembered at last"))}
	_, err = mgr.RecoverVault(ctx, "tenant-a", "alice", []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"), newPass)
	assert.ErrorIs(t, err, ErrVaultCredentialRejected)

	// Typed as the user might: lower case, spaces for dashes.
	typed := strings.ToLower(strings.ReplaceAll(res.RecoveryCode, "-", " "))
	recovered, err := mgr.RecoverVault(ctx, "tenant-a", "alice", []byte(typed), newPass)
	require.NoError(t, err)
	require.NotEmpty(t, recovered.RecoveryCode)
	assert.NotEqual(t, res.RecoveryCode, recovered.RecoveryCode, "a used code is replaced")

	got, err := scoped(t, mgr, "tenant-a", "alice").Get("mine")
	require.NoError(t, err, "recovery opens the session over the same DEK")
	assert.Equal(t, "pw-mine", got.Password)

	_, err = mgr.RecoverVault(ctx, "tenant-a", "alice", []byte(res.RecoveryCode), pass(t, "alice"))
	assert.ErrorIs(t, err, ErrVaultCredentialRejected, "the used code no longer works")

	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", newPass))
	status, err := mgr.VaultStatus(ctx, "tenant-a", "alice")
	require.NoError(t, err)
	recoveries := 0
	for _, f := range status.Factors {
		if f.Type == FactorRecovery {
			recoveries++
		}
	}
	assert.Equal(t, 1, recoveries)
}

func TestVault_RecoverRefusals(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	_, err := mgr.RecoverVault(ctx, "tenant-a", "alice", []byte("CODE"), pass(t, "alice"))
	assert.ErrorIs(t, err, ErrVaultNotInitialized)
	_, err = mgr.RecoverVault(ctx, "tenant-a", "alice", nil, pass(t, "alice"))
	assert.ErrorIs(t, err, ErrVaultInvalidCredential)
	_, err = mgr.RecoverVault(ctx, "tenant-a", "alice", []byte("CODE"), VaultCredential{Type: FactorRecovery, Secret: testSecret(t, []byte("x"))})
	assert.ErrorIs(t, err, ErrVaultRecoveryFactor)
}

func TestVault_InvalidCredentials(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	cases := map[string]VaultCredential{
		"short passphrase":    {Type: FactorPassphrase, Secret: testSecret(t, []byte("short"))},
		"passkey without id":  {Type: FactorPasskey, Secret: testSecret(t, make([]byte, PasskeySecretLength)), PRFSalt: make([]byte, PRFSaltLength)},
		"passkey short out":   {Type: FactorPasskey, CredentialID: []byte("c"), Secret: testSecret(t, []byte("short")), PRFSalt: make([]byte, PRFSaltLength)},
		"passkey bad salt":    {Type: FactorPasskey, CredentialID: []byte("c"), Secret: testSecret(t, make([]byte, PasskeySecretLength)), PRFSalt: []byte("s")},
		"unknown factor type": {Type: "pin", Secret: testSecret(t, []byte("12345678"))},
	}
	for name, cred := range cases {
		_, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", cred)
		assert.ErrorIs(t, err, ErrVaultInvalidCredential, name)
	}
	_, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", VaultCredential{Type: FactorRecovery, Secret: testSecret(t, []byte("x"))})
	assert.ErrorIs(t, err, ErrVaultRecoveryFactor)
	_, err = mgr.EnrollFactor(ctx, "tenant-a", "bad/user", pass(t, "x"))
	assert.ErrorIs(t, err, ErrInvalidUserID)
}

// TestVault_WrapsAreBoundToTheirUser proves a wrapped DEK copied into another
// user's keyring does not open there, even with the right secret.
func TestVault_WrapsAreBoundToTheirUser(t *testing.T) {
	_, _, raw := vaultFixture(t)
	alice, err := newVaultKeyring(raw, "tenant-a", "alice", cheapKDFParams)
	require.NoError(t, err)
	bob, err := newVaultKeyring(raw, "tenant-a", "bob", cheapKDFParams)
	require.NoError(t, err)

	dek := bytes.Repeat([]byte{7}, dekLength)
	f, err := alice.wrap(pass(t, "same"), dek)
	require.NoError(t, err)
	got, err := alice.unwrap(f, pass(t, "same").Secret)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
	_, err = bob.unwrap(f, pass(t, "same").Secret)
	assert.ErrorIs(t, err, ErrVaultCredentialRejected)
}

// TestDEKBackend_EntriesAreBoundToTheirKey proves a sealed entry moved under
// another key does not open.
func TestDEKBackend_EntriesAreBoundToTheirKey(t *testing.T) {
	ctx := context.Background()
	inner := storage.New()
	b := newDEKBackend(inner, bytes.Repeat([]byte{9}, dekLength))
	require.NoError(t, b.Put(ctx, "a", []byte("secret")))

	sealed, err := inner.Get(ctx, "a")
	require.NoError(t, err)
	assert.NotContains(t, string(sealed), "secret")
	require.NoError(t, inner.Put(ctx, "b", sealed))
	_, err = b.Get(ctx, "b")
	var decrypt *PersonalEntryDecryptError
	require.ErrorAs(t, err, &decrypt)

	got, err := b.Get(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, "secret", string(got))
	stored, err := b.PutIfAbsent(ctx, "c", []byte("v"))
	require.NoError(t, err)
	assert.True(t, stored)
	keys, err := b.List(ctx, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a", "b", "c"}, keys)
	exists, err := b.Exists(ctx, "c")
	require.NoError(t, err)
	assert.True(t, exists)
	require.NoError(t, b.Delete(ctx, "c"))
	require.ErrorAs(t, b.Scan(ctx, "", func(string, []byte) error { return nil }), &decrypt, "the moved entry fails the scan")
	require.NoError(t, b.Close())
	_, err = inner.Get(ctx, "a")
	require.NoError(t, err, "Close leaves the tenant barrier open")
}

// TestVault_ConcurrentFirstEnrollmentsShareOneDEK proves two first
// enrollments racing mint one DEK: both factors open the same entries.
func TestVault_ConcurrentFirstEnrollmentsShareOneDEK(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	creds := []VaultCredential{pass(t, "alice"), passkey(t, "cred-1", 0x11)}

	var wg sync.WaitGroup
	errs := make([]error, len(creds))
	for i, cred := range creds {
		wg.Add(1)
		go func(i int, cred VaultCredential) {
			defer wg.Done()
			_, errs[i] = mgr.EnrollFactor(ctx, "tenant-a", "alice", cred)
		}(i, cred)
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, scoped(t, mgr, "tenant-a", "alice").Add(entry("mine", false)))

	for _, cred := range creds {
		require.NoError(t, mgr.LockUser("tenant-a", "alice"))
		require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", cred))
		_, err := scoped(t, mgr, "tenant-a", "alice").Get("mine")
		require.NoError(t, err, string(cred.Type))
	}
}

// TestTenantState_ConcurrentFirstUseDoesNotSealTheTenant is the regression
// for the duplicate tenant state a racing first use builds: dropping it used
// to close its store, whose backend is the tenant barrier, sealing the
// tenant under the state that won.
func TestTenantState_ConcurrentFirstUseDoesNotSealTheTenant(t *testing.T) {
	mgr, reg, _ := vaultFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := mgr.ResolveScopedStore("tenant-a", "alice")
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	tb, err := reg.Tenant("tenant-a")
	require.NoError(t, err)
	assert.False(t, tb.IsSealed())
}
