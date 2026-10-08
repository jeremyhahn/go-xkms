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

package localseal

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errBackendOutage is the sentinel a existsFailingBackend returns from
// Exists, so tests can distinguish "the transport is down" from "the key is
// absent" in assertions.
var errBackendOutage = errors.New("localseal test: backend outage")

// existsFailingBackend wraps a storage.Backend and fails every Exists with
// errBackendOutage instead of delegating — the seam this package's own
// production code already relies on (storage.Backend is an interface
// embedded by value throughout). qrdb's StorageBarrier.Initialize probes
// the root-key path with Exists (not Get) before creating it, so this is
// the call that must fail to force Initialize's non-already-initialized
// error branch.
type existsFailingBackend struct {
	storage.Backend
}

func (existsFailingBackend) Exists(context.Context, string) (bool, error) {
	return false, errBackendOutage
}

const testRootKeyPath = "pkcs11/token/root-key"

// TestController_EncryptsAtRestAndUnsealsWithUserPIN is the decisive test: it
// proves the private key material is genuinely encrypted at rest under the user
// PIN, unreadable while sealed, and recovered after unseal — the whole point of
// C9/L3.
func TestController_EncryptsAtRestAndUnsealsWithUserPIN(t *testing.T) {
	base := storage.NewMemory()
	ctx := context.Background()
	userPIN := []byte("user-pin-1234")
	secret := []byte("private-key-material")

	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)

	// Unseal with the user PIN (first use initializes the barrier), write the
	// sensitive material through the sealed backend, then reseal.
	require.NoError(t, ctrl.Unseal(userPIN))
	require.NoError(t, sealed.Put(ctx, "keys/priv", secret))
	require.NoError(t, ctrl.Seal())

	// At rest, the ciphertext in the base store must NOT contain the plaintext.
	var sawPlaintext bool
	require.NoError(t, base.Scan(ctx, "", func(_ string, value []byte) error {
		if bytes.Contains(value, secret) {
			sawPlaintext = true
		}
		return nil
	}))
	assert.False(t, sawPlaintext, "the private key material must be encrypted at rest, not stored in cleartext")

	// After resealing with the correct PIN, the material round-trips.
	require.NoError(t, ctrl.Unseal(userPIN))
	got, err := sealed.Get(ctx, "keys/priv")
	require.NoError(t, err)
	assert.Equal(t, secret, got, "the correct user PIN must recover the material")
}

// TestController_WrongPINCannotUnseal proves a different PIN cannot open the
// barrier — the passphrase actually gates access.
func TestController_WrongPINCannotUnseal(t *testing.T) {
	base := storage.NewMemory()
	ctx := context.Background()

	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Unseal([]byte("correct-pin")))
	require.NoError(t, sealed.Put(ctx, "keys/priv", []byte("material")))
	require.NoError(t, ctrl.Seal())

	// A fresh controller over the same base (simulating a process restart) with
	// the wrong PIN must fail to unseal.
	ctrl2, _, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	err = ctrl2.Unseal([]byte("wrong-pin"))
	assert.Error(t, err, "the wrong PIN must not unseal the barrier")
}

// TestController_SurvivesRestart proves the sealed store persists across a
// fresh Controller over the same base storage — an offline token must reopen
// after the process restarts.
func TestController_SurvivesRestart(t *testing.T) {
	base := storage.NewMemory()
	ctx := context.Background()
	pin := []byte("persist-pin")

	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Unseal(pin))
	require.NoError(t, sealed.Put(ctx, "keys/priv", []byte("durable")))
	require.NoError(t, ctrl.Seal())

	// New Controller (new process) over the same base, same PIN.
	ctrl2, sealed2, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl2.Unseal(pin))
	got, err := sealed2.Get(ctx, "keys/priv")
	require.NoError(t, err)
	assert.Equal(t, []byte("durable"), got)
}

// TestController_RekeyChangesPINWithoutLosingData is the decisive rekey test:
// after a PIN change the material is intact and readable with the NEW PIN, and
// the OLD PIN no longer opens the barrier — proving C_SetPIN re-protects the
// keys rather than bricking them.
func TestController_RekeyChangesPINWithoutLosingData(t *testing.T) {
	base := storage.NewMemory()
	ctx := context.Background()
	oldPIN := []byte("old-pin")
	newPIN := []byte("new-pin")
	secret := []byte("private-key-material")

	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Unseal(oldPIN))
	require.NoError(t, sealed.Put(ctx, "keys/priv", secret))

	// Change the PIN while unsealed (a logged-in-user C_SetPIN).
	require.NoError(t, ctrl.Rekey(oldPIN, newPIN))
	require.NoError(t, ctrl.Seal())

	// The NEW PIN opens the barrier and the data is intact.
	ctrlNew, sealedNew, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrlNew.Unseal(newPIN))
	got, err := sealedNew.Get(ctx, "keys/priv")
	require.NoError(t, err)
	assert.Equal(t, secret, got, "data must survive the PIN change")

	// The OLD PIN must no longer open the barrier.
	ctrlOld, _, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	assert.Error(t, ctrlOld.Unseal(oldPIN), "the old PIN must not open the barrier after a rekey")
}

// TestController_RekeyPreservesSealState proves a rekey from a SEALED barrier (a
// public-session C_SetPIN) reseals afterward, so it never leaves key material
// exposed.
func TestController_RekeyPreservesSealState(t *testing.T) {
	base := storage.NewMemory()
	ctx := context.Background()

	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Unseal([]byte("p1")))
	require.NoError(t, sealed.Put(ctx, "keys/priv", []byte("material")))
	require.NoError(t, ctrl.Seal())

	// Rekey while sealed (supplying the old PIN); must reseal afterward.
	require.NoError(t, ctrl.Rekey([]byte("p1"), []byte("p2")))
	assert.True(t, ctrl.barrier.IsSealed(), "a rekey that unsealed to re-wrap must reseal")
}

// TestController_RekeyBeforeInitIsNoOp proves changing the PIN before the barrier
// is ever initialized (no key created yet) is harmless — the next login keys it
// to the new PIN.
func TestController_RekeyBeforeInitIsNoOp(t *testing.T) {
	base := storage.NewMemory()
	ctx := context.Background()

	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)

	// No unseal yet → barrier not initialized. Rekey must be a no-op.
	require.NoError(t, ctrl.Rekey([]byte("old"), []byte("new")))

	// The new PIN then keys the store on first unseal.
	require.NoError(t, ctrl.Unseal([]byte("new")))
	require.NoError(t, sealed.Put(ctx, "keys/priv", []byte("v")))
	got, err := sealed.Get(ctx, "keys/priv")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
}

// TestController_RekeyChangePasswordFailureSurfacesErrorAndReseals is the
// failure-injection test for the reseal-on-failure paths in Rekey: an empty
// new passphrase makes qrdb's ChangePassword fail with ErrInvalidPassphrase
// (CredentialsFor tolerates an empty secret; ChangePassword itself does not).
// It proves the failure (a) is returned to the caller rather than swallowed,
// and (b) still leaves the barrier resealed — a rekey attempted from a sealed
// (public) session must never exit unsealed, success or failure.
func TestController_RekeyChangePasswordFailureSurfacesErrorAndReseals(t *testing.T) {
	base := storage.NewMemory()
	ctx := context.Background()
	pin := []byte("p1")

	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Unseal(pin))
	require.NoError(t, sealed.Put(ctx, "keys/priv", []byte("material")))
	require.NoError(t, ctrl.Seal())

	// Rekey from a sealed session with an empty new passphrase: ChangePassword
	// rejects it with ErrInvalidPassphrase instead of the silent success a
	// discarded reseal error used to allow.
	err = ctrl.Rekey(pin, nil)
	assert.Error(t, err, "an empty new passphrase must fail the rekey rather than succeed silently")
	assert.True(t, ctrl.barrier.IsSealed(), "a rekey that fails after unsealing to re-wrap must still reseal")

	// The original PIN must still open the barrier: the failed rekey did not
	// commit a new (invalid) password.
	require.NoError(t, ctrl.Unseal(pin))
	got, err := sealed.Get(ctx, "keys/priv")
	require.NoError(t, err)
	assert.Equal(t, []byte("material"), got, "data must survive a rejected rekey")
}

// errCredentialsFor is the sentinel a failing seal.CredentialsFor stand-in
// returns, so assertions can tell "the injected failure" from any other
// error the barrier itself might produce.
var errCredentialsFor = errors.New("localseal test: CredentialsFor unavailable")

// withFailingCredentialsFor swaps the package-level seal.CredentialsFor seam
// (pkg/seal/strategy.go) for the duration of the calling test with a stand-in
// that always fails, and restores the original via t.Cleanup. It is the
// only way to force the credErr branches in Unseal and Rekey: the real
// CredentialsFor only errors when go-enclave's mlock fails to protect a
// non-empty secret, which is not a fault a portable, host-safe unit test can
// reliably trigger.
func withFailingCredentialsFor(t *testing.T) {
	t.Helper()
	original := seal.CredentialsFor
	seal.CredentialsFor = func(_ context.Context, _ []byte) (seal.Credentials, error) {
		return seal.Credentials{}, errCredentialsFor
	}
	t.Cleanup(func() { seal.CredentialsFor = original })
}

// TestController_Unseal_CredentialsFailureSurfacesError proves Unseal returns
// the CredentialsFor failure rather than proceeding as if no passphrase were
// supplied.
func TestController_Unseal_CredentialsFailureSurfacesError(t *testing.T) {
	ctrl, _, err := New(storage.NewMemory(), testRootKeyPath, nil)
	require.NoError(t, err)

	withFailingCredentialsFor(t)

	err = ctrl.Unseal([]byte("pin"))
	assert.ErrorIs(t, err, errCredentialsFor,
		"Unseal must surface a CredentialsFor failure rather than swallow it")
}

// TestController_Rekey_OldCredentialsFailureSurfacesError proves the
// oldPassphrase CredentialsFor failure inside a sealed Rekey is returned to
// the caller.
func TestController_Rekey_OldCredentialsFailureSurfacesError(t *testing.T) {
	base := storage.NewMemory()
	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Unseal([]byte("correct-pin")))
	require.NoError(t, sealed.Put(context.Background(), "keys/priv", []byte("material")))
	require.NoError(t, ctrl.Seal())

	withFailingCredentialsFor(t)

	err = ctrl.Rekey([]byte("correct-pin"), []byte("new-pin"))
	assert.ErrorIs(t, err, errCredentialsFor,
		"Rekey must surface a failure building credentials for the old passphrase")
	assert.True(t, ctrl.barrier.IsSealed(), "a Rekey that never unsealed must leave the barrier sealed")
}

// TestController_Rekey_NewCredentialsFailureSurfacesErrorAndReseals proves the
// newPassphrase CredentialsFor failure inside Rekey is returned to the
// caller and, because the failure occurs after the barrier was unsealed to
// verify the old PIN, that the barrier is left resealed rather than exposed.
func TestController_Rekey_NewCredentialsFailureSurfacesErrorAndReseals(t *testing.T) {
	base := storage.NewMemory()
	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	pin := []byte("correct-pin")
	require.NoError(t, ctrl.Unseal(pin))
	require.NoError(t, sealed.Put(context.Background(), "keys/priv", []byte("material")))
	require.NoError(t, ctrl.Seal())

	original := seal.CredentialsFor
	seal.CredentialsFor = func(ctx context.Context, secret []byte) (seal.Credentials, error) {
		// Let the real implementation authenticate the old PIN so Rekey
		// reaches the newPassphrase call, which is the one made to fail.
		if string(secret) == string(pin) {
			return original(ctx, secret)
		}
		return seal.Credentials{}, errCredentialsFor
	}
	t.Cleanup(func() { seal.CredentialsFor = original })

	err = ctrl.Rekey(pin, []byte("new-pin"))
	assert.ErrorIs(t, err, errCredentialsFor,
		"Rekey must surface a failure building credentials for the new passphrase")
	assert.True(t, ctrl.barrier.IsSealed(),
		"a Rekey that fails after unsealing to verify the old PIN must reseal before returning")

	// The old PIN must still open the barrier: nothing committed.
	require.NoError(t, ctrl.Unseal(pin))
	got, err := sealed.Get(context.Background(), "keys/priv")
	require.NoError(t, err)
	assert.Equal(t, []byte("material"), got, "data must survive a rejected rekey")
}

// TestController_SealIsIdempotent proves Seal is safe to call when already
// sealed (the module calls it on every logout and finalize).
func TestController_SealIsIdempotent(t *testing.T) {
	ctrl, _, err := New(storage.NewMemory(), testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Seal(), "sealing a never-unsealed barrier is a no-op")
	require.NoError(t, ctrl.Unseal([]byte("pin")))
	require.NoError(t, ctrl.Seal())
	require.NoError(t, ctrl.Seal(), "sealing an already-sealed barrier is a no-op")
}

// TestController_Unseal_BackendOutageDuringInitializeSurfacesError proves a
// storage failure distinct from "no root key yet" (ErrNotFound) is reported
// to the caller rather than folded into the benign already-initialized case.
func TestController_Unseal_BackendOutageDuringInitializeSurfacesError(t *testing.T) {
	ctrl, _, err := New(existsFailingBackend{Backend: storage.NewMemory()}, testRootKeyPath, nil)
	require.NoError(t, err)

	err = ctrl.Unseal([]byte("pin"))
	require.Error(t, err, "a backend outage during Initialize must not be swallowed")
	assert.NotErrorIs(t, err, storage.ErrNotFound, "the outage must not be mistaken for an absent root key")
}

// TestController_Rekey_WrongOldPINWhileSealedSurfacesError proves the
// barrier.Unseal failure inside Rekey (distinct from Controller.Unseal's own
// call) is returned rather than silently treated as a no-op.
func TestController_Rekey_WrongOldPINWhileSealedSurfacesError(t *testing.T) {
	base := storage.NewMemory()
	ctrl, sealed, err := New(base, testRootKeyPath, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Unseal([]byte("correct-pin")))
	require.NoError(t, sealed.Put(context.Background(), "keys/priv", []byte("material")))
	require.NoError(t, ctrl.Seal())

	err = ctrl.Rekey([]byte("wrong-pin"), []byte("new-pin"))
	assert.Error(t, err, "rekeying a sealed barrier with the wrong old PIN must fail")
	assert.True(t, ctrl.barrier.IsSealed(), "a failed rekey must leave the barrier sealed")
}
