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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
