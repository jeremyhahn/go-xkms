// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package services

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The app lock and the barrier are two independently held halves of one lock,
// and unlock has to converge BOTH. These tests pin the whole state table,
// because the reported defect was not a wrong answer in one state -- it was a
// state the implementation never reached.
//
// The defect: with the app lock already open and the barrier sealed, unlock
// returned "app_lock: already unlocked" and never touched the barrier. The
// operator's PIN did nothing, the half that gates credential storage stayed
// closed, and the only recovery was restarting the daemon -- while the
// symptom surfaced somewhere else entirely, as a storage error from the
// FIDO2 authenticator.

// newConvergenceLockService builds a service over a barrier double in the
// requested state. appLocked chooses whether the app lock is engaged; the
// PIN service accepts any PIN, so an unlock's only way to fail is the
// barrier's.
func newConvergenceLockService(t *testing.T, appLocked bool, barrier *mockBarrierService) *AppLockService {
	t.Helper()

	svc := newBarrierBackedAppLockService(t, barrier, nil)
	if !appLocked {
		// AutoUnlock opens the app lock without going through the barrier,
		// which is exactly how production reaches this state: the app was
		// unlocked at some point and the barrier was sealed afterwards.
		svc.AutoUnlock()
	}
	require.Equal(t, appLocked, svc.IsLocked())
	return svc
}

// Both halves locked: the ordinary startup unlock. Both must open.
func TestUnlockConverges_AppLockedAndBarrierSealed(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true}
	svc := newConvergenceLockService(t, true, barrier)

	result := svc.HandleUnlock("correct-pin")

	require.True(t, result.Success, "unexpected failure: %s", result.Error)
	assert.Equal(t, []string{SubsystemAppLock, SubsystemBarrier}, result.Unlocked)
	assert.Empty(t, result.StillLocked)
	assert.False(t, svc.IsLocked())
	assert.True(t, barrier.IsUnsealed())
}

// THE DEFECT. App lock open, barrier sealed: the unlock must unseal the
// barrier rather than refuse because the app lock needs nothing.
func TestUnlockConverges_AppUnlockedAndBarrierSealed(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true}
	svc := newConvergenceLockService(t, false, barrier)

	result := svc.HandleUnlock("correct-pin")

	require.True(t, result.Success, "unexpected failure: %s", result.Error)
	assert.True(t, barrier.unsealCalled, "the barrier was never asked to unseal")
	assert.True(t, barrier.IsUnsealed(), "the barrier is still sealed")
	assert.Equal(t, []string{SubsystemBarrier}, result.Unlocked,
		"only the barrier changed, so only the barrier is reported")
	assert.Empty(t, result.StillLocked)
	assert.False(t, svc.IsLocked())
}

// The credential still reaches the barrier on this path: an already-open app
// lock must not become a way to unseal without the right PIN.
func TestUnlockConverges_AppUnlockedAndBarrierSealed_PassesThePIN(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true}
	svc := newConvergenceLockService(t, false, barrier)

	require.NoError(t, svc.Unlock("the-barrier-password"))
	assert.Equal(t, "the-barrier-password", barrier.unsealPassword)
}

// Both halves open: nothing to converge. Idempotent success, and no
// credential is spent -- a backend that counts attempts must not be walked
// toward its lockout by a no-op.
func TestUnlockConverges_BothUnlockedIsIdempotent(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: false}
	svc := newConvergenceLockService(t, false, barrier)

	result := svc.HandleUnlock("correct-pin")

	require.True(t, result.Success, "unexpected failure: %s", result.Error)
	assert.Empty(t, result.Unlocked, "nothing changed, so nothing is claimed")
	assert.Empty(t, result.StillLocked)
	assert.False(t, barrier.unsealCalled, "an already-open barrier must not be re-unsealed")
	assert.False(t, svc.IsLocked())

	// Twice, because idempotence is the property under test.
	again := svc.HandleUnlock("correct-pin")
	assert.True(t, again.Success)
	assert.False(t, barrier.unsealCalled)
}

// An invalid PIN is still refused on the app-unlocked path, and the barrier
// is still reported as locked. Convergence must not become fail-open.
func TestUnlockConverges_AppUnlockedAndBarrierSealed_InvalidPINRefused(t *testing.T) {
	barrier := &mockBarrierService{
		initialized: true,
		sealed:      true,
		unsealErr:   errors.New("barrier: decrypt failed"),
	}
	svc := newConvergenceLockService(t, false, barrier)

	result := svc.HandleUnlock("wrong-pin")

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, ErrAppLockPINInvalid.Error())
	assert.Equal(t, []string{SubsystemBarrier}, result.StillLocked)
	assert.Empty(t, result.Unlocked)
	assert.False(t, barrier.IsUnsealed())
}

// The same refusal through Unlock, which is what the GUI calls directly.
func TestUnlockConverges_AppUnlockedAndBarrierSealed_InvalidPINError(t *testing.T) {
	barrier := &mockBarrierService{
		initialized: true,
		sealed:      true,
		unsealErr:   errors.New("barrier: decrypt failed"),
	}
	svc := newConvergenceLockService(t, false, barrier)

	err := svc.Unlock("wrong-pin")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINInvalid), "got %v", err)
	assert.False(t, barrier.IsUnsealed())
}

// An empty PIN is refused before the barrier is touched on this path too.
func TestUnlockConverges_AppUnlockedAndBarrierSealed_EmptyPINRefused(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: true}
	svc := newConvergenceLockService(t, false, barrier)

	err := svc.Unlock("")

	assert.True(t, errors.Is(err, ErrAppLockPINRequired))
	assert.False(t, barrier.unsealCalled)
}

// A fault that never reached the credential keeps its own identity on the
// app-unlocked path, the same as it does on the locked one (#510). An
// operator told "invalid PIN" retries a PIN that is correct.
func TestUnlockConverges_AppUnlockedAndBarrierSealed_StrategyFaultKeepsItsIdentity(t *testing.T) {
	barrier := &mockBarrierService{
		initialized: true,
		sealed:      true,
		unsealErr:   &ErrBarrierStrategyUnavailable{Strategy: "tpm2"},
	}
	svc := newConvergenceLockService(t, false, barrier)

	err := svc.Unlock("a-correct-pin")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockUnsealUnavailable), "got %v", err)
	assert.False(t, errors.Is(err, ErrAppLockPINInvalid))
}

// A barrier that was never initialized is absent, not sealed, so an open app
// lock over it converges to success without inventing a barrier from whatever
// string the caller typed.
func TestUnlockConverges_AppUnlockedAndBarrierUninitialized(t *testing.T) {
	barrier := &mockBarrierService{initialized: false}
	svc := newConvergenceLockService(t, false, barrier)

	result := svc.HandleUnlock("some-pin")

	require.True(t, result.Success, "unexpected failure: %s", result.Error)
	assert.Empty(t, result.StillLocked)
	assert.False(t, barrier.unsealCalled, "an absent barrier must not be initialized by an unlock no-op")
}

// The full round trip: lock (which seals), unlock (which opens both), then
// seal the barrier out from under an open app lock and unlock again. The
// second unlock is the recovery that used to require restarting the daemon.
func TestUnlockConverges_RecoversASealedBarrierWithoutARestart(t *testing.T) {
	barrier := &mockBarrierService{initialized: true, sealed: false}
	svc := newConvergenceLockService(t, false, barrier)

	require.NoError(t, svc.Lock())
	require.True(t, svc.IsLocked())
	require.False(t, barrier.IsUnsealed(), "lock must seal the barrier")

	require.NoError(t, svc.Unlock("correct-pin"))
	require.False(t, svc.IsLocked())
	require.True(t, barrier.IsUnsealed())

	// Something seals the barrier while the app stays open.
	require.NoError(t, barrier.Seal())
	require.False(t, barrier.IsUnsealed())

	require.NoError(t, svc.Unlock("correct-pin"))
	assert.True(t, barrier.IsUnsealed(), "the PIN must recover a sealed barrier in place")
	assert.False(t, svc.IsLocked())
}
