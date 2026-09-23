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

package services

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAppLock_TPM2ReunsealAfterAutoLock is #510.
//
// On a TPM host (barrier_strategy: tpm2), the reported failure surfaced after
// the 15-minute inactivity auto-lock: AppLockService.Lock seals the real
// BarrierService, and the next AppLockService.Unlock -- the exact call
// "xkey unlock --pin-stdin" reaches over IPC -- unseals it again in the same
// process. Every prior regression test for this path (barrier_reunseal_test.go)
// exercises BarrierService directly with the passphrase strategy, and every
// AppLockService-level convergence test substitutes mockBarrierService, so
// none of them ever construct a real go-qrdb StorageBarrier carrying a
// TPM2Strategy across a Lock/Unlock cycle. This test wires the real
// BarrierService, seeded with a TPM2 sealer, into a real AppLockService the
// same way NewApp does, and drives it through the production sequence: boot
// unseal, inactivity lock, unlock. A regression that made Unlock rebuild the
// barrier instead of reopening it in place would surface here as
// qrdbsdk.ErrStrategyNotFound, reported through AppLockService as
// ErrAppLockUnsealUnavailable rather than success.
func TestAppLock_TPM2ReunsealAfterAutoLock(t *testing.T) {
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer {
		return &mockSealer{canSeal: true}
	})

	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	pinSvc.SetPINService(qrdbsdk.NewPINService(&mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}, slog.Default()))

	appLockSvc := NewAppLockService(pinSvc, barrierSvc)
	appLockSvc.SetContext(context.Background())
	appLockSvc.SetBarrierStrategy(string(xkms.StrategyTPM2))

	// The boot unseal: the barrier is initialized with the TPM2 strategy and
	// the app lock opens the way AutoUnlock does after a successful auto-unseal.
	require.NoError(t, barrierSvc.Initialize("", string(xkms.StrategyTPM2)))
	require.True(t, barrierSvc.IsUnsealed())
	appLockSvc.AutoUnlock()
	require.False(t, appLockSvc.IsLocked())

	// The 15-minute inactivity auto-lock: this is autoLockNow's body, seals
	// the real barrier rather than a double.
	require.NoError(t, appLockSvc.Lock())
	require.True(t, appLockSvc.IsLocked())
	require.False(t, barrierSvc.IsUnsealed(), "the barrier must be sealed by the lock")

	// The re-unlock: what "xkey unlock --pin-stdin" drives over IPC.
	outcome, err := appLockSvc.UnlockVerified("the-user-pin")
	require.NoError(t, err,
		"unlock after auto-lock must reopen the TPM2 barrier in place, not %v", err)
	assert.False(t, appLockSvc.IsLocked())
	assert.True(t, barrierSvc.IsUnsealed())
	assert.Equal(t, []string{SubsystemAppLock, SubsystemBarrier}, outcome.Unlocked)
	assert.Empty(t, outcome.StillLocked)

	// Pin the failure mode the fix replaces: a strategy-registration fault
	// must never be reachable here for a barrier this process already
	// unsealed once, and if it were it would report as itself, never as an
	// invalid PIN.
	assert.False(t, errors.Is(err, ErrAppLockUnsealUnavailable))
	assert.False(t, errors.Is(err, ErrAppLockPINInvalid))
}

// credentialCheckingSealer is a types.Sealer that actually verifies the
// UserAuth password presented to Unseal against the one Seal was called
// with, unlike the package's shared mockSealer (which round-trips the
// ciphertext regardless of credential). It exists so the control test below
// can tell "the strategy reopened" apart from "the reopen also stopped
// checking the credential".
type credentialCheckingSealer struct {
	canSeal bool
}

func (m *credentialCheckingSealer) Seal(_ context.Context, data []byte, opts *xkms.SealOptions) (*xkms.SealedData, error) {
	var pw []byte
	if opts != nil && opts.Password != nil {
		pw = opts.Password.Bytes()
	}
	return &xkms.SealedData{
		Backend:    xkms.BackendTypeTPM2,
		Ciphertext: data,
		TPMPublic:  []byte("pub"),
		TPMPrivate: pw,
	}, nil
}

func (m *credentialCheckingSealer) Unseal(_ context.Context, sealed *xkms.SealedData, opts *xkms.UnsealOptions) ([]byte, error) {
	var pw []byte
	if opts != nil && opts.Password != nil {
		pw = opts.Password.Bytes()
	}
	if string(pw) != string(sealed.TPMPrivate) {
		return nil, errors.New("credentialCheckingSealer: TPM session authorization failed")
	}
	return sealed.Ciphertext, nil
}

func (m *credentialCheckingSealer) CanSeal() bool {
	return m.canSeal
}

// TestAppLock_TPM2ReunsealAfterAutoLock_WrongCredentialStillRejected is the
// control: the in-place reopen the fix relies on must still be a real
// credential check, not a bypass that accepts anything once the strategy is
// known to be registered.
func TestAppLock_TPM2ReunsealAfterAutoLock_WrongCredentialStillRejected(t *testing.T) {
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer {
		return &credentialCheckingSealer{canSeal: true}
	})

	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	pinSvc.SetPINService(qrdbsdk.NewPINService(&mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}, slog.Default()))

	appLockSvc := NewAppLockService(pinSvc, barrierSvc)
	appLockSvc.SetContext(context.Background())
	appLockSvc.SetBarrierStrategy(string(xkms.StrategyTPM2))

	require.NoError(t, barrierSvc.Initialize("the-correct-user-pin", string(xkms.StrategyTPM2)))
	appLockSvc.AutoUnlock()
	require.NoError(t, appLockSvc.Lock())

	err := appLockSvc.Unlock("a-wrong-pin")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINInvalid),
		"a credential the TPM session rejects is still an invalid PIN, got %v", err)
	assert.True(t, appLockSvc.IsLocked())

	// The correct credential still works afterwards -- the rejected attempt
	// must not have torn down or corrupted the in-place barrier.
	err = appLockSvc.Unlock("the-correct-user-pin")
	require.NoError(t, err)
	assert.False(t, appLockSvc.IsLocked())
}
