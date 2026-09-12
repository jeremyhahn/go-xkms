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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSealedBarrierLockService builds an AppLockService whose barrier is
// initialized and sealed, so Unlock takes the barrier-unseal path, and whose
// Unseal fails with unsealErr.
func newSealedBarrierLockService(t *testing.T, unsealErr error) *AppLockService {
	t.Helper()

	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	pinSvc.SetPINService(qrdbsdk.NewPINService(&mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}, slog.Default()))

	svc := NewAppLockService(pinSvc, &mockBarrierService{
		initialized: true,
		sealed:      true,
		unsealErr:   unsealErr,
	})
	svc.SetContext(context.Background())
	svc.LockForStartup()
	require.True(t, svc.IsLocked())
	return svc
}

// TestUnlockReportsAnUnavailableStrategyAsItself is #510.
//
// On a TPM host configured with barrier_strategy: tpm2, an unlock after the
// idle auto-lock failed with "qrdb/seal: requested strategy not registered"
// and the CLI printed "app_lock: invalid PIN". The PIN retry counter did not
// move, which is the proof no PIN check ran -- the unseal never reached the
// credential. An operator told their correct PIN is wrong retries it, and on a
// backend that does count attempts that is a path into a lockout over a fault
// no PIN could fix.
//
// ErrStrategyMismatch is included because it is the same class: the stored
// blob was sealed by a different strategy than the one configured, which the
// PIN also cannot influence.
func TestUnlockReportsAnUnavailableStrategyAsItself(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"strategy not registered", qrdbsdk.ErrStrategyNotFound},
		{"strategy mismatch", qrdbsdk.ErrStrategyMismatch},
		{"wrapped by the caller", fmt.Errorf("barrier unseal: %w", qrdbsdk.ErrStrategyNotFound)},
		// The shape the real GUI BarrierService actually returns:
		// assembleStrategy hands back *ErrBarrierStrategyUnavailable when
		// tpmSealerFn is nil or the sealer says CanSeal() is false, and that
		// type wraps nothing -- so errors.Is against the qrdb sentinels does
		// not see it. Matching only those left the reported bug in place for
		// the path that actually produces it on a TPM-less host.
		{"the GUI's own strategy-unavailable error", &ErrBarrierStrategyUnavailable{Strategy: "tpm2"}},
		{"wrapped GUI strategy-unavailable", fmt.Errorf("unseal: %w", &ErrBarrierStrategyUnavailable{Strategy: "tpm2"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newSealedBarrierLockService(t, tc.err)

			err := svc.Unlock("a-correct-pin")

			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrAppLockUnsealUnavailable),
				"a strategy fault must be reported as itself, got %v", err)
			assert.False(t, errors.Is(err, ErrAppLockPINInvalid),
				"the PIN was never checked, so the unlock must not claim it was wrong")
			assert.True(t, svc.IsLocked(), "a failed unlock leaves the app locked either way")
		})
	}
}

// TestUnlockStillReportsAWrongPINAsInvalid is the control. Narrowing what
// counts as "invalid PIN" is only correct if an actually-wrong PIN still
// reports that way -- otherwise the fix trades one wrong answer for another.
func TestUnlockStillReportsAWrongPINAsInvalid(t *testing.T) {
	svc := newSealedBarrierLockService(t, errors.New("barrier: decrypt failed"))

	err := svc.Unlock("wrong-pin")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINInvalid),
		"an unseal that failed on the credential is still an invalid PIN, got %v", err)
	assert.False(t, errors.Is(err, ErrAppLockUnsealUnavailable))
	assert.True(t, svc.IsLocked())
}

// TestAppLockUnsealUnavailableIsDistinct keeps the two sentinels from
// collapsing into one another, which would make both assertions above pass
// vacuously.
func TestAppLockUnsealUnavailableIsDistinct(t *testing.T) {
	assert.False(t, errors.Is(ErrAppLockUnsealUnavailable, ErrAppLockPINInvalid))
	assert.False(t, errors.Is(ErrAppLockPINInvalid, ErrAppLockUnsealUnavailable))
	assert.Contains(t, ErrAppLockUnsealUnavailable.Error(), "not checked",
		"the message must tell the operator the PIN was never tested")
}

// TestUnlockReportsACorruptRootKeyAsStorageCorruption keeps a data-loss
// condition out of the credential vocabulary.
//
// The rest of the stack already classifies ErrCorruptRootKey as data loss:
// gRPC maps it to codes.DataLoss (pkg/api/grpc/service_barrier_pin.go:53) and
// REST to 500 (pkg/api/rest/handlers_barrier_pin.go:499). Telling a GUI or
// headless caller "invalid PIN" for an unparseable root key both contradicts
// them and hides storage corruption behind retries that cannot repair it.
func TestUnlockReportsACorruptRootKeyAsStorageCorruption(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"bare", qrdbsdk.ErrCorruptRootKey},
		{"wrapped", fmt.Errorf("barrier unseal: %w", qrdbsdk.ErrCorruptRootKey)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newSealedBarrierLockService(t, tc.err)

			err := svc.Unlock("a-correct-pin")

			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrAppLockStorageCorrupt),
				"a corrupt root key is a storage fault, got %v", err)
			assert.False(t, errors.Is(err, ErrAppLockPINInvalid),
				"no PIN repairs a corrupt root key, so the unlock must not blame the PIN")
			assert.False(t, errors.Is(err, ErrAppLockUnsealUnavailable),
				"corruption is not the same fact as an unavailable strategy")
		})
	}
}

// TestUnsealFailedBeforeTheCredentialCoversBothShapes pins the predicate
// directly, in both directions, so it cannot quietly narrow back to one shape.
func TestUnsealFailedBeforeTheCredentialCoversBothShapes(t *testing.T) {
	assert.True(t, unsealFailedBeforeTheCredential(qrdbsdk.ErrStrategyNotFound))
	assert.True(t, unsealFailedBeforeTheCredential(qrdbsdk.ErrStrategyMismatch))
	assert.True(t, unsealFailedBeforeTheCredential(&ErrBarrierStrategyUnavailable{Strategy: "tpm2"}))
	assert.True(t, unsealFailedBeforeTheCredential(
		fmt.Errorf("wrapped: %w", &ErrBarrierStrategyUnavailable{Strategy: "pkcs11"})))

	assert.False(t, unsealFailedBeforeTheCredential(errors.New("barrier: decrypt failed")),
		"a credential failure is not a strategy fault")
	assert.False(t, unsealFailedBeforeTheCredential(qrdbsdk.ErrCorruptRootKey),
		"corruption is a storage fault and is classified separately")
	assert.False(t, unsealFailedBeforeTheCredential(nil))
}
