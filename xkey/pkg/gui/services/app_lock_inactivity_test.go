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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// barrierCredential is the credential that unseals the barrier — the one the
// lock screen prompts for and the one that works at startup. It is a test
// fixture and has nothing to do with any real installation's secret.
const barrierCredential = "barrier-credential"

// divergedInstall builds an AppLockService in the state that produced the
// reported defect: a barrier that this process has already unsealed, and a
// PIN service whose backend holds a DIFFERENT secret and therefore rejects
// the barrier credential. That divergence is not exotic — a passphrase
// barrier alongside a tpm2 PIN strategy is two independent credential
// stores, and nothing binds their values together.
//
// The returned channel receives every "app:locked" event so a test can wait
// on the real inactivity timer instead of polling or sleeping.
func divergedInstall(t *testing.T) (*AppLockService, *mockBarrierService, *mockPINBackend, chan struct{}) {
	t.Helper()

	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategyTPM2,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: qrdbsdk.ErrPINInvalid,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 3},
	}
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	pinSvc.SetPINService(qrdbsdk.NewPINService(backend, slog.Default()))

	// Unsealed: the state the process is in after a successful startup unlock.
	barrierSvc := &mockBarrierService{initialized: true, sealed: false}

	svc := NewAppLockService(pinSvc, barrierSvc)
	svc.SetContext(context.Background())
	svc.SetBarrierStrategy("passphrase")

	// A real front-end emitter does not block the caller, so neither does
	// this one. A blocking send here would stall the very transitions the
	// tests are measuring and report it as a deadlock in the service.
	locked := make(chan struct{}, 1)
	svc.SetEmitFunc(func(event string, _ any) {
		if event != "app:locked" {
			return
		}
		select {
		case locked <- struct{}{}:
		default:
		}
	})

	return svc, barrierSvc, backend, locked
}

// awaitLocked waits for the inactivity timer to report that it locked the
// app. It fails the test rather than hanging if the timer never fires.
func awaitLocked(t *testing.T, locked <-chan struct{}) {
	t.Helper()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("inactivity timer never locked the app")
	}
}

// TestAppLockService_InactivityLockUnlocksWithStartupCredential is the
// regression test for the reported defect: after the app auto-locked on
// inactivity, the lock screen rejected the credential that unlocks it at
// startup, and each rejection spent one of the TPM's three
// dictionary-attack retries.
//
// The lock here is driven by the production inactivity timer — SetAutoLockMinutes
// arms the same time.AfterFunc that fires after fifteen idle minutes, with
// only the unit of time shortened — so the test cannot pass by locking
// through some path the timer does not take.
func TestAppLockService_InactivityLockUnlocksWithStartupCredential(t *testing.T) {
	svc, barrierSvc, backend, locked := divergedInstall(t)

	svc.autoLockUnit.Store(int64(time.Millisecond))
	svc.SetAutoLockMinutes(1)
	awaitLocked(t, locked)

	require.True(t, svc.IsLocked(), "inactivity timer must lock the app")
	require.True(t, barrierSvc.sealCalled,
		"inactivity lock must seal the barrier; a lock that leaves the data "+
			"encryption key resident protects nothing and sends the unlock "+
			"down the PIN path")
	require.False(t, barrierSvc.IsUnsealed(), "barrier must be sealed after the inactivity lock")

	// The credential that works at startup must work here. It is the only
	// credential the lock screen asks for.
	require.NoError(t, svc.Unlock(barrierCredential),
		"the credential that unseals the barrier at startup must also unlock "+
			"the app after an inactivity lock")

	assert.False(t, svc.IsLocked())
	assert.True(t, barrierSvc.unsealCalled, "unlock must go through the barrier")
	assert.Equal(t, barrierCredential, barrierSvc.unsealPassword)
	assert.Zero(t, backend.verifyUserCalls.Load(),
		"unlock must not reach PIN verification: every attempt there spends "+
			"one of the TPM's dictionary-attack retries on a secret the user "+
			"was never asked for")
}

// TestAppLockService_InactivityLockDoesNotSpendTPMRetries pins the second
// half of the defect independently of whether the unlock succeeds. A wrong
// credential after an inactivity lock must fail against the barrier, which
// has no retry budget, and must never be handed to the TPM-backed PIN
// service, whose counter locks the whole TPM out after three failures.
func TestAppLockService_InactivityLockDoesNotSpendTPMRetries(t *testing.T) {
	svc, barrierSvc, backend, locked := divergedInstall(t)
	barrierSvc.unsealErr = errors.New("seal: wrong credential")

	svc.autoLockUnit.Store(int64(time.Millisecond))
	svc.SetAutoLockMinutes(1)
	awaitLocked(t, locked)

	for attempt := 0; attempt < 5; attempt++ {
		err := svc.Unlock("wrong-credential")
		require.Error(t, err, "a wrong credential must not unlock the app")
		require.True(t, errors.Is(err, ErrAppLockPINInvalid))
		require.True(t, svc.IsLocked())
	}

	assert.Zero(t, backend.verifyUserCalls.Load(),
		"repeated wrong attempts after an inactivity lock must not reach the "+
			"TPM PIN backend, which locks out after three failures")
}

// TestAppLockService_ManualLockSealsBarrier covers the lock button, which
// reaches the same Lock method. A lock the user asked for explicitly must
// protect at least as much as the automatic one.
func TestAppLockService_ManualLockSealsBarrier(t *testing.T) {
	svc, barrierSvc, backend, _ := divergedInstall(t)

	require.NoError(t, svc.Lock())
	require.True(t, barrierSvc.sealCalled)
	require.False(t, barrierSvc.IsUnsealed())

	require.NoError(t, svc.Unlock(barrierCredential))
	assert.Zero(t, backend.verifyUserCalls.Load())
}

// TestAppLockService_LockReportsSealFailure covers the case where the app
// locks but the barrier will not seal. The app must still lock — refusing to
// lock because the key could not be zeroed would leave the interface open,
// which is worse — but the weaker lock must be reported rather than silently
// accepted.
func TestAppLockService_LockReportsSealFailure(t *testing.T) {
	svc, barrierSvc, _, _ := divergedInstall(t)
	sealErr := errors.New("barrier: seal refused")
	barrierSvc.sealErr = sealErr

	err := svc.Lock()

	require.Error(t, err, "a failed seal must not be reported as a clean lock")
	assert.True(t, errors.Is(err, ErrAppLockBarrierSealFailed))
	assert.True(t, errors.Is(err, sealErr), "the cause must survive for diagnosis")
	assert.True(t, svc.IsLocked(), "the app must be locked even when the seal fails")
}

// TestAppLockService_LockWithoutBarrierSucceeds covers an installation with
// no barrier at all. There is nothing to seal, so locking is not an error and
// the PIN path remains the legitimate unlock route.
func TestAppLockService_LockWithoutBarrierSucceeds(t *testing.T) {
	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	pinSvc.SetPINService(qrdbsdk.NewPINService(backend, slog.Default()))

	svc := NewAppLockService(pinSvc, nil)
	svc.SetContext(context.Background())

	require.NoError(t, svc.Lock())
	require.True(t, svc.IsLocked())

	require.NoError(t, svc.Unlock("software-pin"))
	assert.Equal(t, int32(1), backend.verifyUserCalls.Load(),
		"with no barrier the PIN path is the only route, and must be used")
}

// TestAppLockService_UninitializedBarrierLockIsNotAnError covers a barrier
// that was configured but never created, which is the state left behind by a
// wizard that failed part-way. There is no key to zero, so the lock is clean.
func TestAppLockService_UninitializedBarrierLockIsNotAnError(t *testing.T) {
	svc, barrierSvc, _, _ := divergedInstall(t)
	barrierSvc.initialized = false

	require.NoError(t, svc.Lock())
	assert.False(t, barrierSvc.sealCalled, "there is no barrier to seal")
	assert.True(t, svc.IsLocked())
}

// TestAppLockService_LockAndUnlockDoNotInterleave covers the transition
// serialization. Locking is not instantaneous — it seals the barrier — and
// while it was in progress the app used to be observable as locked with the
// barrier still open. A concurrent unlock in that window took the PIN path,
// spending a TPM retry on a secret the user was never prompted for, and could
// clear the locked flag while the lock was still sealing.
func TestAppLockService_LockAndUnlockDoNotInterleave(t *testing.T) {
	svc, barrierSvc, backend, _ := divergedInstall(t)

	const racers = 8
	start := make(chan struct{})
	done := make(chan struct{}, racers*2)

	for i := 0; i < racers; i++ {
		go func() {
			<-start
			_ = svc.Lock()
			done <- struct{}{}
		}()
		go func() {
			<-start
			_ = svc.Unlock(barrierCredential)
			done <- struct{}{}
		}()
	}

	close(start)
	for i := 0; i < racers*2; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("lock/unlock transitions deadlocked")
		}
	}

	// Whatever order they resolved in, the app must never have been unlocked
	// through the PIN path: with a barrier present, that path is unreachable.
	assert.Zero(t, backend.verifyUserCalls.Load(),
		"no interleaving may route an unlock to the PIN backend while a "+
			"barrier is configured")

	// The two states must agree at rest: unlocked implies an open barrier,
	// locked implies a sealed one.
	assert.Equal(t, svc.IsLocked(), !barrierSvc.IsUnsealed(),
		"the locked flag and the barrier seal state must not disagree")
}

// TestAppLockService_UnconfirmedTPMPINStillVerifies covers an installation
// with no barrier whose TPM SRK is provisioned but whose auth this session has
// not confirmed. Reporting the PIN as unset is honest, but it must not become
// a refusal to check a credential the backend can in fact verify.
func TestAppLockService_UnconfirmedTPMPINStillVerifies(t *testing.T) {
	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategyTPM2,
		userPINSet:    false, // auth value not confirmed this session
		initialized:   true,
		verifyUserErr: nil, // the TPM accepts the credential
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 3},
	}
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	pinSvc.SetPINService(qrdbsdk.NewPINService(backend, slog.Default()))

	svc := NewAppLockService(pinSvc, nil)
	svc.SetContext(context.Background())
	require.NoError(t, svc.Lock())

	require.NoError(t, svc.Unlock("srk-auth-value"),
		"a provisioned SRK must still be offered the credential to check")
	assert.Equal(t, int32(1), backend.verifyUserCalls.Load())
	assert.False(t, svc.IsLocked())
}

// TestAppLockService_UnsetPINReportsSetupIncomplete is the other half: a
// backend that genuinely has no credential to check must still produce the
// clearer setup-incomplete error rather than a bare verification failure.
func TestAppLockService_UnsetPINReportsSetupIncomplete(t *testing.T) {
	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		userPINSet:    false,
		initialized:   true,
		verifyUserErr: qrdbsdk.ErrPINNotSet,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	pinSvc.SetPINService(qrdbsdk.NewPINService(backend, slog.Default()))

	svc := NewAppLockService(pinSvc, nil)
	svc.SetContext(context.Background())
	require.NoError(t, svc.Lock())

	err := svc.Unlock("anything")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockSetupIncomplete),
		"a backend with no credential must say setup is incomplete")
	assert.True(t, svc.IsLocked())
}

// TestAppLockService_NotLockedWhileBarrierStillOpen pins the ordering inside
// Lock, deterministically rather than by racing.
//
// Sealing is not instantaneous. If the locked flag were set before the seal
// completed, the app would be observable as locked while its data encryption
// key was still resident — and an unlock arriving in that window would read
// the barrier as open and take the PIN path, spending a TPM retry on a secret
// the user was never prompted for. The flag must flip only after the barrier
// is closed.
func TestAppLockService_NotLockedWhileBarrierStillOpen(t *testing.T) {
	svc, barrierSvc, _, _ := divergedInstall(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	locked := make(chan error, 1)

	barrierSvc.sealHook = func() {
		close(entered)
		<-release
	}

	go func() { locked <- svc.Lock() }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Lock never reached the barrier seal")
	}

	// Observed from outside, mid-seal.
	assert.True(t, barrierSvc.IsUnsealed(), "precondition: the barrier is still open here")
	assert.False(t, svc.IsLocked(),
		"the app must not report itself locked while the barrier is still "+
			"open: an unlock in this window reads the barrier as unsealed and "+
			"takes the PIN path")

	close(release)

	select {
	case err := <-locked:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Lock never completed")
	}

	assert.True(t, svc.IsLocked())
	assert.False(t, barrierSvc.IsUnsealed())
}
