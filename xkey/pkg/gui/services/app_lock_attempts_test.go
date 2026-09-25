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

package services

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// appLockAttemptCounter: the persistence primitive
// ---------------------------------------------------------------------------

func TestAppLockAttemptCounter_InMemoryDefaultsToFullBudget(t *testing.T) {
	c := newAppLockAttemptCounter("")

	blocked, remaining, err := c.blocked()
	require.NoError(t, err)
	assert.False(t, blocked)
	assert.Equal(t, AppLockPINMaxAttempts, remaining)
}

func TestAppLockAttemptCounter_RecordFailureDecrements(t *testing.T) {
	c := newAppLockAttemptCounter("")

	remaining, err := c.recordFailure()
	require.NoError(t, err)
	assert.Equal(t, AppLockPINMaxAttempts-1, remaining)

	remaining, err = c.recordFailure()
	require.NoError(t, err)
	assert.Equal(t, AppLockPINMaxAttempts-2, remaining)
}

func TestAppLockAttemptCounter_RecordFailureNeverGoesNegative(t *testing.T) {
	c := newAppLockAttemptCounter("")

	for i := 0; i < AppLockPINMaxAttempts+5; i++ {
		remaining, err := c.recordFailure()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, remaining, 0)
	}

	blocked, remaining, err := c.blocked()
	require.NoError(t, err)
	assert.True(t, blocked)
	assert.Equal(t, 0, remaining)
}

func TestAppLockAttemptCounter_RecordSuccessResets(t *testing.T) {
	c := newAppLockAttemptCounter("")

	_, err := c.recordFailure()
	require.NoError(t, err)
	_, err = c.recordFailure()
	require.NoError(t, err)

	require.NoError(t, c.recordSuccess())

	_, remaining, err := c.blocked()
	require.NoError(t, err)
	assert.Equal(t, AppLockPINMaxAttempts, remaining)
}

// TestAppLockAttemptCounter_PersistsAcrossInstances is the "survives a
// restart" property: a second counter built over the same data directory
// -- exactly what a fresh process does -- observes the first one's writes,
// rather than starting the budget over.
func TestAppLockAttemptCounter_PersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()

	first := newAppLockAttemptCounter(dir)
	remaining, err := first.recordFailure()
	require.NoError(t, err)
	require.Equal(t, AppLockPINMaxAttempts-1, remaining)
	remaining, err = first.recordFailure()
	require.NoError(t, err)
	require.Equal(t, AppLockPINMaxAttempts-2, remaining)

	// A brand-new counter, as a restarted process would construct, must
	// see the persisted state rather than a fresh budget.
	second := newAppLockAttemptCounter(dir)
	blocked, remaining, err := second.blocked()
	require.NoError(t, err)
	assert.False(t, blocked)
	assert.Equal(t, AppLockPINMaxAttempts-2, remaining)

	remaining, err = second.recordFailure()
	require.NoError(t, err)
	assert.Equal(t, AppLockPINMaxAttempts-3, remaining)
}

func TestAppLockAttemptCounter_PersistsOutsideAnySealedLocation(t *testing.T) {
	dir := t.TempDir()
	c := newAppLockAttemptCounter(dir)
	require.NoError(t, c.recordSuccess())

	path := filepath.Join(dir, "pin", "unlock_attempts")
	info, err := os.Stat(path)
	require.NoError(t, err, "the counter must persist under <dataDir>/pin, not behind any barrier")
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestAppLockAttemptCounter_LoadFailureIsReportedNotSilentlyUnlimited(t *testing.T) {
	dir := t.TempDir()
	pinDir := filepath.Join(dir, "pin")
	require.NoError(t, os.MkdirAll(pinDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(pinDir, "unlock_attempts"), []byte("not json"), 0600))

	c := newAppLockAttemptCounter(dir)
	_, _, err := c.blocked()
	require.Error(t, err, "an unreadable counter must never be treated as an unlimited one")

	var loadErr *AppLockAttemptsLoadError
	require.ErrorAs(t, err, &loadErr)
}

func TestAppLockAttemptCounter_OutOfRangeRecordIsReported(t *testing.T) {
	dir := t.TempDir()
	pinDir := filepath.Join(dir, "pin")
	require.NoError(t, os.MkdirAll(pinDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(pinDir, "unlock_attempts"),
		[]byte(`{"remaining":99}`), 0600))

	c := newAppLockAttemptCounter(dir)
	_, _, err := c.blocked()
	require.Error(t, err)
}

func TestAppLockAttemptCounter_ConcurrentFailuresNeverExceedTheBudget(t *testing.T) {
	c := newAppLockAttemptCounter(t.TempDir())

	const racers = 50
	var wg sync.WaitGroup
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			_, _ = c.recordFailure()
		}()
	}
	wg.Wait()

	_, remaining, err := c.blocked()
	require.NoError(t, err)
	assert.Equal(t, 0, remaining, "50 concurrent failures against an 8-attempt budget must land on exactly zero")
}

// ---------------------------------------------------------------------------
// ResetAppLockAttempts: the out-of-process reset entry point
// ---------------------------------------------------------------------------

func TestResetAppLockAttempts_RestoresTheFullBudget(t *testing.T) {
	dir := t.TempDir()
	c := newAppLockAttemptCounter(dir)
	_, err := c.recordFailure()
	require.NoError(t, err)
	_, err = c.recordFailure()
	require.NoError(t, err)

	require.NoError(t, ResetAppLockAttempts(dir))

	_, remaining, err := newAppLockAttemptCounter(dir).blocked()
	require.NoError(t, err)
	assert.Equal(t, AppLockPINMaxAttempts, remaining)
}

// ---------------------------------------------------------------------------
// AppLockService.Unlock against the budget: the PIN-verification branch
// ---------------------------------------------------------------------------

// newCountingPINLockService builds an AppLockService with no barrier, so
// every Unlock takes the PINService.VerifyUserPIN branch, backed by a
// mockPINBackend that always fails with verifyErr. verifyUserCalls on the
// backend proves whether the PIN was actually evaluated.
func newCountingPINLockService(t *testing.T, verifyErr error) (*AppLockService, *mockPINBackend) {
	t.Helper()

	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: verifyErr,
		lockoutStatus: &qrdbsdk.PINLockoutStatus{MaxAttempts: 5},
	}
	pinSvc.SetPINService(qrdbsdk.NewPINService(backend, slog.Default()))

	svc := NewAppLockService(pinSvc, nil)
	svc.SetContext(context.Background())
	svc.LockForStartup()
	return svc, backend
}

func TestAppLockService_Unlock_DecrementsOnCredentialRejection(t *testing.T) {
	svc, backend := newCountingPINLockService(t, errors.New("wrong pin"))

	err := svc.Unlock("wrong-pin")
	require.Error(t, err)

	var attemptsErr *AppLockAttemptsError
	require.ErrorAs(t, err, &attemptsErr)
	assert.Equal(t, AppLockPINMaxAttempts-1, attemptsErr.Remaining)
	assert.Equal(t, int32(1), backend.verifyUserCalls.Load())
}

func TestAppLockService_Unlock_BlocksAtZeroWithoutEvaluatingThePIN(t *testing.T) {
	svc, backend := newCountingPINLockService(t, errors.New("wrong pin"))

	for i := 0; i < AppLockPINMaxAttempts; i++ {
		err := svc.Unlock("wrong-pin")
		require.Error(t, err)
	}
	require.Equal(t, int32(AppLockPINMaxAttempts), backend.verifyUserCalls.Load())

	// The (N+1)th attempt is refused outright.
	err := svc.Unlock("wrong-pin")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINBlocked))

	var attemptsErr *AppLockAttemptsError
	require.ErrorAs(t, err, &attemptsErr)
	assert.Equal(t, 0, attemptsErr.Remaining)

	// The budget being exhausted must not itself spend a credential check:
	// the call count must not have moved past the eight real attempts.
	assert.Equal(t, int32(AppLockPINMaxAttempts), backend.verifyUserCalls.Load(),
		"a blocked attempt must never reach VerifyUserPIN")
}

func TestAppLockService_Unlock_SuccessResetsTheBudget(t *testing.T) {
	svc, backend := newCountingPINLockService(t, errors.New("wrong pin"))

	// Spend most of the budget.
	for i := 0; i < AppLockPINMaxAttempts-1; i++ {
		require.Error(t, svc.Unlock("wrong-pin"))
	}

	// A correct PIN resets it.
	backend.verifyUserErr = nil
	require.NoError(t, svc.Unlock("correct-pin"))

	// The full budget is available again: another eight failures are
	// evaluated before the ninth is refused.
	svc.LockForStartup()
	backend.verifyUserErr = errors.New("wrong pin")
	backend.verifyUserCalls.Store(0)
	for i := 0; i < AppLockPINMaxAttempts; i++ {
		err := svc.Unlock("wrong-pin")
		require.Error(t, err, "attempt %d should still be evaluated", i+1)
	}
	err := svc.Unlock("wrong-pin")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINBlocked))
	assert.Equal(t, int32(AppLockPINMaxAttempts), backend.verifyUserCalls.Load())
}

// TestAppLockService_ResetAttempts_PersistFailure pins the error branch
// ResetAttempts logs and returns: when the counter cannot be persisted
// (here, its subdirectory is blocked by a same-named file), the reset must
// fail loudly rather than report success while the budget is still
// exhausted on disk.
func TestAppLockService_ResetAttempts_PersistFailure(t *testing.T) {
	svc, _ := newCountingPINLockService(t, errors.New("wrong pin"))

	dir := t.TempDir()
	// "pin" exists as a regular file, so MkdirAll(dir/pin, ...) -- which
	// save() must perform to write dir/pin/unlock_attempts -- fails.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pin"), []byte("not a directory"), 0600))
	svc.SetDataDir(dir)

	err := svc.ResetAttempts()

	require.Error(t, err)
	var saveErr *AppLockAttemptsSaveError
	assert.ErrorAs(t, err, &saveErr)
}

func TestAppLockService_ResetAttempts_RestoresTheBudget(t *testing.T) {
	svc, backend := newCountingPINLockService(t, errors.New("wrong pin"))

	for i := 0; i < AppLockPINMaxAttempts; i++ {
		require.Error(t, svc.Unlock("wrong-pin"))
	}
	require.Error(t, svc.Unlock("wrong-pin"), "budget must be exhausted before the reset")

	require.NoError(t, svc.ResetAttempts())

	backend.verifyUserCalls.Store(0)
	err := svc.Unlock("wrong-pin")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrAppLockPINBlocked), "the reset must have cleared the block")
	assert.Equal(t, int32(1), backend.verifyUserCalls.Load(), "the PIN must be evaluated again after a reset")
}

// TestAppLockService_Unlock_ConcurrentAttemptsNeverExceedTheBudget drives
// many concurrent Unlock calls against a PIN that always fails and proves
// the budget is never over-spent -- run with -race to also confirm the
// counter's own bookkeeping has no data race.
func TestAppLockService_Unlock_ConcurrentAttemptsNeverExceedTheBudget(t *testing.T) {
	svc, backend := newCountingPINLockService(t, errors.New("wrong pin"))

	const racers = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rejectedTotal, blockedTotal int

	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			err := svc.Unlock("wrong-pin")
			require.Error(t, err)

			mu.Lock()
			defer mu.Unlock()
			if errors.Is(err, ErrAppLockPINBlocked) {
				blockedTotal++
			} else {
				rejectedTotal++
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, AppLockPINMaxAttempts, rejectedTotal,
		"exactly the budget's worth of attempts must reach the credential check")
	assert.Equal(t, racers-AppLockPINMaxAttempts, blockedTotal,
		"every attempt beyond the budget must be refused outright")
	assert.Equal(t, int32(AppLockPINMaxAttempts), backend.verifyUserCalls.Load())
}

// ---------------------------------------------------------------------------
// AppLockService.Unlock against the budget: the barrier-unseal branch
// ---------------------------------------------------------------------------

func TestAppLockService_UnsealBarrier_DecrementsOnlyOnCredentialRejection(t *testing.T) {
	svc := newSealedBarrierLockService(t, errors.New("barrier: decrypt failed"))

	err := svc.Unlock("wrong-pin")
	require.Error(t, err)

	var attemptsErr *AppLockAttemptsError
	require.ErrorAs(t, err, &attemptsErr)
	assert.Equal(t, AppLockPINMaxAttempts-1, attemptsErr.Remaining)
}

func TestAppLockService_UnsealBarrier_StrategyFaultDoesNotSpendTheBudget(t *testing.T) {
	svc := newSealedBarrierLockService(t, &ErrBarrierStrategyUnavailable{Strategy: "tpm2"})

	// A generous number of faults: none of them may count.
	for i := 0; i < AppLockPINMaxAttempts*2; i++ {
		err := svc.Unlock("a-correct-pin")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrAppLockUnsealUnavailable))
		assert.False(t, errors.Is(err, ErrAppLockPINBlocked),
			"a strategy fault must never exhaust the budget")
	}

	blocked, remaining, err := svc.attemptCounter().blocked()
	require.NoError(t, err)
	assert.False(t, blocked)
	assert.Equal(t, AppLockPINMaxAttempts, remaining, "the budget must be untouched by faults")
}

func TestAppLockService_UnsealBarrier_CorruptRootKeyDoesNotSpendTheBudget(t *testing.T) {
	svc := newSealedBarrierLockService(t, qrdbsdk.ErrCorruptRootKey)

	for i := 0; i < AppLockPINMaxAttempts*2; i++ {
		err := svc.Unlock("a-correct-pin")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrAppLockStorageCorrupt))
	}

	blocked, remaining, err := svc.attemptCounter().blocked()
	require.NoError(t, err)
	assert.False(t, blocked)
	assert.Equal(t, AppLockPINMaxAttempts, remaining)
}

func TestAppLockService_UnsealBarrier_BlocksAtZero(t *testing.T) {
	svc := newSealedBarrierLockService(t, errors.New("wrong password"))

	for i := 0; i < AppLockPINMaxAttempts; i++ {
		require.Error(t, svc.Unlock("wrong-pin"))
	}

	err := svc.Unlock("wrong-pin")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINBlocked))
}

// ---------------------------------------------------------------------------
// AppLockService.SetDataDir: persistence wired through the real service
// ---------------------------------------------------------------------------

func TestAppLockService_SetDataDir_PersistsAcrossServiceRestarts(t *testing.T) {
	dir := t.TempDir()

	pinSvc1 := NewPINService()
	pinSvc1.SetContext(context.Background())
	backend1 := &mockPINBackend{
		strategy: qrdbsdk.PINStrategySoftware, soPINSet: true, userPINSet: true, initialized: true,
		verifyUserErr: errors.New("wrong pin"),
	}
	pinSvc1.SetPINService(qrdbsdk.NewPINService(backend1, slog.Default()))
	svc1 := NewAppLockService(pinSvc1, nil)
	svc1.SetContext(context.Background())
	svc1.SetDataDir(dir)
	svc1.LockForStartup()

	require.Error(t, svc1.Unlock("wrong-pin"))
	require.Error(t, svc1.Unlock("wrong-pin"))
	require.Error(t, svc1.Unlock("wrong-pin"))

	// A second AppLockService instance over the same data directory, as a
	// restarted daemon process would construct, continues the same budget
	// rather than starting a fresh one.
	pinSvc2 := NewPINService()
	pinSvc2.SetContext(context.Background())
	backend2 := &mockPINBackend{
		strategy: qrdbsdk.PINStrategySoftware, soPINSet: true, userPINSet: true, initialized: true,
		verifyUserErr: errors.New("wrong pin"),
	}
	pinSvc2.SetPINService(qrdbsdk.NewPINService(backend2, slog.Default()))
	svc2 := NewAppLockService(pinSvc2, nil)
	svc2.SetContext(context.Background())
	svc2.SetDataDir(dir)
	svc2.LockForStartup()

	_, remaining, err := svc2.attemptCounter().blocked()
	require.NoError(t, err)
	assert.Equal(t, AppLockPINMaxAttempts-3, remaining)

	for i := 0; i < AppLockPINMaxAttempts-3; i++ {
		require.Error(t, svc2.Unlock("wrong-pin"))
	}
	err = svc2.Unlock("wrong-pin")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppLockPINBlocked))
}

// TestAppLockService_AttemptCounter_ZeroValueServiceNeverReturnsNil pins the
// guard documented on attemptCounter: a zero-value AppLockService{} (never
// passed through NewAppLockService, so s.attempts holds nothing) must still
// get a usable counter rather than a nil the caller would crash on.
func TestAppLockService_AttemptCounter_ZeroValueServiceNeverReturnsNil(t *testing.T) {
	var svc AppLockService

	counter := svc.attemptCounter()

	require.NotNil(t, counter)
	_, _, err := counter.blocked()
	assert.NoError(t, err)
}

// TestAppLockAttemptsLoadError_ErrorAndUnwrap and
// TestAppLockAttemptsSaveError_ErrorAndUnwrap pin the errors.Is/errors.As
// chain callers depend on to tell a corrupt-counter-file failure (load)
// apart from a can't-persist-the-reset failure (save) -- see
// TestAppLockService_ResetAttempts_PersistFailure, which asserts the
// concrete *AppLockAttemptsSaveError type reaches the caller. Unwrap losing
// the cause, or the message dropping the path, would surface as a
// generic/unhelpful error at the one place an operator needs the path to
// fix a permissions problem.
func TestAppLockAttemptsLoadError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("permission denied")
	err := &AppLockAttemptsLoadError{Path: "/var/lib/xkey/attempts.json", Cause: cause}

	msg := err.Error()
	assert.Contains(t, msg, "/var/lib/xkey/attempts.json")
	assert.Contains(t, msg, "permission denied")
	assert.Same(t, cause, err.Unwrap())
	assert.ErrorIs(t, err, cause)
}

func TestAppLockAttemptsSaveError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("disk full")
	err := &AppLockAttemptsSaveError{Path: "/var/lib/xkey/attempts.json", Cause: cause}

	msg := err.Error()
	assert.Contains(t, msg, "/var/lib/xkey/attempts.json")
	assert.Contains(t, msg, "disk full")
	assert.Same(t, cause, err.Unwrap())
	assert.ErrorIs(t, err, cause)
}
