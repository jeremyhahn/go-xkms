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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// Subsystem names reported by UnlockVerified. They are the vocabulary an
// operator sees, so they read as prose rather than as identifiers.
const (
	// SubsystemAppLock is the global app-level lock this service owns.
	SubsystemAppLock = "app lock"

	// SubsystemBarrier is the storage barrier the unlock may unseal.
	SubsystemBarrier = "barrier"
)

// UnlockOutcome describes the effect of an unlock attempt: the subsystems it
// released, and the subsystems still locked afterwards.
//
// It exists because "the unlock call returned" and "something was unlocked"
// are different facts, and reporting the first as the second is a fail-open:
// an automated flow proceeds on a false premise and fails much later in an
// unrelated subsystem. A caller must treat a non-empty StillLocked, or an
// empty Unlocked, as a failure.
type UnlockOutcome struct {
	// Unlocked names the subsystems this attempt released.
	Unlocked []string

	// StillLocked names the subsystems locked after the attempt.
	StillLocked []string
}

// lockSnapshot records the state of every subsystem the app lock governs at
// one instant, so an unlock can be reported as a transition rather than as a
// return code.
type lockSnapshot struct {
	appLocked      bool
	barrierPresent bool
	barrierSealed  bool
}

// AppLockStatus is the frontend-facing representation of the global
// app-level lock state.
type AppLockStatus struct {
	IsLocked         bool `json:"is_locked"`
	AutoLockMinutes  int  `json:"auto_lock_minutes"`
	LockOnScreenLock bool `json:"lock_on_screen_lock"`
}

// unsealFailedBeforeTheCredential reports whether an Unseal error means the
// configured seal strategy could not be assembled or resolved, so the unseal
// stopped before the password was ever tested.
//
// It exists because that fault arrives in TWO shapes and matching only one
// leaves the reported bug in place for the other:
//
//   - go-qrdb's registry sentinels, when the strategy is not registered in the
//     seal registry ("qrdb/seal: requested strategy not registered"); and
//   - the GUI's own *ErrBarrierStrategyUnavailable, which BarrierService.Unseal
//     returns from assembleStrategy when tpmSealerFn is nil or the sealer says
//     CanSeal() is false. That type carries no wrapped cause, so errors.Is
//     against the qrdb sentinels does NOT see it -- it needs errors.As.
//
// Keeping both in one predicate is what stops the two from drifting apart
// again; callers ask this question, never the individual sentinels.
func unsealFailedBeforeTheCredential(err error) bool {
	var strategyUnavailable *ErrBarrierStrategyUnavailable
	if errors.As(err, &strategyUnavailable) {
		return true
	}
	return errors.Is(err, qrdbsdk.ErrStrategyNotFound) ||
		errors.Is(err, qrdbsdk.ErrStrategyMismatch)
}

// barrierUnsealer is the subset of BarrierService that AppLockService
// needs for the seal-aware unlock path. Using an interface here allows
// test doubles without embedding the full BarrierService.
type barrierUnsealer interface {
	IsInitialized() bool
	IsUnsealed() bool
	Initialize(password, strategyID string) error
	Unseal(password, strategyID string) error
	Seal() error
}

// AppLockService manages a global app-level lock with PIN-based unlock.
// When locked, the frontend prevents access to sensitive operations.
// When unlocked, the user has full access until the inactivity timer fires.
//
// Locking seals the barrier. A lock that only blanked the interface would
// leave the data encryption key resident in the process, so it protected
// nothing, and it left Unlock choosing between two different secrets: the
// barrier credential while the barrier was sealed, and the PIN service's
// credential once it was not. That choice is what made the same keystrokes
// succeed at startup and fail after an inactivity lock. Sealing on lock
// makes the lock mean what it says and, as a consequence, routes every
// unlock through the credential the startup unlock uses.
//
// On startup the service is locked and the barrier is sealed, so Unlock
// delegates to BarrierService.Unseal (which fires the post-unseal hook to
// initialize data-dependent services). The PIN path remains for
// installations that have no barrier at all.
type AppLockService struct {
	ctx              context.Context
	log              *slog.Logger
	locked           atomic.Bool
	autoLockMinutes  atomic.Int32
	lockOnScreenLock atomic.Bool
	autoLockTimer    *time.Timer
	autoLockMu       sync.Mutex
	emitFunc         func(string, any)
	pinSvc           *PINService
	barrierSvc       barrierUnsealer
	barrierStrategy  string

	// transitionMu serializes Lock, Unlock and AutoUnlock so the locked flag
	// and the barrier's seal state always change together. Without it a lock
	// in progress is observable as "locked" while the barrier is still open,
	// which sends a concurrent unlock down the PIN path — the exact route
	// this service exists to keep closed — and lets that unlock clear the
	// flag while the lock is still sealing.
	transitionMu sync.Mutex

	// emitMu orders notifications so front ends observe transitions in the
	// order they happened. It is acquired while transitionMu is still held
	// and released after the listener returns, so a slow listener delays
	// later notifications without stalling the state transitions themselves.
	emitMu sync.Mutex

	// autoLockUnit is the real-time duration of one "minute" of the
	// inactivity timeout, in nanoseconds. It exists so a test can drive the
	// actual time.AfterFunc path — the one that fires in production —
	// instead of calling a lock method the timer does not use. It is atomic
	// because the timer arms from whichever goroutine last recorded
	// activity. Zero means one minute.
	autoLockUnit atomic.Int64
}

// NewAppLockService creates a new AppLockService that starts in the
// unlocked state with a default 15-minute inactivity timeout and
// lock-on-screen-lock enabled. The caller is responsible for locking
// the service on returning-user startup paths; first-run (wizard) paths
// leave the service unlocked because the user authenticates during setup.
func NewAppLockService(pinSvc *PINService, barrierSvc barrierUnsealer) *AppLockService {
	svc := &AppLockService{
		log:        slog.Default().With("component", "app_lock"),
		pinSvc:     pinSvc,
		barrierSvc: barrierSvc,
	}
	svc.locked.Store(false)
	svc.autoLockMinutes.Store(15)
	svc.lockOnScreenLock.Store(true)
	svc.autoLockUnit.Store(int64(time.Minute))
	return svc
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *AppLockService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetEmitFunc sets the Wails event emitter for lock/unlock notifications.
func (s *AppLockService) SetEmitFunc(fn func(string, any)) {
	s.emitFunc = fn
}

// SetBarrierStrategy sets the barrier strategy ID used for unseal operations.
// This must be set before the first Unlock call when barrier-based
// authentication is active.
func (s *AppLockService) SetBarrierStrategy(strategyID string) {
	s.barrierStrategy = strategyID
}

// SetAutoLockMinutes configures the auto-lock inactivity timeout.
// A value of 0 disables auto-locking. If the app is currently unlocked,
// the timer is reset with the new duration.
func (s *AppLockService) SetAutoLockMinutes(minutes int) {
	s.autoLockMinutes.Store(int32(minutes))
	if !s.locked.Load() {
		s.resetAutoLockTimer()
	}
}

// SetLockOnScreenLock configures whether the app should lock when the
// OS screen lock is activated.
func (s *AppLockService) SetLockOnScreenLock(enabled bool) {
	s.lockOnScreenLock.Store(enabled)
}

// LockForStartup transitions the app to the locked state during startup
// before the frontend is loaded. No event is emitted; the frontend will
// read the initial lock state via GetStatus on mount.
func (s *AppLockService) LockForStartup() {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()

	s.stopAutoLockTimer()
	s.locked.Store(true)
	s.log.Info("app locked for startup")
}

// Lock sets the app to the locked state. Returns ErrAppLockAlreadyLocked
// if the app is already locked.
func (s *AppLockService) Lock() error {
	s.transitionMu.Lock()
	if s.locked.Load() {
		s.transitionMu.Unlock()
		return ErrAppLockAlreadyLocked
	}
	s.stopAutoLockTimer()
	sealErr := s.sealBarrier()
	// The flag flips only once the barrier is closed, so the app is never
	// observable as locked while its data encryption key is still resident.
	s.locked.Store(true)
	// Claim the notification slot before releasing the state lock so
	// notifications cannot overtake one another, then release the state lock
	// so the listener does not stall the next transition.
	s.emitMu.Lock()
	s.transitionMu.Unlock()
	defer s.emitMu.Unlock()

	s.log.Info("app locked", "barrier_sealed", sealErr == nil)
	if s.emitFunc != nil {
		s.emitFunc("app:locked", nil)
	}
	return sealErr
}

// sealBarrier seals the barrier so a locked app no longer holds the data
// encryption key. It reports nil when there is nothing to seal: no barrier
// is wired, the barrier was never initialized, or it is already sealed.
func (s *AppLockService) sealBarrier() error {
	if s.barrierSvc == nil {
		return nil
	}
	if !s.barrierSvc.IsInitialized() || !s.barrierSvc.IsUnsealed() {
		return nil
	}
	if err := s.barrierSvc.Seal(); err != nil {
		s.log.Error("app lock: barrier seal failed", "error", err)
		return &SentinelCauseError{Sentinel: ErrAppLockBarrierSealFailed, Cause: err}
	}
	s.log.Debug("app lock: barrier sealed")
	return nil
}

// Unlock verifies the provided credential and, on success, transitions the
// app to the unlocked state. When a barrier is configured and sealed — which
// is every locked state on an installation that has one, because Lock seals
// it — the credential is the barrier password. The first unseal of a process
// also fires the post-unseal hook that initializes data-dependent services;
// later unlocks reopen the barrier the stores are already bound to and skip
// it. When there is no barrier at all, verification is delegated to
// PINService.
func (s *AppLockService) Unlock(pin string) error {
	if pin == "" {
		return ErrAppLockPINRequired
	}

	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()

	if !s.locked.Load() {
		return ErrAppLockAlreadyUnlocked
	}

	// Determine barrier state:
	// - barrierConfigured: barrier service is wired
	// - barrierInitialized: barrier storage directory exists (Initialize was called)
	// - barrierSealed: barrier is initialized but not yet unlocked with password
	barrierConfigured := s.barrierSvc != nil
	barrierInitialized := barrierConfigured && s.barrierSvc.IsInitialized()
	barrierSealed := barrierInitialized && !s.barrierSvc.IsUnsealed()

	s.log.Debug("app unlock attempt",
		"barrier_configured", barrierConfigured,
		"barrier_initialized", barrierInitialized,
		"barrier_sealed", barrierSealed,
		"pin_service_configured", s.pinSvc != nil)

	switch {
	case barrierConfigured && !barrierInitialized:
		// Barrier is configured but the root key is missing — typically
		// because the wizard's barrier init failed (e.g. TPM provisioning
		// error) while the PIN was still persisted to the software backend.
		// Verify the PIN first; on success, initialize the barrier with
		// the same PIN so subsequent unlocks take the unseal path. We do
		// NOT auto-initialize without verifying the PIN: that would create
		// a new empty barrier with whatever string the user typed.
		s.log.Warn("app unlock: barrier not initialized, verifying PIN to recover")
		if s.pinSvc == nil {
			s.log.Error("app unlock: PIN service not configured")
			return ErrAppLockSetupIncomplete
		}
		if err := s.pinSvc.VerifyUserPIN(pin); err != nil {
			if errors.Is(err, qrdbsdk.ErrPINNotSet) {
				s.log.Error("app unlock: user PIN not set - setup incomplete",
					"barrier_configured", barrierConfigured,
					"barrier_initialized", barrierInitialized)
				return ErrAppLockSetupIncomplete
			}
			s.log.Warn("app unlock: PIN verification failed", "error", err)
			return err
		}
		// PIN is correct. Try to initialize the barrier with this PIN so
		// future restarts take the unseal path. Failure here does not
		// fail the unlock — the user is authenticated, and a degraded
		// state is better than locking them out. The post-init hook
		// (when registered) wires barrier-dependent stores.
		if initErr := s.barrierSvc.Initialize(pin, s.barrierStrategy); initErr != nil {
			s.log.Warn("app unlock: barrier initialization with PIN failed (continuing without barrier)",
				"strategy", s.barrierStrategy, "error", initErr)
		} else {
			s.log.Info("app unlock: barrier initialized with verified PIN",
				"strategy", s.barrierStrategy)
		}
	case barrierSealed:
		// Barrier is sealed: PIN is the barrier password.
		s.log.Debug("app unlock: using barrier unseal path")
		if err := s.barrierSvc.Unseal(pin, s.barrierStrategy); err != nil {
			// Not every unseal failure is a bad PIN. Two of them never reach
			// the credential at all, so reporting "invalid PIN" states a fact
			// that was never established -- and invites the operator to retry
			// a PIN that is correct (#510).
			switch {
			case errors.Is(err, qrdbsdk.ErrCorruptRootKey):
				// The stored root key would not parse. No PIN repairs that,
				// and the rest of the stack already calls it data loss.
				s.log.Error("app unlock: barrier root key is corrupt - the PIN was not checked",
					"strategy", s.barrierStrategy, "error", err)
				return ErrAppLockStorageCorrupt
			case unsealFailedBeforeTheCredential(err):
				s.log.Error("app unlock: barrier seal strategy unavailable - the PIN was not checked",
					"strategy", s.barrierStrategy, "error", err)
				return ErrAppLockUnsealUnavailable
			}
			s.log.Warn("app unlock: barrier unseal failed", "error", err)
			return ErrAppLockPINInvalid
		}
	default:
		// Barrier already unsealed or not configured: verify via PINService.
		s.log.Debug("app unlock: using PIN verification path")
		if s.pinSvc == nil {
			s.log.Error("app unlock: PIN service not configured")
			return ErrAppLockPINInvalid
		}
		// Ask the backend rather than pre-checking whether a PIN is
		// "set". A backend that cannot verify says so with ErrPINNotSet
		// without touching the hardware, which still yields the clearer
		// setup-incomplete message. Pre-checking would instead refuse a
		// TPM whose SRK is provisioned but whose auth this session has not
		// yet confirmed — a credential the backend can in fact check.
		if err := s.pinSvc.VerifyUserPIN(pin); err != nil {
			if errors.Is(err, qrdbsdk.ErrPINNotSet) {
				s.log.Error("app unlock: user PIN not set - setup incomplete",
					"barrier_configured", barrierConfigured,
					"barrier_initialized", barrierInitialized)
				return ErrAppLockSetupIncomplete
			}
			s.log.Warn("app unlock: PIN verification failed", "error", err)
			return err
		}
	}

	s.locked.Store(false)
	s.resetAutoLockTimer()
	s.log.Info("app unlocked")

	return nil
}

// snapshot observes the current state of every subsystem the app lock
// governs. A barrier that was never initialized is not "locked": it does not
// exist yet, so it is reported as absent rather than as a lock the PIN failed
// to open.
func (s *AppLockService) snapshot() lockSnapshot {
	snap := lockSnapshot{appLocked: s.locked.Load()}
	if s.barrierSvc != nil && s.barrierSvc.IsInitialized() {
		snap.barrierPresent = true
		snap.barrierSealed = !s.barrierSvc.IsUnsealed()
	}
	return snap
}

// UnlockVerified performs Unlock and then verifies the resulting state,
// reporting exactly which subsystems it released and which remained locked.
//
// Unlock's error return is not sufficient on its own: the PIN may be valid
// for one subsystem and not open another, in which case the honest report is
// the name of what it did unlock, not a blanket success.
func (s *AppLockService) UnlockVerified(pin string) (*UnlockOutcome, error) {
	before := s.snapshot()
	err := s.Unlock(pin)
	after := s.snapshot()

	outcome := &UnlockOutcome{}
	if before.appLocked && !after.appLocked {
		outcome.Unlocked = append(outcome.Unlocked, SubsystemAppLock)
	}
	if after.appLocked {
		outcome.StillLocked = append(outcome.StillLocked, SubsystemAppLock)
	}
	if before.barrierSealed && after.barrierPresent && !after.barrierSealed {
		outcome.Unlocked = append(outcome.Unlocked, SubsystemBarrier)
	}
	if after.barrierPresent && after.barrierSealed {
		outcome.StillLocked = append(outcome.StillLocked, SubsystemBarrier)
	}

	return outcome, err
}

// HandleUnlock implements the unlock IPC verb for every front end that
// exposes it (the GUI bridge, the headless daemon, the browser extension
// native host). Rendering the outcome here keeps one truthful report rather
// than one per transport.
//
// Success is reported only when the attempt released something and left
// nothing it governs locked.
func (s *AppLockService) HandleUnlock(pin string) *ipc.UnlockResult {
	outcome, err := s.UnlockVerified(pin)
	result := &ipc.UnlockResult{
		Unlocked:    outcome.Unlocked,
		StillLocked: outcome.StillLocked,
	}

	switch {
	case err != nil:
		result.Error = err.Error()
	case len(outcome.StillLocked) > 0:
		result.Error = "still locked: " + strings.Join(outcome.StillLocked, ", ")
	case len(outcome.Unlocked) == 0:
		result.Error = "nothing was unlocked"
	default:
		result.Success = true
		s.log.Info("app unlocked via IPC", "unlocked", strings.Join(outcome.Unlocked, ", "))
	}

	return result
}

// AutoUnlock transitions the app to the unlocked state without PIN
// verification. This is called from the auto-unseal startup path
// where the barrier was unsealed automatically. No event is emitted
// because the app was never visibly locked to the user.
func (s *AppLockService) AutoUnlock() {
	s.transitionMu.Lock()
	s.locked.Store(false)
	s.resetAutoLockTimer()
	s.emitMu.Lock()
	s.transitionMu.Unlock()
	defer s.emitMu.Unlock()

	s.log.Info("app auto-unlocked")
	if s.emitFunc != nil {
		s.emitFunc("app:unlocked", nil)
	}
}

// IsLocked returns whether the app is currently locked.
func (s *AppLockService) IsLocked() bool {
	return s.locked.Load()
}

// RecordActivity resets the inactivity timer. Call this on any user
// interaction to extend the auto-lock window. This is a no-op when
// the app is locked.
func (s *AppLockService) RecordActivity() {
	if !s.locked.Load() {
		s.resetAutoLockTimer()
	}
}

// GetStatus returns the current app lock status.
func (s *AppLockService) GetStatus() *AppLockStatus {
	return &AppLockStatus{
		IsLocked:         s.locked.Load(),
		AutoLockMinutes:  int(s.autoLockMinutes.Load()),
		LockOnScreenLock: s.lockOnScreenLock.Load(),
	}
}

// resetAutoLockTimer stops any existing timer and starts a new one.
func (s *AppLockService) resetAutoLockTimer() {
	mins := s.autoLockMinutes.Load()
	if mins <= 0 {
		s.stopAutoLockTimer()
		return
	}

	s.autoLockMu.Lock()
	defer s.autoLockMu.Unlock()

	if s.autoLockTimer != nil {
		s.autoLockTimer.Stop()
	}

	unit := time.Duration(s.autoLockUnit.Load())
	if unit <= 0 {
		unit = time.Minute
	}

	s.autoLockTimer = time.AfterFunc(time.Duration(mins)*unit, func() {
		s.autoLockNow(mins)
	})
}

// autoLockNow is the body the inactivity timer runs when it fires. It is a
// named method so a regression test can exercise the inactivity lock through
// the same code the timer executes.
func (s *AppLockService) autoLockNow(mins int32) {
	switch err := s.Lock(); {
	case err == nil:
		s.log.Info("app auto-locked after inactivity", "minutes", mins)
	case errors.Is(err, ErrAppLockAlreadyLocked):
		// Raced with a manual lock; nothing to report.
	default:
		// The app IS locked; only the seal failed. Report it rather than
		// dropping the event, which would hide the weaker lock.
		s.log.Warn("app auto-locked after inactivity, barrier not sealed",
			"minutes", mins, "error", err)
	}
}

// stopAutoLockTimer cancels the auto-lock timer.
func (s *AppLockService) stopAutoLockTimer() {
	s.autoLockMu.Lock()
	defer s.autoLockMu.Unlock()
	if s.autoLockTimer != nil {
		s.autoLockTimer.Stop()
		s.autoLockTimer = nil
	}
}
