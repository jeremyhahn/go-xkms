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
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// AppLockStatus is the frontend-facing representation of the global
// app-level lock state.
type AppLockStatus struct {
	IsLocked         bool `json:"is_locked"`
	AutoLockMinutes  int  `json:"auto_lock_minutes"`
	LockOnScreenLock bool `json:"lock_on_screen_lock"`
}

// barrierUnsealer is the subset of BarrierService that AppLockService
// needs for the seal-aware unlock path. Using an interface here allows
// test doubles without embedding the full BarrierService.
type barrierUnsealer interface {
	IsInitialized() bool
	IsUnsealed() bool
	Initialize(password, strategyID string) error
	Unseal(password, strategyID string) error
}

// AppLockService manages a global app-level lock with PIN-based unlock.
// When locked, the frontend prevents access to sensitive operations.
// When unlocked, the user has full access until the inactivity timer fires.
//
// On startup the service is locked. If the barrier is sealed, Unlock
// delegates to BarrierService.Unseal (which fires the post-unseal hook
// to initialize data-dependent services). When the barrier is already
// unsealed (or absent), Unlock verifies the PIN via PINService.
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
	s.stopAutoLockTimer()
	s.locked.Store(true)
	s.log.Info("app locked for startup")
}

// Lock sets the app to the locked state. Returns ErrAppLockAlreadyLocked
// if the app is already locked.
func (s *AppLockService) Lock() error {
	if s.locked.Load() {
		return ErrAppLockAlreadyLocked
	}
	s.stopAutoLockTimer()
	s.locked.Store(true)
	s.log.Info("app locked")
	if s.emitFunc != nil {
		s.emitFunc("app:locked", nil)
	}
	return nil
}

// Unlock verifies the provided PIN and, on success, transitions the app
// to the unlocked state. When a barrier is configured and still sealed,
// the PIN is used as the barrier password to unseal it (which triggers
// the post-unseal hook for data directory initialization). When the
// barrier is already unsealed (or absent), PIN verification is delegated
// to PINService.
func (s *AppLockService) Unlock(pin string) error {
	if pin == "" {
		return ErrAppLockPINRequired
	}
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

	if barrierConfigured && !barrierInitialized {
		// Barrier is configured but the root key is missing (directory was
		// never created, or data was corrupted). Do NOT auto-initialize,
		// which would create a new empty barrier and silently lose any
		// previously encrypted data. Fall back to PIN verification when
		// available, otherwise report setup incomplete.
		s.log.Warn("app unlock: barrier not initialized, falling back to PIN verification")
		if s.pinSvc == nil {
			s.log.Error("app unlock: PIN service not configured")
			return ErrAppLockPINInvalid
		}
		if status, statusErr := s.pinSvc.GetPINStatus(); statusErr == nil && !status.UserPINSet {
			s.log.Error("app unlock: user PIN not set - setup incomplete",
				"barrier_configured", barrierConfigured,
				"barrier_initialized", barrierInitialized)
			return ErrAppLockSetupIncomplete
		}
		if err := s.pinSvc.VerifyUserPIN(pin); err != nil {
			s.log.Warn("app unlock: PIN verification failed", "error", err)
			return err
		}
	} else if barrierSealed {
		// Barrier is sealed: PIN is the barrier password.
		s.log.Debug("app unlock: using barrier unseal path")
		if err := s.barrierSvc.Unseal(pin, s.barrierStrategy); err != nil {
			s.log.Warn("app unlock: barrier unseal failed", "error", err)
			return ErrAppLockPINInvalid
		}
	} else {
		// Barrier already unsealed or not configured: verify via PINService.
		s.log.Debug("app unlock: using PIN verification path")
		if s.pinSvc == nil {
			s.log.Error("app unlock: PIN service not configured")
			return ErrAppLockPINInvalid
		}
		// Check if PIN is actually set before attempting verification.
		// This provides a clearer error message when setup is incomplete.
		if status, statusErr := s.pinSvc.GetPINStatus(); statusErr == nil && !status.UserPINSet {
			s.log.Error("app unlock: user PIN not set - setup incomplete",
				"barrier_configured", barrierConfigured,
				"barrier_initialized", barrierInitialized)
			return ErrAppLockSetupIncomplete
		}
		if err := s.pinSvc.VerifyUserPIN(pin); err != nil {
			s.log.Warn("app unlock: PIN verification failed", "error", err)
			return err
		}
	}

	s.locked.Store(false)
	s.resetAutoLockTimer()
	s.log.Info("app unlocked")

	return nil
}

// AutoUnlock transitions the app to the unlocked state without PIN
// verification. This is called from the auto-unseal startup path
// where the barrier was unsealed automatically. No event is emitted
// because the app was never visibly locked to the user.
func (s *AppLockService) AutoUnlock() {
	s.locked.Store(false)
	s.resetAutoLockTimer()
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

	s.autoLockTimer = time.AfterFunc(time.Duration(mins)*time.Minute, func() {
		if err := s.Lock(); err == nil {
			s.log.Info("app auto-locked after inactivity", "minutes", mins)
		}
	})
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
