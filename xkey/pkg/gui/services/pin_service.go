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
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// PINStatusInfo describes the current PIN state for the frontend.
type PINStatusInfo struct {
	SOPINSet    bool   `json:"so_pin_set"`
	UserPINSet  bool   `json:"user_pin_set"`
	Initialized bool   `json:"initialized"`
	Strategy    string `json:"strategy"`
}

// PINService exposes PIN management to the frontend. It is a thin wrapper
// over the unified pin.Service that adds Wails context and audit logging.
// It is bound to the Wails runtime so every exported method is callable
// from the Svelte frontend.
type PINService struct {
	ctx        context.Context
	log        *slog.Logger
	auditLog   atomic.Pointer[audit.Logger]
	pinSvc     atomic.Pointer[pin.Service]
	barrierSvc atomic.Pointer[BarrierService]
}

// NewPINService creates a new PINService. The underlying pin.Service must
// be wired via SetPINService before PIN operations are available.
func NewPINService() *PINService {
	return &PINService{
		log: slog.Default().With("component", "pin_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *PINService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *PINService) SetAuditLogger(logger audit.Logger) {
	s.auditLog.Store(&logger)
}

// SetPINService wires the underlying pin.Service that handles all PIN
// operations through the selected backend.
func (s *PINService) SetPINService(svc *pin.Service) {
	s.pinSvc.Store(svc)
}

// SetBarrierService wires the barrier service so that PIN changes
// automatically re-seal the barrier root key with the new password.
func (s *PINService) SetBarrierService(svc *BarrierService) {
	if svc == nil {
		return
	}
	s.barrierSvc.Store(svc)
}

// getPINService returns the underlying pin.Service or ErrPINServiceNotConfigured.
func (s *PINService) getPINService() (*pin.Service, error) {
	svc := s.pinSvc.Load()
	if svc == nil {
		return nil, ErrPINServiceNotConfigured
	}
	return svc, nil
}

// getAuditLogger returns the audit logger, or nil if not configured.
func (s *PINService) getAuditLogger() audit.Logger {
	ptr := s.auditLog.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// GetPINStatus returns the current PIN configuration status.
func (s *PINService) GetPINStatus() (result *PINStatusInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetPINStatus", "recover", r)
			result = nil
			retErr = fmt.Errorf("pin_service: panic in GetPINStatus: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return nil, err
	}

	return &PINStatusInfo{
		SOPINSet:    svc.SOPINSet(),
		UserPINSet:  svc.UserPINSet(),
		Initialized: svc.IsInitialized(),
		Strategy:    string(svc.Strategy()),
	}, nil
}

// SetSOPIN sets the Security Officer PIN.
func (s *PINService) SetSOPIN(currentSOPIN, newSOPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in SetSOPIN", "recover", r)
			retErr = fmt.Errorf("pin_service: panic in SetSOPIN: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	if err := svc.SetSOPIN(currentSOPIN, newSOPIN); err != nil {
		s.logPINOperation(audit.OpSOPINFailed, false, err, map[string]any{
			"operation": "set",
		})
		return err
	}

	s.logPINOperation(audit.OpSOPINChanged, true, nil, map[string]any{
		"operation": "set",
	})
	return nil
}

// SetUserPIN sets the user PIN. Requires SO PIN authorization.
// The FIDO2 PIN hash is pushed to the authenticator automatically
// by the underlying pin.Service.
func (s *PINService) SetUserPIN(soPIN, newUserPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in SetUserPIN", "recover", r)
			retErr = fmt.Errorf("pin_service: panic in SetUserPIN: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	if err := svc.SetUserPIN(soPIN, newUserPIN); err != nil {
		s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
			"operation": "set",
			"type":      "user_pin",
		})
		return err
	}

	s.logPINOperation(audit.OpPINChanged, true, nil, map[string]any{
		"operation": "set",
		"type":      "user_pin",
	})
	return nil
}

// ChangeSOPIN changes the Security Officer PIN.
func (s *PINService) ChangeSOPIN(currentSOPIN, newSOPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ChangeSOPIN", "recover", r)
			retErr = fmt.Errorf("pin_service: panic in ChangeSOPIN: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	if err := svc.ChangeSOPIN(currentSOPIN, newSOPIN); err != nil {
		s.logPINOperation(audit.OpSOPINFailed, false, err, map[string]any{
			"operation": "change",
		})
		return err
	}

	s.logPINOperation(audit.OpSOPINChanged, true, nil, map[string]any{
		"operation": "change",
	})
	return nil
}

// ChangeUserPIN changes the user PIN. The FIDO2 PIN hash is updated
// automatically by the underlying pin.Service.
func (s *PINService) ChangeUserPIN(currentUserPIN, newUserPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ChangeUserPIN", "recover", r)
			retErr = fmt.Errorf("pin_service: panic in ChangeUserPIN: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	s.log.Debug("ChangeUserPIN: attempting PIN change", "strategy", svc.Strategy())

	if err := svc.ChangeUserPIN(currentUserPIN, newUserPIN); err != nil {
		s.log.Warn("ChangeUserPIN: failed", "strategy", svc.Strategy(), "error", err)
		s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
			"operation": "change",
			"type":      "user_pin",
		})
		return err
	}

	s.log.Info("ChangeUserPIN: PIN changed successfully", "strategy", svc.Strategy())
	s.logPINOperation(audit.OpPINChanged, true, nil, map[string]any{
		"operation": "change",
		"type":      "user_pin",
	})

	// Re-seal the barrier root key with the new password so that
	// the next unseal after restart uses the updated credential.
	if bsvc := s.barrierSvc.Load(); bsvc != nil {
		if err := bsvc.ChangePassword(newUserPIN); err != nil {
			s.log.Error("ChangeUserPIN: barrier re-seal failed", "error", err)
			s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
				"operation": "barrier_reseal",
				"type":      "user_pin",
			})
			return ErrBarrierResealFailed
		}
		s.log.Info("ChangeUserPIN: barrier re-sealed with new PIN")
	}
	return nil
}

// VerifyUserPIN verifies the provided user PIN.
func (s *PINService) VerifyUserPIN(userPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in VerifyUserPIN", "recover", r)
			retErr = fmt.Errorf("pin_service: panic in VerifyUserPIN: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		s.log.Warn("VerifyUserPIN: no PIN service configured", "error", err)
		s.logPINOperation(audit.OpPINFailed, false, err, nil)
		return err
	}

	s.log.Debug("VerifyUserPIN: attempting verification",
		"strategy", svc.Strategy(),
		"user_pin_set", svc.UserPINSet())

	if err := svc.VerifyUserPIN(userPIN); err != nil {
		s.log.Warn("VerifyUserPIN: verification failed",
			"error", err,
			"strategy", svc.Strategy())
		s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
			"type": "user_pin",
		})
		// Check if this verification failure resulted in lockout.
		if status := svc.GetLockoutStatus(); status != nil && status.IsLocked {
			s.logPINOperation(audit.OpPINLocked, false, nil, map[string]any{
				"type":            "user_pin",
				"failed_attempts": status.FailedAttempts,
			})
		}
		return err
	}

	s.log.Debug("VerifyUserPIN: verification succeeded")
	s.logPINOperation(audit.OpPINVerified, true, nil, map[string]any{
		"type": "user_pin",
	})
	return nil
}

// VerifySOPIN verifies the provided SO PIN.
func (s *PINService) VerifySOPIN(soPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in VerifySOPIN", "recover", r)
			retErr = fmt.Errorf("pin_service: panic in VerifySOPIN: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		s.logPINOperation(audit.OpSOPINFailed, false, err, nil)
		return err
	}

	if err := svc.VerifySOPIN(soPIN); err != nil {
		s.logPINOperation(audit.OpSOPINFailed, false, err, map[string]any{
			"type": "so_pin",
		})
		return err
	}

	s.logPINOperation(audit.OpSOPINVerified, true, nil, map[string]any{
		"type": "so_pin",
	})
	return nil
}

// GetLockoutStatus returns the current lockout status from the backend.
func (s *PINService) GetLockoutStatus() (result *pin.LockoutStatus, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetLockoutStatus", "recover", r)
			result = nil
			retErr = fmt.Errorf("pin_service: panic in GetLockoutStatus: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return nil, err
	}

	return svc.GetLockoutStatus(), nil
}

// ResetLockout resets the lockout counter using SO PIN authorization.
func (s *PINService) ResetLockout(soPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ResetLockout", "recover", r)
			retErr = fmt.Errorf("pin_service: panic in ResetLockout: %v", r)
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	return svc.ResetLockout(soPIN)
}

// IsPINSet returns true if the user PIN has been configured. Implements
// the PINVerifier pattern for the FIDO2 authenticator.
func (s *PINService) IsPINSet() bool {
	svc := s.pinSvc.Load()
	if svc == nil {
		return false
	}
	return svc.IsPINSet()
}

// VerifyFIDO2Hash compares the provided FIDO2 PIN hash against the backend's
// cached hash. Implements the FIDO2HashVerifier pattern.
func (s *PINService) VerifyFIDO2Hash(hash []byte) bool {
	svc := s.pinSvc.Load()
	if svc == nil {
		return false
	}
	return svc.VerifyFIDO2Hash(hash)
}

// logPINOperation logs a PIN operation to the audit log.
func (s *PINService) logPINOperation(op audit.OperationType, success bool, err error, details map[string]any) {
	logger := s.getAuditLogger()
	if logger == nil {
		return
	}
	backend := "unknown"
	if svc := s.pinSvc.Load(); svc != nil {
		backend = string(svc.Strategy())
	}
	logger.LogPINOperation(op, backend, success, err, details)
}
