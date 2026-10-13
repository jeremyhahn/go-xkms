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

package xkms

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// PINServicer defines operations for managing Security Officer and User PINs.
//
// The PINs guard the platform's own token, so every method is
// platform-scoped (requireSystemTenant, go-xkms#1227): a tenant-scoped caller
// is refused with a *TenantBindingError that reads as not-found, before the
// PIN backend is touched -- a refused attempt does not even count toward the
// lockout.
type PINServicer interface {
	SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error
	SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error
	ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error
	ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error
	VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error
	VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error
	GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error)
	ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error
}

// SetSOPIN sets the Security Officer PIN.
func (s *XKMSService) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	pinManager := s.pinManager.load()
	if err := requireSystemTenant(ctx, "set SO PIN", ""); err != nil {
		return err
	}
	if pinManager == nil {
		return ErrNotConfigured
	}
	return pinManager.SetSOPIN(req.CurrentSOPIN, req.NewSOPIN)
}

// SetUserPIN sets the User PIN using the Security Officer PIN for authorization.
func (s *XKMSService) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	pinManager := s.pinManager.load()
	if err := requireSystemTenant(ctx, "set user PIN", ""); err != nil {
		return err
	}
	if pinManager == nil {
		return ErrNotConfigured
	}
	return pinManager.SetUserPIN(req.SOPIN, req.NewUserPIN)
}

// ChangeSOPIN changes the Security Officer PIN.
func (s *XKMSService) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	pinManager := s.pinManager.load()
	if err := requireSystemTenant(ctx, "change SO PIN", ""); err != nil {
		return err
	}
	if pinManager == nil {
		return ErrNotConfigured
	}
	return pinManager.ChangeSOPIN(req.CurrentSOPIN, req.NewSOPIN)
}

// ChangeUserPIN changes the User PIN.
func (s *XKMSService) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	pinManager := s.pinManager.load()
	if err := requireSystemTenant(ctx, "change user PIN", ""); err != nil {
		return err
	}
	if pinManager == nil {
		return ErrNotConfigured
	}
	return pinManager.ChangeUserPIN(req.CurrentUserPIN, req.NewUserPIN)
}

// VerifySOPIN verifies the Security Officer PIN.
func (s *XKMSService) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	pinManager := s.pinManager.load()
	if err := requireSystemTenant(ctx, "verify SO PIN", ""); err != nil {
		return err
	}
	if pinManager == nil {
		return ErrNotConfigured
	}
	return pinManager.VerifySOPIN(req.SOPIN)
}

// VerifyUserPIN verifies the User PIN.
func (s *XKMSService) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	pinManager := s.pinManager.load()
	if err := requireSystemTenant(ctx, "verify user PIN", ""); err != nil {
		return err
	}
	if pinManager == nil {
		return ErrNotConfigured
	}
	return pinManager.VerifyUserPIN(req.UserPIN)
}

// GetLockoutStatus returns the current PIN lockout status.
func (s *XKMSService) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	pinManager := s.pinManager.load()
	if err := requireSystemTenant(ctx, "PIN lockout status", ""); err != nil {
		return nil, err
	}
	if pinManager == nil {
		return nil, ErrNotConfigured
	}
	status := pinManager.GetLockoutStatus()
	if status == nil {
		// A backend that does not track lockout (the software backend)
		// reports none: no failed attempts, nothing locked.
		return &transport.LockoutStatusResponse{}, nil
	}
	var lockoutUntil string
	if !status.LockoutUntil.IsZero() {
		lockoutUntil = status.LockoutUntil.Format(time.RFC3339)
	}
	return &transport.LockoutStatusResponse{
		FailedAttempts:  status.FailedAttempts,
		MaxAttempts:     status.MaxAttempts,
		IsLocked:        status.IsLocked,
		LockoutUntil:    lockoutUntil,
		RecoverySeconds: status.RecoverySeconds,
	}, nil
}

// ResetLockout resets the PIN lockout counter using the Security Officer PIN.
func (s *XKMSService) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	pinManager := s.pinManager.load()
	if err := requireSystemTenant(ctx, "reset PIN lockout", ""); err != nil {
		return err
	}
	if pinManager == nil {
		return ErrNotConfigured
	}
	return pinManager.ResetLockout(req.SOPIN)
}
