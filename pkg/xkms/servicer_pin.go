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
	if s.pinManager == nil {
		return ErrNotConfigured
	}
	return s.pinManager.SetSOPIN(req.CurrentSOPIN, req.NewSOPIN)
}

// SetUserPIN sets the User PIN using the Security Officer PIN for authorization.
func (s *XKMSService) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	if s.pinManager == nil {
		return ErrNotConfigured
	}
	return s.pinManager.SetUserPIN(req.SOPIN, req.NewUserPIN)
}

// ChangeSOPIN changes the Security Officer PIN.
func (s *XKMSService) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	if s.pinManager == nil {
		return ErrNotConfigured
	}
	return s.pinManager.ChangeSOPIN(req.CurrentSOPIN, req.NewSOPIN)
}

// ChangeUserPIN changes the User PIN.
func (s *XKMSService) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	if s.pinManager == nil {
		return ErrNotConfigured
	}
	return s.pinManager.ChangeUserPIN(req.CurrentUserPIN, req.NewUserPIN)
}

// VerifySOPIN verifies the Security Officer PIN.
func (s *XKMSService) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	if s.pinManager == nil {
		return ErrNotConfigured
	}
	return s.pinManager.VerifySOPIN(req.SOPIN)
}

// VerifyUserPIN verifies the User PIN.
func (s *XKMSService) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	if s.pinManager == nil {
		return ErrNotConfigured
	}
	return s.pinManager.VerifyUserPIN(req.UserPIN)
}

// GetLockoutStatus returns the current PIN lockout status.
func (s *XKMSService) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	if s.pinManager == nil {
		return nil, ErrNotConfigured
	}
	status := s.pinManager.GetLockoutStatus()
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
	if s.pinManager == nil {
		return ErrNotConfigured
	}
	return s.pinManager.ResetLockout(req.SOPIN)
}
