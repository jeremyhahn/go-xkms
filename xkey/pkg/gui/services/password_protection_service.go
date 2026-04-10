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
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

// Password protection service errors.
var (
	// ErrPPNotConfigured indicates the password store has not been initialized.
	ErrPPNotConfigured = errors.New("password_protection: not configured")
)

// PasswordProtectionStatus is the frontend-facing representation of the
// password protection state.
type PasswordProtectionStatus struct {
	Mode          string `json:"mode"`
	TPMAvailable  bool   `json:"tpm_available"`
	KeySource     string `json:"key_source"`
	IsLocked      bool   `json:"is_locked"`
	PasswordCount int    `json:"password_count"`
}

// PasswordProtectionService provides password store status and export.
// Lock/unlock functionality has been removed; the global AppLockService
// now handles all UI-level access gating.
type PasswordProtectionService struct {
	ctx         context.Context
	log         *slog.Logger
	auditLog    atomic.Pointer[audit.Logger]
	staticPWSvc *StaticPasswordService
	sealSvc     *SealService
}

// NewPasswordProtectionService creates a new PasswordProtectionService.
// The configPath parameter is unused and retained only for backward
// compatibility with callers that pass it.
func NewPasswordProtectionService(
	_ string,
	staticPWSvc *StaticPasswordService,
	sealSvc *SealService,
) *PasswordProtectionService {
	return &PasswordProtectionService{
		log:         slog.Default().With("component", "password_protection"),
		staticPWSvc: staticPWSvc,
		sealSvc:     sealSvc,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *PasswordProtectionService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *PasswordProtectionService) SetAuditLogger(logger audit.Logger) {
	s.auditLog.Store(&logger)
}

// logPasswordStoreOp logs a password store operation to the audit log.
func (s *PasswordProtectionService) logPasswordStoreOp(op audit.OperationType, source string, success bool, err error, details map[string]any) {
	ptr := s.auditLog.Load()
	if ptr == nil {
		return
	}
	(*ptr).LogPasswordStoreOperation(op, source, success, err, details)
}

// GetStatus returns the current password protection status.
// IsLocked is always false; the AppLockService handles access gating.
func (s *PasswordProtectionService) GetStatus() (*PasswordProtectionStatus, error) {
	tpmAvailable := false
	if s.sealSvc != nil {
		tpmAvailable, _ = s.sealSvc.CanSeal()
	}

	pwCount := 0
	if s.staticPWSvc != nil && s.staticPWSvc.store != nil {
		if pws, err := s.staticPWSvc.store.List(); err == nil {
			pwCount = len(pws)
		}
	}

	return &PasswordProtectionStatus{
		Mode:          "barrier",
		TPMAvailable:  tpmAvailable,
		KeySource:     "barrier",
		IsLocked:      false,
		PasswordCount: pwCount,
	}, nil
}

// ExportPasswordsDecrypted returns all stored passwords. The barrier
// provides transparent decryption; the AppLockService gates UI access.
func (s *PasswordProtectionService) ExportPasswordsDecrypted(_ string) ([]*staticpw.StaticPassword, error) {
	if s.staticPWSvc == nil || s.staticPWSvc.store == nil {
		return nil, ErrPPNotConfigured
	}

	passwords, err := s.staticPWSvc.store.List()
	if err != nil {
		return nil, err
	}

	return passwords, nil
}
