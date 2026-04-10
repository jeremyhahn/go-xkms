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

//go:build !linux

package services

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// FIDO2 device service errors.
var (
	// ErrFIDO2DeviceAlreadyRunning indicates the virtual FIDO2 device is already running.
	ErrFIDO2DeviceAlreadyRunning = errors.New("fido2_device_service: device already running")

	// ErrFIDO2DeviceNotRunning indicates the virtual FIDO2 device is not running.
	ErrFIDO2DeviceNotRunning = errors.New("fido2_device_service: device not running")

	// ErrFIDO2UHIDNotAvailable indicates the UHID kernel interface is unavailable.
	ErrFIDO2UHIDNotAvailable = errors.New("fido2_device_service: UHID not available")

	// ErrFIDO2StorageRequired indicates that FIDO2 credential storage must be provided.
	ErrFIDO2StorageRequired = errors.New("fido2_device_service: FIDO2 storage is required")

	// ErrFIDO2UHIDSetupFailed indicates that the privileged UHID setup operation failed.
	ErrFIDO2UHIDSetupFailed = errors.New("fido2_device_service: UHID setup failed")
)

// FIDO2DeviceStatus describes the current state of the virtual FIDO2 HID device.
type FIDO2DeviceStatus struct {
	Running                bool   `json:"running"`
	DeviceName             string `json:"device_name"`
	VendorID               string `json:"vendor_id"`
	ProductID              string `json:"product_id"`
	HasPending             bool   `json:"has_pending_touch"`
	Reason                 string `json:"reason,omitempty"`
	RawReason              string `json:"raw_reason,omitempty"`
	AuthenticatorAvailable bool   `json:"authenticator_available"` // Authenticator works via IPC even when UHID unavailable
}

// FIDO2DeviceService is a stub for non-Linux platforms where UHID is not available.
// All lifecycle methods return ErrFIDO2UHIDNotAvailable.
type FIDO2DeviceService struct {
	log         *slog.Logger
	auditLogger audit.Logger
	lastError   string
}

// NewFIDO2DeviceService creates a new FIDO2DeviceService stub.
func NewFIDO2DeviceService(log *slog.Logger) *FIDO2DeviceService {
	return &FIDO2DeviceService{
		log: log,
	}
}

// SetContext is a no-op on non-Linux platforms.
func (s *FIDO2DeviceService) SetContext(_ context.Context) {}

// SetEmitFunc is a no-op on non-Linux platforms.
func (s *FIDO2DeviceService) SetEmitFunc(_ func(eventType string, data any)) {}

// SetLastError records a human-readable reason explaining why the FIDO2
// device is not running. This is surfaced by GetStatus in the Reason field.
func (s *FIDO2DeviceService) SetLastError(reason string) {
	s.lastError = reason
}

// SetAuditLogger is a no-op on non-Linux platforms.
func (s *FIDO2DeviceService) SetAuditLogger(_ audit.Logger) {}

// SetElevator is a no-op on non-Linux platforms.
func (s *FIDO2DeviceService) SetElevator(_ Elevator) {}

// Start returns ErrFIDO2UHIDNotAvailable on non-Linux platforms.
func (s *FIDO2DeviceService) Start(_ authenticator.StatefulCredentialStorage, _ notify.Notifier) error {
	return ErrFIDO2UHIDNotAvailable
}

// Stop returns ErrFIDO2DeviceNotRunning on non-Linux platforms.
func (s *FIDO2DeviceService) Stop() error {
	return ErrFIDO2DeviceNotRunning
}

// IsRunning returns false on non-Linux platforms.
func (s *FIDO2DeviceService) IsRunning() bool {
	return false
}

// GetStatus returns a status indicating the device is not running on non-Linux platforms.
func (s *FIDO2DeviceService) GetStatus() *FIDO2DeviceStatus {
	status := &FIDO2DeviceStatus{
		Running: false,
	}
	if s.lastError != "" {
		status.Reason = s.lastError
		status.RawReason = s.lastError
	} else {
		status.Reason = ErrFIDO2UHIDNotAvailable.Error()
		status.RawReason = ErrFIDO2UHIDNotAvailable.Error()
	}
	return status
}

// FixUHIDPermissions returns ErrFIDO2UHIDNotAvailable on non-Linux platforms.
func (s *FIDO2DeviceService) FixUHIDPermissions() error {
	return ErrFIDO2UHIDNotAvailable
}

// ApproveTouchRequest returns false on non-Linux platforms.
func (s *FIDO2DeviceService) ApproveTouchRequest() bool {
	return false
}

// DenyTouchRequest returns false on non-Linux platforms.
func (s *FIDO2DeviceService) DenyTouchRequest() bool {
	return false
}

// HasPendingTouch returns false on non-Linux platforms.
func (s *FIDO2DeviceService) HasPendingTouch() bool {
	return false
}

// IsAuthenticatorPINSet returns false on non-Linux platforms.
func (s *FIDO2DeviceService) IsAuthenticatorPINSet() bool {
	return false
}
