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

//go:build linux

package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/virtualdevice"
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

// uhidReadTimeout is the polling interval for UHID read operations. This allows
// the bridge goroutines to periodically check the stop channel rather than
// blocking indefinitely on kernel reads.
const uhidReadTimeout = 10 * time.Millisecond

// uhidReasonPrefix is the prefix used in lastError when UHID specifically fails.
// This distinguishes UHID failures from authenticator configuration failures.
const uhidReasonPrefix = "UHID not available"

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

// FIDO2DeviceService manages the lifecycle of a UHID virtual FIDO2 device that
// bridges browser HID commands to the native Go FIDO2 authenticator. It creates
// a kernel-level HID device via /dev/uhid, routes HID packets between the host
// and the authenticator, and exposes user presence approval/denial to the GUI.
//
// All exported methods are safe for concurrent use.
type FIDO2DeviceService struct {
	ctx           context.Context
	log           *slog.Logger
	device        *virtualdevice.NativeVirtualDevice
	uhidDev       *uhid.Device
	socketHandler *authenticator.SocketHandler
	emitFunc      func(eventType string, data any)
	auditLogger   audit.Logger
	externalAuth  *authenticator.Authenticator
	elevator      Elevator
	running       atomic.Bool
	lastError     atomic.Value // stores string
	stopCh        chan struct{}
	bridgeWg      sync.WaitGroup
}

// NewFIDO2DeviceService creates a new FIDO2DeviceService.
func NewFIDO2DeviceService(log *slog.Logger) *FIDO2DeviceService {
	return &FIDO2DeviceService{
		log: log,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *FIDO2DeviceService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetEmitFunc wires the Wails event emission function so the service can push
// events such as fido2:touch_resolved to the frontend.
func (s *FIDO2DeviceService) SetEmitFunc(fn func(eventType string, data any)) {
	s.emitFunc = fn
}

// SetLastError records a human-readable reason explaining why the FIDO2
// device is not running. This is surfaced by GetStatus in the Reason field.
func (s *FIDO2DeviceService) SetLastError(reason string) {
	s.lastError.Store(reason)
}

// SetAuditLogger sets the audit logger for device lifecycle events.
func (s *FIDO2DeviceService) SetAuditLogger(l audit.Logger) {
	s.auditLogger = l
}

// SetAuthenticator sets an external authenticator instance to be used by the
// virtual device. When set, Start() passes this authenticator to the
// NativeVirtualDevice instead of letting it create a new one.
func (s *FIDO2DeviceService) SetAuthenticator(auth *authenticator.Authenticator) {
	s.externalAuth = auth
}

// SetElevator sets the privilege escalation helper for UHID permission fixes.
func (s *FIDO2DeviceService) SetElevator(e Elevator) {
	s.elevator = e
}

// SetWindowHideFunc is a no-op preserved for API compatibility.
// Touch approval no longer hides the window --- the user's xkey
// stays visible and the browser regains focus naturally.
//
// Deprecated: This callback is unused. Will be removed in a future release.
func (s *FIDO2DeviceService) SetWindowHideFunc(_ func()) {
}

// GetRequireUserPresence returns whether the authenticator requires physical
// touch for user presence. Returns true if the authenticator is unavailable.
func (s *FIDO2DeviceService) GetRequireUserPresence() bool {
	if s.externalAuth == nil {
		return true
	}
	return s.externalAuth.Config().RequireUserPresence
}

// SetRequireUserPresence configures whether the authenticator requires
// physical touch. This delegates to the shared authenticator instance.
func (s *FIDO2DeviceService) SetRequireUserPresence(required bool) {
	if s.externalAuth != nil {
		s.externalAuth.SetRequireUserPresence(required)
		s.log.Info("FIDO2 require user presence changed", "required", required)
	}
}

// GetUserIntentCheck returns whether the authenticator shows a confirmation
// dialog before entering PIN flow on GetAssertion.
func (s *FIDO2DeviceService) GetUserIntentCheck() bool {
	if s.externalAuth == nil {
		return false
	}
	return s.externalAuth.Config().EnableUserIntentCheck
}

// SetUserIntentCheck configures whether the authenticator shows a user intent
// dialog before entering PIN flow. This delegates to the shared authenticator.
func (s *FIDO2DeviceService) SetUserIntentCheck(enabled bool) {
	if s.externalAuth != nil {
		s.externalAuth.SetEnableUserIntentCheck(enabled)
		s.log.Info("FIDO2 user intent check changed", "enabled", enabled)
	}
}

// Start creates the SocketHandler, NativeVirtualDevice, and UHID device, then
// starts the bridge loop that routes HID packets between the host and the
// authenticator. The storage parameter provides credential persistence and
// the notifier dispatches user presence notifications.
func (s *FIDO2DeviceService) Start(storage authenticator.StatefulCredentialStorage, notifier notify.Notifier) error {
	if s.running.Load() {
		return ErrFIDO2DeviceAlreadyRunning
	}

	if storage == nil {
		s.lastError.Store(ErrFIDO2StorageRequired.Error())
		return ErrFIDO2StorageRequired
	}

	// Create the socket handler for user presence delegation.
	s.socketHandler = authenticator.NewSocketHandler(notifier, s.log)

	// Emit fido2:touch_resolved on every resolution (approve, deny, timeout)
	// so the frontend clears the pending TouchButton state. Without this,
	// a timeout leaves the button pulsing indefinitely.
	s.socketHandler.SetOnResolved(func(approved bool) {
		s.emit("fido2:touch_resolved", map[string]bool{"approved": approved})
		// Do NOT hide the window after touch approval. The user may be on
		// multiple monitors and wants xkey to remain visible. The browser
		// will regain focus naturally once the FIDO2 ceremony completes.
	})

	// Wire the SocketHandler to the shared authenticator so that USB HID
	// touch prompts are routed to the GUI dialog instead of being
	// auto-approved by the default AutoGrantHandler.
	if s.externalAuth != nil {
		s.externalAuth.SetUserPresenceHandler(s.socketHandler)
		s.log.Info("wired SocketHandler to shared authenticator for user presence")
	}

	// Build the native virtual device configuration.
	deviceCfg := &virtualdevice.NativeVirtualDeviceConfig{
		Storage:                    storage,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		RequireUserPresence:        true,
		EnableUserIntentCheck:      false,
		Manufacturer:               "xKey",
		Product:                    uhid.AuthenticatorDeviceName,
		SerialNumber:               "XKEY001",
		UserPresenceHandler:        s.socketHandler,
		Logger:                     s.log,
	}

	// If an external authenticator was provided, pass it to the device so it
	// is shared with other consumers (e.g., browser extension autofill).
	if s.externalAuth != nil {
		deviceCfg.Authenticator = s.externalAuth
	}

	// Create the native virtual device.
	device, err := virtualdevice.NewNativeVirtualDevice(deviceCfg)
	if err != nil {
		reason := fmt.Sprintf("failed to create virtual device: %v", err)
		s.lastError.Store(reason)
		return fmt.Errorf("fido2_device_service: %s", reason)
	}
	s.device = device

	// Register a callback to emit an event when a credential is created via
	// the CTAP2 MakeCredential flow (e.g., browser WebAuthn registration).
	// This allows the frontend to auto-refresh the credential list.
	device.Authenticator().SetOnCredentialCreated(func(cred *authenticator.StoredCredential) {
		s.emit("fido2:credential_created", map[string]string{
			"relying_party_id":  cred.RPID,
			"relying_party":     cred.RPName,
			"user_name":         cred.UserName,
			"user_display_name": cred.UserDisplayName,
		})
		s.log.Info("FIDO2 credential created",
			slog.String("rp_id", cred.RPID),
			slog.String("user", cred.UserName))
	})
	// Open the UHID kernel interface.
	uhidDev, err := uhid.Open()
	if err != nil {
		closeErr := s.device.Close()
		s.device = nil
		if closeErr != nil {
			s.log.Warn("failed to close virtual device after UHID open failure",
				slog.String("error", closeErr.Error()))
		}
		reason := fmt.Sprintf("UHID not available: %v", err)
		s.lastError.Store(reason)
		return fmt.Errorf("%w: %v", ErrFIDO2UHIDNotAvailable, err)
	}
	s.uhidDev = uhidDev

	// Enable polling with a read timeout so bridge goroutines can check the
	// stop channel instead of blocking indefinitely on kernel reads.
	s.uhidDev.SetReadTimeout(uhidReadTimeout)

	// Create the UHID virtual HID device.
	createCfg := uhid.DefaultCreateConfig()
	createCfg.Name = uhid.AuthenticatorDeviceName
	createCfg.Uniq = "XKEY001"
	if err := s.uhidDev.Create(createCfg); err != nil {
		s.cleanup()
		reason := fmt.Sprintf("failed to create UHID device: %v", err)
		s.lastError.Store(reason)
		return fmt.Errorf("fido2_device_service: %s", reason)
	}

	s.stopCh = make(chan struct{})
	s.running.Store(true)
	s.lastError.Store("")

	go s.bridgeLoop()

	s.log.Info("FIDO2 virtual device started",
		slog.String("device", uhid.AuthenticatorDeviceName),
		slog.String("serial", "XKEY001"))

	if s.auditLogger != nil {
		s.auditLogger.LogServiceEvent(audit.OpServiceStarted, map[string]any{
			"service": "fido2_virtual_device",
			"device":  uhid.AuthenticatorDeviceName,
		})
	}

	return nil
}

// Stop tears down the bridge loop, closes the UHID device, and releases
// the native virtual device. The virtual device is closed first to unblock
// the response-reader goroutine (which blocks on device.Read -> respChan),
// then we wait for both bridge goroutines to exit.
func (s *FIDO2DeviceService) Stop() error {
	if !s.running.Load() {
		return ErrFIDO2DeviceNotRunning
	}

	s.running.Store(false)
	close(s.stopCh)

	// Close the virtual device BEFORE waiting for goroutines. Goroutine 2
	// blocks on device.Read() which waits on respChan; closing the device
	// closes respChan, unblocking the read and allowing the goroutine to exit.
	// Without this, bridgeWg.Wait() deadlocks against cleanup().
	if s.device != nil {
		_ = s.device.Close()
	}

	s.bridgeWg.Wait()

	s.cleanup()

	// Restore the auto-grant handler so the shared authenticator does not
	// hang waiting for a SocketHandler that no longer has a UHID bridge.
	if s.externalAuth != nil {
		s.externalAuth.SetUserPresenceHandler(authenticator.NewAutoGrantHandler())
		s.log.Info("restored AutoGrantHandler on shared authenticator")
	}

	s.log.Info("FIDO2 virtual device stopped")

	if s.auditLogger != nil {
		s.auditLogger.LogServiceEvent(audit.OpServiceStopped, map[string]any{
			"service": "fido2_virtual_device",
		})
	}

	return nil
}

// IsRunning reports whether the virtual FIDO2 device bridge is active.
func (s *FIDO2DeviceService) IsRunning() bool {
	return s.running.Load()
}

// IsAuthenticatorPINSet reports whether the underlying FIDO2 authenticator
// has a PIN configured. Returns false if the device is not running or the
// authenticator is unavailable.
func (s *FIDO2DeviceService) IsAuthenticatorPINSet() bool {
	if !s.running.Load() || s.device == nil {
		return false
	}
	auth := s.device.Authenticator()
	if auth == nil {
		return false
	}
	return auth.IsPINSet()
}

// GetStatus returns the current status of the virtual FIDO2 device.
func (s *FIDO2DeviceService) GetStatus() *FIDO2DeviceStatus {
	status := &FIDO2DeviceStatus{
		Running:                s.running.Load(),
		AuthenticatorAvailable: s.externalAuth != nil,
	}

	if status.Running {
		status.DeviceName = uhid.AuthenticatorDeviceName
		status.VendorID = fmt.Sprintf("0x%04X", virtualdevice.NativeVirtualDeviceVendorID)
		status.ProductID = fmt.Sprintf("0x%04X", virtualdevice.NativeVirtualDeviceProductID)
		if s.socketHandler != nil {
			status.HasPending = s.socketHandler.HasPending()
		}
	} else if v := s.lastError.Load(); v != nil {
		if reason, ok := v.(string); ok && reason != "" {
			// Always preserve the original error text so the frontend can
			// detect specific failure conditions (e.g., UHID permission denied).
			status.RawReason = reason

			// Distinguish UHID-specific failures from authenticator failures.
			// When the authenticator is configured but UHID is unavailable,
			// the authenticator still works via the browser extension IPC.
			if status.AuthenticatorAvailable && strings.HasPrefix(reason, uhidReasonPrefix) {
				status.Reason = "USB HID bridge unavailable \u2014 WebAuthn works via browser extension IPC"
			} else {
				status.Reason = reason
			}
		}
	}

	return status
}

// FixUHIDPermissions uses the privilege elevator to create a udev rule granting
// the "input" group access to /dev/uhid and ensures the uhid kernel module is
// loaded at boot. This delegates to the "xkey uhid setup" CLI command which
// runs with elevated privileges via pkexec or sudo.
func (s *FIDO2DeviceService) FixUHIDPermissions() error {
	if s.elevator == nil || !s.elevator.IsAvailable() {
		return ErrElevationRequired
	}

	output, err := s.elevator.Run([]string{"uhid", "setup"}, nil)
	if err != nil {
		s.log.Error("UHID permission fix failed", "error", err, "output", string(output))
		return fmt.Errorf("%w: %v", ErrFIDO2UHIDSetupFailed, err)
	}
	s.log.Info("UHID permissions fixed via udev rule", "output", string(output))
	return nil
}

// ApproveTouchRequest approves a pending user presence request. Returns true
// if a pending request was claimed and approved, false otherwise. The
// onResolved callback on the SocketHandler emits fido2:touch_resolved and
// hides the window --- no manual emit here.
func (s *FIDO2DeviceService) ApproveTouchRequest() bool {
	if s.socketHandler == nil {
		s.log.Debug("ApproveTouchRequest: socketHandler is nil")
		return false
	}

	hasPending := s.socketHandler.HasPending()
	s.log.Debug("ApproveTouchRequest: attempting approval",
		slog.Bool("has_pending", hasPending))

	approved := s.socketHandler.Approve()
	s.log.Debug("ApproveTouchRequest: result",
		slog.Bool("approved", approved))

	return approved
}

// DenyTouchRequest denies a pending user presence request. Returns true if a
// pending request was claimed and denied, false otherwise. The onResolved
// callback on the SocketHandler emits fido2:touch_resolved.
func (s *FIDO2DeviceService) DenyTouchRequest() bool {
	if s.socketHandler == nil {
		return false
	}
	return s.socketHandler.Deny()
}

// HasPendingTouch reports whether a user presence request is currently
// awaiting approval or denial.
func (s *FIDO2DeviceService) HasPendingTouch() bool {
	if s.socketHandler == nil {
		return false
	}
	return s.socketHandler.HasPending()
}

// bridgeLoop runs two goroutines that shuttle HID packets between the UHID
// kernel device and the native virtual authenticator. The first goroutine
// reads host-to-device output reports from UHID and writes them into the
// authenticator. The second reads device-to-host responses from the
// authenticator and writes them back to UHID as input reports.
//
// Both goroutines use polling with timeouts so they periodically check the
// stop channel and exit cleanly when Stop is called.
func (s *FIDO2DeviceService) bridgeLoop() {
	s.bridgeWg.Add(2)

	// Goroutine 1: UHID -> Authenticator (host sends HID commands)
	go func() {
		defer s.bridgeWg.Done()
		for {
			select {
			case <-s.stopCh:
				return
			default:
			}

			packet, err := s.uhidDev.ReadOutput()
			if err != nil {
				// Timeouts are expected during polling; loop back to
				// check the stop channel and try again.
				if errors.Is(err, uhid.ErrTimeout) {
					continue
				}
				if s.running.Load() {
					s.log.Debug("UHID read error", slog.String("error", err.Error()))
				}
				continue
			}
			if _, writeErr := s.device.Write(packet); writeErr != nil {
				s.log.Debug("device write error", slog.String("error", writeErr.Error()))
			}
		}
	}()

	// Goroutine 2: Authenticator -> UHID (device sends HID responses)
	go func() {
		defer s.bridgeWg.Done()
		for {
			select {
			case <-s.stopCh:
				return
			default:
			}

			buf := make([]byte, uhid.HIDReportSize)
			n, err := s.device.Read(buf)
			if err != nil {
				if s.running.Load() {
					s.log.Debug("device read error", slog.String("error", err.Error()))
				}
				return
			}
			if writeErr := s.uhidDev.WriteInput(buf[:n]); writeErr != nil {
				s.log.Debug("UHID write error", slog.String("error", writeErr.Error()))
			}
		}
	}()
}

// cleanup releases the UHID device and native virtual device resources.
func (s *FIDO2DeviceService) cleanup() {
	if s.uhidDev != nil {
		if err := s.uhidDev.Close(); err != nil {
			s.log.Warn("failed to close UHID device", slog.String("error", err.Error()))
		}
		s.uhidDev = nil
	}

	if s.device != nil {
		if err := s.device.Close(); err != nil {
			s.log.Warn("failed to close virtual device", slog.String("error", err.Error()))
		}
		s.device = nil
	}
}

// emit sends an event to the frontend via the Wails emit function.
func (s *FIDO2DeviceService) emit(eventType string, data any) {
	if s.emitFunc != nil {
		s.emitFunc(eventType, data)
	}
}
