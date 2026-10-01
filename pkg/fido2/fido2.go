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

package fido2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Handler provides high-level FIDO2 operations
type Handler interface {
	// EnrollKey enrolls a FIDO2 key
	EnrollKey(config *EnrollmentConfig) (*EnrollmentResult, error)

	// UnlockWithKey authenticates using FIDO2 and returns the derived key
	UnlockWithKey(config *AuthenticationConfig) ([]byte, error)

	// ListDevices returns available FIDO2 devices
	ListDevices() ([]Device, error)

	// WaitForDevice waits for device insertion
	WaitForDevice(ctx context.Context) (*Device, error)

	// Close closes the handler and releases resources
	Close() error
}

// Logger interface for logging
type Logger interface {
	Printf(format string, v ...interface{})
}

// FIDO2Handler implements the Handler interface
type FIDO2Handler struct {
	config     *Config
	enumerator HIDDeviceEnumerator
	logger     Logger
}

// discardLogger is a logger that discards all output
type discardLogger struct{}

func (d *discardLogger) Printf(format string, v ...interface{}) {}

// NewHandler creates a new FIDO2 handler
func NewHandler(config *Config, enumerator HIDDeviceEnumerator) (*FIDO2Handler, error) {
	if config == nil {
		cfg := DefaultConfig
		config = &cfg
	}

	if err := config.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid configuration", Err: err}
	}

	if enumerator == nil {
		return nil, &errs.Message{Msg: "HID device enumerator required"}
	}

	return &FIDO2Handler{
		config:     config,
		enumerator: enumerator,
		logger:     &discardLogger{},
	}, nil
}

// NewHandlerWithLogger creates a new FIDO2 handler with logging
func NewHandlerWithLogger(config *Config, enumerator HIDDeviceEnumerator, logger Logger) (*FIDO2Handler, error) {
	h, err := NewHandler(config, enumerator)
	if err != nil {
		return nil, err
	}
	if logger != nil {
		h.logger = logger
	}
	return h, nil
}

// PromptWriter is an optional interface for customizing user prompts
type PromptWriter interface {
	io.Writer
}

// hmacSession is an open hmac-secret session on the selected authenticator.
type hmacSession struct {
	ext   *HMACSecretExtension
	close func()
}

// openHMACSession selects a device, opens its CTAP channel, and returns the
// hmac-secret extension of an authenticator that supports it. timeout, when
// positive, overrides the configured timeout until the session is closed.
func (h *FIDO2Handler) openHMACSession(timeout time.Duration) (*hmacSession, error) {
	device, err := h.selectDevice()
	if err != nil {
		return nil, err
	}

	ctapDev, err := NewCTAPHIDDevice(device, h.config)
	if err != nil {
		if closeErr := device.Close(); closeErr != nil {
			log.Printf("failed to close device after CTAP init error: %v", closeErr)
		}
		return nil, &errs.Wrapped{Msg: "failed to initialize CTAP device", Err: err}
	}
	closeDev := func() {
		if err := ctapDev.Close(); err != nil {
			log.Printf("failed to close CTAP device: %v", err)
		}
	}

	auth, err := NewAuthenticator(ctapDev, h.config)
	if err != nil {
		closeDev()
		return nil, &errs.Wrapped{Msg: "failed to create authenticator", Err: err}
	}
	if !auth.SupportsHMACSecret() {
		closeDev()
		return nil, &errs.Message{Msg: "device does not support hmac-secret extension"}
	}
	hmacExt, err := NewHMACSecretExtension(auth)
	if err != nil {
		closeDev()
		return nil, err
	}

	restore := func() {}
	if timeout > 0 {
		originalTimeout := h.config.Timeout
		h.config.Timeout = timeout
		restore = func() { h.config.Timeout = originalTimeout }
	}
	return &hmacSession{ext: hmacExt, close: func() { restore(); closeDev() }}, nil
}

// EnrollKey enrolls a FIDO2 key with the hmac-secret extension. A PIN in
// config authorizes the registration on a PIN-protected key.
func (h *FIDO2Handler) EnrollKey(config *EnrollmentConfig) (*EnrollmentResult, error) {
	if config == nil {
		return nil, ErrEnrollmentConfigNil
	}
	session, err := h.openHMACSession(config.Timeout)
	if err != nil {
		return nil, err
	}
	defer session.close()

	h.logger.Printf("Please touch your security key...")
	result, err := session.ext.EnrollCredential(config)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "enrollment failed", Err: err}
	}

	result.Created = time.Now()
	return result, nil
}

// DeriveHMACSecret evaluates the credential's hmac-secret over config.Salt
// (and Salt2) and returns the raw outputs: AuthenticationResult.HMACSecret
// is the 32-byte HMAC-SHA-256(CredRandom, salt) of CTAP 2.1 12.5, not a key
// derived from it. A PIN in config makes the assertion user-verified, which
// selects the authenticator's CredRandomWithUV: supply a PIN on every
// evaluation that must reproduce an output, or on none. Transient failures
// (no user presence, timeout) are retried up to Config.RetryCount times.
func (h *FIDO2Handler) DeriveHMACSecret(config *AuthenticationConfig) (*AuthenticationResult, error) {
	if config == nil {
		return nil, ErrAuthenticationConfigNil
	}
	session, err := h.openHMACSession(config.Timeout)
	if err != nil {
		return nil, err
	}
	defer session.close()

	var lastErr error
	for attempt := 0; attempt < h.config.RetryCount; attempt++ {
		if attempt > 0 {
			h.logger.Printf("Retry %d/%d - ", attempt+1, h.config.RetryCount)
			<-time.After(h.config.RetryDelay)
		}

		h.logger.Printf("Please touch your security key...")
		result, err := session.ext.DeriveSecret(config)
		if err == nil {
			return result, nil
		}
		lastErr = err
		// The sentinel arrives wrapped by the CTAP2 and hmac-secret layers,
		// so identity comparison would never match and the retry would
		// never run.
		if !errors.Is(err, ErrUserPresenceRequired) && !errors.Is(err, ErrOperationTimeout) {
			return nil, err // Non-retriable error
		}
	}

	if lastErr != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("hmac-secret evaluation failed after %d attempts", h.config.RetryCount), Err: lastErr}
	}
	return nil, &errs.Message{Msg: fmt.Sprintf("hmac-secret evaluation failed after %d attempts", h.config.RetryCount)}
}

// UnlockWithKey authenticates using FIDO2 and returns a key derived from the
// hmac-secret output (GenerateDerivedKey). Use DeriveHMACSecret for the raw
// output.
func (h *FIDO2Handler) UnlockWithKey(config *AuthenticationConfig) ([]byte, error) {
	result, err := h.DeriveHMACSecret(config)
	if err != nil {
		return nil, err
	}
	defer clear(result.HMACSecret)

	derivedKey, err := GenerateDerivedKey(result.HMACSecret)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate derived key", Err: err}
	}
	return derivedKey, nil
}

// ListDevices returns available FIDO2 devices
func (h *FIDO2Handler) ListDevices() ([]Device, error) {
	// Enumerate all FIDO2 devices (vendor ID 0, product ID 0 means all)
	hidDevices, err := h.enumerator.Enumerate(0, 0)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to enumerate devices", Err: err}
	}

	var devices []Device
	for _, hidDev := range hidDevices {
		// Filter for FIDO2 devices if needed
		if h.isFIDO2Device(hidDev) {
			devices = append(devices, Device{
				Path:         hidDev.Path(),
				VendorID:     hidDev.VendorID(),
				ProductID:    hidDev.ProductID(),
				Manufacturer: hidDev.Manufacturer(),
				Product:      hidDev.Product(),
				SerialNumber: hidDev.SerialNumber(),
				Transport:    "usb",
			})
		}
		if err := hidDev.Close(); err != nil {
			log.Printf("failed to close device %s: %v", hidDev.Path(), err)
		}
	}

	return devices, nil
}

// WaitForDevice waits for a FIDO2 device to be inserted
func (h *FIDO2Handler) WaitForDevice(ctx context.Context) (*Device, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			devices, err := h.ListDevices()
			if err != nil {
				continue
			}
			if len(devices) > 0 {
				return &devices[0], nil
			}
		}
	}
}

// selectDevice selects a suitable FIDO2 device
func (h *FIDO2Handler) selectDevice() (HIDDevice, error) {
	// If specific device path is configured, use it
	if h.config.DevicePath != "" {
		device, err := h.enumerator.Open(h.config.DevicePath)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to open configured device %s", h.config.DevicePath), Err: err}
		}
		return device, nil
	}

	// Enumerate devices
	hidDevices, err := h.enumerator.Enumerate(0, 0)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to enumerate devices", Err: err}
	}

	if len(hidDevices) == 0 {
		return nil, ErrNoDeviceFound
	}

	// Filter and select device
	var selectedDevice HIDDevice
	for _, device := range hidDevices {
		if !h.isFIDO2Device(device) {
			if err := device.Close(); err != nil {
				log.Printf("failed to close non-FIDO2 device %s: %v", device.Path(), err)
			}
			continue
		}

		// Apply vendor/product filters if configured
		if len(h.config.AllowedVendors) > 0 {
			allowed := false
			for _, vid := range h.config.AllowedVendors {
				if device.VendorID() == vid {
					allowed = true
					break
				}
			}
			if !allowed {
				if err := device.Close(); err != nil {
					log.Printf("failed to close filtered device %s: %v", device.Path(), err)
				}
				continue
			}
		}

		if len(h.config.AllowedProducts) > 0 {
			allowed := false
			for _, pid := range h.config.AllowedProducts {
				if device.ProductID() == pid {
					allowed = true
					break
				}
			}
			if !allowed {
				if err := device.Close(); err != nil {
					log.Printf("failed to close filtered device %s: %v", device.Path(), err)
				}
				continue
			}
		}

		// Use first matching device
		selectedDevice = device
		break
	}

	// Close remaining devices
	for _, device := range hidDevices {
		if device != selectedDevice {
			if err := device.Close(); err != nil {
				log.Printf("failed to close unselected device %s: %v", device.Path(), err)
			}
		}
	}

	if selectedDevice == nil {
		return nil, ErrNoDeviceFound
	}

	// Enumerate returns metadata-only handles — the Linux enumerator scans
	// sysfs without opening the hidraw file — so the selected device must be
	// re-opened through the enumerator before any CTAP traffic, or the first
	// HID write fails with "device not open". Enumerators that hand back
	// live devices (in-process/test authenticators) return the same instance
	// from Open, which is used as-is.
	opened, err := h.enumerator.Open(selectedDevice.Path())
	if err != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to open selected device %s", selectedDevice.Path()), Err: err}
	}
	if opened != selectedDevice {
		if err := selectedDevice.Close(); err != nil {
			log.Printf("failed to close enumeration handle %s: %v", selectedDevice.Path(), err)
		}
	}

	return opened, nil
}

// isFIDO2Device checks if a HID device is a FIDO2 authenticator
func (h *FIDO2Handler) isFIDO2Device(device HIDDevice) bool {
	// FIDO2 devices use HID usage page 0xF1D0
	// This is a simplified check - proper implementation would query HID descriptor
	// For now, we'll accept any device and let CTAP initialization fail if not FIDO2
	return true
}

// Close closes the handler and releases resources
func (h *FIDO2Handler) Close() error {
	// Nothing to clean up in the handler itself
	return nil
}

// DefaultEnrollmentConfig creates a default enrollment configuration
func DefaultEnrollmentConfig(userName string) *EnrollmentConfig {
	return &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   DefaultConfig.RelyingPartyID,
			Name: DefaultConfig.RelyingPartyName,
		},
		User: User{
			Name:        userName,
			DisplayName: userName,
		},
		RequireUserVerification: false,
		Timeout:                 DefaultUserPresenceTimeout,
	}
}

// DefaultAuthenticationConfig creates a default authentication configuration
func DefaultAuthenticationConfig(credentialID, salt []byte) *AuthenticationConfig {
	return &AuthenticationConfig{
		RelyingPartyID:          DefaultConfig.RelyingPartyID,
		CredentialID:            credentialID,
		Salt:                    salt,
		RequireUserVerification: false,
		Timeout:                 DefaultUserPresenceTimeout,
	}
}
