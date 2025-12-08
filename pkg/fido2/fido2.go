// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package fido2

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"
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
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if enumerator == nil {
		return nil, fmt.Errorf("HID device enumerator required")
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

// EnrollKey enrolls a FIDO2 key
func (h *FIDO2Handler) EnrollKey(config *EnrollmentConfig) (*EnrollmentResult, error) {
	// Find a suitable device
	device, err := h.selectDevice()
	if err != nil {
		return nil, err
	}

	// Open CTAP device
	ctapDev, err := NewCTAPHIDDevice(device, h.config)
	if err != nil {
		if closeErr := device.Close(); closeErr != nil {
			log.Printf("failed to close device after CTAP init error: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to initialize CTAP device: %w", err)
	}
	defer func() {
		if err := ctapDev.Close(); err != nil {
			log.Printf("failed to close CTAP device: %v", err)
		}
	}()

	// Create authenticator
	auth, err := NewAuthenticator(ctapDev, h.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	// Check for hmac-secret support
	if !auth.SupportsHMACSecret() {
		return nil, fmt.Errorf("device does not support hmac-secret extension")
	}

	// Create HMAC-secret extension handler
	hmacExt, err := NewHMACSecretExtension(auth)
	if err != nil {
		return nil, err
	}

	// Set timeout if specified
	if config.Timeout > 0 {
		originalTimeout := h.config.Timeout
		h.config.Timeout = config.Timeout
		defer func() { h.config.Timeout = originalTimeout }()
	}

	// Enroll credential
	h.logger.Printf("Please touch your security key...")
	result, err := hmacExt.EnrollCredential(config)
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}

	result.Created = time.Now()
	return result, nil
}

// UnlockWithKey authenticates using FIDO2 and returns the derived key
func (h *FIDO2Handler) UnlockWithKey(config *AuthenticationConfig) ([]byte, error) {
	// Find device
	device, err := h.selectDevice()
	if err != nil {
		return nil, err
	}

	// Open CTAP device
	ctapDev, err := NewCTAPHIDDevice(device, h.config)
	if err != nil {
		if closeErr := device.Close(); closeErr != nil {
			log.Printf("failed to close device after CTAP init error: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to initialize CTAP device: %w", err)
	}
	defer func() {
		if err := ctapDev.Close(); err != nil {
			log.Printf("failed to close CTAP device: %v", err)
		}
	}()

	// Create authenticator
	auth, err := NewAuthenticator(ctapDev, h.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	// Check for hmac-secret support
	if !auth.SupportsHMACSecret() {
		return nil, fmt.Errorf("device does not support hmac-secret extension")
	}

	// Create HMAC-secret extension handler
	hmacExt, err := NewHMACSecretExtension(auth)
	if err != nil {
		return nil, err
	}

	// Set timeout if specified
	if config.Timeout > 0 {
		originalTimeout := h.config.Timeout
		h.config.Timeout = config.Timeout
		defer func() { h.config.Timeout = originalTimeout }()
	}

	// Retry logic for user presence
	var lastErr error
	for attempt := 0; attempt < h.config.RetryCount; attempt++ {
		if attempt > 0 {
			h.logger.Printf("Retry %d/%d - ", attempt+1, h.config.RetryCount)
			time.Sleep(h.config.RetryDelay)
		}

		h.logger.Printf("Please touch your security key...")

		// Derive secret
		result, err := hmacExt.DeriveSecret(config)
		if err != nil {
			lastErr = err
			if err == ErrUserPresenceRequired || err == ErrOperationTimeout {
				continue // Retry
			}
			return nil, err // Non-retriable error
		}

		// Generate derived key from HMAC secret
		derivedKey, err := GenerateDerivedKey(result.HMACSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to generate derived key: %w", err)
		}

		return derivedKey, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("unlock failed after %d attempts: %w", h.config.RetryCount, lastErr)
	}

	return nil, fmt.Errorf("unlock failed after %d attempts", h.config.RetryCount)
}

// ListDevices returns available FIDO2 devices
func (h *FIDO2Handler) ListDevices() ([]Device, error) {
	// Enumerate all FIDO2 devices (vendor ID 0, product ID 0 means all)
	hidDevices, err := h.enumerator.Enumerate(0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate devices: %w", err)
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
			return nil, fmt.Errorf("failed to open configured device %s: %w", h.config.DevicePath, err)
		}
		return device, nil
	}

	// Enumerate devices
	hidDevices, err := h.enumerator.Enumerate(0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate devices: %w", err)
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

	return selectedDevice, nil
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
