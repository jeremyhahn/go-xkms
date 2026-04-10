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

package virtualdevice

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
)

// NativeVirtualDevice errors.
var (
	// ErrNativeDeviceClosed indicates the native virtual device has been closed.
	ErrNativeDeviceClosed = errors.New("fido2: native virtual device closed")

	// ErrNativeDeviceNilConfig indicates the configuration is nil.
	ErrNativeDeviceNilConfig = errors.New("fido2: native virtual device config is nil")
)

// Constants for native virtual device identification.
const (
	// NativeVirtualDeviceVendorID is the vendor ID for native virtual devices.
	NativeVirtualDeviceVendorID uint16 = 0xF1D0 // FIDO Alliance

	// NativeVirtualDeviceProductID is the product ID for native virtual devices.
	NativeVirtualDeviceProductID uint16 = 0x0001 // Matches uhid.ProductIDVirtualFIDO

	// NativeVirtualDevicePathPrefix is the path prefix for native virtual devices.
	NativeVirtualDevicePathPrefix = "native-fido://"

	// Default response channel buffer size.
	nativeDeviceRespChanSize = 64
)

// NativeVirtualDeviceConfig contains configuration for creating a native virtual device.
type NativeVirtualDeviceConfig struct {
	// SerialNumber is the device serial number.
	SerialNumber string

	// Manufacturer is the manufacturer name.
	Manufacturer string

	// Product is the product name.
	Product string

	// Storage is the credential storage backend.
	// If nil, a new MemoryStorage will be created.
	Storage authenticator.StatefulCredentialStorage

	// AAGUID is the Authenticator Attestation GUID.
	// If zero, the default AAGUID will be used.
	AAGUID [16]byte

	// EnablePIN enables PIN support.
	EnablePIN bool

	// EnableHMACSecret enables the hmac-secret extension.
	EnableHMACSecret bool

	// EnableResidentKey enables resident key (discoverable credential) support.
	EnableResidentKey bool

	// EnableCredentialManagement enables credential management commands.
	EnableCredentialManagement bool

	// SupportedAlgorithms specifies which COSE algorithms are supported.
	// If nil, defaults to ES256.
	SupportedAlgorithms []int

	// KeyBackend is the pluggable key backend for credential key operations.
	// If nil, the legacy crypto.go path is used.
	KeyBackend keybackend.FIDO2KeyBackend

	// RequireUserPresence controls whether user presence (touch) is required
	// even when PIN authentication succeeds. Set to true for hardware-like behavior.
	RequireUserPresence bool

	// EnableUserIntentCheck enables a user presence dialog before returning
	// StatusPINRequired on GetAssertion. This allows users with multiple security
	// keys to decline and let the browser fall through to a different device.
	EnableUserIntentCheck bool

	// UserPresenceHandler is the handler for user presence requests.
	// If nil, an AutoGrantHandler is used.
	UserPresenceHandler authenticator.UserPresenceHandler

	// Authenticator is an optional pre-existing authenticator instance.
	// If non-nil, the virtual device uses this authenticator instead of creating a new one.
	// This allows sharing a single authenticator between the USB HID device and other
	// consumers (e.g., browser extension autofill).
	Authenticator *authenticator.Authenticator

	// Logger is the structured logger for HID-level operational logging.
	// If nil, HID handler structured logging is disabled (debugHIDLog still works).
	Logger *slog.Logger
}

// NativeVirtualDevice implements fido2.HIDDevice using the native Go authenticator.
// This provides a pure Go implementation without external dependencies.
//
// All methods are safe for concurrent use.
type NativeVirtualDevice struct {
	path          string
	authenticator *authenticator.Authenticator
	hidHandler    *authenticator.CTAPHIDHandler
	manufacturer  string
	product       string
	serialNumber  string
	respChan      chan []byte
	closed        atomic.Bool
	ownsAuth      bool // true when this device created the authenticator
	mu            sync.Mutex
}

// NewNativeVirtualDevice creates a new native virtual FIDO2 device.
// The device uses the native Go authenticator implementation.
func NewNativeVirtualDevice(config *NativeVirtualDeviceConfig) (*NativeVirtualDevice, error) {
	if config == nil {
		config = &NativeVirtualDeviceConfig{}
	}

	// Apply defaults
	if config.SerialNumber == "" {
		config.SerialNumber = "NFIDO001"
	}
	if config.Manufacturer == "" {
		config.Manufacturer = "go-xkms"
	}
	if config.Product == "" {
		config.Product = uhid.AuthenticatorDeviceName
	}

	var auth *authenticator.Authenticator
	var ownsAuth bool

	if config.Authenticator != nil {
		// Use the pre-existing authenticator instance.
		auth = config.Authenticator
	} else {
		// Create storage if not provided
		storage := config.Storage
		if storage == nil {
			storage = authenticator.NewMemoryStorage()
		}

		// Build authenticator config
		authConfig := authenticator.DefaultConfig()
		authConfig.Storage = storage

		if config.AAGUID != [16]byte{} {
			authConfig.AAGUID = config.AAGUID
		}

		// Feature flags: callers must explicitly set these to true when desired.
		// DefaultConfig() sets them all true, but the device config takes
		// precedence so callers control which features are active.
		authConfig.EnablePIN = config.EnablePIN
		authConfig.EnableHMACSecret = config.EnableHMACSecret
		authConfig.EnableResidentKey = config.EnableResidentKey
		authConfig.EnableCredentialManagement = config.EnableCredentialManagement

		if len(config.SupportedAlgorithms) > 0 {
			authConfig.SupportedAlgorithms = config.SupportedAlgorithms
		}

		authConfig.RequireUserPresence = config.RequireUserPresence
		authConfig.EnableUserIntentCheck = config.EnableUserIntentCheck
		authConfig.KeyBackend = config.KeyBackend
		authConfig.UserPresenceHandler = config.UserPresenceHandler

		// Create authenticator
		var err error
		auth, err = authenticator.NewAuthenticator(authConfig)
		if err != nil {
			return nil, err
		}
		ownsAuth = true
	}

	// Create the device
	device := &NativeVirtualDevice{
		path:          NativeVirtualDevicePathPrefix + config.SerialNumber,
		authenticator: auth,
		manufacturer:  config.Manufacturer,
		product:       config.Product,
		serialNumber:  config.SerialNumber,
		respChan:      make(chan []byte, nativeDeviceRespChanSize),
		ownsAuth:      ownsAuth,
	}

	// Create HID handler
	device.hidHandler = authenticator.NewCTAPHIDHandler(auth)
	if config.Logger != nil {
		device.hidHandler.SetLogger(config.Logger)
	}

	// Set up response handler
	device.hidHandler.SetResponseHandler(func(response []byte) {
		device.handleResponse(response)
	})

	return device, nil
}

// handleResponse processes a response from the HID handler.
func (d *NativeVirtualDevice) handleResponse(response []byte) {
	if d.closed.Load() {
		return
	}

	// Make a copy to prevent data races
	resp := make([]byte, len(response))
	copy(resp, response)

	// Non-blocking send to response channel
	select {
	case d.respChan <- resp:
	default:
		// Channel full - drop oldest response
		select {
		case <-d.respChan:
		default:
		}
		select {
		case d.respChan <- resp:
		default:
		}
	}
}

// Write sends data to the virtual device (HID output report).
// The data should be a 64-byte HID packet.
func (d *NativeVirtualDevice) Write(data []byte) (int, error) {
	if d.closed.Load() {
		return 0, ErrNativeDeviceClosed
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Process the HID packet through the handler
	d.hidHandler.HandleMessage(data)

	return len(data), nil
}

// Read receives data from the virtual device (HID input report).
// The data buffer should be at least 64 bytes.
func (d *NativeVirtualDevice) Read(data []byte) (int, error) {
	if d.closed.Load() {
		return 0, ErrNativeDeviceClosed
	}

	// Wait for response from the device
	response, ok := <-d.respChan
	if !ok || response == nil {
		return 0, ErrNativeDeviceClosed
	}

	n := copy(data, response)
	return n, nil
}

// Close closes the virtual device and releases resources.
// If the device was created with a pre-existing authenticator, the
// authenticator is not closed (the caller retains ownership).
func (d *NativeVirtualDevice) Close() error {
	if d.closed.Swap(true) {
		return nil // Already closed
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Close the HID handler first
	if d.hidHandler != nil {
		_ = d.hidHandler.Close()
	}

	// Only close the authenticator if this device created it.
	if d.ownsAuth && d.authenticator != nil {
		_ = d.authenticator.Close()
	}

	// Close the response channel
	close(d.respChan)

	return nil
}

// Path returns the virtual device path.
func (d *NativeVirtualDevice) Path() string {
	return d.path
}

// ProductID returns the USB product ID.
func (d *NativeVirtualDevice) ProductID() uint16 {
	return NativeVirtualDeviceProductID
}

// VendorID returns the USB vendor ID.
func (d *NativeVirtualDevice) VendorID() uint16 {
	return NativeVirtualDeviceVendorID
}

// Product returns the product name.
func (d *NativeVirtualDevice) Product() string {
	return d.product
}

// Manufacturer returns the manufacturer name.
func (d *NativeVirtualDevice) Manufacturer() string {
	return d.manufacturer
}

// SerialNumber returns the device serial number.
func (d *NativeVirtualDevice) SerialNumber() string {
	return d.serialNumber
}

// Authenticator returns the underlying authenticator.
// This can be used for direct authenticator operations.
func (d *NativeVirtualDevice) Authenticator() *authenticator.Authenticator {
	return d.authenticator
}

// HIDHandler returns the underlying CTAP-HID handler.
// This can be used for advanced protocol testing.
func (d *NativeVirtualDevice) HIDHandler() *authenticator.CTAPHIDHandler {
	return d.hidHandler
}

// Ensure NativeVirtualDevice implements fido2.HIDDevice.
var _ fido2.HIDDevice = (*NativeVirtualDevice)(nil)
