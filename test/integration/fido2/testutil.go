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

//go:build integration && fido2

package fido2

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/fido2"
	"github.com/stretchr/testify/require"
)

// TestConfig holds FIDO2 integration test configuration
type TestConfig struct {
	DevicePath         string
	CanoKeyQEMU        string
	PIN                string
	Timeout            time.Duration
	WaitDeviceTimeout  time.Duration
	RegistrationConfig *fido2.EnrollmentConfig
	AuthConfig         *fido2.AuthenticationConfig
}

// LoadFIDO2TestConfig loads test configuration from environment
func LoadFIDO2TestConfig() *TestConfig {
	cfg := &TestConfig{
		DevicePath:        os.Getenv("FIDO2_DEVICE_PATH"),
		CanoKeyQEMU:       os.Getenv("CANOKEY_QEMU"),
		PIN:               os.Getenv("FIDO2_PIN"),
		Timeout:           30 * time.Second,
		WaitDeviceTimeout: 60 * time.Second,
	}

	// Use CanoKey QEMU device path if available and the device is valid
	if cfg.CanoKeyQEMU != "" && isValidFIDO2Device(cfg.CanoKeyQEMU) {
		cfg.DevicePath = cfg.CanoKeyQEMU
	} else if cfg.DevicePath != "" && !isValidFIDO2Device(cfg.DevicePath) {
		// FIDO2_DEVICE_PATH is set but device is not valid, clear it for auto-detection
		cfg.DevicePath = ""
	}

	// Auto-detect FIDO2 device if not explicitly set or device doesn't exist
	if cfg.DevicePath == "" {
		cfg.DevicePath = autoDetectFIDO2Device()
	}

	return cfg
}

// isValidFIDO2Device checks if a device path exists and is a valid FIDO2 device
// For hidraw devices, just check existence. For sockets, try to verify they work.
func isValidFIDO2Device(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// For hidraw devices, check if it's a character device
	if strings.HasPrefix(path, "/dev/hidraw") {
		// Character devices have the right mode
		return info.Mode()&os.ModeCharDevice != 0
	}

	// For socket paths (like CanoKey QEMU), try to actually open the device
	// by using the enumerator's Open method directly
	if info.Mode()&os.ModeSocket != 0 {
		enumerator := fido2.NewDefaultEnumerator()
		device, err := enumerator.Open(path)
		if err != nil {
			return false
		}
		// Successfully opened - close it and return true
		device.Close()
		return true
	}

	return false
}

// autoDetectFIDO2Device attempts to find a FIDO2 device automatically
// using the fido2 package to enumerate real devices
func autoDetectFIDO2Device() string {
	// Use the fido2 package to enumerate devices
	cfg := fido2.DefaultConfig
	cfg.Timeout = 5 * time.Second
	enumerator := fido2.NewDefaultEnumerator()

	handler, err := fido2.NewHandler(&cfg, enumerator)
	if err != nil {
		return ""
	}
	defer handler.Close()

	devices, err := handler.ListDevices()
	if err != nil || len(devices) == 0 {
		return ""
	}

	// Return the path of the first detected device
	return devices[0].Path
}

// GetFIDO2Config returns a FIDO2 handler configuration
func (tc *TestConfig) GetFIDO2Config() *fido2.Config {
	cfg := fido2.DefaultConfig
	cfg.DevicePath = tc.DevicePath
	cfg.Timeout = tc.Timeout
	if tc.PIN != "" {
		cfg.RequireUserVerification = true
	}
	return &cfg
}

// CreateHandler creates a new FIDO2 handler for testing
func (tc *TestConfig) CreateHandler(t *testing.T) *fido2.FIDO2Handler {
	t.Helper()

	cfg := tc.GetFIDO2Config()
	enumerator := fido2.NewDefaultEnumerator()

	handler, err := fido2.NewHandler(cfg, enumerator)
	require.NoError(t, err, "Failed to create FIDO2 handler")
	require.NotNil(t, handler)

	return handler
}

// CheckDeviceAvailable checks if a FIDO2 device is available
func (tc *TestConfig) CheckDeviceAvailable(t *testing.T) bool {
	t.Helper()

	handler := tc.CreateHandler(t)
	defer handler.Close()

	devices, err := handler.ListDevices()
	if err != nil {
		t.Logf("Failed to list devices: %v", err)
		return false
	}

	return len(devices) > 0
}

// RequireDevice skips the test if no FIDO2 device is available
func (tc *TestConfig) RequireDevice(t *testing.T) {
	t.Helper()

	if !tc.CheckDeviceAvailable(t) {
		t.Skip("FIDO2 device required but not available. Set FIDO2_DEVICE_PATH or CANOKEY_QEMU to virtual device socket path.")
	}
}

// WaitForDeviceWithTimeout waits for a FIDO2 device with custom timeout
func (tc *TestConfig) WaitForDeviceWithTimeout(t *testing.T, timeout time.Duration) *fido2.Device {
	t.Helper()

	handler := tc.CreateHandler(t)
	defer handler.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	if err != nil {
		t.Skipf("Failed to wait for FIDO2 device: %v. Set FIDO2_DEVICE_PATH or CANOKEY_QEMU.", err)
	}

	require.NotNil(t, device)
	return device
}

// EnrollTestCredential enrolls a test credential for integration testing
func (tc *TestConfig) EnrollTestCredential(t *testing.T, username string) (*fido2.EnrollmentResult, *fido2.FIDO2Handler) {
	t.Helper()

	handler := tc.CreateHandler(t)

	// Create enrollment config
	enrollConfig := fido2.DefaultEnrollmentConfig(username)
	enrollConfig.RelyingParty.ID = "go-keychain-test"
	enrollConfig.RelyingParty.Name = "Go Keychain Integration Tests"
	enrollConfig.User.DisplayName = fmt.Sprintf("Test User %s", username)
	enrollConfig.Timeout = tc.Timeout

	if tc.PIN != "" {
		enrollConfig.RequireUserVerification = true
	}

	t.Logf("Enrolling credential for user: %s (please touch your security key)", username)

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err, "Failed to enroll credential")
	require.NotNil(t, result)
	require.NotEmpty(t, result.CredentialID, "Credential ID should not be empty")
	require.NotEmpty(t, result.Salt, "Salt should not be empty")

	t.Logf("Credential enrolled successfully: ID length=%d, Salt length=%d",
		len(result.CredentialID), len(result.Salt))

	return result, handler
}

// AuthenticateWithCredential authenticates using a previously enrolled credential
func (tc *TestConfig) AuthenticateWithCredential(t *testing.T, handler *fido2.FIDO2Handler, enrollment *fido2.EnrollmentResult) []byte {
	t.Helper()

	// Create authentication config
	authConfig := fido2.DefaultAuthenticationConfig(enrollment.CredentialID, enrollment.Salt)
	authConfig.RelyingPartyID = enrollment.RelyingParty.ID
	authConfig.Timeout = tc.Timeout

	if tc.PIN != "" {
		authConfig.RequireUserVerification = true
	}

	t.Logf("Authenticating (please touch your security key)")

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err, "Authentication failed")
	require.NotEmpty(t, derivedKey, "Derived key should not be empty")
	require.Equal(t, 32, len(derivedKey), "Derived key should be 32 bytes")

	t.Logf("Authentication successful: derived key length=%d", len(derivedKey))

	return derivedKey
}

// GenerateUniqueUsername generates a unique username for testing
func GenerateUniqueUsername(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// CleanupCredential is a helper for cleanup in defer statements
func CleanupCredential(t *testing.T, handler *fido2.FIDO2Handler) {
	t.Helper()
	if handler != nil {
		if err := handler.Close(); err != nil {
			t.Logf("Warning: failed to close handler: %v", err)
		}
	}
}

// AssertDeviceInfo asserts device info fields are properly populated
func AssertDeviceInfo(t *testing.T, device *fido2.Device) {
	t.Helper()

	require.NotEmpty(t, device.Path, "Device path should not be empty")
	require.NotZero(t, device.VendorID, "Vendor ID should not be zero")
	require.NotZero(t, device.ProductID, "Product ID should not be zero")
	require.NotEmpty(t, device.Transport, "Transport should not be empty")

	t.Logf("Device info validated: %s (VID=%04x PID=%04x)",
		device.Product, device.VendorID, device.ProductID)
}

// AssertEnrollmentResult asserts enrollment result fields are properly populated
func AssertEnrollmentResult(t *testing.T, result *fido2.EnrollmentResult) {
	t.Helper()

	require.NotEmpty(t, result.CredentialID, "Credential ID should not be empty")
	require.NotEmpty(t, result.PublicKey, "Public key should not be empty")
	require.NotEmpty(t, result.Salt, "Salt should not be empty")
	require.NotEmpty(t, result.User.Name, "User name should not be empty")
	require.NotEmpty(t, result.RelyingParty.ID, "Relying party ID should not be empty")
	require.False(t, result.Created.IsZero(), "Created timestamp should be set")

	t.Logf("Enrollment result validated: credID=%d bytes, pubKey=%d bytes, salt=%d bytes",
		len(result.CredentialID), len(result.PublicKey), len(result.Salt))
}

// IsCanoKeyQEMU returns true if using CanoKey QEMU virtual device
func (tc *TestConfig) IsCanoKeyQEMU() bool {
	return tc.CanoKeyQEMU != ""
}

// GetDefaultRelyingParty returns default relying party for tests
func GetDefaultRelyingParty() fido2.RelyingParty {
	return fido2.RelyingParty{
		ID:   "go-keychain-test",
		Name: "Go Keychain Integration Tests",
	}
}

// GetDefaultUser returns default user for tests
func GetDefaultUser(username string) fido2.User {
	return fido2.User{
		Name:        username,
		DisplayName: fmt.Sprintf("Test User %s", username),
	}
}
