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
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/fido2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFIDO2ListDevices tests device enumeration
func TestFIDO2ListDevices(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	cfg.RequireDevice(t)

	handler := cfg.CreateHandler(t)
	defer handler.Close()

	t.Log("=== FIDO2 List Devices Test ===")

	devices, err := handler.ListDevices()
	require.NoError(t, err, "Failed to list FIDO2 devices")

	if len(devices) == 0 {
		t.Skip("No FIDO2 devices found. Set FIDO2_DEVICE_PATH or CANOKEY_QEMU to virtual device socket path.")
	}

	t.Logf("Found %d FIDO2 device(s)", len(devices))

	for i, device := range devices {
		t.Logf("Device %d:", i+1)
		t.Logf("  Path: %s", device.Path)
		t.Logf("  Vendor ID: 0x%04x", device.VendorID)
		t.Logf("  Product ID: 0x%04x", device.ProductID)
		t.Logf("  Manufacturer: %s", device.Manufacturer)
		t.Logf("  Product: %s", device.Product)
		t.Logf("  Serial: %s", device.SerialNumber)
		t.Logf("  Transport: %s", device.Transport)

		AssertDeviceInfo(t, &device)
	}

	assert.Greater(t, len(devices), 0, "Should find at least one FIDO2 device")
}

// TestFIDO2WaitForDevice tests waiting for device insertion
func TestFIDO2WaitForDevice(t *testing.T) {
	cfg := LoadFIDO2TestConfig()

	// Quick check if device is already available
	if !cfg.CheckDeviceAvailable(t) {
		t.Skip("No FIDO2 device available for wait test. Set FIDO2_DEVICE_PATH or CANOKEY_QEMU.")
	}

	handler := cfg.CreateHandler(t)
	defer handler.Close()

	t.Log("=== FIDO2 Wait For Device Test ===")

	// Use shorter timeout for testing
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	require.NoError(t, err, "Failed to wait for device")
	require.NotNil(t, device)

	t.Logf("Device detected: %s", device.Product)
	AssertDeviceInfo(t, device)
}

// TestFIDO2WaitForDeviceTimeout tests timeout behavior
func TestFIDO2WaitForDeviceTimeout(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	handler := cfg.CreateHandler(t)
	defer handler.Close()

	t.Log("=== FIDO2 Wait For Device Timeout Test ===")

	// Use very short timeout to force timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := handler.WaitForDevice(ctx)

	// We expect either timeout or success if device is present
	if err != nil {
		assert.ErrorIs(t, err, context.DeadlineExceeded, "Should timeout with context deadline exceeded")
		t.Log("Timeout behavior verified")
	} else {
		t.Log("Device was already present, timeout test skipped")
	}
}

// TestFIDO2EnrollmentFlow tests the complete enrollment flow
func TestFIDO2EnrollmentFlow(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	cfg.RequireDevice(t)

	t.Log("=== FIDO2 Enrollment Flow Test ===")

	username := GenerateUniqueUsername("test-enroll")
	result, handler := cfg.EnrollTestCredential(t, username)
	defer CleanupCredential(t, handler)

	// Validate enrollment result
	AssertEnrollmentResult(t, result)

	assert.Equal(t, username, result.User.Name, "Username should match")
	assert.Equal(t, "go-keychain-test", result.RelyingParty.ID, "RP ID should match")
	assert.NotEmpty(t, result.AAGUID, "AAGUID should be present")

	t.Logf("Enrollment successful for user: %s", username)
	t.Logf("  Credential ID: %d bytes", len(result.CredentialID))
	t.Logf("  Public Key: %d bytes", len(result.PublicKey))
	t.Logf("  Salt: %d bytes", len(result.Salt))
	t.Logf("  Sign Count: %d", result.SignCount)
}

// TestFIDO2AuthenticationFlow tests the complete authentication flow
func TestFIDO2AuthenticationFlow(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	cfg.RequireDevice(t)

	t.Log("=== FIDO2 Authentication Flow Test ===")

	// First enroll a credential
	username := GenerateUniqueUsername("test-auth")
	enrollment, handler := cfg.EnrollTestCredential(t, username)
	defer CleanupCredential(t, handler)

	t.Log("Credential enrolled, now testing authentication...")

	// Authenticate with the enrolled credential
	derivedKey := cfg.AuthenticateWithCredential(t, handler, enrollment)

	assert.Equal(t, 32, len(derivedKey), "Derived key should be 32 bytes")
	assert.NotEqual(t, make([]byte, 32), derivedKey, "Derived key should not be all zeros")

	t.Logf("Authentication successful, derived key: %d bytes", len(derivedKey))
}

// TestFIDO2RepeatedAuthentication tests multiple authentications with same credential
func TestFIDO2RepeatedAuthentication(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	cfg.RequireDevice(t)

	t.Log("=== FIDO2 Repeated Authentication Test ===")

	// Enroll credential
	username := GenerateUniqueUsername("test-repeat-auth")
	enrollment, handler := cfg.EnrollTestCredential(t, username)
	defer CleanupCredential(t, handler)

	// Perform multiple authentications
	numAttempts := 3
	var previousKey []byte

	for i := 0; i < numAttempts; i++ {
		t.Logf("Authentication attempt %d/%d", i+1, numAttempts)

		derivedKey := cfg.AuthenticateWithCredential(t, handler, enrollment)
		assert.Equal(t, 32, len(derivedKey), "Derived key should be 32 bytes")

		if i > 0 {
			// Derived key should be consistent across authentications
			assert.Equal(t, previousKey, derivedKey, "Derived key should be consistent")
		}

		previousKey = derivedKey
		t.Logf("  Attempt %d successful", i+1)

		// Small delay between attempts
		if i < numAttempts-1 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	t.Logf("All %d authentication attempts successful with consistent derived keys", numAttempts)
}

// TestFIDO2HandlerLifecycle tests handler creation and cleanup
func TestFIDO2HandlerLifecycle(t *testing.T) {
	cfg := LoadFIDO2TestConfig()

	t.Log("=== FIDO2 Handler Lifecycle Test ===")

	// Test handler creation
	handler := cfg.CreateHandler(t)
	require.NotNil(t, handler)

	// Test handler close
	err := handler.Close()
	assert.NoError(t, err, "Handler close should not error")

	// Test multiple close calls (should be safe)
	err = handler.Close()
	assert.NoError(t, err, "Multiple close calls should be safe")

	t.Log("Handler lifecycle validated")
}

// TestFIDO2InvalidCredential tests authentication with invalid credential
func TestFIDO2InvalidCredential(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	cfg.RequireDevice(t)

	t.Log("=== FIDO2 Invalid Credential Test ===")

	handler := cfg.CreateHandler(t)
	defer handler.Close()

	// Create authentication config with fake credential
	fakeCredID := []byte("fake-credential-id-that-does-not-exist")
	fakeSalt := []byte("fake-salt-value-for-testing-purposes")

	authConfig := fido2.DefaultAuthenticationConfig(fakeCredID, fakeSalt)
	authConfig.RelyingPartyID = "go-keychain-test"
	authConfig.Timeout = 5 * time.Second

	t.Log("Attempting authentication with invalid credential (should fail)...")

	_, err := handler.UnlockWithKey(authConfig)
	assert.Error(t, err, "Authentication with invalid credential should fail")

	t.Logf("Expected error received: %v", err)
}

// TestFIDO2DeviceInfo tests getting device information
func TestFIDO2DeviceInfo(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	cfg.RequireDevice(t)

	handler := cfg.CreateHandler(t)
	defer handler.Close()

	t.Log("=== FIDO2 Device Info Test ===")

	devices, err := handler.ListDevices()
	require.NoError(t, err)
	require.Greater(t, len(devices), 0, "At least one device should be available")

	device := devices[0]

	t.Log("Device Information:")
	t.Logf("  Path: %s", device.Path)
	t.Logf("  Vendor ID: 0x%04x", device.VendorID)
	t.Logf("  Product ID: 0x%04x", device.ProductID)
	t.Logf("  Manufacturer: %s", device.Manufacturer)
	t.Logf("  Product: %s", device.Product)
	t.Logf("  Serial Number: %s", device.SerialNumber)
	t.Logf("  Transport: %s", device.Transport)

	// Validate device info
	AssertDeviceInfo(t, &device)

	// Check for CanoKey QEMU virtual device
	if cfg.IsCanoKeyQEMU() {
		t.Log("Using CanoKey QEMU virtual device")
		assert.Contains(t, device.Path, "/dev/hidraw", "CanoKey QEMU should use hidraw device")
	}
}

// TestFIDO2EnrollmentWithUserVerification tests enrollment with PIN
func TestFIDO2EnrollmentWithUserVerification(t *testing.T) {
	cfg := LoadFIDO2TestConfig()

	// Skip if no PIN configured
	if cfg.PIN == "" {
		t.Skip("User verification test requires PIN. Set FIDO2_PIN environment variable.")
	}

	cfg.RequireDevice(t)

	t.Log("=== FIDO2 Enrollment With User Verification Test ===")

	handler := cfg.CreateHandler(t)
	defer handler.Close()

	username := GenerateUniqueUsername("test-uv-enroll")
	enrollConfig := fido2.DefaultEnrollmentConfig(username)
	enrollConfig.RelyingParty = GetDefaultRelyingParty()
	enrollConfig.User = GetDefaultUser(username)
	enrollConfig.RequireUserVerification = true
	enrollConfig.Timeout = cfg.Timeout

	t.Log("Enrolling with user verification (PIN required)...")

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err, "Enrollment with UV should succeed")
	require.NotNil(t, result)

	AssertEnrollmentResult(t, result)

	t.Log("Enrollment with user verification successful")
}

// TestFIDO2ConcurrentOperations tests concurrent device operations
func TestFIDO2ConcurrentOperations(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	cfg.RequireDevice(t)

	t.Log("=== FIDO2 Concurrent Operations Test ===")

	// Create multiple handlers
	handler1 := cfg.CreateHandler(t)
	defer handler1.Close()

	handler2 := cfg.CreateHandler(t)
	defer handler2.Close()

	// Both handlers should be able to list devices
	devices1, err1 := handler1.ListDevices()
	devices2, err2 := handler2.ListDevices()

	assert.NoError(t, err1, "Handler 1 should list devices")
	assert.NoError(t, err2, "Handler 2 should list devices")
	assert.Equal(t, len(devices1), len(devices2), "Both handlers should see same device count")

	t.Logf("Concurrent operations successful: both handlers see %d device(s)", len(devices1))
}

// TestFIDO2ErrorHandling tests various error conditions
func TestFIDO2ErrorHandling(t *testing.T) {
	t.Log("=== FIDO2 Error Handling Test ===")

	t.Run("InvalidConfig", func(t *testing.T) {
		// Test with nil config
		_, err := fido2.NewHandler(nil, fido2.NewDefaultEnumerator())
		assert.NoError(t, err, "Handler should accept nil config and use defaults")
	})

	t.Run("NilEnumerator", func(t *testing.T) {
		// Test with nil enumerator
		cfg := fido2.DefaultConfig
		_, err := fido2.NewHandler(&cfg, nil)
		assert.Error(t, err, "Handler should reject nil enumerator")
		assert.Contains(t, err.Error(), "enumerator", "Error should mention enumerator")
	})

	t.Run("EmptyCredentialID", func(t *testing.T) {
		cfg := LoadFIDO2TestConfig()
		cfg.RequireDevice(t)

		handler := cfg.CreateHandler(t)
		defer handler.Close()

		// Try to authenticate with empty credential ID
		authConfig := fido2.DefaultAuthenticationConfig([]byte{}, []byte("salt"))
		authConfig.RelyingPartyID = "go-keychain-test"

		_, err := handler.UnlockWithKey(authConfig)
		assert.Error(t, err, "Authentication with empty credential ID should fail")
	})

	t.Log("Error handling tests completed")
}
