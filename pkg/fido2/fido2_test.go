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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandler(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)
	require.NotNil(t, handler)

	assert.Equal(t, &config, handler.config)
	assert.Equal(t, enum, handler.enumerator)
}

func TestNewHandler_NilConfig(t *testing.T) {
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(nil, enum)
	require.NoError(t, err)
	require.NotNil(t, handler)

	// Should use default config
	assert.NotNil(t, handler.config)
	assert.Equal(t, "go-keychain", handler.config.RelyingPartyID)
}

func TestNewHandler_NilEnumerator(t *testing.T) {
	config := DefaultConfig

	handler, err := NewHandler(&config, nil)
	assert.Error(t, err)
	assert.Nil(t, handler)
}

func TestHandler_ListDevices(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Initially no devices
	devices, err := handler.ListDevices()
	require.NoError(t, err)
	assert.Empty(t, devices)

	// Add a device
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	devices, err = handler.ListDevices()
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, "/dev/hidraw0", devices[0].Path)

	// Add another device
	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	enum.AddDevice(mockDev2)

	devices, err = handler.ListDevices()
	require.NoError(t, err)
	assert.Len(t, devices, 2)
}

func TestHandler_WaitForDevice(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Add device after a delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		mockDev := NewMockHIDDevice("/dev/hidraw0")
		enum.AddDevice(mockDev)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, "/dev/hidraw0", device.Path)
}

func TestHandler_WaitForDevice_Timeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	assert.Error(t, err)
	assert.Nil(t, device)
}

func TestHandler_EnrollKey(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.CredentialID)
	assert.NotEmpty(t, result.Salt)
	assert.Equal(t, "testuser", result.User.Name)
	assert.False(t, result.Created.IsZero())
}

func TestHandler_EnrollKey_NoDevice(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	result, err := handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

func TestHandler_EnrollKey_NoHMACSecretSupport(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	// Create a mock device that doesn't support hmac-secret
	// We'll need to intercept GetInfo response
	_, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Create custom CTAP device
	device, _ := enum.Open("/dev/hidraw0")
	ctapDev, _ := NewCTAPHIDDevice(device, &config)

	// Create an authenticator without hmac-secret support
	auth := &Authenticator{
		device: ctapDev,
		config: &config,
		info: &DeviceInfo{
			Extensions: []string{}, // No hmac-secret
		},
	}

	// Test that NewHMACSecretExtension fails
	_, err = NewHMACSecretExtension(auth)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedExtension)
}

func TestHandler_UnlockWithKey(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	credID := make([]byte, 32)
	salt := make([]byte, 32)

	authConfig := DefaultAuthenticationConfig(credID, salt)

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)

	assert.Equal(t, 64, len(derivedKey), "Derived key should be 512 bits")
}

func TestHandler_UnlockWithKey_NoDevice(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	derivedKey, err := handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Nil(t, derivedKey)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

func TestHandler_SelectDevice_SpecificPath(t *testing.T) {
	config := DefaultConfig
	config.DevicePath = "/dev/hidraw1"
	enum := NewMockHIDDeviceEnumerator()

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, "/dev/hidraw1", device.Path())
}

func TestHandler_SelectDevice_WithVendorFilter(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0xABCD}
	enum := NewMockHIDDeviceEnumerator()

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev1.vendorID = 0x1234

	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev2.vendorID = 0xABCD

	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, uint16(0xABCD), device.VendorID())
}

func TestHandler_SelectDevice_WithProductFilter(t *testing.T) {
	config := DefaultConfig
	config.AllowedProducts = []uint16{0x9999}
	enum := NewMockHIDDeviceEnumerator()

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev1.productID = 0x5678

	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev2.productID = 0x9999

	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, uint16(0x9999), device.ProductID())
}

func TestHandler_SelectDevice_NoMatchingDevice(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0xFFFF}
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.vendorID = 0x1234
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

func TestHandler_Close(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	err = handler.Close()
	assert.NoError(t, err)
}

func TestHandler_FullFlow(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)
	defer func() { _ = handler.Close() }()

	// Step 1: Enroll
	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollResult, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, enrollResult)

	// Step 2: Unlock using enrolled credential
	authConfig := DefaultAuthenticationConfig(
		enrollResult.CredentialID,
		enrollResult.Salt,
	)

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)

	assert.Equal(t, 64, len(derivedKey))

	// Verify deterministic unlock
	derivedKey2, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	assert.Equal(t, derivedKey, derivedKey2)
}

func TestHandler_EnrollKey_WithCustomTimeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Timeout = 5 * time.Second

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestHandler_UnlockWithKey_WithRetry(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 2
	config.RetryDelay = 10 * time.Millisecond

	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	credID := make([]byte, 32)
	salt := make([]byte, 32)

	authConfig := DefaultAuthenticationConfig(credID, salt)

	// Mock will succeed on first attempt
	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)
}

func TestHandler_IsFIDO2Device(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	mockDev := NewMockHIDDevice("/dev/hidraw0")

	// Current implementation accepts all devices
	assert.True(t, handler.isFIDO2Device(mockDev))
}

func TestDefaultEnrollmentConfig(t *testing.T) {
	config := DefaultEnrollmentConfig("alice")

	assert.Equal(t, "go-keychain", config.RelyingParty.ID)
	assert.Equal(t, "Go Keychain", config.RelyingParty.Name)
	assert.Equal(t, "alice", config.User.Name)
	assert.Equal(t, "alice", config.User.DisplayName)
	assert.False(t, config.RequireUserVerification)
	assert.Equal(t, DefaultUserPresenceTimeout, config.Timeout)
}

func TestDefaultAuthenticationConfig(t *testing.T) {
	credID := []byte("test-cred-id")
	salt := []byte("test-salt")

	config := DefaultAuthenticationConfig(credID, salt)

	assert.Equal(t, "go-keychain", config.RelyingPartyID)
	assert.Equal(t, credID, config.CredentialID)
	assert.Equal(t, salt, config.Salt)
	assert.False(t, config.RequireUserVerification)
	assert.Equal(t, DefaultUserPresenceTimeout, config.Timeout)
}

func TestHandler_MultipleDevices(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	// Add multiple devices
	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev3 := NewMockHIDDevice("/dev/hidraw2")

	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)
	enum.AddDevice(mockDev3)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	devices, err := handler.ListDevices()
	require.NoError(t, err)
	assert.Len(t, devices, 3)

	// Verify all devices are listed
	paths := make(map[string]bool)
	for _, dev := range devices {
		paths[dev.Path] = true
	}

	assert.True(t, paths["/dev/hidraw0"])
	assert.True(t, paths["/dev/hidraw1"])
	assert.True(t, paths["/dev/hidraw2"])
}

func TestNewHandlerWithLogger(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	// Test with nil logger
	handler, err := NewHandlerWithLogger(&config, enum, nil)
	require.NoError(t, err)
	require.NotNil(t, handler)

	// Test with custom logger
	mockLogger := &MockLogger{}
	handler2, err := NewHandlerWithLogger(&config, enum, mockLogger)
	require.NoError(t, err)
	require.NotNil(t, handler2)
	assert.Equal(t, mockLogger, handler2.logger)
}

func TestNewHandlerWithLogger_NilEnumerator(t *testing.T) {
	config := DefaultConfig

	_, err := NewHandlerWithLogger(&config, nil, nil)
	assert.Error(t, err)
}

func TestNewHandler_InvalidConfig(t *testing.T) {
	// Even an invalid config should be corrected by Validate()
	config := Config{
		Timeout:    -1,
		RetryCount: -5,
		RetryDelay: -10,
	}
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)
	require.NotNil(t, handler)

	// Values should be corrected
	assert.Greater(t, handler.config.Timeout, time.Duration(0))
	assert.GreaterOrEqual(t, handler.config.RetryCount, 0)
}

// MockLogger for testing
type MockLogger struct {
	messages []string
}

func (m *MockLogger) Printf(format string, v ...interface{}) {
	m.messages = append(m.messages, fmt.Sprintf(format, v...))
}

func TestHandler_EnrollKey_WithTimeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Timeout = 100 * time.Millisecond

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestHandler_UnlockWithKey_WithTimeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))
	authConfig.Timeout = 100 * time.Millisecond

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)
}

func TestHandler_SelectDevice_InvalidPath(t *testing.T) {
	config := DefaultConfig
	config.DevicePath = "/dev/nonexistent"
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	_, err = handler.selectDevice()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open")
}

func TestDiscardLogger(t *testing.T) {
	logger := &discardLogger{}
	// Should not panic
	logger.Printf("test %s", "message")
}

func TestHandler_WaitForDevice_CancelledContext(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	device, err := handler.WaitForDevice(ctx)
	assert.Error(t, err)
	assert.Nil(t, device)
}

func TestHandler_ListDevices_EnumerateError(t *testing.T) {
	config := DefaultConfig

	// Create a mock enumerator that returns errors
	enum := &MockErrorEnumerator{}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	devices, err := handler.ListDevices()
	assert.Error(t, err)
	assert.Nil(t, devices)
	assert.Contains(t, err.Error(), "failed to enumerate devices")
}

func TestHandler_SelectDevice_EnumerateError(t *testing.T) {
	config := DefaultConfig

	// Create a mock enumerator that returns errors
	enum := &MockErrorEnumerator{}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to enumerate devices")
}

// MockErrorEnumerator always returns errors
type MockErrorEnumerator struct{}

func (e *MockErrorEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return nil, fmt.Errorf("enumerate error")
}

func (e *MockErrorEnumerator) Open(path string) (HIDDevice, error) {
	return nil, fmt.Errorf("open error")
}

func TestHandler_SelectDevice_AllFilteredOut(t *testing.T) {
	config := DefaultConfig
	config.AllowedProducts = []uint16{0xFFFF}
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.productID = 0x1234
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

func TestDiscardLogger_Printf(t *testing.T) {
	logger := &discardLogger{}
	// Should not panic and do nothing
	logger.Printf("test message %s %d", "hello", 42)
}

func TestHandler_EnrollKey_LoggerOutput(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	mockLogger := &MockLogger{}
	handler, err := NewHandlerWithLogger(&config, enum, mockLogger)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify logger was called
	assert.NotEmpty(t, mockLogger.messages)
	assert.Contains(t, mockLogger.messages[0], "Please touch")
}

func TestHandler_UnlockWithKey_LoggerOutput(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 1
	config.RetryDelay = 10 * time.Millisecond
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	mockLogger := &MockLogger{}
	handler, err := NewHandlerWithLogger(&config, enum, mockLogger)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)

	// Verify logger was called
	assert.NotEmpty(t, mockLogger.messages)
}

func TestHandler_SelectDevice_FilterBothVendorAndProduct(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0xABCD}
	config.AllowedProducts = []uint16{0x9999}
	enum := NewMockHIDDeviceEnumerator()

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev1.vendorID = 0x1234
	mockDev1.productID = 0x5678

	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev2.vendorID = 0xABCD
	mockDev2.productID = 0x8888

	mockDev3 := NewMockHIDDevice("/dev/hidraw2")
	mockDev3.vendorID = 0xABCD
	mockDev3.productID = 0x9999

	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)
	enum.AddDevice(mockDev3)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, uint16(0xABCD), device.VendorID())
	assert.Equal(t, uint16(0x9999), device.ProductID())
}
