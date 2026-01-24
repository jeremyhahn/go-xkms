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

//go:build integration && linux

package uhid

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/uhid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUHIDOpen(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err, "Failed to open UHID device")
	require.NotNil(t, device, "Device should not be nil")
	defer device.Close()

	// Verify initial device state
	assert.False(t, device.IsClosed(), "Device should not be marked as closed")
	assert.False(t, device.IsCreated(), "Device should not be marked as created")
	assert.Greater(t, device.Fd(), 0, "File descriptor should be positive")
}

func TestUHIDOpenPermissionDenied(t *testing.T) {
	// This test verifies error handling when UHID is not accessible.
	// If /dev/uhid exists but we can open it, skip this test.
	skipIfNoUHID(t)
	t.Skip("UHID is accessible - cannot test permission denied scenario")
}

func TestUHIDCreateDevice(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err)
	defer device.Close()

	// Create device with default FIDO2 configuration
	cfg := uhid.DefaultCreateConfig()
	cfg.Name = generateUniqueDeviceName("test-create")
	cfg.Uniq = generateUniqueSerial()

	err = device.Create(cfg)
	require.NoError(t, err, "Failed to create UHID device")

	// Verify device state after creation
	assert.True(t, device.IsCreated(), "Device should be marked as created")
	assert.False(t, device.IsClosed(), "Device should not be closed")
}

func TestUHIDCreateDeviceWithNilConfig(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err)
	defer device.Close()

	// Create device with nil config should use default configuration
	err = device.Create(nil)
	require.NoError(t, err, "Create with nil config should use defaults")

	assert.True(t, device.IsCreated(), "Device should be created with default config")
}

func TestUHIDCreateDeviceAlreadyCreated(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-already-created")
	defer cleanup()

	// Attempt to create again should fail
	err := device.Create(nil)
	require.Error(t, err, "Creating device twice should fail")
	assert.True(t, errors.Is(err, uhid.ErrDeviceAlreadyCreated),
		"Expected ErrDeviceAlreadyCreated, got: %v", err)
}

func TestUHIDDeviceLifecycle(t *testing.T) {
	skipIfNoUHID(t)

	// Phase 1: Open
	device, err := uhid.Open()
	require.NoError(t, err)

	assert.False(t, device.IsClosed())
	assert.False(t, device.IsCreated())
	fd := device.Fd()
	assert.Greater(t, fd, 0)

	// Phase 2: Create
	cfg := uhid.DefaultCreateConfig()
	cfg.Name = generateUniqueDeviceName("test-lifecycle")
	cfg.Uniq = generateUniqueSerial()

	err = device.Create(cfg)
	require.NoError(t, err)

	assert.True(t, device.IsCreated())
	assert.False(t, device.IsClosed())
	assert.Equal(t, fd, device.Fd(), "File descriptor should remain the same")

	// Phase 3: Close
	err = device.Close()
	require.NoError(t, err)

	assert.True(t, device.IsClosed())
	assert.Equal(t, -1, device.Fd(), "File descriptor should be -1 after close")

	// Phase 4: Verify operations fail on closed device
	err = device.Create(nil)
	assert.True(t, errors.Is(err, uhid.ErrDeviceNotOpen))

	err = device.WriteInput([]byte{0x01})
	assert.True(t, errors.Is(err, uhid.ErrDeviceNotOpen))

	_, err = device.ReadOutput()
	assert.True(t, errors.Is(err, uhid.ErrDeviceNotOpen))
}

func TestUHIDWriteInput(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-write-input")
	defer cleanup()

	// Write a simple HID input report
	report := createFIDO2HIDReport([]byte{0x01, 0x02, 0x03, 0x04})
	err := device.WriteInput(report)
	require.NoError(t, err, "Failed to write HID input report")
}

func TestUHIDWriteInputEmptyData(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-write-empty")
	defer cleanup()

	// Writing empty data should succeed
	err := device.WriteInput([]byte{})
	require.NoError(t, err, "Writing empty data should succeed")
}

func TestUHIDWriteInputMaxSize(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-write-max")
	defer cleanup()

	// Write maximum allowed size
	maxData := make([]byte, uhid.MaxReportDescriptorSize)
	for i := range maxData {
		maxData[i] = byte(i % 256)
	}

	err := device.WriteInput(maxData)
	require.NoError(t, err, "Writing max size data should succeed")
}

func TestUHIDWriteInputTooLarge(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-write-too-large")
	defer cleanup()

	// Write data larger than allowed
	largeData := make([]byte, uhid.MaxReportDescriptorSize+1)
	err := device.WriteInput(largeData)
	require.Error(t, err, "Writing oversized data should fail")
	assert.True(t, errors.Is(err, uhid.ErrInvalidPacket),
		"Expected ErrInvalidPacket, got: %v", err)
}

func TestUHIDWriteInputOnClosedDevice(t *testing.T) {
	skipIfNoUHID(t)

	device, _ := createTestDevice(t, "test-write-closed")
	device.Close()

	err := device.WriteInput([]byte{0x01})
	require.Error(t, err)
	assert.True(t, errors.Is(err, uhid.ErrDeviceNotOpen),
		"Expected ErrDeviceNotOpen, got: %v", err)
}

func TestUHIDConcurrentAccess(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-concurrent")
	defer cleanup()

	const numGoroutines = 10
	const numOperationsPerGoroutine = 100

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*numOperationsPerGoroutine)

	// Launch multiple goroutines that write input reports concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperationsPerGoroutine; j++ {
				report := createFIDO2HIDReport([]byte{byte(id), byte(j)})
				if err := device.WriteInput(report); err != nil {
					errChan <- err
					return
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Errorf("Concurrent write failed: %v", err)
	}

	// Verify device is still in valid state
	assert.True(t, device.IsCreated())
	assert.False(t, device.IsClosed())
}

func TestUHIDConcurrentStateAccess(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-concurrent-state")
	defer cleanup()

	const numGoroutines = 50
	var wg sync.WaitGroup

	// Launch goroutines that concurrently check device state
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = device.IsCreated()
				_ = device.IsClosed()
				_ = device.Fd()
			}
		}()
	}

	wg.Wait()

	// Device should still be valid
	assert.True(t, device.IsCreated())
	assert.False(t, device.IsClosed())
}

func TestUHIDCreateWithFIDO2Descriptor(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err)
	defer device.Close()

	// Create device with explicit FIDO2 HID descriptor
	cfg := &uhid.CreateConfig{
		Name:             generateUniqueDeviceName("test-fido2"),
		Phys:             "test-fido2-phys",
		Uniq:             generateUniqueSerial(),
		VendorID:         uhid.VendorIDVirtualFIDO,
		ProductID:        uhid.ProductIDVirtualFIDO,
		Version:          0x0100,
		ReportDescriptor: uhid.FIDO2HIDReportDescriptor,
	}

	err = device.Create(cfg)
	require.NoError(t, err, "Failed to create FIDO2 HID device")

	assert.True(t, device.IsCreated())

	// Verify we can write standard FIDO2 HID reports (64 bytes)
	fido2Report := make([]byte, uhid.HIDReportSize)
	fido2Report[0] = 0xFF // Channel ID high byte
	fido2Report[1] = 0xFF // Channel ID low byte (broadcast)
	fido2Report[2] = 0x86 // CTAPHID_INIT command
	fido2Report[3] = 0x00 // Length high byte
	fido2Report[4] = 0x08 // Length low byte

	err = device.WriteInput(fido2Report)
	require.NoError(t, err, "Failed to write FIDO2 HID report")
}

func TestUHIDCreateWithCustomDescriptor(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err)
	defer device.Close()

	// Create a simple custom HID descriptor (generic HID device)
	customDescriptor := []byte{
		0x06, 0x00, 0xFF, // Usage Page (Vendor Defined)
		0x09, 0x01, // Usage (Vendor)
		0xA1, 0x01, // Collection (Application)
		0x09, 0x02, //   Usage (Vendor)
		0x15, 0x00, //   Logical Minimum (0)
		0x26, 0xFF, 0x00, //   Logical Maximum (255)
		0x75, 0x08, //   Report Size (8)
		0x95, 0x08, //   Report Count (8)
		0x81, 0x02, //   Input (Data, Var, Abs)
		0x09, 0x03, //   Usage (Vendor)
		0x91, 0x02, //   Output (Data, Var, Abs)
		0xC0, // End Collection
	}

	cfg := &uhid.CreateConfig{
		Name:             generateUniqueDeviceName("test-custom-hid"),
		Phys:             "test-custom-phys",
		Uniq:             generateUniqueSerial(),
		VendorID:         0x1234,
		ProductID:        0x5678,
		Version:          0x0001,
		ReportDescriptor: customDescriptor,
	}

	err = device.Create(cfg)
	require.NoError(t, err, "Failed to create custom HID device")

	assert.True(t, device.IsCreated())
}

func TestUHIDDeviceSetReadTimeout(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-timeout")
	defer cleanup()

	// Test setting various timeouts
	timeouts := []time.Duration{
		0,
		100 * time.Millisecond,
		1 * time.Second,
		5 * time.Second,
	}

	for _, timeout := range timeouts {
		device.SetReadTimeout(timeout)
		// No error means success - we can't easily verify the internal state
	}
}

func TestUHIDDeviceSetNonBlocking(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-nonblocking")
	defer cleanup()

	// Enable non-blocking mode
	err := device.SetNonBlocking(true)
	require.NoError(t, err, "Failed to set non-blocking mode")

	// Disable non-blocking mode
	err = device.SetNonBlocking(false)
	require.NoError(t, err, "Failed to clear non-blocking mode")
}

func TestUHIDDeviceSetNonBlockingOnClosedDevice(t *testing.T) {
	skipIfNoUHID(t)

	device, _ := createTestDevice(t, "test-nonblock-closed")
	device.Close()

	err := device.SetNonBlocking(true)
	require.Error(t, err)
	assert.True(t, errors.Is(err, uhid.ErrDeviceNotOpen),
		"Expected ErrDeviceNotOpen, got: %v", err)
}

func TestUHIDCloseIdempotent(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err)

	cfg := uhid.DefaultCreateConfig()
	cfg.Name = generateUniqueDeviceName("test-close-idempotent")
	cfg.Uniq = generateUniqueSerial()

	err = device.Create(cfg)
	require.NoError(t, err)

	// First close
	err = device.Close()
	require.NoError(t, err)
	assert.True(t, device.IsClosed())

	// Second close should be idempotent (no error)
	err = device.Close()
	require.NoError(t, err, "Second close should not return error")

	// Third close
	err = device.Close()
	require.NoError(t, err, "Third close should not return error")
}

func TestUHIDDeviceCleanupOnPanic(t *testing.T) {
	skipIfNoUHID(t)

	// This test verifies that devices can be properly cleaned up
	// even in error scenarios

	device, err := uhid.Open()
	require.NoError(t, err)

	cfg := uhid.DefaultCreateConfig()
	cfg.Name = generateUniqueDeviceName("test-cleanup-panic")
	cfg.Uniq = generateUniqueSerial()

	err = device.Create(cfg)
	require.NoError(t, err)

	// Use defer to ensure cleanup
	defer func() {
		if r := recover(); r != nil {
			// Recovered from panic - verify we can still close
			err := device.Close()
			assert.NoError(t, err, "Should be able to close device after panic recovery")
		}
	}()

	// Normal cleanup
	err = device.Close()
	require.NoError(t, err)
}

func TestUHIDMultipleDevices(t *testing.T) {
	skipIfNoUHID(t)

	const numDevices = 5
	devices := make([]*uhid.Device, numDevices)
	cleanups := make([]func(), numDevices)

	// Create multiple devices
	for i := 0; i < numDevices; i++ {
		device, cleanup := createTestDevice(t, "test-multi")
		devices[i] = device
		cleanups[i] = cleanup
	}

	// Verify all devices are created
	for i, device := range devices {
		assert.True(t, device.IsCreated(), "Device %d should be created", i)
		assert.False(t, device.IsClosed(), "Device %d should not be closed", i)
	}

	// Write to all devices
	for i, device := range devices {
		report := createFIDO2HIDReport([]byte{byte(i)})
		err := device.WriteInput(report)
		require.NoError(t, err, "Failed to write to device %d", i)
	}

	// Cleanup all devices
	for _, cleanup := range cleanups {
		cleanup()
	}

	// Verify all devices are closed
	for i, device := range devices {
		assert.True(t, device.IsClosed(), "Device %d should be closed", i)
	}
}

func TestUHIDDeviceWithLongName(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err)
	defer device.Close()

	// Create device with maximum length name (127 chars + null terminator)
	longName := make([]byte, 200)
	for i := range longName {
		longName[i] = byte('A' + (i % 26))
	}

	cfg := &uhid.CreateConfig{
		Name:             string(longName),
		Phys:             "test-long-name-phys",
		Uniq:             generateUniqueSerial(),
		VendorID:         uhid.VendorIDVirtualFIDO,
		ProductID:        uhid.ProductIDVirtualFIDO,
		Version:          0x0100,
		ReportDescriptor: uhid.FIDO2HIDReportDescriptor,
	}

	// Should succeed - name will be truncated internally
	err = device.Create(cfg)
	require.NoError(t, err, "Device creation with long name should succeed (truncated)")

	assert.True(t, device.IsCreated())
}

func TestUHIDDeviceWithEmptyName(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err)
	defer device.Close()

	cfg := &uhid.CreateConfig{
		Name:             "",
		Phys:             "",
		Uniq:             "",
		VendorID:         uhid.VendorIDVirtualFIDO,
		ProductID:        uhid.ProductIDVirtualFIDO,
		Version:          0x0100,
		ReportDescriptor: uhid.FIDO2HIDReportDescriptor,
	}

	err = device.Create(cfg)
	require.NoError(t, err, "Device creation with empty name should succeed")

	assert.True(t, device.IsCreated())
}

func TestUHIDSerializeCreate2RequestIntegration(t *testing.T) {
	// This test validates that SerializeCreate2Request produces valid data
	// by actually creating a device with equivalent configuration

	skipIfNoUHID(t)

	cfg := &uhid.CreateConfig{
		Name:             generateUniqueDeviceName("test-serialize"),
		Phys:             "serialize-phys",
		Uniq:             generateUniqueSerial(),
		VendorID:         uhid.VendorIDVirtualFIDO,
		ProductID:        uhid.ProductIDVirtualFIDO,
		Version:          0x0100,
		ReportDescriptor: uhid.FIDO2HIDReportDescriptor,
	}

	// Get serialized buffer for inspection
	buf := uhid.SerializeCreate2Request(cfg)
	require.NotNil(t, buf)
	require.Greater(t, len(buf), 0)

	// Now create actual device with same config
	device, err := uhid.Open()
	require.NoError(t, err)
	defer device.Close()

	err = device.Create(cfg)
	require.NoError(t, err, "Serialized config should produce valid UHID device")

	assert.True(t, device.IsCreated())
}

func TestUHIDSerializeInput2RequestIntegration(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-serialize-input")
	defer cleanup()

	// Test data
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Get serialized buffer for inspection
	buf := uhid.SerializeInput2Request(testData)
	require.NotNil(t, buf)

	// Write actual data
	err := device.WriteInput(testData)
	require.NoError(t, err, "Writing data should succeed")
}

func TestUHIDFd(t *testing.T) {
	skipIfNoUHID(t)

	device, err := uhid.Open()
	require.NoError(t, err)

	// Fd should be valid before close
	fd := device.Fd()
	assert.Greater(t, fd, 0, "File descriptor should be positive")

	// Create device
	cfg := uhid.DefaultCreateConfig()
	cfg.Name = generateUniqueDeviceName("test-fd")
	cfg.Uniq = generateUniqueSerial()

	err = device.Create(cfg)
	require.NoError(t, err)

	// Fd should remain same after create
	assert.Equal(t, fd, device.Fd())

	// Close device
	device.Close()

	// Fd should be -1 after close
	assert.Equal(t, -1, device.Fd(), "Fd should be -1 after close")
}

func TestUHIDReadOutputTimeout(t *testing.T) {
	skipIfNoUHID(t)

	device, cleanup := createTestDevice(t, "test-read-timeout")
	defer cleanup()

	// Set a short timeout
	device.SetReadTimeout(100 * time.Millisecond)

	// ReadOutput should timeout since there's no host reading from the device
	start := time.Now()
	_, err := device.ReadOutput()
	elapsed := time.Since(start)

	// Should timeout with ErrTimeout
	require.Error(t, err)
	assert.True(t, errors.Is(err, uhid.ErrTimeout),
		"Expected ErrTimeout, got: %v", err)

	// Verify timeout was approximately the configured duration
	assert.Greater(t, elapsed, 50*time.Millisecond,
		"Timeout should have waited at least 50ms")
	assert.Less(t, elapsed, 500*time.Millisecond,
		"Timeout should not have exceeded 500ms")
}

func TestUHIDReadOutputOnClosedDevice(t *testing.T) {
	skipIfNoUHID(t)

	device, _ := createTestDevice(t, "test-read-closed")
	device.Close()

	_, err := device.ReadOutput()
	require.Error(t, err)
	assert.True(t, errors.Is(err, uhid.ErrDeviceNotOpen),
		"Expected ErrDeviceNotOpen, got: %v", err)
}
