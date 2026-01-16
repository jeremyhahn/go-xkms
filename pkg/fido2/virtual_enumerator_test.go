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

//go:build linux

package fido2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVirtualDeviceEnumerator(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()
	require.NotNil(t, enum)
	assert.NotNil(t, enum.devices)
	assert.Equal(t, 0, enum.DeviceCount())
}

func TestVirtualDeviceEnumerator_RegisterDevice_Success(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum.RegisterDevice(device)
	require.NoError(t, err)
	assert.Equal(t, 1, enum.DeviceCount())
}

func TestVirtualDeviceEnumerator_RegisterDevice_NilDevice(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	err := enum.RegisterDevice(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device is nil")
}

func TestVirtualDeviceEnumerator_RegisterDevice_Duplicate(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum.RegisterDevice(device)
	require.NoError(t, err)

	// Register same device again
	err = enum.RegisterDevice(device)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestVirtualDeviceEnumerator_UnregisterDevice_Success(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum.RegisterDevice(device)
	require.NoError(t, err)
	assert.Equal(t, 1, enum.DeviceCount())

	err = enum.UnregisterDevice(device.Path())
	require.NoError(t, err)
	assert.Equal(t, 0, enum.DeviceCount())
}

func TestVirtualDeviceEnumerator_UnregisterDevice_NotFound(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	err := enum.UnregisterDevice("virtualfido://nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestVirtualDeviceEnumerator_Enumerate_All(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device1, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device1.Close() }()

	device2, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST002",
	})
	require.NoError(t, err)
	defer func() { _ = device2.Close() }()

	err = enum.RegisterDevice(device1)
	require.NoError(t, err)
	err = enum.RegisterDevice(device2)
	require.NoError(t, err)

	// Enumerate all (vendorID=0, productID=0)
	devices, err := enum.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 2)
}

func TestVirtualDeviceEnumerator_Enumerate_ByVendorID(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum.RegisterDevice(device)
	require.NoError(t, err)

	// Filter by VirtualFIDO vendor ID
	devices, err := enum.Enumerate(VirtualFIDOVendorID, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Filter by different vendor ID (should return none)
	devices, err = enum.Enumerate(0x1234, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 0)
}

func TestVirtualDeviceEnumerator_Enumerate_ByProductID(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum.RegisterDevice(device)
	require.NoError(t, err)

	// Filter by VirtualFIDO product ID
	devices, err := enum.Enumerate(0, VirtualFIDOProductID)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Filter by different product ID (should return none)
	devices, err = enum.Enumerate(0, 0x9999)
	require.NoError(t, err)
	assert.Len(t, devices, 0)
}

func TestVirtualDeviceEnumerator_Enumerate_ByBothIDs(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum.RegisterDevice(device)
	require.NoError(t, err)

	// Filter by both IDs
	devices, err := enum.Enumerate(VirtualFIDOVendorID, VirtualFIDOProductID)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Filter with wrong vendor (should return none)
	devices, err = enum.Enumerate(0x1234, VirtualFIDOProductID)
	require.NoError(t, err)
	assert.Len(t, devices, 0)
}

func TestVirtualDeviceEnumerator_Open_VirtualPath(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum.RegisterDevice(device)
	require.NoError(t, err)

	// Open by virtual path
	opened, err := enum.Open(VirtualFIDOPathPrefix + "TEST001")
	require.NoError(t, err)
	assert.Equal(t, device, opened)
}

func TestVirtualDeviceEnumerator_Open_NotFound(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := enum.Open(VirtualFIDOPathPrefix + "NONEXISTENT")
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "not found")
}

func TestVirtualDeviceEnumerator_Open_RegularPath(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum.RegisterDevice(device)
	require.NoError(t, err)

	// Try to open with regular path (matches device path)
	opened, err := enum.Open(device.Path())
	require.NoError(t, err)
	assert.Equal(t, device, opened)
}

func TestVirtualDeviceEnumerator_Open_RegularPathNotFound(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device, err := enum.Open("/dev/hidraw99")
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "not found")
}

func TestVirtualDeviceEnumerator_Close(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	device1, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)

	device2, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST002",
	})
	require.NoError(t, err)

	err = enum.RegisterDevice(device1)
	require.NoError(t, err)
	err = enum.RegisterDevice(device2)
	require.NoError(t, err)

	assert.Equal(t, 2, enum.DeviceCount())

	err = enum.Close()
	require.NoError(t, err)
	assert.Equal(t, 0, enum.DeviceCount())
}

func TestVirtualDeviceEnumerator_ImplementsInterface(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()
	var _ HIDDeviceEnumerator = enum
}

// Tests for CombinedEnumerator

func TestNewCombinedEnumerator(t *testing.T) {
	enum1 := NewVirtualDeviceEnumerator()
	enum2 := NewVirtualDeviceEnumerator()

	combined := NewCombinedEnumerator(enum1, enum2)
	require.NotNil(t, combined)
	assert.Len(t, combined.enumerators, 2)
}

func TestCombinedEnumerator_Enumerate_MultipleEnumerators(t *testing.T) {
	enum1 := NewVirtualDeviceEnumerator()
	enum2 := NewVirtualDeviceEnumerator()

	device1, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "ENUM1_DEV1",
	})
	require.NoError(t, err)
	defer func() { _ = device1.Close() }()

	device2, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "ENUM2_DEV1",
	})
	require.NoError(t, err)
	defer func() { _ = device2.Close() }()

	err = enum1.RegisterDevice(device1)
	require.NoError(t, err)
	err = enum2.RegisterDevice(device2)
	require.NoError(t, err)

	combined := NewCombinedEnumerator(enum1, enum2)

	// Should find devices from both enumerators
	devices, err := combined.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 2)
}

func TestCombinedEnumerator_Enumerate_WithError(t *testing.T) {
	// Create an error-returning enumerator
	errEnum := &MockErrorEnumerator{}
	goodEnum := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = goodEnum.RegisterDevice(device)
	require.NoError(t, err)

	combined := NewCombinedEnumerator(errEnum, goodEnum)

	// Should still return devices from good enumerator
	devices, err := combined.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 1)
}

func TestCombinedEnumerator_Open_FirstEnumerator(t *testing.T) {
	enum1 := NewVirtualDeviceEnumerator()
	enum2 := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	err = enum1.RegisterDevice(device)
	require.NoError(t, err)

	combined := NewCombinedEnumerator(enum1, enum2)

	opened, err := combined.Open(device.Path())
	require.NoError(t, err)
	assert.Equal(t, device, opened)
}

func TestCombinedEnumerator_Open_SecondEnumerator(t *testing.T) {
	enum1 := NewVirtualDeviceEnumerator()
	enum2 := NewVirtualDeviceEnumerator()

	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient:   NewMockFIDOClient(),
		SerialNumber: "TEST001",
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	// Add to second enumerator only
	err = enum2.RegisterDevice(device)
	require.NoError(t, err)

	combined := NewCombinedEnumerator(enum1, enum2)

	opened, err := combined.Open(device.Path())
	require.NoError(t, err)
	assert.Equal(t, device, opened)
}

func TestCombinedEnumerator_Open_NotFound(t *testing.T) {
	enum1 := NewVirtualDeviceEnumerator()
	enum2 := NewVirtualDeviceEnumerator()

	combined := NewCombinedEnumerator(enum1, enum2)

	device, err := combined.Open("virtualfido://NONEXISTENT")
	assert.Error(t, err)
	assert.Nil(t, device)
}

func TestCombinedEnumerator_Open_EmptyEnumerators(t *testing.T) {
	combined := NewCombinedEnumerator()

	device, err := combined.Open("virtualfido://TEST001")
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "not found")
}

func TestCombinedEnumerator_ImplementsInterface(t *testing.T) {
	combined := NewCombinedEnumerator()
	var _ HIDDeviceEnumerator = combined
}
