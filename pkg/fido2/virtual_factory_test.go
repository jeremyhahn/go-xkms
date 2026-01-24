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

	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDefaultVirtualDevice(t *testing.T) {
	device, err := CreateDefaultVirtualDevice()
	require.NoError(t, err)
	require.NotNil(t, device)
	defer func() { _ = device.Close() }()

	// Verify device properties
	assert.Equal(t, "VFIDO-CLI-001", device.SerialNumber())
	assert.Equal(t, "go-keychain", device.Manufacturer())
	assert.Equal(t, "VirtualFIDO CLI", device.Product())
	assert.Equal(t, uint16(VirtualFIDOVendorID), device.VendorID())
	assert.Equal(t, uint16(VirtualFIDOProductID), device.ProductID())
	assert.Equal(t, VirtualFIDOPathPrefix+"VFIDO-CLI-001", device.Path())
}

func TestCreateVirtualDeviceWithSerial(t *testing.T) {
	device, err := CreateVirtualDeviceWithSerial("TEST-SERIAL-123")
	require.NoError(t, err)
	require.NotNil(t, device)
	defer func() { _ = device.Close() }()

	// Verify device properties
	assert.Equal(t, "TEST-SERIAL-123", device.SerialNumber())
	assert.Equal(t, VirtualFIDOPathPrefix+"TEST-SERIAL-123", device.Path())
	assert.NotNil(t, device.FIDOClient())
}

func TestGetVirtualEnumerator(t *testing.T) {
	// Reset the global enumerator for testing
	virtualDeviceMu.Lock()
	globalNativeVirtualEnumerator = nil
	virtualDeviceMu.Unlock()

	enumerator, err := GetVirtualEnumerator()
	require.NoError(t, err)
	require.NotNil(t, enumerator)

	// Verify device is registered
	devices, err := enumerator.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Verify it's the expected device (now uses native virtual device with native-fido:// prefix)
	assert.Equal(t, NativeVirtualDevicePathPrefix+"VFIDO-CLI-001", devices[0].Path())

	// Calling again should return the same enumerator (singleton)
	enumerator2, err := GetVirtualEnumerator()
	require.NoError(t, err)
	assert.Same(t, enumerator, enumerator2)
}

func TestInMemoryDataSaver(t *testing.T) {
	saver := &inMemoryDataSaver{}

	// Test initial state
	data := saver.RetrieveData()
	assert.Nil(t, data)

	// Test passphrase
	assert.Equal(t, "", saver.Passphrase())

	// Test save and retrieve
	testData := []byte("test data 12345")
	saver.SaveData(testData)

	retrieved := saver.RetrieveData()
	assert.Equal(t, testData, retrieved)

	// Test that modifications to retrieved data don't affect stored data
	retrieved[0] = 'X'
	retrieved2 := saver.RetrieveData()
	assert.Equal(t, testData, retrieved2)
}

func TestAutoApprover(t *testing.T) {
	approver := &autoApprover{}

	// Test that it always approves with different action types
	params := fido_client.ClientActionRequestParams{
		RelyingParty: "test-rp",
		UserName:     "test-user",
	}
	result := approver.ApproveClientAction(fido_client.ClientActionFIDOMakeCredential, params)
	assert.True(t, result)

	result = approver.ApproveClientAction(fido_client.ClientActionFIDOGetAssertion, params)
	assert.True(t, result)
}
