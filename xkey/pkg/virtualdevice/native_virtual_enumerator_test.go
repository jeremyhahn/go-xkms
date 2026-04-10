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
	"encoding/binary"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
)

// TestNativeVirtualDeviceEnumerator_RegisterDevice tests device registration.
func TestNativeVirtualDeviceEnumerator_RegisterDevice(t *testing.T) {
	enumerator := NewNativeVirtualDeviceEnumerator()

	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		SerialNumber: "TEST001",
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Register device
	err = enumerator.RegisterDevice(device)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	// Verify count
	if enumerator.DeviceCount() != 1 {
		t.Errorf("expected 1 device, got %d", enumerator.DeviceCount())
	}

	// Duplicate registration should fail
	err = enumerator.RegisterDevice(device)
	if err != ErrNativeEnumeratorDeviceExists {
		t.Errorf("expected ErrNativeEnumeratorDeviceExists, got %v", err)
	}

	// Nil device should fail
	err = enumerator.RegisterDevice(nil)
	if err != ErrNativeEnumeratorDeviceNil {
		t.Errorf("expected ErrNativeEnumeratorDeviceNil, got %v", err)
	}
}

// TestNativeVirtualDeviceEnumerator_UnregisterDevice tests device unregistration.
func TestNativeVirtualDeviceEnumerator_UnregisterDevice(t *testing.T) {
	enumerator := NewNativeVirtualDeviceEnumerator()

	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		SerialNumber: "TEST002",
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	err = enumerator.RegisterDevice(device)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	// Unregister device
	err = enumerator.UnregisterDevice(device.Path())
	if err != nil {
		t.Fatalf("UnregisterDevice failed: %v", err)
	}

	if enumerator.DeviceCount() != 0 {
		t.Errorf("expected 0 devices, got %d", enumerator.DeviceCount())
	}

	// Unregistering non-existent device should fail
	err = enumerator.UnregisterDevice("nonexistent")
	if err != ErrNativeEnumeratorDeviceNotFound {
		t.Errorf("expected ErrNativeEnumeratorDeviceNotFound, got %v", err)
	}
}

// TestNativeVirtualDeviceEnumerator_Enumerate tests device enumeration.
func TestNativeVirtualDeviceEnumerator_Enumerate(t *testing.T) {
	enumerator := NewNativeVirtualDeviceEnumerator()

	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		SerialNumber: "TEST003",
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	err = enumerator.RegisterDevice(device)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	// Enumerate all devices
	devices, err := enumerator.Enumerate(0, 0)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("expected 1 device, got %d", len(devices))
	}

	// Enumerate with matching vendor ID
	devices, err = enumerator.Enumerate(NativeVirtualDeviceVendorID, 0)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("expected 1 device with matching vendor ID, got %d", len(devices))
	}

	// Enumerate with non-matching vendor ID
	devices, err = enumerator.Enumerate(0x1234, 0)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("expected 0 devices with non-matching vendor ID, got %d", len(devices))
	}

	// Enumerate with matching product ID
	devices, err = enumerator.Enumerate(0, NativeVirtualDeviceProductID)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("expected 1 device with matching product ID, got %d", len(devices))
	}

	// Enumerate with non-matching product ID
	devices, err = enumerator.Enumerate(0, 0xFFFF)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("expected 0 devices with non-matching product ID, got %d", len(devices))
	}
}

// TestNativeVirtualDeviceEnumerator_Open tests device opening.
func TestNativeVirtualDeviceEnumerator_Open(t *testing.T) {
	enumerator := NewNativeVirtualDeviceEnumerator()

	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		SerialNumber: "TEST004",
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	err = enumerator.RegisterDevice(device)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	// Open by native path
	opened, err := enumerator.Open(device.Path())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if opened.Path() != device.Path() {
		t.Errorf("path mismatch: got %s, want %s", opened.Path(), device.Path())
	}

	// Open non-existent path
	_, err = enumerator.Open("nonexistent")
	if err != ErrNativeEnumeratorDeviceNotFound {
		t.Errorf("expected ErrNativeEnumeratorDeviceNotFound, got %v", err)
	}

	// Open non-existent native path
	_, err = enumerator.Open(NativeVirtualDevicePathPrefix + "nonexistent")
	if err != ErrNativeEnumeratorDeviceNotFound {
		t.Errorf("expected ErrNativeEnumeratorDeviceNotFound, got %v", err)
	}
}

// TestNativeVirtualDeviceEnumerator_WrapperNoClose tests that wrapper does not close device.
func TestNativeVirtualDeviceEnumerator_WrapperNoClose(t *testing.T) {
	enumerator := NewNativeVirtualDeviceEnumerator()

	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		SerialNumber: "TEST005",
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	err = enumerator.RegisterDevice(device)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	// Open and close the wrapper
	opened, err := enumerator.Open(device.Path())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	err = opened.Close()
	if err != nil {
		t.Fatalf("wrapper Close failed: %v", err)
	}

	// Device should still be usable after wrapper close
	devices, err := enumerator.Enumerate(0, 0)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("expected 1 device after wrapper close, got %d", len(devices))
	}
}

// TestNativeVirtualDeviceEnumerator_Close tests enumerator closure.
func TestNativeVirtualDeviceEnumerator_Close(t *testing.T) {
	enumerator := NewNativeVirtualDeviceEnumerator()

	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		SerialNumber: "TEST006",
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	err = enumerator.RegisterDevice(device)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	// Close the enumerator (should close all devices)
	err = enumerator.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if enumerator.DeviceCount() != 0 {
		t.Errorf("expected 0 devices after close, got %d", enumerator.DeviceCount())
	}
}

// TestNativeVirtualDeviceEnumerator_ImplementsInterface tests interface compliance.
func TestNativeVirtualDeviceEnumerator_ImplementsInterface(t *testing.T) {
	var _ fido2.HIDDeviceEnumerator = (*NativeVirtualDeviceEnumerator)(nil)
}

// TestNativeVirtualDeviceEnumerator_WrapperMethods tests wrapper HIDDevice methods.
func TestNativeVirtualDeviceEnumerator_WrapperMethods(t *testing.T) {
	enumerator := NewNativeVirtualDeviceEnumerator()

	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		SerialNumber: "TEST007",
		Manufacturer: "TestMfg",
		Product:      "TestProd",
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	err = enumerator.RegisterDevice(device)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	// Get wrapper via Enumerate
	devices, err := enumerator.Enumerate(0, 0)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	wrapper := devices[0]

	// Test all wrapper methods
	if wrapper.VendorID() != NativeVirtualDeviceVendorID {
		t.Errorf("VendorID mismatch: got 0x%04X, want 0x%04X", wrapper.VendorID(), NativeVirtualDeviceVendorID)
	}

	if wrapper.ProductID() != NativeVirtualDeviceProductID {
		t.Errorf("ProductID mismatch: got 0x%04X, want 0x%04X", wrapper.ProductID(), NativeVirtualDeviceProductID)
	}

	if wrapper.Manufacturer() != "TestMfg" {
		t.Errorf("Manufacturer mismatch: got %s, want TestMfg", wrapper.Manufacturer())
	}

	if wrapper.Product() != "TestProd" {
		t.Errorf("Product mismatch: got %s, want TestProd", wrapper.Product())
	}

	if wrapper.SerialNumber() != "TEST007" {
		t.Errorf("SerialNumber mismatch: got %s, want TEST007", wrapper.SerialNumber())
	}

	// Test Write through wrapper
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := make([]byte, fido2.HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], fido2.CIDBroadcast)
	packet[4] = fido2.CTAPHID_INIT
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(nonce)))
	copy(packet[7:], nonce)

	n, err := wrapper.Write(packet)
	if err != nil {
		t.Fatalf("wrapper Write failed: %v", err)
	}
	if n != len(packet) {
		t.Errorf("wrapper Write returned %d, want %d", n, len(packet))
	}

	// Test Read through wrapper
	response := make([]byte, fido2.HIDPacketSize)
	n, err = wrapper.Read(response)
	if err != nil {
		t.Fatalf("wrapper Read failed: %v", err)
	}
	if n != fido2.HIDPacketSize {
		t.Errorf("wrapper Read returned %d, want %d", n, fido2.HIDPacketSize)
	}

	// Verify it's a valid INIT response
	if response[4] != fido2.CTAPHID_INIT {
		t.Errorf("expected INIT response, got 0x%02X", response[4])
	}
}

// TestNativeVirtualDeviceEnumerator_EnumerateWithBothIDs tests enumeration with both vendor and product IDs.
func TestNativeVirtualDeviceEnumerator_EnumerateWithBothIDs(t *testing.T) {
	enumerator := NewNativeVirtualDeviceEnumerator()

	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{
		SerialNumber: "TEST008",
	})
	if err != nil {
		t.Fatalf("failed to create device: %v", err)
	}
	defer func() { _ = device.Close() }()

	err = enumerator.RegisterDevice(device)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	// Enumerate with both matching IDs
	devices, err := enumerator.Enumerate(NativeVirtualDeviceVendorID, NativeVirtualDeviceProductID)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("expected 1 device with matching IDs, got %d", len(devices))
	}

	// Enumerate with matching vendor but non-matching product
	devices, err = enumerator.Enumerate(NativeVirtualDeviceVendorID, 0xFFFF)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("expected 0 devices with non-matching product ID, got %d", len(devices))
	}
}
