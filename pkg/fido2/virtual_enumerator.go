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
	"fmt"
	"strings"
	"sync"
)

// VirtualDeviceEnumerator implements HIDDeviceEnumerator for virtual FIDO2 devices.
// It manages a registry of virtual devices that can be enumerated and opened
// like physical HID devices.
type VirtualDeviceEnumerator struct {
	devices map[string]*VirtualFIDO2Device
	mu      sync.RWMutex
}

// NewVirtualDeviceEnumerator creates a new virtual device enumerator.
func NewVirtualDeviceEnumerator() *VirtualDeviceEnumerator {
	return &VirtualDeviceEnumerator{
		devices: make(map[string]*VirtualFIDO2Device),
	}
}

// RegisterDevice adds a virtual device to the enumerator's registry.
// The device will be discoverable via Enumerate() and openable via Open().
func (e *VirtualDeviceEnumerator) RegisterDevice(device *VirtualFIDO2Device) error {
	if device == nil {
		return fmt.Errorf("fido2: device is nil")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	path := device.Path()
	if _, exists := e.devices[path]; exists {
		return fmt.Errorf("fido2: device with path %s already registered", path)
	}

	e.devices[path] = device
	return nil
}

// UnregisterDevice removes a virtual device from the enumerator's registry.
func (e *VirtualDeviceEnumerator) UnregisterDevice(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.devices[path]; !exists {
		return fmt.Errorf("fido2: device with path %s not found", path)
	}

	delete(e.devices, path)
	return nil
}

// Enumerate returns all registered virtual devices that match the given
// vendor and product IDs. If vendorID and productID are both 0, all
// virtual devices are returned.
func (e *VirtualDeviceEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var devices []HIDDevice
	for _, device := range e.devices {
		// Match all if both IDs are 0
		if vendorID == 0 && productID == 0 {
			devices = append(devices, device)
			continue
		}

		// Match by vendor ID
		if vendorID != 0 && device.VendorID() != vendorID {
			continue
		}

		// Match by product ID
		if productID != 0 && device.ProductID() != productID {
			continue
		}

		devices = append(devices, device)
	}

	return devices, nil
}

// Open opens a virtual device by its path.
func (e *VirtualDeviceEnumerator) Open(path string) (HIDDevice, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Handle virtual device paths
	if strings.HasPrefix(path, VirtualFIDOPathPrefix) {
		device, exists := e.devices[path]
		if !exists {
			return nil, fmt.Errorf("fido2: virtual device not found: %s", path)
		}
		return device, nil
	}

	// Check if any registered device matches the path
	for devicePath, device := range e.devices {
		if devicePath == path {
			return device, nil
		}
	}

	return nil, fmt.Errorf("fido2: device not found: %s", path)
}

// DeviceCount returns the number of registered virtual devices.
func (e *VirtualDeviceEnumerator) DeviceCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.devices)
}

// Close unregisters all devices and releases resources.
func (e *VirtualDeviceEnumerator) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for path, device := range e.devices {
		_ = device.Close()
		delete(e.devices, path)
	}

	return nil
}

// Ensure VirtualDeviceEnumerator implements HIDDeviceEnumerator.
var _ HIDDeviceEnumerator = (*VirtualDeviceEnumerator)(nil)

// CombinedEnumerator wraps multiple enumerators to search across both
// virtual and physical devices.
type CombinedEnumerator struct {
	enumerators []HIDDeviceEnumerator
}

// NewCombinedEnumerator creates an enumerator that searches across multiple
// underlying enumerators. This allows combining virtual devices with
// physical devices for testing or hybrid scenarios.
func NewCombinedEnumerator(enumerators ...HIDDeviceEnumerator) *CombinedEnumerator {
	return &CombinedEnumerator{
		enumerators: enumerators,
	}
}

// Enumerate returns devices from all underlying enumerators.
func (c *CombinedEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	var allDevices []HIDDevice

	for _, enumerator := range c.enumerators {
		devices, err := enumerator.Enumerate(vendorID, productID)
		if err != nil {
			// Log but continue with other enumerators
			continue
		}
		allDevices = append(allDevices, devices...)
	}

	return allDevices, nil
}

// Open tries to open a device from any of the underlying enumerators.
func (c *CombinedEnumerator) Open(path string) (HIDDevice, error) {
	var lastErr error

	for _, enumerator := range c.enumerators {
		device, err := enumerator.Open(path)
		if err == nil {
			return device, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("fido2: device not found: %s", path)
}

// Ensure CombinedEnumerator implements HIDDeviceEnumerator.
var _ HIDDeviceEnumerator = (*CombinedEnumerator)(nil)
