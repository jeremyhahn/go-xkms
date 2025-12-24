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

//go:build !linux

package fido2

// VirtualDeviceEnumerator is a stub for non-Linux platforms.
// Virtual FIDO2 devices are only supported on Linux.
type VirtualDeviceEnumerator struct{}

// NewVirtualDeviceEnumerator creates a new virtual device enumerator stub.
func NewVirtualDeviceEnumerator() *VirtualDeviceEnumerator {
	return &VirtualDeviceEnumerator{}
}

// Enumerate returns an empty slice on non-Linux platforms.
func (e *VirtualDeviceEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return nil, nil
}

// Open returns an error on non-Linux platforms.
func (e *VirtualDeviceEnumerator) Open(path string) (HIDDevice, error) {
	return nil, ErrVirtualDeviceNotSupported
}

// Register does nothing on non-Linux platforms.
func (e *VirtualDeviceEnumerator) Register(device *VirtualFIDO2Device) error {
	return ErrVirtualDeviceNotSupported
}

// Unregister does nothing on non-Linux platforms.
func (e *VirtualDeviceEnumerator) Unregister(path string) {
}

// CombinedEnumerator combines multiple HID device enumerators.
type CombinedEnumerator struct {
	enumerators []HIDDeviceEnumerator
}

// NewCombinedEnumerator creates a new combined enumerator.
func NewCombinedEnumerator(enumerators ...HIDDeviceEnumerator) *CombinedEnumerator {
	return &CombinedEnumerator{enumerators: enumerators}
}

// Enumerate returns devices from all enumerators.
func (c *CombinedEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	var allDevices []HIDDevice
	for _, enum := range c.enumerators {
		devices, err := enum.Enumerate(vendorID, productID)
		if err != nil {
			continue
		}
		allDevices = append(allDevices, devices...)
	}
	return allDevices, nil
}

// Open tries to open a device using each enumerator.
func (c *CombinedEnumerator) Open(path string) (HIDDevice, error) {
	for _, enum := range c.enumerators {
		device, err := enum.Open(path)
		if err == nil {
			return device, nil
		}
	}
	return nil, ErrHIDNotSupported
}
