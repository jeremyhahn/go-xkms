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

import "errors"

// ErrVirtualDeviceClosed is returned when operating on a closed virtual device.
var ErrVirtualDeviceClosed = errors.New("fido2: virtual device is closed")

// ErrVirtualDeviceNotSupported is returned when virtual FIDO2 devices are not supported on the platform.
var ErrVirtualDeviceNotSupported = errors.New("fido2: virtual FIDO2 devices are only supported on Linux")

const (
	// VirtualFIDOVendorID is the vendor ID for virtual FIDO devices.
	VirtualFIDOVendorID = 0xF1D0 // FIDO Alliance

	// VirtualFIDOProductID is the product ID for virtual FIDO devices.
	VirtualFIDOProductID = 0x0001

	// VirtualFIDOPathPrefix is the path prefix for virtual devices.
	VirtualFIDOPathPrefix = "virtualfido://"
)

// VirtualFIDO2Device is a stub for non-Linux platforms.
// Virtual FIDO2 devices are only supported on Linux.
type VirtualFIDO2Device struct{}

// VirtualDeviceConfig contains configuration for a virtual FIDO2 device.
type VirtualDeviceConfig struct {
	// Path is the virtual device path (e.g., "virtualfido://device1")
	Path string

	// AAGUID is the Authenticator Attestation GUID
	AAGUID [16]byte

	// SupportResidentKeys enables resident key (discoverable credential) support
	SupportResidentKeys bool

	// SupportUserVerification enables user verification support
	SupportUserVerification bool
}

// NewVirtualFIDO2Device returns an error on non-Linux platforms.
func NewVirtualFIDO2Device(config *VirtualDeviceConfig) (*VirtualFIDO2Device, error) {
	return nil, ErrVirtualDeviceNotSupported
}

// Path returns an empty string on non-Linux platforms.
func (v *VirtualFIDO2Device) Path() string {
	return ""
}

// VendorID returns 0 on non-Linux platforms.
func (v *VirtualFIDO2Device) VendorID() uint16 {
	return 0
}

// ProductID returns 0 on non-Linux platforms.
func (v *VirtualFIDO2Device) ProductID() uint16 {
	return 0
}

// Manufacturer returns an empty string on non-Linux platforms.
func (v *VirtualFIDO2Device) Manufacturer() string {
	return ""
}

// Product returns an empty string on non-Linux platforms.
func (v *VirtualFIDO2Device) Product() string {
	return ""
}

// Open returns an error on non-Linux platforms.
func (v *VirtualFIDO2Device) Open() error {
	return ErrVirtualDeviceNotSupported
}

// Close returns nil on non-Linux platforms.
func (v *VirtualFIDO2Device) Close() error {
	return nil
}

// Write returns an error on non-Linux platforms.
func (v *VirtualFIDO2Device) Write(data []byte) (int, error) {
	return 0, ErrVirtualDeviceNotSupported
}

// Read returns an error on non-Linux platforms.
func (v *VirtualFIDO2Device) Read(data []byte) (int, error) {
	return 0, ErrVirtualDeviceNotSupported
}
