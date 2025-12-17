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

// ErrHIDNotSupported is returned when HID operations are attempted on unsupported platforms
var ErrHIDNotSupported = errors.New("fido2: HID device access is only supported on Linux")

// stubEnumerator is a no-op HID enumerator for unsupported platforms
type stubEnumerator struct{}

// NewDefaultEnumerator returns a stub enumerator on non-Linux platforms.
// All operations will return ErrHIDNotSupported.
func NewDefaultEnumerator() HIDDeviceEnumerator {
	return &stubEnumerator{}
}

// Enumerate returns an error indicating HID is not supported on this platform
func (s *stubEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return nil, ErrHIDNotSupported
}

// Open returns an error indicating HID is not supported on this platform
func (s *stubEnumerator) Open(path string) (HIDDevice, error) {
	return nil, ErrHIDNotSupported
}
