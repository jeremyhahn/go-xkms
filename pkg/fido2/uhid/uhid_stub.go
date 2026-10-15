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

//go:build !linux

package uhid

import "time"

// Device represents a UHID virtual HID device.
// On non-Linux platforms, all operations return ErrNotSupported.
type Device struct{}

// Open returns ErrNotSupported on non-Linux platforms.
func Open() (*Device, error) {
	return nil, ErrNotSupported
}

// Create returns ErrNotSupported on non-Linux platforms.
func (d *Device) Create(cfg *CreateConfig) error {
	return ErrNotSupported
}

// ReadOutput returns ErrNotSupported on non-Linux platforms.
func (d *Device) ReadOutput() ([]byte, error) {
	return nil, ErrNotSupported
}

// WriteInput returns ErrNotSupported on non-Linux platforms.
func (d *Device) WriteInput(data []byte) error {
	return ErrNotSupported
}

// Close returns nil on non-Linux platforms.
func (d *Device) Close() error {
	return nil
}

// SetReadTimeout is a no-op on non-Linux platforms.
func (d *Device) SetReadTimeout(timeout time.Duration) {}

// SetNonBlocking returns ErrNotSupported on non-Linux platforms.
func (d *Device) SetNonBlocking(nonBlocking bool) error {
	return ErrNotSupported
}

// IsCreated returns false on non-Linux platforms.
func (d *Device) IsCreated() bool {
	return false
}

// IsClosed returns true on non-Linux platforms.
func (d *Device) IsClosed() bool {
	return true
}

// Fd returns -1 on non-Linux platforms.
func (d *Device) Fd() int {
	return -1
}
