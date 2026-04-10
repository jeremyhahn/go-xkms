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

package uhid

import "errors"

// Package-level errors for UHID operations.
var (
	// ErrUHIDNotAvailable is returned when /dev/uhid is not available.
	ErrUHIDNotAvailable = errors.New("uhid: /dev/uhid not available")

	// ErrDeviceCreationFailed is returned when UHID_CREATE2 fails.
	ErrDeviceCreationFailed = errors.New("uhid: device creation failed")

	// ErrDeviceNotOpen is returned when operations are attempted on a closed device.
	ErrDeviceNotOpen = errors.New("uhid: device not open")

	// ErrWriteFailed is returned when writing to UHID fails.
	ErrWriteFailed = errors.New("uhid: write failed")

	// ErrReadFailed is returned when reading from UHID fails.
	ErrReadFailed = errors.New("uhid: read failed")

	// ErrInvalidPacket is returned when a UHID packet is malformed.
	ErrInvalidPacket = errors.New("uhid: invalid packet")

	// ErrNotSupported is returned on non-Linux platforms.
	ErrNotSupported = errors.New("uhid: not supported on this platform")

	// ErrDeviceAlreadyCreated is returned when Create is called on an already created device.
	ErrDeviceAlreadyCreated = errors.New("uhid: device already created")

	// ErrTimeout is returned when a read operation times out.
	ErrTimeout = errors.New("uhid: read timeout")
)
