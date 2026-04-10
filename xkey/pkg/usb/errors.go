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

// Package usb provides USB disk image creation and management for xKey
// portable deployments. It supports creating two-partition disk images
// with a FAT32 boot partition containing xkey binaries and a LUKS2
// encrypted data partition.
package usb

import (
	"errors"
	"fmt"
)

// Sentinel errors for USB operations.
var (
	// ErrDeviceNotFound indicates the specified device or image was not found.
	ErrDeviceNotFound = errors.New("usb: device or image not found")

	// ErrDeviceBusy indicates the device is currently in use.
	ErrDeviceBusy = errors.New("usb: device is busy")

	// ErrImageExists indicates an image file already exists at the path.
	ErrImageExists = errors.New("usb: image already exists")

	// ErrImageNotFound indicates the image file was not found.
	ErrImageNotFound = errors.New("usb: image not found")

	// ErrInvalidSize indicates the size parameter is invalid.
	ErrInvalidSize = errors.New("usb: invalid size")

	// ErrPartitionFailed indicates GPT partitioning failed.
	ErrPartitionFailed = errors.New("usb: partitioning failed")

	// ErrFormatFailed indicates filesystem formatting failed.
	ErrFormatFailed = errors.New("usb: format failed")

	// ErrMountFailed indicates a mount operation failed.
	ErrMountFailed = errors.New("usb: mount failed")

	// ErrUnmountFailed indicates an unmount operation failed.
	ErrUnmountFailed = errors.New("usb: unmount failed")

	// ErrPermissionDenied indicates root privileges are required.
	ErrPermissionDenied = errors.New("usb: permission denied (requires root)")

	// ErrSystemDisk indicates the device appears to be a system disk.
	ErrSystemDisk = errors.New("usb: device appears to be a system disk")

	// ErrCopyFailed indicates a file copy operation failed.
	ErrCopyFailed = errors.New("usb: file copy failed")

	// ErrLoopSetupFailed indicates loop device setup failed.
	ErrLoopSetupFailed = errors.New("usb: loop device setup failed")

	// ErrBinaryNotFound indicates a binary to copy was not found.
	ErrBinaryNotFound = errors.New("usb: binary not found")
)

// USBError represents a USB operation error with context.
type USBError struct {
	Operation string
	Path      string
	Err       error
}

// Error returns the formatted error message.
func (e *USBError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("usb: %s failed for %s: %v", e.Operation, e.Path, e.Err)
	}
	return fmt.Sprintf("usb: %s failed: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *USBError) Unwrap() error {
	return e.Err
}
