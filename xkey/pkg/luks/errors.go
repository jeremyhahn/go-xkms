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

package luks

import (
	"errors"
	"fmt"
)

// Package-level sentinel errors.
var (
	ErrVolumeNotFound       = errors.New("luks: volume not found")
	ErrVolumeAlreadyExists  = errors.New("luks: encrypted container already exists - use 'xkey luks2 wipe' first to destroy existing data")
	ErrVolumeNotMounted     = errors.New("luks: volume not mounted")
	ErrVolumeAlreadyMounted = errors.New("luks: volume already mounted")
	ErrInvalidPassphrase    = errors.New("luks: invalid passphrase")
	ErrPassphraseMismatch   = errors.New("luks: passphrase confirmation mismatch")
	ErrLoopDeviceSetup      = errors.New("luks: failed to setup loop device")
	ErrLUKSFormat           = errors.New("luks: failed to format volume")
	ErrLUKSUnlock           = errors.New("luks: failed to unlock volume")
	ErrLUKSLock             = errors.New("luks: failed to lock volume")
	ErrFilesystemCreate     = errors.New("luks: failed to create filesystem")
	ErrMountFailed          = errors.New("luks: failed to mount volume")
	ErrUnmountFailed        = errors.New("luks: failed to unmount volume")
	ErrDataCopyFailed       = errors.New("luks: failed to copy data")
	ErrPermissionDenied     = errors.New("luks: permission denied (requires root)")
)

// VolumeError represents a LUKS volume operation error.
type VolumeError struct {
	Operation string
	Path      string
	Err       error
}

// Error returns the error message.
func (e *VolumeError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("luks: %s failed for %s: %v", e.Operation, e.Path, e.Err)
	}
	return fmt.Sprintf("luks: %s failed: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *VolumeError) Unwrap() error {
	return e.Err
}
