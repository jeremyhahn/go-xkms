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

	// ErrKeyringUnavailable is the identity of every KeyringError: the kernel
	// keyring is not usable by this process, so no volume can be unlocked.
	ErrKeyringUnavailable = errors.New("luks: the kernel keyring is unavailable to this process")
)

// KeyringError reports a failed kernel keyring preflight. It is
// ErrKeyringUnavailable to errors.Is, and it unwraps to go-luks2's own
// classification (luks2.ErrKeyringBlocked for a seccomp policy,
// luks2.ErrKeyringUnsupported for a kernel without key support,
// luks2.ErrKeyringQuotaExhausted, luks2.ErrKeyringFailed), whose message
// names the syscalls and the remedy.
type KeyringError struct {
	// Err is go-luks2's classified error.
	Err error
}

// Error implements the error interface.
func (e *KeyringError) Error() string {
	return "luks: kernel keyring preflight failed: " + e.Err.Error()
}

// Unwrap returns go-luks2's classified error.
func (e *KeyringError) Unwrap() error { return e.Err }

// Is reports ErrKeyringUnavailable as this error's identity.
func (e *KeyringError) Is(target error) bool { return target == ErrKeyringUnavailable }

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

// MessageError is a typed error that carries a preformatted message. It
// replaces inline formatted-error constructions that do not wrap a cause.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
