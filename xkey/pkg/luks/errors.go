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

	sdkluks "github.com/jeremyhahn/go-xkms/sdk/go/luks"
)

// Package-level sentinel errors.
var (
	// ErrVolumeNotFound reports that no LUKS container exists at the
	// configured path. It is sdkluks.ErrVolumeNotFound to errors.Is.
	ErrVolumeNotFound = sdkluks.ErrVolumeNotFound

	// ErrVolumeAlreadyExists reports that a LUKS container already exists
	// at the configured path, with xkey's own CLI remedy. It is
	// sdkluks.ErrVolumeAlreadyExists to errors.Is.
	ErrVolumeAlreadyExists error = volumeAlreadyExistsError{}

	// ErrVolumeNotMounted reports that an operation requiring a mounted
	// volume found it unmounted. It is sdkluks.ErrNotMounted to errors.Is.
	ErrVolumeNotMounted = sdkluks.ErrNotMounted

	// ErrVolumeAlreadyMounted reports an attempt to mount a volume that is
	// already mounted. It is sdkluks.ErrAlreadyMounted to errors.Is.
	ErrVolumeAlreadyMounted = sdkluks.ErrAlreadyMounted

	ErrPassphraseMismatch = errors.New("luks: passphrase confirmation mismatch")
	ErrPermissionDenied   = errors.New("luks: permission denied (requires root)")
)

// volumeAlreadyExistsError carries xkey's CLI-specific remedy text while
// still answering true to errors.Is(err, sdkluks.ErrVolumeAlreadyExists):
// the production Executor's own ErrVolumeAlreadyExists (reached only on the
// rare TOCTOU race between Volume.Exists and the Executor's own check)
// means the same thing to a caller, just without the xkey-specific hint.
type volumeAlreadyExistsError struct{}

// Error implements the error interface.
func (volumeAlreadyExistsError) Error() string {
	return "luks: encrypted container already exists - use 'xkey luks2 wipe' first to destroy existing data"
}

// Is reports sdkluks.ErrVolumeAlreadyExists as this error's identity.
func (volumeAlreadyExistsError) Is(target error) bool {
	return target == sdkluks.ErrVolumeAlreadyExists
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
