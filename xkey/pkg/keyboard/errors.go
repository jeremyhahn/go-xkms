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

package keyboard

import "errors"

// Package-level errors for keyboard operations.
var (
	// ErrKeyboardClosed is returned when operations are attempted on a closed keyboard.
	ErrKeyboardClosed = errors.New("keyboard: device is closed")

	// ErrKeyboardOpenFailed is returned when the UHID device cannot be opened.
	ErrKeyboardOpenFailed = errors.New("keyboard: failed to open UHID device")

	// ErrKeyboardCreateFailed is returned when the HID device creation fails.
	ErrKeyboardCreateFailed = errors.New("keyboard: failed to create HID device")

	// ErrUnsupportedChar is returned when a character has no scancode mapping.
	ErrUnsupportedChar = errors.New("keyboard: unsupported character")

	// ErrTypeFailed is returned when writing a HID report fails.
	ErrTypeFailed = errors.New("keyboard: failed to type character")

	// ErrEmptyString is returned when TypeString is called with an empty string.
	ErrEmptyString = errors.New("keyboard: empty string")
)

// DetailError appends detail text directly after a wrapped error while
// preserving errors.Is / errors.As matching of the wrapped error through
// Unwrap. The detail text carries its own leading separator.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
