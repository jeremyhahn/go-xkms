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

import (
	"errors"
	"testing"
)

// TestDetailError_Error verifies the wrapped error message is followed
// directly by the detail text, with no separator inserted (callers supply
// their own leading punctuation in Detail).
func TestDetailError_Error(t *testing.T) {
	err := &DetailError{Err: ErrInvalidPacket, Detail: ": short read (2 bytes)"}

	want := "uhid: invalid packet: short read (2 bytes)"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("errors.Is(err, ErrInvalidPacket) = false, want true")
	}
}

// TestSentinelCauseError_Error verifies the message joins the sentinel and
// the cause, and that errors.Is matches both through Unwrap.
func TestSentinelCauseError_Error(t *testing.T) {
	cause := errors.New("permission denied")
	err := &SentinelCauseError{Sentinel: ErrUHIDNotAvailable, Cause: cause}

	want := "uhid: /dev/uhid not available: permission denied"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrUHIDNotAvailable) {
		t.Errorf("errors.Is(err, ErrUHIDNotAvailable) = false, want true")
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(err, cause) = false, want true")
	}
}

// TestWrappedError_ErrorAndUnwrap verifies the message format and that
// Unwrap returns exactly the wrapped cause for errors.Is/errors.As chains.
func TestWrappedError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("bad file descriptor")
	err := &WrappedError{Msg: "failed to get file flags", Err: cause}

	want := "failed to get file flags: bad file descriptor"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got := errors.Unwrap(err); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(err, cause) = false, want true")
	}
}
