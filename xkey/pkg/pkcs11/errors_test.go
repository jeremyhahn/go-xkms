// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package pkcs11

import (
	"errors"
	"testing"
)

// TestDetailError_ComposesAndUnwraps verifies DetailError's documented
// contract: Error() appends Detail directly after the wrapped error's own
// message (Detail carries its own leading separator), and Unwrap() still
// exposes the wrapped sentinel to errors.Is so callers can match on it
// through the appended text.
func TestDetailError_ComposesAndUnwraps(t *testing.T) {
	err := &DetailError{Err: ErrKeyNotFound, Detail: ": my-key-id"}

	if got, want := err.Error(), ErrKeyNotFound.Error()+": my-key-id"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Error("errors.Is(err, ErrKeyNotFound) = false, want true")
	}
}

// TestSentinelCauseError_MatchesBothSentinelAndCause verifies the
// documented purpose of SentinelCauseError: errors.Is must match both the
// package sentinel and the backend's underlying cause, since a caller may
// legitimately check for either.
func TestSentinelCauseError_MatchesBothSentinelAndCause(t *testing.T) {
	cause := errors.New("backend: connection reset")
	err := &SentinelCauseError{Sentinel: ErrSigningFailed, Cause: cause}

	if got, want := err.Error(), ErrSigningFailed.Error()+": "+cause.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrSigningFailed) {
		t.Error("errors.Is(err, ErrSigningFailed) = false, want true")
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true")
	}
}
