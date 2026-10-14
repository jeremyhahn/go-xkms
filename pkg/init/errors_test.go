// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package initialize

import (
	"errors"
	"testing"
)

var errCause = errors.New("cause")

// TestRandomSourceError_WrapsCauseAndMatchesSentinel pins that a random-source
// failure reports both the sentinel and the underlying cause, so callers can
// branch on ErrRandomSource and still log what the entropy source said.
func TestRandomSourceError_WrapsCauseAndMatchesSentinel(t *testing.T) {
	err := error(&RandomSourceError{Err: errCause})

	if !errors.Is(err, ErrRandomSource) {
		t.Error("RandomSourceError must match ErrRandomSource")
	}
	if !errors.Is(err, errCause) {
		t.Error("RandomSourceError must unwrap to its cause")
	}
	if want := ErrRandomSource.Error() + ": cause"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// TestRandomSourceError_DoesNotMatchOtherSentinels guards against an Is that
// answers true for any target.
func TestRandomSourceError_DoesNotMatchOtherSentinels(t *testing.T) {
	err := error(&RandomSourceError{Err: errCause})

	if errors.Is(err, ErrAdminKeyGeneration) {
		t.Error("RandomSourceError must not match ErrAdminKeyGeneration")
	}
}

// TestAdminKeyGenerationError_WrapsCauseAndMatchesSentinel pins the same
// contract for the first-boot administrator key failure.
func TestAdminKeyGenerationError_WrapsCauseAndMatchesSentinel(t *testing.T) {
	err := error(&AdminKeyGenerationError{Err: errCause})

	if !errors.Is(err, ErrAdminKeyGeneration) {
		t.Error("AdminKeyGenerationError must match ErrAdminKeyGeneration")
	}
	if !errors.Is(err, errCause) {
		t.Error("AdminKeyGenerationError must unwrap to its cause")
	}
	if want := ErrAdminKeyGeneration.Error() + ": cause"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// TestAdminKeyGenerationError_DoesNotMatchOtherSentinels guards against an Is
// that answers true for any target.
func TestAdminKeyGenerationError_DoesNotMatchOtherSentinels(t *testing.T) {
	err := error(&AdminKeyGenerationError{Err: errCause})

	if errors.Is(err, ErrRandomSource) {
		t.Error("AdminKeyGenerationError must not match ErrRandomSource")
	}
}
