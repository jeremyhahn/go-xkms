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

package token

import (
	"errors"
	"testing"
)

// TestErrors_Unwrap pins the Unwrap() contract for the error types that
// wrap an underlying cause.
func TestErrors_Unwrap(t *testing.T) {
	underlying := errors.New("boom")

	t.Run("InvalidTokenError", func(t *testing.T) {
		err := &InvalidTokenError{Reason: "r", Err: underlying}
		if !errors.Is(err, underlying) {
			t.Fatal("errors.Is did not find the wrapped error")
		}
	})
	t.Run("StoreError", func(t *testing.T) {
		err := &StoreError{Op: "save", Err: underlying}
		if !errors.Is(err, underlying) {
			t.Fatal("errors.Is did not find the wrapped error")
		}
	})
	t.Run("SigningError", func(t *testing.T) {
		err := &SigningError{Err: underlying}
		if !errors.Is(err, underlying) {
			t.Fatal("errors.Is did not find the wrapped error")
		}
	})
}
