// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package fido2

import (
	"errors"
	"testing"
)

// TestLocalCeremonyError_Unwrap pins the Unwrap() contract so errors.Is/As
// keep working through a wrapped ceremony-stage failure.
func TestLocalCeremonyError_Unwrap(t *testing.T) {
	underlying := errors.New("boom")
	err := &LocalCeremonyError{Stage: "GetAssertion", Err: underlying}
	if !errors.Is(err, underlying) {
		t.Fatal("errors.Is did not find the wrapped error")
	}
}
