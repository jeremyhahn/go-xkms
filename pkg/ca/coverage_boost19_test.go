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

// Package ca coverage boost, nineteenth pass: revocation-persistence storage
// faults (the revocationStore backend of putRevocationBlobIfAbsent) and the
// mustMarshal panic-on-unsupported-type guard.
package ca

import (
	"testing"
)

// TestMustMarshal_PanicsOnUnsupportedType_B19 exercises mustMarshal's
// panic-on-marshal-error guard. mustMarshal is only ever called internally
// with known-good ASN.1 values; this test proves the defensive panic fires
// for a type ASN.1 cannot encode (a Go channel), rather than silently
// returning corrupt bytes.
func TestMustMarshal_PanicsOnUnsupportedType_B19(t *testing.T) {
	t.Parallel()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected mustMarshal to panic on an unsupported type")
		}
	}()
	mustMarshal(make(chan int))
}
