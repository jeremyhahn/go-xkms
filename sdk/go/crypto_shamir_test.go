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

package xkms

import (
	"testing"
)

// TestShamirVerifyShare_ProtectedShare pins the go-qrdb v0.58.5 Shamir
// re-export: a share is a ShamirProtectedShare (its value in protected
// memory) and ShamirVerifyShare takes it. A nil share is reported, never
// dereferenced.
func TestShamirVerifyShare_ProtectedShare(t *testing.T) {
	var shares []*ShamirProtectedShare
	if err := ShamirVerifyShare(nil, shares); err == nil {
		t.Fatal("ShamirVerifyShare accepted a nil share")
	}
}
