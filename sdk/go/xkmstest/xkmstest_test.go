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

package xkmstest

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

// TestFIPSReExports asserts each FIPS re-export is the fipstest function
// itself, so SDK consumers get the same skip semantics. Funcs are not
// comparable with ==, so the test compares their code pointers.
func TestFIPSReExports(t *testing.T) {
	cases := []struct {
		name      string
		got, want any
	}{
		{"OutsideFIPS", OutsideFIPS, fipstest.OutsideFIPS},
		{"OutsideFIPSAfterRefusal", OutsideFIPSAfterRefusal, fipstest.OutsideFIPSAfterRefusal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reflect.ValueOf(tc.got).Pointer() != reflect.ValueOf(tc.want).Pointer() {
				t.Fatalf("%s does not re-export fipstest.%s", tc.name, tc.name)
			}
		})
	}
}
