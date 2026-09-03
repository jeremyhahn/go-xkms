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

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
)

// The trap this surface exists to stop a consumer re-deriving: GOFIPS140
// accepts "off" among its spellings, so a local "is it set?" check reads the
// operator's explicit opt-OUT as an opt-in and silently enables a compliance
// control they declined.
func TestFIPSEnabled_HonoursTheGOFIPS140Spellings(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"off", false},
		{"latest", true},
		{"inprocess", true},
		{"certified", true},
		{"v1.0.0", true},
	}

	for _, tc := range tests {
		t.Run("GOFIPS140="+tc.value, func(t *testing.T) {
			t.Setenv("GOFIPS140", tc.value)

			if got := FIPSEnabled(); got != tc.want {
				t.Fatalf("FIPSEnabled() = %t, want %t for GOFIPS140=%q", got, tc.want, tc.value)
			}
		})
	}
}

// FIPSMode is the OR of the two signals, and fails toward more restriction:
// either one alone is reason enough to refuse a non-approved algorithm.
// Whatever the build says, setting GOFIPS140 must be able to turn it on.
func TestFIPSMode_EitherSignalIsEnough(t *testing.T) {
	t.Setenv("GOFIPS140", "latest")

	if !FIPSMode() {
		t.Fatal("FIPSMode() = false with GOFIPS140=latest; the environment signal must be honoured")
	}
}

// With the environment declining FIPS, FIPSMode reflects the module signal
// alone. This asserts the composition rather than a fixed value, because the
// module half depends on how the test binary was built.
func TestFIPSMode_WithoutEnvironmentTracksTheModule(t *testing.T) {
	t.Setenv("GOFIPS140", "off")

	if FIPSEnabled() {
		t.Fatal("FIPSEnabled() = true with GOFIPS140=off -- the opt-out was read as an opt-in")
	}
	// The module half is read from the backing package rather than from a new
	// export: the SDK deliberately publishes no build-provenance accessor, and
	// adding one for a test's convenience would put back the misleading
	// surface that was removed.
	if got, want := FIPSMode(), fips.Compiled(); got != want {
		t.Fatalf("FIPSMode() = %t, want %t: with the environment off, FIPSMode is the module signal", got, want)
	}
}
