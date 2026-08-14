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

package server

import (
	"crypto"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestNew_AppliesWeakHashPolicy asserts that the config setting is actually
// wired to the policy it names. A knob that ComplianceGaps reports but that
// never reaches pkg/types would refuse to start a daemon while changing
// nothing about which digests it will sign with — and, worse, an operator who
// accepted the compliance gap in order to do legacy interop would find it
// still did not work.
//
// server.New is the composition root every deployment goes through, so it is
// where the process-wide policy is set.
func TestNew_AppliesWeakHashPolicy(t *testing.T) {
	// The policy is process-global; restore it so the rest of the package's
	// tests see the secure default.
	defer types.SetAllowWeakHashes(false)

	xkms.Reset()
	defer xkms.Reset()

	for _, tc := range []struct {
		name  string
		allow bool
	}{
		{"secure default refuses weak hashes", false},
		{"operator opt-in admits weak hashes", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Start from the opposite setting so a New that ignores the config
			// entirely fails rather than passing by coincidence.
			types.SetAllowWeakHashes(!tc.allow)

			cfg := createMinimalConfig(t)
			cfg.Crypto.AllowWeakHashes = tc.allow

			srv, err := New(cfg)
			if err != nil {
				t.Fatalf("server.New: %v", err)
			}
			defer func() { _ = srv.Shutdown() }()

			// FIPS mode is the ceiling: inside the validated module's
			// boundary the opt-in is ignored, so the expected outcome is the
			// configured value ANDed with "FIPS is off". Expressed this way the
			// test asserts the real rule in both postures instead of skipping
			// one of them.
			want := tc.allow && !types.FIPSMode()

			if got := types.AllowWeakHashes(); got != want {
				t.Fatalf("types.AllowWeakHashes() = %v, want %v (FIPS mode = %v)",
					got, want, types.FIPSMode())
			}

			_, sha1Present := types.AvailableHashes()["SHA-1"]
			if sha1Present != want {
				t.Errorf("SHA-1 present in AvailableHashes = %v, want %v", sha1Present, want)
			}
			if got := types.ParseHash("SHA-1"); (got == crypto.SHA1) != want {
				t.Errorf("ParseHash(\"SHA-1\") = %v, want weak-hash policy %v", got, want)
			}
		})
	}
}
