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

package mlkem512

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestNewAndCreate_RefuseUnderFIPS is the compliance assertion for this
// package's one shared FIPS seam (go-xkms #21): crypto/fips140.Enabled is
// fixed when the process starts, so the only honest way to exercise the
// refusal is a separate process, re-exec'd under GODEBUG=fips140=on and
// again under the stricter GODEBUG=fips140=only. This mirrors the re-exec
// pattern already used by pkg/types.TestFIPSMode_RefusesNonApprovedAlgorithms
// and pkg/certstore.TestToString_UnderFIPSOnly.
func TestNewAndCreate_RefuseUnderFIPS(t *testing.T) {
	for _, godebug := range []string{"fips140=on", "fips140=only"} {
		t.Run(godebug, func(t *testing.T) {
			if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
				if _, err := New(); err != ErrFIPSMode {
					t.Fatalf("New() error = %v, want ErrFIPSMode", err)
				}

				seed := make([]byte, SeedSize)
				if _, err := Create(seed); err != ErrFIPSMode {
					t.Fatalf("Create() error = %v, want ErrFIPSMode", err)
				}
				return
			}

			cmd := exec.Command(os.Args[0], "-test.run=TestNewAndCreate_RefuseUnderFIPS/"+godebug, "-test.v")
			cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG="+godebug)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s subprocess failed: %v\n%s", godebug, err, out)
			}
			if !strings.Contains(string(out), "PASS") {
				t.Errorf("%s subprocess did not pass:\n%s", godebug, out)
			}
		})
	}
}

// TestNewAndCreate_SucceedOutsideFIPS pins the other half of the contract in
// the same process this suite already runs in: outside FIPS mode, neither
// constructor is affected by the seam added for go-xkms #21.
//
// This runs in whatever mode the ambient `go test` invocation set rather than
// re-exec'ing (TestNewAndCreate_RefuseUnderFIPS already covers both fips140=on
// and fips140=only exhaustively via subprocess), so a suite run entirely under
// GODEBUG=fips140=only -- go-xkms#23's fips-aware CI lane -- asserts the
// refusal here too instead of failing on a nil check the ambient mode makes
// impossible to satisfy.
func TestNewAndCreate_SucceedOutsideFIPS(t *testing.T) {
	k, err := New()
	if fips140.Enabled() {
		if err != ErrFIPSMode {
			t.Fatalf("New() error = %v, want ErrFIPSMode", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	defer k.Clean()

	seed := k.ExportSecretKey()
	if seed == nil {
		t.Fatal("ExportSecretKey() = nil, want a 64-byte seed")
	}

	reconstructed, err := Create(seed)
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	defer reconstructed.Clean()
}
