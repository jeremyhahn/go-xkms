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

package server

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runUnderFIPS140 reports whether the caller runs with GODEBUG=fips140=<mode>
// in force, in which case it returns true so the caller performs its real
// assertion. Otherwise it re-execs the current test under that mode, asserts
// the child passed, and returns false so the caller asserts nothing itself.
//
// crypto/fips140.Enabled is fixed when the process starts, and the suite may
// itself run under GODEBUG=fips140=only (go-xkms#23) from a GOFIPS140 build
// that defaults to fips140=on, so a test that deliberately exercises an
// algorithm outside the FIPS 140-3 module runs in a fips140=off child of its
// own. A parent already outside the module runs an "off" test in place.
func runUnderFIPS140(t *testing.T, mode string) bool {
	t.Helper()
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == mode || (mode == "off" && !fips140.Enabled()) {
		if want := mode != "off"; fips140.Enabled() != want {
			t.Fatalf("crypto/fips140.Enabled() = %v in the fips140=%s child, want %v", fips140.Enabled(), mode, want)
		}
		return true
	}

	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GODEBUG=") || strings.HasPrefix(kv, "XKMS_FIPS_SUBPROCESS=") {
			continue
		}
		env = append(env, kv)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(env, "XKMS_FIPS_SUBPROCESS="+mode, "GODEBUG=fips140="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=%s subprocess failed: %v\n%s", mode, err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Errorf("fips140=%s subprocess did not pass:\n%s", mode, out)
	}
	return false
}
