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

package types

import (
	"crypto"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// weakHashDefaultSubprocessEnv marks the child process spawned by
// TestWeakHashPolicy_DefaultIsRefuseInAFreshProcess.
const weakHashDefaultSubprocessEnv = "XKMS_WEAK_HASH_DEFAULT_SUBPROCESS"

// TestWeakHashPolicy_DefaultIsRefuseInAFreshProcess asserts the value init
// seeds, in a process where nothing else has run.
//
// Every other test of this policy sets it first, so all of them would stay
// green if the seed were changed back to "permitted unless FIPS is on" — which
// is exactly the regression this pins: with that seed, a process that never
// applies a configuration (a library embedding xkms, or a daemon whose YAML
// omits crypto.allow_weak_hashes) signs with MD5 on request. The only honest
// way to observe the seed is a fresh process, because the package-level policy
// is process-global and any earlier test may have written to it.
//
// The child runs with no FIPS selector, so it also proves the refusal does not
// depend on FIPS mode being on.
func TestWeakHashPolicy_DefaultIsRefuseInAFreshProcess(t *testing.T) {
	if os.Getenv(weakHashDefaultSubprocessEnv) == "1" {
		if FIPSMode() {
			t.Fatal("child process is in FIPS mode; this test must prove the default " +
				"outside FIPS, where the permissive seed used to apply")
		}
		if AllowWeakHashes() {
			t.Error("the weak-hash policy must refuse by default: a process that has " +
				"applied no configuration must not produce signatures over broken digests")
		}
		// The seed has to reach the tables callers actually use, not just the
		// accessor: ParseHash is what every API layer calls.
		for _, name := range []string{"MD5", "SHA-1", "SHA1", "MD5SHA1", "RIPEMD160"} {
			if got := ParseHash(name); got != 0 {
				t.Errorf("ParseHash(%q) = %v, want 0 by default", name, got)
			}
			if _, present := AvailableHashes()[name]; present {
				t.Errorf("AvailableHashes() advertises %q by default", name)
			}
		}
		// The strong digests must still resolve; a refusing default that also
		// broke SHA-256 would pass every assertion above and serve nothing.
		if got := ParseHash("SHA-256"); got != crypto.SHA256 {
			t.Errorf("ParseHash(\"SHA-256\") = %v, want %v", got, crypto.SHA256)
		}
		return
	}

	// This test's whole point is the seed's value outside FIPS, so the
	// child must run with no FIPS selector even when the parent test binary
	// itself was invoked under GODEBUG=fips140=only (as go-xkms#23 requires
	// for the rest of this suite): a GODEBUG inherited from the parent's
	// environment would fail the child's own FIPSMode() guard above for a
	// reason that has nothing to do with the weak-hash seed.
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GODEBUG=") {
			continue
		}
		env = append(env, kv)
	}
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestWeakHashPolicy_DefaultIsRefuseInAFreshProcess$", "-test.v")
	cmd.Env = append(env, weakHashDefaultSubprocessEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fresh-process subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fresh-process subprocess did not pass:\n%s", out)
	}
}
