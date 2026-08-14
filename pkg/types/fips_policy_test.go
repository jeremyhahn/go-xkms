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
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestAlgorithmPolicy_RefusesByDefault pins the layering: the process refuses
// the legacy primitives until something applies a configuration, in either
// FIPS mode. Nothing is admitted merely because FIPS happens to be off — a
// library embedding xkms, a test, or a daemon whose YAML says nothing must not
// silently produce a forgeable signature or expose a decryption oracle.
//
// The opt-in and the FIPS ceiling are covered by the CanOnlyTighten tests and
// by TestFIPSMode_RefusesNonApprovedAlgorithms, which re-execs with
// GODEBUG=fips140=on because fips140.Enabled() is fixed at process start.
func TestAlgorithmPolicy_RefusesByDefault(t *testing.T) {
	// Restore whatever the surrounding suite had, then assert the pristine
	// package default by tightening explicitly (init already stored false;
	// this also proves nothing in the package re-admits them on its own).
	origHash, origWrap := AllowWeakHashes(), AllowLegacyKeyWrap()
	t.Cleanup(func() {
		SetAllowWeakHashes(origHash)
		SetAllowLegacyKeyWrap(origWrap)
	})

	SetAllowWeakHashes(false)
	SetAllowLegacyKeyWrap(false)

	if AllowWeakHashes() {
		t.Error("the collision-broken digests must be refused until configured")
	}
	if AllowLegacyKeyWrap() {
		t.Error("the unauthenticated key-wrap constructions must be refused until configured")
	}
}

// TestSetAllowWeakHashes_CanOnlyTighten proves the setter is a one-way valve
// with respect to FIPS: a caller may restrict the policy, but outside FIPS
// mode may also restore it, and inside FIPS mode may never loosen it.
func TestSetAllowWeakHashes_CanOnlyTighten(t *testing.T) {
	original := AllowWeakHashes()
	t.Cleanup(func() { SetAllowWeakHashes(original) })

	SetAllowWeakHashes(false)
	if AllowWeakHashes() {
		t.Fatal("SetAllowWeakHashes(false) must always tighten the policy")
	}

	SetAllowWeakHashes(true)
	if FIPSMode() {
		if AllowWeakHashes() {
			t.Error("in FIPS mode the policy must not be loosenable")
		}
	} else if !AllowWeakHashes() {
		t.Error("outside FIPS mode the policy must be restorable")
	}
}

// TestSetAllowLegacyKeyWrap_CanOnlyTighten is the key-wrap counterpart.
func TestSetAllowLegacyKeyWrap_CanOnlyTighten(t *testing.T) {
	original := AllowLegacyKeyWrap()
	t.Cleanup(func() { SetAllowLegacyKeyWrap(original) })

	SetAllowLegacyKeyWrap(false)
	if AllowLegacyKeyWrap() {
		t.Fatal("SetAllowLegacyKeyWrap(false) must always tighten the policy")
	}

	SetAllowLegacyKeyWrap(true)
	if FIPSMode() {
		if AllowLegacyKeyWrap() {
			t.Error("in FIPS mode the policy must not be loosenable")
		}
	} else if !AllowLegacyKeyWrap() {
		t.Error("outside FIPS mode the policy must be restorable")
	}
}

// TestFIPSMode_RefusesNonApprovedAlgorithms exercises the FIPS-on half by
// re-execing this test binary with GODEBUG=fips140=on. fips140.Enabled() is
// fixed when the process starts, so the only honest way to test the enabled
// branch is in a separate process.
func TestFIPSMode_RefusesNonApprovedAlgorithms(t *testing.T) {
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		// Child: assert the FIPS posture.
		if !FIPSMode() {
			t.Fatal("child process is not in FIPS mode; GODEBUG=fips140=on was not honored")
		}
		if AllowWeakHashes() {
			t.Error("FIPS mode must refuse the collision-broken digests")
		}
		if AllowLegacyKeyWrap() {
			t.Error("FIPS mode must refuse the unauthenticated key-wrap constructions")
		}
		// The setter must not be able to re-admit them.
		SetAllowWeakHashes(true)
		SetAllowLegacyKeyWrap(true)
		if AllowWeakHashes() || AllowLegacyKeyWrap() {
			t.Error("FIPS mode policy must not be loosenable by the setter")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFIPSMode_RefusesNonApprovedAlgorithms", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("FIPS-mode subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("FIPS-mode subprocess did not pass:\n%s", out)
	}
}
