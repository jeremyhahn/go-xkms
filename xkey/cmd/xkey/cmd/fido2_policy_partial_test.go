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

package cmd

import (
	"testing"
)

// runRPPolicySetArgs executes `fido2 policy set` with the given flag
// arguments, resetting cobra flag state first so only the flags this
// invocation passes count as changed.
func runRPPolicySetArgs(t *testing.T, args ...string) {
	t.Helper()
	resetCommandFlagsForTest(t, RootCmd)
	resetFIDO2PolicyFlags()

	_ = captureRPPolicyStdout(t, func() {
		RootCmd.SetArgs(append([]string{"fido2", "policy", "set"}, args...))
		if execErr := RootCmd.Execute(); execErr != nil {
			t.Fatalf("fido2 policy set %v failed: %v", args, execErr)
		}
	})
}

// TestRPPolicySet_PartialUpdatePreservesStoredSettings is the #321 regression
// probe on the CLI: `xkey fido2 policy set --rpid ... --blocked` against a
// populated RP must change only Blocked. Before the fix the unset cobra flag
// defaults overwrote the SO's UV, UP, attestation and enterprise settings
// with their permissive zero values.
func TestRPPolicySet_PartialUpdatePreservesStoredSettings(t *testing.T) {
	storePath := newRPPolicyTestDir(t, "rp-policy-partial-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	runRPPolicySetArgs(t,
		"--rpid", "rp.example",
		"--uv", "required",
		"--up", "true",
		"--attestation", "direct",
		"--enterprise",
	)

	runRPPolicySetArgs(t, "--rpid", "rp.example", "--blocked")

	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	policy, err := store.GetPolicy("rp.example")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}

	if policy.UVOverride != "required" {
		t.Errorf("UVOverride = %q, want %q (cleared by a partial update)", policy.UVOverride, "required")
	}
	if policy.UPOverride == nil || !*policy.UPOverride {
		t.Errorf("UPOverride = %v, want true (cleared by a partial update)", policy.UPOverride)
	}
	if policy.AttestationOverride != "direct" {
		t.Errorf("AttestationOverride = %q, want %q (cleared by a partial update)", policy.AttestationOverride, "direct")
	}
	if !policy.Enterprise {
		t.Error("Enterprise = false, want true (cleared by a partial update)")
	}
	if !policy.Blocked {
		t.Error("Blocked = false, want true (the one field the update carried)")
	}
}

// TestRPPolicySet_BlockSurvivesUnrelatedSet asserts that blocking an RP and
// then setting an unrelated field does not lift the block.
func TestRPPolicySet_BlockSurvivesUnrelatedSet(t *testing.T) {
	storePath := newRPPolicyTestDir(t, "rp-policy-block-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	runRPPolicySetArgs(t, "--rpid", "blocked.example", "--blocked")
	runRPPolicySetArgs(t, "--rpid", "blocked.example", "--uv", "required")

	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	policy, err := store.GetPolicy("blocked.example")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}

	if !policy.Blocked {
		t.Error("Blocked = false: a set that omits --blocked lifted the RP block")
	}
	if policy.UVOverride != "required" {
		t.Errorf("UVOverride = %q, want %q", policy.UVOverride, "required")
	}
}

// TestRPPolicySet_ExplicitBlockedFalseUnblocks asserts the distinction merge
// semantics must preserve: a flag the user explicitly sets to its zero value
// does take effect.
func TestRPPolicySet_ExplicitBlockedFalseUnblocks(t *testing.T) {
	storePath := newRPPolicyTestDir(t, "rp-policy-unblock-*")
	setFIDO2ViperFile(storePath)
	defer resetFIDO2Viper()

	runRPPolicySetArgs(t, "--rpid", "unblock.example", "--uv", "required", "--blocked")
	runRPPolicySetArgs(t, "--rpid", "unblock.example", "--blocked=false")

	store, err := createFIDO2RPPolicyStore(buildFIDO2Config())
	if err != nil {
		t.Fatalf("failed to create store for verification: %v", err)
	}
	policy, err := store.GetPolicy("unblock.example")
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}

	if policy.Blocked {
		t.Error("Blocked = true: an explicit --blocked=false must lift the block")
	}
	if policy.UVOverride != "required" {
		t.Errorf("UVOverride = %q, want %q (must survive the unblock)", policy.UVOverride, "required")
	}
}
