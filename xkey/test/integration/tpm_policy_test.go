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

//go:build integration && linux && tpm_simulator

// Package xkey provides integration tests for `xkey tpm policy` -- the named
// TPM policy service run locally over a swtpm -- and barrier auto-unseal
// through it.
package xkey

import (
	"encoding/json"
	"strings"
	"testing"
)

// tpmPolicyArgs appends the swtpm device selection to a `xkey tpm` command.
func tpmPolicyArgs(device string, args ...string) []string {
	return append([]string{"tpm", "--device", device}, args...)
}

// TestCLI_TPMPolicy_Lifecycle creates a named policy over the swtpm's live
// PCRs and walks it through verify, revoke, update and delete.
func TestCLI_TPMPolicy_Lifecycle(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	t.Setenv("XKEY_DATA_DIR", dataDir)
	device := swtpmDevicePath(t)

	createOut := RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "create", "boot", "--pcrs", "0,7")...)
	if !strings.Contains(createOut, "Name:         boot") {
		t.Fatalf("create did not show the policy: %s", createOut)
	}

	listOut := RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "-o", "json", "policy", "list")...)
	var policies []struct {
		Name     string `json:"name"`
		Builtin  bool   `json:"builtin"`
		Approved bool   `json:"approved"`
	}
	if err := json.Unmarshal([]byte(listOut), &policies); err != nil {
		t.Fatalf("list is not JSON: %v\n%s", err, listOut)
	}
	if len(policies) != 2 || !policies[0].Builtin || policies[1].Name != "boot" || !policies[1].Approved {
		t.Fatalf("expected the platform policy and an approved boot policy, got %+v", policies)
	}

	RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "verify", "boot")...)

	RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "revoke", "boot")...)
	verifyOut := RunXKeyExpectFailure(t, binary, "", tpmPolicyArgs(device, "policy", "verify", "boot")...)
	if !strings.Contains(verifyOut, "does not satisfy the policy") {
		t.Errorf("a revoked policy must fail verify, got: %s", verifyOut)
	}

	RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "update", "boot")...)
	RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "verify", "boot")...)

	rotateOut := RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "authority", "rotate")...)
	if !strings.Contains(rotateOut, "Generation: 2") {
		t.Errorf("rotate did not report generation 2: %s", rotateOut)
	}

	RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "delete", "boot")...)
	RunXKeyExpectFailure(t, binary, "", tpmPolicyArgs(device, "policy", "get", "boot")...)
}

// TestCLI_TPMPolicy_CreateRequiresPCRs refuses a policy with no PCRs.
func TestCLI_TPMPolicy_CreateRequiresPCRs(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	t.Setenv("XKEY_DATA_DIR", dataDir)
	device := swtpmDevicePath(t)

	out := RunXKeyExpectFailure(t, binary, "", tpmPolicyArgs(device, "policy", "create", "boot")...)
	if !strings.Contains(out, "--pcrs is required") {
		t.Errorf("expected the missing --pcrs error, got: %s", out)
	}
}

// TestCLI_TPMPolicy_BarrierAutoUnseal seals a software barrier's password
// under a named policy and unseals the barrier with it, no password read.
func TestCLI_TPMPolicy_BarrierAutoUnseal(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	t.Setenv("XKEY_DATA_DIR", dataDir)
	device := swtpmDevicePath(t)
	password := "tpm-policy-auto-unseal-42!"

	RunXKeyExpectSuccess(t, binary, password+"\n"+password+"\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "create", "boot", "--pcrs", "0,7")...)
	enableOut := RunXKeyExpectSuccess(t, binary, password+"\n", tpmPolicyArgs(device, "policy", "auto-unseal", "boot")...)
	if !strings.Contains(enableOut, `enabled under TPM policy "boot"`) {
		t.Fatalf("auto-unseal was not enabled: %s", enableOut)
	}

	// The sealed password is bound to the policy, so it cannot be deleted.
	deleteOut := RunXKeyExpectFailure(t, binary, "", tpmPolicyArgs(device, "policy", "delete", "boot")...)
	if !strings.Contains(deleteOut, "sealed/xkey-barrier-auto-unseal") {
		t.Errorf("delete must be refused, naming the sealed password: %s", deleteOut)
	}

	unsealOut := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "unseal", "--auto", "--tpm-device", device, "--data-dir", dataDir)
	if !strings.Contains(unsealOut, "auto-unsealed") {
		t.Fatalf("barrier did not auto-unseal: %s", unsealOut)
	}

	RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "auto-unseal", "--off")...)
	offOut := RunXKeyExpectFailure(t, binary, "",
		"barrier", "unseal", "--auto", "--tpm-device", device, "--data-dir", dataDir)
	if !strings.Contains(offOut, "no auto-unseal policy configured") {
		t.Errorf("with auto-unseal off, --auto must fail: %s", offOut)
	}
	RunXKeyExpectSuccess(t, binary, "", tpmPolicyArgs(device, "policy", "delete", "boot")...)
}
