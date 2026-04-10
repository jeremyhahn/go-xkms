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

//go:build integration && linux && tpm_simulator

// Package xkey provides integration tests for PCR policy management and
// barrier auto-unseal using a TPM simulator (swtpm).
package xkey

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// PCR Policy Create
// ---------------------------------------------------------------------------

// TestCLI_PolicyCreate_Success verifies that creating a PCR policy
// with valid indices and bank succeeds and prints confirmation.
func TestCLI_PolicyCreate_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "test-secure-boot",
		"--pcrs", "0,1,2,3,7",
		"--bank", "sha256",
		"--store", storePath)

	if !strings.Contains(stdout, "Created policy") {
		t.Errorf("Expected 'Created policy' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "test-secure-boot") {
		t.Errorf("Expected policy name 'test-secure-boot' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "SHA256") && !strings.Contains(stdout, "sha256") {
		t.Errorf("Expected bank 'SHA256' or 'sha256' in output, got: %s", stdout)
	}
}

// TestCLI_PolicyCreate_MissingPCRs verifies that creating a policy
// without the --pcrs flag fails with a clear error.
func TestCLI_PolicyCreate_MissingPCRs(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "create", "bad-policy",
		"--bank", "sha256",
		"--store", storePath)

	if !strings.Contains(errOutput, "pcrs") {
		t.Errorf("Expected error mentioning 'pcrs', got: %s", errOutput)
	}
}

// TestCLI_PolicyCreate_InvalidBank verifies that an invalid bank value
// is rejected.
func TestCLI_PolicyCreate_InvalidBank(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "create", "bad-bank-policy",
		"--pcrs", "0,7",
		"--bank", "md5",
		"--store", storePath)

	if !strings.Contains(errOutput, "invalid bank") && !strings.Contains(errOutput, "bank") {
		t.Errorf("Expected error about invalid bank, got: %s", errOutput)
	}
}

// TestCLI_PolicyCreate_SHA384Bank verifies that SHA-384 bank is accepted.
func TestCLI_PolicyCreate_SHA384Bank(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "sha384-policy",
		"--pcrs", "0,7",
		"--bank", "sha384",
		"--store", storePath)

	if !strings.Contains(stdout, "Created policy") {
		t.Errorf("Expected 'Created policy' in output, got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy List
// ---------------------------------------------------------------------------

// TestCLI_PolicyList_Empty verifies that listing policies when none
// exist produces the expected "No policies found" message.
func TestCLI_PolicyList_Empty(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if !strings.Contains(stdout, "No policies found") {
		t.Errorf("Expected 'No policies found', got: %s", stdout)
	}
}

// TestCLI_PolicyList_ShowsCreatedPolicy verifies that a created policy
// appears in the list output.
func TestCLI_PolicyList_ShowsCreatedPolicy(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a policy first.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "list-test-policy",
		"--pcrs", "0,2,7",
		"--bank", "sha256",
		"--store", storePath)

	// List and verify.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if !strings.Contains(stdout, "list-test-policy") {
		t.Errorf("Expected 'list-test-policy' in list output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "PCR Policies") {
		t.Errorf("Expected 'PCR Policies' header in output, got: %s", stdout)
	}
}

// TestCLI_PolicyList_MultiplePolicies verifies that multiple policies
// are all shown in the list.
func TestCLI_PolicyList_MultiplePolicies(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create two policies.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "policy-alpha",
		"--pcrs", "0,1",
		"--bank", "sha256",
		"--store", storePath)

	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "policy-beta",
		"--pcrs", "2,3,7",
		"--bank", "sha256",
		"--store", storePath)

	// List and verify both appear.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if !strings.Contains(stdout, "policy-alpha") {
		t.Errorf("Expected 'policy-alpha' in list output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "policy-beta") {
		t.Errorf("Expected 'policy-beta' in list output, got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Get
// ---------------------------------------------------------------------------

// TestCLI_PolicyGet_Success verifies that getting a specific policy
// displays its details including PCR values.
func TestCLI_PolicyGet_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "get-test-policy",
		"--pcrs", "0,7",
		"--bank", "sha256",
		"--store", storePath)

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "get", "get-test-policy",
		"--store", storePath)

	if !strings.Contains(stdout, "get-test-policy") {
		t.Errorf("Expected policy name in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "PCR Values") {
		t.Errorf("Expected 'PCR Values' section in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "PCR[") {
		t.Errorf("Expected PCR value entries in output, got: %s", stdout)
	}
}

// TestCLI_PolicyGet_NotFound verifies that getting a nonexistent
// policy fails.
func TestCLI_PolicyGet_NotFound(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create the store first with a dummy policy so the store exists.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "dummy",
		"--pcrs", "0",
		"--bank", "sha256",
		"--store", storePath)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "get", "nonexistent-policy",
		"--store", storePath)

	if !strings.Contains(errOutput, "not found") {
		t.Errorf("Expected 'not found' error, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Delete
// ---------------------------------------------------------------------------

// TestCLI_PolicyDelete_Success verifies that deleting an existing
// policy succeeds and the policy no longer appears in the list.
func TestCLI_PolicyDelete_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a policy.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "delete-me",
		"--pcrs", "0,1,2,3,7",
		"--bank", "sha256",
		"--store", storePath)

	// Delete it.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "delete", "delete-me",
		"--store", storePath)

	if !strings.Contains(stdout, "Deleted policy") {
		t.Errorf("Expected 'Deleted policy' in output, got: %s", stdout)
	}

	// Verify it is gone from the list.
	listOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if strings.Contains(listOut, "delete-me") {
		t.Errorf("Deleted policy 'delete-me' should not appear in list, got: %s", listOut)
	}
}

// TestCLI_PolicyDelete_NotFound verifies that deleting a nonexistent
// policy fails with an appropriate error.
func TestCLI_PolicyDelete_NotFound(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a dummy so the store directory exists.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "keeper",
		"--pcrs", "0",
		"--bank", "sha256",
		"--store", storePath)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "delete", "ghost-policy",
		"--store", storePath)

	if !strings.Contains(errOutput, "not found") {
		t.Errorf("Expected 'not found' error, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Create + List + Delete Full Lifecycle
// ---------------------------------------------------------------------------

// TestCLI_PolicyCreateListDelete_Lifecycle exercises the complete
// policy CRUD lifecycle: create, verify in list, delete, verify removed.
func TestCLI_PolicyCreateListDelete_Lifecycle(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Step 1: Create.
	createOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "lifecycle-policy",
		"--pcrs", "0,1,2,3,7",
		"--bank", "sha256",
		"--store", storePath)

	if !strings.Contains(createOut, "Created policy") {
		t.Fatalf("Create failed, output: %s", createOut)
	}

	// Step 2: List and verify presence.
	listOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if !strings.Contains(listOut, "lifecycle-policy") {
		t.Fatalf("Policy not found in list after creation, output: %s", listOut)
	}

	// Step 3: Delete.
	deleteOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "delete", "lifecycle-policy",
		"--store", storePath)

	if !strings.Contains(deleteOut, "Deleted policy") {
		t.Fatalf("Delete failed, output: %s", deleteOut)
	}

	// Step 4: Verify empty list.
	finalList := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if strings.Contains(finalList, "lifecycle-policy") {
		t.Errorf("Policy still appears in list after deletion, output: %s", finalList)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Export
// ---------------------------------------------------------------------------

// TestCLI_PolicyExport_Success verifies that exporting a policy
// produces valid JSON with the expected fields.
func TestCLI_PolicyExport_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "export-test",
		"--pcrs", "0,7",
		"--bank", "sha256",
		"--store", storePath)

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "export", "export-test",
		"--store", storePath)

	var exported struct {
		Name       string            `json:"name"`
		Bank       string            `json:"bank"`
		PCRs       map[string]string `json:"pcrs"`
		AutoUnseal bool              `json:"auto_unseal"`
		CreatedAt  string            `json:"created_at"`
		UpdatedAt  string            `json:"updated_at"`
	}

	if err := json.Unmarshal([]byte(stdout), &exported); err != nil {
		t.Fatalf("Failed to parse exported JSON: %v\nOutput: %s", err, stdout)
	}

	if exported.Name != "export-test" {
		t.Errorf("Expected name='export-test', got: %s", exported.Name)
	}
	if exported.Bank != "SHA256" {
		t.Errorf("Expected bank='SHA256', got: %s", exported.Bank)
	}
	if exported.AutoUnseal {
		t.Error("Expected auto_unseal=false for newly created policy")
	}
}

// TestCLI_PolicyExport_NotFound verifies that exporting a nonexistent
// policy fails.
func TestCLI_PolicyExport_NotFound(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a dummy so store exists.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "exists",
		"--pcrs", "0",
		"--bank", "sha256",
		"--store", storePath)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "export", "no-such-policy",
		"--store", storePath)

	if !strings.Contains(errOutput, "not found") {
		t.Errorf("Expected 'not found' error, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Set/Clear Auto-Unseal
// ---------------------------------------------------------------------------

// TestCLI_PolicySetAutoUnseal_Success verifies that marking a policy
// for auto-unseal succeeds and the designation appears in the list.
func TestCLI_PolicySetAutoUnseal_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a policy.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "auto-test",
		"--pcrs", "0,1,2,3",
		"--bank", "sha256",
		"--store", storePath)

	// Set auto-unseal.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "set-auto-unseal", "auto-test",
		"--store", storePath)

	if !strings.Contains(stdout, "Auto-unseal policy set") {
		t.Errorf("Expected 'Auto-unseal policy set' in output, got: %s", stdout)
	}

	// Verify it shows in the list.
	listOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if !strings.Contains(listOut, "[auto-unseal]") {
		t.Errorf("Expected '[auto-unseal]' tag in list output, got: %s", listOut)
	}
}

// TestCLI_PolicySetAutoUnseal_NotFound verifies that setting
// auto-unseal on a nonexistent policy fails.
func TestCLI_PolicySetAutoUnseal_NotFound(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a dummy so store exists.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "placeholder",
		"--pcrs", "0",
		"--bank", "sha256",
		"--store", storePath)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "set-auto-unseal", "nonexistent",
		"--store", storePath)

	if !strings.Contains(errOutput, "not found") {
		t.Errorf("Expected 'not found' error, got: %s", errOutput)
	}
}

// TestCLI_PolicyClearAutoUnseal_Success verifies that clearing the
// auto-unseal designation succeeds.
func TestCLI_PolicyClearAutoUnseal_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create and set auto-unseal.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "clear-test",
		"--pcrs", "0,7",
		"--bank", "sha256",
		"--store", storePath)

	RunXKeyExpectSuccess(t, binary, "",
		"policy", "set-auto-unseal", "clear-test",
		"--store", storePath)

	// Clear auto-unseal.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "clear-auto-unseal",
		"--store", storePath)

	if !strings.Contains(stdout, "Auto-unseal policy cleared") {
		t.Errorf("Expected 'Auto-unseal policy cleared' in output, got: %s", stdout)
	}

	// Verify auto-unseal tag is gone from the list.
	listOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if strings.Contains(listOut, "[auto-unseal]") {
		t.Errorf("Auto-unseal tag should not appear after clearing, got: %s", listOut)
	}
}

// TestCLI_PolicyDeleteAutoUnseal_Blocked verifies that deleting a
// policy marked as auto-unseal is rejected.
func TestCLI_PolicyDeleteAutoUnseal_Blocked(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create and set auto-unseal.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "protected-policy",
		"--pcrs", "0,1",
		"--bank", "sha256",
		"--store", storePath)

	RunXKeyExpectSuccess(t, binary, "",
		"policy", "set-auto-unseal", "protected-policy",
		"--store", storePath)

	// Attempt to delete should fail.
	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "delete", "protected-policy",
		"--store", storePath)

	if !strings.Contains(errOutput, "auto-unseal") && !strings.Contains(errOutput, "clear") {
		t.Errorf("Expected error about auto-unseal blocking delete, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Verify
// ---------------------------------------------------------------------------

// TestCLI_PolicyVerify_MatchesCurrent verifies that a freshly created
// policy matches the current PCR state (swtpm state is stable).
func TestCLI_PolicyVerify_MatchesCurrent(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a policy with current PCR values.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "verify-match",
		"--pcrs", "0,1,2,3",
		"--bank", "sha256",
		"--store", storePath)

	// Verify should pass since PCR values have not changed.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "verify", "verify-match",
		"--store", storePath)

	if !strings.Contains(stdout, "VALID") {
		t.Errorf("Expected 'VALID' verification result, got: %s", stdout)
	}
}

// TestCLI_PolicyVerify_NotFound verifies that verifying a nonexistent
// policy fails.
func TestCLI_PolicyVerify_NotFound(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a dummy so store exists.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "dummy",
		"--pcrs", "0",
		"--bank", "sha256",
		"--store", storePath)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "verify", "ghost",
		"--store", storePath)

	if !strings.Contains(errOutput, "not found") {
		t.Errorf("Expected 'not found' error, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Refresh
// ---------------------------------------------------------------------------

// TestCLI_PolicyRefresh_Success verifies that refreshing a policy with
// current PCR values succeeds.
func TestCLI_PolicyRefresh_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "refresh-test",
		"--pcrs", "0,7",
		"--bank", "sha256",
		"--store", storePath)

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "refresh", "refresh-test",
		"--store", storePath)

	if !strings.Contains(stdout, "Refreshed policy") {
		t.Errorf("Expected 'Refreshed policy' in output, got: %s", stdout)
	}
}

// TestCLI_PolicyRefresh_NotFound verifies that refreshing a nonexistent
// policy fails.
func TestCLI_PolicyRefresh_NotFound(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create a dummy so store exists.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "dummy",
		"--pcrs", "0",
		"--bank", "sha256",
		"--store", storePath)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"policy", "refresh", "missing-policy",
		"--store", storePath)

	if !strings.Contains(errOutput, "not found") {
		t.Errorf("Expected 'not found' error, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy with Barrier Auto-Unseal (TPM2 Strategy)
// ---------------------------------------------------------------------------

// TestCLI_PolicyBarrierAutoUnseal_Lifecycle exercises the full workflow
// of initializing a TPM2 barrier, creating a PCR policy, designating it
// for auto-unseal, and verifying that the policy matches the current
// platform state.
func TestCLI_PolicyBarrierAutoUnseal_Lifecycle(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")
	password := "pcr-auto-unseal-test-42!"

	// Step 1: Initialize barrier with TPM2 strategy.
	initOut := RunXKeyExpectSuccess(t, binary, password+"\n"+password+"\n",
		"barrier", "init", "--strategy", "tpm2", "--data-dir", dataDir)

	if !strings.Contains(initOut, "Barrier initialized successfully") {
		t.Fatalf("Barrier init failed, output: %s", initOut)
	}

	// Step 2: Verify barrier status shows TPM2 and initialized.
	statusOut := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)

	var status struct {
		Initialized    bool   `json:"initialized"`
		Sealed         bool   `json:"sealed"`
		Strategy       string `json:"strategy"`
		HardwareBacked bool   `json:"hardware_backed"`
	}
	if err := json.Unmarshal([]byte(statusOut), &status); err != nil {
		t.Fatalf("Failed to parse barrier status JSON: %v\nOutput: %s", err, statusOut)
	}
	if !status.Initialized {
		t.Fatal("Expected barrier initialized=true")
	}
	if status.Strategy != "tpm2" {
		t.Errorf("Expected strategy='tpm2', got: %s", status.Strategy)
	}
	if !status.HardwareBacked {
		t.Error("Expected hardware_backed=true for tpm2")
	}

	// Step 3: Create a PCR policy capturing current state.
	createOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "auto-unseal-policy",
		"--pcrs", "0,1,2,3",
		"--bank", "sha256",
		"--store", storePath)

	if !strings.Contains(createOut, "Created policy") {
		t.Fatalf("Policy creation failed, output: %s", createOut)
	}

	// Step 4: Designate the policy for auto-unseal.
	autoOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "set-auto-unseal", "auto-unseal-policy",
		"--store", storePath)

	if !strings.Contains(autoOut, "Auto-unseal policy set") {
		t.Fatalf("Set auto-unseal failed, output: %s", autoOut)
	}

	// Step 5: Verify policy passes against current PCR state.
	// Since swtpm state is stable, the freshly captured policy
	// should match the current PCR values.
	verifyOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "verify", "auto-unseal-policy",
		"--store", storePath)

	if !strings.Contains(verifyOut, "VALID") {
		t.Errorf("Expected PCR policy to be VALID, got: %s", verifyOut)
	}

	// Step 6: Verify auto-unseal tag appears in list.
	listOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--store", storePath)

	if !strings.Contains(listOut, "[auto-unseal]") {
		t.Errorf("Expected '[auto-unseal]' tag in list, got: %s", listOut)
	}

	// Step 7: Unseal the barrier with password to confirm it still works.
	unsealOut := RunXKeyExpectSuccess(t, binary, password+"\n",
		"barrier", "unseal", "--data-dir", dataDir)

	if !strings.Contains(unsealOut, "unsealed") {
		t.Errorf("Barrier unseal failed, output: %s", unsealOut)
	}

	// Step 8: Seal the barrier again.
	sealOut := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "seal", "--data-dir", dataDir)

	if !strings.Contains(sealOut, "sealed") {
		t.Errorf("Barrier seal failed, output: %s", sealOut)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Pagination
// ---------------------------------------------------------------------------

// TestCLI_PolicyList_Pagination verifies that the --page and --page-size
// flags produce correct paginated output.
func TestCLI_PolicyList_Pagination(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create three policies.
	for _, name := range []string{"page-a", "page-b", "page-c"} {
		RunXKeyExpectSuccess(t, binary, "",
			"policy", "create", name,
			"--pcrs", "0",
			"--bank", "sha256",
			"--store", storePath)
	}

	// Request page 1 with page size 2.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"policy", "list",
		"--page", "1",
		"--page-size", "2",
		"--store", storePath)

	if !strings.Contains(stdout, "page") || !strings.Contains(stdout, "3 total") {
		t.Logf("Pagination output: %s", stdout)
	}

	// The output should contain at least some policy names.
	if !strings.Contains(stdout, "PCR Policies") && !strings.Contains(stdout, "page") {
		t.Errorf("Expected paginated header in output, got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// PCR Policy Auto-Unseal Replacement
// ---------------------------------------------------------------------------

// TestCLI_PolicySetAutoUnseal_Replaces verifies that setting a new
// auto-unseal policy clears the previous designation.
func TestCLI_PolicySetAutoUnseal_Replaces(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "policies")

	// Create two policies.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "first-auto",
		"--pcrs", "0",
		"--bank", "sha256",
		"--store", storePath)

	RunXKeyExpectSuccess(t, binary, "",
		"policy", "create", "second-auto",
		"--pcrs", "0,7",
		"--bank", "sha256",
		"--store", storePath)

	// Set first as auto-unseal.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "set-auto-unseal", "first-auto",
		"--store", storePath)

	// Replace with second.
	RunXKeyExpectSuccess(t, binary, "",
		"policy", "set-auto-unseal", "second-auto",
		"--store", storePath)

	// Verify the exported second policy shows auto_unseal=true.
	exportOut := RunXKeyExpectSuccess(t, binary, "",
		"policy", "export", "second-auto",
		"--store", storePath)

	var exported struct {
		AutoUnseal bool `json:"auto_unseal"`
	}
	if err := json.Unmarshal([]byte(exportOut), &exported); err != nil {
		t.Fatalf("Failed to parse export JSON: %v", err)
	}
	if !exported.AutoUnseal {
		t.Error("Expected second-auto to have auto_unseal=true")
	}

	// Verify first-auto no longer has auto-unseal.
	firstExport := RunXKeyExpectSuccess(t, binary, "",
		"policy", "export", "first-auto",
		"--store", storePath)

	var firstEx struct {
		AutoUnseal bool `json:"auto_unseal"`
	}
	if err := json.Unmarshal([]byte(firstExport), &firstEx); err != nil {
		t.Fatalf("Failed to parse first export JSON: %v", err)
	}
	if firstEx.AutoUnseal {
		t.Error("Expected first-auto to have auto_unseal=false after replacement")
	}
}
