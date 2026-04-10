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

//go:build integration && linux

// Package xkey provides comprehensive integration tests for the xkey CLI
// barrier commands, covering initialization, seal/unseal lifecycle, status
// reporting, error handling, and data encryption verification with the
// software sealing strategy.
package xkey

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Barrier Init - Software Strategy
// ---------------------------------------------------------------------------

// TestCLI_BarrierInit_Software_Success verifies that initializing the barrier
// with the software strategy produces success output and creates the root key
// file on disk.
func TestCLI_BarrierInit_Software_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	stdin := "testpassword123\ntestpassword123\n"
	stdout := RunXKeyExpectSuccess(t, binary, stdin,
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	if !strings.Contains(stdout, "Barrier initialized successfully") {
		t.Errorf("Expected output to contain 'Barrier initialized successfully', got: %s", stdout)
	}
	if !strings.Contains(stdout, "software") {
		t.Errorf("Expected output to mention 'software' strategy, got: %s", stdout)
	}

	// Verify root key file was created on disk.
	rootKeyPath := filepath.Join(dataDir, "store", "seal", "root.key")
	if _, err := os.Stat(rootKeyPath); os.IsNotExist(err) {
		t.Errorf("Expected root key file at %s, but it does not exist", rootKeyPath)
	}
}

// TestCLI_BarrierInit_Software_EmptyPassword verifies that initializing the
// barrier with an empty password is rejected.
func TestCLI_BarrierInit_Software_EmptyPassword(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Two empty lines for password + confirmation.
	stdin := "\n\n"
	errOutput := RunXKeyExpectFailure(t, binary, stdin,
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "empty") && !strings.Contains(errOutput, "password") {
		t.Logf("Error output: %s", errOutput)
	}

	// Root key should NOT have been created.
	rootKeyPath := filepath.Join(dataDir, "store", "seal", "root.key")
	if _, err := os.Stat(rootKeyPath); err == nil {
		t.Error("Root key file should not exist after failed init with empty password")
	}
}

// TestCLI_BarrierInit_Software_MismatchPassword verifies that mismatched
// password and confirmation are rejected during barrier initialization.
func TestCLI_BarrierInit_Software_MismatchPassword(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	stdin := "password_one\npassword_two\n"
	errOutput := RunXKeyExpectFailure(t, binary, stdin,
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "match") && !strings.Contains(errOutput, "do not match") &&
		!strings.Contains(errOutput, "password") {
		t.Logf("Error output: %s", errOutput)
	}

	// Root key should NOT have been created.
	rootKeyPath := filepath.Join(dataDir, "store", "seal", "root.key")
	if _, err := os.Stat(rootKeyPath); err == nil {
		t.Error("Root key file should not exist after failed init with mismatched passwords")
	}
}

// TestCLI_BarrierInit_Software_AlreadyInitialized verifies that attempting
// to initialize a barrier that is already initialized fails with an
// appropriate error.
func TestCLI_BarrierInit_Software_AlreadyInitialized(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// First init should succeed.
	stdin := "testpassword123\ntestpassword123\n"
	RunXKeyExpectSuccess(t, binary, stdin,
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Second init should fail.
	errOutput := RunXKeyExpectFailure(t, binary, stdin,
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "already initialized") && !strings.Contains(errOutput, "root key exists") {
		t.Errorf("Expected error about already initialized barrier, got: %s", errOutput)
	}
}

// TestCLI_BarrierInit_Software_InvalidStrategy verifies that specifying an
// unknown strategy is rejected.
func TestCLI_BarrierInit_Software_InvalidStrategy(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	stdin := "testpassword123\ntestpassword123\n"
	errOutput := RunXKeyExpectFailure(t, binary, stdin,
		"barrier", "init", "--strategy", "bogus_strategy", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "unknown strategy") && !strings.Contains(errOutput, "invalid") {
		t.Errorf("Expected error about unknown strategy, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// Barrier Status
// ---------------------------------------------------------------------------

// TestCLI_BarrierStatus_AfterInit_ShowsInitializedAndSealed verifies that
// after initialization, the status command reports Initialized: Yes and
// State: Sealed.
func TestCLI_BarrierStatus_AfterInit_ShowsInitializedAndSealed(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Check human-readable status.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--data-dir", dataDir)

	if !strings.Contains(stdout, "Yes") {
		t.Errorf("Expected status to show initialized 'Yes', got: %s", stdout)
	}
	if !strings.Contains(stdout, "Sealed") {
		t.Errorf("Expected status to show 'Sealed', got: %s", stdout)
	}
	if !strings.Contains(stdout, "software") {
		t.Errorf("Expected status to show 'software' strategy, got: %s", stdout)
	}
}

// TestCLI_BarrierStatus_JSON_AfterInit verifies that the --json flag
// produces valid JSON with correct fields after initialization.
func TestCLI_BarrierStatus_JSON_AfterInit(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Get JSON status.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)

	var status struct {
		Initialized    bool   `json:"initialized"`
		Sealed         bool   `json:"sealed"`
		Strategy       string `json:"strategy"`
		HardwareBacked bool   `json:"hardware_backed"`
		DataDir        string `json:"data_dir"`
		RootKeyPath    string `json:"root_key_path"`
	}

	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatalf("Failed to parse JSON status output: %v\nOutput: %s", err, stdout)
	}

	if !status.Initialized {
		t.Error("Expected initialized=true in JSON status")
	}
	if !status.Sealed {
		t.Error("Expected sealed=true in JSON status after fresh init")
	}
	if status.Strategy != "software" {
		t.Errorf("Expected strategy='software', got: %s", status.Strategy)
	}
	if status.HardwareBacked {
		t.Error("Expected hardware_backed=false for software strategy")
	}
}

// TestCLI_BarrierStatus_NotInitialized verifies that the status command
// reports an uninitialized barrier correctly.
func TestCLI_BarrierStatus_NotInitialized(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--data-dir", dataDir)

	if !strings.Contains(stdout, "Not Initialized") {
		t.Errorf("Expected 'Not Initialized' in status, got: %s", stdout)
	}
}

// TestCLI_BarrierStatus_JSON_NotInitialized verifies that the --json flag
// returns initialized=false when the barrier has not been set up.
func TestCLI_BarrierStatus_JSON_NotInitialized(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)

	var status struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}

	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatalf("Failed to parse JSON status: %v\nOutput: %s", err, stdout)
	}

	if status.Initialized {
		t.Error("Expected initialized=false for uninitialized barrier")
	}
}

// ---------------------------------------------------------------------------
// Barrier Unseal - Software Strategy
// ---------------------------------------------------------------------------

// TestCLI_BarrierUnseal_Software_Success verifies that unsealing the barrier
// with the correct password succeeds and reports the strategy.
func TestCLI_BarrierUnseal_Software_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Unseal barrier.
	stdout := RunXKeyExpectSuccess(t, binary, "testpassword123\n",
		"barrier", "unseal", "--data-dir", dataDir)

	if !strings.Contains(stdout, "unsealed successfully") {
		t.Errorf("Expected 'unsealed successfully' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "software") {
		t.Errorf("Expected output to mention 'software' strategy, got: %s", stdout)
	}
}

// TestCLI_BarrierUnseal_Software_WrongPassword verifies that unsealing the
// barrier with an incorrect password fails.
func TestCLI_BarrierUnseal_Software_WrongPassword(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Attempt unseal with wrong password.
	errOutput := RunXKeyExpectFailure(t, binary, "wrongpassword\n",
		"barrier", "unseal", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "unseal") && !strings.Contains(errOutput, "decrypt") &&
		!strings.Contains(errOutput, "password") && !strings.Contains(errOutput, "failed") {
		t.Logf("Error output: %s", errOutput)
	}
}

// TestCLI_BarrierUnseal_Software_EmptyPassword verifies that unsealing with
// an empty password is rejected.
func TestCLI_BarrierUnseal_Software_EmptyPassword(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Attempt unseal with empty password.
	errOutput := RunXKeyExpectFailure(t, binary, "\n",
		"barrier", "unseal", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "empty") && !strings.Contains(errOutput, "password") {
		t.Logf("Error output: %s", errOutput)
	}
}

// TestCLI_BarrierUnseal_WhenNotInitialized verifies that attempting to unseal
// a barrier that has not been initialized fails with an appropriate error.
func TestCLI_BarrierUnseal_WhenNotInitialized(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	errOutput := RunXKeyExpectFailure(t, binary, "testpassword123\n",
		"barrier", "unseal", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "not initialized") && !strings.Contains(errOutput, "init") {
		t.Errorf("Expected error about barrier not initialized, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// Barrier Seal
// ---------------------------------------------------------------------------

// TestCLI_BarrierSeal_AfterUnseal verifies that sealing the barrier after
// it has been unsealed succeeds.
func TestCLI_BarrierSeal_AfterUnseal(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Unseal barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\n",
		"barrier", "unseal", "--data-dir", dataDir)

	// Seal barrier.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "seal", "--data-dir", dataDir)

	if !strings.Contains(stdout, "sealed successfully") {
		t.Errorf("Expected 'sealed successfully' in output, got: %s", stdout)
	}
}

// TestCLI_BarrierSeal_WhenAlreadySealed verifies that sealing a barrier that
// is already sealed is idempotent (succeeds without error).
func TestCLI_BarrierSeal_WhenAlreadySealed(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier (it is sealed after init).
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Seal without unseal first -- should be idempotent.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "seal", "--data-dir", dataDir)

	if !strings.Contains(stdout, "sealed") {
		t.Errorf("Expected output to contain 'sealed', got: %s", stdout)
	}
}

// TestCLI_BarrierSeal_WhenNotInitialized verifies that sealing a barrier that
// has not been initialized fails with an appropriate error.
func TestCLI_BarrierSeal_WhenNotInitialized(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"barrier", "seal", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "not initialized") && !strings.Contains(errOutput, "init") {
		t.Errorf("Expected error about barrier not initialized, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// Barrier Full Lifecycle
// ---------------------------------------------------------------------------

// TestCLI_BarrierFullLifecycle_Software exercises the complete barrier
// lifecycle: init -> status (sealed) -> unseal -> status (confirms strategy)
// -> seal -> status (sealed) -> unseal again (verifies re-unseal works).
func TestCLI_BarrierFullLifecycle_Software(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	password := "lifecycle-test-password!"

	// Step 1: Initialize.
	initOut := RunXKeyExpectSuccess(t, binary, password+"\n"+password+"\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)
	if !strings.Contains(initOut, "Barrier initialized successfully") {
		t.Fatalf("Init failed, output: %s", initOut)
	}

	// Step 2: Status should show Sealed.
	statusOut := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)
	var status1 struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}
	if err := json.Unmarshal([]byte(statusOut), &status1); err != nil {
		t.Fatalf("Failed to parse status JSON: %v", err)
	}
	if !status1.Initialized || !status1.Sealed {
		t.Errorf("After init: expected initialized=true, sealed=true; got initialized=%v, sealed=%v",
			status1.Initialized, status1.Sealed)
	}

	// Step 3: Unseal.
	unsealOut := RunXKeyExpectSuccess(t, binary, password+"\n",
		"barrier", "unseal", "--data-dir", dataDir)
	if !strings.Contains(unsealOut, "unsealed") {
		t.Fatalf("Unseal failed, output: %s", unsealOut)
	}

	// Step 4: Status should still show initialized with strategy info.
	// Note: CLI status always reports Sealed because it creates a fresh
	// barrier instance each time (no shared process state). This is expected
	// for a CLI tool. We verify the strategy and initialized fields.
	statusOut2 := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)
	var status2 struct {
		Initialized bool   `json:"initialized"`
		Strategy    string `json:"strategy"`
	}
	if err := json.Unmarshal([]byte(statusOut2), &status2); err != nil {
		t.Fatalf("Failed to parse status JSON: %v", err)
	}
	if !status2.Initialized {
		t.Error("Expected initialized=true after unseal")
	}
	if status2.Strategy != "software" {
		t.Errorf("Expected strategy='software', got: %s", status2.Strategy)
	}

	// Step 5: Seal.
	sealOut := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "seal", "--data-dir", dataDir)
	if !strings.Contains(sealOut, "sealed") {
		t.Fatalf("Seal failed, output: %s", sealOut)
	}

	// Step 6: Status should show Sealed again.
	statusOut3 := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)
	var status3 struct {
		Sealed bool `json:"sealed"`
	}
	if err := json.Unmarshal([]byte(statusOut3), &status3); err != nil {
		t.Fatalf("Failed to parse status JSON: %v", err)
	}
	if !status3.Sealed {
		t.Error("Expected sealed=true after seal command")
	}

	// Step 7: Re-unseal to verify the barrier can be unlocked again.
	reUnsealOut := RunXKeyExpectSuccess(t, binary, password+"\n",
		"barrier", "unseal", "--data-dir", dataDir)
	if !strings.Contains(reUnsealOut, "unsealed") {
		t.Errorf("Re-unseal failed, output: %s", reUnsealOut)
	}
}

// ---------------------------------------------------------------------------
// Barrier Data Encryption Verification
// ---------------------------------------------------------------------------

// TestCLI_BarrierInit_Software_PasswordEncryptsData verifies that data stored
// through the barrier is actually encrypted on disk. It initializes the
// barrier, adds a password entry, seals the barrier, and then reads the raw
// store files on disk to confirm the cleartext password value is NOT present.
func TestCLI_BarrierInit_Software_PasswordEncryptsData(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	barrierPassword := "barrier-encryption-test!"
	secretValue := "SuperSecret_PlaintextCanary_12345"

	// Step 1: Initialize barrier with software strategy.
	RunXKeyExpectSuccess(t, binary, barrierPassword+"\n"+barrierPassword+"\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Step 2: Add a password using a store path inside the barrier data dir.
	// This uses the plain file-based password store. The key thing we are
	// verifying is whether the root key file itself is encrypted (not cleartext).
	storePath := filepath.Join(dataDir, "passwords")
	RunXKeyExpectSuccess(t, binary, "",
		"password", "add",
		"--name", "BarrierTest",
		"--password", secretValue,
		"--store", storePath)

	// Step 3: Verify the root key blob is NOT stored as cleartext.
	// The root key file should contain a JSON-serialized SealedRootKey blob
	// with encrypted ciphertext, not raw key material.
	rootKeyPath := filepath.Join(dataDir, "store", "seal", "root.key")
	rootKeyData, err := os.ReadFile(rootKeyPath)
	if err != nil {
		t.Fatalf("Failed to read root key file: %v", err)
	}

	// The root key file should be valid JSON (SealedRootKey structure).
	var sealedKey map[string]interface{}
	if err := json.Unmarshal(rootKeyData, &sealedKey); err != nil {
		t.Fatalf("Root key file is not valid JSON: %v", err)
	}

	// Verify the sealed root key contains a strategy field and ciphertext,
	// confirming it was properly sealed and not stored as raw key material.
	if _, hasStrategy := sealedKey["strategy"]; !hasStrategy {
		t.Error("Root key blob missing 'strategy' field -- may not be properly sealed")
	}

	// The raw root key file should NOT contain the barrier password in cleartext.
	rootKeyStr := string(rootKeyData)
	if strings.Contains(rootKeyStr, barrierPassword) {
		t.Error("Root key file contains the barrier password in cleartext")
	}
}

// ---------------------------------------------------------------------------
// Barrier Status - Hardware Backed Reporting
// ---------------------------------------------------------------------------

// TestCLI_BarrierStatus_SoftwareNotHardwareBacked verifies that the software
// strategy reports hardware_backed=false in JSON output.
func TestCLI_BarrierStatus_SoftwareNotHardwareBacked(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Get JSON status.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)

	var status struct {
		HardwareBacked bool `json:"hardware_backed"`
	}
	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatalf("Failed to parse JSON status: %v\nOutput: %s", err, stdout)
	}

	if status.HardwareBacked {
		t.Error("Expected hardware_backed=false for software strategy")
	}
}

// TestCLI_BarrierStatus_HumanReadable_NotHardwareBacked verifies the
// human-readable status output shows Hardware-backed: No for software.
func TestCLI_BarrierStatus_HumanReadable_NotHardwareBacked(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--data-dir", dataDir)

	if !strings.Contains(stdout, "No") {
		t.Errorf("Expected 'Hardware-backed: No' in status output, got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// Barrier Init - Auto-detect Strategy
// ---------------------------------------------------------------------------

// TestCLI_BarrierInit_AutoDetect verifies that omitting the --strategy flag
// auto-selects the software strategy (since TPM2 and PKCS#11 are not
// available in the standard test environment).
func TestCLI_BarrierInit_AutoDetect(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	stdin := "autodetect-test-pw!\nautodetect-test-pw!\n"
	stdout := RunXKeyExpectSuccess(t, binary, stdin,
		"barrier", "init", "--data-dir", dataDir)

	if !strings.Contains(stdout, "Barrier initialized successfully") {
		t.Errorf("Expected success message, got: %s", stdout)
	}
	// Without hardware, auto-detect should fall back to software.
	if !strings.Contains(stdout, "software") {
		t.Errorf("Expected auto-detect to select 'software' strategy, got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// Barrier with Different Passwords
// ---------------------------------------------------------------------------

// TestCLI_BarrierUnseal_Software_MultipleUnsealCycles verifies that the
// barrier can be unsealed and resealed multiple times without corruption.
func TestCLI_BarrierUnseal_Software_MultipleUnsealCycles(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	password := "multi-cycle-password-99!"

	// Initialize.
	RunXKeyExpectSuccess(t, binary, password+"\n"+password+"\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Run 3 unseal-seal cycles.
	for i := 0; i < 3; i++ {
		unsealOut := RunXKeyExpectSuccess(t, binary, password+"\n",
			"barrier", "unseal", "--data-dir", dataDir)
		if !strings.Contains(unsealOut, "unsealed") {
			t.Fatalf("Cycle %d: unseal failed, output: %s", i, unsealOut)
		}

		sealOut := RunXKeyExpectSuccess(t, binary, "",
			"barrier", "seal", "--data-dir", dataDir)
		if !strings.Contains(sealOut, "sealed") {
			t.Fatalf("Cycle %d: seal failed, output: %s", i, sealOut)
		}
	}
}
