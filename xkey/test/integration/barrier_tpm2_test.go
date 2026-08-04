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

// Package xkey provides integration tests for the xkey CLI barrier commands
// using the TPM2 sealing strategy. These tests require an ephemeral swtpm
// instance (started and provisioned once per test binary by
// swtpmDevicePath, see swtpm_test_helpers.go) exposed as a unix-socket
// device via --tpm-device. swtpm is used instead of --tpm-simulator because
// swtpm is a persistent external TPM emulator whose state is shared by every
// "xkey" CLI subprocess that connects to it -- exactly like real hardware --
// whereas the in-process go-tpm-tools simulator behind --tpm-simulator
// starts a brand-new blank virtual TPM in every process and so cannot
// support a multi-step (init -> unseal -> seal) CLI workflow.
package xkey

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Barrier Init - TPM2 Strategy
// ---------------------------------------------------------------------------

// TestCLI_BarrierInit_TPM2_Success verifies that initializing the barrier
// with the tpm2 strategy succeeds against the shared swtpm instance.
func TestCLI_BarrierInit_TPM2_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	device := swtpmDevicePath(t)

	// TPM2 strategy still requires a password for the sealed root key blob.
	stdin := "tpm2-test-password!\ntpm2-test-password!\n"
	stdout := RunXKeyExpectSuccess(t, binary, stdin,
		"barrier", "init", "--strategy", "tpm2", "--tpm-device", device, "--data-dir", dataDir)

	if !strings.Contains(stdout, "Barrier initialized successfully") {
		t.Errorf("Expected 'Barrier initialized successfully', got: %s", stdout)
	}
	if !strings.Contains(stdout, "tpm2") {
		t.Errorf("Expected output to mention 'tpm2' strategy, got: %s", stdout)
	}
}

// TestCLI_BarrierInit_TPM2_StatusShowsTPM2 verifies that after TPM2
// initialization, the status command reports Strategy: tpm2.
func TestCLI_BarrierInit_TPM2_StatusShowsTPM2(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	device := swtpmDevicePath(t)

	// Initialize with TPM2.
	stdin := "tpm2-test-password!\ntpm2-test-password!\n"
	RunXKeyExpectSuccess(t, binary, stdin,
		"barrier", "init", "--strategy", "tpm2", "--tpm-device", device, "--data-dir", dataDir)

	// Check human-readable status.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--data-dir", dataDir)

	if !strings.Contains(stdout, "tpm2") {
		t.Errorf("Expected status to show 'tpm2' strategy, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Yes") {
		t.Errorf("Expected status to show initialized 'Yes', got: %s", stdout)
	}
}

// TestCLI_BarrierInit_TPM2_StatusShowsHardwareBacked verifies that after
// TPM2 initialization, the JSON status reports hardware_backed=true.
func TestCLI_BarrierInit_TPM2_StatusShowsHardwareBacked(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	device := swtpmDevicePath(t)

	// Initialize with TPM2.
	stdin := "tpm2-test-password!\ntpm2-test-password!\n"
	RunXKeyExpectSuccess(t, binary, stdin,
		"barrier", "init", "--strategy", "tpm2", "--tpm-device", device, "--data-dir", dataDir)

	// Get JSON status.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)

	var status struct {
		Initialized    bool   `json:"initialized"`
		Sealed         bool   `json:"sealed"`
		Strategy       string `json:"strategy"`
		HardwareBacked bool   `json:"hardware_backed"`
	}

	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatalf("Failed to parse JSON status: %v\nOutput: %s", err, stdout)
	}

	if !status.Initialized {
		t.Error("Expected initialized=true")
	}
	if status.Strategy != "tpm2" {
		t.Errorf("Expected strategy='tpm2', got: %s", status.Strategy)
	}
	if !status.HardwareBacked {
		t.Error("Expected hardware_backed=true for tpm2 strategy")
	}
}

// ---------------------------------------------------------------------------
// Barrier Init - Auto-detect Strategy (Hardware-first, swtpm-backed)
// ---------------------------------------------------------------------------

// TestCLI_BarrierInit_AutoDetect verifies that omitting the --strategy flag
// auto-selects the best available strategy: tpm2 when a TPM 2.0 device is
// available (hardware-first, matching the GUI and the documented preference
// order), otherwise software. --tpm-device points at the shared swtpm
// instance so this test never depends on, or touches, host TPM hardware.
func TestCLI_BarrierInit_AutoDetect(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	device := swtpmDevicePath(t)

	stdin := "autodetect-test-pw!\nautodetect-test-pw!\n"
	stdout := RunXKeyExpectSuccess(t, binary, stdin,
		"barrier", "init", "--tpm-device", device, "--data-dir", dataDir)

	if !strings.Contains(stdout, "Barrier initialized successfully") {
		t.Errorf("Expected success message, got: %s", stdout)
	}
	if !strings.Contains(stdout, "tpm2") {
		t.Errorf("Expected auto-detect to select the tpm2 strategy, got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// Barrier Unseal - TPM2 Strategy
// ---------------------------------------------------------------------------

// TestCLI_BarrierUnseal_TPM2_Success verifies that unsealing a TPM2-sealed
// barrier with the correct password succeeds.
func TestCLI_BarrierUnseal_TPM2_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	device := swtpmDevicePath(t)

	password := "tpm2-unseal-test!"

	// Initialize with TPM2.
	RunXKeyExpectSuccess(t, binary, password+"\n"+password+"\n",
		"barrier", "init", "--strategy", "tpm2", "--tpm-device", device, "--data-dir", dataDir)

	// Unseal.
	stdout := RunXKeyExpectSuccess(t, binary, password+"\n",
		"barrier", "unseal", "--tpm-device", device, "--data-dir", dataDir)

	if !strings.Contains(stdout, "unsealed successfully") {
		t.Errorf("Expected 'unsealed successfully', got: %s", stdout)
	}
}

// TestCLI_BarrierUnseal_TPM2_WrongPassword verifies that unsealing a
// TPM2-sealed barrier with the wrong password fails.
func TestCLI_BarrierUnseal_TPM2_WrongPassword(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	device := swtpmDevicePath(t)

	// Initialize with TPM2.
	RunXKeyExpectSuccess(t, binary, "correct-tpm2-pw\ncorrect-tpm2-pw\n",
		"barrier", "init", "--strategy", "tpm2", "--tpm-device", device, "--data-dir", dataDir)

	// Attempt unseal with wrong password.
	errOutput := RunXKeyExpectFailure(t, binary, "wrong-tpm2-pw\n",
		"barrier", "unseal", "--tpm-device", device, "--data-dir", dataDir)

	if !strings.Contains(errOutput, "unseal") && !strings.Contains(errOutput, "decrypt") &&
		!strings.Contains(errOutput, "failed") {
		t.Logf("Error output: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// Barrier Full Lifecycle - TPM2 Strategy
// ---------------------------------------------------------------------------

// TestCLI_BarrierFullLifecycle_TPM2 exercises the complete barrier lifecycle
// with the TPM2 strategy: init -> unseal -> seal -> unseal again.
func TestCLI_BarrierFullLifecycle_TPM2(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	device := swtpmDevicePath(t)

	password := "tpm2-lifecycle-pw-42!"

	// Step 1: Initialize.
	initOut := RunXKeyExpectSuccess(t, binary, password+"\n"+password+"\n",
		"barrier", "init", "--strategy", "tpm2", "--tpm-device", device, "--data-dir", dataDir)
	if !strings.Contains(initOut, "Barrier initialized successfully") {
		t.Fatalf("Init failed, output: %s", initOut)
	}

	// Step 2: Verify status shows TPM2 strategy.
	statusOut := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--json", "--data-dir", dataDir)
	var status struct {
		Strategy       string `json:"strategy"`
		HardwareBacked bool   `json:"hardware_backed"`
	}
	if err := json.Unmarshal([]byte(statusOut), &status); err != nil {
		t.Fatalf("Failed to parse status JSON: %v", err)
	}
	if status.Strategy != "tpm2" {
		t.Errorf("Expected strategy='tpm2', got: %s", status.Strategy)
	}
	if !status.HardwareBacked {
		t.Error("Expected hardware_backed=true for tpm2")
	}

	// Step 3: Unseal.
	unsealOut := RunXKeyExpectSuccess(t, binary, password+"\n",
		"barrier", "unseal", "--tpm-device", device, "--data-dir", dataDir)
	if !strings.Contains(unsealOut, "unsealed") {
		t.Fatalf("Unseal failed, output: %s", unsealOut)
	}

	// Step 4: Seal.
	sealOut := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "seal", "--tpm-device", device, "--data-dir", dataDir)
	if !strings.Contains(sealOut, "sealed") {
		t.Fatalf("Seal failed, output: %s", sealOut)
	}

	// Step 5: Re-unseal to verify the barrier can be unlocked again.
	reUnsealOut := RunXKeyExpectSuccess(t, binary, password+"\n",
		"barrier", "unseal", "--tpm-device", device, "--data-dir", dataDir)
	if !strings.Contains(reUnsealOut, "unsealed") {
		t.Errorf("Re-unseal failed, output: %s", reUnsealOut)
	}
}
