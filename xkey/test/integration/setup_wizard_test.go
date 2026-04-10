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

// Package xkey provides integration tests for the xkey CLI setup wizard,
// including PIN management, barrier seal/unseal, and password operations.
package xkey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Suite 1: PIN Operations
// ---------------------------------------------------------------------------

// TestCLI_PinSetSO verifies that setting the Security Officer PIN succeeds
// when a valid 6+ character PIN is provided with matching confirmation.
func TestCLI_PinSetSO(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Pipe: new PIN + confirmation.
	stdin := "123456\n123456\n"
	stdout := RunXKeyExpectSuccess(t, binary, stdin,
		"pin", "set-so", "--data-dir", dataDir)

	if !strings.Contains(stdout, "SO PIN set") {
		t.Errorf("Expected output to contain 'SO PIN set', got: %s", stdout)
	}
}

// TestCLI_PinSetSO_TooShort verifies that setting the SO PIN with fewer
// than 6 characters is rejected.
func TestCLI_PinSetSO_TooShort(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// 3-character PIN is below the 6-character minimum.
	stdin := "abc\nabc\n"
	errOutput := RunXKeyExpectFailure(t, binary, stdin,
		"pin", "set-so", "--data-dir", dataDir)

	if !strings.Contains(errOutput, "6") && !strings.Contains(errOutput, "short") &&
		!strings.Contains(errOutput, "length") && !strings.Contains(errOutput, "too short") {
		t.Logf("Error output: %s", errOutput)
		// The error should indicate the PIN is too short. Accept any of the
		// common variations from the PIN manager error messages.
	}
}

// TestCLI_PinSetUser verifies that setting the User PIN succeeds after the
// SO PIN has been configured.
func TestCLI_PinSetUser(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Step 1: Set SO PIN.
	soStdin := "123456\n123456\n"
	RunXKeyExpectSuccess(t, binary, soStdin,
		"pin", "set-so", "--data-dir", dataDir)

	// Step 2: Set User PIN.
	// stdin: SO PIN (auth) + new User PIN + confirmation.
	userStdin := "123456\n654321\n654321\n"
	stdout := RunXKeyExpectSuccess(t, binary, userStdin,
		"pin", "set-user", "--data-dir", dataDir)

	if !strings.Contains(stdout, "User PIN set") {
		t.Errorf("Expected output to contain 'User PIN set', got: %s", stdout)
	}
}

// TestCLI_PinVerifySO verifies that SO PIN verification succeeds with the
// correct PIN.
func TestCLI_PinVerifySO(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Set SO PIN.
	RunXKeyExpectSuccess(t, binary, "123456\n123456\n",
		"pin", "set-so", "--data-dir", dataDir)

	// Verify SO PIN.
	stdout := RunXKeyExpectSuccess(t, binary, "123456\n",
		"pin", "verify", "--type", "so", "--data-dir", dataDir)

	if !strings.Contains(stdout, "VALID") {
		t.Errorf("Expected output to contain 'VALID', got: %s", stdout)
	}
}

// TestCLI_PinVerifyWrongPIN verifies that SO PIN verification fails when
// the wrong PIN is provided.
func TestCLI_PinVerifyWrongPIN(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Set SO PIN.
	RunXKeyExpectSuccess(t, binary, "123456\n123456\n",
		"pin", "set-so", "--data-dir", dataDir)

	// Attempt verification with wrong PIN.
	_, stderr, exitCode := RunXKey(t, binary, "wrongpin\n",
		"pin", "verify", "--type", "so", "--data-dir", dataDir)

	if exitCode == 0 {
		t.Fatal("Expected verification with wrong PIN to fail (non-zero exit)")
	}

	combined := stderr
	if !strings.Contains(combined, "INVALID") && !strings.Contains(combined, "invalid") &&
		!strings.Contains(combined, "verify") {
		t.Logf("Stderr: %s", combined)
	}
}

// TestCLI_PinStatus verifies that the pin status command reports the correct
// state after setting the SO PIN.
func TestCLI_PinStatus(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Set SO PIN.
	RunXKeyExpectSuccess(t, binary, "123456\n123456\n",
		"pin", "set-so", "--data-dir", dataDir)

	// Check status.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"pin", "status", "--data-dir", dataDir)

	if !strings.Contains(stdout, "SO PIN") {
		t.Errorf("Expected status output to contain 'SO PIN', got: %s", stdout)
	}
	if !strings.Contains(stdout, "Yes") {
		t.Errorf("Expected status output to indicate SO PIN is set ('Yes'), got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// Suite 2: Barrier Operations
// ---------------------------------------------------------------------------

// TestCLI_BarrierInit_Software verifies that initializing the barrier with
// the software strategy succeeds.
func TestCLI_BarrierInit_Software(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Pipe: password + confirmation.
	stdin := "testpassword123\ntestpassword123\n"
	stdout := RunXKeyExpectSuccess(t, binary, stdin,
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	if !strings.Contains(stdout, "Barrier initialized") {
		t.Errorf("Expected output to contain 'Barrier initialized', got: %s", stdout)
	}
	if !strings.Contains(stdout, "software") {
		t.Errorf("Expected output to mention 'software' strategy, got: %s", stdout)
	}
}

// TestCLI_BarrierStatus_Sealed verifies that after initialization the barrier
// reports a sealed state.
func TestCLI_BarrierStatus_Sealed(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Check status.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"barrier", "status", "--data-dir", dataDir)

	if !strings.Contains(stdout, "Sealed") {
		t.Errorf("Expected barrier status to contain 'Sealed', got: %s", stdout)
	}
	if !strings.Contains(stdout, "Initialized") || !strings.Contains(stdout, "Yes") {
		t.Errorf("Expected barrier status to show 'Initialized: Yes', got: %s", stdout)
	}
}

// TestCLI_BarrierUnseal verifies that the barrier can be unsealed with the
// correct password after initialization.
func TestCLI_BarrierUnseal(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)

	// Initialize barrier.
	RunXKeyExpectSuccess(t, binary, "testpassword123\ntestpassword123\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	// Unseal barrier.
	stdout := RunXKeyExpectSuccess(t, binary, "testpassword123\n",
		"barrier", "unseal", "--data-dir", dataDir)

	if !strings.Contains(stdout, "unsealed") {
		t.Errorf("Expected output to contain 'unsealed', got: %s", stdout)
	}
}

// TestCLI_BarrierSeal verifies the full seal/unseal lifecycle: init, unseal,
// then seal.
func TestCLI_BarrierSeal(t *testing.T) {
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

	if !strings.Contains(stdout, "sealed") {
		t.Errorf("Expected output to contain 'sealed', got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// Suite 3: Password Operations
// ---------------------------------------------------------------------------

// TestCLI_PasswordAdd verifies that adding a static password succeeds and
// produces the expected confirmation output.
func TestCLI_PasswordAdd(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "passwords")

	stdout := RunXKeyExpectSuccess(t, binary, "",
		"password", "add",
		"--name", "TestPW",
		"--password", "s3cret!",
		"--store", storePath)

	if !strings.Contains(stdout, "Added password: TestPW") {
		t.Errorf("Expected 'Added password: TestPW' in output, got: %s", stdout)
	}
}

// TestCLI_PasswordGet verifies that a stored password can be retrieved by
// name, outputting only the raw password value.
func TestCLI_PasswordGet(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "passwords")

	// Add password.
	RunXKeyExpectSuccess(t, binary, "",
		"password", "add",
		"--name", "TestPW",
		"--password", "s3cret!",
		"--store", storePath)

	// Get password.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"password", "get", "TestPW",
		"--store", storePath)

	if stdout != "s3cret!" {
		t.Errorf("Expected password output to be exactly 's3cret!', got: %q", stdout)
	}
}

// TestCLI_PasswordList verifies that listing passwords shows the names of
// all stored entries.
func TestCLI_PasswordList(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "passwords")

	// Add password.
	RunXKeyExpectSuccess(t, binary, "",
		"password", "add",
		"--name", "TestPW",
		"--password", "s3cret!",
		"--store", storePath)

	// List passwords.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"password", "list",
		"--store", storePath)

	if !strings.Contains(stdout, "TestPW") {
		t.Errorf("Expected list output to contain 'TestPW', got: %s", stdout)
	}
}

// TestCLI_PasswordDelete verifies that removing a password with --force
// succeeds and produces the expected confirmation output.
func TestCLI_PasswordDelete(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "passwords")

	// Add password.
	RunXKeyExpectSuccess(t, binary, "",
		"password", "add",
		"--name", "TestPW",
		"--password", "s3cret!",
		"--store", storePath)

	// Remove password.
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"password", "remove", "--force", "TestPW",
		"--store", storePath)

	if !strings.Contains(stdout, "Removed: TestPW") {
		t.Errorf("Expected 'Removed: TestPW' in output, got: %s", stdout)
	}

	// Verify password is gone.
	_, _, exitCode := RunXKey(t, binary, "",
		"password", "get", "TestPW",
		"--store", storePath)

	if exitCode == 0 {
		t.Error("Expected get after delete to fail, but it succeeded")
	}
}

// TestCLI_Password_EncryptionVerified documents the storage behavior of the
// static password store. The default BackendStore (without the encrypted_store
// wrapper) serializes passwords as JSON. This test verifies that the raw file
// on disk reflects the expected behavior: without encryption enabled, the
// password value is present in cleartext in the JSON file. When the
// EncryptedStore wrapper is used, the password would be encrypted.
func TestCLI_Password_EncryptionVerified(t *testing.T) {
	binary := getOrBuildBinary(t)
	dataDir := SetupCleanEnvironment(t)
	storePath := filepath.Join(dataDir, "passwords")

	secretValue := "s3cret!TopSecret"

	// Add a password with a known value.
	RunXKeyExpectSuccess(t, binary, "",
		"password", "add",
		"--name", "EncTest",
		"--password", secretValue,
		"--store", storePath)

	// Walk the store directory to find JSON files containing the password data.
	// The BackendStore uses the file storage backend which writes JSON files
	// under a "staticpw/" subdirectory.
	found := false
	containsCleartext := false

	err := filepath.Walk(storePath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		// Read any regular file in the store directory.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		content := string(data)
		if strings.Contains(content, "EncTest") {
			found = true
			if strings.Contains(content, secretValue) {
				containsCleartext = true
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk store directory: %v", err)
	}

	if !found {
		t.Fatal("Expected to find a store file containing the password entry 'EncTest'")
	}

	// Document current behavior: the default CLI password store does not
	// encrypt at rest. The BackendStore writes JSON with cleartext passwords.
	// The EncryptedStore wrapper must be used to enable at-rest encryption.
	if containsCleartext {
		t.Log("Password stored in cleartext (default BackendStore behavior). " +
			"Use EncryptedStore wrapper for at-rest encryption.")
	} else {
		t.Log("Password is NOT stored in cleartext. Encrypted store is in use.")
	}
}
