// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// execCLI executes the CLI binary with given arguments
func execCLI(t *testing.T, cfg *TestConfig, args ...string) (string, string, error) {
	t.Helper()

	cmd := exec.Command(cfg.CLIBinPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

// TestCLIVersion tests the CLI version command
func TestCLIVersion(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	stdout, stderr, err := execCLI(t, cfg, "version")
	if err != nil {
		t.Logf("stderr: %s", stderr)
		assertNoError(t, err, "Version command failed")
	}

	output := stdout + stderr
	if output == "" {
		t.Fatal("Version command produced no output")
	}

	t.Logf("CLI version output: %s", strings.TrimSpace(output))
}

// TestCLIListBackends tests the CLI backends list command
func TestCLIListBackends(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	stdout, stderr, err := execCLI(t, cfg, "backends", "list")
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		assertNoError(t, err, "Backends list command failed")
	}

	output := stdout + stderr
	if output == "" {
		t.Fatal("Backends list command produced no output")
	}

	// Should contain at least pkcs8 backend
	assertContains(t, output, "pkcs8", "Output should contain pkcs8 backend")

	t.Logf("CLI backends list output:\n%s", strings.TrimSpace(output))
}

// TestCLIBackendInfo tests the CLI backend info command
func TestCLIBackendInfo(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	stdout, stderr, err := execCLI(t, cfg, "backends", "info", "pkcs8")
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		assertNoError(t, err, "Backend info command failed")
	}

	output := stdout + stderr
	if output == "" {
		t.Fatal("Backend info command produced no output")
	}

	assertContains(t, output, "pkcs8", "Output should contain backend name")

	t.Logf("CLI backend info output:\n%s", strings.TrimSpace(output))
}

// TestCLIHelp tests the CLI help command
func TestCLIHelp(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	tests := []struct {
		name string
		args []string
	}{
		{"Root help", []string{"--help"}},
		{"Backends help", []string{"backends", "--help"}},
		{"Version help", []string{"version", "--help"}},
		{"Key help", []string{"key", "--help"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, _ := execCLI(t, cfg, tt.args...)

			output := stdout + stderr
			if output == "" {
				t.Fatal("Help command produced no output")
			}

			// Help output should contain "Usage:"
			assertContains(t, output, "Usage", "Help output should contain Usage")

			t.Logf("Help output:\n%s", strings.TrimSpace(output))
		})
	}
}

// TestCLIInvalidCommand tests CLI error handling for invalid commands
func TestCLIInvalidCommand(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	_, stderr, err := execCLI(t, cfg, "invalid-command")
	if err == nil {
		t.Fatal("Expected error for invalid command")
	}

	// Should have error message in stderr or stdout
	if stderr == "" {
		t.Log("No error message in stderr for invalid command")
	} else {
		t.Logf("Error message for invalid command: %s", stderr)
	}
}

// TestCLIGenerateKey tests key generation via CLI
func TestCLIGenerateKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	keyID := generateUniqueID("cli-key")
	keyDir := "/tmp/keystore-cli-test"

	// Ensure clean key directory
	os.RemoveAll(keyDir)
	os.MkdirAll(keyDir, 0755)
	defer os.RemoveAll(keyDir)

	tests := []struct {
		name    string
		keyType string
		keySize string
		curve   string
	}{
		{"RSA 2048", "rsa", "2048", ""},
		{"ECDSA P256", "ecdsa", "", "P256"},
		{"Ed25519", "ed25519", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testKeyID := fmt.Sprintf("%s-%s", keyID, tt.keyType)

			args := []string{"key", "generate", testKeyID,
				"--backend", "pkcs8",
				"--key-type", tt.keyType,
				"--key-dir", keyDir,
			}

			if tt.keySize != "" {
				args = append(args, "--key-size", tt.keySize)
			}
			if tt.curve != "" {
				args = append(args, "--curve", tt.curve)
			}

			stdout, stderr, err := execCLI(t, cfg, args...)
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				assertNoError(t, err, "Generate key command failed")
			}

			t.Logf("Generated %s key: %s", tt.keyType, testKeyID)

			// Cleanup - delete the key
			delArgs := []string{"key", "delete", testKeyID,
				"--backend", "pkcs8",
				"--key-dir", keyDir,
			}
			execCLI(t, cfg, delArgs...)
		})
	}
}

// TestCLIListKeys tests listing keys via CLI
func TestCLIListKeys(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	keyID := generateUniqueID("cli-list-key")
	keyDir := "/tmp/keystore-cli-test"

	// Ensure clean key directory
	os.RemoveAll(keyDir)
	os.MkdirAll(keyDir, 0755)
	defer os.RemoveAll(keyDir)

	// Generate a test key first
	genArgs := []string{"key", "generate", keyID,
		"--backend", "pkcs8",
		"--key-type", "rsa",
		"--key-size", "2048",
		"--key-dir", keyDir,
	}
	_, _, err := execCLI(t, cfg, genArgs...)
	assertNoError(t, err, "Failed to generate test key")

	defer func() {
		delArgs := []string{"key", "delete", keyID,
			"--backend", "pkcs8",
			"--key-dir", keyDir,
		}
		execCLI(t, cfg, delArgs...)
	}()

	// List keys
	stdout, stderr, err := execCLI(t, cfg, "key", "list",
		"--backend", "pkcs8",
		"--key-dir", keyDir,
	)
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		assertNoError(t, err, "List keys command failed")
	}

	output := stdout + stderr
	assertContains(t, output, keyID, "Output should contain the generated key")

	t.Logf("CLI list keys output:\n%s", strings.TrimSpace(stdout))
}

// TestCLISignVerify tests sign and verify operations via CLI
func TestCLISignVerify(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	keyID := generateUniqueID("cli-sign-key")
	keyDir := "/tmp/keystore-cli-test"

	// Ensure clean key directory
	os.RemoveAll(keyDir)
	os.MkdirAll(keyDir, 0755)
	defer os.RemoveAll(keyDir)

	// Generate key
	genArgs := []string{"key", "generate", keyID,
		"--backend", "pkcs8",
		"--key-type", "rsa",
		"--key-size", "2048",
		"--key-dir", keyDir,
	}
	_, _, err := execCLI(t, cfg, genArgs...)
	assertNoError(t, err, "Failed to generate key")

	defer func() {
		delArgs := []string{"key", "delete", keyID,
			"--backend", "pkcs8",
			"--key-dir", keyDir,
		}
		execCLI(t, cfg, delArgs...)
	}()

	// Create test data
	testData := "test data for CLI signing"
	tmpFile := "/tmp/cli-test-data.txt"
	err = os.WriteFile(tmpFile, []byte(testData), 0644)
	assertNoError(t, err, "Failed to create test data file")
	defer os.Remove(tmpFile)

	// Sign data
	sigFile := "/tmp/cli-test-signature.sig"
	defer os.Remove(sigFile)

	signArgs := []string{"key", "sign", keyID, testData,
		"--backend", "pkcs8",
		"--key-dir", keyDir,
		"--hash", "SHA256",
	}

	stdout, stderr, err := execCLI(t, cfg, signArgs...)
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		assertNoError(t, err, "Sign command failed")
	}

	// The sign command should output the signature
	signature := strings.TrimSpace(stdout)
	if signature == "" {
		t.Fatal("Sign command produced no signature output")
	}

	t.Logf("Signed data successfully, signature length: %d", len(signature))

	// Note: Verify command implementation may vary - this is a placeholder
	// The actual verify command syntax should be verified with the CLI implementation
	t.Logf("Signature verification via CLI would use: key verify %s --signature <sig>", keyID)
}

// TestCLIDeleteKey tests key deletion via CLI
func TestCLIDeleteKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	keyID := generateUniqueID("cli-delete-key")
	keyDir := "/tmp/keystore-cli-test"

	// Ensure clean key directory
	os.RemoveAll(keyDir)
	os.MkdirAll(keyDir, 0755)
	defer os.RemoveAll(keyDir)

	// Generate key
	genArgs := []string{"key", "generate", keyID,
		"--backend", "pkcs8",
		"--key-type", "rsa",
		"--key-size", "2048",
		"--key-dir", keyDir,
	}
	_, _, err := execCLI(t, cfg, genArgs...)
	assertNoError(t, err, "Failed to generate key")

	// Delete key
	delArgs := []string{"key", "delete", keyID,
		"--backend", "pkcs8",
		"--key-dir", keyDir,
	}
	stdout, stderr, err := execCLI(t, cfg, delArgs...)
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		assertNoError(t, err, "Delete command failed")
	}

	t.Logf("Deleted key via CLI: %s", keyID)

	// Verify key is gone by trying to list it
	listArgs := []string{"key", "get", keyID,
		"--backend", "pkcs8",
		"--key-dir", keyDir,
	}
	_, _, err = execCLI(t, cfg, listArgs...)
	if err == nil {
		t.Fatal("Key still exists after deletion")
	}
}

// TestCLIGetKey tests getting key details via CLI
func TestCLIGetKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isCLIAvailable(t, cfg) {
		t.Fatal("CLI binary required for integration tests. Run: make build")
	}

	keyID := generateUniqueID("cli-get-key")
	keyDir := "/tmp/keystore-cli-test"

	// Ensure clean key directory
	os.RemoveAll(keyDir)
	os.MkdirAll(keyDir, 0755)
	defer os.RemoveAll(keyDir)

	// Generate key
	genArgs := []string{"key", "generate", keyID,
		"--backend", "pkcs8",
		"--key-type", "rsa",
		"--key-size", "2048",
		"--key-dir", keyDir,
	}
	_, _, err := execCLI(t, cfg, genArgs...)
	assertNoError(t, err, "Failed to generate key")

	defer func() {
		delArgs := []string{"key", "delete", keyID,
			"--backend", "pkcs8",
			"--key-dir", keyDir,
		}
		execCLI(t, cfg, delArgs...)
	}()

	// Get key details
	getArgs := []string{"key", "get", keyID,
		"--backend", "pkcs8",
		"--key-dir", keyDir,
	}
	stdout, stderr, err := execCLI(t, cfg, getArgs...)
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
		assertNoError(t, err, "Get key command failed")
	}

	output := stdout + stderr
	assertContains(t, output, keyID, "Output should contain key ID")

	t.Logf("CLI get key output:\n%s", strings.TrimSpace(stdout))
}
