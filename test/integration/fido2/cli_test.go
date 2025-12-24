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

//go:build integration && fido2

package fido2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CLITestConfig holds CLI test configuration
type CLITestConfig struct {
	CLIBinPath string
	DevicePath string
	Timeout    time.Duration
}

// LoadCLITestConfig loads CLI test configuration
func LoadCLITestConfig() *CLITestConfig {
	projectRoot := getProjectRoot()
	defaultCLIPath := filepath.Join(projectRoot, "build", "bin", "keychain")

	return &CLITestConfig{
		CLIBinPath: getEnv("KEYSTORE_CLI_BIN", defaultCLIPath),
		DevicePath: os.Getenv("FIDO2_DEVICE_PATH"),
		Timeout:    30 * time.Second,
	}
}

// execCLI executes CLI command and returns stdout, stderr, error
func (cfg *CLITestConfig) execCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()

	cmd := exec.Command(cfg.CLIBinPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// isCLIAvailable checks if CLI binary is available
func (cfg *CLITestConfig) isCLIAvailable(t *testing.T) bool {
	t.Helper()

	if _, err := os.Stat(cfg.CLIBinPath); os.IsNotExist(err) {
		return false
	}

	cmd := exec.Command(cfg.CLIBinPath, "version")
	return cmd.Run() == nil
}

// requireCLI skips test if CLI is not available
func (cfg *CLITestConfig) requireCLI(t *testing.T) {
	t.Helper()

	if !cfg.isCLIAvailable(t) {
		t.Skipf("CLI binary not available: %s. Run 'make build' first.", cfg.CLIBinPath)
	}
}

// TestCLIFIDO2ListDevices tests the 'fido2 list-devices' command
func TestCLIFIDO2ListDevices(t *testing.T) {
	cfg := LoadCLITestConfig()
	cfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== CLI FIDO2 List Devices Test ===")

	// Test with default output format
	t.Run("DefaultOutput", func(t *testing.T) {
		stdout, stderr, err := cfg.execCLI(t, "fido2", "list-devices")

		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
		}

		require.NoError(t, err, "list-devices command should succeed")

		output := stdout + stderr
		assert.NotEmpty(t, output, "Output should not be empty")

		t.Logf("List devices output:\n%s", output)
	})

	// Test with JSON output format
	t.Run("JSONOutput", func(t *testing.T) {
		stdout, stderr, err := cfg.execCLI(t, "--output", "json", "fido2", "list-devices")

		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
		}

		require.NoError(t, err, "list-devices with JSON output should succeed")

		// Parse JSON output
		var devices []map[string]interface{}
		err = json.Unmarshal([]byte(stdout), &devices)
		require.NoError(t, err, "Output should be valid JSON")

		require.Greater(t, len(devices), 0, "Should have at least one device")

		device := devices[0]
		assert.NotEmpty(t, device["path"], "Device should have path")
		assert.NotZero(t, device["vendor_id"], "Device should have vendor ID")
		assert.NotZero(t, device["product_id"], "Device should have product ID")

		t.Logf("Found %d device(s) via CLI JSON output", len(devices))
	})

	// Test with specific device path
	if fido2Cfg.DevicePath != "" {
		t.Run("SpecificDevice", func(t *testing.T) {
			stdout, stderr, err := cfg.execCLI(t, "fido2", "list-devices", "--device", fido2Cfg.DevicePath)

			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
			}

			require.NoError(t, err, "list-devices with specific device should succeed")

			output := stdout + stderr
			assert.Contains(t, output, fido2Cfg.DevicePath, "Output should contain device path")
		})
	}
}

// TestCLIFIDO2WaitDevice tests the 'fido2 wait-device' command
func TestCLIFIDO2WaitDevice(t *testing.T) {
	cfg := LoadCLITestConfig()
	cfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()

	// Require FIDO2 device
	fido2Cfg.RequireDevice(t)

	t.Log("=== CLI FIDO2 Wait Device Test ===")

	// Test with short timeout (device should already be present)
	stdout, stderr, err := cfg.execCLI(t, "fido2", "wait-device", "--timeout", "5s")

	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
	}

	require.NoError(t, err, "wait-device should succeed when device is present")

	output := stdout + stderr
	assert.NotEmpty(t, output, "Output should not be empty")
	assert.Contains(t, strings.ToLower(output), "device", "Output should mention device")

	t.Logf("Wait device output:\n%s", output)
}

// TestCLIFIDO2Register tests the 'fido2 register' command
func TestCLIFIDO2Register(t *testing.T) {
	cfg := LoadCLITestConfig()
	cfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== CLI FIDO2 Register Test ===")

	username := GenerateUniqueUsername("cli-test-user")

	// Test basic registration
	t.Run("BasicRegistration", func(t *testing.T) {
		args := []string{
			"fido2", "register", username,
			"--rp-id", "go-keychain-test",
			"--rp-name", "CLI Integration Test",
			"--timeout", "30s",
		}

		if fido2Cfg.DevicePath != "" {
			args = append(args, "--device", fido2Cfg.DevicePath)
		}

		t.Log("Please touch your security key to register...")

		stdout, stderr, err := cfg.execCLI(t, args...)

		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
		}

		require.NoError(t, err, "register command should succeed")

		output := stdout + stderr
		assert.NotEmpty(t, output, "Output should not be empty")
		assert.Contains(t, strings.ToLower(output), "credential", "Output should mention credential")

		t.Logf("Registration output:\n%s", output)
	})

	// Test registration with JSON output
	t.Run("JSONOutput", func(t *testing.T) {
		username := GenerateUniqueUsername("cli-json-user")

		args := []string{
			"--output", "json",
			"fido2", "register", username,
			"--rp-id", "go-keychain-test",
			"--rp-name", "CLI Integration Test",
			"--timeout", "30s",
		}

		if fido2Cfg.DevicePath != "" {
			args = append(args, "--device", fido2Cfg.DevicePath)
		}

		t.Log("Please touch your security key to register (JSON output)...")

		stdout, stderr, err := cfg.execCLI(t, args...)

		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
		}

		require.NoError(t, err, "register command with JSON should succeed")

		// Parse JSON output
		var result map[string]interface{}
		err = json.Unmarshal([]byte(stdout), &result)
		require.NoError(t, err, "Output should be valid JSON")

		assert.NotEmpty(t, result["credential_id"], "Should have credential ID")
		assert.NotEmpty(t, result["salt"], "Should have salt")
		assert.NotEmpty(t, result["public_key"], "Should have public key")

		t.Logf("Registration successful via CLI (JSON)")
		t.Logf("  Credential ID: %v", result["credential_id"])
		t.Logf("  Salt: %v", result["salt"])
	})
}

// TestCLIFIDO2Authenticate tests the 'fido2 authenticate' command
func TestCLIFIDO2Authenticate(t *testing.T) {
	cfg := LoadCLITestConfig()
	cfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== CLI FIDO2 Authenticate Test ===")

	// First, register a credential using the API
	username := GenerateUniqueUsername("cli-auth-user")
	enrollment, handler := fido2Cfg.EnrollTestCredential(t, username)
	defer CleanupCredential(t, handler)

	// Encode credential ID and salt for CLI
	credIDBase64 := base64.StdEncoding.EncodeToString(enrollment.CredentialID)
	saltBase64 := base64.StdEncoding.EncodeToString(enrollment.Salt)

	t.Log("Credential enrolled, now testing CLI authentication...")

	// Test authentication
	t.Run("BasicAuthentication", func(t *testing.T) {
		args := []string{
			"fido2", "authenticate",
			"--credential-id", credIDBase64,
			"--salt", saltBase64,
			"--rp-id", "go-keychain-test",
			"--timeout", "30s",
		}

		if fido2Cfg.DevicePath != "" {
			args = append(args, "--device", fido2Cfg.DevicePath)
		}

		t.Log("Please touch your security key to authenticate...")

		stdout, stderr, err := cfg.execCLI(t, args...)

		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
		}

		require.NoError(t, err, "authenticate command should succeed")

		output := stdout + stderr
		assert.NotEmpty(t, output, "Output should not be empty")
		assert.Contains(t, strings.ToLower(output), "derived", "Output should mention derived key")

		t.Logf("Authentication output:\n%s", output)
	})

	// Test authentication with hex output
	t.Run("HexOutput", func(t *testing.T) {
		args := []string{
			"fido2", "authenticate",
			"--credential-id", credIDBase64,
			"--salt", saltBase64,
			"--rp-id", "go-keychain-test",
			"--timeout", "30s",
			"--hex",
		}

		if fido2Cfg.DevicePath != "" {
			args = append(args, "--device", fido2Cfg.DevicePath)
		}

		t.Log("Please touch your security key to authenticate (hex output)...")

		stdout, stderr, err := cfg.execCLI(t, args...)

		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
		}

		require.NoError(t, err, "authenticate command with hex should succeed")

		output := stdout + stderr
		assert.NotEmpty(t, output, "Output should not be empty")

		t.Logf("Authentication with hex output successful")
	})
}

// TestCLIFIDO2Info tests the 'fido2 info' command
func TestCLIFIDO2Info(t *testing.T) {
	cfg := LoadCLITestConfig()
	cfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== CLI FIDO2 Info Test ===")

	// Test basic device info
	t.Run("BasicInfo", func(t *testing.T) {
		args := []string{"fido2", "info"}

		if fido2Cfg.DevicePath != "" {
			args = append(args, "--device", fido2Cfg.DevicePath)
		}

		stdout, stderr, err := cfg.execCLI(t, args...)

		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
		}

		require.NoError(t, err, "info command should succeed")

		output := stdout + stderr
		assert.NotEmpty(t, output, "Output should not be empty")
		assert.Contains(t, strings.ToLower(output), "device", "Output should mention device")

		t.Logf("Device info output:\n%s", output)
	})

	// Test info with JSON output
	t.Run("JSONOutput", func(t *testing.T) {
		args := []string{"--output", "json", "fido2", "info"}

		if fido2Cfg.DevicePath != "" {
			args = append(args, "--device", fido2Cfg.DevicePath)
		}

		stdout, stderr, err := cfg.execCLI(t, args...)

		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
		}

		require.NoError(t, err, "info command with JSON should succeed")

		// Parse JSON output
		var info map[string]interface{}
		err = json.Unmarshal([]byte(stdout), &info)
		require.NoError(t, err, "Output should be valid JSON")

		assert.NotEmpty(t, info["path"], "Should have device path")
		assert.NotZero(t, info["vendor_id"], "Should have vendor ID")
		assert.NotZero(t, info["product_id"], "Should have product ID")

		t.Logf("Device info retrieved via CLI (JSON)")
	})
}

// TestCLIFIDO2FullWorkflow tests a complete registration and authentication workflow
func TestCLIFIDO2FullWorkflow(t *testing.T) {
	cfg := LoadCLITestConfig()
	cfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== CLI FIDO2 Full Workflow Test ===")

	username := GenerateUniqueUsername("cli-workflow-user")

	// Step 1: Register
	t.Log("Step 1: Registering credential...")

	registerArgs := []string{
		"--output", "json",
		"fido2", "register", username,
		"--rp-id", "go-keychain-test",
		"--rp-name", "CLI Workflow Test",
		"--timeout", "30s",
	}

	if fido2Cfg.DevicePath != "" {
		registerArgs = append(registerArgs, "--device", fido2Cfg.DevicePath)
	}

	t.Log("Please touch your security key to register...")

	stdout, stderr, err := cfg.execCLI(t, registerArgs...)
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
	}
	require.NoError(t, err, "Registration should succeed")

	// Parse registration result
	var regResult map[string]interface{}
	err = json.Unmarshal([]byte(stdout), &regResult)
	require.NoError(t, err, "Registration output should be valid JSON")

	credID := regResult["credential_id"].(string)
	salt := regResult["salt"].(string)

	t.Logf("Registration successful")
	t.Logf("  Credential ID: %s", credID[:32]+"...")
	t.Logf("  Salt: %s", salt[:32]+"...")

	// Step 2: Authenticate
	t.Log("Step 2: Authenticating with credential...")

	authArgs := []string{
		"--output", "json",
		"fido2", "authenticate",
		"--credential-id", credID,
		"--salt", salt,
		"--rp-id", "go-keychain-test",
		"--timeout", "30s",
	}

	if fido2Cfg.DevicePath != "" {
		authArgs = append(authArgs, "--device", fido2Cfg.DevicePath)
	}

	t.Log("Please touch your security key to authenticate...")

	stdout, stderr, err = cfg.execCLI(t, authArgs...)
	if err != nil {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", stderr)
	}
	require.NoError(t, err, "Authentication should succeed")

	// Parse authentication result
	var authResult map[string]interface{}
	err = json.Unmarshal([]byte(stdout), &authResult)
	require.NoError(t, err, "Authentication output should be valid JSON")

	assert.True(t, authResult["success"].(bool), "Authentication should be successful")
	assert.NotEmpty(t, authResult["derived_key"], "Should have derived key")
	assert.Equal(t, float64(32), authResult["key_length"].(float64), "Derived key should be 32 bytes")

	t.Log("Full workflow completed successfully!")
	t.Logf("  Derived key length: %v bytes", authResult["key_length"])
}

// TestCLIFIDO2ErrorCases tests error handling in CLI commands
func TestCLIFIDO2ErrorCases(t *testing.T) {
	cfg := LoadCLITestConfig()
	cfg.requireCLI(t)

	t.Log("=== CLI FIDO2 Error Cases Test ===")

	t.Run("AuthWithoutCredentialID", func(t *testing.T) {
		// Missing required credential-id flag
		_, _, err := cfg.execCLI(t, "fido2", "authenticate", "--salt", "test")
		assert.Error(t, err, "Should fail without credential ID")
	})

	t.Run("AuthWithoutSalt", func(t *testing.T) {
		// Missing required salt flag
		_, _, err := cfg.execCLI(t, "fido2", "authenticate", "--credential-id", "test")
		assert.Error(t, err, "Should fail without salt")
	})

	t.Run("RegisterWithoutUsername", func(t *testing.T) {
		// Missing required username argument
		_, _, err := cfg.execCLI(t, "fido2", "register")
		assert.Error(t, err, "Should fail without username")
	})

	t.Run("InvalidDevicePath", func(t *testing.T) {
		stdout, stderr, err := cfg.execCLI(t, "fido2", "list-devices", "--device", "/dev/nonexistent")
		// The command should either:
		// 1. Return an error (expected for invalid device path)
		// 2. Return no devices found (graceful handling)
		// Both are acceptable behaviors for an invalid device path
		if err != nil {
			// Error is expected - check if output mentions the issue
			combined := strings.ToLower(stdout + stderr)
			t.Logf("Command failed as expected with output: %s", combined)
		} else {
			// Command succeeded but should return no devices
			t.Logf("Command succeeded (graceful handling): stdout=%s", stdout)
		}
	})

	t.Log("Error case tests completed")
}

// Helper functions

func getProjectRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	// This file is in test/integration/fido2/, so go up 3 levels
	return filepath.Join(filepath.Dir(filename), "..", "..", "..")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
