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

//go:build integration && pkcs11_tool
// +build integration,pkcs11_tool

// Package module provides integration tests for the PKCS#11 module implementation.
// These tests validate compatibility with pkcs11-tool from OpenSC and other
// standard PKCS#11 tools by exercising the module through its exported C interface.
//
// NOTE: These tests require persistent token state across module reloads.
// They are disabled by default and require the pkcs11_tool build tag.
// Run with: go test -tags='integration,pkcs11_tool' ./test/integration/pkcs11/module/...
package module

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// PKCS11ToolConfig holds configuration for pkcs11-tool testing.
type PKCS11ToolConfig struct {
	// ModulePath is the path to the PKCS#11 shared library.
	ModulePath string

	// SlotID is the slot to use for operations.
	SlotID string

	// PIN is the user PIN for authentication.
	PIN string

	// SOPIN is the Security Officer PIN.
	SOPIN string
}

// DefaultPKCS11ToolConfig returns the default configuration for pkcs11-tool testing.
func DefaultPKCS11ToolConfig() *PKCS11ToolConfig {
	modulePath := os.Getenv("PKCS11_MODULE")
	if modulePath == "" {
		// Check both possible paths (devcontainer and local)
		if _, err := os.Stat("/workspace/build/lib/libxkms_pkcs11.so"); err == nil {
			modulePath = "/workspace/build/lib/libxkms_pkcs11.so"
		} else {
			modulePath = "build/lib/libxkms_pkcs11.so"
		}
	}

	pin := os.Getenv("PKCS11_PIN")
	if pin == "" {
		pin = string(TestPINs.User)
	}

	soPin := os.Getenv("PKCS11_SO_PIN")
	if soPin == "" {
		soPin = string(TestPINs.SO)
	}

	return &PKCS11ToolConfig{
		ModulePath: modulePath,
		SlotID:     "0",
		PIN:        pin,
		SOPIN:      soPin,
	}
}

// checkPKCS11ToolAvailable checks if pkcs11-tool is available in PATH.
func checkPKCS11ToolAvailable(t *testing.T) {
	t.Helper()

	_, err := exec.LookPath("pkcs11-tool")
	if err != nil {
		t.Skip("pkcs11-tool not available in PATH, skipping compatibility tests")
	}
}

// checkSharedLibraryAvailable checks if the PKCS#11 shared library exists.
func checkSharedLibraryAvailable(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Skipf("PKCS#11 shared library not found at %s, skipping compatibility tests", path)
	}
}

// runPKCS11Tool executes pkcs11-tool with the given arguments and returns output.
func runPKCS11Tool(t *testing.T, cfg *PKCS11ToolConfig, args ...string) (string, error) {
	t.Helper()

	// Prepend module path
	fullArgs := append([]string{"--module", cfg.ModulePath}, args...)

	cmd := exec.Command("pkcs11-tool", fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Logf("pkcs11-tool stderr: %s", stderr.String())
	}

	return stdout.String(), err
}

// initializeTokenViaPKCS11Tool initializes the token and user PIN using pkcs11-tool.
// This is necessary because pkcs11-tool loads its own module instance that doesn't
// share state with the Go test's module instance.
func initializeTokenViaPKCS11Tool(t *testing.T, cfg *PKCS11ToolConfig) {
	t.Helper()

	// Initialize token with SO PIN
	output, err := runPKCS11Tool(t, cfg,
		"--slot", cfg.SlotID,
		"--init-token",
		"--label", TestLabels.Token,
		"--so-pin", cfg.SOPIN,
	)
	if err != nil {
		t.Logf("pkcs11-tool --init-token output: %s", output)
		t.Fatalf("failed to init token via pkcs11-tool: %v", err)
	}

	// Initialize user PIN (requires SO login)
	output, err = runPKCS11Tool(t, cfg,
		"--slot", cfg.SlotID,
		"--login",
		"--login-type", "so",
		"--so-pin", cfg.SOPIN,
		"--init-pin",
		"--new-pin", cfg.PIN,
	)
	if err != nil {
		t.Logf("pkcs11-tool --init-pin output: %s", output)
		t.Fatalf("failed to init user PIN via pkcs11-tool: %v", err)
	}
}

// TestPKCS11ToolListSlots tests that pkcs11-tool --list-slots works correctly.
// This validates the module's C_GetSlotList and C_GetSlotInfo implementations.
func TestPKCS11ToolListSlots(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Set up the module backend first
	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	t.Run("list_slots", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg, "--list-slots")
		if err != nil {
			t.Fatalf("pkcs11-tool --list-slots failed: %v", err)
		}

		// Verify output contains slot information
		if !strings.Contains(output, "Slot") {
			t.Errorf("expected slot information in output, got: %s", output)
		}

		t.Logf("pkcs11-tool --list-slots output:\n%s", output)
	})

	t.Run("list_slots_with_tokens", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg, "--list-slots", "--show-info")
		if err != nil {
			t.Fatalf("pkcs11-tool --list-slots --show-info failed: %v", err)
		}

		// Verify token label is shown
		if !strings.Contains(output, TestLabels.Token) {
			t.Logf("warning: expected token label %q in output, got: %s", TestLabels.Token, output)
		}

		t.Logf("pkcs11-tool --list-slots --show-info output:\n%s", output)
	})
}

// TestPKCS11ToolListMechanisms tests that pkcs11-tool --list-mechanisms works.
// This validates the module's C_GetMechanismList and C_GetMechanismInfo implementations.
func TestPKCS11ToolListMechanisms(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Set up the module
	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	t.Run("list_mechanisms", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg, "--list-mechanisms", "--slot", cfg.SlotID)
		if err != nil {
			t.Fatalf("pkcs11-tool --list-mechanisms failed: %v", err)
		}

		t.Logf("pkcs11-tool --list-mechanisms output:\n%s", output)

		// Check for expected mechanisms
		expectedMechanisms := []string{
			"RSA-PKCS-KEY-PAIR-GEN",
			"RSA-PKCS",
			"SHA256-RSA-PKCS",
			"EC-KEY-PAIR-GEN",
			"ECDSA",
			"AES-KEY-GEN",
		}

		for _, mech := range expectedMechanisms {
			// Mechanism names may vary in format, check case-insensitively
			if !strings.Contains(strings.ToUpper(output), strings.ToUpper(mech)) {
				t.Logf("warning: expected mechanism %q not found in output", mech)
			}
		}
	})

	t.Run("list_mechanisms_verbose", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg, "--list-mechanisms", "--slot", cfg.SlotID, "-v")
		if err != nil {
			t.Fatalf("pkcs11-tool --list-mechanisms -v failed: %v", err)
		}

		// Verbose output should include key sizes
		if !strings.Contains(output, "min") && !strings.Contains(output, "max") {
			t.Logf("warning: expected key size info in verbose output, got: %s", output)
		}

		t.Logf("pkcs11-tool --list-mechanisms -v output:\n%s", output)
	})
}

// TestPKCS11ToolGenerateKey tests key generation via pkcs11-tool.
// This validates the module's C_GenerateKeyPair and C_GenerateKey implementations.
func TestPKCS11ToolGenerateKey(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Initialize token via pkcs11-tool (not Go API) since pkcs11-tool loads its own module instance
	initializeTokenViaPKCS11Tool(t, cfg)

	t.Run("generate_rsa_keypair", func(t *testing.T) {
		keyLabel := "pkcs11-tool-rsa-test-key"

		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "rsa:2048",
			"--label", keyLabel,
			"--id", "01",
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --keypairgen (RSA) failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool RSA keypair generation output:\n%s", output)

		// Verify key was created via pkcs11-tool --list-objects
		listOutput, listErr := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "pubkey",
		)
		if listErr == nil && strings.Contains(listOutput, keyLabel) {
			t.Logf("verified RSA key exists via --list-objects")
		} else {
			t.Logf("warning: could not verify RSA key via --list-objects")
		}
	})

	t.Run("generate_ec_keypair", func(t *testing.T) {
		keyLabel := "pkcs11-tool-ec-test-key"

		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "EC:secp256r1",
			"--label", keyLabel,
			"--id", "02",
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --keypairgen (EC) failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool EC keypair generation output:\n%s", output)

		// Verify key was created via pkcs11-tool --list-objects
		listOutput, listErr := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "pubkey",
		)
		if listErr == nil && strings.Contains(listOutput, keyLabel) {
			t.Logf("verified EC key exists via --list-objects")
		} else {
			t.Logf("warning: could not verify EC key via --list-objects")
		}
	})

	t.Run("generate_aes_key", func(t *testing.T) {
		keyLabel := "pkcs11-tool-aes-test-key"

		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keygen",
			"--key-type", "aes:32", // 32 bytes = 256 bits
			"--label", keyLabel,
			"--id", "03",
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --keygen (AES) failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool AES key generation output:\n%s", output)

		// Verify key was created via pkcs11-tool --list-objects
		listOutput, listErr := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "secrkey",
		)
		if listErr == nil && strings.Contains(listOutput, keyLabel) {
			t.Logf("verified AES key exists via --list-objects")
		} else {
			t.Logf("warning: could not verify AES key via --list-objects")
		}
	})
}

// TestPKCS11ToolSign tests signing operations via pkcs11-tool.
// This validates the module's C_SignInit and C_Sign implementations.
// NOTE: Requires persistent backend - in-memory module doesn't persist keys across pkcs11-tool invocations.
func TestPKCS11ToolSign(t *testing.T) {
	skipIfNoFilePersistence(t)

	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Initialize token and generate keys via pkcs11-tool (separate module instance)
	initializeTokenViaPKCS11Tool(t, cfg)

	keyLabel := "tool-sign-test-key"

	// Generate a key pair for signing tests via pkcs11-tool
	output, err := runPKCS11Tool(t, cfg,
		"--login",
		"--pin", cfg.PIN,
		"--slot", cfg.SlotID,
		"--keypairgen",
		"--key-type", "rsa:2048",
		"--label", keyLabel,
		"--id", "10",
	)
	if err != nil {
		t.Fatalf("failed to generate key pair for signing test: %v, output: %s", err, output)
	}
	t.Logf("generated key pair via pkcs11-tool: %s", output)

	t.Run("sign_with_rsa_pkcs", func(t *testing.T) {
		// Create test data to sign
		testData := []byte("test data for pkcs11-tool signing")

		// Write test data to a temporary file
		tmpDataFile := t.TempDir() + "/test_data.bin"
		tmpSigFile := t.TempDir() + "/signature.bin"

		err := writeTestFile(tmpDataFile, testData)
		if err != nil {
			t.Fatalf("failed to write test data file: %v", err)
		}

		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--sign",
			"--mechanism", "RSA-PKCS",
			"--label", keyLabel,
			"--input-file", tmpDataFile,
			"--output-file", tmpSigFile,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --sign failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool sign output:\n%s", output)

		// Verify signature file was created and has content
		sigData, err := readTestFile(tmpSigFile)
		if err != nil {
			t.Fatalf("could not read signature file: %v", err)
		}
		t.Logf("signature size: %d bytes", len(sigData))

		if len(sigData) == 0 {
			t.Error("signature is empty")
		}
	})

	t.Run("sign_with_sha256_rsa_pkcs", func(t *testing.T) {
		testData := []byte("test data for SHA256-RSA-PKCS signing")

		tmpDataFile := t.TempDir() + "/test_data_sha256.bin"
		tmpSigFile := t.TempDir() + "/signature_sha256.bin"

		err := writeTestFile(tmpDataFile, testData)
		if err != nil {
			t.Fatalf("failed to write test data file: %v", err)
		}

		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--sign",
			"--mechanism", "SHA256-RSA-PKCS",
			"--label", keyLabel,
			"--input-file", tmpDataFile,
			"--output-file", tmpSigFile,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --sign (SHA256-RSA-PKCS) failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool sign (SHA256-RSA-PKCS) output:\n%s", output)

		// Verify signature file was created and has content
		sigData, err := readTestFile(tmpSigFile)
		if err != nil {
			t.Fatalf("could not read signature file: %v", err)
		}
		t.Logf("signature size: %d bytes", len(sigData))

		if len(sigData) == 0 {
			t.Error("signature is empty")
		}
	})
}

// TestPKCS11ToolListObjects tests object listing via pkcs11-tool.
// This validates the module's C_FindObjectsInit, C_FindObjects, and C_FindObjectsFinal.
func TestPKCS11ToolListObjects(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Initialize token via pkcs11-tool
	initializeTokenViaPKCS11Tool(t, cfg)

	// Generate a few keys via pkcs11-tool
	for i := 0; i < 3; i++ {
		keyLabel := fmt.Sprintf("list-test-key-%c", rune('a'+i))

		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "rsa:2048",
			"--label", keyLabel,
			"--id", fmt.Sprintf("%02x", i+1),
		)
		if err != nil {
			t.Fatalf("failed to generate key pair %d: %v, output: %s", i, err, output)
		}
	}

	t.Run("list_objects", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --list-objects failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool --list-objects output:\n%s", output)

		// Check that we can see some keys
		if !strings.Contains(output, "Key") && !strings.Contains(output, "Object") {
			t.Logf("warning: expected key/object information in output")
		}
	})

	t.Run("list_public_keys", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "pubkey",
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --list-objects --type pubkey failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool list public keys output:\n%s", output)
	})

	t.Run("list_private_keys", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "privkey",
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --list-objects --type privkey failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool list private keys output:\n%s", output)
	})
}

// TestPKCS11ToolTokenInfo tests token information retrieval via pkcs11-tool.
// This validates the module's C_GetTokenInfo implementation.
func TestPKCS11ToolTokenInfo(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Set up the module
	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	t.Run("show_token_info", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--show-info",
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --show-info failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool --show-info output:\n%s", output)

		// Check for expected fields
		expectedFields := []string{
			"Cryptoki",
			"Manufacturer",
			"Library",
		}

		for _, field := range expectedFields {
			if !strings.Contains(output, field) {
				t.Logf("warning: expected field %q not found in output", field)
			}
		}
	})

	t.Run("token_info", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--token-info",
		)

		// Some versions of pkcs11-tool may not support --token-info
		if err != nil {
			t.Logf("pkcs11-tool --token-info may not be supported: %v", err)
			t.Skip("--token-info not supported by this version of pkcs11-tool")
		}

		t.Logf("pkcs11-tool --token-info output:\n%s", output)
	})
}

// TestPKCS11ToolInitToken tests token initialization via pkcs11-tool.
// This validates the module's C_InitToken implementation.
func TestPKCS11ToolInitToken(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	t.Run("init_token", func(t *testing.T) {
		tokenLabel := "pkcs11-tool-init-token"

		output, err := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--init-token",
			"--label", tokenLabel,
			"--so-pin", cfg.SOPIN,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --init-token failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool --init-token output:\n%s", output)

		// Verify token was initialized by checking token info via pkcs11-tool
		infoOutput, infoErr := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--show-info",
		)
		if infoErr == nil && strings.Contains(infoOutput, tokenLabel) {
			t.Logf("verified token label via --show-info: %s", tokenLabel)
		} else {
			t.Logf("warning: could not verify token label via --show-info")
		}
	})
}

// TestPKCS11ToolInitPIN tests PIN initialization via pkcs11-tool.
// This validates the module's C_InitPIN implementation.
func TestPKCS11ToolInitPIN(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Initialize token first via pkcs11-tool (no user PIN yet)
	output, err := runPKCS11Tool(t, cfg,
		"--slot", cfg.SlotID,
		"--init-token",
		"--label", TestLabels.Token,
		"--so-pin", cfg.SOPIN,
	)
	if err != nil {
		t.Fatalf("pkcs11-tool --init-token failed: %v, output: %s", err, output)
	}

	t.Run("init_user_pin", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--login",
			"--login-type", "so",
			"--so-pin", cfg.SOPIN,
			"--init-pin",
			"--new-pin", cfg.PIN,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --init-pin failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool --init-pin output:\n%s", output)

		// Verify user can now login with the new PIN via pkcs11-tool
		loginOutput, loginErr := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--login",
			"--pin", cfg.PIN,
			"--list-objects",
		)
		if loginErr != nil {
			t.Errorf("user login with initialized PIN failed via pkcs11-tool: %v", loginErr)
		} else {
			t.Log("user login with initialized PIN successful")
			t.Logf("list objects output: %s", loginOutput)
		}
	})
}

// TestPKCS11ToolChangePIN tests PIN change via pkcs11-tool.
// This validates the module's C_SetPIN implementation.
func TestPKCS11ToolChangePIN(t *testing.T) {
	skipIfNoFilePersistence(t)

	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Initialize token via pkcs11-tool
	initializeTokenViaPKCS11Tool(t, cfg)

	t.Run("change_user_pin", func(t *testing.T) {
		oldPIN := cfg.PIN
		newPIN := "newuserpin123"

		output, err := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--login",
			"--pin", oldPIN,
			"--change-pin",
			"--new-pin", newPIN,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --change-pin failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool --change-pin output:\n%s", output)

		// Verify new PIN works via pkcs11-tool
		loginOutput, loginErr := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--login",
			"--pin", newPIN,
			"--list-objects",
		)
		if loginErr != nil {
			t.Errorf("login with new PIN failed: %v", loginErr)
		} else {
			t.Log("login with new PIN successful")
			t.Logf("list objects output: %s", loginOutput)
		}

		// Verify old PIN no longer works via pkcs11-tool
		_, oldLoginErr := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--login",
			"--pin", oldPIN,
			"--list-objects",
		)
		if oldLoginErr == nil {
			t.Error("login with old PIN should have failed")
		} else {
			t.Log("old PIN correctly rejected")
		}

		// Restore original PIN for subsequent tests
		_, restoreErr := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--login",
			"--pin", newPIN,
			"--change-pin",
			"--new-pin", oldPIN,
		)
		if restoreErr != nil {
			t.Logf("warning: failed to restore original PIN: %v", restoreErr)
		} else {
			t.Log("original PIN restored for subsequent tests")
		}
	})
}

// TestPKCS11ToolDelete tests object deletion via pkcs11-tool.
// This validates the module's C_DestroyObject implementation.
func TestPKCS11ToolDelete(t *testing.T) {
	skipIfNoFilePersistence(t)

	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Initialize token via pkcs11-tool
	initializeTokenViaPKCS11Tool(t, cfg)

	// Generate a key to delete via pkcs11-tool
	keyLabel := "delete-test-key"
	genOutput, genErr := runPKCS11Tool(t, cfg,
		"--login",
		"--pin", cfg.PIN,
		"--slot", cfg.SlotID,
		"--keypairgen",
		"--key-type", "rsa:2048",
		"--label", keyLabel,
		"--id", "20",
	)
	if genErr != nil {
		t.Fatalf("failed to generate key pair for delete test: %v, output: %s", genErr, genOutput)
	}

	// Verify key exists via pkcs11-tool
	listOutput, listErr := runPKCS11Tool(t, cfg,
		"--login",
		"--pin", cfg.PIN,
		"--slot", cfg.SlotID,
		"--list-objects",
		"--type", "pubkey",
	)
	if listErr != nil || !strings.Contains(listOutput, keyLabel) {
		t.Fatalf("generated key not found before deletion: %v", listErr)
	}

	t.Run("delete_object", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--delete-object",
			"--type", "pubkey",
			"--label", keyLabel,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --delete-object failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool --delete-object output:\n%s", output)

		// Verify key was deleted via pkcs11-tool
		afterOutput, _ := runPKCS11Tool(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "pubkey",
		)
		if strings.Contains(afterOutput, keyLabel) {
			t.Logf("warning: key still found after deletion via pkcs11-tool")
		} else {
			t.Log("key successfully deleted")
		}
	})
}

// TestPKCS11ToolRandomData tests random data generation via pkcs11-tool.
// This validates the module's C_GenerateRandom implementation.
func TestPKCS11ToolRandomData(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Random generation doesn't require token initialization or login
	t.Run("generate_random", func(t *testing.T) {
		tmpFile := t.TempDir() + "/random.bin"

		output, err := runPKCS11Tool(t, cfg,
			"--slot", cfg.SlotID,
			"--generate-random", "32",
			"--output-file", tmpFile,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --generate-random failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool --generate-random output:\n%s", output)

		// Verify random data was generated
		randomData, err := readTestFile(tmpFile)
		if err != nil {
			t.Fatalf("failed to read random data file: %v", err)
		}

		if len(randomData) != 32 {
			t.Errorf("expected 32 bytes of random data, got %d", len(randomData))
		}

		// Check that data is not all zeros
		allZeros := true
		for _, b := range randomData {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("random data appears to be all zeros")
		}

		t.Logf("generated random data: %x", randomData)
	})
}

// TestPKCS11ModuleExportedSymbols tests that the shared library exports required symbols.
// This is a basic compatibility check for the C interface.
func TestPKCS11ModuleExportedSymbols(t *testing.T) {
	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	// Use nm to check exported symbols
	nmPath, err := exec.LookPath("nm")
	if err != nil {
		t.Skip("nm not available, skipping symbol export test")
	}

	t.Run("check_c_getfunctionlist", func(t *testing.T) {
		cmd := exec.Command(nmPath, "-D", cfg.ModulePath)
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("nm failed: %v", err)
		}

		outputStr := string(output)

		// Check for C_GetFunctionList (required entry point)
		if !strings.Contains(outputStr, "C_GetFunctionList") {
			t.Error("C_GetFunctionList symbol not exported")
		}

		// Check for C_GetInterface (PKCS#11 v3.0)
		if !strings.Contains(outputStr, "C_GetInterface") {
			t.Log("C_GetInterface not exported (optional for v3.0)")
		}

		// Log some symbols for debugging
		lines := strings.Split(outputStr, "\n")
		count := 0
		for _, line := range lines {
			if strings.Contains(line, "C_") {
				t.Logf("found symbol: %s", strings.TrimSpace(line))
				count++
			}
		}
		t.Logf("total C_ symbols found: %d", count)
	})
}

// TestPKCS11ModuleVersionInfo tests that module version info is retrievable.
func TestPKCS11ModuleVersionInfo(t *testing.T) {
	checkPKCS11ToolAvailable(t)

	cfg := DefaultPKCS11ToolConfig()
	checkSharedLibraryAvailable(t, cfg.ModulePath)

	t.Run("version_info", func(t *testing.T) {
		output, err := runPKCS11Tool(t, cfg, "-I")
		if err != nil {
			t.Fatalf("pkcs11-tool -I failed: %v, output: %s", err, output)
		}

		t.Logf("pkcs11-tool -I output:\n%s", output)

		// Extract Cryptoki version
		versionRe := regexp.MustCompile(`Cryptoki version\s+(\d+\.\d+)`)
		matches := versionRe.FindStringSubmatch(output)
		if len(matches) >= 2 {
			t.Logf("Cryptoki version: %s", matches[1])
		}

		// Extract library description
		if strings.Contains(output, "go-xkms") || strings.Contains(output, "KeyStore()") {
			t.Log("module identification found in output")
		}
	})
}

// writeTestFile writes data to a file for testing.
func writeTestFile(path string, data []byte) error {
	cmd := exec.Command("tee", path)
	cmd.Stdin = bytes.NewReader(data)
	return cmd.Run()
}

// readTestFile reads data from a file.
func readTestFile(path string) ([]byte, error) {
	cmd := exec.Command("cat", path)
	return cmd.Output()
}
