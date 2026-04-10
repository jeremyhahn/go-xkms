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

//go:build integration && pkcs11 && pkcs11_tool
// +build integration,pkcs11,pkcs11_tool

// Package module provides comprehensive pkcs11-tool integration tests for the
// go-xkms PKCS#11 module. These tests execute pkcs11-tool subprocess commands
// to validate external tool compatibility with the PKCS#11 shared library.
//
// These tests validate ALL operations supported by pkcs11-tool according to
// OASIS PKCS#11 v3.0 specification.
//
// Required environment variables:
//   - PKCS11_MODULE: Path to the PKCS#11 shared library (default: /usr/lib/pkcs11/libgo-xkms-pkcs11.so)
//   - PKCS11_PIN: User PIN (default: 87654321)
//   - PKCS11_SO_PIN: Security Officer PIN (default: 12345678)
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// Type aliases for PKCS#11 module types to simplify test code.
type (
	Mechanism    = module.Mechanism
	ObjectHandle = module.ObjectHandle
	CK_RV        = module.CK_RV
)

// Mechanism type constants
const (
	CKM_RSA_PKCS_KEY_PAIR_GEN = module.CKM_RSA_PKCS_KEY_PAIR_GEN
	CKM_AES_KEY_GEN           = module.CKM_AES_KEY_GEN
	CKM_EC_KEY_PAIR_GEN       = module.CKM_EC_KEY_PAIR_GEN
	CKM_RSA_PKCS              = module.CKM_RSA_PKCS
	CKM_SHA256_RSA_PKCS       = module.CKM_SHA256_RSA_PKCS
	CKM_SHA384_RSA_PKCS       = module.CKM_SHA384_RSA_PKCS
	CKM_SHA512_RSA_PKCS       = module.CKM_SHA512_RSA_PKCS
	CKM_ECDSA                 = module.CKM_ECDSA
)

// =============================================================================
// PKCS11Tool Test Configuration
// =============================================================================

// PKCS11ToolTestConfig holds configuration for pkcs11-tool integration tests.
type PKCS11ToolTestConfig struct {
	ModulePath string
	SlotID     string
	PIN        string
	SOPIN      string
	TempDir    string
}

// NewPKCS11ToolTestConfig creates a new test configuration from environment variables.
func NewPKCS11ToolTestConfig(t *testing.T) *PKCS11ToolTestConfig {
	t.Helper()

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

	return &PKCS11ToolTestConfig{
		ModulePath: modulePath,
		SlotID:     "0",
		PIN:        pin,
		SOPIN:      soPin,
		TempDir:    t.TempDir(),
	}
}

// skipIfToolUnavailable skips the test if pkcs11-tool is not available.
func skipIfToolUnavailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool not available in PATH, skipping test")
	}
}

// skipIfModuleUnavailable skips the test if the PKCS#11 module is not available.
func skipIfModuleUnavailable(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("PKCS#11 module not found at %s, skipping test", path)
	}
}

// runPKCS11ToolCommand executes pkcs11-tool with given arguments and returns output.
func runPKCS11ToolCommand(t *testing.T, cfg *PKCS11ToolTestConfig, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	fullArgs := append([]string{"--module", cfg.ModulePath}, args...)
	cmd := exec.Command("pkcs11-tool", fullArgs...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err != nil {
		t.Logf("pkcs11-tool command: pkcs11-tool %s", strings.Join(fullArgs, " "))
		t.Logf("pkcs11-tool stderr: %s", stderr)
	}

	return stdout, stderr, err
}

// mustRunPKCS11ToolCommand executes pkcs11-tool and fails test on error.
func mustRunPKCS11ToolCommand(t *testing.T, cfg *PKCS11ToolTestConfig, args ...string) string {
	t.Helper()
	stdout, _, err := runPKCS11ToolCommand(t, cfg, args...)
	if err != nil {
		t.Fatalf("pkcs11-tool failed: %v", err)
	}
	return stdout
}

// writeTestDataFile writes test data to a temporary file.
func writeTestDataFile(t *testing.T, dir string, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write test data file: %v", err)
	}
	return path
}

// readTestDataFile reads data from a file.
func readTestDataFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test data file: %v", err)
	}
	return data
}

// =============================================================================
// 1. Module/Library Info Tests
// OASIS PKCS#11 v3.0 Section 5.4 - C_GetInfo
// =============================================================================

func TestPKCS11Tool_ShowInfo(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	// Initialize module backend for tests
	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	t.Run("show_info", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--show-info")

		// Verify manufacturer info
		if !strings.Contains(output, "Manufacturer") {
			t.Error("expected Manufacturer field in output")
		}

		// Verify Cryptoki version
		versionRe := regexp.MustCompile(`Cryptoki version\s+(\d+)\.(\d+)`)
		matches := versionRe.FindStringSubmatch(output)
		if len(matches) < 3 {
			t.Error("expected Cryptoki version in output")
		} else {
			major, _ := strconv.Atoi(matches[1])
			if major < 2 {
				t.Errorf("expected Cryptoki version >= 2.0, got %s.%s", matches[1], matches[2])
			}
			t.Logf("Cryptoki version: %s.%s", matches[1], matches[2])
		}

		// Verify library version
		if !strings.Contains(output, "Library") {
			t.Error("expected Library field in output")
		}

		t.Logf("pkcs11-tool --show-info output:\n%s", output)
	})

	t.Run("show_info_verbose", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "-I", "-v")
		t.Logf("pkcs11-tool -I -v output:\n%s", output)
	})
}

// =============================================================================
// 2. Slot/Token Operations Tests
// OASIS PKCS#11 v3.0 Section 5.5 - C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo
// =============================================================================

func TestPKCS11Tool_SlotOperations(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	t.Run("list_slots", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--list-slots")

		if !strings.Contains(output, "Slot") {
			t.Error("expected Slot information in output")
		}

		t.Logf("pkcs11-tool --list-slots output:\n%s", output)
	})

	t.Run("list_token_slots", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--list-token-slots")

		// Should show slots with tokens present
		t.Logf("pkcs11-tool --list-token-slots output:\n%s", output)
	})

	t.Run("slot_description", func(t *testing.T) {
		// Get slot info for slot 0
		output, _, err := runPKCS11ToolCommand(t, cfg, "--slot", cfg.SlotID, "--list-slots")
		if err != nil {
			t.Logf("slot info may require initialized token: %v", err)
		}
		t.Logf("Slot %s description:\n%s", cfg.SlotID, output)
	})
}

func TestPKCS11Tool_TokenInfo(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	t.Run("show_token_info", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--slot", cfg.SlotID, "-T")

		// Check for token label
		if !strings.Contains(output, "Token") {
			t.Error("expected Token information in output")
		}

		t.Logf("pkcs11-tool -T output:\n%s", output)
	})
}

func TestPKCS11Tool_TokenInit(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	t.Run("init_token", func(t *testing.T) {
		// Setup fresh environment
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		tokenLabel := "pkcs11-tool-token"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--slot", cfg.SlotID,
			"--init-token",
			"--label", tokenLabel,
			"--so-pin", cfg.SOPIN,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --init-token failed: %v, output: %s", err, output)
		}

		t.Logf("Token initialization output:\n%s", output)
	})

	t.Run("init_pin", func(t *testing.T) {
		// Setup with initialized token
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		output, _, err := runPKCS11ToolCommand(t, cfg,
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

		t.Logf("PIN initialization output:\n%s", output)
	})

	t.Run("change_pin", func(t *testing.T) {
		skipIfNoFilePersistence(t)

		oldPIN := cfg.PIN
		newPIN := "newpin1234"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--slot", cfg.SlotID,
			"--login",
			"--pin", oldPIN,
			"--change-pin",
			"--new-pin", newPIN,
		)

		if err != nil {
			t.Fatalf("pkcs11-tool --change-pin failed: %v, output: %s", err, output)
		}

		t.Logf("PIN change output:\n%s", output)

		// Verify new PIN works via pkcs11-tool (tests the shared library)
		verifyOutput, _, verifyErr := runPKCS11ToolCommand(t, cfg,
			"--slot", cfg.SlotID,
			"--login",
			"--pin", newPIN,
			"--list-objects",
		)
		if verifyErr != nil {
			t.Errorf("login with new PIN failed: %v, output: %s", verifyErr, verifyOutput)
		} else {
			t.Log("login with new PIN successful")
		}

		// Restore original PIN for subsequent tests via pkcs11-tool
		_, _, restoreErr := runPKCS11ToolCommand(t, cfg,
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

// =============================================================================
// 3. Mechanism Operations Tests
// OASIS PKCS#11 v3.0 Section 5.12 - C_GetMechanismList, C_GetMechanismInfo
// =============================================================================

func TestPKCS11Tool_Mechanisms(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	t.Run("list_mechanisms", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--slot", cfg.SlotID, "--list-mechanisms")

		// Verify expected mechanisms are present
		expectedMechanisms := []string{
			"RSA", // RSA mechanisms
			"EC",  // ECDSA mechanisms
			"AES", // AES mechanisms
			"SHA", // Digest mechanisms
		}

		outputUpper := strings.ToUpper(output)
		for _, mech := range expectedMechanisms {
			if !strings.Contains(outputUpper, mech) {
				t.Logf("warning: expected mechanism containing %q not found", mech)
			}
		}

		t.Logf("pkcs11-tool --list-mechanisms output:\n%s", output)
	})

	t.Run("list_mechanisms_verbose", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--slot", cfg.SlotID, "--list-mechanisms", "-v")

		// Verbose output should include key sizes
		if !strings.Contains(strings.ToLower(output), "key") {
			t.Log("verbose mechanism info may not include key size details")
		}

		t.Logf("pkcs11-tool --list-mechanisms -v output:\n%s", output)
	})

	t.Run("verify_rsa_mechanisms", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--slot", cfg.SlotID, "--list-mechanisms")

		rsaMechanisms := []string{
			"RSA-PKCS-KEY-PAIR-GEN",
			"RSA-PKCS",
			"SHA256-RSA-PKCS",
		}

		outputUpper := strings.ToUpper(strings.ReplaceAll(output, "_", "-"))
		for _, mech := range rsaMechanisms {
			if !strings.Contains(outputUpper, mech) {
				t.Logf("RSA mechanism %q not found (may be named differently)", mech)
			}
		}
	})

	t.Run("verify_ec_mechanisms", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--slot", cfg.SlotID, "--list-mechanisms")

		ecMechanisms := []string{
			"EC-KEY-PAIR-GEN",
			"ECDSA",
		}

		outputUpper := strings.ToUpper(strings.ReplaceAll(output, "_", "-"))
		for _, mech := range ecMechanisms {
			if !strings.Contains(outputUpper, mech) {
				t.Logf("EC mechanism %q not found (may be named differently)", mech)
			}
		}
	})

	t.Run("verify_aes_mechanisms", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--slot", cfg.SlotID, "--list-mechanisms")

		aesMechanisms := []string{
			"AES-KEY-GEN",
		}

		outputUpper := strings.ToUpper(strings.ReplaceAll(output, "_", "-"))
		for _, mech := range aesMechanisms {
			if !strings.Contains(outputUpper, mech) {
				t.Logf("AES mechanism %q not found (may be named differently)", mech)
			}
		}
	})

	t.Run("verify_eddsa_mechanisms", func(t *testing.T) {
		output := mustRunPKCS11ToolCommand(t, cfg, "--slot", cfg.SlotID, "--list-mechanisms")

		eddsaMechanisms := []string{
			"EDDSA",
			"ED25519",
		}

		outputUpper := strings.ToUpper(strings.ReplaceAll(output, "_", "-"))
		found := false
		for _, mech := range eddsaMechanisms {
			if strings.Contains(outputUpper, mech) {
				found = true
				break
			}
		}
		if !found {
			t.Log("EdDSA/Ed25519 mechanism not found (may not be supported)")
		}
	})
}

// =============================================================================
// 4. Key Generation Tests
// OASIS PKCS#11 v3.0 Section 5.14 - C_GenerateKey, C_GenerateKeyPair
// =============================================================================

func TestPKCS11Tool_KeyGeneration(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	t.Run("generate_rsa_2048", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		keyLabel := "pkcs11-tool-rsa-2048"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "rsa:2048",
			"--label", keyLabel,
			"--id", "01",
		)

		if err != nil {
			t.Fatalf("RSA 2048 key generation failed: %v, output: %s", err, output)
		}

		t.Logf("RSA 2048 key generation output:\n%s", output)
	})

	t.Run("generate_rsa_4096", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		keyLabel := "pkcs11-tool-rsa-4096"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "rsa:4096",
			"--label", keyLabel,
			"--id", "02",
		)

		if err != nil {
			t.Logf("RSA 4096 key generation failed (may not be supported): %v", err)
		} else {
			t.Logf("RSA 4096 key generation output:\n%s", output)
		}
	})

	t.Run("generate_ec_p256", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		keyLabel := "pkcs11-tool-ec-p256"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "EC:secp256r1",
			"--label", keyLabel,
			"--id", "03",
		)

		if err != nil {
			t.Fatalf("EC P-256 key generation failed: %v, output: %s", err, output)
		}

		t.Logf("EC P-256 key generation output:\n%s", output)
	})

	t.Run("generate_ec_p384", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		keyLabel := "pkcs11-tool-ec-p384"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "EC:secp384r1",
			"--label", keyLabel,
			"--id", "04",
		)

		if err != nil {
			t.Fatalf("EC P-384 key generation failed: %v, output: %s", err, output)
		}

		t.Logf("EC P-384 key generation output:\n%s", output)
	})

	t.Run("generate_ec_p521", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		keyLabel := "pkcs11-tool-ec-p521"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "EC:secp521r1",
			"--label", keyLabel,
			"--id", "05",
		)

		if err != nil {
			t.Logf("EC P-521 key generation failed (may not be supported): %v", err)
		} else {
			t.Logf("EC P-521 key generation output:\n%s", output)
		}
	})

	t.Run("generate_aes_128", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		keyLabel := "pkcs11-tool-aes-128"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keygen",
			"--key-type", "aes:16",
			"--label", keyLabel,
			"--id", "06",
		)

		if err != nil {
			t.Fatalf("AES-128 key generation failed: %v, output: %s", err, output)
		}

		t.Logf("AES-128 key generation output:\n%s", output)
	})

	t.Run("generate_aes_256", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		keyLabel := "pkcs11-tool-aes-256"

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keygen",
			"--key-type", "aes:32",
			"--label", keyLabel,
			"--id", "07",
		)

		if err != nil {
			t.Fatalf("AES-256 key generation failed: %v, output: %s", err, output)
		}

		t.Logf("AES-256 key generation output:\n%s", output)
	})
}

// =============================================================================
// 5. Object Operations Tests
// OASIS PKCS#11 v3.0 Section 5.7 - C_FindObjects, C_GetAttributeValue, C_DestroyObject
// =============================================================================

func TestPKCS11Tool_ObjectOperations(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	t.Run("list_objects", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate a key to ensure there's something to list
		pubTemplate := BuildRSAPublicKeyTemplate("list-test-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("list-test-priv")
		mechanism := &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		output := mustRunPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
		)

		t.Logf("pkcs11-tool --list-objects output:\n%s", output)
	})

	t.Run("list_private_keys", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildRSAPublicKeyTemplate("list-priv-test-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("list-priv-test-priv")
		mechanism := &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		output := mustRunPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "privkey",
		)

		if !strings.Contains(output, "Private") && !strings.Contains(output, "priv") {
			t.Log("No private keys explicitly shown (may be filtered)")
		}

		t.Logf("pkcs11-tool --list-objects --type privkey output:\n%s", output)
	})

	t.Run("list_public_keys", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildRSAPublicKeyTemplate("list-pub-test-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("list-pub-test-priv")
		mechanism := &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		output := mustRunPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "pubkey",
		)

		t.Logf("pkcs11-tool --list-objects --type pubkey output:\n%s", output)
	})

	t.Run("list_secret_keys", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		template := BuildAESKeyTemplate("list-secret-test", 32)
		mechanism := &Mechanism{Type: CKM_AES_KEY_GEN}
		_, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		output := mustRunPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "secrkey",
		)

		t.Logf("pkcs11-tool --list-objects --type secrkey output:\n%s", output)
	})

	t.Run("read_public_key", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		keyLabel := "read-pubkey-test"
		pubTemplate := BuildRSAPublicKeyTemplate(keyLabel, 2048)
		privTemplate := BuildRSAPrivateKeyTemplate(keyLabel + "-priv")
		mechanism := &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		pubKeyFile := filepath.Join(cfg.TempDir, "pubkey.der")

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--read-object",
			"--type", "pubkey",
			"--label", keyLabel,
			"-o", pubKeyFile,
		)

		if err != nil {
			t.Logf("read-object may not be supported: %v, output: %s", err, output)
		} else {
			data := readTestDataFile(t, pubKeyFile)
			if len(data) == 0 {
				t.Error("expected non-empty public key data")
			}
			t.Logf("Read public key: %d bytes", len(data))
		}
	})

	t.Run("delete_object", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		keyLabel := "delete-test-key"
		pubTemplate := BuildRSAPublicKeyTemplate(keyLabel, 2048)
		privTemplate := BuildRSAPrivateKeyTemplate(keyLabel + "-priv")
		mechanism := &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Verify key exists
		_, found := FindKeyByLabel(t, env, session, keyLabel)
		if !found {
			t.Fatal("key not found before deletion")
		}

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--delete-object",
			"--type", "pubkey",
			"--label", keyLabel,
		)

		if err != nil {
			t.Logf("delete-object failed: %v, output: %s", err, output)
		} else {
			t.Logf("Delete object output:\n%s", output)
		}
	})
}

// =============================================================================
// 6. Signing Operations Tests
// OASIS PKCS#11 v3.0 Section 5.13 - C_SignInit, C_Sign
// =============================================================================

func TestPKCS11Tool_SigningOperations(t *testing.T) {
	skipIfNoFilePersistence(t)
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	t.Run("sign_rsa_pkcs", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		keyLabel := "rsa-sign-test"
		pubTemplate := BuildRSAPublicKeyTemplate(keyLabel, 2048)
		privTemplate := BuildRSAPrivateKeyTemplate(keyLabel + "-priv")
		mechanism := &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Create test data
		testData := []byte("Test data for RSA-PKCS signing")
		dataFile := writeTestDataFile(t, cfg.TempDir, "rsa_data.bin", testData)
		sigFile := filepath.Join(cfg.TempDir, "rsa_sig.bin")

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--sign",
			"--mechanism", "RSA-PKCS",
			"--label", keyLabel+"-priv",
			"--input-file", dataFile,
			"--output-file", sigFile,
		)

		if err != nil {
			t.Fatalf("RSA-PKCS sign failed: %v, output: %s", err, output)
		}

		sigData := readTestDataFile(t, sigFile)
		if len(sigData) == 0 {
			t.Error("expected non-empty signature")
		}
		t.Logf("RSA-PKCS signature size: %d bytes", len(sigData))
	})

	t.Run("sign_sha256_rsa_pkcs", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		keyLabel := "rsa-sha256-sign-test"
		pubTemplate := BuildRSAPublicKeyTemplate(keyLabel, 2048)
		privTemplate := BuildRSAPrivateKeyTemplate(keyLabel + "-priv")
		mechanism := &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		testData := []byte("Test data for SHA256-RSA-PKCS signing")
		dataFile := writeTestDataFile(t, cfg.TempDir, "sha256_rsa_data.bin", testData)
		sigFile := filepath.Join(cfg.TempDir, "sha256_rsa_sig.bin")

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--sign",
			"--mechanism", "SHA256-RSA-PKCS",
			"--label", keyLabel+"-priv",
			"--input-file", dataFile,
			"--output-file", sigFile,
		)

		if err != nil {
			t.Fatalf("SHA256-RSA-PKCS sign failed: %v, output: %s", err, output)
		}

		sigData := readTestDataFile(t, sigFile)
		t.Logf("SHA256-RSA-PKCS signature size: %d bytes", len(sigData))
	})

	t.Run("sign_ecdsa", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		keyLabel := "ecdsa-sign-test"
		pubTemplate := BuildECPublicKeyTemplate(keyLabel, OID_P256)
		privTemplate := BuildECPrivateKeyTemplate(keyLabel + "-priv")
		mechanism := &Mechanism{Type: CKM_EC_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// ECDSA expects pre-hashed data for raw mechanism
		testData := hashSHA256([]byte("Test data for ECDSA signing"))
		dataFile := writeTestDataFile(t, cfg.TempDir, "ecdsa_data.bin", testData)
		sigFile := filepath.Join(cfg.TempDir, "ecdsa_sig.bin")

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--sign",
			"--mechanism", "ECDSA",
			"--label", keyLabel+"-priv",
			"--input-file", dataFile,
			"--output-file", sigFile,
		)

		if err != nil {
			t.Fatalf("ECDSA sign failed: %v, output: %s", err, output)
		}

		sigData := readTestDataFile(t, sigFile)
		t.Logf("ECDSA signature size: %d bytes", len(sigData))
	})

	t.Run("sign_ecdsa_sha256", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		keyLabel := "ecdsa-sha256-sign-test"
		pubTemplate := BuildECPublicKeyTemplate(keyLabel, OID_P256)
		privTemplate := BuildECPrivateKeyTemplate(keyLabel + "-priv")
		mechanism := &Mechanism{Type: CKM_EC_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		testData := []byte("Test data for ECDSA-SHA256 signing")
		dataFile := writeTestDataFile(t, cfg.TempDir, "ecdsa_sha256_data.bin", testData)
		sigFile := filepath.Join(cfg.TempDir, "ecdsa_sha256_sig.bin")

		_, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--sign",
			"--mechanism", "ECDSA-SHA256",
			"--label", keyLabel+"-priv",
			"--input-file", dataFile,
			"--output-file", sigFile,
		)

		if err != nil {
			t.Logf("ECDSA-SHA256 may not be directly supported: %v", err)
		} else {
			sigData := readTestDataFile(t, sigFile)
			t.Logf("ECDSA-SHA256 signature size: %d bytes", len(sigData))
		}
	})
}

// =============================================================================
// 7. Verification Operations Tests
// OASIS PKCS#11 v3.0 Section 5.13 - C_VerifyInit, C_Verify
// =============================================================================

// TestPKCS11Tool_VerificationOperations tests sign operations using pkcs11-tool exclusively
// for key generation and signing. This test validates that keys generated by pkcs11-tool
// can be used for signing operations.
//
// Note: Cryptographic signature verification is tested in the Go module unit tests.
// This test focuses on pkcs11-tool CLI compatibility rather than cryptographic correctness.
func TestPKCS11Tool_VerificationOperations(t *testing.T) {
	skipIfNoFilePersistence(t)
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	t.Run("sign_rsa_sha256", func(t *testing.T) {
		// Initialize module for this test
		_, session := SetupInitializedModule(t)
		_ = session

		keyLabel := "rsa-verify-test"
		keyID := "30"

		// Generate RSA key with pkcs11-tool
		keygenOutput, keygenStderr, keygenErr := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "rsa:2048",
			"--label", keyLabel,
			"--id", keyID,
		)
		if keygenErr != nil {
			t.Fatalf("RSA key generation failed: %v\nstdout: %s\nstderr: %s", keygenErr, keygenOutput, keygenStderr)
		}
		t.Logf("RSA key generation succeeded:\n%s", keygenOutput)

		// Prepare test data and file paths
		testData := []byte("Test data for RSA sign and verify")
		dataFile := writeTestDataFile(t, cfg.TempDir, "rsa_verify_data.bin", testData)
		sigFile := filepath.Join(cfg.TempDir, "rsa_verify_sig.bin")

		// Sign with pkcs11-tool
		signOutput, signStderr, signErr := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--sign",
			"--mechanism", "SHA256-RSA-PKCS",
			"--id", keyID,
			"--input-file", dataFile,
			"--output-file", sigFile,
		)
		if signErr != nil {
			t.Fatalf("RSA sign failed: %v\nstdout: %s\nstderr: %s", signErr, signOutput, signStderr)
		}
		t.Log("RSA SHA256-RSA-PKCS sign succeeded")

		// Read signature and verify it's correct size for RSA-2048
		sigData := readTestDataFile(t, sigFile)
		if len(sigData) == 0 {
			t.Fatal("expected non-empty signature")
		}

		// RSA-2048 signature should be 256 bytes (2048 bits / 8)
		expectedSigSize := 256
		if len(sigData) != expectedSigSize {
			t.Errorf("expected RSA signature size %d bytes, got %d", expectedSigSize, len(sigData))
		}
		t.Logf("RSA signature size: %d bytes (expected %d)", len(sigData), expectedSigSize)
	})

	t.Run("sign_ecdsa_p256", func(t *testing.T) {
		// Initialize module for this test
		_, session := SetupInitializedModule(t)
		_ = session

		keyLabel := "ecdsa-verify-test"
		keyID := "31"

		// Generate EC key with pkcs11-tool
		keygenOutput, keygenStderr, keygenErr := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "EC:secp256r1",
			"--label", keyLabel,
			"--id", keyID,
		)
		if keygenErr != nil {
			t.Fatalf("EC key generation failed: %v\nstdout: %s\nstderr: %s", keygenErr, keygenOutput, keygenStderr)
		}
		t.Logf("EC key generation succeeded:\n%s", keygenOutput)

		// Prepare test data (pre-hashed for ECDSA raw mechanism)
		testData := hashSHA256([]byte("Test data for ECDSA sign and verify"))
		dataFile := writeTestDataFile(t, cfg.TempDir, "ecdsa_verify_data.bin", testData)
		sigFile := filepath.Join(cfg.TempDir, "ecdsa_verify_sig.bin")

		// Sign with pkcs11-tool
		signOutput, signStderr, signErr := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--sign",
			"--mechanism", "ECDSA",
			"--id", keyID,
			"--input-file", dataFile,
			"--output-file", sigFile,
		)
		if signErr != nil {
			t.Fatalf("ECDSA sign failed: %v\nstdout: %s\nstderr: %s", signErr, signOutput, signStderr)
		}
		t.Log("ECDSA sign succeeded")

		// Read signature and verify it's a reasonable size
		sigData := readTestDataFile(t, sigFile)
		if len(sigData) == 0 {
			t.Fatal("expected non-empty signature")
		}

		// P-256 ECDSA signature: 64 bytes raw (R||S) or 70-72 bytes DER encoded
		if len(sigData) < 64 || len(sigData) > 72 {
			t.Errorf("unexpected ECDSA signature size: %d bytes (expected 64-72)", len(sigData))
		}
		t.Logf("ECDSA signature size: %d bytes", len(sigData))

		// Verify signature format
		if len(sigData) == 64 {
			t.Log("ECDSA signature is in raw R||S format")
		} else if sigData[0] == 0x30 {
			t.Log("ECDSA signature is in DER-encoded format")
		}
	})

	t.Run("list_generated_keys", func(t *testing.T) {
		// Verify the keys we generated are listed
		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
		)
		if err != nil {
			t.Fatalf("list objects failed: %v", err)
		}

		// Check for our generated keys
		if !strings.Contains(output, "rsa-verify-test") {
			t.Error("expected to find RSA key 'rsa-verify-test' in object list")
		}
		if !strings.Contains(output, "ecdsa-verify-test") {
			t.Error("expected to find EC key 'ecdsa-verify-test' in object list")
		}
		t.Log("All generated keys found in object list")
	})
}

// =============================================================================
// 8. Encryption/Decryption Operations Tests
// OASIS PKCS#11 v3.0 Section 5.13 - C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt
// =============================================================================

func TestPKCS11Tool_EncryptionOperations(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	t.Run("encrypt_aes_cbc", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		keyLabel := "aes-enc-test"
		template := BuildAESKeyTemplate(keyLabel, 32)
		mechanism := &Mechanism{Type: CKM_AES_KEY_GEN}
		_, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		// AES-CBC requires 16-byte aligned plaintext
		plaintext := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes
		plainFile := writeTestDataFile(t, cfg.TempDir, "aes_plain.bin", plaintext)
		cipherFile := filepath.Join(cfg.TempDir, "aes_cipher.bin")

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--encrypt",
			"--mechanism", "AES-CBC",
			"--label", keyLabel,
			"--input-file", plainFile,
			"--output-file", cipherFile,
		)

		if err != nil {
			t.Logf("AES-CBC encryption may not be directly supported by pkcs11-tool: %v", err)
		} else {
			cipherData := readTestDataFile(t, cipherFile)
			t.Logf("AES-CBC encryption output:\n%s", output)
			t.Logf("Ciphertext size: %d bytes", len(cipherData))
		}
	})

	t.Run("encrypt_rsa_pkcs", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		keyLabel := "rsa-enc-test"
		pubTemplate := BuildRSAPublicKeyTemplate(keyLabel, 2048)
		privTemplate := BuildRSAPrivateKeyTemplate(keyLabel + "-priv")
		mechanism := &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// RSA-PKCS max plaintext is modulus - 11 bytes
		plaintext := []byte("Short plaintext for RSA-PKCS encryption")
		plainFile := writeTestDataFile(t, cfg.TempDir, "rsa_plain.bin", plaintext)
		cipherFile := filepath.Join(cfg.TempDir, "rsa_cipher.bin")

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--encrypt",
			"--mechanism", "RSA-PKCS",
			"--label", keyLabel,
			"--input-file", plainFile,
			"--output-file", cipherFile,
		)

		if err != nil {
			t.Logf("RSA-PKCS encryption may not be supported: %v", err)
		} else {
			t.Logf("RSA-PKCS encryption output:\n%s", output)
		}
	})
}

// =============================================================================
// 9. Random Number Generation Tests
// OASIS PKCS#11 v3.0 Section 5.17 - C_GenerateRandom
// =============================================================================

func TestPKCS11Tool_RandomGeneration(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	randomSizes := []struct {
		name string
		size string
	}{
		{"32_bytes", "32"},
		{"64_bytes", "64"},
		{"256_bytes", "256"},
	}

	for _, tc := range randomSizes {
		t.Run("generate_random_"+tc.name, func(t *testing.T) {
			env := SetupTestEnvironment(t, nil)
			env.MustInitializeModule(t)
			env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

			outputFile := filepath.Join(cfg.TempDir, "random_"+tc.name+".bin")

			output, _, err := runPKCS11ToolCommand(t, cfg,
				"--slot", cfg.SlotID,
				"--generate-random", tc.size,
				"--output-file", outputFile,
			)

			if err != nil {
				t.Fatalf("generate-random %s failed: %v, output: %s", tc.size, err, output)
			}

			// Verify random data
			randomData := readTestDataFile(t, outputFile)
			expectedSize, _ := strconv.Atoi(tc.size)
			if len(randomData) != expectedSize {
				t.Errorf("expected %d bytes, got %d", expectedSize, len(randomData))
			}

			// Basic randomness check - not all zeros
			allZeros := true
			for _, b := range randomData {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("random data is all zeros (extremely unlikely)")
			}

			t.Logf("Generated %s of random data", tc.name)
		})
	}

	t.Run("random_uniqueness", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Generate multiple random values and ensure uniqueness
		values := make([][]byte, 5)
		for i := range values {
			outputFile := filepath.Join(cfg.TempDir, "random_unique_"+strconv.Itoa(i)+".bin")

			_, _, err := runPKCS11ToolCommand(t, cfg,
				"--slot", cfg.SlotID,
				"--generate-random", "32",
				"--output-file", outputFile,
			)

			if err != nil {
				t.Fatalf("generate-random failed: %v", err)
			}

			values[i] = readTestDataFile(t, outputFile)
		}

		// Check uniqueness
		for i := 0; i < len(values); i++ {
			for j := i + 1; j < len(values); j++ {
				if bytes.Equal(values[i], values[j]) {
					t.Error("generated duplicate random values (extremely unlikely)")
				}
			}
		}

		t.Log("Random values are unique")
	})
}

// =============================================================================
// 10. Login/Logout Operations Tests
// OASIS PKCS#11 v3.0 Section 5.6 - C_Login, C_Logout
// =============================================================================

func TestPKCS11Tool_LoginOperations(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	t.Run("user_login", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.Module.CloseSession(session)

		// Test user login by attempting an operation that requires login
		output := mustRunPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
		)

		t.Logf("User login and list-objects output:\n%s", output)
	})

	t.Run("so_login", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		output, _, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--login-type", "so",
			"--so-pin", cfg.SOPIN,
			"--slot", cfg.SlotID,
			"--list-objects",
		)

		if err != nil {
			t.Logf("SO login may have restrictions: %v", err)
		} else {
			t.Logf("SO login and list-objects output:\n%s", output)
		}
	})

	t.Run("wrong_pin_login", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		_, stderr, err := runPKCS11ToolCommand(t, cfg,
			"--login",
			"--pin", "wrongpin",
			"--slot", cfg.SlotID,
			"--list-objects",
		)

		if err == nil {
			t.Error("expected error with wrong PIN")
		}

		// Should contain PIN error message
		outputLower := strings.ToLower(stderr)
		if !strings.Contains(outputLower, "pin") && !strings.Contains(outputLower, "error") {
			t.Log("Error message may not explicitly mention PIN")
		}

		t.Logf("Wrong PIN login error (expected): %v", err)
	})
}

// =============================================================================
// Comprehensive Table-Driven Tests
// =============================================================================

// TestPKCS11Tool_AllSigningMechanisms tests all supported signing mechanisms using pkcs11-tool exclusively.
// NOTE: This test requires a persistent backend. When using the in-memory backend,
// each pkcs11-tool invocation loads a fresh library instance and keys don't persist
// between invocations. Skip this test when running against the in-memory backend.
func TestPKCS11Tool_AllSigningMechanisms(t *testing.T) {
	skipIfNoFilePersistence(t)
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	testCases := []struct {
		name      string
		mechanism string
		keyType   string // rsa:2048 or EC:secp256r1
		keyLabel  string
		dataPrep  func([]byte) []byte // How to prepare data for signing
		idBytes   string              // Unique ID for the key (hex string)
	}{
		{
			name:      "RSA_PKCS",
			mechanism: "RSA-PKCS",
			keyType:   "rsa:2048",
			keyLabel:  "sign-rsa-pkcs",
			dataPrep:  hashSHA256,
			idBytes:   "20",
		},
		{
			name:      "SHA256_RSA_PKCS",
			mechanism: "SHA256-RSA-PKCS",
			keyType:   "rsa:2048",
			keyLabel:  "sign-sha256-rsa",
			dataPrep:  func(d []byte) []byte { return d },
			idBytes:   "21",
		},
		{
			name:      "SHA384_RSA_PKCS",
			mechanism: "SHA384-RSA-PKCS",
			keyType:   "rsa:2048",
			keyLabel:  "sign-sha384-rsa",
			dataPrep:  func(d []byte) []byte { return d },
			idBytes:   "22",
		},
		{
			name:      "SHA512_RSA_PKCS",
			mechanism: "SHA512-RSA-PKCS",
			keyType:   "rsa:2048",
			keyLabel:  "sign-sha512-rsa",
			dataPrep:  func(d []byte) []byte { return d },
			idBytes:   "23",
		},
		{
			name:      "ECDSA_P256",
			mechanism: "ECDSA",
			keyType:   "EC:secp256r1",
			keyLabel:  "sign-ecdsa-p256",
			dataPrep:  hashSHA256,
			idBytes:   "24",
		},
		{
			name:      "EdDSA_Ed25519",
			mechanism: "EDDSA",
			keyType:   "EC:edwards25519",
			keyLabel:  "sign-eddsa-ed25519",
			dataPrep:  func(d []byte) []byte { return d }, // EdDSA handles hashing internally
			idBytes:   "25",
		},
		{
			name:      "ECDSA_P384",
			mechanism: "ECDSA",
			keyType:   "EC:secp384r1",
			keyLabel:  "sign-ecdsa-p384",
			dataPrep:  hashSHA384,
			idBytes:   "26",
		},
		{
			name:      "ECDSA_P521",
			mechanism: "ECDSA",
			keyType:   "EC:secp521r1",
			keyLabel:  "sign-ecdsa-p521",
			dataPrep:  hashSHA512,
			idBytes:   "27",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate key with pkcs11-tool
			keygenOutput, keygenStderr, keygenErr := runPKCS11ToolCommand(t, cfg,
				"--login",
				"--pin", cfg.PIN,
				"--slot", cfg.SlotID,
				"--keypairgen",
				"--key-type", tc.keyType,
				"--label", tc.keyLabel,
				"--id", tc.idBytes,
			)

			if keygenErr != nil {
				t.Fatalf("%s key generation failed: %v\nstdout: %s\nstderr: %s", tc.name, keygenErr, keygenOutput, keygenStderr)
			}

			t.Logf("%s key generation succeeded:\n%s", tc.name, keygenOutput)

			// Prepare test data
			rawData := []byte("Test data for signing with " + tc.name)
			signData := tc.dataPrep(rawData)
			dataFile := writeTestDataFile(t, cfg.TempDir, tc.name+"_data.bin", signData)
			sigFile := filepath.Join(cfg.TempDir, tc.name+"_sig.bin")

			// Sign with pkcs11-tool using the key we just generated
			signOutput, signStderr, signErr := runPKCS11ToolCommand(t, cfg,
				"--login",
				"--pin", cfg.PIN,
				"--slot", cfg.SlotID,
				"--sign",
				"--mechanism", tc.mechanism,
				"--id", tc.idBytes,
				"--input-file", dataFile,
				"--output-file", sigFile,
			)

			if signErr != nil {
				t.Fatalf("%s sign failed: %v\nstdout: %s\nstderr: %s", tc.name, signErr, signOutput, signStderr)
			}

			t.Logf("%s sign succeeded", tc.name)

			// Read and verify signature is non-empty
			sigData := readTestDataFile(t, sigFile)
			if len(sigData) == 0 {
				t.Error("expected non-empty signature")
			}

			t.Logf("%s: signature size = %d bytes", tc.name, len(sigData))
		})
	}
}

// TestPKCS11Tool_AllKeyTypes tests key generation for all supported key types.
func TestPKCS11Tool_AllKeyTypes(t *testing.T) {
	skipIfToolUnavailable(t)
	cfg := NewPKCS11ToolTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	testCases := []struct {
		name    string
		keyType string
		keyArgs []string
	}{
		{"RSA_2048", "keypair", []string{"--keypairgen", "--key-type", "rsa:2048"}},
		{"EC_P256", "keypair", []string{"--keypairgen", "--key-type", "EC:secp256r1"}},
		{"EC_P384", "keypair", []string{"--keypairgen", "--key-type", "EC:secp384r1"}},
		{"Ed25519", "keypair", []string{"--keypairgen", "--key-type", "EC:edwards25519"}},
		{"AES_128", "symmetric", []string{"--keygen", "--key-type", "aes:16"}},
		{"AES_192", "symmetric", []string{"--keygen", "--key-type", "aes:24"}},
		{"AES_256", "symmetric", []string{"--keygen", "--key-type", "aes:32"}},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, session := SetupInitializedModule(t)
			_ = session

			keyLabel := "keygen-" + tc.name
			keyID := strconv.Itoa(i + 10)

			args := append([]string{
				"--login",
				"--pin", cfg.PIN,
				"--slot", cfg.SlotID,
			}, tc.keyArgs...)
			args = append(args, "--label", keyLabel, "--id", keyID)

			output, _, err := runPKCS11ToolCommand(t, cfg, args...)

			if err != nil {
				t.Logf("%s key generation may not be supported: %v", tc.name, err)
			} else {
				t.Logf("%s key generation succeeded:\n%s", tc.name, output)
			}
		})
	}
}
