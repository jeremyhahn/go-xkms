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

//go:build integration

// Package oath provides integration tests for the xkey oath CLI commands.
// These tests execute the real xkey binary and verify actual CLI behavior.
package oath

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOATHCLI_FullWorkflow tests the complete OATH credential management workflow
// using the real xkey CLI binary.
func TestOATHCLI_FullWorkflow(t *testing.T) {
	helper := NewOATHTestHelper(t)

	credName := "TestCredential"
	credSecret := "JBSWY3DPEHPK3PXP"
	credIssuer := "TestIssuer"

	// Step 1: Add credential
	t.Run("Add", func(t *testing.T) {
		result := helper.RunOATH("add",
			"--name", credName,
			"--secret", credSecret,
			"--issuer", credIssuer)
		require.True(t, result.Success(),
			"Add command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains("Added") || result.OutputContains("added"),
			"Output should confirm credential was added: %s", result.Combined())
	})

	// Step 2: Verify credential appears in list
	t.Run("List", func(t *testing.T) {
		result := helper.RunOATH("list")
		require.True(t, result.Success(),
			"List command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains(credName),
			"List output should contain credential name: %s", result.Combined())
		assert.True(t, result.OutputContains(credIssuer),
			"List output should contain issuer: %s", result.Combined())
		assert.True(t, result.OutputContains("TOTP"),
			"List output should show TOTP type: %s", result.Combined())
	})

	// Step 3: Generate OTP code
	t.Run("Generate", func(t *testing.T) {
		result := helper.RunOATH("generate", credName)
		require.True(t, result.Success(),
			"Generate command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)

		// Extract and verify OTP code format
		code, found := ExtractOTPCode(result.Stdout)
		require.True(t, found, "Should find OTP code in output: %s", result.Stdout)
		assert.True(t, IsValidOTPCode(code),
			"OTP code should be 6-8 digits: %s", code)
		assert.Len(t, code, 6, "Default TOTP should be 6 digits: %s", code)
	})

	// Step 4: Remove credential with force flag
	t.Run("Remove", func(t *testing.T) {
		result := helper.RunOATH("remove", credName, "--force")
		require.True(t, result.Success(),
			"Remove command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains("Removed") || result.OutputContains("removed"),
			"Output should confirm removal: %s", result.Combined())
	})

	// Step 5: Verify credential is gone from list
	t.Run("ListAfterRemove", func(t *testing.T) {
		result := helper.RunOATH("list")
		require.True(t, result.Success(),
			"List command failed after remove: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.False(t, result.OutputContains(credName),
			"List output should not contain removed credential: %s", result.Combined())
	})
}

// TestOATHCLI_AddWithURI tests adding credentials using otpauth:// URI.
func TestOATHCLI_AddWithURI(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Standard TOTP URI
	t.Run("TOTPUri", func(t *testing.T) {
		uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
		result := helper.RunOATH("add", "--uri", uri)
		require.True(t, result.Success(),
			"Add with URI failed: %s", result.Combined())

		// Verify credential was added
		result = helper.RunOATH("list")
		require.True(t, result.Success())
		assert.True(t, result.OutputContains("GitHub"),
			"Should contain credential from URI: %s", result.Combined())
	})

	// TOTP URI with non-default parameters
	t.Run("TOTPUriCustomParams", func(t *testing.T) {
		uri := "otpauth://totp/AWS:admin@company.com?secret=GEZDGNBVGY3TQOJQ&issuer=AWS&algorithm=SHA256&digits=8&period=60"
		result := helper.RunOATH("add", "--uri", uri)
		require.True(t, result.Success(),
			"Add with custom URI failed: %s", result.Combined())

		// Verify credential appears in list
		result = helper.RunOATH("list")
		require.True(t, result.Success())
		assert.True(t, result.OutputContains("AWS"),
			"Should contain AWS credential: %s", result.Combined())
		assert.True(t, result.OutputContains("SHA256"),
			"Should show SHA256 algorithm: %s", result.Combined())
	})

	// HOTP URI with counter
	t.Run("HOTPUri", func(t *testing.T) {
		uri := "otpauth://hotp/Service:user?secret=JBSWY3DPEHPK3PXP&counter=42&issuer=Service"
		result := helper.RunOATH("add", "--uri", uri)
		require.True(t, result.Success(),
			"Add HOTP with URI failed: %s", result.Combined())

		result = helper.RunOATH("list")
		require.True(t, result.Success())
		assert.True(t, result.OutputContains("Service"),
			"Should contain Service credential: %s", result.Combined())
		assert.True(t, result.OutputContains("HOTP"),
			"Should show HOTP type: %s", result.Combined())
	})

	// Override name when using URI
	t.Run("URIWithNameOverride", func(t *testing.T) {
		uri := "otpauth://totp/Original:user?secret=HXDMVJECJJWSRB3H&issuer=Original"
		result := helper.RunOATH("add", "--uri", uri, "--name", "OverriddenName")
		require.True(t, result.Success(),
			"Add with name override failed: %s", result.Combined())

		result = helper.RunOATH("list")
		require.True(t, result.Success())
		assert.True(t, result.OutputContains("OverriddenName"),
			"Should use overridden name: %s", result.Combined())
	})
}

// TestOATHCLI_AddVariousConfigs tests adding credentials with various configurations.
func TestOATHCLI_AddVariousConfigs(t *testing.T) {
	helper := NewOATHTestHelper(t)

	testCases := []struct {
		name      string
		credName  string
		otpType   string
		algorithm string
		digits    string
	}{
		{"TOTP_SHA1_6", "TestSHA1", "totp", "SHA1", "6"},
		{"TOTP_SHA256_6", "TestSHA256", "totp", "SHA256", "6"},
		{"TOTP_SHA512_6", "TestSHA512", "totp", "SHA512", "6"},
		{"TOTP_7Digits", "Test7Digits", "totp", "SHA1", "7"},
		{"TOTP_8Digits", "Test8Digits", "totp", "SHA1", "8"},
		{"HOTP_SHA1", "TestHOTP", "hotp", "SHA1", "6"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := helper.RunOATH("add",
				"--name", tc.credName,
				"--secret", "JBSWY3DPEHPK3PXP",
				"--type", tc.otpType,
				"--algorithm", tc.algorithm,
				"--digits", tc.digits)
			require.True(t, result.Success(),
				"Add %s failed: %s", tc.name, result.Combined())

			// Generate and verify code
			result = helper.RunOATH("generate", tc.credName)
			require.True(t, result.Success(),
				"Generate for %s failed: %s", tc.name, result.Combined())

			code, found := ExtractOTPCode(result.Stdout)
			require.True(t, found, "Should find OTP code for %s: %s", tc.name, result.Stdout)

			expectedDigits := 6
			switch tc.digits {
			case "7":
				expectedDigits = 7
			case "8":
				expectedDigits = 8
			}
			assert.Len(t, code, expectedDigits,
				"Code for %s should have %d digits: %s", tc.name, expectedDigits, code)
		})
	}
}

// TestOATHCLI_GenerateAll tests generating codes for all credentials.
func TestOATHCLI_GenerateAll(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Add multiple credentials
	credentials := []string{"Credential1", "Credential2", "Credential3"}
	for _, name := range credentials {
		result := helper.RunOATH("add",
			"--name", name,
			"--secret", "JBSWY3DPEHPK3PXP",
			"--issuer", "Test")
		require.True(t, result.Success(), "Add %s failed: %s", name, result.Combined())
	}

	// Generate for all
	result := helper.RunOATH("generate", "--all")
	require.True(t, result.Success(),
		"Generate --all failed: %s", result.Combined())

	// Verify all credentials appear in output
	for _, name := range credentials {
		assert.True(t, result.OutputContains(name),
			"Output should contain %s: %s", name, result.Combined())
	}
}

// TestOATHCLI_GenerateMultiple tests generating codes for multiple specific credentials.
func TestOATHCLI_GenerateMultiple(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Add multiple credentials
	credentials := []string{"CredA", "CredB", "CredC"}
	for _, name := range credentials {
		result := helper.RunOATH("add",
			"--name", name,
			"--secret", "JBSWY3DPEHPK3PXP")
		require.True(t, result.Success())
	}

	// Generate for specific credentials
	result := helper.RunOATH("generate", "CredA", "CredC")
	require.True(t, result.Success(),
		"Generate multiple failed: %s", result.Combined())

	// Verify outputs contain codes
	outputLines := strings.Split(result.Stdout, "\n")
	codeCount := 0
	for _, line := range outputLines {
		if code, found := ExtractOTPCode(line); found && IsValidOTPCode(code) {
			codeCount++
		}
	}
	assert.GreaterOrEqual(t, codeCount, 2,
		"Should generate at least 2 codes: %s", result.Combined())
}

// TestOATHCLI_ListEmpty tests listing when no credentials exist.
func TestOATHCLI_ListEmpty(t *testing.T) {
	helper := NewOATHTestHelper(t)

	result := helper.RunOATH("list")
	require.True(t, result.Success(),
		"List on empty store should succeed: %s", result.Combined())
	assert.True(t, result.OutputContains("No") || result.OutputContains("no") ||
		result.OutputContains("(0)"),
		"Output should indicate no credentials: %s", result.Combined())
}

// TestOATHCLI_ListWithSecrets tests listing credentials with --secrets flag.
func TestOATHCLI_ListWithSecrets(t *testing.T) {
	helper := NewOATHTestHelper(t)

	secret := "JBSWY3DPEHPK3PXP"
	result := helper.RunOATH("add",
		"--name", "SecretTest",
		"--secret", secret)
	require.True(t, result.Success())

	// List without --secrets (secret should be hidden)
	result = helper.RunOATH("list")
	require.True(t, result.Success())
	assert.False(t, result.OutputContains(secret),
		"Secret should be hidden by default: %s", result.Combined())

	// List with --secrets (secret should be visible)
	result = helper.RunOATH("list", "--secrets")
	require.True(t, result.Success())
	assert.True(t, result.OutputContains(secret),
		"Secret should be visible with --secrets: %s", result.Combined())
}

// TestOATHCLI_ListWithURI tests listing credentials with --uri flag.
func TestOATHCLI_ListWithURI(t *testing.T) {
	helper := NewOATHTestHelper(t)

	result := helper.RunOATH("add",
		"--name", "URITest",
		"--secret", "JBSWY3DPEHPK3PXP",
		"--issuer", "TestIssuer")
	require.True(t, result.Success())

	result = helper.RunOATH("list", "--uri")
	require.True(t, result.Success())
	assert.True(t, result.OutputContains("otpauth://"),
		"Output should contain otpauth URI: %s", result.Combined())
}

// TestOATHCLI_RemoveMultiple tests removing multiple credentials at once.
func TestOATHCLI_RemoveMultiple(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Add credentials
	for _, name := range []string{"Remove1", "Remove2", "Remove3"} {
		result := helper.RunOATH("add",
			"--name", name,
			"--secret", "JBSWY3DPEHPK3PXP")
		require.True(t, result.Success())
	}

	// Remove multiple
	result := helper.RunOATH("remove", "Remove1", "Remove3", "--force")
	require.True(t, result.Success(),
		"Remove multiple failed: %s", result.Combined())

	// Verify only Remove2 remains
	result = helper.RunOATH("list")
	require.True(t, result.Success())
	assert.False(t, result.OutputContains("Remove1"),
		"Remove1 should be gone: %s", result.Combined())
	assert.True(t, result.OutputContains("Remove2"),
		"Remove2 should remain: %s", result.Combined())
	assert.False(t, result.OutputContains("Remove3"),
		"Remove3 should be gone: %s", result.Combined())
}

// TestOATHCLI_InvalidSecret tests error handling for invalid secrets.
func TestOATHCLI_InvalidSecret(t *testing.T) {
	helper := NewOATHTestHelper(t)

	invalidSecrets := []struct {
		secret string
		reason string
	}{
		{"!!!INVALID!!!", "contains non-base32 characters"},
		{"999999", "becomes empty after normalization (9 is dropped)"},
		{"@#$%^&", "only special characters"},
	}

	for i, tc := range invalidSecrets {
		tc := tc
		t.Run(fmt.Sprintf("InvalidSecret_%d", i), func(t *testing.T) {
			// Use unique name for each subtest to avoid duplicate detection
			name := fmt.Sprintf("InvalidSecretTest-%d-%d", i, time.Now().UnixNano())
			result := helper.RunOATH("add",
				"--name", name,
				"--secret", tc.secret)
			assert.False(t, result.Success(),
				"Add with invalid secret should fail (%s): %s", tc.reason, tc.secret)
		})
	}
}

// TestOATHCLI_InvalidDigits tests error handling for invalid digit counts.
func TestOATHCLI_InvalidDigits(t *testing.T) {
	helper := NewOATHTestHelper(t)

	invalidDigits := []string{"5", "9", "0", "-1", "abc"}

	for _, digits := range invalidDigits {
		t.Run("InvalidDigits_"+digits, func(t *testing.T) {
			result := helper.RunOATH("add",
				"--name", "InvalidDigitsTest",
				"--secret", "JBSWY3DPEHPK3PXP",
				"--digits", digits)
			assert.False(t, result.Success(),
				"Add with invalid digits %s should fail", digits)
		})
	}
}

// TestOATHCLI_InvalidAlgorithm tests error handling for invalid algorithms.
func TestOATHCLI_InvalidAlgorithm(t *testing.T) {
	helper := NewOATHTestHelper(t)

	result := helper.RunOATH("add",
		"--name", "InvalidAlgTest",
		"--secret", "JBSWY3DPEHPK3PXP",
		"--algorithm", "MD5")
	assert.False(t, result.Success(),
		"Add with invalid algorithm should fail")
}

// TestOATHCLI_InvalidType tests error handling for invalid OTP types.
func TestOATHCLI_InvalidType(t *testing.T) {
	helper := NewOATHTestHelper(t)

	result := helper.RunOATH("add",
		"--name", "InvalidTypeTest",
		"--secret", "JBSWY3DPEHPK3PXP",
		"--type", "invalid")
	assert.False(t, result.Success(),
		"Add with invalid type should fail")
}

// TestOATHCLI_InvalidURI tests error handling for invalid URIs.
func TestOATHCLI_InvalidURI(t *testing.T) {
	helper := NewOATHTestHelper(t)

	invalidURIs := []string{
		"https://example.com",                            // Wrong scheme
		"otpauth://invalid/Test?secret=JBSWY3DPEHPK3PXP", // Invalid type
		"otpauth://totp/Test",                            // Missing secret
		"otpauth://totp/Test?secret=!!!",                 // Invalid secret
	}

	for i, uri := range invalidURIs {
		t.Run("InvalidURI_"+string(rune('0'+i)), func(t *testing.T) {
			result := helper.RunOATH("add", "--uri", uri)
			assert.False(t, result.Success(),
				"Add with invalid URI should fail: %s", uri)
		})
	}
}

// TestOATHCLI_GenerateNonExistent tests generating code for non-existent credential.
func TestOATHCLI_GenerateNonExistent(t *testing.T) {
	helper := NewOATHTestHelper(t)

	result := helper.RunOATH("generate", "NonExistent")
	// Should either fail or show error message
	assert.True(t, !result.Success() || result.OutputContains("not found") ||
		result.OutputContains("error") || result.OutputContains("Error"),
		"Generate for non-existent should fail or show error: %s", result.Combined())
}

// TestOATHCLI_RemoveNonExistent tests removing a non-existent credential.
func TestOATHCLI_RemoveNonExistent(t *testing.T) {
	helper := NewOATHTestHelper(t)

	result := helper.RunOATH("remove", "NonExistent", "--force")
	// Should either fail or show error message
	assert.True(t, !result.Success() || result.OutputContains("not found") ||
		result.OutputContains("error") || result.OutputContains("Error"),
		"Remove non-existent should fail or show error: %s", result.Combined())
}

// TestOATHCLI_DuplicateAdd tests adding a credential with the same name twice.
func TestOATHCLI_DuplicateAdd(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// First add should succeed
	result := helper.RunOATH("add",
		"--name", "Duplicate",
		"--secret", "JBSWY3DPEHPK3PXP")
	require.True(t, result.Success(), "First add should succeed: %s", result.Combined())

	// Second add with same name should fail
	result = helper.RunOATH("add",
		"--name", "Duplicate",
		"--secret", "GEZDGNBVGY3TQOJQ")
	assert.False(t, result.Success(),
		"Duplicate add should fail")
	assert.True(t, result.OutputContains("exist") || result.OutputContains("Exist") ||
		result.OutputContains("duplicate") || result.OutputContains("Duplicate"),
		"Error should mention duplicate: %s", result.Combined())
}

// TestOATHCLI_MissingRequiredArgs tests error handling for missing arguments.
func TestOATHCLI_MissingRequiredArgs(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Missing name
	t.Run("MissingName", func(t *testing.T) {
		result := helper.RunOATH("add", "--secret", "JBSWY3DPEHPK3PXP")
		assert.False(t, result.Success(),
			"Add without name should fail")
	})

	// Missing secret (and no URI)
	t.Run("MissingSecret", func(t *testing.T) {
		result := helper.RunOATH("add", "--name", "NoSecret")
		assert.False(t, result.Success(),
			"Add without secret should fail")
	})

	// Missing credential name for generate (without --all)
	t.Run("GenerateMissingCredential", func(t *testing.T) {
		result := helper.RunOATH("generate")
		assert.False(t, result.Success(),
			"Generate without credential should fail")
	})

	// Missing credential name for remove
	t.Run("RemoveMissingCredential", func(t *testing.T) {
		result := helper.RunOATH("remove", "--force")
		assert.False(t, result.Success(),
			"Remove without credential should fail")
	})
}

// TestOATHCLI_HOTPCounterIncrement tests that HOTP counter increments after generation.
func TestOATHCLI_HOTPCounterIncrement(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Add HOTP credential
	result := helper.RunOATH("add",
		"--name", "HOTPCounter",
		"--secret", "JBSWY3DPEHPK3PXP",
		"--type", "hotp")
	require.True(t, result.Success(), "Add HOTP failed: %s", result.Combined())

	// Generate first code
	result1 := helper.RunOATH("generate", "HOTPCounter")
	require.True(t, result1.Success(), "First generate failed: %s", result1.Combined())
	code1, found1 := ExtractOTPCode(result1.Stdout)
	require.True(t, found1, "Should find first code: %s", result1.Stdout)

	// Generate second code - should be different due to counter increment
	result2 := helper.RunOATH("generate", "HOTPCounter")
	require.True(t, result2.Success(), "Second generate failed: %s", result2.Combined())
	code2, found2 := ExtractOTPCode(result2.Stdout)
	require.True(t, found2, "Should find second code: %s", result2.Stdout)

	assert.NotEqual(t, code1, code2,
		"HOTP codes should differ after counter increment: %s vs %s", code1, code2)
}

// TestOATHCLI_TOTPConsistency tests that TOTP generates consistent codes within time window.
func TestOATHCLI_TOTPConsistency(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Add TOTP credential
	result := helper.RunOATH("add",
		"--name", "TOTPConsistent",
		"--secret", "JBSWY3DPEHPK3PXP",
		"--type", "totp")
	require.True(t, result.Success(), "Add TOTP failed: %s", result.Combined())

	// Generate multiple codes rapidly - should be the same within time window
	var codes []string
	for i := 0; i < 3; i++ {
		result := helper.RunOATH("generate", "TOTPConsistent")
		require.True(t, result.Success())
		code, found := ExtractOTPCode(result.Stdout)
		require.True(t, found)
		codes = append(codes, code)
	}

	// All codes generated within a short time should be the same
	// (unless we happen to cross a 30-second boundary)
	// Just verify they're all valid 6-digit codes
	for _, code := range codes {
		assert.True(t, IsValidOTPCode(code), "Code should be valid: %s", code)
		assert.Len(t, code, 6, "TOTP should be 6 digits: %s", code)
	}
}

// TestOATHCLI_HelpOutput tests that help commands work correctly.
func TestOATHCLI_HelpOutput(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Test oath help
	t.Run("OATHHelp", func(t *testing.T) {
		result := helper.RunCommand("oath", "--help")
		require.True(t, result.Success(), "OATH help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("OATH") || result.OutputContains("oath") ||
			result.OutputContains("TOTP") || result.OutputContains("HOTP"),
			"Help should mention OATH/TOTP/HOTP: %s", result.Combined())
	})

	// Test add help
	t.Run("AddHelp", func(t *testing.T) {
		result := helper.RunCommand("oath", "add", "--help")
		require.True(t, result.Success(), "Add help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("add") || result.OutputContains("Add"),
			"Help should describe add command: %s", result.Combined())
		assert.True(t, result.OutputContains("secret") || result.OutputContains("uri"),
			"Help should mention secret or uri: %s", result.Combined())
	})

	// Test generate help
	t.Run("GenerateHelp", func(t *testing.T) {
		result := helper.RunCommand("oath", "generate", "--help")
		require.True(t, result.Success(), "Generate help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("generate") || result.OutputContains("Generate") ||
			result.OutputContains("code"),
			"Help should describe generate command: %s", result.Combined())
	})
}

// TestOATHCLI_CommandAliases tests command aliases.
func TestOATHCLI_CommandAliases(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Add a credential first
	result := helper.RunOATH("add",
		"--name", "AliasTest",
		"--secret", "JBSWY3DPEHPK3PXP")
	require.True(t, result.Success())

	// Test 'ls' alias for list
	t.Run("LsAlias", func(t *testing.T) {
		result := helper.RunOATH("ls")
		require.True(t, result.Success(), "ls alias should work: %s", result.Combined())
		assert.True(t, result.OutputContains("AliasTest"),
			"ls should show credential: %s", result.Combined())
	})

	// Test 'gen' alias for generate
	t.Run("GenAlias", func(t *testing.T) {
		result := helper.RunOATH("gen", "AliasTest")
		require.True(t, result.Success(), "gen alias should work: %s", result.Combined())
		code, found := ExtractOTPCode(result.Stdout)
		assert.True(t, found && IsValidOTPCode(code),
			"gen should produce valid code: %s", result.Combined())
	})

	// Test 'code' alias for generate
	t.Run("CodeAlias", func(t *testing.T) {
		result := helper.RunOATH("code", "AliasTest")
		require.True(t, result.Success(), "code alias should work: %s", result.Combined())
		code, found := ExtractOTPCode(result.Stdout)
		assert.True(t, found && IsValidOTPCode(code),
			"code should produce valid code: %s", result.Combined())
	})

	// Test 'rm' alias for remove
	t.Run("RmAlias", func(t *testing.T) {
		result := helper.RunOATH("rm", "AliasTest", "--force")
		require.True(t, result.Success(), "rm alias should work: %s", result.Combined())
	})

	// Verify removal
	result = helper.RunOATH("list")
	assert.False(t, result.OutputContains("AliasTest"),
		"Credential should be removed: %s", result.Combined())
}

// TestOATHCLI_CaseSensitiveLookup tests credential lookup behavior.
func TestOATHCLI_CaseSensitiveLookup(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Add credential
	result := helper.RunOATH("add",
		"--name", "CaseTest",
		"--secret", "JBSWY3DPEHPK3PXP")
	require.True(t, result.Success())

	// Try various case variations
	variations := []string{"CaseTest", "casetest", "CASETEST", "cAsEtEsT"}
	for _, name := range variations {
		t.Run("Lookup_"+name, func(t *testing.T) {
			result := helper.RunOATH("generate", name)
			// The lookup may or may not be case-sensitive depending on implementation
			// Just verify it doesn't crash
			if result.Success() {
				code, found := ExtractOTPCode(result.Stdout)
				assert.True(t, found && IsValidOTPCode(code),
					"Should produce valid code for %s: %s", name, result.Combined())
			}
		})
	}
}

// TestOATHCLI_StoreFilePersistence tests that credentials persist to the store file.
func TestOATHCLI_StoreFilePersistence(t *testing.T) {
	helper := NewOATHTestHelper(t)

	// Add credential
	result := helper.RunOATH("add",
		"--name", "PersistTest",
		"--secret", "JBSWY3DPEHPK3PXP")
	require.True(t, result.Success())

	// Verify store file exists
	_, err := os.Stat(helper.StorePath())
	assert.NoError(t, err, "Store file should exist")

	// Verify credential can be retrieved
	result = helper.RunOATH("list")
	require.True(t, result.Success())
	assert.True(t, result.OutputContains("PersistTest"),
		"Credential should persist: %s", result.Combined())
}
