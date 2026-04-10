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

// Package piv provides integration tests for the xkey piv CLI commands.
// These tests execute the real xkey binary and verify actual CLI behavior.
package piv

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPIVCLI_FullWorkflow tests the complete PIV certificate management workflow
// using the real xkey CLI binary.
func TestPIVCLI_FullWorkflow(t *testing.T) {
	helper := NewPIVTestHelper(t)

	// Create a test certificate file
	certPath := helper.CreateTestCertFile("test-piv-workflow")

	// Step 1: Store certificate in slot 9a (PIV Authentication)
	t.Run("Store", func(t *testing.T) {
		result := helper.RunPIV("store", "9a", certPath)
		require.True(t, result.Success(),
			"Store command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains("stored"),
			"Output should confirm certificate was stored: %s", result.Combined())
		assert.True(t, result.OutputContains("9a"),
			"Output should reference slot 9a: %s", result.Combined())
	})

	// Step 2: Verify certificate appears in list
	t.Run("List", func(t *testing.T) {
		result := helper.RunPIV("list")
		require.True(t, result.Success(),
			"List command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains("9a"),
			"List output should contain slot 9a: %s", result.Combined())
		assert.True(t, result.OutputContains("test-piv-workflow"),
			"List output should contain certificate subject: %s", result.Combined())
	})

	// Step 3: Show certificate details
	t.Run("Show", func(t *testing.T) {
		result := helper.RunPIV("show", "9a")
		require.True(t, result.Success(),
			"Show command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains("test-piv-workflow"),
			"Show output should contain subject: %s", result.Combined())
		assert.True(t, result.OutputContains("Subject"),
			"Show output should have Subject field: %s", result.Combined())
	})

	// Step 4: Export certificate in PEM format
	t.Run("ExportPEM", func(t *testing.T) {
		exportPath := filepath.Join(helper.StoragePath(), "exported-9a.pem")
		result := helper.RunPIV("export", "9a", "--format", "pem", "--output", exportPath)
		require.True(t, result.Success(),
			"Export PEM command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)

		// Verify the exported file exists and is valid PEM
		exportedData, err := os.ReadFile(exportPath)
		require.NoError(t, err, "Should be able to read exported file")

		block, _ := pem.Decode(exportedData)
		require.NotNil(t, block, "Exported file should be valid PEM")
		assert.Equal(t, "CERTIFICATE", block.Type, "PEM type should be CERTIFICATE")
	})

	// Step 5: Export certificate in DER format
	t.Run("ExportDER", func(t *testing.T) {
		exportPath := filepath.Join(helper.StoragePath(), "exported-9a.der")
		result := helper.RunPIV("export", "9a", "--format", "der", "--output", exportPath)
		require.True(t, result.Success(),
			"Export DER command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)

		// Verify the exported file exists and has content
		exportedData, err := os.ReadFile(exportPath)
		require.NoError(t, err, "Should be able to read exported DER file")
		assert.NotEmpty(t, exportedData, "Exported DER file should have content")
	})

	// Step 6: Delete certificate with force flag
	t.Run("Delete", func(t *testing.T) {
		result := helper.RunPIV("delete", "9a", "--force")
		require.True(t, result.Success(),
			"Delete command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains("deleted") || result.OutputContains("Deleted"),
			"Output should confirm deletion: %s", result.Combined())
	})

	// Step 7: Verify certificate is gone from list
	t.Run("ListAfterDelete", func(t *testing.T) {
		result := helper.RunPIV("list")
		require.True(t, result.Success(),
			"List command failed after delete: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.False(t, result.OutputContains("test-piv-workflow"),
			"List output should not contain deleted certificate: %s", result.Combined())
	})
}

// TestPIVCLI_StoreAllPrimarySlots tests storing certificates in all primary PIV slots.
func TestPIVCLI_StoreAllPrimarySlots(t *testing.T) {
	helper := NewPIVTestHelper(t)

	slots := []struct {
		slot string
		name string
	}{
		{"9a", "PIV Authentication"},
		{"9c", "Digital Signature"},
		{"9d", "Key Management"},
		{"9e", "Card Authentication"},
	}

	// Store certificates in all slots
	for _, s := range slots {
		t.Run("Store_"+s.slot, func(t *testing.T) {
			certPath := helper.CreateTestCertFile("test-slot-" + s.slot)
			result := helper.RunPIV("store", s.slot, certPath)
			require.True(t, result.Success(),
				"Failed to store in slot %s: %s", s.slot, result.Combined())
		})
	}

	// Verify all slots appear in list
	t.Run("ListAllSlots", func(t *testing.T) {
		result := helper.RunPIV("list")
		require.True(t, result.Success(), "List command failed: %s", result.Combined())

		for _, s := range slots {
			assert.True(t, result.OutputContains(s.slot),
				"List should contain slot %s: %s", s.slot, result.Combined())
		}
	})

	// Show status
	t.Run("Status", func(t *testing.T) {
		result := helper.RunPIV("status")
		require.True(t, result.Success(), "Status command failed: %s", result.Combined())
		assert.True(t, result.OutputContains("4/4") || result.OutputContains("4"),
			"Status should show 4 certificates: %s", result.Combined())
	})
}

// TestPIVCLI_StorePEMAndDER tests storing certificates in both PEM and DER formats.
func TestPIVCLI_StorePEMAndDER(t *testing.T) {
	helper := NewPIVTestHelper(t)

	// Test PEM format
	t.Run("StorePEM", func(t *testing.T) {
		certPath := helper.CreateTestCertFile("test-pem-format")
		result := helper.RunPIV("store", "9a", certPath)
		require.True(t, result.Success(),
			"Store PEM failed: %s", result.Combined())
		assert.True(t, result.OutputContains("PEM") || result.OutputContains("pem"),
			"Output should mention PEM format: %s", result.Combined())
	})

	// Delete and test DER format
	helper.RunPIV("delete", "9a", "--force")

	t.Run("StoreDER", func(t *testing.T) {
		cert := helper.GenerateTestCertificate("test-der-format")

		tmpFile, err := os.CreateTemp("", "piv-test-cert-*.der")
		require.NoError(t, err)
		tmpFile.Close()
		t.Cleanup(func() { os.Remove(tmpFile.Name()) })

		helper.WriteCertificateDER(cert, tmpFile.Name())

		result := helper.RunPIV("store", "9a", tmpFile.Name())
		require.True(t, result.Success(),
			"Store DER failed: %s", result.Combined())
		assert.True(t, result.OutputContains("DER") || result.OutputContains("der"),
			"Output should mention DER format: %s", result.Combined())
	})
}

// TestPIVCLI_InvalidSlot tests error handling for invalid slot identifiers.
func TestPIVCLI_InvalidSlot(t *testing.T) {
	helper := NewPIVTestHelper(t)

	invalidSlots := []string{
		"9f",   // Not a valid PIV slot
		"00",   // Invalid
		"ff",   // Invalid
		"abc",  // Invalid format
		"",     // Empty (will fail differently)
		"9a9a", // Too long
		"invalid",
	}

	certPath := helper.CreateTestCertFile("test-invalid-slot")

	for _, slot := range invalidSlots {
		if slot == "" {
			continue // Skip empty - needs different arg count
		}
		t.Run("InvalidSlot_"+slot, func(t *testing.T) {
			result := helper.RunPIV("store", slot, certPath)
			assert.False(t, result.Success(),
				"Store with invalid slot %s should fail", slot)
			assert.True(t, result.OutputContains("invalid") || result.OutputContains("Invalid") ||
				result.OutputContains("error") || result.OutputContains("Error"),
				"Output should indicate error for invalid slot %s: %s", slot, result.Combined())
		})
	}
}

// TestPIVCLI_ShowNonExistent tests showing a certificate from an empty slot.
func TestPIVCLI_ShowNonExistent(t *testing.T) {
	helper := NewPIVTestHelper(t)

	result := helper.RunPIV("show", "9a")
	assert.False(t, result.Success(),
		"Show on empty slot should fail")
	assert.True(t, result.OutputContains("not found") || result.OutputContains("Not found") ||
		result.OutputContains("error") || result.OutputContains("Error"),
		"Output should indicate certificate not found: %s", result.Combined())
}

// TestPIVCLI_DeleteNonExistent tests deleting from an empty slot.
func TestPIVCLI_DeleteNonExistent(t *testing.T) {
	helper := NewPIVTestHelper(t)

	result := helper.RunPIV("delete", "9a", "--force")
	assert.False(t, result.Success(),
		"Delete on empty slot should fail")
	assert.True(t, result.OutputContains("not found") || result.OutputContains("Not found") ||
		result.OutputContains("error") || result.OutputContains("Error"),
		"Output should indicate certificate not found: %s", result.Combined())
}

// TestPIVCLI_ExportNonExistent tests exporting from an empty slot.
func TestPIVCLI_ExportNonExistent(t *testing.T) {
	helper := NewPIVTestHelper(t)

	exportPath := filepath.Join(helper.StoragePath(), "should-not-exist.pem")
	result := helper.RunPIV("export", "9a", "--format", "pem", "--output", exportPath)
	assert.False(t, result.Success(),
		"Export from empty slot should fail")

	// Verify no file was created
	_, err := os.Stat(exportPath)
	assert.True(t, os.IsNotExist(err),
		"Export file should not exist after failed export")
}

// TestPIVCLI_ListEmpty tests listing when no certificates are stored.
func TestPIVCLI_ListEmpty(t *testing.T) {
	helper := NewPIVTestHelper(t)

	result := helper.RunPIV("list")
	require.True(t, result.Success(),
		"List on empty storage should succeed: %s", result.Combined())
	assert.True(t, result.OutputContains("No certificates") || result.OutputContains("no certificates") ||
		result.OutputContains("(0)"),
		"Output should indicate no certificates: %s", result.Combined())
}

// TestPIVCLI_Status tests the status command output.
func TestPIVCLI_Status(t *testing.T) {
	helper := NewPIVTestHelper(t)

	t.Run("EmptyStatus", func(t *testing.T) {
		result := helper.RunPIV("status")
		require.True(t, result.Success(), "Status command should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("Storage") || result.OutputContains("storage"),
			"Status should show storage info: %s", result.Combined())
		assert.True(t, result.OutputContains("software") || result.OutputContains("file"),
			"Status should show backend type: %s", result.Combined())
	})

	// Store a certificate and check status again
	certPath := helper.CreateTestCertFile("test-status")
	helper.RunPIV("store", "9a", certPath)

	t.Run("StatusWithCert", func(t *testing.T) {
		result := helper.RunPIV("status")
		require.True(t, result.Success(), "Status command should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("9a"),
			"Status should show populated slot: %s", result.Combined())
	})
}

// TestPIVCLI_StoreOverwrite tests overwriting an existing certificate.
func TestPIVCLI_StoreOverwrite(t *testing.T) {
	helper := NewPIVTestHelper(t)

	// Store first certificate
	certPath1 := helper.CreateTestCertFile("first-cert")
	result := helper.RunPIV("store", "9a", certPath1)
	require.True(t, result.Success(), "First store should succeed: %s", result.Combined())

	// Verify first certificate
	result = helper.RunPIV("show", "9a")
	require.True(t, result.Success())
	assert.True(t, result.OutputContains("first-cert"),
		"Should show first certificate: %s", result.Combined())

	// Store second certificate (overwrite)
	certPath2 := helper.CreateTestCertFile("second-cert")
	result = helper.RunPIV("store", "9a", certPath2)
	require.True(t, result.Success(), "Overwrite store should succeed: %s", result.Combined())

	// Verify second certificate replaced the first
	result = helper.RunPIV("show", "9a")
	require.True(t, result.Success())
	assert.True(t, result.OutputContains("second-cert"),
		"Should show second certificate after overwrite: %s", result.Combined())
	assert.False(t, result.OutputContains("first-cert"),
		"Should not show first certificate after overwrite: %s", result.Combined())
}

// TestPIVCLI_InvalidCertificateFile tests error handling for invalid certificate files.
func TestPIVCLI_InvalidCertificateFile(t *testing.T) {
	helper := NewPIVTestHelper(t)

	// Test non-existent file
	t.Run("NonExistentFile", func(t *testing.T) {
		result := helper.RunPIV("store", "9a", "/nonexistent/path/cert.pem")
		assert.False(t, result.Success(), "Store with non-existent file should fail")
	})

	// Test invalid PEM content
	t.Run("InvalidPEM", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "invalid-cert-*.pem")
		require.NoError(t, err)
		tmpFile.WriteString("not a valid certificate")
		tmpFile.Close()
		t.Cleanup(func() { os.Remove(tmpFile.Name()) })

		result := helper.RunPIV("store", "9a", tmpFile.Name())
		assert.False(t, result.Success(), "Store with invalid PEM should fail")
	})

	// Test empty file
	t.Run("EmptyFile", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "empty-cert-*.pem")
		require.NoError(t, err)
		tmpFile.Close()
		t.Cleanup(func() { os.Remove(tmpFile.Name()) })

		result := helper.RunPIV("store", "9a", tmpFile.Name())
		assert.False(t, result.Success(), "Store with empty file should fail")
	})
}

// TestPIVCLI_ExportToStdout tests exporting to stdout (no --output flag).
func TestPIVCLI_ExportToStdout(t *testing.T) {
	helper := NewPIVTestHelper(t)

	// Store a certificate first
	certPath := helper.CreateTestCertFile("test-stdout-export")
	result := helper.RunPIV("store", "9a", certPath)
	require.True(t, result.Success(), "Store should succeed: %s", result.Combined())

	// Export to stdout
	result = helper.RunPIV("export", "9a", "--format", "pem")
	require.True(t, result.Success(), "Export to stdout should succeed: %s", result.Combined())

	// Verify stdout contains PEM certificate
	assert.True(t, strings.Contains(result.Stdout, "BEGIN CERTIFICATE"),
		"Stdout should contain PEM header: %s", result.Stdout)
	assert.True(t, strings.Contains(result.Stdout, "END CERTIFICATE"),
		"Stdout should contain PEM footer: %s", result.Stdout)
}

// TestPIVCLI_ExportInvalidFormat tests export with invalid format.
func TestPIVCLI_ExportInvalidFormat(t *testing.T) {
	helper := NewPIVTestHelper(t)

	// Store a certificate first
	certPath := helper.CreateTestCertFile("test-invalid-format")
	helper.RunPIV("store", "9a", certPath)

	// Try invalid format
	result := helper.RunPIV("export", "9a", "--format", "invalid")
	assert.False(t, result.Success(), "Export with invalid format should fail")
	assert.True(t, result.OutputContains("invalid") || result.OutputContains("Invalid"),
		"Output should indicate invalid format: %s", result.Combined())
}

// TestPIVCLI_HelpOutput tests that help commands work correctly.
func TestPIVCLI_HelpOutput(t *testing.T) {
	helper := NewPIVTestHelper(t)

	// Test piv help
	t.Run("PIVHelp", func(t *testing.T) {
		result := helper.RunCommand("piv", "--help")
		require.True(t, result.Success(), "PIV help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("PIV") || result.OutputContains("piv"),
			"Help should mention PIV: %s", result.Combined())
		assert.True(t, result.OutputContains("store") || result.OutputContains("list"),
			"Help should list subcommands: %s", result.Combined())
	})

	// Test store help
	t.Run("StoreHelp", func(t *testing.T) {
		result := helper.RunCommand("piv", "store", "--help")
		require.True(t, result.Success(), "Store help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("store") || result.OutputContains("Store"),
			"Help should describe store command: %s", result.Combined())
	})
}

// TestPIVCLI_SlotAliases tests slot name aliases (if supported).
func TestPIVCLI_SlotAliases(t *testing.T) {
	helper := NewPIVTestHelper(t)

	certPath := helper.CreateTestCertFile("test-slot-alias")

	// Test uppercase slot
	t.Run("UppercaseSlot", func(t *testing.T) {
		result := helper.RunPIV("store", "9A", certPath)
		// Should work (case insensitive) or fail with specific error
		if result.Success() {
			result = helper.RunPIV("show", "9a")
			assert.True(t, result.Success(), "Should find cert stored with uppercase slot")
			helper.RunPIV("delete", "9a", "--force")
		}
	})
}

// TestPIVCLI_CommandAliases tests command aliases (rm for delete, ls for list).
func TestPIVCLI_CommandAliases(t *testing.T) {
	helper := NewPIVTestHelper(t)

	// Store a certificate first
	certPath := helper.CreateTestCertFile("test-aliases")
	helper.RunPIV("store", "9a", certPath)

	// Test 'ls' alias for list
	t.Run("LsAlias", func(t *testing.T) {
		result := helper.RunPIV("ls")
		require.True(t, result.Success(), "ls alias should work: %s", result.Combined())
		assert.True(t, result.OutputContains("9a"),
			"ls should show stored certificate: %s", result.Combined())
	})

	// Test 'rm' alias for delete
	t.Run("RmAlias", func(t *testing.T) {
		result := helper.RunPIV("rm", "9a", "--force")
		require.True(t, result.Success(), "rm alias should work: %s", result.Combined())
	})

	// Verify deletion
	result := helper.RunPIV("list")
	assert.True(t, result.OutputContains("No certificates") || !result.OutputContains("test-aliases"),
		"Certificate should be deleted: %s", result.Combined())
}
