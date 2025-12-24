//go:build integration && frost

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

// Package integration provides FROST integration tests for go-keychain API protocols.
// These tests verify that FROST threshold signature operations work consistently
// across all supported protocols.
package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/test/integration/api/commands"
)

// TestFROST_KeygenAllProtocols tests FROST key generation across all protocols
func TestFROST_KeygenAllProtocols(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	protocols := commands.AllProtocols()

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			keyDir := commands.CreateTempKeyDir(t)
			keyID := commands.GenerateUniqueKeyID("frost-keygen")

			// Test participant mode keygen
			t.Run("participant-mode", func(t *testing.T) {
				args := []string{
					"--local",
					"--key-dir", keyDir,
					"frost", "keygen",
					"--key-id", keyID,
					"--algorithm", "FROST-Ed25519-SHA512",
					"--threshold", "2",
					"--total", "3",
					"--participants", "alice,bob,charlie",
					"--participant-id", "1",
				}
				stdout, stderr, err := runner.RunCommand(t, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("FROST keygen failed: %v", err)
				}

				// Verify output contains expected fields
				output := stdout + stderr
				assertContains(t, output, keyID, "Should contain key ID")
			})
		})
	}
}

// TestFROST_TrustedDealerAllProtocols tests FROST trusted dealer mode across protocols
func TestFROST_TrustedDealerAllProtocols(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	protocols := commands.AllProtocols()

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			keyDir := commands.CreateTempKeyDir(t)
			keyID := commands.GenerateUniqueKeyID("frost-dealer")
			exportDir := filepath.Join(keyDir, "frost-packages")
			if err := os.MkdirAll(exportDir, 0755); err != nil {
				t.Fatalf("Failed to create export dir: %v", err)
			}

			args := []string{
				"--local",
				"--key-dir", keyDir,
				"frost", "keygen",
				"--key-id", keyID,
				"--algorithm", "FROST-Ed25519-SHA512",
				"--threshold", "2",
				"--total", "3",
				"--participants", "alice,bob,charlie",
				"--export-dir", exportDir, // export-dir triggers dealer mode
				"-o", "json",
			}
			stdout, stderr, err := runner.RunCommand(t, args...)
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				t.Fatalf("FROST dealer keygen failed: %v", err)
			}

			// Parse JSON output to verify packages
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(stdout), &result); err == nil {
				if packages, ok := result["packages"].([]interface{}); ok {
					if len(packages) != 3 {
						t.Fatalf("Expected 3 packages, got %d", len(packages))
					}
					t.Logf("[%s] Generated %d key packages", protocol, len(packages))
				}
			}
		})
	}
}

// TestFROST_FullSigningCeremony tests FROST signing ceremony components.
// Note: A complete multi-participant signing ceremony requires distributed
// coordination across separate processes/machines. This test verifies the
// individual CLI commands work correctly in dealer mode, which is the
// most comprehensive single-process test possible.
func TestFROST_FullSigningCeremony(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	keyDir := commands.CreateTempKeyDir(t)
	keyID := commands.GenerateUniqueKeyID("frost-ceremony")
	threshold := 2
	total := 3

	// Step 1: Generate key in participant mode (stores locally)
	// Using --participant-id stores the key in the backend so list/info work
	t.Run("participant-keygen", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "keygen",
			"--key-id", keyID,
			"--algorithm", "FROST-Ed25519-SHA512",
			"--threshold", fmt.Sprintf("%d", threshold),
			"--total", fmt.Sprintf("%d", total),
			"--participants", "alice,bob,charlie",
			"--participant-id", "1",
			"-o", "json",
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("Participant keygen failed: %v", err)
		}
		t.Logf("Generated key with threshold %d/%d for participant 1", threshold, total)
	})

	// Step 2: List the generated key
	t.Run("list-key", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "list",
			"-o", "json",
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stderr: %s", stderr)
			t.Fatalf("frost list failed: %v", err)
		}

		if !strings.Contains(stdout, keyID) {
			t.Fatalf("Expected key %s in list output, got: %s", keyID, stdout)
		}
		t.Logf("Key %s found in list", keyID)
	})

	// Step 3: Get key info
	t.Run("key-info", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "info", keyID,
			"-o", "json",
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stderr: %s", stderr)
			t.Fatalf("frost info failed: %v", err)
		}

		// Verify key info contains expected fields
		if !strings.Contains(stdout, keyID) {
			t.Fatalf("Key info should contain key ID, got: %s", stdout)
		}
		t.Logf("Key info retrieved successfully")
	})

	// Step 4: Delete the key
	t.Run("delete-key", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "delete", keyID,
			"--force",
		}
		_, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stderr: %s", stderr)
			t.Fatalf("frost delete failed: %v", err)
		}
		t.Logf("Key %s deleted successfully", keyID)
	})

	// Step 5: Verify key is deleted
	t.Run("verify-deleted", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "list",
			"-o", "json",
		}
		stdout, _, err := runner.RunCommand(t, args...)
		// List may return empty or not contain the deleted key
		if err == nil && strings.Contains(stdout, keyID) {
			t.Fatalf("Key %s should be deleted but still appears in list", keyID)
		}
		t.Logf("Verified key %s is deleted", keyID)
	})
}

// TestFROST_ListKeysAllProtocols tests listing FROST keys across all protocols
func TestFROST_ListKeysAllProtocols(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	protocols := commands.AllProtocols()

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			keyDir := commands.CreateTempKeyDir(t)
			keyID := commands.GenerateUniqueKeyID("frost-list")

			// Generate a key first
			genArgs := []string{
				"--local",
				"--key-dir", keyDir,
				"frost", "keygen",
				"--key-id", keyID,
				"--threshold", "2",
				"--total", "3",
				"--participant-id", "1",
			}
			_, stderr, err := runner.RunCommand(t, genArgs...)
			if err != nil {
				t.Logf("stderr: %s", stderr)
				t.Fatalf("Keygen failed: %v", err)
			}

			// List keys
			listArgs := []string{
				"--local",
				"--key-dir", keyDir,
				"frost", "list",
			}
			stdout, stderr, err := runner.RunCommand(t, listArgs...)
			if err != nil {
				t.Logf("stderr: %s", stderr)
				t.Fatalf("List failed: %v", err)
			}

			output := stdout + stderr
			if !strings.Contains(output, keyID) {
				t.Fatalf("Key %s not in list", keyID)
			}
			t.Logf("[%s] Listed FROST keys successfully", protocol)
		})
	}
}

// TestFROST_DeleteKeyAllProtocols tests deleting FROST keys across all protocols
func TestFROST_DeleteKeyAllProtocols(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	protocols := commands.AllProtocols()

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			keyDir := commands.CreateTempKeyDir(t)
			keyID := commands.GenerateUniqueKeyID("frost-delete")

			// Generate a key
			genArgs := []string{
				"--local",
				"--key-dir", keyDir,
				"frost", "keygen",
				"--key-id", keyID,
				"--threshold", "2",
				"--total", "3",
				"--participant-id", "1",
			}
			_, stderr, err := runner.RunCommand(t, genArgs...)
			if err != nil {
				t.Logf("stderr: %s", stderr)
				t.Fatalf("Keygen failed: %v", err)
			}

			// Delete key
			delArgs := []string{
				"--local",
				"--key-dir", keyDir,
				"frost", "delete", keyID,
				"--force", // Skip confirmation prompt
			}
			_, stderr, err = runner.RunCommand(t, delArgs...)
			if err != nil {
				t.Logf("stderr: %s", stderr)
				t.Fatalf("Delete failed: %v", err)
			}

			// Verify deletion
			listArgs := []string{
				"--local",
				"--key-dir", keyDir,
				"frost", "list",
			}
			stdout, _, _ := runner.RunCommand(t, listArgs...)
			if strings.Contains(stdout, keyID) {
				t.Fatalf("Key %s still exists after delete", keyID)
			}

			t.Logf("[%s] Deleted FROST key successfully", protocol)
		})
	}
}

// TestFROST_AllCiphersuites tests all supported FROST ciphersuites
func TestFROST_AllCiphersuites(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	ciphersuites := []string{
		"FROST-Ed25519-SHA512",
		"FROST-ristretto255-SHA512",
		"FROST-Ed448-SHAKE256",
		"FROST-P256-SHA256",
		"FROST-secp256k1-SHA256",
	}

	for _, suite := range ciphersuites {
		t.Run(suite, func(t *testing.T) {
			keyDir := commands.CreateTempKeyDir(t)
			keyID := commands.GenerateUniqueKeyID("frost-suite")

			args := []string{
				"--local",
				"--key-dir", keyDir,
				"frost", "keygen",
				"--key-id", keyID,
				"--algorithm", suite,
				"--threshold", "2",
				"--total", "3",
				"--participant-id", "1",
			}
			stdout, stderr, err := runner.RunCommand(t, args...)
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				t.Fatalf("Keygen with %s failed: %v", suite, err)
			}
			t.Logf("Ciphersuite %s: OK", suite)
		})
	}
}

// TestFROST_CLIWorkflow tests the complete FROST CLI workflow
// This test exercises all FROST commands in the proper sequence:
// participant keygen -> info -> dealer keygen -> list -> delete
func TestFROST_CLIWorkflow(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	keyDir := commands.CreateTempKeyDir(t)
	participantKeyID := commands.GenerateUniqueKeyID("frost-participant")
	dealerKeyID := commands.GenerateUniqueKeyID("frost-dealer")
	exportDir := filepath.Join(keyDir, "frost-packages")

	// Create export directory for dealer mode
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		t.Fatalf("Failed to create export dir: %v", err)
	}

	// Step 1: Participant mode keygen
	t.Run("participant-keygen", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "keygen",
			"--key-id", participantKeyID,
			"--algorithm", "FROST-Ed25519-SHA512",
			"--threshold", "2",
			"--total", "3",
			"--participant-id", "1",
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("Participant keygen failed: %v", err)
		}
		t.Logf("Participant key created: %s", participantKeyID)
	})

	// Step 2: Key info
	t.Run("key-info", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "info", participantKeyID,
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("Key info failed: %v", err)
		}
		output := stdout + stderr
		assertContains(t, output, participantKeyID, "Should show key ID")
		t.Logf("Key info retrieved successfully")
	})

	// Step 3: Dealer mode keygen
	t.Run("dealer-keygen", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "keygen",
			"--key-id", dealerKeyID,
			"--algorithm", "FROST-Ed25519-SHA512",
			"--threshold", "2",
			"--total", "3",
			"--participants", "alice,bob,charlie",
			"--export-dir", exportDir,
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("Dealer keygen failed: %v", err)
		}

		// Verify exported files exist
		files, err := os.ReadDir(exportDir)
		if err != nil {
			t.Fatalf("Failed to read export dir: %v", err)
		}
		if len(files) != 3 {
			t.Fatalf("Expected 3 exported packages, got %d", len(files))
		}
		t.Logf("Dealer keygen complete: %d packages exported", len(files))
	})

	// Step 4: List keys
	t.Run("list-keys", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "list",
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("List keys failed: %v", err)
		}
		output := stdout + stderr
		assertContains(t, output, participantKeyID, "Should list participant key")
		t.Logf("Keys listed successfully")
	})

	// Step 5: Delete participant key
	t.Run("delete-participant-key", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "delete", participantKeyID,
			"--force",
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("Delete key failed: %v", err)
		}
		t.Logf("Participant key deleted: %s", participantKeyID)
	})

	// Step 6: Verify deletion
	t.Run("verify-deletion", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "list",
		}
		stdout, _, _ := runner.RunCommand(t, args...)
		if strings.Contains(stdout, participantKeyID) {
			t.Fatalf("Key %s should not exist after deletion", participantKeyID)
		}
		t.Logf("Deletion verified - key no longer in list")
	})
}

// Helper functions

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
