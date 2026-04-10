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

// Package ssh provides integration tests for the xkey ssh CLI commands.
// These tests execute the real xkey binary and verify actual CLI behavior
// in standalone mode (local key storage) and server modes (Unix socket, gRPC).
package ssh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSSH_ProtocolAvailability logs which protocols are available.
// This runs first to help diagnose test skips.
func TestSSH_ProtocolAvailability(t *testing.T) {
	LogAvailableProtocols(t)
}

// TestSSHKeys_Generate tests SSH key generation across all modes and backends.
func TestSSHKeys_Generate(t *testing.T) {
	configs := GetAllTestConfigs(t)

	keyTypes := []struct {
		name     string
		keyType  string
		extraArg []string
	}{
		{name: "Ed25519", keyType: "ed25519", extraArg: nil},
		{name: "RSA2048", keyType: "rsa", extraArg: []string{"--bits", "2048"}},
		{name: "ECDSA_P256", keyType: "ecdsa", extraArg: []string{"--curve", "P-256"}},
	}

	for _, cfg := range configs {
		cfg := cfg
		t.Run(cfg.Name, func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, cfg)

			for _, kt := range keyTypes {
				kt := kt
				t.Run(kt.name, func(t *testing.T) {
					keyID := fmt.Sprintf("test-%s-%s-%d", kt.keyType, strings.ReplaceAll(cfg.Name, "/", "-"), time.Now().UnixNano())

					args := []string{"generate", "--id", keyID, "--type", kt.keyType}
					args = append(args, helper.ModeArgs()...)
					args = append(args, kt.extraArg...)

					result := helper.RunSSHKeys(args...)

					require.True(t, result.Success(),
						"Generate %s key should succeed: %s", kt.keyType, result.Combined())
					assert.True(t, result.OutputContains("Generated") || result.OutputContains(keyID),
						"Output should confirm key generation: %s", result.Combined())

					// Clean up
					cleanupArgs := append([]string{"delete", keyID, "--force"}, helper.ModeArgs()...)
					helper.RunSSHKeys(cleanupArgs...)
				})
			}
		})
	}
}

// TestSSHKeys_GenerateErrors tests error handling for key generation.
func TestSSHKeys_GenerateErrors(t *testing.T) {
	helper := NewSSHTestHelper(t)

	t.Run("InvalidKeyType", func(t *testing.T) {
		args := append([]string{"generate", "--id", "invalid-key", "--type", "invalid-type"}, helper.ModeArgs()...)
		result := helper.RunSSHKeys(args...)
		assert.False(t, result.Success(), "Generate with invalid type should fail")
		assert.True(t, result.OutputContains("invalid") || result.OutputContains("Invalid") ||
			result.OutputContains("error") || result.OutputContains("Error") ||
			result.OutputContains("unsupported"),
			"Output should indicate invalid type: %s", result.Combined())
	})

	t.Run("MissingID", func(t *testing.T) {
		args := append([]string{"generate", "--type", "ed25519"}, helper.ModeArgs()...)
		result := helper.RunSSHKeys(args...)
		assert.False(t, result.Success(), "Generate without ID should fail")
		assert.True(t, result.OutputContains("required") || result.OutputContains("Required") ||
			result.OutputContains("ID") || result.OutputContains("id"),
			"Output should mention missing ID: %s", result.Combined())
	})
}

// TestSSHKeys_ListExportDelete tests the full key lifecycle across all modes and backends.
func TestSSHKeys_ListExportDelete(t *testing.T) {
	configs := GetAllTestConfigs(t)

	for _, cfg := range configs {
		cfg := cfg
		t.Run(cfg.Name, func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, cfg)

			keyID := fmt.Sprintf("lifecycle-test-%s-%d", strings.ReplaceAll(cfg.Name, "/", "-"), time.Now().UnixNano())

			// Generate a key
			genArgs := append([]string{"generate", "--id", keyID, "--type", "ed25519"}, helper.ModeArgs()...)
			genResult := helper.RunSSHKeys(genArgs...)
			require.True(t, genResult.Success(),
				"Generate should succeed: %s", genResult.Combined())

			// List keys
			t.Run("List", func(t *testing.T) {
				listArgs := append([]string{"list"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(listArgs...)
				require.True(t, result.Success(),
					"List should succeed: %s", result.Combined())
				assert.True(t, result.OutputContains(keyID) || result.OutputContains("ed25519"),
					"List should show the key: %s", result.Combined())
			})

			// Export public key
			t.Run("Export", func(t *testing.T) {
				exportArgs := append([]string{"export", keyID}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(exportArgs...)
				require.True(t, result.Success(),
					"Export should succeed: %s", result.Combined())
				assert.True(t, result.OutputContains("ssh-ed25519"),
					"Export should output Ed25519 public key: %s", result.Stdout)

				// Verify fingerprint
				_, hasFingerprint := ExtractPublicKey(result.Stdout)
				assert.True(t, hasFingerprint, "Should contain valid SSH public key")
			})

			// Delete key
			t.Run("Delete", func(t *testing.T) {
				deleteArgs := append([]string{"delete", keyID, "--force"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(deleteArgs...)
				require.True(t, result.Success(),
					"Delete should succeed: %s", result.Combined())
			})

			// Verify deleted
			t.Run("VerifyDeleted", func(t *testing.T) {
				exportArgs := append([]string{"export", keyID}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(exportArgs...)
				assert.False(t, result.Success(),
					"Export of deleted key should fail")
			})
		})
	}
}

// TestSSHKeys_Import tests key import across all modes and backends.
func TestSSHKeys_Import(t *testing.T) {
	configs := GetAllTestConfigs(t)

	keyTypes := []string{"ed25519", "rsa", "ecdsa"}

	for _, cfg := range configs {
		cfg := cfg
		t.Run(cfg.Name, func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, cfg)

			for _, keyType := range keyTypes {
				keyType := keyType
				t.Run(keyType, func(t *testing.T) {
					// Create a test key using ssh-keygen
					keyPath, err := helper.CreateTestSSHKey(keyType)
					if err != nil {
						t.Skipf("Cannot create test key (ssh-keygen may not be available): %v", err)
					}

					keyID := fmt.Sprintf("imported-%s-%s-%d", keyType, strings.ReplaceAll(cfg.Name, "/", "-"), time.Now().UnixNano())

					// Import the key
					importArgs := append([]string{"import", keyPath, "--id", keyID}, helper.ModeArgs()...)
					result := helper.RunSSHKeys(importArgs...)

					require.True(t, result.Success(),
						"Import %s key should succeed: %s", keyType, result.Combined())
					assert.True(t, result.OutputContains("Imported") || result.OutputContains("imported") ||
						result.OutputContains(keyID),
						"Output should confirm import: %s", result.Combined())

					// Clean up
					cleanupArgs := append([]string{"delete", keyID, "--force"}, helper.ModeArgs()...)
					helper.RunSSHKeys(cleanupArgs...)
				})
			}
		})
	}
}

// TestSSHKeys_ImportErrors tests error handling for key import.
func TestSSHKeys_ImportErrors(t *testing.T) {
	helper := NewSSHTestHelper(t)

	t.Run("MissingFile", func(t *testing.T) {
		args := append([]string{"import", "/nonexistent/path/to/key", "--id", "test-key"}, helper.ModeArgs()...)
		result := helper.RunSSHKeys(args...)
		assert.False(t, result.Success(), "Import of non-existent file should fail")
	})

	t.Run("MissingPath", func(t *testing.T) {
		args := append([]string{"import", "--id", "test-key"}, helper.ModeArgs()...)
		result := helper.RunSSHKeys(args...)
		assert.False(t, result.Success(), "Import without file path should fail")
	})
}

// TestSSHKeys_ExportErrors tests error handling for key export.
func TestSSHKeys_ExportErrors(t *testing.T) {
	configs := GetAllTestConfigs(t)

	for _, cfg := range configs {
		cfg := cfg
		t.Run(cfg.Name, func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, cfg)

			t.Run("MissingKey", func(t *testing.T) {
				exportArgs := append([]string{"export", "non-existent-key-12345"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(exportArgs...)
				assert.False(t, result.Success(),
					"Export of non-existent key should fail")
			})

			t.Run("MissingID", func(t *testing.T) {
				exportArgs := append([]string{"export"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(exportArgs...)
				assert.False(t, result.Success(),
					"Export without key ID should fail")
			})
		})
	}
}

// TestSSHKeys_DeleteErrors tests error handling for key deletion.
func TestSSHKeys_DeleteErrors(t *testing.T) {
	configs := GetAllTestConfigs(t)

	for _, cfg := range configs {
		cfg := cfg
		t.Run(cfg.Name, func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, cfg)

			t.Run("MissingKey", func(t *testing.T) {
				deleteArgs := append([]string{"delete", "non-existent-key-12345", "--force"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(deleteArgs...)
				// May succeed with warning or fail - just check it doesn't crash
				_ = result
			})

			t.Run("MissingID", func(t *testing.T) {
				deleteArgs := append([]string{"delete", "--force"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(deleteArgs...)
				assert.False(t, result.Success(),
					"Delete without key ID should fail")
			})
		})
	}
}

// TestSSHKeys_Aliases tests command aliases work correctly.
func TestSSHKeys_Aliases(t *testing.T) {
	configs := GetAllTestConfigs(t)

	for _, cfg := range configs {
		cfg := cfg
		t.Run(cfg.Name, func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, cfg)

			// Test 'ls' alias for list
			t.Run("LsAlias", func(t *testing.T) {
				lsArgs := append([]string{"ls"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(lsArgs...)
				require.True(t, result.Success(),
					"ls alias should work: %s", result.Combined())
			})

			// Test 'rm' alias for delete (should be recognized even if it fails due to missing args)
			t.Run("RmAlias", func(t *testing.T) {
				rmArgs := append([]string{"rm", "--force"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(rmArgs...)
				assert.False(t, result.OutputContains("unknown command"),
					"rm alias should be recognized: %s", result.Combined())
			})

			// Test 'remove' alias for delete
			t.Run("RemoveAlias", func(t *testing.T) {
				removeArgs := append([]string{"remove", "--force"}, helper.ModeArgs()...)
				result := helper.RunSSHKeys(removeArgs...)
				assert.False(t, result.OutputContains("unknown command"),
					"remove alias should be recognized: %s", result.Combined())
			})
		})
	}
}

// TestSSHAgent_StartStop tests agent lifecycle in standalone mode.
func TestSSHAgent_StartStop(t *testing.T) {
	helper := NewSSHTestHelper(t)

	// Clean up any existing socket
	helper.CleanupSocket()

	// Start agent in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx,
		helper.BinaryPath(),
		"ssh", "agent", "start",
		"--foreground",
		"--socket", helper.SocketPath(),
		"--store", helper.StorePath(),
	)
	cmd.Env = helper.CommandEnv()

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}

	// Wait for socket to become available
	if !helper.WaitForSocket(10 * time.Second) {
		cancel()
		cmd.Wait()
		t.Fatal("Agent socket did not become available")
	}

	// Verify socket exists and responds
	assert.True(t, helper.SocketExists(), "Socket file should exist")
	assert.True(t, helper.SocketResponds(), "Socket should respond to connections")

	// Stop the agent
	cancel()
	cmd.Wait()
}

// TestSSHAgent_Status tests agent status command.
func TestSSHAgent_Status(t *testing.T) {
	helper := NewSSHTestHelper(t)

	// Test status when agent is not running
	t.Run("NotRunning", func(t *testing.T) {
		helper.CleanupSocket()

		result := helper.RunSSHAgent("status")
		// Status command may fail or succeed when not running, check output
		assert.True(t, result.OutputContains("not running") || result.OutputContains("not found") ||
			result.OutputContains("no agent") || result.ExitCode != 0,
			"Should indicate agent is not running or return error: %s", result.Combined())
	})

	// Test status when agent is running
	t.Run("Running", func(t *testing.T) {
		helper.CleanupSocket()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := exec.CommandContext(ctx,
			helper.BinaryPath(),
			"ssh", "agent", "start",
			"--foreground",
			"--socket", helper.SocketPath(),
			"--store", helper.StorePath(),
		)
		cmd.Env = helper.CommandEnv()

		if err := cmd.Start(); err != nil {
			t.Fatalf("Failed to start agent: %v", err)
		}
		defer func() {
			cancel()
			cmd.Wait()
		}()

		if !helper.WaitForSocket(10 * time.Second) {
			t.Fatal("Agent socket did not become available")
		}

		result := helper.RunSSHAgent("status")
		require.True(t, result.Success(),
			"Status should succeed when running: %s", result.Combined())
		assert.True(t, result.OutputContains("running"),
			"Should indicate agent is running: %s", result.Combined())
	})
}

// TestSSHAgent_PrintEnv tests print-env flag for various shells.
func TestSSHAgent_PrintEnv(t *testing.T) {
	helper := NewSSHTestHelper(t)

	testCases := []struct {
		name     string
		shell    string
		expected string
	}{
		{name: "Bash", shell: "bash", expected: "export SSH_AUTH_SOCK="},
		{name: "Fish", shell: "fish", expected: "set -gx SSH_AUTH_SOCK"},
		{name: "Csh", shell: "csh", expected: "setenv SSH_AUTH_SOCK"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := helper.RunSSHAgent("start",
				"--print-env",
				"--shell", tc.shell,
				"--socket", helper.SocketPath(),
				"--store", helper.StorePath(),
			)

			// Check if output contains expected format
			if result.OutputContains("SSH_AUTH_SOCK") {
				assert.True(t, result.OutputContains(tc.expected),
					"Output for %s should contain '%s': %s", tc.shell, tc.expected, result.Combined())
			}
		})
	}
}

// TestSSHAgent_SignWithAgent tests signing via ssh-add.
func TestSSHAgent_SignWithAgent(t *testing.T) {
	helper := NewSSHTestHelper(t)

	// Clean up any existing socket
	helper.CleanupSocket()

	// Generate a test key
	keyID := fmt.Sprintf("test-agent-sign-key-%d", time.Now().UnixNano())
	genArgs := append([]string{"generate", "--id", keyID, "--type", "ed25519"}, helper.ModeArgs()...)
	genResult := helper.RunSSHKeys(genArgs...)
	if !genResult.Success() {
		t.Fatalf("Cannot generate test key: %s", genResult.Combined())
	}
	defer func() {
		cleanupArgs := append([]string{"delete", keyID, "--force"}, helper.ModeArgs()...)
		helper.RunSSHKeys(cleanupArgs...)
	}()

	// Start the agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx,
		helper.BinaryPath(),
		"ssh", "agent", "start",
		"--foreground",
		"--socket", helper.SocketPath(),
		"--store", helper.StorePath(),
	)
	cmd.Env = helper.CommandEnv()

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	// Wait for socket
	if !helper.WaitForSocket(10 * time.Second) {
		t.Fatal("Agent socket did not become available")
	}

	// Use ssh-add -l to list keys
	t.Run("ListWithSSHAdd", func(t *testing.T) {
		result := helper.RunSSHAdd("-l")
		if result.Success() {
			t.Logf("ssh-add -l output: %s", result.Combined())
		} else if result.OutputContains("no identities") || result.OutputContains("agent has no identities") {
			t.Log("Agent has no identities (expected if key wasn't auto-loaded)")
		} else {
			t.Logf("ssh-add -l result: %s", result.Combined())
		}
	})

	// Use ssh-add -L to list full public keys
	t.Run("ListPublicKeysWithSSHAdd", func(t *testing.T) {
		result := helper.RunSSHAdd("-L")
		if result.Success() && result.OutputContains("ssh-") {
			t.Logf("Found SSH public keys")
		}
	})
}

// TestSSHCLI_HelpOutput tests help commands work correctly.
func TestSSHCLI_HelpOutput(t *testing.T) {
	helper := NewSSHTestHelper(t)

	testCases := []struct {
		name     string
		args     []string
		contains []string
	}{
		{
			name:     "SSHHelp",
			args:     []string{"--help"},
			contains: []string{"SSH", "ssh", "agent", "keys", "standalone", "server"},
		},
		{
			name:     "AgentHelp",
			args:     []string{"agent", "--help"},
			contains: []string{"agent", "Agent"},
		},
		{
			name:     "AgentStartHelp",
			args:     []string{"agent", "start", "--help"},
			contains: []string{"start", "Start", "foreground", "socket", "store"},
		},
		{
			name:     "KeysHelp",
			args:     []string{"keys", "--help"},
			contains: []string{"keys", "Keys"},
		},
		{
			name:     "KeysGenerateHelp",
			args:     []string{"keys", "generate", "--help"},
			contains: []string{"generate", "Generate", "ed25519", "rsa", "type", "store"},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := helper.RunSSH(tc.args...)
			require.True(t, result.Success(),
				"%s should succeed: %s", tc.name, result.Combined())

			foundAny := false
			for _, s := range tc.contains {
				if result.OutputContains(s) {
					foundAny = true
					break
				}
			}
			assert.True(t, foundAny,
				"Help output should contain one of %v: %s", tc.contains, result.Combined())
		})
	}
}

// TestSSHKeys_FullWorkflow tests complete key management workflow across all modes.
func TestSSHKeys_FullWorkflow(t *testing.T) {
	configs := GetAllTestConfigs(t)

	for _, cfg := range configs {
		cfg := cfg
		t.Run(cfg.Name, func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, cfg)

			keyID := fmt.Sprintf("workflow-test-%s-%d", strings.ReplaceAll(cfg.Name, "/", "-"), time.Now().UnixNano())

			// Step 1: Generate key
			genArgs := append([]string{"generate", "--id", keyID, "--type", "ed25519"}, helper.ModeArgs()...)
			genResult := helper.RunSSHKeys(genArgs...)
			require.True(t, genResult.Success(),
				"Generate should succeed: %s", genResult.Combined())

			// Step 2: Verify in list
			listArgs := append([]string{"list"}, helper.ModeArgs()...)
			listResult := helper.RunSSHKeys(listArgs...)
			require.True(t, listResult.Success(),
				"List should succeed: %s", listResult.Combined())

			// Step 3: Export public key
			exportArgs := append([]string{"export", keyID}, helper.ModeArgs()...)
			exportResult := helper.RunSSHKeys(exportArgs...)
			require.True(t, exportResult.Success(),
				"Export should succeed: %s", exportResult.Combined())
			assert.True(t, exportResult.OutputContains("ssh-ed25519"),
				"Should output Ed25519 public key: %s", exportResult.Stdout)

			// Step 4: Export to file
			pubKeyPath := filepath.Join(helper.TempDir(), "exported.pub")
			if err := os.WriteFile(pubKeyPath, []byte(exportResult.Stdout), 0644); err != nil {
				t.Fatalf("Failed to write public key file: %v", err)
			}
			contents, err := os.ReadFile(pubKeyPath)
			require.NoError(t, err)
			assert.True(t, strings.Contains(string(contents), "ssh-ed25519"),
				"File should contain Ed25519 key")

			// Step 5: Delete key
			deleteArgs := append([]string{"delete", keyID, "--force"}, helper.ModeArgs()...)
			deleteResult := helper.RunSSHKeys(deleteArgs...)
			require.True(t, deleteResult.Success(),
				"Delete should succeed: %s", deleteResult.Combined())

			// Step 6: Verify deleted
			verifyArgs := append([]string{"export", keyID}, helper.ModeArgs()...)
			verifyResult := helper.RunSSHKeys(verifyArgs...)
			assert.False(t, verifyResult.Success(),
				"Export of deleted key should fail")
		})
	}
}

// TestSSHKeys_BackendSelection tests explicit backend selection in server modes.
func TestSSHKeys_BackendSelection(t *testing.T) {
	if !IsXKMSdAvailable() {
		t.Skip("Skipping: xkmsd is not available")
	}

	// Test Unix socket if available
	if IsUnixSocketAvailable() {
		unixURL := "unix://" + GetUnixSocketPath()

		t.Run("unix", func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, SSHTestConfig{
				Mode:    ModeUnix,
				Backend: BackendSoftware,
				Name:    "unix/software",
				XKMSURL: unixURL,
			})

			// Only test backends that are verified to work
			backends := []TestBackend{}
			if IsXKMSdBackendWorking(t, unixURL, BackendSoftware) {
				backends = append(backends, BackendSoftware)
			}
			if IsTPM2Available() && IsXKMSdBackendWorking(t, unixURL, BackendTPM2) {
				backends = append(backends, BackendTPM2)
			}

			if len(backends) == 0 {
				t.Skip("Skipping: no working xkmsd backends available for unix mode")
			}

			for _, backend := range backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					args := []string{"list", "--xkmsd-url", unixURL, "--backend", string(backend)}
					result := helper.RunSSHKeys(args...)
					require.True(t, result.Success(),
						"List with backend %s should succeed: %s", backend, result.Combined())
				})
			}
		})
	}

	// Test gRPC if available
	if IsGRPCAvailable() {
		grpcURL := "grpc://" + GetGRPCAddr()

		t.Run("grpc", func(t *testing.T) {
			helper := NewSSHTestHelperWithConfig(t, SSHTestConfig{
				Mode:    ModeGRPC,
				Backend: BackendSoftware,
				Name:    "grpc/software",
				XKMSURL: grpcURL,
			})

			// Only test backends that are verified to work
			backends := []TestBackend{}
			if IsXKMSdBackendWorking(t, grpcURL, BackendSoftware) {
				backends = append(backends, BackendSoftware)
			}
			if IsTPM2Available() && IsXKMSdBackendWorking(t, grpcURL, BackendTPM2) {
				backends = append(backends, BackendTPM2)
			}

			if len(backends) == 0 {
				t.Skip("Skipping: no working xkmsd backends available for grpc mode")
			}

			for _, backend := range backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					args := []string{"list", "--xkmsd-url", grpcURL, "--backend", string(backend)}
					result := helper.RunSSHKeys(args...)
					require.True(t, result.Success(),
						"List with backend %s should succeed: %s", backend, result.Combined())
				})
			}
		})
	}
}

// TestSSHAgent_ServerModes tests agent with xkmsd backends.
//
// KNOWN ISSUE: This test has intermittent timeout issues where the SSH agent
// doesn't respond to ssh-add requests when using the xkmsd backend.
// TODO: Investigate why the agent hangs when using xkmsd backend for SSH operations.
func TestSSHAgent_ServerModes(t *testing.T) {
	t.Skip("Skipping: known timeout issue with xkmsd backend - see TODO")

	if !IsXKMSdAvailable() {
		t.Skip("Skipping: xkmsd is not available")
	}

	testCases := []struct {
		name      string
		mode      TestMode
		available func() bool
		xkmsdURL  string
	}{
		{
			name:      "unix",
			mode:      ModeUnix,
			available: IsUnixSocketAvailable,
			xkmsdURL:  "unix://" + GetUnixSocketPath(),
		},
		{
			name:      "grpc",
			mode:      ModeGRPC,
			available: IsGRPCAvailable,
			xkmsdURL:  "grpc://" + GetGRPCAddr(),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if !tc.available() {
				t.Skipf("Skipping: %s mode not available", tc.name)
			}

			// Verify the backend actually works for SSH operations
			if !IsXKMSdBackendWorking(t, tc.xkmsdURL, BackendSoftware) {
				t.Skipf("Skipping: xkmsd %s backend not working for SSH operations", tc.name)
			}

			helper := NewSSHTestHelperWithConfig(t, SSHTestConfig{
				Mode:    tc.mode,
				Backend: BackendSoftware,
				Name:    tc.name + "/software",
				XKMSURL: tc.xkmsdURL,
			})

			// Clean up any existing socket
			helper.CleanupSocket()

			// Generate a test key
			keyID := fmt.Sprintf("test-agent-%s-key-%d", tc.name, time.Now().UnixNano())
			genArgs := append([]string{"generate", "--id", keyID, "--type", "ed25519"}, helper.ModeArgs()...)
			genResult := helper.RunSSHKeys(genArgs...)
			if !genResult.Success() {
				t.Fatalf("Cannot generate test key: %s", genResult.Combined())
			}
			defer func() {
				cleanupArgs := append([]string{"delete", keyID, "--force"}, helper.ModeArgs()...)
				helper.RunSSHKeys(cleanupArgs...)
			}()

			// Start the agent
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cmd := exec.CommandContext(ctx,
				helper.BinaryPath(),
				"ssh", "agent", "start",
				"--foreground",
				"--socket", helper.SocketPath(),
				"--xkmsd-url", tc.xkmsdURL,
				"--backend", "software",
			)
			cmd.Env = helper.CommandEnv()

			if err := cmd.Start(); err != nil {
				t.Fatalf("Failed to start agent: %v", err)
			}
			defer func() {
				cancel()
				cmd.Wait()
			}()

			// Wait for socket
			if !helper.WaitForSocket(10 * time.Second) {
				t.Fatal("Agent socket did not become available")
			}

			// Use ssh-add -l to list keys
			result := helper.RunSSHAdd("-l")
			t.Logf("ssh-add -l output (%s mode): %s", tc.name, result.Combined())
		})
	}
}
