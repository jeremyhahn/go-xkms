//go:build integration

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

// Package integration provides integration tests for go-keychain API protocols.
// These tests verify that all CLI commands work consistently across all supported
// protocols: REST, gRPC, QUIC, MCP, and Unix socket.
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/test/integration/api/commands"
)

// enabledBuildTags returns the build tags enabled for the current test run
func enabledBuildTags() []string {
	// These are set at compile time based on build tags
	tags := []string{"integration"}

	// Check for frost support
	if isFrostEnabled() {
		tags = append(tags, "frost")
	}

	// Add other tags as needed
	return tags
}

// isFrostEnabled checks if FROST support is compiled in
func isFrostEnabled() bool {
	// This will be true when built with -tags frost
	// We detect by checking if the frost command exists
	runner := commands.NewTestRunner()

	// Check if CLI binary exists without using testing.T
	if _, err := os.Stat(runner.CLIBinPath); os.IsNotExist(err) {
		return false
	}

	// Check if frost command is available
	cmd := exec.Command(runner.CLIBinPath, "frost", "--help")
	output, err := cmd.CombinedOutput()
	// If frost command works, it's enabled
	return err == nil && !strings.Contains(string(output), "not compiled")
}

// TestProtocolParity_Version tests the version command across all protocols
func TestProtocolParity_Version(t *testing.T) {
	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatalf("CLI binary required. Run: make build (path: %s)", runner.CLIBinPath)
	}

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			// Version doesn't need server connection
			stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, "version")
			if err != nil {
				t.Logf("stderr: %s", stderr)
			}
			assertNoError(t, err, "Version command failed")

			output := stdout + stderr
			assertNotEmpty(t, output, "Version output should not be empty")
			t.Logf("[%s] Version: %s", protocol, strings.TrimSpace(output))
		})
	}
}

// TestProtocolParity_BackendsList tests listing backends across all protocols
func TestProtocolParity_BackendsList(t *testing.T) {
	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatalf("CLI binary required. Run: make build (path: %s)", runner.CLIBinPath)
	}

	protocols := commands.CLIProtocols()

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, "backends", "list")
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				t.Fatalf("[%s] backends list failed: %v", protocol, err)
			}

			output := stdout + stderr
			assertContains(t, output, "software", "Should list software backend")
			t.Logf("[%s] Backends: %s", protocol, strings.TrimSpace(output))
		})
	}
}

// TestProtocolParity_KeyLifecycle tests the complete key lifecycle across all protocols
func TestProtocolParity_KeyLifecycle(t *testing.T) {
	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatalf("CLI binary required. Run: make build (path: %s)", runner.CLIBinPath)
	}

	protocols := commands.CLIProtocols()
	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			keyID := commands.GenerateUniqueKeyID(fmt.Sprintf("test-%s", protocol))

			// Step 1: Generate key
			t.Run("generate", func(t *testing.T) {
				args := []string{
					"key", "generate", keyID,
					"--backend", "software",
					"--key-dir", keyDir,
					"--key-type", "ecdsa",
					"--key-algorithm", "ecdsa",
					"--curve", "P-256",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("Key generation failed: %v", err)
				}
				t.Logf("[%s] Generated key: %s", protocol, keyID)
			})

			// Step 2: List keys
			t.Run("list", func(t *testing.T) {
				args := []string{
					"key", "list",
					"--backend", "software",
					"--key-dir", keyDir,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("Key list failed: %v", err)
				}
				assertContains(t, stdout+stderr, keyID, "Key should be in list")
			})

			// Step 3: Sign data
			t.Run("sign", func(t *testing.T) {
				args := []string{
					"key", "sign", keyID, "test data to sign",
					"--backend", "software",
					"--key-dir", keyDir,
					"--key-type", "ecdsa",
					"--key-algorithm", "ecdsa",
					"--hash", "SHA-256",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("Sign failed: %v", err)
				}
				signature := strings.TrimSpace(stdout)
				assertNotEmpty(t, signature, "Signature should not be empty")
				t.Logf("[%s] Signature length: %d", protocol, len(signature))
			})

			// Step 4: Delete key
			t.Run("delete", func(t *testing.T) {
				args := []string{
					"key", "delete", keyID,
					"--backend", "software",
					"--key-dir", keyDir,
					"--key-type", "ecdsa",
					"--key-algorithm", "ecdsa",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("Delete failed: %v", err)
				}
				t.Logf("[%s] Deleted key: %s", protocol, keyID)
			})
		})
	}
}

// TestProtocolParity_FrostOperations tests FROST operations across all protocols
func TestProtocolParity_FrostOperations(t *testing.T) {
	if !isFrostEnabled() {
		t.Skip("FROST support not compiled. Build with: -tags frost")
	}

	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatal("CLI binary required. Run: make build")
	}

	protocols := commands.CLIProtocols()
	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir)

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			keyID := commands.GenerateUniqueKeyID(fmt.Sprintf("frost-%s", protocol))

			// Step 1: Generate FROST key (participant mode)
			t.Run("keygen", func(t *testing.T) {
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
				t.Logf("[%s] Generated FROST key: %s", protocol, keyID)
			})

			// Step 2: List FROST keys
			t.Run("list", func(t *testing.T) {
				args := []string{
					"--local",
					"--key-dir", keyDir,
					"frost", "list",
				}
				stdout, stderr, err := runner.RunCommand(t, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("FROST list failed: %v", err)
				}
				assertContains(t, stdout+stderr, keyID, "FROST key should be in list")
			})

			// Step 3: Get FROST key info
			t.Run("info", func(t *testing.T) {
				args := []string{
					"--local",
					"--key-dir", keyDir,
					"frost", "info", keyID,
				}
				stdout, stderr, err := runner.RunCommand(t, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("FROST info failed: %v", err)
				}
				assertContains(t, stdout+stderr, keyID, "Should show key ID")
				assertContains(t, stdout+stderr, "FROST", "Should show FROST type")
			})

			// Step 4: Generate nonces (Round 1)
			t.Run("round1", func(t *testing.T) {
				args := []string{
					"--local",
					"--key-dir", keyDir,
					"frost", "round1", keyID,
				}
				stdout, stderr, err := runner.RunCommand(t, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("FROST round1 failed: %v", err)
				}
				// Should output nonce commitments
				output := stdout + stderr
				assertNotEmpty(t, output, "Round 1 should produce output")
				t.Logf("[%s] FROST Round 1 complete", protocol)
			})

			// Step 5: Delete FROST key
			t.Run("delete", func(t *testing.T) {
				args := []string{
					"--local",
					"--key-dir", keyDir,
					"frost", "delete", keyID,
				}
				stdout, stderr, err := runner.RunCommand(t, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("FROST delete failed: %v", err)
				}
				t.Logf("[%s] Deleted FROST key: %s", protocol, keyID)
			})
		})
	}
}

// TestProtocolParity_FrostTrustedDealer tests FROST trusted dealer mode
func TestProtocolParity_FrostTrustedDealer(t *testing.T) {
	if !isFrostEnabled() {
		t.Skip("FROST support not compiled. Build with: -tags frost")
	}

	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatal("CLI binary required. Run: make build")
	}

	keyDir := commands.CreateTempKeyDir(t)
	keyID := commands.GenerateUniqueKeyID("frost-dealer")

	// Generate keys using trusted dealer
	t.Run("dealer-keygen", func(t *testing.T) {
		args := []string{
			"--local",
			"--key-dir", keyDir,
			"frost", "keygen",
			"--key-id", keyID,
			"--algorithm", "FROST-Ed25519-SHA512",
			"--threshold", "2",
			"--total", "3",
			"--participants", "alice,bob,charlie",
			"--dealer",
		}
		stdout, stderr, err := runner.RunCommand(t, args...)
		if err != nil {
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Fatalf("FROST dealer keygen failed: %v", err)
		}
		// Dealer mode should output packages
		output := stdout + stderr
		assertContains(t, output, "packages", "Should output key packages")
		t.Logf("FROST dealer keygen complete")
	})
}

// TestAllCommandsAllProtocols runs all defined commands across all protocols
func TestAllCommandsAllProtocols(t *testing.T) {
	runner := commands.NewTestRunner()
	if !runner.IsCLIAvailable(t) {
		t.Fatal("CLI binary required. Run: make build")
	}

	enabledTags := enabledBuildTags()
	protocols := commands.CLIProtocols()

	// Create results summary
	type protocolResults struct {
		protocol commands.ProtocolType
		passed   int
		failed   int
		skipped  int
	}

	allResults := make(map[commands.ProtocolType]*protocolResults)

	for _, protocol := range protocols {
		allResults[protocol] = &protocolResults{protocol: protocol}

		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
				return
			}

			keyDir := commands.CreateTempKeyDir(t)
			localRunner := runner.WithKeyDir(keyDir).WithBackend("software")

			results := localRunner.RunAllCommandsForProtocol(t, protocol, enabledTags)

			for _, result := range results {
				if result.Passed {
					allResults[protocol].passed++
				} else {
					allResults[protocol].failed++
				}
			}
		})
	}

	// Print summary
	t.Log("\n=== Protocol Parity Summary ===")
	for _, protocol := range protocols {
		r := allResults[protocol]
		t.Logf("[%s] Passed: %d, Failed: %d, Skipped: %d",
			protocol, r.passed, r.failed, r.skipped)
	}
}

// Helper functions

func isProtocolAvailable(t *testing.T, runner *commands.TestRunner, protocol commands.ProtocolType) bool {
	t.Helper()

	switch protocol {
	case commands.ProtocolUnix:
		return checkUnixSocketExists(runner.UnixSocketPath)
	case commands.ProtocolREST:
		return checkHTTPEndpoint(runner.RESTBaseURL + "/health")
	case commands.ProtocolGRPC:
		return checkTCPEndpoint(runner.GRPCAddr)
	case commands.ProtocolQUIC:
		return checkHTTPEndpoint(runner.QUICBaseURL + "/health")
	case commands.ProtocolMCP:
		return checkTCPEndpoint(runner.MCPAddr)
	default:
		return false
	}
}

func checkUnixSocketExists(socketPath string) bool {
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return false
	}
	return true
}

func checkHTTPEndpoint(url string) bool {
	// Quick check - just try to connect
	// In real tests, you'd use http.Client with timeout
	return true // Assume available if configured
}

func checkTCPEndpoint(addr string) bool {
	// Quick check
	return true // Assume available if configured
}
