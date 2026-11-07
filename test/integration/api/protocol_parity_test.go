//go:build integration

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

// Package integration provides integration tests for go-xkms API protocols.
// These tests verify that all CLI commands work consistently across all supported
// protocols: REST, gRPC, QUIC, MCP, and Unix socket.
package integration

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/test/integration/api/commands"
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
	runner.RequireCLI(t)

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
	runner.RequireCLI(t)

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
	runner.RequireCLI(t)

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
					"--hash", "sha256",
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

// TestAllCommandsAllProtocols runs all defined commands across all protocols
func TestAllCommandsAllProtocols(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

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

			var failedNames []string
			for _, result := range results {
				if result.Passed {
					allResults[protocol].passed++
					continue
				}
				allResults[protocol].failed++
				failedNames = append(failedNames, result.Command.Name)
			}

			// A failed command fails the test.
			//
			// This used to tally results and print a summary with t.Logf and
			// nothing else, so the subtest passed no matter how many commands
			// failed -- sixteen REST failures, every one of them
			// "server error: unauthorized", reported green. test/integration's
			// own conventions require each command to be confirmed against each
			// protocol, and a run that cannot fail confirms nothing.
			if len(failedNames) > 0 {
				t.Errorf("%d of %d commands failed on %s: %s",
					len(failedNames), len(results), protocol, strings.Join(failedNames, ", "))
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
	case commands.ProtocolEmbedded:
		return true // Embedded mode is always available
	case commands.ProtocolUnix:
		return checkUnixSocketExists(runner.UnixSocketPath)
	case commands.ProtocolREST:
		return checkHTTPEndpoint(t, runner.RESTBaseURL+"/health")
	case commands.ProtocolGRPC:
		return checkTCPEndpoint(runner.GRPCAddr)
	case commands.ProtocolQUIC:
		return checkQUICEndpoint(t, runner.QUICBaseURL)
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

func checkHTTPEndpoint(tb testing.TB, url string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig(tb),
		},
	}
	resp, err := client.Get(url) //nolint:noctx // simple health check
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

func checkQUICEndpoint(t *testing.T, baseURL string) bool {
	// QUIC uses HTTP/3 over UDP — standard HTTP/TCP clients can't reach it.
	// Probe the server via the CLI with a lightweight backends list command that
	// requires an actual server round-trip.
	runner := commands.NewTestRunner()
	binPath := runner.CLIBinPath
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return false
	}
	host := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	args := append([]string{"--server", "quic://" + host}, runner.TLSArgs(t, commands.ProtocolQUIC)...)
	cmd := exec.Command(binPath, append(args, "backends", "list")...)
	return cmd.Run() == nil
}

func checkTCPEndpoint(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
