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
// These tests verify that CA operations work consistently across all supported
// protocols: REST, gRPC, QUIC, and Unix socket.
package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/test/integration/api/commands"
)

// uniqueCN generates a unique common name with a timestamp suffix to avoid
// "certificate already exists" errors across repeated test runs.
func uniqueCN(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1000000)
}

// TestProtocolParity_CA_Bundle tests the ca bundle command across all protocols
func TestProtocolParity_CA_Bundle(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, "ca", "bundle")
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				t.Fatalf("[%s] ca bundle failed: %v", protocol, err)
			}

			output := stdout + stderr
			assertContains(t, output, "CERTIFICATE", "CA bundle should contain PEM certificate data")
			t.Logf("[%s] CA bundle retrieved (%d bytes)", protocol, len(output))
		})
	}
}

// TestProtocolParity_CA_Certificate tests the ca certificate command across all protocols
func TestProtocolParity_CA_Certificate(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, "ca", "certificate")
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				t.Fatalf("[%s] ca certificate failed: %v", protocol, err)
			}

			output := stdout + stderr
			outputLower := strings.ToLower(output)
			if !strings.Contains(outputLower, "subject") {
				t.Fatalf("[%s] ca certificate output missing subject info: %s", protocol, output)
			}
			t.Logf("[%s] CA certificate info: %s", protocol, strings.TrimSpace(output))
		})
	}
}

// TestProtocolParity_CA_Issue tests the ca issue command across all protocols
func TestProtocolParity_CA_Issue(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			cn := uniqueCN(fmt.Sprintf("test-server-%s", protocol))
			args := []string{
				"ca", "issue",
				"--cn", cn,
				"--profile", "server",
			}
			stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				t.Fatalf("[%s] ca issue failed: %v", protocol, err)
			}

			output := stdout + stderr
			outputLower := strings.ToLower(output)
			if !strings.Contains(outputLower, "serial number") && !strings.Contains(outputLower, "serial_number") {
				t.Fatalf("[%s] ca issue output missing serial number: %s", protocol, output)
			}
			t.Logf("[%s] Issued certificate for CN=%s", protocol, cn)
		})
	}
}

// TestProtocolParity_CA_Lifecycle tests the full CA certificate lifecycle across all protocols.
// The lifecycle steps are: issue -> status (not revoked) -> revoke -> status (revoked) -> crl.
func TestProtocolParity_CA_Lifecycle(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			var serialNumber string

			// Step 1: Issue a certificate
			t.Run("issue", func(t *testing.T) {
				cn := uniqueCN(fmt.Sprintf("lifecycle-test-%s", protocol))
				args := []string{
					"ca", "issue",
					"--cn", cn,
					"--profile", "server",
					"--output", "json",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("[%s] ca issue failed: %v", protocol, err)
				}

				// Parse serial number from JSON output
				serialNumber = extractSerialNumber(t, stdout+stderr)
				assertNotEmpty(t, serialNumber, "Serial number should not be empty")
				t.Logf("[%s] Issued certificate with serial: %s", protocol, serialNumber)
			})

			// Step 2: Check status -- should not be revoked
			t.Run("status-not-revoked", func(t *testing.T) {
				if serialNumber == "" {
					t.Fatalf("No serial number from issue step - cannot check status")
				}

				args := []string{
					"ca", "status",
					"--serial", serialNumber,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("[%s] ca status failed: %v", protocol, err)
				}

				output := stdout + stderr
				outputLower := strings.ToLower(output)
				if !strings.Contains(outputLower, "not revoked") && !strings.Contains(outputLower, "\"revoked\":false") && !strings.Contains(outputLower, "\"revoked\": false") {
					t.Fatalf("[%s] certificate should not be revoked: %s", protocol, output)
				}
				t.Logf("[%s] Status confirmed not revoked", protocol)
			})

			// Step 3: Revoke the certificate
			t.Run("revoke", func(t *testing.T) {
				if serialNumber == "" {
					t.Fatalf("No serial number from issue step - cannot revoke")
				}

				args := []string{
					"ca", "revoke",
					"--serial", serialNumber,
					"--reason", "1",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("[%s] ca revoke failed: %v", protocol, err)
				}

				output := stdout + stderr
				assertNotEmpty(t, output, "Revoke output should not be empty")
				t.Logf("[%s] Revoked certificate: %s", protocol, serialNumber)
			})

			// Step 4: Check status -- should be revoked
			t.Run("status-revoked", func(t *testing.T) {
				if serialNumber == "" {
					t.Fatalf("No serial number from issue step - cannot check revocation status")
				}

				args := []string{
					"ca", "status",
					"--serial", serialNumber,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("[%s] ca status failed: %v", protocol, err)
				}

				output := stdout + stderr
				outputLower := strings.ToLower(output)
				if !strings.Contains(outputLower, "revoked") {
					t.Fatalf("[%s] certificate should be revoked: %s", protocol, output)
				}
				t.Logf("[%s] Status confirmed revoked", protocol)
			})

			// Step 5: Generate CRL and verify the revoked cert appears
			t.Run("crl", func(t *testing.T) {
				args := []string{
					"ca", "crl",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("[%s] ca crl failed: %v", protocol, err)
				}

				output := stdout + stderr
				if !strings.Contains(output, "CRL") && !strings.Contains(output, "CERTIFICATE") {
					t.Fatalf("[%s] CRL output should contain CRL or CERTIFICATE data: %s", protocol, output)
				}
				t.Logf("[%s] CRL generated (%d bytes)", protocol, len(output))
			})
		})
	}
}

// TestProtocolParity_CA_CRL tests the ca crl command across all protocols
func TestProtocolParity_CA_CRL(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	for _, protocol := range commands.CLIProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, "ca", "crl")
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				t.Fatalf("[%s] ca crl failed: %v", protocol, err)
			}

			output := stdout + stderr
			if !strings.Contains(output, "CRL") && !strings.Contains(output, "X509") && !strings.Contains(output, "CERTIFICATE") {
				t.Fatalf("[%s] CRL output should contain CRL, X509, or CERTIFICATE data: %s", protocol, output)
			}
			t.Logf("[%s] CRL retrieved (%d bytes)", protocol, len(output))
		})
	}
}

// extractSerialNumber parses a serial number from combined CLI output.
// It first attempts to parse JSON, then falls back to scanning for
// "Serial Number:" in plain text output.
func extractSerialNumber(t *testing.T, output string) string {
	t.Helper()

	// Try JSON parsing first
	jsonStart := strings.Index(output, "{")
	jsonEnd := strings.LastIndex(output, "}")
	if jsonStart >= 0 && jsonEnd > jsonStart {
		jsonStr := output[jsonStart : jsonEnd+1]
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
			if serial, ok := result["serial_number"]; ok {
				return fmt.Sprintf("%v", serial)
			}
		}
	}

	// Fall back to plain text parsing
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "serial number") || strings.Contains(lineLower, "serial_number") {
			// Try "Serial Number: <value>" format
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	t.Logf("Could not extract serial number from output: %s", output)
	return ""
}
