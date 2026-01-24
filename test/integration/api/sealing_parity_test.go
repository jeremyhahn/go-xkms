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
// These tests verify that sealing operations work consistently across all supported
// protocols: REST, gRPC, QUIC, and Unix socket.
package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/test/integration/api/commands"
)

// sealOutput represents the JSON output from the seal command
type sealOutput struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag"`
}

// TestProtocolParity_CanSeal tests that can-seal returns true for software backend across all protocols
func TestProtocolParity_CanSeal(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	protocols := commands.CLIProtocols()

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			// Test can-seal command
			args := []string{
				"can-seal",
				"--backend", "software",
			}
			stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
			if err != nil {
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
				t.Fatalf("[%s] can-seal command failed: %v", protocol, err)
			}

			output := stdout + stderr
			assertContains(t, output, "can_seal", "Output should contain can_seal field")
			t.Logf("[%s] can-seal output: %s", protocol, strings.TrimSpace(output))

			// Verify that the software backend reports sealing capability as true
			assertContains(t, output, "true", "Software backend should support sealing")
		})
	}
}

// TestProtocolParity_SealUnsealLifecycle tests seal/unseal roundtrip for each protocol
func TestProtocolParity_SealUnsealLifecycle(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	protocols := commands.CLIProtocols()
	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")

	testPlaintext := "secret-data-to-protect-12345"
	sealKeyName := "seal-test-key"
	// Use just the key name - the backend/type/algo are specified via separate flags
	sealKeyID := sealKeyName

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			var sealedData sealOutput

			// Step 1: Generate a key for sealing
			t.Run("generate-key", func(t *testing.T) {
				args := []string{
					"key", "generate", sealKeyName,
					"--key-algorithm", "ecdsa",
					"--curve", "P-256",
					"--key-type", "tls",
					"--backend", "software",
					"--key-dir", keyDir,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("key generate failed: %v", err)
				}
				t.Logf("[%s] Generated sealing key: %s", protocol, sealKeyName)
			})

			// Step 2: Verify sealing capability
			t.Run("can-seal", func(t *testing.T) {
				args := []string{
					"can-seal",
					"--backend", "software",
					"--key-dir", keyDir,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("can-seal failed: %v", err)
				}

				output := stdout + stderr
				assertContains(t, output, "true", "Backend should support sealing")
				t.Logf("[%s] Verified sealing capability", protocol)
			})

			// Step 3: Seal the test data
			t.Run("seal", func(t *testing.T) {
				args := []string{
					"seal", testPlaintext,
					"--key-id", sealKeyID,
					"--backend", "software",
					"--key-dir", keyDir,
					"--output", "json",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("seal command failed: %v", err)
				}

				// Parse the JSON output
				output := strings.TrimSpace(stdout)
				if output == "" {
					output = strings.TrimSpace(stderr)
				}

				if err := json.Unmarshal([]byte(output), &sealedData); err != nil {
					// Try to find JSON in the combined output
					combinedOutput := stdout + stderr
					jsonStart := strings.Index(combinedOutput, "{")
					jsonEnd := strings.LastIndex(combinedOutput, "}")
					if jsonStart >= 0 && jsonEnd > jsonStart {
						jsonStr := combinedOutput[jsonStart : jsonEnd+1]
						if err := json.Unmarshal([]byte(jsonStr), &sealedData); err != nil {
							t.Fatalf("Failed to parse seal output as JSON: %v\nOutput: %s", err, combinedOutput)
						}
					} else {
						t.Fatalf("Failed to parse seal output as JSON: %v\nOutput: %s", err, combinedOutput)
					}
				}

				// Validate sealed data components are present
				assertNotEmpty(t, sealedData.Ciphertext, "Ciphertext should not be empty")
				assertNotEmpty(t, sealedData.Nonce, "Nonce should not be empty")
				assertNotEmpty(t, sealedData.Tag, "Tag should not be empty")

				t.Logf("[%s] Sealed data - ciphertext length: %d, nonce length: %d, tag length: %d",
					protocol, len(sealedData.Ciphertext), len(sealedData.Nonce), len(sealedData.Tag))
			})

			// Step 4: Unseal the data and verify it matches the original
			t.Run("unseal", func(t *testing.T) {
				// Skip if seal failed (sealedData would be empty)
				if sealedData.Ciphertext == "" {
					t.Skip("Skipping unseal - seal operation did not produce output")
				}

				args := []string{
					"unseal",
					"--key-id", sealKeyID,
					"--ciphertext", sealedData.Ciphertext,
					"--nonce", sealedData.Nonce,
					"--tag", sealedData.Tag,
					"--backend", "software",
					"--key-dir", keyDir,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("unseal command failed: %v", err)
				}

				// The unsealed plaintext should match the original
				unsealedData := strings.TrimSpace(stdout)
				if unsealedData == "" {
					unsealedData = strings.TrimSpace(stderr)
				}

				// Handle potential JSON wrapper in output
				if strings.Contains(unsealedData, "plaintext") {
					var result struct {
						Plaintext string `json:"plaintext"`
					}
					if err := json.Unmarshal([]byte(unsealedData), &result); err == nil {
						unsealedData = result.Plaintext
					}
				}

				assertEqual(t, testPlaintext, unsealedData, "Unsealed data should match original plaintext")
				t.Logf("[%s] Successfully unsealed and verified data", protocol)
			})

			// Step 5: Cleanup - delete the test key
			t.Run("cleanup", func(t *testing.T) {
				args := []string{
					"key", "delete", sealKeyName,
					"--backend", "software",
					"--key-dir", keyDir,
				}
				_, _, _ = runner.RunCommandWithProtocol(t, protocol, args...)
				// Ignore cleanup errors
			})
		})
	}
}

// TestProtocolParity_SealWithAAD tests seal/unseal with additional authenticated data
func TestProtocolParity_SealWithAAD(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	protocols := commands.CLIProtocols()
	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")

	testPlaintext := "secret-with-aad-67890"
	testAAD := "additional-authenticated-data"
	sealKeyName := "seal-aad-test-key"
	// Use just the key name - the backend/type/algo are specified via separate flags
	sealKeyID := sealKeyName

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			var sealedData sealOutput

			// Step 1: Generate a key for sealing
			t.Run("generate-key", func(t *testing.T) {
				args := []string{
					"key", "generate", sealKeyName,
					"--key-algorithm", "ecdsa",
					"--curve", "P-256",
					"--key-type", "tls",
					"--backend", "software",
					"--key-dir", keyDir,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("key generate failed: %v", err)
				}
				t.Logf("[%s] Generated sealing key: %s", protocol, sealKeyName)
			})

			// Step 2: Seal with AAD
			t.Run("seal-with-aad", func(t *testing.T) {
				args := []string{
					"seal", testPlaintext,
					"--key-id", sealKeyID,
					"--backend", "software",
					"--key-dir", keyDir,
					"--aad", testAAD,
					"--output", "json",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("seal with AAD failed: %v", err)
				}

				// Parse the JSON output
				combinedOutput := stdout + stderr
				jsonStart := strings.Index(combinedOutput, "{")
				jsonEnd := strings.LastIndex(combinedOutput, "}")
				if jsonStart >= 0 && jsonEnd > jsonStart {
					jsonStr := combinedOutput[jsonStart : jsonEnd+1]
					if err := json.Unmarshal([]byte(jsonStr), &sealedData); err != nil {
						t.Fatalf("Failed to parse seal output as JSON: %v", err)
					}
				} else {
					t.Fatalf("No JSON found in seal output: %s", combinedOutput)
				}

				assertNotEmpty(t, sealedData.Ciphertext, "Ciphertext should not be empty")
				t.Logf("[%s] Sealed data with AAD", protocol)
			})

			// Step 3: Unseal with matching AAD
			t.Run("unseal-with-aad", func(t *testing.T) {
				if sealedData.Ciphertext == "" {
					t.Skip("Skipping unseal - seal operation did not produce output")
				}

				args := []string{
					"unseal",
					"--key-id", sealKeyID,
					"--ciphertext", sealedData.Ciphertext,
					"--nonce", sealedData.Nonce,
					"--tag", sealedData.Tag,
					"--aad", testAAD,
					"--backend", "software",
					"--key-dir", keyDir,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("unseal with AAD failed: %v", err)
				}

				unsealedData := strings.TrimSpace(stdout)
				if unsealedData == "" {
					unsealedData = strings.TrimSpace(stderr)
				}

				// Handle potential JSON wrapper
				if strings.Contains(unsealedData, "plaintext") {
					var result struct {
						Plaintext string `json:"plaintext"`
					}
					if err := json.Unmarshal([]byte(unsealedData), &result); err == nil {
						unsealedData = result.Plaintext
					}
				}

				assertEqual(t, testPlaintext, unsealedData, "Unsealed data should match original")
				t.Logf("[%s] Successfully unsealed with AAD", protocol)
			})

			// Step 4: Verify unseal fails with wrong AAD
			t.Run("unseal-wrong-aad-fails", func(t *testing.T) {
				if sealedData.Ciphertext == "" {
					t.Skip("Skipping unseal - seal operation did not produce output")
				}

				args := []string{
					"unseal",
					"--key-id", sealKeyID,
					"--ciphertext", sealedData.Ciphertext,
					"--nonce", sealedData.Nonce,
					"--tag", sealedData.Tag,
					"--aad", "wrong-aad-value",
					"--backend", "software",
					"--key-dir", keyDir,
				}
				_, _, err := runner.RunCommandWithProtocol(t, protocol, args...)

				// Unseal with wrong AAD should fail
				assertError(t, err, "Unseal with wrong AAD should fail")
				t.Logf("[%s] Correctly rejected unseal with wrong AAD", protocol)
			})

			// Step 5: Cleanup - delete the test key
			t.Run("cleanup", func(t *testing.T) {
				args := []string{
					"key", "delete", sealKeyName,
					"--backend", "software",
					"--key-dir", keyDir,
				}
				_, _, _ = runner.RunCommandWithProtocol(t, protocol, args...)
				// Ignore cleanup errors
			})
		})
	}
}

// TestProtocolParity_SealInvalidInput tests error handling for invalid seal operations
func TestProtocolParity_SealInvalidInput(t *testing.T) {
	runner := commands.NewTestRunner()
	runner.RequireCLI(t)

	protocols := commands.CLIProtocols()
	keyDir := commands.CreateTempKeyDir(t)
	runner = runner.WithKeyDir(keyDir).WithBackend("software")

	sealKeyName := "seal-invalid-test-key"
	// Use just the key name - the backend/type/algo are specified via separate flags
	sealKeyID := sealKeyName

	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			if !isProtocolAvailable(t, runner, protocol) {
				t.Fatalf("Protocol %s not available - server must be running", protocol)
			}

			// Generate a key for this protocol's tests
			t.Run("generate-key", func(t *testing.T) {
				args := []string{
					"key", "generate", sealKeyName,
					"--key-algorithm", "ecdsa",
					"--curve", "P-256",
					"--key-type", "tls",
					"--backend", "software",
					"--key-dir", keyDir,
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, args...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Fatalf("key generate failed: %v", err)
				}
			})

			// Test unseal with invalid ciphertext
			t.Run("unseal-invalid-ciphertext", func(t *testing.T) {
				args := []string{
					"unseal",
					"--key-id", sealKeyID,
					"--ciphertext", "invalid-base64!@#$",
					"--nonce", "dGVzdG5vbmNl",
					"--tag", "dGVzdHRhZw==",
					"--backend", "software",
					"--key-dir", keyDir,
				}
				_, _, err := runner.RunCommandWithProtocol(t, protocol, args...)

				// Should fail with invalid input
				assertError(t, err, "Unseal with invalid ciphertext should fail")
				t.Logf("[%s] Correctly rejected invalid ciphertext", protocol)
			})

			// Test unseal with mismatched components
			t.Run("unseal-mismatched-components", func(t *testing.T) {
				// First seal some data
				sealArgs := []string{
					"seal", "test-data",
					"--key-id", sealKeyID,
					"--backend", "software",
					"--key-dir", keyDir,
					"--output", "json",
				}
				stdout, stderr, err := runner.RunCommandWithProtocol(t, protocol, sealArgs...)
				if err != nil {
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Skip("Skipping - could not seal test data")
				}

				var sealedData sealOutput
				combinedOutput := stdout + stderr
				jsonStart := strings.Index(combinedOutput, "{")
				jsonEnd := strings.LastIndex(combinedOutput, "}")
				if jsonStart >= 0 && jsonEnd > jsonStart {
					jsonStr := combinedOutput[jsonStart : jsonEnd+1]
					if err := json.Unmarshal([]byte(jsonStr), &sealedData); err != nil {
						t.Skip("Skipping - could not parse seal output")
					}
				}

				// Try to unseal with a tampered tag
				args := []string{
					"unseal",
					"--key-id", sealKeyID,
					"--ciphertext", sealedData.Ciphertext,
					"--nonce", sealedData.Nonce,
					"--tag", "dGFtcGVyZWR0YWc=", // "tamperedtag" in base64
					"--backend", "software",
					"--key-dir", keyDir,
				}
				_, _, err = runner.RunCommandWithProtocol(t, protocol, args...)

				// Should fail with authentication error
				assertError(t, err, "Unseal with tampered tag should fail")
				t.Logf("[%s] Correctly rejected tampered authentication tag", protocol)
			})

			// Cleanup
			t.Run("cleanup", func(t *testing.T) {
				args := []string{
					"key", "delete", sealKeyName,
					"--backend", "software",
					"--key-dir", keyDir,
				}
				_, _, _ = runner.RunCommandWithProtocol(t, protocol, args...)
			})
		})
	}
}
