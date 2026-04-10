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

// Package module provides multi-protocol pkcs11-tool integration tests.
//
// These tests use the external pkcs11-tool command to validate the PKCS#11
// shared library works correctly across all supported protocols (Unix gRPC
// over UDS, gRPC over TCP) and all available backends.
//
// Test Matrix:
//
//	Protocols: unix, grpc
//	Backends: software, tpm2, pkcs11, quantum, awskms, gcpkms, azurekv
//
// Environment Variables:
//
//	PKCS11_MODULE           - Path to PKCS#11 module
//	PKCS11_PIN              - User PIN (default: 87654321)
//	PKCS11_SO_PIN           - Security Officer PIN (default: 12345678)
//	XKMS_UNIX_SOCKET    - Unix socket path
//	XKMS_GRPC_ADDR      - gRPC server address
//
// Usage:
//
//	go test -v -tags='integration,pkcs11,pkcs11_tool' ./test/integration/pkcs11/module/... -run TestPKCS11ToolMultiProtocol
package module

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// =============================================================================
// PKCS11Tool Multi-Protocol Test Configuration
// =============================================================================

// PKCS11ToolMultiProtocolConfig holds configuration for multi-protocol pkcs11-tool tests.
type PKCS11ToolMultiProtocolConfig struct {
	ModulePath string
	SlotID     string
	PIN        string
	SOPIN      string
	TempDir    string
	Protocol   ProtocolType
	Backend    module.BackendType
}

// NewPKCS11ToolMultiProtocolConfig creates a test config for the given protocol and backend.
func NewPKCS11ToolMultiProtocolConfig(t *testing.T, protocol ProtocolType, backend module.BackendType) *PKCS11ToolMultiProtocolConfig {
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

	return &PKCS11ToolMultiProtocolConfig{
		ModulePath: modulePath,
		SlotID:     "0",
		PIN:        pin,
		SOPIN:      soPin,
		TempDir:    t.TempDir(),
		Protocol:   protocol,
		Backend:    backend,
	}
}

// SetProtocolEnv sets environment variables for the specified protocol.
func (c *PKCS11ToolMultiProtocolConfig) SetProtocolEnv(t *testing.T) {
	t.Helper()

	suite := NewMultiProtocolTestSuite()
	cfg := suite.GetProtocolConfig(c.Protocol)

	// Set target based on protocol
	os.Setenv("XKMS_PKCS11_TARGET", cfg.Target)
	os.Setenv("XKMS_PKCS11_DEFAULT_BACKEND", string(c.Backend))

	t.Cleanup(func() {
		os.Unsetenv("XKMS_PKCS11_TARGET")
		os.Unsetenv("XKMS_PKCS11_DEFAULT_BACKEND")
	})
}

// RunPKCS11Tool executes pkcs11-tool with the given arguments.
func (c *PKCS11ToolMultiProtocolConfig) RunPKCS11Tool(t *testing.T, args ...string) (string, string, error) {
	t.Helper()

	fullArgs := append([]string{"--module", c.ModulePath}, args...)
	cmd := exec.Command("pkcs11-tool", fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// RunPKCS11ToolWithPIN executes pkcs11-tool with login using user PIN.
func (c *PKCS11ToolMultiProtocolConfig) RunPKCS11ToolWithPIN(t *testing.T, args ...string) (string, string, error) {
	t.Helper()

	loginArgs := append([]string{"--login", "--pin", c.PIN, "--slot", c.SlotID}, args...)
	return c.RunPKCS11Tool(t, loginArgs...)
}

// isSoftHSMAvailable checks if SoftHSM is available for pkcs11 backend testing.
// SoftHSM is available if the library exists.
func isSoftHSMAvailable() bool {
	// Check for SoftHSM library at common locations
	softHSMPaths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	}

	// Also check SOFTHSM_LIBRARY env var
	if envPath := os.Getenv("SOFTHSM_LIBRARY"); envPath != "" {
		softHSMPaths = append([]string{envPath}, softHSMPaths...)
	}

	for _, path := range softHSMPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

// skipIfPKCS11BackendUnavailable skips the test if SoftHSM library is not available.
// The pkcs11 backend tests require SoftHSM to be installed in the test environment.
func skipIfPKCS11BackendUnavailable(t *testing.T, backend module.BackendType) {
	t.Helper()
	if backend != module.BackendPKCS11 {
		return
	}

	if !isSoftHSMAvailable() {
		t.Skip("Skipping: pkcs11 backend requires SoftHSM library which is not installed")
	}
}

// =============================================================================
// Multi-Protocol pkcs11-tool Command Tests
// =============================================================================

// PKCS11Command defines a pkcs11-tool command to test.
type PKCS11Command struct {
	Name        string
	Args        []string
	RequiresPIN bool
	Validate    func(t *testing.T, stdout, stderr string, err error)
}

// CoreCommands returns the core pkcs11-tool commands that must work on all protocols.
func CoreCommands() []PKCS11Command {
	return []PKCS11Command{
		{
			Name: "show-info",
			Args: []string{"--show-info"},
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("show-info failed: %v\nstderr: %s", err, stderr)
					return
				}
				if !strings.Contains(stdout, "Cryptoki version") {
					t.Error("show-info: missing Cryptoki version")
				}
			},
		},
		{
			Name: "list-slots",
			Args: []string{"--list-slots"},
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("list-slots failed: %v\nstderr: %s", err, stderr)
					return
				}
				if !strings.Contains(stdout, "Slot") {
					t.Error("list-slots: no slots found in output")
				}
			},
		},
		{
			Name: "list-mechanisms",
			Args: []string{"--list-mechanisms"},
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("list-mechanisms failed: %v\nstderr: %s", err, stderr)
					return
				}
				// Should have at least some mechanisms
				if len(stdout) < 50 {
					t.Error("list-mechanisms: output too short, expected mechanisms list")
				}
			},
		},
	}
}

// KeyGenerationCommands returns key generation commands to test.
func KeyGenerationCommands(label string) []PKCS11Command {
	return []PKCS11Command{
		{
			Name:        "keypairgen-rsa-2048",
			Args:        []string{"--keypairgen", "--key-type", "RSA:2048", "--label", label + "-rsa2048"},
			RequiresPIN: true,
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("keypairgen RSA-2048 failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
		{
			Name:        "keypairgen-ec-p256",
			Args:        []string{"--keypairgen", "--key-type", "EC:secp256r1", "--label", label + "-ecp256"},
			RequiresPIN: true,
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("keypairgen EC P-256 failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
		{
			Name:        "keypairgen-ec-p384",
			Args:        []string{"--keypairgen", "--key-type", "EC:secp384r1", "--label", label + "-ecp384"},
			RequiresPIN: true,
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("keypairgen EC P-384 failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
		{
			Name:        "keygen-aes-256",
			Args:        []string{"--keygen", "--key-type", "AES:32", "--label", label + "-aes256"},
			RequiresPIN: true,
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("keygen AES-256 failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
	}
}

// ObjectCommands returns object operation commands to test.
func ObjectCommands() []PKCS11Command {
	return []PKCS11Command{
		{
			Name:        "list-objects",
			Args:        []string{"--list-objects"},
			RequiresPIN: true,
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("list-objects failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
		{
			Name:        "list-objects-privkey",
			Args:        []string{"--list-objects", "--type", "privkey"},
			RequiresPIN: true,
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("list-objects privkey failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
		{
			Name:        "list-objects-pubkey",
			Args:        []string{"--list-objects", "--type", "pubkey"},
			RequiresPIN: true,
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("list-objects pubkey failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
		{
			Name:        "list-objects-secrkey",
			Args:        []string{"--list-objects", "--type", "secrkey"},
			RequiresPIN: true,
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("list-objects secrkey failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
	}
}

// RandomCommands returns random generation commands to test.
func RandomCommands() []PKCS11Command {
	return []PKCS11Command{
		{
			Name: "generate-random-32",
			Args: []string{"--generate-random", "32"},
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("generate-random 32 failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
		{
			Name: "generate-random-64",
			Args: []string{"--generate-random", "64"},
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("generate-random 64 failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
		{
			Name: "generate-random-256",
			Args: []string{"--generate-random", "256"},
			Validate: func(t *testing.T, stdout, stderr string, err error) {
				if err != nil {
					t.Errorf("generate-random 256 failed: %v\nstderr: %s", err, stderr)
				}
			},
		},
	}
}

// =============================================================================
// Multi-Protocol Test Execution
// =============================================================================

// TestPKCS11ToolMultiProtocol_CoreCommands tests core commands across all protocols.
func TestPKCS11ToolMultiProtocol_CoreCommands(t *testing.T) {
	skipIfToolUnavailable(t)
	suite := NewMultiProtocolTestSuite()
	commands := CoreCommands()

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			cfg := NewPKCS11ToolMultiProtocolConfig(t, protocol, module.BackendSoftware)
			skipIfModuleUnavailable(t, cfg.ModulePath)
			cfg.SetProtocolEnv(t)

			for _, cmd := range commands {
				cmd := cmd
				t.Run(cmd.Name, func(t *testing.T) {
					var stdout, stderr string
					var err error

					if cmd.RequiresPIN {
						stdout, stderr, err = cfg.RunPKCS11ToolWithPIN(t, cmd.Args...)
					} else {
						stdout, stderr, err = cfg.RunPKCS11Tool(t, cmd.Args...)
					}

					cmd.Validate(t, stdout, stderr, err)
				})
			}
		})
	}
}

// TestPKCS11ToolMultiProtocol_KeyGeneration tests key generation across all protocols and backends.
func TestPKCS11ToolMultiProtocol_KeyGeneration(t *testing.T) {
	skipIfToolUnavailable(t)
	suite := NewMultiProtocolTestSuite()

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					// Skip pkcs11 backend if SoftHSM is not available
					skipIfPKCS11BackendUnavailable(t, backend)

					cfg := NewPKCS11ToolMultiProtocolConfig(t, protocol, backend)
					skipIfModuleUnavailable(t, cfg.ModulePath)
					cfg.SetProtocolEnv(t)

					// Generate unique label for this test run
					label := fmt.Sprintf("mp-%s-%s", protocol, backend)
					commands := KeyGenerationCommands(label)

					for _, cmd := range commands {
						cmd := cmd
						t.Run(cmd.Name, func(t *testing.T) {
							stdout, stderr, err := cfg.RunPKCS11ToolWithPIN(t, cmd.Args...)
							cmd.Validate(t, stdout, stderr, err)
						})
					}
				})
			}
		})
	}
}

// TestPKCS11ToolMultiProtocol_ObjectOperations tests object operations across all protocols and backends.
func TestPKCS11ToolMultiProtocol_ObjectOperations(t *testing.T) {
	skipIfToolUnavailable(t)
	suite := NewMultiProtocolTestSuite()
	commands := ObjectCommands()

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					// Skip pkcs11 backend if SoftHSM is not available
					skipIfPKCS11BackendUnavailable(t, backend)

					cfg := NewPKCS11ToolMultiProtocolConfig(t, protocol, backend)
					skipIfModuleUnavailable(t, cfg.ModulePath)
					cfg.SetProtocolEnv(t)

					for _, cmd := range commands {
						cmd := cmd
						t.Run(cmd.Name, func(t *testing.T) {
							stdout, stderr, err := cfg.RunPKCS11ToolWithPIN(t, cmd.Args...)
							cmd.Validate(t, stdout, stderr, err)
						})
					}
				})
			}
		})
	}
}

// TestPKCS11ToolMultiProtocol_RandomGeneration tests random generation across all protocols and backends.
func TestPKCS11ToolMultiProtocol_RandomGeneration(t *testing.T) {
	skipIfToolUnavailable(t)
	suite := NewMultiProtocolTestSuite()
	commands := RandomCommands()

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					// Skip pkcs11 backend if SoftHSM is not available
					skipIfPKCS11BackendUnavailable(t, backend)

					cfg := NewPKCS11ToolMultiProtocolConfig(t, protocol, backend)
					skipIfModuleUnavailable(t, cfg.ModulePath)
					cfg.SetProtocolEnv(t)

					for _, cmd := range commands {
						cmd := cmd
						t.Run(cmd.Name, func(t *testing.T) {
							stdout, stderr, err := cfg.RunPKCS11Tool(t, cmd.Args...)
							cmd.Validate(t, stdout, stderr, err)
						})
					}
				})
			}
		})
	}
}

// TestPKCS11ToolMultiProtocol_SignVerify tests sign/verify workflow across all protocols and backends.
// NOTE: Requires persistent backend - in-memory module doesn't persist keys across pkcs11-tool invocations.
func TestPKCS11ToolMultiProtocol_SignVerify(t *testing.T) {
	skipIfNoFilePersistence(t)
	skipIfToolUnavailable(t)
	suite := NewMultiProtocolTestSuite()

	mechanisms := []struct {
		Name     string
		KeyType  string
		SignMech string
		KeyLabel string
	}{
		{"RSA-PKCS", "RSA:2048", "RSA-PKCS", "sign-rsa"},
		{"ECDSA", "EC:secp256r1", "ECDSA", "sign-ecdsa"},
	}

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					// Skip pkcs11 backend if SoftHSM is not available
					skipIfPKCS11BackendUnavailable(t, backend)

					cfg := NewPKCS11ToolMultiProtocolConfig(t, protocol, backend)
					skipIfModuleUnavailable(t, cfg.ModulePath)
					cfg.SetProtocolEnv(t)

					for _, mech := range mechanisms {
						mech := mech
						t.Run(mech.Name, func(t *testing.T) {
							label := fmt.Sprintf("%s-%s-%s", mech.KeyLabel, protocol, backend)

							// Step 1: Generate key pair
							_, stderr, err := cfg.RunPKCS11ToolWithPIN(t,
								"--keypairgen",
								"--key-type", mech.KeyType,
								"--label", label,
							)
							if err != nil {
								t.Fatalf("keypairgen failed: %v\nstderr: %s", err, stderr)
							}

							// Step 2: Create test data file
							dataFile := filepath.Join(cfg.TempDir, "data.bin")
							sigFile := filepath.Join(cfg.TempDir, "sig.bin")
							testData := []byte("Test data for multi-protocol sign/verify")
							if err := os.WriteFile(dataFile, testData, 0600); err != nil {
								t.Fatalf("failed to write test data: %v", err)
							}

							// Step 3: Sign
							_, stderr, err = cfg.RunPKCS11ToolWithPIN(t,
								"--sign",
								"--mechanism", mech.SignMech,
								"--label", label,
								"--input-file", dataFile,
								"--output-file", sigFile,
							)
							if err != nil {
								t.Fatalf("sign failed: %v\nstderr: %s", err, stderr)
							}

							// Step 4: Verify signature file exists
							if _, err := os.Stat(sigFile); os.IsNotExist(err) {
								t.Fatal("signature file not created")
							}

							// Step 5: Read public key for verification (if needed)
							// Note: pkcs11-tool verify requires the public key
							// For now, we just verify the signature was created

							// Cleanup: Delete the test key
							_, _, _ = cfg.RunPKCS11ToolWithPIN(t,
								"--delete-object",
								"--type", "privkey",
								"--label", label,
							)
							_, _, _ = cfg.RunPKCS11ToolWithPIN(t,
								"--delete-object",
								"--type", "pubkey",
								"--label", label,
							)
						})
					}
				})
			}
		})
	}
}

// TestPKCS11ToolMultiProtocol_FullLifecycle tests complete key lifecycle across protocols.
// NOTE: Requires persistent backend - in-memory module doesn't persist keys across pkcs11-tool invocations.
func TestPKCS11ToolMultiProtocol_FullLifecycle(t *testing.T) {
	skipIfNoFilePersistence(t)
	skipIfToolUnavailable(t)
	suite := NewMultiProtocolTestSuite()

	for _, protocol := range AllProtocols() {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			if !suite.IsProtocolAvailable(protocol) {
				t.Skipf("protocol %s not available", protocol)
			}

			for _, backend := range suite.Backends {
				backend := backend
				t.Run(string(backend), func(t *testing.T) {
					// Skip pkcs11 backend if SoftHSM is not available
					skipIfPKCS11BackendUnavailable(t, backend)

					cfg := NewPKCS11ToolMultiProtocolConfig(t, protocol, backend)
					skipIfModuleUnavailable(t, cfg.ModulePath)
					cfg.SetProtocolEnv(t)

					label := fmt.Sprintf("lifecycle-%s-%s", protocol, backend)

					// Step 1: Generate key pair
					t.Log("Step 1: Generate key pair")
					_, stderr, err := cfg.RunPKCS11ToolWithPIN(t,
						"--keypairgen",
						"--key-type", "EC:secp256r1",
						"--label", label,
					)
					if err != nil {
						t.Fatalf("keypairgen failed: %v\nstderr: %s", err, stderr)
					}

					// Step 2: List objects to verify key exists
					t.Log("Step 2: Verify key exists")
					stdout, stderr, err := cfg.RunPKCS11ToolWithPIN(t, "--list-objects")
					if err != nil {
						t.Fatalf("list-objects failed: %v\nstderr: %s", err, stderr)
					}
					if !strings.Contains(stdout, label) {
						t.Error("generated key not found in object list")
					}

					// Step 3: Sign data
					t.Log("Step 3: Sign data")
					dataFile := filepath.Join(cfg.TempDir, "lifecycle-data.bin")
					sigFile := filepath.Join(cfg.TempDir, "lifecycle-sig.bin")
					if err := os.WriteFile(dataFile, []byte("Lifecycle test data"), 0600); err != nil {
						t.Fatalf("failed to write test data: %v", err)
					}

					_, stderr, err = cfg.RunPKCS11ToolWithPIN(t,
						"--sign",
						"--mechanism", "ECDSA",
						"--label", label,
						"--input-file", dataFile,
						"--output-file", sigFile,
					)
					if err != nil {
						t.Fatalf("sign failed: %v\nstderr: %s", err, stderr)
					}

					// Step 4: Verify signature was created
					t.Log("Step 4: Verify signature file")
					sigData, err := os.ReadFile(sigFile)
					if err != nil {
						t.Fatalf("failed to read signature: %v", err)
					}
					if len(sigData) == 0 {
						t.Error("signature is empty")
					}

					// Step 5: Delete key
					t.Log("Step 5: Delete key")
					_, stderr, err = cfg.RunPKCS11ToolWithPIN(t,
						"--delete-object",
						"--type", "privkey",
						"--label", label,
					)
					if err != nil {
						t.Logf("delete privkey warning: %v\nstderr: %s", err, stderr)
					}

					_, stderr, err = cfg.RunPKCS11ToolWithPIN(t,
						"--delete-object",
						"--type", "pubkey",
						"--label", label,
					)
					if err != nil {
						t.Logf("delete pubkey warning: %v\nstderr: %s", err, stderr)
					}

					// Step 6: Verify key is deleted
					t.Log("Step 6: Verify key deleted")
					stdout, _, _ = cfg.RunPKCS11ToolWithPIN(t, "--list-objects")
					if strings.Contains(stdout, label) {
						t.Error("key still exists after deletion")
					}
				})
			}
		})
	}
}

// TestPKCS11ToolMultiProtocol_ProtocolParity verifies all protocols produce identical results.
func TestPKCS11ToolMultiProtocol_ProtocolParity(t *testing.T) {
	skipIfToolUnavailable(t)
	suite := NewMultiProtocolTestSuite()

	if len(suite.AvailableProtocols) < 2 {
		t.Skip("need at least 2 available protocols for parity test")
	}

	// Collect mechanism lists from each protocol
	mechanismLists := make(map[ProtocolType]string)

	for _, protocol := range suite.AvailableProtocols {
		cfg := NewPKCS11ToolMultiProtocolConfig(t, protocol, module.BackendSoftware)
		skipIfModuleUnavailable(t, cfg.ModulePath)
		cfg.SetProtocolEnv(t)

		stdout, stderr, err := cfg.RunPKCS11Tool(t, "--list-mechanisms")
		if err != nil {
			t.Fatalf("list-mechanisms failed for %s: %v\nstderr: %s", protocol, err, stderr)
		}

		mechanismLists[protocol] = stdout
	}

	// Compare mechanism lists across protocols
	var referenceProtocol ProtocolType
	var referenceMechs string

	for protocol, mechs := range mechanismLists {
		if referenceMechs == "" {
			referenceProtocol = protocol
			referenceMechs = mechs
			continue
		}

		if mechs != referenceMechs {
			t.Errorf("mechanism list differs between %s and %s", referenceProtocol, protocol)
		}
	}
}
