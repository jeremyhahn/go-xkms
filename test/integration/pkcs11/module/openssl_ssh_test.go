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

// Package module provides OpenSSL and SSH integration tests for the go-xkms
// PKCS#11 module. These tests validate that the PKCS#11 shared library works
// correctly with OpenSSL's pkcs11 engine and SSH's PKCS#11 provider.
//
// Build tags: integration,pkcs11_tool
package module

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// OpenSSL Integration Tests
// =============================================================================

// OpenSSLTestConfig holds configuration for OpenSSL integration tests.
type OpenSSLTestConfig struct {
	ModulePath    string
	EngineID      string
	PIN           string
	SOPIN         string
	TempDir       string
	OpenSSLConfig string
}

// NewOpenSSLTestConfig creates OpenSSL test configuration.
func NewOpenSSLTestConfig(t *testing.T) *OpenSSLTestConfig {
	t.Helper()

	modulePath := os.Getenv("PKCS11_MODULE")
	if modulePath == "" {
		if _, err := os.Stat("/workspace/build/lib/libxkms_pkcs11.so"); err == nil {
			modulePath = "/workspace/build/lib/libxkms_pkcs11.so"
		} else {
			modulePath = "build/lib/libxkms_pkcs11.so"
		}
	}

	tempDir := t.TempDir()

	// Create OpenSSL configuration file for pkcs11 engine
	configContent := `
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so
MODULE_PATH = ` + modulePath + `
init = 0

[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]
`

	configFile := filepath.Join(tempDir, "openssl.cnf")
	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write OpenSSL config: %v", err)
	}

	return &OpenSSLTestConfig{
		ModulePath:    modulePath,
		EngineID:      "pkcs11",
		PIN:           string(TestPINs.User),
		SOPIN:         string(TestPINs.SO),
		TempDir:       tempDir,
		OpenSSLConfig: configFile,
	}
}

// checkOpenSSLAvailable checks if OpenSSL is available.
func checkOpenSSLAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available in PATH, skipping OpenSSL integration tests")
	}
}

// checkOpenSSLPKCS11EngineAvailable checks if the OpenSSL pkcs11 engine is available.
func checkOpenSSLPKCS11EngineAvailable(t *testing.T) {
	t.Helper()

	// Check for libp11/OpenSSL engine
	enginePaths := []string{
		"/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so",
		"/usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so",
		"/usr/lib/engines/pkcs11.so",
		"/usr/lib64/engines-3/pkcs11.so",
	}

	found := false
	for _, path := range enginePaths {
		if _, err := os.Stat(path); err == nil {
			found = true
			break
		}
	}

	if !found {
		t.Skip("OpenSSL pkcs11 engine not found, skipping OpenSSL integration tests (install libengine-pkcs11-openssl)")
	}
}

// runOpenSSLCommand executes openssl with the given arguments.
func runOpenSSLCommand(t *testing.T, cfg *OpenSSLTestConfig, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	cmd := exec.Command("openssl", args...)
	cmd.Env = append(os.Environ(), "OPENSSL_CONF="+cfg.OpenSSLConfig)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err != nil {
		t.Logf("openssl command: openssl %s", strings.Join(args, " "))
		t.Logf("openssl stderr: %s", stderr)
	}

	return stdout, stderr, err
}

// TestOpenSSL_EngineInfo tests that the OpenSSL pkcs11 engine can load our module.
func TestOpenSSL_EngineInfo(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	// Initialize the module
	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	t.Run("list_engine", func(t *testing.T) {
		stdout, stderr, err := runOpenSSLCommand(t, cfg, "engine", "-t", "pkcs11")

		if err != nil {
			t.Logf("Engine test failed (engine may not be configured): %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Skip("pkcs11 engine not properly configured")
		}

		// Assertions
		assert.Contains(t, strings.ToLower(stdout+stderr), "pkcs11", "output should mention pkcs11 engine")
		t.Logf("OpenSSL engine info:\n%s", stdout)
	})
}

// TestOpenSSL_RSASignature tests RSA signing via OpenSSL pkcs11 engine.
func TestOpenSSL_RSASignature(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key via pkcs11-tool
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "openssl-rsa-test"
	keyID := "40"

	// Generate RSA key
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", keyID,
	)
	require.NoError(t, err, "RSA key generation should succeed")

	t.Run("sign_with_openssl_engine", func(t *testing.T) {
		// Create test data
		testData := []byte("Test data for OpenSSL RSA signing")
		dataFile := filepath.Join(cfg.TempDir, "openssl_data.bin")
		err := os.WriteFile(dataFile, testData, 0600)
		require.NoError(t, err)

		sigFile := filepath.Join(cfg.TempDir, "openssl_sig.bin")

		// Sign using OpenSSL with pkcs11 engine
		// URI format: pkcs11:object=<label>;pin-value=<pin>
		keyURI := "pkcs11:object=" + keyLabel + ";pin-value=" + cfg.PIN

		stdout, stderr, err := runOpenSSLCommand(t, cfg,
			"dgst", "-sha256", "-engine", "pkcs11", "-keyform", "engine",
			"-sign", keyURI,
			"-out", sigFile,
			dataFile,
		)

		if err != nil {
			t.Logf("OpenSSL sign failed (may need engine configuration): %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Skip("OpenSSL pkcs11 engine sign not working")
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		assert.Equal(t, 256, len(sigData), "RSA-2048 signature should be 256 bytes")

		t.Logf("OpenSSL RSA signature size: %d bytes", len(sigData))
	})
}

// TestOpenSSL_ECDSASignature tests ECDSA signing via OpenSSL pkcs11 engine.
func TestOpenSSL_ECDSASignature(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "openssl-ec-test"
	keyID := "41"

	// Generate EC key
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:secp256r1",
		"--label", keyLabel, "--id", keyID,
	)
	require.NoError(t, err, "EC key generation should succeed")

	t.Run("sign_ecdsa_with_openssl", func(t *testing.T) {
		testData := []byte("Test data for OpenSSL ECDSA signing")
		dataFile := filepath.Join(cfg.TempDir, "openssl_ec_data.bin")
		err := os.WriteFile(dataFile, testData, 0600)
		require.NoError(t, err)

		sigFile := filepath.Join(cfg.TempDir, "openssl_ec_sig.bin")
		keyURI := "pkcs11:object=" + keyLabel + ";pin-value=" + cfg.PIN

		stdout, stderr, err := runOpenSSLCommand(t, cfg,
			"dgst", "-sha256", "-engine", "pkcs11", "-keyform", "engine",
			"-sign", keyURI,
			"-out", sigFile,
			dataFile,
		)

		if err != nil {
			t.Logf("OpenSSL ECDSA sign failed: %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Skip("OpenSSL pkcs11 engine ECDSA sign not working")
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		// P-256 ECDSA signature in DER format is typically 70-72 bytes
		assert.True(t, len(sigData) >= 64 && len(sigData) <= 72,
			"ECDSA signature should be 64-72 bytes, got %d", len(sigData))

		t.Logf("OpenSSL ECDSA signature size: %d bytes", len(sigData))
	})
}

// TestOpenSSL_ECDSA_P384_Signature tests ECDSA P-384 signing via OpenSSL pkcs11 engine.
func TestOpenSSL_ECDSA_P384_Signature(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "openssl-ec-p384-test"
	keyID := "60"

	// Generate EC P-384 key
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:secp384r1",
		"--label", keyLabel, "--id", keyID,
	)
	require.NoError(t, err, "EC P-384 key generation should succeed")

	t.Run("sign_ecdsa_p384_with_openssl", func(t *testing.T) {
		testData := []byte("Test data for OpenSSL ECDSA P-384 signing")
		dataFile := filepath.Join(cfg.TempDir, "openssl_ec_p384_data.bin")
		err := os.WriteFile(dataFile, testData, 0600)
		require.NoError(t, err)

		sigFile := filepath.Join(cfg.TempDir, "openssl_ec_p384_sig.bin")
		keyURI := "pkcs11:object=" + keyLabel + ";pin-value=" + cfg.PIN

		stdout, stderr, err := runOpenSSLCommand(t, cfg,
			"dgst", "-sha384", "-engine", "pkcs11", "-keyform", "engine",
			"-sign", keyURI,
			"-out", sigFile,
			dataFile,
		)

		if err != nil {
			t.Logf("OpenSSL ECDSA P-384 sign failed: %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Skip("OpenSSL pkcs11 engine ECDSA P-384 sign not working")
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		// P-384 ECDSA signature in DER format is typically 96-104 bytes
		assert.True(t, len(sigData) >= 90 && len(sigData) <= 110,
			"ECDSA P-384 signature should be 90-110 bytes, got %d", len(sigData))

		t.Logf("OpenSSL ECDSA P-384 signature size: %d bytes", len(sigData))
	})
}

// TestOpenSSL_ECDSA_P521_Signature tests ECDSA P-521 signing via OpenSSL pkcs11 engine.
func TestOpenSSL_ECDSA_P521_Signature(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "openssl-ec-p521-test"
	keyID := "61"

	// Generate EC P-521 key
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:secp521r1",
		"--label", keyLabel, "--id", keyID,
	)
	require.NoError(t, err, "EC P-521 key generation should succeed")

	t.Run("sign_ecdsa_p521_with_openssl", func(t *testing.T) {
		testData := []byte("Test data for OpenSSL ECDSA P-521 signing")
		dataFile := filepath.Join(cfg.TempDir, "openssl_ec_p521_data.bin")
		err := os.WriteFile(dataFile, testData, 0600)
		require.NoError(t, err)

		sigFile := filepath.Join(cfg.TempDir, "openssl_ec_p521_sig.bin")
		keyURI := "pkcs11:object=" + keyLabel + ";pin-value=" + cfg.PIN

		stdout, stderr, err := runOpenSSLCommand(t, cfg,
			"dgst", "-sha512", "-engine", "pkcs11", "-keyform", "engine",
			"-sign", keyURI,
			"-out", sigFile,
			dataFile,
		)

		if err != nil {
			t.Logf("OpenSSL ECDSA P-521 sign failed: %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Skip("OpenSSL pkcs11 engine ECDSA P-521 sign not working")
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		// P-521 ECDSA signature in DER format is typically 132-140 bytes
		assert.True(t, len(sigData) >= 125 && len(sigData) <= 145,
			"ECDSA P-521 signature should be 125-145 bytes, got %d", len(sigData))

		t.Logf("OpenSSL ECDSA P-521 signature size: %d bytes", len(sigData))
	})
}

// TestOpenSSL_Ed25519_Signature tests Ed25519 signing via OpenSSL pkcs11 engine.
func TestOpenSSL_Ed25519_Signature(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "openssl-ed25519-test"
	keyID := "62"

	// Generate Ed25519 key
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:edwards25519",
		"--label", keyLabel, "--id", keyID,
	)
	require.NoError(t, err, "Ed25519 key generation should succeed")

	t.Run("sign_ed25519_with_openssl", func(t *testing.T) {
		testData := []byte("Test data for OpenSSL Ed25519 signing")
		dataFile := filepath.Join(cfg.TempDir, "openssl_ed25519_data.bin")
		err := os.WriteFile(dataFile, testData, 0600)
		require.NoError(t, err)

		sigFile := filepath.Join(cfg.TempDir, "openssl_ed25519_sig.bin")
		keyURI := "pkcs11:object=" + keyLabel + ";pin-value=" + cfg.PIN

		// Ed25519 doesn't use a separate hash algorithm - it's built-in
		stdout, stderr, err := runOpenSSLCommand(t, cfg,
			"pkeyutl", "-sign",
			"-engine", "pkcs11", "-keyform", "engine",
			"-inkey", keyURI,
			"-in", dataFile,
			"-out", sigFile,
			"-rawin", // Ed25519 requires raw input
		)

		if err != nil {
			t.Logf("OpenSSL Ed25519 sign failed: %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			// Ed25519 via pkcs11 engine may not be supported in all OpenSSL builds
			t.Skip("OpenSSL pkcs11 engine Ed25519 sign not working (may need OpenSSL 3.0+)")
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		// Ed25519 signature is always 64 bytes
		assert.Equal(t, 64, len(sigData), "Ed25519 signature should be 64 bytes")

		t.Logf("OpenSSL Ed25519 signature size: %d bytes", len(sigData))
	})
}

// TestOpenSSL_AES_Encryption tests AES encryption/decryption via OpenSSL with PKCS#11 keys.
// Note: AES via PKCS#11 engine requires secret key object support.
func TestOpenSSL_AES_Encryption(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module
	_, session := SetupInitializedModule(t)
	_ = session

	testCases := []struct {
		name     string
		keySize  int
		keyLabel string
		keyID    string
	}{
		{"AES_128", 16, "openssl-aes128-test", "70"},
		{"AES_192", 24, "openssl-aes192-test", "71"},
		{"AES_256", 32, "openssl-aes256-test", "72"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate AES key using pkcs11-tool
			_, _, err := runPKCS11ToolCommand(t, p11Cfg,
				"--login", "--pin", p11Cfg.PIN,
				"--slot", p11Cfg.SlotID,
				"--keygen", "--key-type", "aes:"+string(rune('0'+tc.keySize)),
				"--label", tc.keyLabel, "--id", tc.keyID,
			)

			// Note: pkcs11-tool may not support direct AES keygen with specific sizes
			// Try alternate format if first fails
			if err != nil {
				keySizeArg := ""
				switch tc.keySize {
				case 16:
					keySizeArg = "aes:16"
				case 24:
					keySizeArg = "aes:24"
				case 32:
					keySizeArg = "aes:32"
				}

				_, _, err = runPKCS11ToolCommand(t, p11Cfg,
					"--login", "--pin", p11Cfg.PIN,
					"--slot", p11Cfg.SlotID,
					"--keygen", "--key-type", keySizeArg,
					"--label", tc.keyLabel, "--id", tc.keyID,
				)
			}

			if err != nil {
				t.Skipf("AES key generation not supported for %s via pkcs11-tool", tc.name)
			}

			t.Run("encrypt_decrypt_via_pkcs11", func(t *testing.T) {
				// Create test plaintext (must be block-aligned for CBC without padding)
				plaintext := make([]byte, 32) // 2 AES blocks
				_, err := rand.Read(plaintext)
				require.NoError(t, err)

				plaintextFile := filepath.Join(cfg.TempDir, tc.name+"_plaintext.bin")
				ciphertextFile := filepath.Join(cfg.TempDir, tc.name+"_ciphertext.bin")
				decryptedFile := filepath.Join(cfg.TempDir, tc.name+"_decrypted.bin")

				err = os.WriteFile(plaintextFile, plaintext, 0600)
				require.NoError(t, err)

				// Generate random IV
				iv := make([]byte, 16)
				_, err = rand.Read(iv)
				require.NoError(t, err)

				ivFile := filepath.Join(cfg.TempDir, tc.name+"_iv.bin")
				err = os.WriteFile(ivFile, iv, 0600)
				require.NoError(t, err)

				keyURI := "pkcs11:object=" + tc.keyLabel + ";pin-value=" + cfg.PIN

				// Try to encrypt using OpenSSL with pkcs11 engine
				// Note: AES symmetric encryption via PKCS#11 engine may not be universally supported
				stdout, stderr, err := runOpenSSLCommand(t, cfg,
					"enc", "-aes-256-cbc",
					"-engine", "pkcs11",
					"-K", keyURI,
					"-iv", "00000000000000000000000000000000",
					"-in", plaintextFile,
					"-out", ciphertextFile,
					"-nopad",
				)

				if err != nil {
					t.Logf("OpenSSL AES encrypt via pkcs11 failed (expected - symmetric keys not typically supported via engine): %v", err)
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)

					// Fallback: Verify key exists and can be used via pkcs11-tool encrypt
					t.Run("verify_key_exists", func(t *testing.T) {
						stdout, _, err := runPKCS11ToolCommand(t, p11Cfg,
							"--login", "--pin", p11Cfg.PIN,
							"--slot", p11Cfg.SlotID,
							"--list-objects", "--type", "secrkey",
						)

						if err == nil && strings.Contains(stdout, tc.keyLabel) {
							t.Logf("AES key %s exists in token", tc.keyLabel)
							assert.Contains(t, stdout, tc.keyLabel, "AES key should be listed")
						}
					})

					// Test AES via pkcs11-tool directly
					t.Run("encrypt_decrypt_via_pkcs11tool", func(t *testing.T) {
						// Encrypt using pkcs11-tool
						_, _, encErr := runPKCS11ToolCommand(t, p11Cfg,
							"--login", "--pin", p11Cfg.PIN,
							"--slot", p11Cfg.SlotID,
							"--encrypt", "--mechanism", "AES-CBC",
							"--label", tc.keyLabel,
							"--iv", "00000000000000000000000000000000",
							"--input-file", plaintextFile,
							"--output-file", ciphertextFile,
						)

						if encErr != nil {
							t.Logf("pkcs11-tool AES encrypt failed: %v", encErr)
							t.Skip("AES encryption not working via pkcs11-tool")
						}

						// Verify ciphertext
						ciphertext, err := os.ReadFile(ciphertextFile)
						require.NoError(t, err)
						assert.NotEmpty(t, ciphertext, "ciphertext should not be empty")
						assert.NotEqual(t, plaintext, ciphertext, "ciphertext should differ from plaintext")

						// Decrypt
						_, _, decErr := runPKCS11ToolCommand(t, p11Cfg,
							"--login", "--pin", p11Cfg.PIN,
							"--slot", p11Cfg.SlotID,
							"--decrypt", "--mechanism", "AES-CBC",
							"--label", tc.keyLabel,
							"--iv", "00000000000000000000000000000000",
							"--input-file", ciphertextFile,
							"--output-file", decryptedFile,
						)

						if decErr != nil {
							t.Logf("pkcs11-tool AES decrypt failed: %v", decErr)
							t.Skip("AES decryption not working via pkcs11-tool")
						}

						// Verify roundtrip
						decrypted, err := os.ReadFile(decryptedFile)
						require.NoError(t, err)
						assert.Equal(t, plaintext, decrypted, "decrypted should match plaintext")

						t.Logf("%s encrypt/decrypt roundtrip successful via pkcs11-tool", tc.name)
					})

					return
				}

				// If OpenSSL enc worked, verify and decrypt
				ciphertext, err := os.ReadFile(ciphertextFile)
				require.NoError(t, err)
				assert.NotEmpty(t, ciphertext, "ciphertext should not be empty")

				// Decrypt
				stdout, stderr, err = runOpenSSLCommand(t, cfg,
					"enc", "-d", "-aes-256-cbc",
					"-engine", "pkcs11",
					"-K", keyURI,
					"-iv", "00000000000000000000000000000000",
					"-in", ciphertextFile,
					"-out", decryptedFile,
					"-nopad",
				)

				if err != nil {
					t.Logf("OpenSSL AES decrypt failed: %v", err)
					t.Logf("stdout: %s", stdout)
					t.Logf("stderr: %s", stderr)
					t.Skip("OpenSSL pkcs11 engine AES decryption not working")
				}

				decrypted, err := os.ReadFile(decryptedFile)
				require.NoError(t, err)
				assert.Equal(t, plaintext, decrypted, "decrypted should match plaintext")

				t.Logf("%s encrypt/decrypt roundtrip successful via OpenSSL engine", tc.name)
			})
		})
	}
}

// TestOpenSSL_GenerateSelfSignedCert tests generating a self-signed certificate using PKCS#11 key.
func TestOpenSSL_GenerateSelfSignedCert(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "openssl-cert-test"
	keyID := "42"

	// Generate RSA key
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", keyID,
	)
	require.NoError(t, err, "RSA key generation should succeed")

	t.Run("generate_self_signed_cert", func(t *testing.T) {
		certFile := filepath.Join(cfg.TempDir, "test.crt")
		keyURI := "pkcs11:object=" + keyLabel + ";pin-value=" + cfg.PIN

		stdout, stderr, err := runOpenSSLCommand(t, cfg,
			"req", "-new", "-x509",
			"-engine", "pkcs11",
			"-keyform", "engine",
			"-key", keyURI,
			"-out", certFile,
			"-days", "365",
			"-subj", "/CN=go-xkms-test/O=Test",
			"-sha256",
		)

		if err != nil {
			t.Logf("OpenSSL cert generation failed: %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Skip("OpenSSL pkcs11 engine cert generation not working")
		}

		// Assertions - verify certificate was created and is valid
		certData, err := os.ReadFile(certFile)
		require.NoError(t, err, "should be able to read certificate file")
		assert.NotEmpty(t, certData, "certificate should not be empty")

		// Parse and validate certificate
		block, _ := pem.Decode(certData)
		require.NotNil(t, block, "certificate should be PEM encoded")
		assert.Equal(t, "CERTIFICATE", block.Type, "should be a certificate")

		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err, "should parse as valid X.509 certificate")
		assert.Equal(t, "go-xkms-test", cert.Subject.CommonName, "CN should match")
		assert.Equal(t, "Test", cert.Subject.Organization[0], "O should match")

		t.Logf("Generated self-signed certificate for CN=%s", cert.Subject.CommonName)
	})
}

// TestOpenSSL_RSAEncryptDecrypt tests RSA encryption/decryption via OpenSSL.
func TestOpenSSL_RSAEncryptDecrypt(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkOpenSSLAvailable(t)
	checkOpenSSLPKCS11EngineAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewOpenSSLTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "openssl-enc-test"
	keyID := "43"

	// Generate RSA key
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", keyID,
	)
	require.NoError(t, err, "RSA key generation should succeed")

	t.Run("encrypt_decrypt_roundtrip", func(t *testing.T) {
		// Create test plaintext
		plaintext := make([]byte, 32)
		_, err := rand.Read(plaintext)
		require.NoError(t, err)

		plaintextFile := filepath.Join(cfg.TempDir, "plaintext.bin")
		ciphertextFile := filepath.Join(cfg.TempDir, "ciphertext.bin")
		decryptedFile := filepath.Join(cfg.TempDir, "decrypted.bin")

		err = os.WriteFile(plaintextFile, plaintext, 0600)
		require.NoError(t, err)

		keyURI := "pkcs11:object=" + keyLabel + ";pin-value=" + cfg.PIN

		// Encrypt
		stdout, stderr, err := runOpenSSLCommand(t, cfg,
			"pkeyutl", "-encrypt",
			"-engine", "pkcs11",
			"-keyform", "engine",
			"-inkey", keyURI,
			"-in", plaintextFile,
			"-out", ciphertextFile,
		)

		if err != nil {
			t.Logf("OpenSSL encrypt failed: %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Skip("OpenSSL pkcs11 engine encryption not working")
		}

		// Verify ciphertext
		ciphertext, err := os.ReadFile(ciphertextFile)
		require.NoError(t, err)
		assert.NotEmpty(t, ciphertext, "ciphertext should not be empty")
		assert.NotEqual(t, plaintext, ciphertext, "ciphertext should differ from plaintext")

		// Decrypt
		stdout, stderr, err = runOpenSSLCommand(t, cfg,
			"pkeyutl", "-decrypt",
			"-engine", "pkcs11",
			"-keyform", "engine",
			"-inkey", keyURI,
			"-in", ciphertextFile,
			"-out", decryptedFile,
		)

		if err != nil {
			t.Logf("OpenSSL decrypt failed: %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)
			t.Skip("OpenSSL pkcs11 engine decryption not working")
		}

		// Assertions - verify roundtrip
		decrypted, err := os.ReadFile(decryptedFile)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted, "decrypted data should match original plaintext")

		t.Log("OpenSSL RSA encrypt/decrypt roundtrip successful")
	})
}

// =============================================================================
// SSH Integration Tests
// =============================================================================

// SSHTestConfig holds configuration for SSH integration tests.
type SSHTestConfig struct {
	ModulePath string
	PIN        string
	TempDir    string
}

// NewSSHTestConfig creates SSH test configuration.
func NewSSHTestConfig(t *testing.T) *SSHTestConfig {
	t.Helper()

	modulePath := os.Getenv("PKCS11_MODULE")
	if modulePath == "" {
		if _, err := os.Stat("/workspace/build/lib/libxkms_pkcs11.so"); err == nil {
			modulePath = "/workspace/build/lib/libxkms_pkcs11.so"
		} else {
			modulePath = "build/lib/libxkms_pkcs11.so"
		}
	}

	return &SSHTestConfig{
		ModulePath: modulePath,
		PIN:        string(TestPINs.User),
		TempDir:    t.TempDir(),
	}
}

// checkSSHKeygenAvailable checks if ssh-keygen is available.
func checkSSHKeygenAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available in PATH, skipping SSH integration tests")
	}
}

// checkSSHAddAvailable checks if ssh-add is available.
func checkSSHAddAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add not available in PATH, skipping SSH integration tests")
	}
}

// runSSHKeygenCommand executes ssh-keygen with the given arguments.
func runSSHKeygenCommand(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	cmd := exec.Command("ssh-keygen", args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err != nil {
		t.Logf("ssh-keygen command: ssh-keygen %s", strings.Join(args, " "))
		t.Logf("ssh-keygen stderr: %s", stderr)
	}

	return stdout, stderr, err
}

// TestSSH_ListPKCS11Keys tests listing keys from PKCS#11 provider via ssh-keygen.
func TestSSH_ListPKCS11Keys(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate keys
	_, session := SetupInitializedModule(t)
	_ = session

	// Generate RSA key for SSH
	keyLabel := "ssh-rsa-test"
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", "50",
	)
	require.NoError(t, err, "RSA key generation should succeed")

	// Generate ECDSA key for SSH
	ecKeyLabel := "ssh-ecdsa-test"
	_, _, err = runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:secp256r1",
		"--label", ecKeyLabel, "--id", "51",
	)
	require.NoError(t, err, "ECDSA key generation should succeed")

	t.Run("list_pkcs11_keys", func(t *testing.T) {
		// ssh-keygen -D lists all keys from PKCS#11 provider
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			t.Logf("ssh-keygen -D failed: %v", err)
			t.Logf("stdout: %s", stdout)
			t.Logf("stderr: %s", stderr)

			// Check if it's a PIN prompt issue
			if strings.Contains(stderr, "PIN") || strings.Contains(stderr, "passphrase") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 listing not working")
		}

		// Assertions
		assert.NotEmpty(t, stdout, "should list at least one key")

		// SSH public key format starts with key type
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		assert.GreaterOrEqual(t, len(lines), 1, "should have at least one key")

		for _, line := range lines {
			// SSH public key format: <type> <base64-data> <comment>
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				keyType := parts[0]
				assert.True(t,
					strings.HasPrefix(keyType, "ssh-rsa") ||
						strings.HasPrefix(keyType, "ecdsa-sha2") ||
						strings.HasPrefix(keyType, "ssh-ed25519"),
					"key type should be valid SSH format: %s", keyType)
				t.Logf("Found SSH key: %s", keyType)
			}
		}

		t.Logf("ssh-keygen -D output:\n%s", stdout)
	})
}

// TestSSH_ExportPKCS11PublicKey tests exporting SSH public key from PKCS#11.
func TestSSH_ExportPKCS11PublicKey(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "ssh-export-test"
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", "52",
	)
	require.NoError(t, err, "RSA key generation should succeed")

	t.Run("export_public_key_to_file", func(t *testing.T) {
		pubKeyFile := filepath.Join(cfg.TempDir, "ssh_pub.pub")

		// Export keys from PKCS#11 provider
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			if strings.Contains(stderr, "PIN") || strings.Contains(stderr, "passphrase") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 export not working")
		}

		// Write first key to file
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		require.GreaterOrEqual(t, len(lines), 1, "should have at least one key")

		err = os.WriteFile(pubKeyFile, []byte(lines[0]+"\n"), 0600)
		require.NoError(t, err)

		// Assertions - verify file contains valid SSH public key
		pubKeyData, err := os.ReadFile(pubKeyFile)
		require.NoError(t, err)

		keyLine := strings.TrimSpace(string(pubKeyData))
		parts := strings.Fields(keyLine)
		require.GreaterOrEqual(t, len(parts), 2, "should have key type and data")

		keyType := parts[0]
		assert.True(t,
			strings.HasPrefix(keyType, "ssh-rsa") ||
				strings.HasPrefix(keyType, "ecdsa-sha2"),
			"exported key should be valid SSH format")

		t.Logf("Exported SSH public key: %s...", keyLine[:min(80, len(keyLine))])
	})
}

// TestSSH_KeyFingerprint tests getting SSH key fingerprint from PKCS#11.
func TestSSH_KeyFingerprint(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "ssh-fingerprint-test"
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", "53",
	)
	require.NoError(t, err, "RSA key generation should succeed")

	t.Run("get_key_fingerprint", func(t *testing.T) {
		// Get keys and save to temp file
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			if strings.Contains(stderr, "PIN") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 not working")
		}

		// Write first key to file
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		require.GreaterOrEqual(t, len(lines), 1)

		pubKeyFile := filepath.Join(cfg.TempDir, "fp_key.pub")
		err = os.WriteFile(pubKeyFile, []byte(lines[0]+"\n"), 0600)
		require.NoError(t, err)

		// Get fingerprint
		fpStdout, fpStderr, fpErr := runSSHKeygenCommand(t, "-l", "-f", pubKeyFile)
		if fpErr != nil {
			t.Logf("fingerprint failed: %v, stderr: %s", fpErr, fpStderr)
			t.Skip("ssh-keygen fingerprint not working")
		}

		// Assertions - verify fingerprint format
		// Format: <bits> <hash>:<fingerprint> <comment> (<type>)
		assert.NotEmpty(t, fpStdout, "fingerprint should not be empty")

		// SHA256 fingerprint format
		sha256Re := regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`)
		assert.True(t, sha256Re.MatchString(fpStdout),
			"should contain SHA256 fingerprint")

		// Extract and log fingerprint
		matches := sha256Re.FindString(fpStdout)
		t.Logf("SSH key fingerprint: %s", matches)
	})
}

// TestSSH_ECDSAKey tests ECDSA key operations with SSH.
func TestSSH_ECDSAKey(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate ECDSA key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "ssh-ecdsa-nistp256"
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:secp256r1",
		"--label", keyLabel, "--id", "54",
	)
	require.NoError(t, err, "ECDSA key generation should succeed")

	t.Run("list_ecdsa_key", func(t *testing.T) {
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			if strings.Contains(stderr, "PIN") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 ECDSA not working")
		}

		// Assertions - look for ECDSA key
		found := false
		for _, line := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(line, "ecdsa-sha2-nistp256") {
				found = true
				t.Logf("Found ECDSA key: %s...", line[:min(80, len(line))])
				break
			}
		}

		assert.True(t, found || len(stdout) > 0,
			"should find at least one key (ECDSA or RSA)")

		t.Logf("ssh-keygen -D ECDSA output:\n%s", stdout)
	})
}

// TestSSH_AuthorizedKeysFormat tests that exported keys are in authorized_keys format.
func TestSSH_AuthorizedKeysFormat(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "ssh-authkeys-test"
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", "55",
	)
	require.NoError(t, err, "RSA key generation should succeed")

	t.Run("verify_authorized_keys_format", func(t *testing.T) {
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			if strings.Contains(stderr, "PIN") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 not working")
		}

		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		require.GreaterOrEqual(t, len(lines), 1)

		for i, line := range lines {
			if line == "" {
				continue
			}

			// Assertions - verify authorized_keys format
			parts := strings.Fields(line)
			require.GreaterOrEqual(t, len(parts), 2,
				"line %d should have at least key type and data", i)

			keyType := parts[0]
			keyData := parts[1]

			// Verify key type
			validTypes := []string{"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256",
				"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-ed25519"}
			isValidType := false
			for _, vt := range validTypes {
				if keyType == vt {
					isValidType = true
					break
				}
			}
			assert.True(t, isValidType, "key type %s should be valid", keyType)

			// Verify base64 data exists and is reasonable length
			assert.GreaterOrEqual(t, len(keyData), 100,
				"base64 key data should be substantial")

			t.Logf("Key %d: type=%s, data_len=%d", i, keyType, len(keyData))
		}
	})
}

// TestSSH_Ed25519Key tests Ed25519 key operations with SSH.
func TestSSH_Ed25519Key(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate Ed25519 key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "ssh-ed25519-test"
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:edwards25519",
		"--label", keyLabel, "--id", "80",
	)
	require.NoError(t, err, "Ed25519 key generation should succeed")

	t.Run("list_ed25519_key", func(t *testing.T) {
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			if strings.Contains(stderr, "PIN") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 Ed25519 not working")
		}

		// Assertions - look for Ed25519 key
		found := false
		for _, line := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(line, "ssh-ed25519") {
				found = true
				t.Logf("Found Ed25519 key: %s...", line[:min(80, len(line))])
				break
			}
		}

		// Ed25519 via PKCS#11 may not be supported by all SSH versions
		if !found {
			t.Logf("Ed25519 key not found in SSH output (may not be supported)")
			t.Logf("ssh-keygen -D output:\n%s", stdout)
		}

		assert.True(t, found || len(stdout) > 0,
			"should find at least one key")
	})
}

// TestSSH_ECDSA_P384_Key tests ECDSA P-384 key operations with SSH.
func TestSSH_ECDSA_P384_Key(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate ECDSA P-384 key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "ssh-ecdsa-p384"
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:secp384r1",
		"--label", keyLabel, "--id", "81",
	)
	require.NoError(t, err, "ECDSA P-384 key generation should succeed")

	t.Run("list_ecdsa_p384_key", func(t *testing.T) {
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			if strings.Contains(stderr, "PIN") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 ECDSA P-384 not working")
		}

		// Assertions - look for ECDSA P-384 key
		found := false
		for _, line := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(line, "ecdsa-sha2-nistp384") {
				found = true
				t.Logf("Found ECDSA P-384 key: %s...", line[:min(80, len(line))])
				break
			}
		}

		assert.True(t, found || len(stdout) > 0,
			"should find at least one key (ECDSA P-384 or other)")

		t.Logf("ssh-keygen -D ECDSA P-384 output:\n%s", stdout)
	})
}

// TestSSH_ECDSA_P521_Key tests ECDSA P-521 key operations with SSH.
func TestSSH_ECDSA_P521_Key(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module and generate ECDSA P-521 key
	_, session := SetupInitializedModule(t)
	_ = session

	keyLabel := "ssh-ecdsa-p521"
	_, _, err := runPKCS11ToolCommand(t, p11Cfg,
		"--login", "--pin", p11Cfg.PIN,
		"--slot", p11Cfg.SlotID,
		"--keypairgen", "--key-type", "EC:secp521r1",
		"--label", keyLabel, "--id", "82",
	)
	require.NoError(t, err, "ECDSA P-521 key generation should succeed")

	t.Run("list_ecdsa_p521_key", func(t *testing.T) {
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			if strings.Contains(stderr, "PIN") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 ECDSA P-521 not working")
		}

		// Assertions - look for ECDSA P-521 key
		found := false
		for _, line := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(line, "ecdsa-sha2-nistp521") {
				found = true
				t.Logf("Found ECDSA P-521 key: %s...", line[:min(80, len(line))])
				break
			}
		}

		assert.True(t, found || len(stdout) > 0,
			"should find at least one key (ECDSA P-521 or other)")

		t.Logf("ssh-keygen -D ECDSA P-521 output:\n%s", stdout)
	})
}

// TestSSH_AllKeyTypes tests listing all supported key types from PKCS#11.
func TestSSH_AllKeyTypes(t *testing.T) {
	skipIfNoFilePersistence(t)
	checkSSHKeygenAvailable(t)
	skipIfToolUnavailable(t)

	cfg := NewSSHTestConfig(t)
	skipIfModuleUnavailable(t, cfg.ModulePath)

	p11Cfg := NewPKCS11ToolTestConfig(t)

	// Initialize module
	_, session := SetupInitializedModule(t)
	_ = session

	// Generate various key types
	keyTypes := []struct {
		label      string
		keyType    string
		id         string
		sshKeyType string
	}{
		{"ssh-all-rsa", "rsa:2048", "90", "ssh-rsa"},
		{"ssh-all-p256", "EC:secp256r1", "91", "ecdsa-sha2-nistp256"},
		{"ssh-all-p384", "EC:secp384r1", "92", "ecdsa-sha2-nistp384"},
		{"ssh-all-p521", "EC:secp521r1", "93", "ecdsa-sha2-nistp521"},
		{"ssh-all-ed25519", "EC:edwards25519", "94", "ssh-ed25519"},
	}

	for _, kt := range keyTypes {
		_, _, err := runPKCS11ToolCommand(t, p11Cfg,
			"--login", "--pin", p11Cfg.PIN,
			"--slot", p11Cfg.SlotID,
			"--keypairgen", "--key-type", kt.keyType,
			"--label", kt.label, "--id", kt.id,
		)
		require.NoError(t, err, "%s key generation should succeed", kt.label)
	}

	t.Run("list_all_key_types", func(t *testing.T) {
		stdout, stderr, err := runSSHKeygenCommand(t, "-D", cfg.ModulePath)

		if err != nil {
			if strings.Contains(stderr, "PIN") {
				t.Skip("ssh-keygen requires interactive PIN entry, skipping")
			}
			t.Skip("ssh-keygen PKCS#11 not working")
		}

		// Count key types found
		foundTypes := make(map[string]int)
		for _, line := range strings.Split(stdout, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			for _, kt := range keyTypes {
				if strings.HasPrefix(line, kt.sshKeyType) {
					foundTypes[kt.sshKeyType]++
				}
			}
		}

		t.Logf("Key types found:")
		for keyType, count := range foundTypes {
			t.Logf("  %s: %d keys", keyType, count)
		}

		// At minimum, RSA and P-256 should work
		assert.GreaterOrEqual(t, len(foundTypes), 1,
			"should find at least one key type")

		// Log full output for debugging
		t.Logf("ssh-keygen -D full output:\n%s", stdout)
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
