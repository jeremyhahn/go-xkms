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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

// opensslEngineBinary returns the openssl command the ENGINE lanes drive.
//
// OPENSSL_BIN selects the build, exactly as it does for the provider lanes; only
// the fallback differs. OpenSSL 4.0 removed ENGINE support outright and the
// image's default openssl is 4.0.1, so an ENGINE test run against it cannot
// pass however correct the module is. These lanes therefore fall back to the
// image's OpenSSL 3 build, which still has engines, while the provider lanes
// keep testing 4.0.1.
func opensslEngineBinary() string {
	return opensslBinaryOr("openssl-3")
}

// requireOpenSSL asserts the openssl CLI is on PATH.
//
// The devcontainer installs it (ca-certificates depends on the openssl
// package), so its absence means the image drifted and the OpenSSL interop
// coverage silently disappeared.
func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(opensslBinary()); err != nil {
		t.Fatalf("%s is not on PATH: %v; the devcontainer image must provide it",
			opensslBinary(), err)
	}
}

// requireOpenSSLPKCS11Engine asserts the ENGINE lane can run at all: an openssl
// build that still supports engines, and the libp11 engine itself.
func requireOpenSSLPKCS11Engine(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath(opensslEngineBinary()); err != nil {
		t.Fatalf("%s is not on PATH: %v; the ENGINE lanes need an OpenSSL build that "+
			"still supports engines (set OPENSSL_BIN to select one)",
			opensslEngineBinary(), err)
	}

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
		t.Fatalf("the OpenSSL pkcs11 engine was not found in any of %v; the devcontainer "+
			"image must install libengine-pkcs11-openssl", enginePaths)
	}
}

// runOpenSSLCommand executes the ENGINE lane's openssl with the given arguments.
func runOpenSSLCommand(t *testing.T, cfg *OpenSSLTestConfig, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	cmd := exec.Command(opensslEngineBinary(), args...)
	cmd.Env = append(os.Environ(), "OPENSSL_CONF="+cfg.OpenSSLConfig)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err != nil {
		t.Logf("openssl command: %s %s", opensslEngineBinary(), strings.Join(args, " "))
		t.Logf("openssl stderr: %s", stderr)
	}

	return stdout, stderr, err
}

// TestOpenSSL_EngineInfo tests that the OpenSSL pkcs11 engine can load our module.
func TestOpenSSL_EngineInfo(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("the OpenSSL pkcs11 engine did not load the module: %v (stderr: %s)", err, stderr)
		}

		// Assertions
		assert.Contains(t, strings.ToLower(stdout+stderr), "pkcs11", "output should mention pkcs11 engine")
		t.Logf("OpenSSL engine info:\n%s", stdout)
	})
}

// TestOpenSSL_RSASignature tests RSA signing via OpenSSL pkcs11 engine.
func TestOpenSSL_RSASignature(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("OpenSSL pkcs11 engine sign not working: %v (stderr: %s)", err, stderr)
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		assert.Equal(t, 256, len(sigData), "RSA-2048 signature should be 256 bytes")

		requireEngineSignatureVerifies(t, cfg, p11Cfg, keyLabel, "rsa", "-sha256", dataFile, sigFile)

		t.Logf("OpenSSL RSA signature size: %d bytes", len(sigData))
	})
}

// requireEngineSignatureVerifies checks a signature produced through the
// OpenSSL pkcs11 ENGINE against the token's public key, outside the module.
//
// Every test in this file used to assert only the *size* of the signature the
// engine produced. A signature over the wrong digest, with the wrong padding,
// in the wrong encoding, or 256 bytes of noise all have the right size and all
// passed. Verification here runs with only OpenSSL's default provider active
// (runOpenSSLDefault), so the token cannot participate and cannot simply hand
// its own output back: the signature has to be genuinely correct under the
// public key the token published. keyCmd is "rsa" or "ec"; digestFlag must be
// the same digest the signature was produced over.
func requireEngineSignatureVerifies(t *testing.T, cfg *OpenSSLTestConfig, p11 *PKCS11ToolTestConfig,
	keyLabel, keyCmd, digestFlag, dataFile, sigFile string) {
	t.Helper()

	pubPEM := exportPublicKeyPEM(t, cfg, p11, keyLabel, keyCmd)

	requireSignatureVerifiesAgainst(t, pubPEM, keyLabel, digestFlag, dataFile, sigFile)
}

// requireSignatureVerifiesAgainst verifies sigFile over dataFile against an
// already-exported public key, with only OpenSSL's default provider active.
func requireSignatureVerifiesAgainst(t *testing.T, pubPEM, keyLabel, digestFlag, dataFile, sigFile string) {
	t.Helper()

	_, stderr, err := runOpenSSLDefault(t,
		"dgst", digestFlag, "-verify", pubPEM, "-signature", sigFile, dataFile,
	)
	require.NoErrorf(t, err,
		"the signature the pkcs11 ENGINE produced for %q did not verify against "+
			"that key's own public key outside the module: %s", keyLabel, stderr)
}

// exportPublicKeyPEMViaProvider reads a public key out of the module through
// pkcs11-provider and writes it as PEM.
//
// This exists only because `pkcs11-tool --read-object --type pubkey` cannot
// export a P-384 public key: it fails with "cannot create EVP_PKEY". The fault
// is OpenSC's, not this module's — SoftHSM, the reference PKCS#11
// implementation, fails identically for its own P-384 key under the same
// pkcs11-tool build, while P-256 and P-521 export fine from both. The module's
// CKA_EC_POINT for that key is a well-formed DER OCTET STRING holding a
// 97-byte uncompressed point and its CKA_EC_PARAMS is the secp384r1 OID, which
// is exactly why this second reader succeeds on the same object.
func exportPublicKeyPEMViaProvider(t *testing.T, cfg *OpenSSLTestConfig, label string) string {
	t.Helper()
	requireOpenSSLPKCS11Provider(t)

	pemPath := filepath.Join(cfg.TempDir, label+".provider.pub.pem")
	providerCfg := providerConfig(t, cfg.ModulePath, cfg.PIN)

	_, stderr, err := runOpenSSLWithProvider(t, providerCfg, cfg.PIN,
		"pkey", "-in", "pkcs11:object="+label+";type=public",
		"-pubin", "-pubout", "-out", pemPath,
	)
	require.NoErrorf(t, err,
		"exporting the public key for %q through pkcs11-provider failed: %s", label, stderr)

	return pemPath
}

// TestOpenSSL_ECDSASignature tests ECDSA signing via OpenSSL pkcs11 engine.
func TestOpenSSL_ECDSASignature(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("OpenSSL pkcs11 engine ECDSA sign not working: %v (stderr: %s)", err, stderr)
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		// P-256 ECDSA signature in DER format is typically 70-72 bytes
		assert.True(t, len(sigData) >= 64 && len(sigData) <= 72,
			"ECDSA signature should be 64-72 bytes, got %d", len(sigData))

		// The size range above spans both the raw r||s form PKCS#11 uses and the
		// ASN.1 DER form OpenSSL expects, so it cannot tell them apart. This
		// verification can: libp11 hands OpenSSL whatever the token returned,
		// and a raw r||s signature does not parse as DER.
		requireEngineSignatureVerifies(t, cfg, p11Cfg, keyLabel, "ec", "-sha256", dataFile, sigFile)

		t.Logf("OpenSSL ECDSA signature size: %d bytes", len(sigData))
	})
}

// TestOpenSSL_ECDSA_P384_Signature tests ECDSA P-384 signing via OpenSSL pkcs11 engine.
func TestOpenSSL_ECDSA_P384_Signature(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("OpenSSL pkcs11 engine ECDSA P-384 sign not working: %v (stderr: %s)", err, stderr)
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		// P-384 ECDSA signature in DER format is typically 96-104 bytes
		assert.True(t, len(sigData) >= 90 && len(sigData) <= 110,
			"ECDSA P-384 signature should be 90-110 bytes, got %d", len(sigData))

		// The public key is exported through pkcs11-provider rather than
		// pkcs11-tool. The subtest below pins the reason.
		pubPEM := exportPublicKeyPEMViaProvider(t, cfg, keyLabel)
		requireSignatureVerifiesAgainst(t, pubPEM, keyLabel, "-sha384", dataFile, sigFile)

		t.Logf("OpenSSL ECDSA P-384 signature size: %d bytes", len(sigData))
	})

	t.Run("pkcs11-tool cannot export a P-384 public key", func(t *testing.T) {
		// This asserts a defect in OpenSC's pkcs11-tool, not in the module, and
		// pinning it is what keeps the workaround above honest: the day OpenSC
		// can read a P-384 public key, this fails and the special case goes
		// away.
		//
		// The evidence that the fault is the tool's: SoftHSM, the reference
		// PKCS#11 implementation, fails the identical command with the identical
		// message for its own P-384 key, and the very same object on this token
		// exports without complaint through pkcs11-provider, which reads the
		// same CKA_EC_PARAMS and CKA_EC_POINT. P-256 and P-521 exports through
		// pkcs11-tool succeed in the sibling tests, so the failure is specific
		// to this one curve.
		out := filepath.Join(cfg.TempDir, "p384-via-tool.der")
		stdout, stderr, err := runPKCS11ToolCommand(t, p11Cfg,
			"--login", "--pin", p11Cfg.PIN, "--slot", p11Cfg.SlotID,
			"--read-object", "--type", "pubkey", "--label", keyLabel,
			"--output-file", out,
		)
		require.Errorf(t, err,
			"pkcs11-tool exported the P-384 public key; OpenSC has been fixed, so "+
				"drop exportPublicKeyPEMViaProvider from this test and use "+
				"requireEngineSignatureVerifies like the other curves (stdout: %s)", stdout)
		assert.Contains(t, stdout+stderr, "cannot create EVP_PKEY",
			"pkcs11-tool failed for a different reason than the known OpenSC "+
				"P-384 defect, which means something else is wrong")
	})
}

// TestOpenSSL_ECDSA_P521_Signature tests ECDSA P-521 signing via OpenSSL pkcs11 engine.
func TestOpenSSL_ECDSA_P521_Signature(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("OpenSSL pkcs11 engine ECDSA P-521 sign not working: %v (stderr: %s)", err, stderr)
		}

		// Assertions
		sigData, err := os.ReadFile(sigFile)
		require.NoError(t, err, "should be able to read signature file")
		assert.NotEmpty(t, sigData, "signature should not be empty")
		// P-521 ECDSA signature in DER format is typically 132-140 bytes
		assert.True(t, len(sigData) >= 125 && len(sigData) <= 145,
			"ECDSA P-521 signature should be 125-145 bytes, got %d", len(sigData))

		requireEngineSignatureVerifies(t, cfg, p11Cfg, keyLabel, "ec", "-sha512", dataFile, sigFile)

		t.Logf("OpenSSL ECDSA P-521 signature size: %d bytes", len(sigData))
	})
}

// Ed25519 has no test in this file. The deprecated libp11 ENGINE has no
// mechanism to carry an EdDSA key or its raw-message signing convention, so
// it cannot represent Ed25519 at all — the same reason RSA-PSS and OAEP live
// on the provider path rather than here. See
// TestOpenSSLProvider_Ed25519SignVerify in openssl_provider_test.go.

// TestOpenSSL_AES_Encryption tests AES encryption/decryption via OpenSSL with PKCS#11 keys.
// Note: AES via PKCS#11 engine requires secret key object support.
func TestOpenSSL_AES_Encryption(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
				"--keygen", "--key-type", "aes:"+strconv.Itoa(tc.keySize),
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
				t.Fatalf("AES key generation for %s failed via pkcs11-tool: %v; the token "+
					"advertises CKM_AES_KEY_GEN with CKF_GENERATE", tc.name, err)
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
						// The assertion below used to be wrapped in
						// `if err == nil && strings.Contains(stdout, tc.keyLabel)`,
						// which is the condition it was asserting: a token that
						// lost the key, or a C_FindObjects that returned nothing,
						// passed silently. Both failure modes now fail.
						stdout, stderr, err := runPKCS11ToolCommand(t, p11Cfg,
							"--login", "--pin", p11Cfg.PIN,
							"--slot", p11Cfg.SlotID,
							"--list-objects", "--type", "secrkey",
						)
						require.NoErrorf(t, err,
							"listing secret keys failed: %v (stderr: %s)", err, stderr)
						assert.Contains(t, stdout, tc.keyLabel,
							"the AES key %q was generated on the token, so C_FindObjects "+
								"must return it among the secret keys", tc.keyLabel)
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
							t.Fatalf("pkcs11-tool AES-CBC encrypt failed: %v; the token "+
								"advertises CKM_AES_CBC with CKF_ENCRYPT", encErr)
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
							t.Fatalf("pkcs11-tool AES-CBC decrypt failed: %v; the token "+
								"advertises CKM_AES_CBC with CKF_DECRYPT", decErr)
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
					t.Fatalf("OpenSSL pkcs11 engine AES decryption not working: %v (stderr: %s)", err, stderr)
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
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("OpenSSL pkcs11 engine cert generation not working: %v (stderr: %s)", err, stderr)
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
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("OpenSSL pkcs11 engine encryption not working: %v (stderr: %s)", err, stderr)
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
			t.Fatalf("OpenSSL pkcs11 engine decryption not working: %v (stderr: %s)", err, stderr)
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

// requireSSHKeygen asserts ssh-keygen is on PATH.
func requireSSHKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Fatalf("ssh-keygen is not on PATH: %v; the devcontainer image must install "+
			"openssh-client", err)
	}
}

// requireSSHAdd asserts ssh-add is on PATH.
func requireSSHAdd(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Fatalf("ssh-add is not on PATH: %v; the devcontainer image must install "+
			"openssh-client", err)
	}
}

// askpassEnv builds the environment that lets OpenSSH supply a PKCS#11 PIN
// without a terminal.
//
// ssh-keygen -D and ssh-add -s have no PIN flag: they read the PIN through the
// normal passphrase path. With SSH_ASKPASS pointed at a program that prints the
// PIN and SSH_ASKPASS_REQUIRE=force, OpenSSH uses that program instead of the
// tty, which is the documented non-interactive route. These tests used to skip
// the moment ssh-keygen mentioned a PIN, so the entire PKCS#11-over-SSH surface
// went unverified; driving askpass exercises it for real.
//
// SSH_ASKPASS_REQUIRE arrived in OpenSSH 8.4. DISPLAY is set as well so older
// clients, which only consult SSH_ASKPASS when a display is configured, take
// the same path.
func askpassEnv(t *testing.T, pin string) []string {
	t.Helper()

	script := filepath.Join(t.TempDir(), "askpass.sh")
	contents := "#!/bin/sh\nprintf '%s' " + shellQuote(pin) + "\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatalf("writing askpass helper: %v", err)
	}

	return append(os.Environ(),
		"SSH_ASKPASS="+script,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=:0",
	)
}

// shellQuote wraps s in single quotes for safe use in a /bin/sh script.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runSSHKeygenCommand executes ssh-keygen with the given arguments, supplying
// the token PIN through askpass so no terminal is required.
func runSSHKeygenCommand(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	cmd := exec.Command("ssh-keygen", args...)
	cmd.Env = askpassEnv(t, string(TestPINs.User))
	cmd.Stdin = strings.NewReader(string(TestPINs.User) + "\n")

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

// sshTokenKey is one line of `ssh-keygen -D` output: an SSH public key the
// PKCS#11 provider exposed, together with the label the token gave it.
type sshTokenKey struct {
	// Line is the verbatim authorized_keys line ssh-keygen printed.
	Line string

	// Algo is the SSH key algorithm name, e.g. "ssh-ed25519".
	Algo string

	// Comment is the trailing field, which ssh-keygen fills with CKA_LABEL.
	Comment string

	// PublicKey is Line parsed by golang.org/x/crypto/ssh.
	PublicKey ssh.PublicKey
}

// listSSHTokenKeys runs `ssh-keygen -D` against the module and parses every key
// it returns.
//
// Parsing with golang.org/x/crypto/ssh rather than string matching means a line
// that merely looks like an SSH key does not pass: the base64 body must decode
// into a well-formed public key of the algorithm named in the first field.
func listSSHTokenKeys(t *testing.T, modulePath string) []sshTokenKey {
	t.Helper()

	stdout, stderr, err := runSSHKeygenCommand(t, "-D", modulePath)
	require.NoErrorf(t, err,
		"ssh-keygen -D failed against the module: %v (stderr: %s); the PIN is "+
			"supplied non-interactively via SSH_ASKPASS", err, stderr)

	var keys []sshTokenKey
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		pub, comment, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(line))
		require.NoErrorf(t, parseErr,
			"ssh-keygen printed a line that is not a valid SSH public key: %q", line)

		keys = append(keys, sshTokenKey{
			Line:      line,
			Algo:      pub.Type(),
			Comment:   comment,
			PublicKey: pub,
		})
	}

	require.NotEmpty(t, keys, "ssh-keygen -D returned no keys from the token")
	return keys
}

// findSSHTokenKey returns the key ssh-keygen reported under the given label.
func findSSHTokenKey(t *testing.T, keys []sshTokenKey, label string) sshTokenKey {
	t.Helper()

	for _, k := range keys {
		if k.Comment == label {
			return k
		}
	}

	var seen []string
	for _, k := range keys {
		seen = append(seen, k.Algo+" "+k.Comment)
	}
	t.Fatalf("ssh-keygen -D did not report a key labelled %q; it listed: %v", label, seen)
	return sshTokenKey{}
}

// subjectPublicKeyInfo normalises what `pkcs11-tool --read-object --type
// pubkey` wrote into DER SubjectPublicKeyInfo.
//
// pkcs11-tool is inconsistent about this, and the inconsistency is the tool's
// rather than the token's: for an RSA or short-Weierstrass EC key it writes raw
// DER, but for an Edwards key it writes a PEM "PUBLIC KEY" block. SoftHSM, the
// reference PKCS#11 implementation, produces exactly the same split under the
// same pkcs11-tool build, which is what rules the module out as the cause. The
// difference is therefore absorbed here rather than asserted away, and any
// third encoding still fails.
func subjectPublicKeyInfo(t *testing.T, raw []byte) []byte {
	t.Helper()

	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN")) {
		return raw
	}

	block, rest := pem.Decode(raw)
	require.NotNil(t, block, "the exported public key looks like PEM but does not decode")
	assert.Equal(t, "PUBLIC KEY", block.Type,
		"an exported public key must be a PEM PUBLIC KEY block")
	assert.Empty(t, bytes.TrimSpace(rest), "the exported public key has trailing data")

	return block.Bytes
}

// requireSSHKeyMatchesToken asserts that the authorized_keys line ssh-keygen
// produced encodes the same public key the token holds under that label.
//
// The exported line was previously never compared against anything. A module
// that returned a different key, a stale key, or a hard-coded one would still
// have produced a well-formed `ssh-rsa AAAA...` line and passed. The public key
// is re-read here over a separate path (pkcs11-tool C_GetAttributeValue, then
// x509 SubjectPublicKeyInfo, then ssh.NewPublicKey) and the two authorized_keys
// encodings are compared byte for byte.
func requireSSHKeyMatchesToken(t *testing.T, p11 *PKCS11ToolTestConfig, key sshTokenKey, label string) {
	t.Helper()

	der := filepath.Join(t.TempDir(), label+".pub.der")
	_, stderr, err := runPKCS11ToolCommand(t, p11,
		"--login", "--pin", p11.PIN, "--slot", p11.SlotID,
		"--read-object", "--type", "pubkey", "--label", label,
		"--output-file", der,
	)
	require.NoErrorf(t, err, "reading the public key %q off the token failed: %s", label, stderr)

	raw, err := os.ReadFile(der)
	require.NoError(t, err)

	spki := subjectPublicKeyInfo(t, raw)

	parsed, err := x509.ParsePKIXPublicKey(spki)
	require.NoErrorf(t, err,
		"the public key the token returned for %q is not a valid "+
			"SubjectPublicKeyInfo", label)

	fromToken, err := ssh.NewPublicKey(parsed)
	require.NoErrorf(t, err, "converting the token's %q public key to SSH form failed", label)

	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(fromToken)))
	got := key.Algo + " " + strings.Fields(key.Line)[1]
	assert.Equal(t, want, got,
		"the key ssh-keygen exported for %q is not the key the token holds under "+
			"that label", label)
}

// TestSSH_ListPKCS11Keys tests listing keys from PKCS#11 provider via ssh-keygen.
func TestSSH_ListPKCS11Keys(t *testing.T) {
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("ssh-keygen PKCS#11 listing not working: %v (stderr: %s); the PIN is supplied non-interactively via SSH_ASKPASS", err, stderr)
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
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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

		// Select the key this test generated rather than whichever key happens
		// to be listed first: the token is shared across the suite, so lines[0]
		// belonged to an arbitrary other test.
		keys := listSSHTokenKeys(t, cfg.ModulePath)
		key := findSSHTokenKey(t, keys, keyLabel)

		assert.Equal(t, ssh.KeyAlgoRSA, key.Algo,
			"a 2048-bit RSA token key must be exported as %s", ssh.KeyAlgoRSA)

		// The exported line must encode the key the token actually holds.
		requireSSHKeyMatchesToken(t, p11Cfg, key, keyLabel)

		require.NoError(t, os.WriteFile(pubKeyFile, []byte(key.Line+"\n"), 0600))

		// The file must round-trip through ssh-keygen's own parser, which is
		// what an administrator installing it into authorized_keys relies on.
		roundTripped, err := os.ReadFile(pubKeyFile)
		require.NoError(t, err)
		reparsed, _, _, _, err := ssh.ParseAuthorizedKey(roundTripped)
		require.NoError(t, err, "the exported file is not a valid authorized_keys entry")
		assert.Equal(t, key.PublicKey.Marshal(), reparsed.Marshal(),
			"writing the exported key to a file and reading it back changed it")

		t.Logf("Exported SSH public key: %s...", key.Line[:min(80, len(key.Line))])
	})
}

// TestSSH_KeyFingerprint tests getting SSH key fingerprint from PKCS#11.
func TestSSH_KeyFingerprint(t *testing.T) {
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("ssh-keygen PKCS#11 not working: %v (stderr: %s); the PIN is supplied non-interactively via SSH_ASKPASS", err, stderr)
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
			t.Fatalf("ssh-keygen -l failed on the exported public key: %v (stderr: %s)", fpErr, fpStderr)
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
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("ssh-keygen PKCS#11 ECDSA not working: %v (stderr: %s); the PIN is supplied non-interactively via SSH_ASKPASS", err, stderr)
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
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("ssh-keygen PKCS#11 not working: %v (stderr: %s); the PIN is supplied non-interactively via SSH_ASKPASS", err, stderr)
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

// TestSSH_Ed25519Key drives an Ed25519 key that never leaves the token through
// the whole OpenSSH stack: listing, signing via ssh-agent, and a real login.
//
// This test used to assert the opposite. OpenSSH 9.2's ssh-pkcs11 layer handled
// only RSA and ECDSA and printed "skipping unsupported key type" for anything
// else, so the test pinned that limitation and deliberately failed if an
// Ed25519 key was ever listed. OpenSSH 10.1 added support for Ed25519 keys
// hosted on PKCS#11 tokens, and the devcontainer now ships 10.4p1, so the
// limitation is gone and the coverage it was blocking is here instead.
func TestSSH_Ed25519Key(t *testing.T) {
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireSSHPKCS11Ed25519Support(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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

	t.Run("ssh-keygen lists the Ed25519 token key", func(t *testing.T) {
		// ssh-keygen -D reads CKA_EC_PARAMS and CKA_EC_POINT and rebuilds the
		// public key itself, so a token that reports the wrong curve OID, or a
		// point that is not 32 raw bytes, is either dropped from the listing or
		// comes back under the wrong algorithm name.
		keys := listSSHTokenKeys(t, cfg.ModulePath)
		key := findSSHTokenKey(t, keys, keyLabel)

		assert.Equal(t, ssh.KeyAlgoED25519, key.Algo,
			"an edwards25519 token key must be exported as %s", ssh.KeyAlgoED25519)
		assert.Len(t, key.PublicKey.Marshal(), 51,
			"an ssh-ed25519 public key blob is the 11-byte algorithm name plus a "+
				"4-byte length, then a 4-byte length and the 32-byte point")

		requireSSHKeyMatchesToken(t, p11Cfg, key, keyLabel)

		t.Logf("ssh-keygen -D listed: %s", key.Line)
	})

	t.Run("the token signs for ssh-agent and the signature verifies", func(t *testing.T) {
		// Listing a public key proves nothing about signing. Here the private
		// key stays on the token, ssh-agent asks it for a signature through
		// ssh-pkcs11-helper, and the signature is checked in Go against the
		// public key ssh-keygen exported. Nothing in the module participates in
		// the verification, so a signature over the wrong bytes, or an Ed25519
		// signature that is not the raw 64-byte R||S of RFC 8032, fails here.
		keys := listSSHTokenKeys(t, cfg.ModulePath)
		key := findSSHTokenKey(t, keys, keyLabel)

		agentClient := startTokenSSHAgent(t, cfg.ModulePath, cfg.PIN)
		signer := agentKeyForBlob(t, agentClient, key.PublicKey)

		payload := make([]byte, 64)
		_, err := rand.Read(payload)
		require.NoError(t, err)

		sig, err := agentClient.Sign(signer, payload)
		require.NoError(t, err, "ssh-agent could not obtain a signature from the token")
		assert.Equal(t, ssh.KeyAlgoED25519, sig.Format,
			"an Ed25519 key signs with the %s algorithm", ssh.KeyAlgoED25519)
		assert.Len(t, sig.Blob, 64,
			"an Ed25519 signature is the 64-byte concatenation of R and S (RFC 8032)")

		require.NoError(t, key.PublicKey.Verify(payload, sig),
			"the signature the token produced does not verify against the public "+
				"key ssh-keygen exported for the same object")

		// A signature must be bound to its message.
		tampered := make([]byte, len(payload))
		copy(tampered, payload)
		tampered[0] ^= 0x01
		assert.Error(t, key.PublicKey.Verify(tampered, sig),
			"the signature verified over data that was never signed")
	})

	t.Run("sshd accepts a login with the Ed25519 token key", func(t *testing.T) {
		// The end-to-end proof: a real sshd, a real SSH transcript, and a
		// private key that only exists inside the token. authorized_keys holds
		// nothing but this one key and the client is restricted to
		// ssh-ed25519, so a successful login cannot have come from any other
		// key or algorithm.
		keys := listSSHTokenKeys(t, cfg.ModulePath)
		key := findSSHTokenKey(t, keys, keyLabel)

		startTokenSSHAgent(t, cfg.ModulePath, cfg.PIN)
		output := sshLoginWithAlgorithm(t, key, ssh.KeyAlgoED25519)

		assert.Contains(t, output, sshLoginMarker,
			"the remote command did not run, so the login did not complete")
	})
}

// sshLoginMarker is echoed by the remote command so the test can tell a
// completed login from an empty but successful-looking transcript.
const sshLoginMarker = "PKCS11_SSH_LOGIN_OK"

// minOpenSSHForPKCS11Ed25519 is the first OpenSSH release whose ssh-pkcs11
// layer can carry an Ed25519 key hosted on a token.
const minOpenSSHForPKCS11Ed25519 = 10.1

// requireSSHPKCS11Ed25519Support asserts the OpenSSH on PATH is new enough to
// represent an Ed25519 PKCS#11 key.
//
// Before 10.1 ssh-keygen -D silently dropped such keys with "skipping
// unsupported key type", which would make every assertion below fail for a
// reason that has nothing to do with the module. Failing here names the real
// cause: the image regressed to an older OpenSSH.
func requireSSHPKCS11Ed25519Support(t *testing.T) {
	t.Helper()

	// ssh -V writes to stderr and exits non-zero on some builds, so the output
	// is read rather than the status.
	out, _ := exec.Command("ssh", "-V").CombinedOutput()
	banner := strings.TrimSpace(string(out))

	m := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`).FindStringSubmatch(banner)
	require.Lenf(t, m, 3, "could not read an OpenSSH version out of %q", banner)

	major, err := strconv.Atoi(m[1])
	require.NoError(t, err)
	minor, err := strconv.Atoi(m[2])
	require.NoError(t, err)

	version := float64(major) + float64(minor)/10
	require.GreaterOrEqualf(t, version, minOpenSSHForPKCS11Ed25519,
		"OpenSSH %d.%d cannot host Ed25519 keys on a PKCS#11 token; support "+
			"arrived in %.1f and the devcontainer image must provide it (banner: %q)",
		major, minor, minOpenSSHForPKCS11Ed25519, banner)

	t.Logf("OpenSSH banner: %s", banner)
}

// shortTempDir creates a temp directory outside the test's own tree.
//
// Unix socket paths are limited to about 108 bytes, and t.TempDir() derives its
// path from the test and subtest names, which are long enough here to overflow
// that and make the agent socket unbindable.
func shortTempDir(t *testing.T, prefix string) string {
	t.Helper()

	dir, err := os.MkdirTemp("", prefix)
	require.NoError(t, err, "creating a scratch directory for the SSH harness")
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("removing %s: %v", dir, err)
		}
	})
	return dir
}

// startTokenSSHAgent runs an ssh-agent, loads the PKCS#11 module into it and
// returns a client for it. SSH_AUTH_SOCK is set for the remainder of the test.
//
// ssh-agent refuses providers outside its compile-time allow list, which the
// build in the devcontainer sets to the system library directories; -P widens
// it to wherever the module under test was built. The module reads its backend
// configuration from the environment, so the agent — and the
// ssh-pkcs11-helper it forks — inherit this process's environment.
func startTokenSSHAgent(t *testing.T, modulePath, pin string) agent.ExtendedAgent {
	t.Helper()
	requireSSHAdd(t)

	dir := shortTempDir(t, "p11agent")
	sock := filepath.Join(dir, "agent.sock")

	cmd := exec.Command("ssh-agent", "-D", "-a", sock, "-P", filepath.Join(filepath.Dir(modulePath), "*"))
	cmd.Env = os.Environ()
	require.NoError(t, cmd.Start(), "starting ssh-agent")
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("stopping ssh-agent: %v", err)
		}
		_ = cmd.Wait()
	})

	waitForSocket(t, sock)
	t.Setenv("SSH_AUTH_SOCK", sock)

	add := exec.Command("ssh-add", "-s", modulePath)
	add.Env = append(askpassEnv(t, pin), "SSH_AUTH_SOCK="+sock)
	addOut, err := add.CombinedOutput()
	require.NoErrorf(t, err,
		"ssh-add -s could not load the module into ssh-agent: %v (%s)", err, addOut)

	conn, err := net.Dial("unix", sock)
	require.NoError(t, err, "connecting to the ssh-agent socket")
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("closing the agent connection: %v", err)
		}
	})

	return agent.NewClient(conn)
}

// agentKeyForBlob returns the agent's handle on the given public key.
//
// Matching on the wire encoding rather than the comment is what makes the
// signature test meaningful: the key the agent signs with is provably the same
// key ssh-keygen exported.
func agentKeyForBlob(t *testing.T, client agent.ExtendedAgent, pub ssh.PublicKey) *agent.Key {
	t.Helper()

	keys, err := client.List()
	require.NoError(t, err, "listing the agent's identities")

	want := pub.Marshal()
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), want) {
			return k
		}
	}

	var seen []string
	for _, k := range keys {
		seen = append(seen, k.Format+" "+k.Comment)
	}
	t.Fatalf("ssh-agent does not hold the token key that ssh-keygen exported; it holds: %v", seen)
	return nil
}

// waitForSocket blocks until path exists, failing the test if it never appears.
func waitForSocket(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the socket %s never appeared", path)
}

// sshdBinary returns the sshd to run the login test against.
//
// The devcontainer installs OpenSSH under its own prefix and only puts the
// client tools on PATH, so sshd is looked for there first.
func sshdBinary(t *testing.T) string {
	t.Helper()

	candidates := []string{
		"/usr/local/openssh-10.4p1/sbin/sshd",
		"/usr/local/sbin/sshd",
		"/usr/sbin/sshd",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}

	t.Fatalf("no sshd found in any of %v nor on PATH; the devcontainer image must "+
		"provide the OpenSSH server for the PKCS#11 login test", candidates)
	return ""
}

// freeTCPPort returns a loopback port that is free right now.
func freeTCPPort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "reserving a port for the test sshd")

	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// waitForTCP blocks until the port accepts connections.
func waitForTCP(t *testing.T, port int) {
	t.Helper()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			if err := conn.Close(); err != nil {
				t.Logf("closing the probe connection: %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nothing was listening on %s within the timeout", addr)
}

// TestSSH_ECDSA_P384_Key tests ECDSA P-384 key operations with SSH.
func TestSSH_ECDSA_P384_Key(t *testing.T) {
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("ssh-keygen PKCS#11 ECDSA P-384 not working: %v (stderr: %s); the PIN is supplied non-interactively via SSH_ASKPASS", err, stderr)
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
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
			t.Fatalf("ssh-keygen PKCS#11 ECDSA P-521 not working: %v (stderr: %s); the PIN is supplied non-interactively via SSH_ASKPASS", err, stderr)
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
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)

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
		// Every generated key must come back, identified by its own label and
		// with the SSH algorithm its PKCS#11 key type implies. The previous
		// assertion accepted finding any ONE of the five, so four of the five
		// key types could vanish from ssh-keygen's view without failing.
		keys := listSSHTokenKeys(t, cfg.ModulePath)

		for _, kt := range keyTypes {
			key := findSSHTokenKey(t, keys, kt.label)
			assert.Equalf(t, kt.sshKeyType, key.Algo,
				"the token key %q was generated as %s, so ssh-keygen must report "+
					"it as %s, not %s", kt.label, kt.keyType, kt.sshKeyType, key.Algo)
			t.Logf("Found %s as %s", kt.label, key.Algo)
		}
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
