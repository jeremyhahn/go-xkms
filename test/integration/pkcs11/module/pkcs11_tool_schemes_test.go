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

// Package module covers three interop surfaces the other pkcs11-tool and
// OpenSSL suites in this directory do not exercise:
//
//   - RSA-PSS signing driven entirely through pkcs11-tool's combined
//     hash-and-sign mechanism, rather than through the OpenSSL provider's
//     pkeyutl path that openssl_provider_test.go already covers.
//   - Message digesting through pkcs11-tool's --hash mode, checked against
//     crypto/sha256 computed on the same input.
//   - Ed25519 key generation performed entirely inside the token by
//     pkcs11-provider's OSSL_OP_KEYMGMT path, mirroring the RSA/EC coverage
//     in openssl_rand_keygen_test.go for the one key type that has no
//     algorithm parameters at all.
//
// Every test here fails rather than skips when its tooling is missing, for
// the same reason the rest of this package does: a silent skip is how
// interop coverage disappears without anyone noticing.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// RSA-PSS signing via pkcs11-tool
// =============================================================================

// TestPKCS11Tool_SignRSAPSS drives an RSA-PSS signature through pkcs11-tool
// end to end: it generates an RSA-2048 key pair with the tool, then signs a
// message with the combined hash-and-sign PSS mechanism the tool exposes.
//
// pkcs11-tool derives the PSS hashAlg and MGF1 hash directly from the
// mechanism name -- SHA256-RSA-PKCS-PSS implies SHA-256 for both -- and
// defaults the salt length to the digest length when --salt-len is not
// given, so no extra flags are required for the common case this test
// exercises. (Assumption: if the installed pkcs11-tool instead requires an
// explicit --hash-algorithm/--salt-len pair for this mechanism name, that
// needs confirming in the devcontainer; RSA-PKCS-PSS is the documented
// fallback name for the raw, caller-hashed variant.)
func TestPKCS11Tool_SignRSAPSS(t *testing.T) {
	requireFilePersistence(t)
	requireTool(t)
	cfg := NewPKCS11ToolTestConfig(t)
	requireModule(t, cfg.ModulePath)

	SetupInitializedModule(t)

	const keyLabel = "pss-sign-test"
	const keyID = "70"

	keygenOutput, keygenStderr, keygenErr := runPKCS11ToolCommand(t, cfg,
		"--login", "--pin", cfg.PIN,
		"--slot", cfg.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", keyID,
	)
	if keygenErr != nil {
		t.Fatalf("RSA key generation for PSS signing failed: %v\nstdout: %s\nstderr: %s",
			keygenErr, keygenOutput, keygenStderr)
	}

	testData := []byte("Test data for RSA-PSS signing")
	dataFile := writeTestDataFile(t, cfg.TempDir, "rsa_pss_data.bin", testData)
	sigFile := filepath.Join(cfg.TempDir, "rsa_pss_sig.bin")

	signOutput, signStderr, signErr := runPKCS11ToolCommand(t, cfg,
		"--login", "--pin", cfg.PIN,
		"--slot", cfg.SlotID,
		"--sign",
		"--mechanism", "SHA256-RSA-PKCS-PSS",
		"--id", keyID,
		"--input-file", dataFile,
		"--output-file", sigFile,
	)
	if signErr != nil {
		t.Fatalf("RSA-PSS sign failed: %v\nstdout: %s\nstderr: %s", signErr, signOutput, signStderr)
	}

	sigData := readTestDataFile(t, sigFile)
	if len(sigData) == 0 {
		t.Fatal("expected non-empty RSA-PSS signature")
	}

	// An RSA-2048 PSS signature is exactly the modulus size, same as PKCS#1 v1.5.
	const expectedSigSize = 256
	if len(sigData) != expectedSigSize {
		t.Errorf("expected RSA-PSS signature size %d bytes, got %d", expectedSigSize, len(sigData))
	}
	t.Logf("RSA-PSS signature size: %d bytes", len(sigData))
}

// =============================================================================
// Message digest via pkcs11-tool --hash
// =============================================================================

// TestPKCS11Tool_HashDigest drives a message digest through pkcs11-tool's
// --hash mode and checks the result against crypto/sha256 computed on the
// same input, proving the module's C_Digest path matches the standard
// library rather than merely producing 32 plausible-looking bytes.
//
// C_Digest operates on the module and slot rather than on a key object, so
// this follows the same no-login setup as TestPKCS11Tool_ShowInfo and
// TestPKCS11Tool_SlotOperations rather than the authenticated setup the
// signing tests use.
func TestPKCS11Tool_HashDigest(t *testing.T) {
	requireTool(t)
	cfg := NewPKCS11ToolTestConfig(t)
	requireModule(t, cfg.ModulePath)

	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	testData := []byte("Known input for pkcs11-tool --hash")
	dataFile := writeTestDataFile(t, cfg.TempDir, "hash_input.bin", testData)
	digestFile := filepath.Join(cfg.TempDir, "hash_output.bin")

	output, _, err := runPKCS11ToolCommand(t, cfg,
		"--slot", cfg.SlotID,
		"--hash", "--mechanism", "SHA256",
		"--input-file", dataFile,
		"--output-file", digestFile,
	)
	if err != nil {
		t.Fatalf("pkcs11-tool --hash --mechanism SHA256 failed: %v, output: %s", err, output)
	}

	digest := readTestDataFile(t, digestFile)
	if len(digest) != sha256.Size {
		t.Fatalf("expected a %d-byte SHA-256 digest, got %d bytes", sha256.Size, len(digest))
	}

	want := sha256.Sum256(testData)
	if !bytes.Equal(digest, want[:]) {
		t.Errorf("pkcs11-tool digest %x does not match crypto/sha256 digest %x", digest, want)
	}
	t.Logf("pkcs11-tool --hash digest matches crypto/sha256: %x", digest)
}

// =============================================================================
// Ed25519 key generation via the OpenSSL PKCS#11 provider
// =============================================================================

// TestPKCS11ProviderKeygen_Ed25519InToken generates an Ed25519 key pair
// entirely inside the token through pkcs11-provider's OSSL_OP_KEYMGMT path,
// then proves the pair is usable: the public half is read back through the
// provider, the private half signs with it, and the signature is verified
// outside the module against the exported public key.
//
// This mirrors TestPKCS11ProviderKeygen_GeneratesUsableKeyInToken in
// openssl_rand_keygen_test.go for RSA and EC, but Ed25519 has no algorithm
// parameters -- no curve choice, no digest -- so "-algorithm ED25519" alone
// is sufficient for genpkey; there is no equivalent of the RSA/EC -pkeyopt
// flags that test passes. Key creation goes through genpkeyInToken, whose
// exit status is deliberately ignored: genpkey always tries to serialise the
// new private key to -out, and pkcs11-provider refuses that for any token
// key (see TestPKCS11ProviderKeygen_RefusesToExportTokenPrivateKey), so the
// command exits 1 even on a fully successful generation. What matters is the
// key pair it left on the token, which the assertions below exercise.
func TestPKCS11ProviderKeygen_Ed25519InToken(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

	SetupInitializedModule(t)

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	label := uniqueLabel("prov-genpkey-ed25519")

	genpkeyInToken(t, cfg, cfgPath, label, "-algorithm", "ED25519")

	// Read the public half back through the provider. This is the same
	// C_GetAttributeValue path TestPKCS11ProviderKeygen_
	// GeneratesUsableKeyInToken exercises for RSA/EC generated objects.
	pubPEM := filepath.Join(cfg.TempDir, label+".pub.pem")
	_, stderr, trace, err := runOpenSSLWithProviderTrace(t, cfgPath, cfg.PIN,
		"pkey", "-provider", "pkcs11", "-propquery", "?provider=pkcs11",
		"-in", "pkcs11:object="+label+";type=public", "-pubin", "-pubout",
		"-out", pubPEM,
	)
	require.NoErrorf(t, err,
		"the public half of the Ed25519 key the provider just generated could "+
			"not be read back through the provider. stderr: %s\nprovider trace:\n%s",
		stderr, trace)

	// Sign with the private half, which stays in the token. Ed25519 signs the
	// message itself rather than a digest, so -rawin is required and there is
	// no -digest option to pass -- the same convention
	// TestOpenSSLProvider_Ed25519SignVerify uses in openssl_provider_test.go.
	dataFile := filepath.Join(cfg.TempDir, label+".dat")
	sigFile := filepath.Join(cfg.TempDir, label+".sig")
	require.NoError(t, os.WriteFile(dataFile, []byte("provider-generated ed25519 payload"), 0o600))

	_, stderr, trace, err = runOpenSSLWithProviderTrace(t, cfgPath, cfg.PIN,
		"pkeyutl", "-provider", "pkcs11", "-propquery", "?provider=pkcs11",
		"-sign", "-inkey", "pkcs11:object="+label+";type=private",
		"-rawin",
		"-in", dataFile, "-out", sigFile,
	)
	require.NoErrorf(t, err,
		"the private half of the generated Ed25519 key could not sign. "+
			"stderr: %s\nprovider trace:\n%s", stderr, trace)

	sig, readErr := os.ReadFile(sigFile)
	require.NoError(t, readErr)
	require.Lenf(t, sig, ed25519.SignatureSize,
		"an Ed25519 signature from the generated key is the wrong size, so the "+
			"provider signed with something other than the key it generated")

	// Verify entirely outside the module, against the exported public key.
	// Without this the test would pass for a generated pair whose public and
	// private halves have no mathematical relationship to each other.
	_, stderr, err = runOpenSSLDefault(t,
		"pkeyutl", "-verify", "-pubin", "-inkey", pubPEM,
		"-rawin", "-in", dataFile, "-sigfile", sigFile,
	)
	require.NoErrorf(t, err,
		"a signature made with the generated Ed25519 private key did not verify "+
			"against the generated public key, so C_GenerateKeyPair returned two "+
			"halves that do not belong to each other: %s", stderr)
}
