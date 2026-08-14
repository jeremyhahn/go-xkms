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

// Package module covers the two OpenSSL operations that create material on the
// token rather than consuming an existing key: randomness and key generation.
//
// They are together because both were unverified through OpenSSL and for
// opposite reasons. `openssl rand` cannot reach the module at all — the reason
// is pkcs11-provider's, and asserting it is the only way to stop a test that
// merely runs `openssl rand -provider pkcs11` from looking like coverage.
// `openssl genpkey` can reach the module, and its exit status says nothing
// useful about it: the command asks for the private key to be serialised, which
// no PKCS#11 provider will do for a token key. What genpkey leaves behind is the
// thing worth asserting, so the tests here assert that instead.
//
// The key-generation tests are named TestPKCS11ProviderKeygen_* rather than
// TestOpenSSLProvider_* so that the provider's key CREATION path has a Make
// target of its own (integration-test-pkcs11-provider-keygen). It is the only
// path in the suite where the module derives an object's attributes itself
// rather than copying them out of a caller's template, which is a distinct
// enough risk to be separately attributable.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOpenSSLProvider_HasNoRandomGenerator records that `openssl rand` cannot
// reach the module's C_GenerateRandom.
//
// pkcs11-provider 1.2.0 registers no OSSL_OP_RAND implementation, so
// `openssl rand -provider pkcs11` succeeds while quietly using libcrypto's own
// DRBG — naming the provider on the command line changes nothing. A test that
// ran that command and checked the bytes looked random would be pure theatre.
//
// The module's C_GenerateRandom is genuinely exercised, directly, by
// TestPKCS11Tool_RandomGeneration. When pkcs11-provider grows a RAND this test
// fails, and `openssl rand` coverage should be written at that point.
func TestOpenSSLProvider_HasNoRandomGenerator(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)

	stdout, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"list", "-random-generators", "-provider", "pkcs11")
	require.NoErrorf(t, err, "listing random generators failed: %s", stderr)

	for _, line := range strings.Split(stdout, "\n") {
		require.NotContainsf(t, line, "@ pkcs11",
			"pkcs11-provider now offers a random generator (%q), so `openssl rand` "+
				"can finally reach the module's C_GenerateRandom: replace this "+
				"assertion with a real test of it",
			strings.TrimSpace(line))
	}
}

// runOpenSSLWithProviderTrace runs openssl with pkcs11-provider active and its
// debug trace captured, and returns the trace alongside the command's output.
//
// The trace is how a failed genpkey is told apart from a failed genpkey: the
// command exits 1 whether the provider gave up on the new key's attributes or
// merely declined to serialise a key that must not leave the token, and it
// prints the same message either way. Only the trace says which C_* call the
// provider reached before it stopped.
func runOpenSSLWithProviderTrace(t *testing.T, cfgPath, pin string, args ...string) (stdout, stderr, trace string, err error) {
	t.Helper()

	tracePath := filepath.Join(t.TempDir(), "pkcs11-provider.trace")

	cmd := exec.Command(opensslBinary(), args...)
	cmd.Env = append(os.Environ(),
		"OPENSSL_CONF="+cfgPath,
		"PKCS11_PROVIDER_DEBUG=file:"+tracePath,
		"PKCS11_PIN="+pin,
	)

	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()

	// A missing trace is not a test failure on its own: the caller asserts on
	// the contents, and an empty string fails those assertions with a message
	// about what was expected rather than about file I/O.
	traceBytes, readErr := os.ReadFile(tracePath)
	if readErr != nil {
		t.Logf("pkcs11-provider wrote no debug trace to %s: %v", tracePath, readErr)
	}

	return out.String(), errBuf.String(), string(traceBytes), err
}

// genpkeyInToken generates a key pair inside the token through the provider and
// returns the label it was created under.
//
// The command's exit status is deliberately dropped. `openssl genpkey`
// serialises the new private key to -out, and pkcs11-provider refuses that for
// any token key — correctly, since the key is CKA_SENSITIVE and never leaves the
// module — so the command always exits 1. The refusal itself is pinned by
// TestPKCS11ProviderKeygen_RefusesToExportTokenPrivateKey; what the callers here
// want is the key pair it left on the token.
func genpkeyInToken(t *testing.T, cfg *OpenSSLTestConfig, cfgPath, label string, keyOpts ...string) {
	t.Helper()

	args := append([]string{
		"genpkey", "-provider", "pkcs11", "-propquery", "?provider=pkcs11",
		"-pkeyopt", "pkcs11_uri:pkcs11:object=" + label,
		"-out", filepath.Join(cfg.TempDir, label+".refused"),
	}, keyOpts...)

	_, stderr, _, err := runOpenSSLWithProviderTrace(t, cfgPath, cfg.PIN, args...)
	if err != nil {
		t.Logf("genpkey for %q exited with %v (expected: the private key cannot be "+
			"serialised); stderr: %s", label, err, strings.TrimSpace(stderr))
	}
}

// TestPKCS11ProviderKeygen_GeneratesUsableKeyInToken generates a key pair inside
// the module through OpenSSL and then uses it, end to end.
//
// This is how an application provisions a key it never wants to see: `openssl
// genpkey` with the pkcs11 provider, which issues C_GenerateKeyPair. Every other
// key in this suite is created by pkcs11-tool from a template the tool wrote, so
// the provider's own creation path is the only one where the MODULE decides what
// an object's CKA_CLASS and CKA_KEY_TYPE are. Those two are CK_ULONGs, eight
// bytes wide on every platform this module targets, and a token that stores them
// four bytes wide hands an application that allocated sizeof(CK_ULONG) four bytes
// of value and four bytes of its own uninitialized buffer — which is how
// pkcs11-provider came to decode a generated key's class as 0xFFFFFFFF00000002
// and abandon the object.
//
// Both halves of the pair are therefore read back through the provider after
// generation, which is exactly the C_GetAttributeValue path that width defect
// breaks: the public half is exported to PEM, the private half signs, and the
// signature is verified outside the module against that PEM. A module that
// narrows either attribute again fails here, at the read-back, rather than
// leaving a key on the token that only looks fine in an object listing.
func TestPKCS11ProviderKeygen_GeneratesUsableKeyInToken(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

	SetupInitializedModule(t)

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)

	for _, tc := range []struct {
		name    string
		keyOpts []string
		sigLen  int
	}{
		{
			name:    "rsa2048",
			keyOpts: []string{"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"},
			// An RSA-2048 signature is exactly the modulus size.
			sigLen: 256,
		},
		{
			name:    "ecdsa_p256",
			keyOpts: []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"},
			// ECDSA signatures are DER and vary by a byte or two, so length is
			// not asserted for them.
			sigLen: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh label per run. The token's file storage outlives a single
			// `make` invocation, and two objects sharing a label would make the
			// PKCS#11 URI below ambiguous — the provider could then sign with the
			// private key of one pair and be verified against the public key of
			// another, which fails for a reason that has nothing to do with the
			// module.
			label := uniqueLabel("prov-genpkey-" + tc.name)

			genpkeyInToken(t, cfg, cfgPath, label, tc.keyOpts...)

			// Read the public half back through the provider. This is the
			// assertion the four-byte CKA_CLASS defect fails: the provider finds
			// the object, reads its class into a CK_ULONG, and gives up on it.
			pubPEM := filepath.Join(cfg.TempDir, label+".pub.pem")
			_, stderr, trace, err := runOpenSSLWithProviderTrace(t, cfgPath, cfg.PIN,
				"pkey", "-provider", "pkcs11", "-propquery", "?provider=pkcs11",
				"-in", "pkcs11:object="+label+";type=public", "-pubin", "-pubout",
				"-out", pubPEM,
			)
			require.NoErrorf(t, err,
				"the public half of the key the provider just generated could not be "+
					"read back through the provider. The module derives CKA_CLASS and "+
					"CKA_KEY_TYPE itself for a generated object; both are CK_ULONGs and "+
					"must be stored at the native width. stderr: %s\nprovider trace:\n%s",
				stderr, trace)

			// Sign with the private half, which stays in the token.
			dataFile := filepath.Join(cfg.TempDir, label+".dat")
			sigFile := filepath.Join(cfg.TempDir, label+".sig")
			require.NoError(t, os.WriteFile(dataFile, []byte("provider-generated key payload"), 0o600))

			_, stderr, trace, err = runOpenSSLWithProviderTrace(t, cfgPath, cfg.PIN,
				"pkeyutl", "-provider", "pkcs11", "-propquery", "?provider=pkcs11",
				"-sign", "-inkey", "pkcs11:object="+label+";type=private",
				"-rawin", "-digest", "sha256",
				"-in", dataFile, "-out", sigFile,
			)
			require.NoErrorf(t, err,
				"the private half of the key the provider just generated could not "+
					"sign. stderr: %s\nprovider trace:\n%s", stderr, trace)

			if tc.sigLen > 0 {
				sig, readErr := os.ReadFile(sigFile)
				require.NoError(t, readErr)
				require.Lenf(t, sig, tc.sigLen,
					"a signature from the generated key is the wrong size, so the "+
						"provider signed with something other than the key it generated")
			}

			// Verify outside the module. Without this the test would pass for a
			// module that generated a public and a private object with no
			// mathematical relationship to each other: both halves would still
			// read back, and signing would still produce plausible bytes.
			_, stderr, err = runOpenSSLDefault(t,
				"dgst", "-sha256", "-verify", pubPEM, "-signature", sigFile, dataFile,
			)
			require.NoErrorf(t, err,
				"a signature made with the generated private key did not verify "+
					"against the generated public key, so C_GenerateKeyPair returned "+
					"two halves that do not belong to each other: %s", stderr)
		})
	}
}

// TestPKCS11ProviderKeygen_RefusesToExportTokenPrivateKey pins the reason
// `openssl genpkey` exits 1 against this module, so that the day it exits 0 —
// or fails for a different reason — someone finds out.
//
// genpkey always serialises the new private key to -out, and a PKCS#11 provider
// will not produce the private half of a token key: it is CKA_SENSITIVE and
// CKA_EXTRACTABLE is meaningless to a key whose material lives in the backend.
// pkcs11-provider is right to refuse, SoftHSM 2.6 under the identical provider
// build is refused identically, and no invocation of genpkey — with or without
// -out, with or without -outpubkey — exits 0 for any PKCS#11 module here. A test
// that asserted a zero exit would therefore be asserting something no module can
// satisfy.
//
// Asserting merely that it exits non-zero would be just as bad in the other
// direction: that was also true when the module stored a four-byte CKA_CLASS and
// the provider abandoned the key before it ever reached the export. The
// assertions below separate the two. The trace must show C_GenerateKeyPair was
// called AND that the provider then reached its export entry point, which it
// only does for an object it successfully built; the failure message must be
// OpenSSL's serialisation failure and not a key-generation failure; and no
// private key may appear in the output file.
func TestPKCS11ProviderKeygen_RefusesToExportTokenPrivateKey(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

	SetupInitializedModule(t)

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)

	label := uniqueLabel("prov-genpkey-export")
	outPath := filepath.Join(cfg.TempDir, label+".pem")

	stdout, stderr, trace, err := runOpenSSLWithProviderTrace(t, cfgPath, cfg.PIN,
		"genpkey", "-provider", "pkcs11", "-propquery", "?provider=pkcs11",
		"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
		"-pkeyopt", "pkcs11_uri:pkcs11:object="+label,
		"-out", outPath,
	)

	require.Errorf(t, err,
		"`openssl genpkey` now succeeds against the module, which means "+
			"pkcs11-provider serialised a token private key. Either the provider "+
			"changed policy — in which case assert the exported key instead — or "+
			"the module is handing out material that must never leave it. "+
			"stdout: %s stderr: %s", stdout, stderr)

	require.Containsf(t, trace, "GenerateKeyPair",
		"the provider never reached C_GenerateKeyPair, so genpkey failed before "+
			"the module was asked to create anything: this test's subject did not "+
			"run. Provider trace:\n%s", trace)

	// The provider only calls its export entry point for a key object it
	// successfully built out of the new handles, which is the step a four-byte
	// CKA_CLASS or CKA_KEY_TYPE prevents. Reaching it is the evidence that the
	// command failed at serialisation rather than at attribute decoding.
	require.Containsf(t, trace, "_export(",
		"the provider gave up before attempting to export the generated key, so "+
			"genpkey failed for a reason other than the export refusal this test "+
			"pins — most likely the module narrowed a CK_ULONG attribute again. "+
			"Provider trace:\n%s", trace)

	require.Containsf(t, stderr, "Error writing key(s)",
		"genpkey failed with something other than OpenSSL's serialisation error, "+
			"so the failure is no longer the export refusal: %s", stderr)

	require.NotContainsf(t, stderr, "Key Gen failed",
		"genpkey reported a key GENERATION failure, which is what the four-byte "+
			"CKA_CLASS defect produced. The command must get as far as trying to "+
			"write the key out: %s", stderr)

	// Nothing may have been written. A provider that refuses the export but
	// leaves a partial or plaintext key behind would still fail the exit-status
	// check above while doing exactly what must not happen.
	written, readErr := os.ReadFile(outPath)
	if readErr == nil {
		require.NotContainsf(t, string(written), "PRIVATE KEY",
			"a token private key was written to %s despite the export being "+
				"refused", outPath)
	}
}

// TestPKCS11ProviderKeygen_CreatesBothObjects proves C_GenerateKeyPair through
// the provider leaves a complete pair on the token.
//
// This is the token's view of what the previous tests observe through the
// provider, and it is worth having separately: it reads the objects with
// pkcs11-tool, which searches on a template it wrote itself and therefore still
// finds a key whose module-derived attributes the provider could not decode. If
// this test passes while the usability test fails, the fault is in what the
// module STORES for an object it derived; if this one fails too, generation
// itself has regressed, which is a different and larger problem.
func TestPKCS11ProviderKeygen_CreatesBothObjects(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	label := uniqueLabel("prov-genpkey-objects")

	genpkeyInToken(t, cfg, cfgPath, label,
		"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")

	listing, stderr, err := runPKCS11ToolCommand(t, p11,
		"--login", "--pin", p11.PIN, "--slot", p11.SlotID, "--list-objects")
	require.NoErrorf(t, err, "listing the token's objects failed: %s", stderr)

	require.Containsf(t, listing, label,
		"C_GenerateKeyPair through the provider left nothing on the token, so "+
			"generation itself has regressed rather than only the provider's "+
			"read-back of the new handles. Objects present:\n%s", listing)

	require.GreaterOrEqualf(t, strings.Count(listing, label), 2,
		"a key PAIR must leave both a public and a private object under %q; "+
			"only one was found. Objects present:\n%s", label, listing)
}
