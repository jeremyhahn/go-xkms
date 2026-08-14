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

// Package module drives the go-xkms PKCS#11 shared library through OpenSSL to
// prove the module behaves correctly for a real, unmodified Cryptoki consumer.
//
// The suite in openssl_ssh_test.go exercises OpenSSL's legacy libp11 ENGINE.
// This file covers what that one does not:
//
//   - pkcs11-provider, the interface that replaced ENGINEs in OpenSSL 3. It
//     issues a different C_* call sequence than libp11 — notably it probes
//     attributes and mechanism lists far more aggressively, and it uses the
//     two-call output buffer convention throughout — so it exercises paths the
//     engine never reaches.
//   - The signature schemes and padding modes the engine suite skips: RSA-PSS,
//     raw CKM_RSA_PKCS over a caller-supplied DigestInfo, OAEP with a
//     non-default hash, and Ed25519 — the ENGINE has no mechanism to carry an
//     EdDSA key or its raw-message signing convention at all.
//   - A complete TLS handshake with the module holding the server key, which is
//     the operation an actual deployment performs.
//   - The same operations against each compiled-in backend, so a backend that
//     regresses is caught rather than being masked by the software default.
//
// Every test here fails rather than skips when its tooling is missing: a silent
// skip is how OpenSSL interop coverage disappears without anyone noticing.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
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

// providerModuleCandidates lists where the devcontainer image installs
// pkcs11-provider, most recent OpenSSL first.
//
// The image carries two OpenSSLs: 4.0.1 built from source under its own prefix,
// and Debian's 3.x. Each has its own copy of the provider, and they are not
// interchangeable — a provider compiled against 3.x headers will not load into
// a 4.x libcrypto, and vice versa. The one to use is therefore the one
// belonging to whichever openssl is on PATH.
var providerModuleCandidates = []string{
	"/usr/local/openssl-4.0.1/lib/ossl-modules/pkcs11.so",
	"/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",
	"/usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11.so",
}

// opensslModulesDir asks the openssl on PATH where it loads providers from,
// which is the authoritative answer for the build actually running.
func opensslModulesDir(t *testing.T) string {
	t.Helper()

	out, err := exec.Command(opensslBinary(), "version", "-m").Output()
	if err != nil {
		return ""
	}
	// The output is: MODULESDIR: "/path/to/ossl-modules"
	_, quoted, found := strings.Cut(string(out), "\"")
	if !found {
		return ""
	}
	dir, _, found := strings.Cut(quoted, "\"")
	if !found {
		return ""
	}
	return dir
}

// opensslBinary returns the openssl command the provider lanes drive.
//
// The default is the image's default openssl, which is 4.0.1: the provider is
// the only way to drive a PKCS#11 module from OpenSSL 4, so these tests must
// keep exercising it.
func opensslBinary() string {
	return opensslBinaryOr("openssl")
}

// opensslBinaryOr returns the openssl command selected by OPENSSL_BIN, falling
// back to the caller's default.
//
// OPENSSL_BIN selects a specific build, which is what lets the same suite run
// against both OpenSSLs in the image without duplicating any test. The lanes
// differ only in which build they fall back to, so the environment variable is
// read in exactly one place.
func opensslBinaryOr(fallback string) string {
	if bin := os.Getenv("OPENSSL_BIN"); bin != "" {
		return bin
	}
	return fallback
}

// resolveProviderModule returns the pkcs11-provider shared object matching the
// openssl under test.
func resolveProviderModule(t *testing.T) string {
	t.Helper()

	if override := os.Getenv("PKCS11_PROVIDER_MODULE"); override != "" {
		return override
	}

	// Prefer the provider living beside the running openssl: that pairing is
	// the only one guaranteed to be ABI-compatible.
	if dir := opensslModulesDir(t); dir != "" {
		candidate := filepath.Join(dir, "pkcs11.so")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	for _, candidate := range providerModuleCandidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// requireOpenSSLPKCS11Provider asserts pkcs11-provider is installed for the
// openssl under test.
//
// It fails rather than skips: the devcontainer builds it explicitly, so its
// absence means the image drifted and the provider coverage silently vanished.
// That matters more since OpenSSL 4.0 removed ENGINE support outright, leaving
// the provider as the only way to drive a PKCS#11 module from OpenSSL at all.
func requireOpenSSLPKCS11Provider(t *testing.T) {
	t.Helper()
	if resolveProviderModule(t) == "" {
		t.Fatalf("pkcs11-provider not found for %s (searched its MODULESDIR and %v); "+
			"the devcontainer image must build one against this OpenSSL",
			opensslBinary(), providerModuleCandidates)
	}
}

// providerConfig writes an OpenSSL configuration that loads pkcs11-provider
// against the module under test, and returns its path.
//
// pkcs11-provider is configured through openssl.cnf rather than the command
// line, so every provider-driven test needs one of these.
func providerConfig(t *testing.T, modulePath, pin string) string {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "openssl-pkcs11.cnf")
	// pkcs11-module-token-pin lets the provider log in without prompting, which
	// is what keeps the suite non-interactive; the default provider stays
	// active so verification and key parsing still work.
	cfg := fmt.Sprintf(`openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = %s
pkcs11-module-path = %s
pkcs11-module-token-pin = %s
# OpenSSL 4.0 runs OPENSSL_cleanup() from a global destructor rather than
# atexit(), so it can execute after a PKCS#11 module's own atexit teardown and
# crash on the way out -- after the operation has already succeeded and its
# output has been written. no-deinit is pkcs11-provider's documented workaround
# (provider-pkcs11(7)) and is harmless on OpenSSL 3.
pkcs11-module-quirks = no-deinit
activate = 1
`, resolveProviderModule(t), modulePath, pin)

	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))
	return cfgPath
}

// defaultOnlyConfig writes an OpenSSL configuration activating only the default
// provider, and returns its path.
//
// Out-of-module verification must run without the PKCS#11 provider, so that a
// signature is checked against exported public key material rather than being
// handed back to the token that produced it. Reaching that state by pointing
// OPENSSL_CONF at the ENGINE config, or by clearing it, both misfire on OpenSSL
// 4.0: engines were removed outright, so an engine config is invalid and every
// verification fails with "unsupported ... Algorithm (dgst : 0)" before it ever
// looks at the signature. A test asserting a verification must FAIL then passes
// for entirely the wrong reason.
func defaultOnlyConfig(t *testing.T) string {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "openssl-default.cnf")
	const cfg = `openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))
	return cfgPath
}

// runOpenSSLDefault runs openssl with only the default provider active.
//
// This is the "outside the module" half of every round trip in this file: the
// token cannot participate, so a successful verification proves the signature
// is genuinely correct rather than merely echoed back by whatever produced it.
func runOpenSSLDefault(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	cmd := exec.Command(opensslBinary(), args...)
	cmd.Env = append(os.Environ(), "OPENSSL_CONF="+defaultOnlyConfig(t))

	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()

	if err != nil {
		t.Logf("openssl (default provider only): openssl %s", strings.Join(args, " "))
		t.Logf("stderr: %s", errBuf.String())
	}
	return out.String(), errBuf.String(), err
}

// runOpenSSLWithProvider runs openssl with pkcs11-provider active.
func runOpenSSLWithProvider(t *testing.T, cfgPath, pin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	cmd := exec.Command(opensslBinary(), args...)
	cmd.Env = append(os.Environ(),
		"OPENSSL_CONF="+cfgPath,
		// pkcs11-provider reads the PIN from here rather than prompting, which
		// keeps the tests non-interactive.
		"PKCS11_PROVIDER_DEBUG=file:/dev/null",
		"PKCS11_PIN="+pin,
	)

	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return out.String(), errBuf.String(), err
}

// generateTestKey creates a key in the module via pkcs11-tool and returns its
// label. Key creation goes through pkcs11-tool rather than OpenSSL so that a
// failure in key generation is distinguishable from a failure in the OpenSSL
// path under test.
func generateTestKey(t *testing.T, cfg *PKCS11ToolTestConfig, keyType, label, id string) {
	t.Helper()

	_, stderr, err := runPKCS11ToolCommand(t, cfg,
		"--login", "--pin", cfg.PIN,
		"--slot", cfg.SlotID,
		"--keypairgen", "--key-type", keyType,
		"--label", label, "--id", id,
	)
	require.NoErrorf(t, err, "generating %s key %q failed: %s", keyType, label, stderr)
}

// pkcs11URI builds a PKCS#11 URI (RFC 7512) for an object in the module.
func pkcs11URI(label, pin string) string {
	return fmt.Sprintf("pkcs11:object=%s;type=private;pin-value=%s", label, pin)
}

// =============================================================================
// pkcs11-provider: the OpenSSL 3 interface
// =============================================================================

// TestOpenSSLProvider_Loads verifies OpenSSL can load pkcs11-provider against
// the module and enumerate it.
//
// This is the smoke test for every other provider test: if the provider cannot
// load the module, the failures below would all look like operation bugs.
func TestOpenSSLProvider_Loads(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)

	stdout, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN, "list", "-providers")
	require.NoErrorf(t, err, "openssl list -providers failed: %s", stderr)

	assert.Contains(t, stdout, "pkcs11",
		"the pkcs11 provider must appear in the active provider list")
}

// TestOpenSSLProvider_ListsModuleMechanisms verifies the provider can query the
// module's mechanism list and surfaces the signature algorithms it advertises.
//
// This exercises C_GetMechanismList and C_GetMechanismInfo through a consumer
// that actually acts on the flags, rather than a test that only reads them.
func TestOpenSSLProvider_ListsModuleMechanisms(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)

	stdout, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"list", "-signature-algorithms", "-provider", "pkcs11")
	require.NoErrorf(t, err, "listing signature algorithms failed: %s", stderr)

	assert.NotEmpty(t, strings.TrimSpace(stdout),
		"the module must advertise at least one signature algorithm to the provider")
}

// providerKeyURI builds the URI form pkcs11-provider accepts. The provider
// takes the PIN from the config file, so it is absent here.
func providerKeyURI(label string) string {
	return "pkcs11:object=" + label + ";type=private"
}

// exportPublicKeyPEM reads a public key out of the module and converts it to
// PEM, so verification can run outside the module. keyCmd is "rsa" or "ec".
func exportPublicKeyPEM(t *testing.T, cfg *OpenSSLTestConfig, p11 *PKCS11ToolTestConfig, label, keyCmd string) string {
	t.Helper()

	der := filepath.Join(cfg.TempDir, label+".pub.der")
	pemPath := filepath.Join(cfg.TempDir, label+".pub.pem")

	_, stderr, err := runPKCS11ToolCommand(t, p11,
		"--login", "--pin", p11.PIN, "--slot", p11.SlotID,
		"--read-object", "--type", "pubkey", "--label", label,
		"--output-file", der,
	)
	require.NoErrorf(t, err, "exporting the public key for %q failed: %s", label, stderr)

	_, stderr, err = runOpenSSLDefault(t,
		keyCmd, "-pubin", "-inform", "DER", "-in", der,
		"-outform", "PEM", "-out", pemPath,
	)
	require.NoErrorf(t, err, "converting the public key for %q failed: %s", label, stderr)
	return pemPath
}

// TestOpenSSLProvider_RSASignVerify drives a full RSA sign-and-verify through
// the provider.
//
// The verify half runs against the public key outside the module, so a
// signature the module produces must be verifiable by plain OpenSSL — which is
// the property that matters and the one a module-internal test cannot prove.
func TestOpenSSLProvider_RSASignVerify(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-rsa-sign"
	generateTestKey(t, p11, "rsa:2048", label, "60")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	dataFile := filepath.Join(cfg.TempDir, "prov-rsa.dat")
	sigFile := filepath.Join(cfg.TempDir, "prov-rsa.sig")
	require.NoError(t, os.WriteFile(dataFile, []byte("provider rsa payload"), 0o600))

	pubPEM := exportPublicKeyPEM(t, cfg, p11, label, "rsa")

	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkeyutl", "-sign", "-inkey", providerKeyURI(label),
		"-rawin", "-digest", "sha256",
		"-in", dataFile, "-out", sigFile,
	)
	require.NoErrorf(t, err, "provider RSA sign failed: %s", stderr)

	sig, err := os.ReadFile(sigFile)
	require.NoError(t, err)
	assert.Len(t, sig, 256, "an RSA-2048 signature is 256 bytes")

	// The signature must verify outside the module. This is what catches a
	// module that hashes the caller's digest a second time: signing still
	// "succeeds" and returns a correctly sized signature that verifies against
	// nothing.
	_, stderr, err = runOpenSSLDefault(t,
		"dgst", "-sha256", "-verify", pubPEM, "-signature", sigFile, dataFile,
	)
	require.NoErrorf(t, err,
		"a signature produced through the provider did not verify against its "+
			"own public key: %s", stderr)
}

// TestOpenSSLProvider_ECDSASignVerify drives ECDSA through the provider.
//
// ECDSA is where signature-encoding defects surface: PKCS#11 carries a raw
// r||s pair while OpenSSL expects ASN.1 DER, so a module that forwards the
// backend's encoding unchanged produces something no verifier accepts.
func TestOpenSSLProvider_ECDSASignVerify(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-ec-sign"
	generateTestKey(t, p11, "EC:prime256v1", label, "64")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	dataFile := filepath.Join(cfg.TempDir, "prov-ec.dat")
	sigFile := filepath.Join(cfg.TempDir, "prov-ec.sig")
	require.NoError(t, os.WriteFile(dataFile, []byte("provider ecdsa payload"), 0o600))

	pubPEM := exportPublicKeyPEM(t, cfg, p11, label, "ec")

	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkeyutl", "-sign", "-inkey", providerKeyURI(label),
		"-rawin", "-digest", "sha256",
		"-in", dataFile, "-out", sigFile,
	)
	require.NoErrorf(t, err, "provider ECDSA sign failed: %s", stderr)

	_, stderr, err = runOpenSSLDefault(t,
		"dgst", "-sha256", "-verify", pubPEM, "-signature", sigFile, dataFile,
	)
	require.NoErrorf(t, err,
		"an ECDSA signature from the provider did not verify, which points at a "+
			"signature-encoding defect (raw r||s vs ASN.1 DER): %s", stderr)
}

// TestOpenSSLProvider_RSAPSS_IsActuallyPSS proves a PSS request produces a PSS
// signature rather than being silently downgraded to PKCS#1 v1.5.
//
// Both assertions are load-bearing. A v1.5 signature is still a well-formed
// signature of the right length, so without the negative case this test passes
// even when the module ignores the requested padding entirely — which is
// exactly the defect it was written for.
func TestOpenSSLProvider_RSAPSS_IsActuallyPSS(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-pss"
	generateTestKey(t, p11, "rsa:2048", label, "65")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	dataFile := filepath.Join(cfg.TempDir, "prov-pss.dat")
	sigFile := filepath.Join(cfg.TempDir, "prov-pss.sig")
	require.NoError(t, os.WriteFile(dataFile, []byte("provider pss payload"), 0o600))

	pubPEM := exportPublicKeyPEM(t, cfg, p11, label, "rsa")

	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkeyutl", "-sign", "-inkey", providerKeyURI(label),
		"-rawin", "-digest", "sha256",
		"-pkeyopt", "rsa_padding_mode:pss",
		"-pkeyopt", "rsa_pss_saltlen:digest",
		"-in", dataFile, "-out", sigFile,
	)
	require.NoErrorf(t, err, "provider PSS sign failed: %s", stderr)

	// Both directions go through pkeyutl with the padding named explicitly.
	// `dgst -verify` without -sigopt fails on OpenSSL 4.0 with an algorithm
	// fetch error rather than a verification failure, which would make the
	// negative case below pass without ever checking the signature.
	verifyWithPadding := func(t *testing.T, padding string) (string, error) {
		t.Helper()
		args := []string{
			"pkeyutl", "-verify", "-pubin", "-inkey", pubPEM,
			"-rawin", "-digest", "sha256",
			"-pkeyopt", "rsa_padding_mode:" + padding,
		}
		if padding == "pss" {
			args = append(args, "-pkeyopt", "rsa_pss_saltlen:digest")
		}
		args = append(args, "-in", dataFile, "-sigfile", sigFile)

		stdout, stderr, err := runOpenSSLDefault(t, args...)
		return stdout + stderr, err
	}

	t.Run("verifies_as_pss", func(t *testing.T) {
		out, err := verifyWithPadding(t, "pss")
		require.NoErrorf(t, err, "a PSS signature must verify as PSS: %s", out)
		assert.Contains(t, out, "Signature Verified Successfully")
	})

	t.Run("does_not_verify_as_pkcs1v15", func(t *testing.T) {
		// The load-bearing negative. Without it this file would pass even if
		// the module silently downgraded the request to PKCS#1 v1.5, because a
		// v1.5 signature is still a perfectly valid signature -- just not the
		// one that was asked for. That downgrade was a real defect once.
		out, err := verifyWithPadding(t, "pkcs1")
		require.Errorf(t, err,
			"a PSS signature must not verify under PKCS#1 v1.5; if it does, the "+
				"module ignored the requested padding and signed with v1.5. Output: %s", out)
		assert.NotContains(t, out, "Signature Verified Successfully",
			"the v1.5 verification must not report success")
	})
}

// TestOpenSSLProvider_EnumeratesObjects verifies the provider can list the
// module's objects through OSSL_STORE, which is how an application discovers
// keys by URI rather than by handle.
func TestOpenSSLProvider_EnumeratesObjects(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-store"
	generateTestKey(t, p11, "rsa:2048", label, "66")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)

	stdout, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"storeutl", "-text", "pkcs11:")
	require.NoErrorf(t, err, "enumerating the module through OSSL_STORE failed: %s", stderr)

	assert.Contains(t, stdout, label,
		"the store listing must include the key that was just generated")
}

// TestOpenSSLProvider_CSRAndCertificate issues a CSR and a self-signed
// certificate with the key held in the module.
//
// This is the X.509 signing path rather than the raw digest path, and it is
// what a deployment uses to obtain a certificate for a module-resident key.
func TestOpenSSLProvider_CSRAndCertificate(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-x509"
	generateTestKey(t, p11, "rsa:2048", label, "67")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	csrFile := filepath.Join(cfg.TempDir, "prov.csr")
	crtFile := filepath.Join(cfg.TempDir, "prov.crt")

	t.Run("csr_self_signature_verifies", func(t *testing.T) {
		_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
			"req", "-new", "-key", providerKeyURI(label),
			"-subj", "/CN=xkms-provider-csr", "-sha256", "-out", csrFile,
		)
		require.NoErrorf(t, err, "generating the CSR failed: %s", stderr)

		_, stderr, err = runOpenSSLDefault(t, "req", "-in", csrFile, "-verify", "-noout")
		require.NoErrorf(t, err,
			"the CSR's self-signature did not verify: %s", stderr)
	})

	t.Run("certificate_verifies_against_itself", func(t *testing.T) {
		_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
			"req", "-new", "-x509", "-days", "1", "-key", providerKeyURI(label),
			"-subj", "/CN=xkms-provider-cert", "-sha256", "-out", crtFile,
		)
		require.NoErrorf(t, err, "issuing the certificate failed: %s", stderr)

		pemBytes, err := os.ReadFile(crtFile)
		require.NoError(t, err)
		block, _ := pem.Decode(pemBytes)
		require.NotNil(t, block, "the issued certificate must be valid PEM")
		_, err = x509.ParseCertificate(block.Bytes)
		require.NoError(t, err, "the issued certificate must parse as X.509")

		_, stderr, err = runOpenSSLDefault(t, "verify", "-CAfile", crtFile, crtFile)
		require.NoErrorf(t, err,
			"the certificate does not verify against its own embedded key: %s", stderr)
	})
}

// =============================================================================
// Signature schemes and padding the engine suite does not cover
// =============================================================================

// TestOpenSSLProvider_RSAOAEP_RoundTrip encrypts with the public key outside
// the module and decrypts inside it, using OAEP with SHA-256.
//
// The padding has to survive the whole path: the service layer defaults to
// PKCS#1 v1.5, so an OAEP ciphertext decrypted without options fails with what
// looks like corruption rather than a padding mismatch.
func TestOpenSSLProvider_RSAOAEP_RoundTrip(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-oaep"
	generateTestKey(t, p11, "rsa:2048", label, "68")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	plainFile := filepath.Join(cfg.TempDir, "oaep.plain")
	cipherFile := filepath.Join(cfg.TempDir, "oaep.enc")
	outFile := filepath.Join(cfg.TempDir, "oaep.out")
	pubPEM := filepath.Join(cfg.TempDir, "oaep.pub.pem")

	plaintext := []byte("oaep round trip")
	require.NoError(t, os.WriteFile(plainFile, plaintext, 0o600))

	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkey", "-in", "pkcs11:object="+label+";type=public",
		"-pubin", "-pubout", "-out", pubPEM,
	)
	require.NoErrorf(t, err, "exporting the public key failed: %s", stderr)

	_, stderr, err = runOpenSSLDefault(t,
		"pkeyutl", "-encrypt", "-pubin", "-inkey", pubPEM,
		"-pkeyopt", "rsa_padding_mode:oaep",
		"-pkeyopt", "rsa_oaep_md:sha256",
		"-in", plainFile, "-out", cipherFile,
	)
	require.NoErrorf(t, err, "OAEP encrypt failed: %s", stderr)

	_, stderr, err = runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkeyutl", "-decrypt", "-inkey", providerKeyURI(label),
		"-pkeyopt", "rsa_padding_mode:oaep",
		"-pkeyopt", "rsa_oaep_md:sha256",
		"-in", cipherFile, "-out", outFile,
	)
	require.NoErrorf(t, err, "OAEP decrypt inside the module failed: %s", stderr)

	got, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got,
		"the OAEP round trip must recover the plaintext exactly")
}

// TestOpenSSLProvider_Ed25519SignVerify drives Ed25519 sign, public-key
// export, and verification through the provider.
//
// Ed25519 lives here rather than in the ENGINE suite in openssl_ssh_test.go
// because the deprecated libp11 ENGINE has no mechanism to carry an EdDSA key
// or its raw-message signing convention — the same reason RSA-PSS and OAEP
// moved to the provider path. The verify half runs entirely outside the
// module, with the pkcs11 provider not loaded, against a public key the
// provider exported: that is what proves the signature is genuinely correct
// rather than merely 64 bytes of well-formed noise.
func TestOpenSSLProvider_Ed25519SignVerify(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	// SetupInitializedModule reinitializes the token (C_InitToken), which
	// erases any objects a prior run left on it. pkcs11-provider enumerates
	// every object in the slot when it opens it and abandons the whole slot
	// if even one object fails to convert, so a token holding only the key
	// this test creates is what keeps the test reproducible across runs.
	SetupInitializedModule(t)

	const label = "prov-ed25519"
	generateTestKey(t, p11, "EC:edwards25519", label, "69")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	dataFile := filepath.Join(cfg.TempDir, "prov-ed25519.dat")
	sigFile := filepath.Join(cfg.TempDir, "prov-ed25519.sig")
	pubPEM := filepath.Join(cfg.TempDir, "prov-ed25519.pub.pem")
	require.NoError(t, os.WriteFile(dataFile, []byte("provider ed25519 payload"), 0o600))

	// Sign. Ed25519 signs the message itself rather than a digest, so -rawin
	// is required and there is no -digest option to pass.
	//
	// pkcs11-provider is known to segfault on exit on this OpenSSL 3.0.20
	// build after producing correct output (SoftHSM shows the same symptom,
	// so this is a provider bug, not one in this module), so a non-zero exit
	// here must not fail the test by itself; the signature file's presence
	// and length are what prove the sign actually happened.
	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkeyutl", "-sign", "-inkey", providerKeyURI(label),
		"-rawin", "-in", dataFile, "-out", sigFile,
	)
	if err != nil {
		t.Logf("openssl exited non-zero after the Ed25519 sign (tolerated, see "+
			"the provider exit-crash note above the call): %v; stderr: %s", err, stderr)
	}

	sig, err := os.ReadFile(sigFile)
	require.NoError(t, err, "the Ed25519 signature must have been written despite the exit status")
	assert.Len(t, sig, ed25519.SignatureSize, "an Ed25519 signature is exactly 64 bytes")

	// Export the public key through the provider. Same exit-crash caveat as
	// the sign step above: check the artifact, not the process exit status.
	_, stderr, err = runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkey", "-in", "pkcs11:object="+label+";type=public",
		"-pubin", "-pubout", "-out", pubPEM,
	)
	if err != nil {
		t.Logf("openssl exited non-zero after exporting the Ed25519 public key "+
			"(tolerated, see the provider exit-crash note above): %v; stderr: %s", err, stderr)
	}

	pemBytes, err := os.ReadFile(pubPEM)
	require.NoError(t, err, "the exported public key must have been written despite the exit status")
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "the exported public key must be valid PEM")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err, "the exported public key must parse as a PKIX SubjectPublicKeyInfo")
	edPub, ok := pub.(ed25519.PublicKey)
	require.Truef(t, ok, "the exported key must be an Ed25519 public key, got %T", pub)
	assert.Len(t, edPub, ed25519.PublicKeySize)

	// Verify outside the module entirely, with only the default provider
	// active. This is the assertion that matters: a signature the module
	// produces must be verifiable by plain OpenSSL against the key it
	// exported, which a module-internal length check cannot prove.
	stdout, stderr, err := runOpenSSLDefault(t,
		"pkeyutl", "-verify", "-pubin", "-inkey", pubPEM,
		"-rawin", "-in", dataFile, "-sigfile", sigFile,
	)
	require.NoErrorf(t, err, "the Ed25519 signature did not verify against the "+
		"module's own exported public key: %s", stderr)
	assert.Contains(t, stdout, "Signature Verified Successfully",
		"openssl must report a successful verification; got: %s", stdout)
}

// =============================================================================
// A real TLS handshake with the module holding the server key
// =============================================================================

// TestOpenSSL_TLSHandshake_ServerKeyInModule stands up an OpenSSL TLS server
// whose private key lives in the module and completes a handshake against it.
//
// This is the operation a deployment actually performs, and it exercises the
// module under OpenSSL's own call sequence and timing rather than a test
// harness's. A module that passes every unit test but cannot terminate TLS is
// not usable, and only an end-to-end handshake demonstrates the difference.
func TestOpenSSL_TLSHandshake_ServerKeyInModule(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "tls-server-key"
	generateTestKey(t, p11, "rsa:2048", label, "63")

	certFile := filepath.Join(cfg.TempDir, "tls-server.crt")
	keyURI := providerKeyURI(label)

	// Issue a self-signed certificate whose key stays in the module.
	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"req", "-new", "-x509", "-days", "1", "-key", keyURI,
		"-out", certFile, "-subj", "/CN=xkms-pkcs11-tls-test", "-sha256",
	)
	require.NoErrorf(t, err, "issuing the server certificate failed: %s", stderr)

	certPEM, err := os.ReadFile(certFile)
	require.NoError(t, err)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "the issued certificate must be valid PEM")
	_, err = x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "the issued certificate must parse as X.509")

	// Start s_server with the module-resident key.
	const addr = "127.0.0.1:44330"
	server := exec.Command(opensslBinary(), "s_server",
		"-key", keyURI, "-cert", certFile,
		"-accept", "44330", "-naccept", "1", "-www",
	)
	server.Env = append(os.Environ(), "OPENSSL_CONF="+cfgPath)
	require.NoError(t, server.Start(), "starting s_server failed")
	defer func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	}()

	// Retry the handshake itself rather than probing the port first: with
	// -naccept 1 the server serves exactly one connection, and a probe would
	// consume it, leaving the real client with a refused connection.
	var out []byte
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		client := exec.Command(opensslBinary(), "s_client",
			"-connect", addr, "-servername", "xkms-pkcs11-tls-test", "-brief",
		)
		client.Stdin = strings.NewReader("")
		out, err = client.CombinedOutput()
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoErrorf(t, err, "the TLS handshake failed: %s", string(out))

	// s_client -brief prints the negotiated protocol and cipher on success.
	assert.Contains(t, string(out), "Protocol version",
		"s_client must report a completed handshake; output: %s", string(out))
}
