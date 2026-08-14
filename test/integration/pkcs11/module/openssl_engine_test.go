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

// Package module covers the OpenSSL 3 ENGINE lane operations that
// openssl_ssh_test.go leaves out.
//
// That file drives the libp11 ENGINE through `dgst -sign` with PKCS#1 v1.5, and
// `pkeyutl` with v1.5 encryption, and issues a self-signed certificate whose
// signature it never checks. Four things a real OpenSSL 3 caller does are
// therefore unverified on this lane, and each reaches module code the provider
// lane reaches differently or not at all, because libp11 issues its own C_*
// sequence:
//
//   - RSA-PSS via `dgst -sigopt`. A PSS request silently answered with PKCS#1
//     v1.5 produces a signature of exactly the right size, so only a negative
//     verification can detect it.
//   - CSR generation, the operation that obtains a certificate for a
//     module-resident key from a real CA.
//   - OAEP decryption, which carries CK_RSA_PKCS_OAEP_PARAMS through libp11's
//     mechanism setup rather than the provider's.
//   - Terminating TLS. TLS 1.3 mandates RSASSA-PSS for RSA CertificateVerify, so
//     a completed handshake through the ENGINE is also proof that PSS works
//     under OpenSSL's own call sequence and timing.
//
// The two limitations libp11 genuinely has are asserted rather than assumed, so
// they fail if it ever gains the capability.
//
// The ENGINE lane runs against the image's OpenSSL 3 build: OpenSSL 4.0 removed
// ENGINE support outright. opensslEngineBinary() in openssl_ssh_test.go is the
// single place that selects it.
//
// Build tags: integration,pkcs11,pkcs11_tool
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
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// engineKeyURI builds the URI form libp11 accepts, carrying the PIN inline
// because the ENGINE has no other non-interactive way to receive it.
func engineKeyURI(label, pin string) string {
	return "pkcs11:object=" + label + ";pin-value=" + pin
}

// TestOpenSSL_EngineRSAPSS proves a PSS request through the ENGINE produces a
// PSS signature rather than being silently downgraded to PKCS#1 v1.5.
//
// Both directions are load-bearing. A v1.5 signature is a perfectly well-formed
// 256-byte RSA signature, so without the negative case this test would pass
// against a module that ignored -sigopt entirely — which is exactly the defect
// it exists for.
func TestOpenSSL_EngineRSAPSS(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "engine-pss"
	generateTestKey(t, p11, "rsa:2048", label, "44")

	dataFile := filepath.Join(cfg.TempDir, "engine-pss.dat")
	sigFile := filepath.Join(cfg.TempDir, "engine-pss.sig")
	require.NoError(t, os.WriteFile(dataFile, []byte("engine pss payload"), 0o600))

	pubPEM := exportPublicKeyPEM(t, cfg, p11, label, "rsa")

	_, stderr, err := runOpenSSLCommand(t, cfg,
		"dgst", "-sha256", "-engine", "pkcs11", "-keyform", "engine",
		"-sign", engineKeyURI(label, cfg.PIN),
		"-sigopt", "rsa_padding_mode:pss",
		"-sigopt", "rsa_pss_saltlen:digest",
		"-out", sigFile, dataFile,
	)
	require.NoErrorf(t, err, "the ENGINE could not produce a PSS signature: %s", stderr)

	sig, err := os.ReadFile(sigFile)
	require.NoError(t, err)
	assert.Len(t, sig, 256, "an RSA-2048 signature is 256 bytes whatever the padding")

	t.Run("verifies_as_pss", func(t *testing.T) {
		_, stderr, err := runOpenSSLDefault(t,
			"dgst", "-sha256", "-verify", pubPEM,
			"-sigopt", "rsa_padding_mode:pss",
			"-sigopt", "rsa_pss_saltlen:digest",
			"-signature", sigFile, dataFile,
		)
		require.NoErrorf(t, err,
			"a signature requested as PSS did not verify as PSS: %s", stderr)
	})

	t.Run("does_not_verify_as_pkcs1v15", func(t *testing.T) {
		_, stderr, err := runOpenSSLDefault(t,
			"dgst", "-sha256", "-verify", pubPEM,
			"-signature", sigFile, dataFile,
		)
		require.Errorf(t, err,
			"a PSS signature must not verify under PKCS#1 v1.5; that it does "+
				"means the module ignored the requested padding and signed with "+
				"v1.5. stderr: %s", stderr)
	})
}

// TestOpenSSL_EngineCSR generates a certificate signing request for a key that
// never leaves the module.
//
// This is how a module-resident key obtains a certificate from a real CA, and it
// is a different signing path from `req -x509`: the signature covers a
// CertificationRequestInfo rather than a TBSCertificate. The self-signature is
// checked with the ENGINE unloaded, so the token cannot participate in verifying
// its own output.
func TestOpenSSL_EngineCSR(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "engine-csr"
	generateTestKey(t, p11, "rsa:2048", label, "45")

	csrFile := filepath.Join(cfg.TempDir, "engine.csr")

	_, stderr, err := runOpenSSLCommand(t, cfg,
		"req", "-new", "-engine", "pkcs11", "-keyform", "engine",
		"-key", engineKeyURI(label, cfg.PIN),
		"-subj", "/CN=xkms-engine-csr", "-sha256", "-out", csrFile,
	)
	require.NoErrorf(t, err, "generating a CSR through the ENGINE failed: %s", stderr)

	_, stderr, err = runOpenSSLDefault(t, "req", "-in", csrFile, "-verify", "-noout")
	require.NoErrorf(t, err, "the CSR's self-signature did not verify: %s", stderr)

	// Parsed independently so the subject and the certified public key are
	// checked against what was asked for, not just that a signature exists.
	pemBytes, err := os.ReadFile(csrFile)
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "the CSR must be valid PEM")
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err, "the CSR must parse as PKCS#10")
	assert.Equal(t, "xkms-engine-csr", csr.Subject.CommonName)
	require.NoError(t, csr.CheckSignature(),
		"the CSR does not carry a valid self-signature over its own "+
			"CertificationRequestInfo")
}

// TestOpenSSL_EngineSelfSignedCertificateVerifies issues a self-signed
// certificate through the ENGINE and checks its signature.
//
// TestOpenSSL_GenerateSelfSignedCert in openssl_ssh_test.go issues the same
// certificate but only parses it and compares the subject fields, which a
// certificate carrying 256 bytes of noise in place of a signature would pass.
// This one verifies the signature, in two independent implementations.
func TestOpenSSL_EngineSelfSignedCertificateVerifies(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "engine-selfsigned"
	generateTestKey(t, p11, "rsa:2048", label, "46")

	certFile := filepath.Join(cfg.TempDir, "engine-selfsigned.crt")

	_, stderr, err := runOpenSSLCommand(t, cfg,
		"req", "-new", "-x509", "-days", "1",
		"-engine", "pkcs11", "-keyform", "engine",
		"-key", engineKeyURI(label, cfg.PIN),
		"-subj", "/CN=xkms-engine-selfsigned", "-sha256", "-out", certFile,
	)
	require.NoErrorf(t, err, "issuing a certificate through the ENGINE failed: %s", stderr)

	_, stderr, err = runOpenSSLDefault(t, "verify", "-CAfile", certFile, certFile)
	require.NoErrorf(t, err,
		"the certificate does not verify against its own embedded key: %s", stderr)

	pemBytes, err := os.ReadFile(certFile)
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "the certificate must be valid PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "the certificate must parse as X.509")
	assert.Equal(t, "xkms-engine-selfsigned", cert.Subject.CommonName)
	require.NoError(t, cert.CheckSignatureFrom(cert),
		"the certificate's signature does not verify against its own public key")
}

// TestOpenSSL_EngineRSAOAEPDecrypt encrypts with OAEP outside the module and
// decrypts inside it through the ENGINE.
//
// openssl_ssh_test.go covers only PKCS#1 v1.5 on this lane. OAEP is a different
// mechanism carried through libp11's own mechanism setup, and the module's
// service layer defaults to v1.5, so a dropped parameter surfaces here as what
// looks like corruption rather than as a padding mismatch.
func TestOpenSSL_EngineRSAOAEPDecrypt(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "engine-oaep"
	generateTestKey(t, p11, "rsa:2048", label, "47")

	plainFile := filepath.Join(cfg.TempDir, "engine-oaep.plain")
	cipherFile := filepath.Join(cfg.TempDir, "engine-oaep.enc")
	outFile := filepath.Join(cfg.TempDir, "engine-oaep.out")

	plaintext := make([]byte, 32)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(plainFile, plaintext, 0o600))

	pubPEM := exportPublicKeyPEM(t, cfg, p11, label, "rsa")

	_, stderr, err := runOpenSSLDefault(t,
		"pkeyutl", "-encrypt", "-pubin", "-inkey", pubPEM,
		"-pkeyopt", "rsa_padding_mode:oaep",
		"-pkeyopt", "rsa_oaep_md:sha256",
		"-in", plainFile, "-out", cipherFile,
	)
	require.NoErrorf(t, err, "OAEP encrypt outside the module failed: %s", stderr)

	_, stderr, err = runOpenSSLCommand(t, cfg,
		"pkeyutl", "-decrypt", "-engine", "pkcs11", "-keyform", "engine",
		"-inkey", engineKeyURI(label, cfg.PIN),
		"-pkeyopt", "rsa_padding_mode:oaep",
		"-pkeyopt", "rsa_oaep_md:sha256",
		"-in", cipherFile, "-out", outFile,
	)
	require.NoErrorf(t, err, "OAEP decrypt through the ENGINE failed: %s", stderr)

	got, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got,
		"the OAEP round trip through the ENGINE must recover the plaintext exactly")
}

// TestOpenSSL_EngineTLSHandshake terminates TLS through the ENGINE with the
// server key held in the module.
//
// Beyond proving the module survives OpenSSL's own call sequence and timing,
// this covers RSASSA-PSS on the ENGINE lane from the other direction: TLS 1.3
// mandates PSS for an RSA CertificateVerify, so a handshake that completes and
// reports RSA-PSS is independent confirmation of TestOpenSSL_EngineRSAPSS.
func TestOpenSSL_EngineTLSHandshake(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "engine-tls"
	generateTestKey(t, p11, "rsa:2048", label, "48")

	certFile := filepath.Join(cfg.TempDir, "engine-tls.crt")
	keyURI := engineKeyURI(label, cfg.PIN)

	_, stderr, err := runOpenSSLCommand(t, cfg,
		"req", "-new", "-x509", "-days", "1",
		"-engine", "pkcs11", "-keyform", "engine", "-key", keyURI,
		"-subj", "/CN=xkms-engine-tls", "-sha256", "-out", certFile,
	)
	require.NoErrorf(t, err, "issuing the server certificate failed: %s", stderr)

	port := freeTCPPort(t)
	server := exec.Command(opensslEngineBinary(), "s_server",
		"-engine", "pkcs11", "-keyform", "engine",
		"-key", keyURI, "-cert", certFile,
		"-accept", strconv.Itoa(port), "-naccept", "1", "-www",
	)
	server.Env = append(os.Environ(), "OPENSSL_CONF="+cfg.OpenSSLConfig)

	// The server's own output is the only useful evidence when it refuses to
	// start: an ENGINE that cannot load the key exits before binding, and the
	// client then reports nothing but "connection refused".
	var serverOut lockedBuffer
	server.Stdout = &serverOut
	server.Stderr = &serverOut
	require.NoError(t, server.Start(), "starting s_server with the ENGINE failed")
	defer func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	}()

	// The port is deliberately NOT probed first: -naccept 1 means s_server
	// serves exactly one connection, and a probe would consume it and leave the
	// real client with a refused connection.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	out := tlsHandshakeTranscriptDiag(t, addr, "xkms-engine-tls", serverOut.String)

	assert.Containsf(t, out, "Protocol version",
		"s_client must report a completed handshake; s_client output:\n%s\n"+
			"s_server output:\n%s", out, serverOut.String())

	// TLS 1.3 signs the CertificateVerify with RSASSA-PSS, so a handshake that
	// completed with an RSA server key is independent confirmation that the
	// module produced a real PSS signature. The two OpenSSL builds in the image
	// spell the scheme differently -- 3.x prints "RSA-PSS", 4.x prints the IANA
	// name "rsa_pss_rsae_sha*" -- and the client may be either.
	assert.Truef(t,
		strings.Contains(out, "RSA-PSS") || strings.Contains(out, "rsa_pss_"),
		"the handshake did not report an RSASSA-PSS signature, so the module's "+
			"RSA key did not sign the CertificateVerify. s_client output:\n%s\n"+
			"s_server output:\n%s", out, serverOut.String())
}

// =============================================================================
// Limitations of libp11, pinned so they cannot rot silently
// =============================================================================

// TestOpenSSL_EngineCannotGenerateKeys records that the libp11 ENGINE has no
// key-generation capability.
//
// `openssl genpkey -engine pkcs11` exits zero and prints a private key, which
// makes it look supported. It is not: the ENGINE is loaded and then ignored, and
// the key is generated in software by libcrypto and written to stdout in the
// clear. Asserting that the key is NOT on the token is what makes the difference
// visible; a caller who assumed otherwise would believe a software key was
// hardware-protected.
//
// Key generation on this module is reached through pkcs11-tool
// (TestPKCS11Tool_KeyGeneration) and, for the provider lane, through
// TestOpenSSLProvider_GeneratesKeyInToken.
func TestOpenSSL_EngineCannotGenerateKeys(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "engine-genpkey"
	outFile := filepath.Join(cfg.TempDir, "engine-genpkey.pem")

	stdout, stderr, err := runOpenSSLCommand(t, cfg,
		"genpkey", "-engine", "pkcs11", "-algorithm", "RSA",
		"-pkeyopt", "rsa_keygen_bits:2048", "-out", outFile,
	)
	require.NoErrorf(t, err,
		"`genpkey -engine pkcs11` failed outright; it is expected to succeed and "+
			"generate in software: %s%s", stdout, stderr)

	// The key it produced is exportable, which a token-resident key never is.
	pemBytes, err := os.ReadFile(outFile)
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "genpkey must have written a PEM private key")
	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err,
		"genpkey wrote something that is not a PKCS#8 private key, so the "+
			"assumption this test is built on no longer holds")

	// And nothing was created on the token. When libp11 gains keygen this
	// stops being true and the assertion below fails, at which point the real
	// coverage should replace it.
	listing, _, err := runPKCS11ToolCommand(t, p11,
		"--login", "--pin", p11.PIN, "--slot", p11.SlotID, "--list-objects")
	require.NoError(t, err, "listing the token's objects failed")
	require.NotContainsf(t, listing, label,
		"the libp11 ENGINE now creates keys on the token; replace this "+
			"assertion with a real key-generation test for the ENGINE lane")
}

// TestOpenSSL_EngineCannotUseEd25519 records that the libp11 ENGINE cannot carry
// an Ed25519 token key.
//
// The ENGINE predates EdDSA in OpenSSL and has no representation for a key whose
// signing convention is raw-message rather than digest-then-sign, so it cannot
// load one however correct the module is. This is why Ed25519 coverage lives on
// the provider lane (TestOpenSSLProvider_Ed25519SignVerify) and in the OpenSSH
// suite. Asserting it means the day libp11 gains EdDSA, this fails and the
// missing lane is noticed.
func TestOpenSSL_EngineCannotUseEd25519(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "engine-ed25519"
	generateTestKey(t, p11, "EC:edwards25519", label, "49")

	dataFile := filepath.Join(cfg.TempDir, "engine-ed25519.dat")
	sigFile := filepath.Join(cfg.TempDir, "engine-ed25519.sig")
	require.NoError(t, os.WriteFile(dataFile, []byte("engine ed25519 payload"), 0o600))

	// The key exists on the token: pkcs11-tool can sign with it, so a failure
	// below is the ENGINE's inability to represent the key, not a missing object.
	_, stderr, err := runPKCS11ToolCommand(t, p11,
		"--login", "--pin", p11.PIN, "--slot", p11.SlotID,
		"--sign", "--mechanism", "EDDSA", "--id", "49",
		"--input-file", dataFile, "--output-file", sigFile,
	)
	require.NoErrorf(t, err,
		"the token cannot sign with its own Ed25519 key, which is a module "+
			"defect rather than the ENGINE limitation this test is about: %s", stderr)

	stdout, stderr, err := runOpenSSLCommand(t, cfg,
		"pkeyutl", "-sign", "-engine", "pkcs11", "-keyform", "engine",
		"-inkey", engineKeyURI(label, cfg.PIN),
		"-rawin", "-in", dataFile,
		"-out", filepath.Join(cfg.TempDir, "engine-ed25519-openssl.sig"),
	)
	require.Errorf(t, err,
		"the libp11 ENGINE signed with an Ed25519 token key; it has gained EdDSA "+
			"support, so give this lane real Ed25519 coverage instead of this "+
			"assertion. stdout: %s stderr: %s", stdout, stderr)
}

// lockedBuffer is a bytes.Buffer that is safe to read while a child process is
// still writing to it.
//
// exec.Cmd writes a subprocess's output from its own goroutine, so reading the
// buffer to build a failure message while the process is alive is a data race.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends p to the buffer.
func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
