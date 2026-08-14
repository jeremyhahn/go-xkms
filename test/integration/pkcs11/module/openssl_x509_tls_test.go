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

// Package module covers the two X.509 roles a module-resident key actually
// takes in a deployment, neither of which openssl_provider_test.go reaches.
//
// The existing X.509 coverage is self-signed only, where the signing key and the
// certified key are the same object. A module that signed over the wrong
// TBSCertificate bytes could still produce a certificate that verifies against
// itself, so that shape cannot distinguish a correct signature from a
// coincidence. Issuing to a separate, externally generated subject key removes
// the coincidence.
//
// The TLS coverage there is RSA only. TLS 1.3 negotiates a signature scheme per
// key type, so an ECDSA server key exercises ecdsa_secp256r1_sha256 rather than
// rsa_pss_rsae_sha256 — a different mechanism on the module and a different
// signature encoding on the wire.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
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

// TestOpenSSLProvider_SignsCertificateAsCA uses a module-resident key to sign
// somebody else's CSR, then builds the chain outside the module.
//
// The CA key is RSA deliberately. An EC CA key issued through pkcs11-provider
// produces a certificate carrying explicit curve parameters, which OpenSSL
// refuses to build a chain from; TestOpenSSLProvider_ExportsExplicitECParameters
// pins that as the provider's behaviour rather than this module's, and will fail
// when the provider is fixed so this restriction can be lifted.
func TestOpenSSLProvider_SignsCertificateAsCA(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-ca-key"
	generateTestKey(t, p11, "rsa:2048", label, "78")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	caCert := filepath.Join(cfg.TempDir, "ca.crt")
	leafKey := filepath.Join(cfg.TempDir, "leaf.key")
	leafCSR := filepath.Join(cfg.TempDir, "leaf.csr")
	leafCert := filepath.Join(cfg.TempDir, "leaf.crt")

	// `x509 -req` reads X.509v3 extensions out of the active OpenSSL config, and
	// the provider config has no section for them; an empty file is how one says
	// "add no extensions" without OpenSSL falling back to the config's
	// [default] section and failing on openssl_conf.
	emptyExt := filepath.Join(cfg.TempDir, "noext.cnf")
	require.NoError(t, os.WriteFile(emptyExt, nil, 0o600))

	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"req", "-new", "-x509", "-days", "1", "-key", providerKeyURI(label),
		"-subj", "/CN=xkms-pkcs11-issuing-ca", "-sha256",
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign",
		"-out", caCert,
	)
	require.NoErrorf(t, err, "issuing the CA certificate failed: %s", stderr)

	// The subject key is generated outside the module and stays there, so the
	// certified key and the signing key are provably different objects.
	_, stderr, err = runOpenSSLDefault(t,
		"req", "-new", "-newkey", "rsa:2048", "-nodes",
		"-keyout", leafKey, "-subj", "/CN=xkms-pkcs11-leaf", "-out", leafCSR,
	)
	require.NoErrorf(t, err, "generating the subject CSR failed: %s", stderr)

	_, stderr, err = runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"x509", "-req", "-in", leafCSR,
		"-CA", caCert, "-CAkey", providerKeyURI(label),
		"-set_serial", "4097", "-days", "1", "-sha256",
		"-extfile", emptyExt, "-out", leafCert,
	)
	require.NoErrorf(t, err,
		"signing a CSR with the module-resident CA key failed: %s", stderr)

	pemBytes, err := os.ReadFile(leafCert)
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "the issued certificate must be valid PEM")
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "the issued certificate must parse as X.509")
	assert.Equal(t, "xkms-pkcs11-leaf", leaf.Subject.CommonName)
	assert.Equal(t, "xkms-pkcs11-issuing-ca", leaf.Issuer.CommonName)

	// The chain is built and checked outside the module. This is what proves the
	// module signed the leaf's own TBSCertificate with the CA key, rather than
	// producing a well-formed certificate over the wrong bytes.
	_, stderr, err = runOpenSSLDefault(t, "verify", "-CAfile", caCert, leafCert)
	require.NoErrorf(t, err,
		"the certificate the module issued does not chain to its own CA "+
			"certificate: %s", stderr)

	// Go's verifier is a second, independent implementation, and unlike
	// `openssl verify` it checks the signature against a parsed public key this
	// test controls rather than one loaded through OpenSSL's own machinery.
	caBytes, err := os.ReadFile(caCert)
	require.NoError(t, err)
	caBlock, _ := pem.Decode(caBytes)
	require.NotNil(t, caBlock)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)
	require.NoError(t, leaf.CheckSignatureFrom(ca),
		"the leaf's signature does not verify against the CA certificate's "+
			"public key, so the module signed the wrong bytes or with the wrong key")
}

// TestOpenSSL_TLSHandshake_ECDSAServerKeyInModule terminates TLS with an ECDSA
// key that never leaves the module.
//
// The negotiated signature scheme is asserted, not merely that a handshake
// completed: a server that quietly fell back to a different key would still
// connect, and the point of the test is that this key did the signing.
func TestOpenSSL_TLSHandshake_ECDSAServerKeyInModule(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "tls-server-ec"
	generateTestKey(t, p11, "EC:prime256v1", label, "79")

	certFile := filepath.Join(cfg.TempDir, "tls-server-ec.crt")
	keyURI := providerKeyURI(label)
	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)

	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"req", "-new", "-x509", "-days", "1", "-key", keyURI,
		"-out", certFile, "-subj", "/CN=xkms-pkcs11-ec-tls", "-sha256",
	)
	require.NoErrorf(t, err, "issuing the ECDSA server certificate failed: %s", stderr)

	const port = "44331"
	server := exec.Command(opensslBinary(), "s_server",
		"-key", keyURI, "-cert", certFile,
		"-accept", port, "-naccept", "1", "-www",
	)
	server.Env = append(os.Environ(), "OPENSSL_CONF="+cfgPath)
	require.NoError(t, server.Start(), "starting s_server with the ECDSA token key failed")
	defer func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	}()

	out := tlsHandshakeTranscript(t, "127.0.0.1:"+port, "xkms-pkcs11-ec-tls")

	assert.Contains(t, out, "Protocol version",
		"s_client must report a completed handshake; output: %s", out)
	// The two OpenSSL builds in the image name the scheme differently: 3.x
	// prints the family ("ECDSA"), 4.x prints the IANA name
	// ("ecdsa_secp256r1_sha256"). Either proves an ECDSA key signed the
	// CertificateVerify; an RSA scheme would mean the module's key was not used.
	assert.Truef(t,
		strings.Contains(out, "ecdsa_secp256r1_sha256") ||
			strings.Contains(out, "Signature type: ECDSA"),
		"the handshake was not signed by the P-256 token key: no ECDSA signature "+
			"scheme appears in the transcript. Output: %s", out)
}

// TestOpenSSLProvider_ECPublicKeyExport checks what pkcs11-provider makes of an
// EC public key the module publishes, and pins the consequence.
//
// Two properties are asserted unconditionally because they are the module's:
// the token publishes CKA_EC_PARAMS as a namedCurve OID, and the key the
// provider hands OpenSSL is the same public point the token holds.
//
// The third is the provider's, and it differs between the two OpenSSL builds in
// this image. The provider compiled against 4.0.1 re-encodes the key with
// explicit curve parameters, which OpenSSL then refuses to build a chain from
// (X509_V_ERR_EC_KEY_EXPLICIT_PARAMS) — that is why
// TestOpenSSLProvider_SignsCertificateAsCA uses an RSA key. The provider
// compiled against 3.0.20 emits a namedCurve and chains fine. SoftHSM driven
// through the same 4.0.1 provider produces the identical explicit encoding for
// its own P-256 key, which is what rules this module out as the cause.
//
// Rather than pin one build's behaviour, this asserts the LINK between the two:
// a namedCurve export must chain, and an explicit-parameter export must fail
// for exactly that reason. Either way the assertion has teeth, and the day the
// 4.0.1 provider starts emitting namedCurve the EC key becomes usable for the CA
// role and this test says so instead of silently passing.
func TestOpenSSLProvider_ECPublicKeyExport(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-ec-params"
	generateTestKey(t, p11, "EC:prime256v1", label, "80")

	// What the token itself published. pkcs11-tool builds the
	// SubjectPublicKeyInfo straight from CKA_EC_PARAMS and CKA_EC_POINT, so this
	// is the module's own encoding, and Go's x509 accepts it only for a
	// namedCurve: ParsePKIXPublicKey rejects explicit parameters outright.
	der := filepath.Join(cfg.TempDir, label+".pub.der")
	_, stderr, err := runPKCS11ToolCommand(t, p11,
		"--login", "--pin", p11.PIN, "--slot", p11.SlotID,
		"--read-object", "--type", "pubkey", "--label", label,
		"--output-file", der,
	)
	require.NoErrorf(t, err, "reading the public key off the token failed: %s", stderr)

	raw, err := os.ReadFile(der)
	require.NoError(t, err)
	tokenSPKI := subjectPublicKeyInfo(t, raw)

	tokenPub, err := x509.ParsePKIXPublicKey(tokenSPKI)
	require.NoError(t, err,
		"the module's CKA_EC_PARAMS must be a namedCurve OID; Go's x509 rejects "+
			"explicit parameters, so a failure here IS a module defect")
	tokenEC, ok := tokenPub.(*ecdsa.PublicKey)
	require.Truef(t, ok, "expected an ECDSA public key from the token, got %T", tokenPub)

	// What the provider hands OpenSSL.
	providerPEM := exportProviderPublicKeyPEM(t, cfg, label)
	pemBytes, err := os.ReadFile(providerPEM)
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "the provider's export must be valid PEM")

	// The point is compared through the raw BIT STRING, which is identical under
	// either parameter encoding, so this holds on both OpenSSL builds. A
	// provider that returned some other key would fail here whatever it did with
	// the parameters.
	require.Equal(t,
		elliptic.Marshal(tokenEC.Curve, tokenEC.X, tokenEC.Y),
		subjectPublicKeyBits(t, block.Bytes),
		"the public point pkcs11-provider exported is not the point the token "+
			"published for the same object")

	_, namedCurveErr := x509.ParsePKIXPublicKey(block.Bytes)
	usesNamedCurve := namedCurveErr == nil

	// The consequence: whether an EC certificate issued through the provider can
	// be used to build a chain follows directly from the encoding above.
	chainErr := ecChainVerificationError(t, cfg, p11, label)

	if usesNamedCurve {
		require.NoErrorf(t, chainErr,
			"the provider exported a namedCurve, so a certificate issued with "+
				"this EC key must chain; it did not: %v", chainErr)
		t.Log("this pkcs11-provider build exports namedCurve; EC keys can take " +
			"the CA role in TestOpenSSLProvider_SignsCertificateAsCA")
		return
	}

	require.Errorf(t, chainErr,
		"the provider exported explicit curve parameters, which OpenSSL refuses "+
			"to build a chain from, yet the chain verified; the link this test "+
			"asserts no longer holds and it needs revisiting")
	assert.Contains(t, chainErr.Error(), "explicit",
		"an explicit-parameter EC certificate must fail chain building for that "+
			"reason specifically; a different failure means something else is wrong")
}

// ecChainVerificationError issues a CA certificate and a leaf with the EC token
// key and returns the error from verifying the chain, or nil if it verifies.
//
// Failure to ISSUE is fatal: that would be a signing problem rather than the
// encoding question this is asked to answer.
func ecChainVerificationError(t *testing.T, cfg *OpenSSLTestConfig, p11 *PKCS11ToolTestConfig, label string) error {
	t.Helper()

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	caCert := filepath.Join(cfg.TempDir, "ec-ca.crt")
	leafKey := filepath.Join(cfg.TempDir, "ec-leaf.key")
	leafCSR := filepath.Join(cfg.TempDir, "ec-leaf.csr")
	leafCert := filepath.Join(cfg.TempDir, "ec-leaf.crt")
	emptyExt := filepath.Join(cfg.TempDir, "ec-noext.cnf")
	require.NoError(t, os.WriteFile(emptyExt, nil, 0o600))

	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"req", "-new", "-x509", "-days", "1", "-key", providerKeyURI(label),
		"-subj", "/CN=xkms-pkcs11-ec-ca", "-sha256",
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign",
		"-out", caCert,
	)
	require.NoErrorf(t, err, "issuing the EC CA certificate failed: %s", stderr)

	_, stderr, err = runOpenSSLDefault(t,
		"req", "-new", "-newkey", "rsa:2048", "-nodes",
		"-keyout", leafKey, "-subj", "/CN=xkms-pkcs11-ec-leaf", "-out", leafCSR,
	)
	require.NoErrorf(t, err, "generating the subject CSR failed: %s", stderr)

	_, stderr, err = runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"x509", "-req", "-in", leafCSR,
		"-CA", caCert, "-CAkey", providerKeyURI(label),
		"-set_serial", "4098", "-days", "1", "-sha256",
		"-extfile", emptyExt, "-out", leafCert,
	)
	require.NoErrorf(t, err, "signing the CSR with the EC token key failed: %s", stderr)

	stdout, stderr, err := runOpenSSLDefault(t, "verify", "-CAfile", caCert, leafCert)
	if err == nil {
		return nil
	}
	return fmt.Errorf("openssl verify refused the chain: %s%s", stdout, stderr)
}

// subjectPublicKeyBits returns the subjectPublicKey BIT STRING of a DER
// SubjectPublicKeyInfo.
//
// It deliberately does not interpret the algorithm parameters, so it works
// whether an EC key carries a namedCurve OID or a full explicit specification —
// which is what lets the point be compared across encodings.
func subjectPublicKeyBits(t *testing.T, spki []byte) []byte {
	t.Helper()

	var parsed struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(spki, &parsed)
	require.NoError(t, err, "the export is not a well-formed SubjectPublicKeyInfo")
	require.Empty(t, rest, "the SubjectPublicKeyInfo has trailing data")

	return parsed.PublicKey.RightAlign()
}

// tlsHandshakeTranscript dials addr with s_client and returns the transcript.
//
// The handshake itself is retried rather than the port being probed first: with
// -naccept 1 the server serves exactly one connection, and a probe would consume
// it, leaving the real client with a refused connection. The client runs with
// only the default provider active so it cannot reach the module, which is what
// makes it an independent peer rather than a second view of the same token.
func tlsHandshakeTranscript(t *testing.T, addr, serverName string) string {
	t.Helper()
	return tlsHandshakeTranscriptDiag(t, addr, serverName, func() string { return "" })
}

// tlsHandshakeTranscriptDiag is tlsHandshakeTranscript with a hook that supplies
// the server's own output for the failure message.
//
// A TLS server holding its key in a PKCS#11 module can fail in two ways that
// look identical from the client: it never bound the port because it could not
// load the key, or it bound and then failed to sign. Only the server's output
// distinguishes them, and "connection refused" on its own sends the reader
// looking in the wrong place.
func tlsHandshakeTranscriptDiag(t *testing.T, addr, serverName string, serverOutput func() string) string {
	t.Helper()

	var out []byte
	var err error

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		client := exec.Command(opensslBinary(), "s_client",
			"-connect", addr, "-servername", serverName, "-brief",
		)
		client.Stdin = strings.NewReader("")
		client.Env = append(os.Environ(), "OPENSSL_CONF="+defaultOnlyConfig(t))

		out, err = client.CombinedOutput()
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoErrorf(t, err,
		"the TLS handshake failed: %s\nthe server said:\n%s", string(out), serverOutput())

	return string(out)
}
