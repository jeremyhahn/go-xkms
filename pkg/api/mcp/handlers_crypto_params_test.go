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

package mcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file holds the tests that prove a crypto parameter sent over the MCP
// JSON-RPC surface ARRIVES at the signing/encrypting primitive, rather than
// merely that the call succeeded.
//
// That distinction is the whole point. This transport used to decode
// {key_id, backend, data, hash} and nothing else, then call signer.Sign with
// the bare crypto.Hash as its opts -- which is PKCS#1 v1.5 for an RSA key. A
// caller asking for RSASSA-PSS received a perfectly valid signature under the
// wrong scheme and a success response. Every assertion below is therefore
// paired with a negative: a test that only checks "it verified" cannot tell
// the two schemes apart, because both produce a valid signature.

// mcpCall invokes a handler with the given params marshaled as JSON-RPC.
func mcpCall(
	t *testing.T,
	handler func(context.Context, *JSONRPCRequest) (interface{}, error),
	method string,
	params interface{},
) (interface{}, error) {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	return handler(context.Background(), &JSONRPCRequest{
		JSONRPC: "2.0", Method: method, Params: raw, ID: 1,
	})
}

// generateRSAKey creates an RSA key in the software backend and returns its
// public half, parsed from the PEM the server reports.
func generateRSAKey(t *testing.T, server *Server, keyID string) *rsa.PublicKey {
	t.Helper()

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, Backend: "software", KeyType: "rsa", KeySize: 2048,
	})
	require.NoError(t, err)

	result, err := mcpCall(t, server.handleGetKey, "xkms.getKey", GetKeyParams{
		KeyID: keyID, Backend: "software",
	})
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(result.(GetKeyResult).PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	return rsaPub
}

// generateSymmetricKey creates an AES-256-GCM key in the software backend.
func generateSymmetricKey(t *testing.T, server *Server, keyID string) {
	t.Helper()
	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, Backend: "software", KeyType: "symmetric", Algorithm: "aes256-gcm",
	})
	require.NoError(t, err)
}

// signatureBytes extracts the raw signature from a SignResult.
func signatureBytes(t *testing.T, result interface{}) []byte {
	t.Helper()
	signResult, ok := result.(SignResult)
	require.True(t, ok)
	sig, ok := signResult.Signature.([]byte)
	require.True(t, ok, "signature must be raw bytes, got %T", signResult.Signature)
	require.NotEmpty(t, sig)
	return sig
}

// ============================================================================
// RSA-PSS
// ============================================================================

// TestHandler_Sign_PSSIsNotDowngradedToPKCS1v15 is the regression test for the
// silent downgrade. It asserts both halves: the signature verifies as PSS at
// the requested salt length, AND it does not verify as PKCS#1 v1.5.
//
// The negative is the load-bearing half. A PKCS#1 v1.5 signature over the same
// digest is still a valid signature, so a test that merely asserted success
// and a non-empty signature passed against the old behaviour.
func TestHandler_Sign_PSSIsNotDowngradedToPKCS1v15(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	pub := generateRSAKey(t, server, "mcp-pss-key")
	message := []byte("payload to sign under PSS")
	digest := sha256.Sum256(message)

	for _, saltLength := range []int{32, rsa.PSSSaltLengthAuto} {
		result, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
			KeyID:      "mcp-pss-key",
			Backend:    "software",
			Data:       message,
			Hash:       "SHA-256",
			Padding:    "pss",
			SaltLength: saltLength,
		})
		require.NoError(t, err)
		signature := signatureBytes(t, result)

		assert.NoError(t,
			rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature,
				&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: saltLength}),
			"signature must verify as RSASSA-PSS at the requested salt length %d", saltLength)

		assert.Error(t,
			rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature),
			"a PSS request must not be answered with a PKCS#1 v1.5 signature (salt length %d)", saltLength)
	}
}

// TestHandler_Sign_PSSSaltLengthArrives proves SaltLength is not merely
// accepted but used: a signature made at a 32-byte salt must fail verification
// when checked against a different fixed salt length.
func TestHandler_Sign_PSSSaltLengthArrives(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	pub := generateRSAKey(t, server, "mcp-pss-salt")
	message := []byte("salt length must survive the wire")
	digest := sha256.Sum256(message)

	result, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: "mcp-pss-salt", Backend: "software", Data: message,
		Hash: "SHA-256", Padding: "pss", SaltLength: 32,
	})
	require.NoError(t, err)
	signature := signatureBytes(t, result)

	require.NoError(t, rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}))

	assert.Error(t, rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 20}),
		"a signature made with a 32-byte salt must not verify at a 20-byte salt")
}

// TestHandler_Sign_DefaultPaddingRemainsPKCS1v15 pins the backward-compatible
// default: an absent padding field still means PKCS#1 v1.5, so existing
// clients are unaffected by the field's introduction.
func TestHandler_Sign_DefaultPaddingRemainsPKCS1v15(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	pub := generateRSAKey(t, server, "mcp-default-padding")
	message := []byte("no padding field at all")
	digest := sha256.Sum256(message)

	result, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: "mcp-default-padding", Backend: "software", Data: message, Hash: "SHA-256",
	})
	require.NoError(t, err)
	signature := signatureBytes(t, result)

	assert.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature))
	assert.Error(t, rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthAuto}))
}

// TestHandler_Sign_DataIsDigestNotHashedTwice proves DataIsDigest arrives: a
// caller-supplied digest must be signed as-is rather than hashed again.
func TestHandler_Sign_DataIsDigestNotHashedTwice(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	pub := generateRSAKey(t, server, "mcp-prehashed")
	message := []byte("pre-hashed input")
	digest := sha256.Sum256(message)

	result, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: "mcp-prehashed", Backend: "software", Data: digest[:],
		Hash: "SHA-256", Padding: "pss", SaltLength: 32, DataIsDigest: true,
	})
	require.NoError(t, err)
	signature := signatureBytes(t, result)

	assert.NoError(t, rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}),
		"the supplied digest must be signed directly")

	doubleHashed := sha256.Sum256(digest[:])
	assert.Error(t, rsa.VerifyPSS(pub, crypto.SHA256, doubleHashed[:], signature,
		&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}),
		"the digest must not be hashed a second time")
}

// TestHandler_Sign_PSSRejectedForNonRSAKey proves the padding request is
// refused rather than silently falling back to the key's native scheme.
func TestHandler_Sign_PSSRejectedForNonRSAKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "mcp-ecdsa-pss", Backend: "software", KeyType: "ecdsa", Curve: "P-256",
	})
	require.NoError(t, err)

	_, err = mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: "mcp-ecdsa-pss", Backend: "software", Data: []byte("data"),
		Hash: "SHA-256", Padding: "pss",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrInvalidKeyAlgorithm)
}

// TestHandler_Sign_UnknownPaddingRefused proves a misspelled padding scheme is
// an error rather than a silent fallback to the default.
func TestHandler_Sign_UnknownPaddingRefused(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateRSAKey(t, server, "mcp-bad-padding")

	_, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: "mcp-bad-padding", Backend: "software", Data: []byte("data"),
		Hash: "SHA-256", Padding: "pss1",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrInvalidSignatureScheme)
	assert.Contains(t, err.Error(), "pss1")
}

// TestHandler_Verify_PSSRoundTrip proves the verify handler honours the same
// parameters: a PSS signature produced independently must verify only when the
// request names PSS, and must be reported invalid when it does not.
func TestHandler_Verify_PSSRoundTrip(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateRSAKey(t, server, "mcp-pss-verify")
	message := []byte("verify me under PSS")

	signed, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: "mcp-pss-verify", Backend: "software", Data: message,
		Hash: "SHA-256", Padding: "pss", SaltLength: 32,
	})
	require.NoError(t, err)
	signature := signatureBytes(t, signed)

	verify := func(params VerifyParams) bool {
		result, vErr := mcpCall(t, server.handleVerify, "xkms.verify", params)
		require.NoError(t, vErr)
		return result.(VerifyResult).Valid
	}

	assert.True(t, verify(VerifyParams{
		KeyID: "mcp-pss-verify", Backend: "software", Data: message, Signature: signature,
		Hash: "SHA-256", Padding: "pss", SaltLength: 32,
	}), "a PSS signature must verify when the request names PSS")

	assert.False(t, verify(VerifyParams{
		KeyID: "mcp-pss-verify", Backend: "software", Data: message, Signature: signature,
		Hash: "SHA-256",
	}), "a PSS signature must not verify as PKCS#1 v1.5")
}

// twoBackendServer builds an MCP server over two INDEPENDENT stores, each
// with its own storage, registered under the "software" (default) and "tpm2"
// backend names and each holding a DIFFERENT RSA key under keyID.
//
// The shared createTestServer fixture registers two names for a single store,
// which cannot distinguish "signed with the named backend" from "signed with
// the default one". Both names here are served by the software implementation:
// what is under test is the routing, not the hardware.
//
// The keys are created directly against each backend rather than through
// xkms.generateKey, because that handler resolves the named backend only far
// enough to set KeyAttributes.StoreType and then generates in s.keystore --
// the same "named backend, default keystore" split this test exists to pin on
// the signing path. Building the fixture through it would make the test
// vacuous.
func twoBackendServer(t *testing.T, keyID string) (*Server, *rsa.PublicKey, *rsa.PublicKey) {
	t.Helper()
	xkms.Reset()
	t.Cleanup(cleanupXKMS)

	build := func(storeType types.StoreType) (xkms.Backend, *rsa.PublicKey) {
		be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
		require.NoError(t, err)
		ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
		require.NoError(t, err)

		key, err := ks.GenerateRSA(context.Background(), &types.KeyAttributes{
			CN:            keyID,
			StoreType:     storeType,
			KeyType:       types.KeyTypeSigning,
			RSAAttributes: &types.RSAAttributes{KeySize: types.RSAKeySize2048},
		})
		require.NoError(t, err)
		signer, ok := key.(crypto.Signer)
		require.True(t, ok)
		pub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok)
		return ks, pub
	}

	defaultKS, defaultPub := build(types.StoreSoftware)
	namedKS, namedPub := build(types.StoreTPM2)

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": defaultKS, "tpm2": namedKS},
		DefaultBackend: "software",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)

	server, err := NewServer(&Config{
		XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)

	require.NotEqual(t, defaultPub.N, namedPub.N, "the fixture must hold two distinct keys")
	return server, defaultPub, namedPub
}

// TestHandler_Sign_UsesNamedBackendNotDefault proves the request's backend is
// the one that signs.
//
// The handler used to resolve the key's attributes in params.Backend but then
// sign with s.keystore, the process default backend. Two backends each holding
// a DIFFERENT key under the same ID is exactly the case that exposes it: the
// caller got a signature from the default backend's key, and a success
// response either way.
//
// The oracle is the public key the signature verifies under. Both signatures
// are valid; only the key they belong to distinguishes right from wrong.
func TestHandler_Sign_UsesNamedBackendNotDefault(t *testing.T) {
	const keyID = "same-name-different-key"
	server, defaultPub, namedPub := twoBackendServer(t, keyID)

	message := []byte("route me by name")
	digest := sha256.Sum256(message)

	result, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: keyID, Backend: "tpm2", Data: message, Hash: "SHA-256",
	})
	require.NoError(t, err)
	signature := signatureBytes(t, result)

	assert.NoError(t, rsa.VerifyPKCS1v15(namedPub, crypto.SHA256, digest[:], signature),
		"the named backend's key must be the one that signed")
	assert.Error(t, rsa.VerifyPKCS1v15(defaultPub, crypto.SHA256, digest[:], signature),
		"the default backend's key must not be the one that signed")
}

// TestHandler_Verify_UsesNamedBackendNotDefault is the verify-side
// counterpart: a signature made by the named backend's key must verify only
// when the request names that backend.
func TestHandler_Verify_UsesNamedBackendNotDefault(t *testing.T) {
	const keyID = "same-name-different-key"
	server, _, _ := twoBackendServer(t, keyID)

	message := []byte("verify against the right key")
	signed, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: keyID, Backend: "tpm2", Data: message, Hash: "SHA-256",
	})
	require.NoError(t, err)
	signature := signatureBytes(t, signed)

	verify := func(backendName string) bool {
		result, vErr := mcpCall(t, server.handleVerify, "xkms.verify", VerifyParams{
			KeyID: keyID, Backend: backendName, Data: message,
			Signature: signature, Hash: "SHA-256",
		})
		require.NoError(t, vErr)
		return result.(VerifyResult).Valid
	}

	assert.True(t, verify("tpm2"))
	assert.False(t, verify("software"),
		"the default backend's key must not validate the named backend's signature")
}

// TestHandler_Sign_UnknownBackendRefused is the bad-input counterpart: a
// backend that does not exist must be refused rather than quietly served by
// the default one.
func TestHandler_Sign_UnknownBackendRefused(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateRSAKey(t, server, "mcp-unknown-backend")

	_, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: "mcp-unknown-backend", Backend: "nosuchbackend",
		Data: []byte("data"), Hash: "SHA-256",
	})
	require.Error(t, err)
}

// ============================================================================
// RSA-OAEP
// ============================================================================

// TestHandler_Decrypt_OAEPHashArrives proves the OAEP digest travels: a
// ciphertext built with SHA-384 decrypts only when the request names SHA-384.
//
// This handler used to hard-wire rsa.OAEPOptions{Hash: crypto.SHA256} for
// every asymmetric key, so no other digest could be used over this transport
// at all -- and PKCS#1 v1.5 ciphertexts were undecryptable.
func TestHandler_Decrypt_OAEPHashArrives(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	pub := generateRSAKey(t, server, "mcp-oaep-decrypt")
	plaintext := []byte("oaep secret")
	ciphertext, err := rsa.EncryptOAEP(sha512.New384(), rand.Reader, pub, plaintext, nil)
	require.NoError(t, err)

	result, err := mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-oaep-decrypt", Backend: "software", Ciphertext: ciphertext,
		Padding: "oaep", Hash: "SHA-384",
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.(DecryptResult).Plaintext)

	_, err = mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-oaep-decrypt", Backend: "software", Ciphertext: ciphertext,
		Padding: "oaep", Hash: "SHA-256",
	})
	assert.Error(t, err, "a SHA-384 OAEP ciphertext must not decrypt under SHA-256")

	// Decrypting an OAEP ciphertext as PKCS#1 v1.5 yields uniform bytes, and
	// v1.5 unpadding ACCEPTS uniform bytes whenever they happen to carry its
	// 00 02 ... 00 frame: measured at 1.4e-3 per attempt (432 of 300,000).
	// So "must error" was a one-in-700 flake (#474's CI run). What must hold
	// is that the padding is not interchangeable: a v1.5 decrypt either
	// fails or returns bytes that are not the plaintext.
	v15, err := mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-oaep-decrypt", Backend: "software", Ciphertext: ciphertext,
	})
	if err == nil {
		assert.NotEqual(t, plaintext, v15.(DecryptResult).Plaintext,
			"an OAEP ciphertext must not decrypt to its plaintext as PKCS#1 v1.5")
	}
}

// TestHandler_Decrypt_OAEPLabelArrives proves the OAEP label reaches the
// primitive: a ciphertext built with a label decrypts only when the same label
// is supplied.
func TestHandler_Decrypt_OAEPLabelArrives(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	pub := generateRSAKey(t, server, "mcp-oaep-label")
	label := []byte("tenant-42")
	plaintext := []byte("labelled secret")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, label)
	require.NoError(t, err)

	result, err := mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-oaep-label", Backend: "software", Ciphertext: ciphertext,
		Padding: "oaep", Hash: "SHA-256", Label: label,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.(DecryptResult).Plaintext)

	_, err = mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-oaep-label", Backend: "software", Ciphertext: ciphertext,
		Padding: "oaep", Hash: "SHA-256",
	})
	assert.Error(t, err, "a labelled OAEP ciphertext must not decrypt without the label")
}

// TestHandler_Decrypt_PKCS1v15Supported proves the padding default is honoured
// and that a PKCS#1 v1.5 ciphertext -- previously undecryptable over this
// transport -- now works.
func TestHandler_Decrypt_PKCS1v15Supported(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	pub := generateRSAKey(t, server, "mcp-v15-decrypt")
	plaintext := []byte("v15 secret")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext) //nolint:staticcheck // SA1019: covers the CKM_RSA_PKCS (PKCS#1 v1.5) request path
	require.NoError(t, err)

	result, err := mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-v15-decrypt", Backend: "software", Ciphertext: ciphertext,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.(DecryptResult).Plaintext)
}

// TestHandler_Decrypt_UnknownPaddingRefused proves a misspelled padding scheme
// is refused rather than silently treated as the default.
func TestHandler_Decrypt_UnknownPaddingRefused(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateRSAKey(t, server, "mcp-bad-decrypt-padding")

	_, err := mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-bad-decrypt-padding", Backend: "software",
		Ciphertext: []byte("blob"), Padding: "oeap",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oeap")
}

// TestHandler_AsymmetricEncrypt_HashArrives proves the OAEP digest selected on
// the encrypt side is the one used. The handler used to force SHA-256 and
// carried no hash field at all.
func TestHandler_AsymmetricEncrypt_HashArrives(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateRSAKey(t, server, "mcp-asym-hash")
	plaintext := []byte("choose my digest")

	encrypted, err := mcpCall(t, server.handleAsymmetricEncrypt, "xkms.asymmetricEncrypt",
		AsymmetricEncryptParams{
			KeyID: "mcp-asym-hash", Backend: "software", Plaintext: plaintext, Hash: "SHA-384",
		})
	require.NoError(t, err)
	ciphertext := encrypted.(AsymmetricEncryptResult).Ciphertext

	// The oracle runs through the decrypt handler, which is the only holder of
	// the private half: it must open under SHA-384 and refuse under SHA-256.
	result, err := mcpCall(t, server.handleAsymmetricDecrypt, "xkms.asymmetricDecrypt",
		AsymmetricDecryptParams{
			KeyID: "mcp-asym-hash", Backend: "software", Ciphertext: ciphertext,
			Padding: "oaep", Hash: "SHA-384",
		})
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.(AsymmetricDecryptResult).Plaintext)

	_, err = mcpCall(t, server.handleAsymmetricDecrypt, "xkms.asymmetricDecrypt",
		AsymmetricDecryptParams{
			KeyID: "mcp-asym-hash", Backend: "software", Ciphertext: ciphertext,
		})
	assert.Error(t, err, "a SHA-384 OAEP ciphertext must not open under the SHA-256 default")
}

// TestHandler_AsymmetricEncrypt_WeakHashRefused proves the weak-hash policy is
// enforced on this transport too: SHA-1 OAEP is refused rather than performed.
func TestHandler_AsymmetricEncrypt_WeakHashRefused(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateRSAKey(t, server, "mcp-asym-weak")

	_, err := mcpCall(t, server.handleAsymmetricEncrypt, "xkms.asymmetricEncrypt",
		AsymmetricEncryptParams{
			KeyID: "mcp-asym-weak", Backend: "software", Plaintext: []byte("data"), Hash: "SHA-1",
		})
	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrWeakOAEPHash)
}

// TestHandler_AsymmetricDecrypt_DefaultsToOAEPSHA256 pins the backward
// compatibility of this method's own default: it is the counterpart of
// xkms.asymmetricEncrypt, which only ever produces OAEP-SHA-256, so an
// unchanged caller that names neither still round-trips.
func TestHandler_AsymmetricDecrypt_DefaultsToOAEPSHA256(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateRSAKey(t, server, "mcp-asym-default")
	plaintext := []byte("default round trip")

	encrypted, err := mcpCall(t, server.handleAsymmetricEncrypt, "xkms.asymmetricEncrypt",
		AsymmetricEncryptParams{
			KeyID: "mcp-asym-default", Backend: "software", Plaintext: plaintext,
		})
	require.NoError(t, err)

	result, err := mcpCall(t, server.handleAsymmetricDecrypt, "xkms.asymmetricDecrypt",
		AsymmetricDecryptParams{
			KeyID: "mcp-asym-default", Backend: "software",
			Ciphertext: encrypted.(AsymmetricEncryptResult).Ciphertext,
		})
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.(AsymmetricDecryptResult).Plaintext)
}

// ============================================================================
// AEAD
// ============================================================================

// TestHandler_EncryptDecrypt_AADAuthenticated proves the additional
// authenticated data reaches the AEAD on both legs: the tag must fail to
// authenticate when the AAD is omitted or altered on decrypt.
//
// Succeeding at the round trip alone would prove nothing -- a handler that
// dropped AdditionalData on both sides would round-trip just as happily.
func TestHandler_EncryptDecrypt_AADAuthenticated(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateSymmetricKey(t, server, "mcp-aes-aad")
	aad := []byte("bound-context")
	plaintext := []byte("aead payload")

	encrypted, err := mcpCall(t, server.handleEncrypt, "xkms.encrypt", EncryptParams{
		KeyID: "mcp-aes-aad", Backend: "software", Plaintext: plaintext, AdditionalData: aad,
	})
	require.NoError(t, err)
	enc := encrypted.(EncryptResult)

	result, err := mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-aes-aad", Backend: "software",
		Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag, AdditionalData: aad,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.(DecryptResult).Plaintext)

	_, err = mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-aes-aad", Backend: "software",
		Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag,
	})
	assert.Error(t, err, "decryption must fail when the AAD the tag authenticates is omitted")

	_, err = mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-aes-aad", Backend: "software",
		Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag,
		AdditionalData: []byte("different-context"),
	})
	assert.Error(t, err, "decryption must fail when the AAD is altered")
}

// TestHandler_Encrypt_NonceArrives proves a caller-supplied AEAD nonce is used
// rather than discarded in favour of a fresh random one. The parameter was
// absent from this transport's request type entirely.
//
// A dropped nonce still produces a decryptable ciphertext, so the oracle is
// the nonce the backend reports back: it must be the one that was sent.
func TestHandler_Encrypt_NonceArrives(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateSymmetricKey(t, server, "mcp-aes-nonce")
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	encrypted, err := mcpCall(t, server.handleEncrypt, "xkms.encrypt", EncryptParams{
		KeyID: "mcp-aes-nonce", Backend: "software",
		Plaintext: []byte("pinned nonce"), Nonce: nonce,
	})
	require.NoError(t, err)
	assert.Equal(t, nonce, encrypted.(EncryptResult).Nonce,
		"the caller-supplied nonce must be the one used")
}

// TestHandler_Encrypt_BadNonceRefused proves a nonce of the wrong length is
// refused rather than silently replaced with a generated one -- which would
// produce a ciphertext the caller believes is bound to its own nonce.
func TestHandler_Encrypt_BadNonceRefused(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateSymmetricKey(t, server, "mcp-aes-bad-nonce")

	_, err := mcpCall(t, server.handleEncrypt, "xkms.encrypt", EncryptParams{
		KeyID: "mcp-aes-bad-nonce", Backend: "software",
		Plaintext: []byte("data"), Nonce: []byte("short"),
	})
	require.Error(t, err)
}

// TestHandler_EncryptDecrypt_TagSizeArrives proves a truncated AEAD tag length
// travels on both legs: the tag must be exactly the requested length, and
// verifying it at the cipher's full length must fail (NIST SP 800-38D section
// 5.2.2 step 5).
func TestHandler_EncryptDecrypt_TagSizeArrives(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateSymmetricKey(t, server, "mcp-aes-tagsize")
	plaintext := []byte("short tag payload")

	encrypted, err := mcpCall(t, server.handleEncrypt, "xkms.encrypt", EncryptParams{
		KeyID: "mcp-aes-tagsize", Backend: "software", Plaintext: plaintext, TagSize: 12,
	})
	require.NoError(t, err)
	enc := encrypted.(EncryptResult)
	assert.Len(t, enc.Tag, 12, "the tag must be truncated to the requested length")

	result, err := mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-aes-tagsize", Backend: "software",
		Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag, TagSize: 12,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.(DecryptResult).Plaintext)

	_, err = mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-aes-tagsize", Backend: "software",
		Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag,
	})
	assert.Error(t, err, "a 12-byte tag must not be verified at the cipher's full tag length")
}

// TestHandler_EncryptDecrypt_CBCModeAndIVArrive proves the cipher mode and the
// AES-CBC initialization vector both travel: the ciphertext must decrypt only
// under the same mode and IV.
func TestHandler_EncryptDecrypt_CBCModeAndIVArrive(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateSymmetricKey(t, server, "mcp-aes-cbc")
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	require.NoError(t, err)

	plaintext := []byte("cbc mode payload needs padding")
	encrypted, err := mcpCall(t, server.handleEncrypt, "xkms.encrypt", EncryptParams{
		KeyID: "mcp-aes-cbc", Backend: "software", Plaintext: plaintext, Mode: "cbc-pad", IV: iv,
	})
	require.NoError(t, err)
	enc := encrypted.(EncryptResult)
	assert.Equal(t, iv, enc.IV, "the caller-supplied IV must be the one used")

	result, err := mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-aes-cbc", Backend: "software",
		Ciphertext: enc.Ciphertext, Mode: "cbc-pad", IV: iv,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.(DecryptResult).Plaintext)

	// Decrypting the same ciphertext as the default AEAD mode must not
	// reproduce the plaintext: the mode is part of the construction.
	_, err = mcpCall(t, server.handleDecrypt, "xkms.decrypt", DecryptParams{
		KeyID: "mcp-aes-cbc", Backend: "software", Ciphertext: enc.Ciphertext, IV: iv,
	})
	assert.Error(t, err, "a CBC ciphertext must not decrypt under the default AEAD mode")
}

// TestHandler_Encrypt_UnknownModeRefused proves a misspelled cipher mode is
// refused rather than silently running the default cipher.
func TestHandler_Encrypt_UnknownModeRefused(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	generateSymmetricKey(t, server, "mcp-aes-bad-mode")

	_, err := mcpCall(t, server.handleEncrypt, "xkms.encrypt", EncryptParams{
		KeyID: "mcp-aes-bad-mode", Backend: "software",
		Plaintext: []byte("data"), Mode: "ccb",
	})
	require.Error(t, err)
}

// ============================================================================
// Tenant scoping
// ============================================================================

// TestCallerTenantID covers the helper directly, including the unauthenticated
// case where no identity is present.
//
// The tenant used to be dropped entirely on this transport: every operation
// resolved against the untenanted backend regardless of who asked.
func TestCallerTenantID(t *testing.T) {
	assert.Equal(t, "", callerTenantID(t.Context()),
		"a request with no identity carries no tenant")

	ctx := auth.WithIdentity(t.Context(), &auth.Identity{Subject: "svc", TenantID: "tenant-b"})
	assert.Equal(t, "tenant-b", callerTenantID(ctx))
}

// mcpCallAs invokes a handler with an authenticated identity belonging to
// tenantID. An empty tenantID sends no identity at all.
func mcpCallAs(
	t *testing.T,
	handler func(context.Context, *JSONRPCRequest) (interface{}, error),
	method string,
	params interface{},
	tenantID string,
) (interface{}, error) {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	ctx := context.Background()
	if tenantID != "" {
		ctx = auth.WithIdentity(ctx, &auth.Identity{Subject: "svc", TenantID: tenantID})
	}
	return handler(ctx, &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1})
}

// generateRSAKeyAs creates an RSA key owned by tenantID. An empty tenantID
// creates the untenanted key of that name.
//
// It does not read the key back: xkms.getKey resolves through
// XKMSService.GetKey, which takes no tenant, so a tenant asking for its own
// key by name is answered with the untenanted key. That gap is reported
// separately; the tests below take the signature itself as the oracle instead.
func generateRSAKeyAs(t *testing.T, server *Server, keyID, tenantID string) {
	t.Helper()

	_, err := mcpCallAs(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, Backend: "software", KeyType: "rsa", KeySize: 2048,
	}, tenantID)
	require.NoError(t, err)
}

// TestHandler_Sign_TenantIDForwarded proves the caller's tenant reaches the
// service layer and selects which key signs.
//
// The oracle is key identity, not the presence of an error. The same key ID
// exists twice -- once owned by tenant-a, once untenanted -- and each request
// must reach its own key: the tenant's signature must not verify under the
// untenanted key. An assertion that a tenant-scoped call merely fails is
// satisfied by a wholly broken tenant path, which is what this test used to
// assert.
func TestHandler_Sign_TenantIDForwarded(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	const keyID = "mcp-tenant-sign"
	sharedPub := generateRSAKey(t, server, keyID)
	generateRSAKeyAs(t, server, keyID, "tenant-a")

	params := SignParams{
		KeyID: keyID, Backend: "software", Data: []byte("data"), Hash: "SHA-256",
	}
	digest := sha256.Sum256([]byte("data"))

	signatureFrom := func(tenantID string) []byte {
		result, err := mcpCallAs(t, server.handleSign, "xkms.sign", params, tenantID)
		require.NoError(t, err, "a caller must be able to sign with its own key")
		sig, err := decodeSignature(result.(SignResult).Signature)
		require.NoError(t, err)
		return sig
	}

	sharedSig := signatureFrom("")
	require.NoError(t, rsa.VerifyPKCS1v15(sharedPub, crypto.SHA256, digest[:], sharedSig),
		"an untenanted request must sign with the untenanted key")

	tenantSig := signatureFrom("tenant-a")
	assert.Error(t, rsa.VerifyPKCS1v15(sharedPub, crypto.SHA256, digest[:], tenantSig),
		"a tenant-scoped request signed with the untenanted key; the tenant never selected the key")
	assert.NotEqual(t, sharedSig, tenantSig,
		"both requests produced the same signature, so both reached the same key")
}

// TestHandler_Sign_ForeignTenantCannotSign is the negative control: a tenant
// that owns no key of that name must not be served another tenant's.
func TestHandler_Sign_ForeignTenantCannotSign(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	const keyID = "mcp-tenant-a-only"
	generateRSAKeyAs(t, server, keyID, "tenant-a")

	_, err := mcpCallAs(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: keyID, Backend: "software", Data: []byte("data"), Hash: "SHA-256",
	}, "tenant-b")
	require.Error(t, err, "a tenant must not sign with another tenant's key")
}

// ============================================================================
// decodeSignature
// ============================================================================

// TestDecodeSignature covers every encoding this transport accepts and proves
// the malformed cases are refused rather than decoded to an empty signature,
// which would be reported as a verification failure.
func TestDecodeSignature(t *testing.T) {
	raw := []byte{0x01, 0x02, 0xFF}

	t.Run("bytes", func(t *testing.T) {
		got, err := decodeSignature(raw)
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})

	t.Run("base64 string", func(t *testing.T) {
		got, err := decodeSignature("AQL/")
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})

	t.Run("raw string", func(t *testing.T) {
		got, err := decodeSignature("not base64 !!")
		require.NoError(t, err)
		assert.Equal(t, []byte("not base64 !!"), got)
	})

	t.Run("byte array", func(t *testing.T) {
		got, err := decodeSignature([]interface{}{float64(1), float64(2), float64(255)})
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})

	t.Run("nil is refused", func(t *testing.T) {
		_, err := decodeSignature(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("non-byte array is refused", func(t *testing.T) {
		_, err := decodeSignature([]interface{}{"not a number"})
		require.Error(t, err)
	})

	t.Run("object is refused", func(t *testing.T) {
		_, err := decodeSignature(map[string]interface{}{"foo": "bar"})
		require.Error(t, err)
	})
}
