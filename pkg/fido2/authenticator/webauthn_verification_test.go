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

package authenticator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend/software"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend/tpm2"
	"github.com/stretchr/testify/require"
)

// testWebAuthnFlow runs a full CTAP2 MakeCredential -> GetAssertion flow
// and verifies the assertion signature RP-side using ecdsa.VerifyASN1.
func testWebAuthnFlow(t *testing.T, auth *Authenticator, algorithm int) {
	t.Helper()

	rpID := "example.com"
	clientDataHash := make([]byte, ClientDataHashSize)
	_, err := rand.Read(clientDataHash)
	require.NoError(t, err)

	// === MakeCredential ===
	makeCredReq := map[int]interface{}{
		1: clientDataHash,                                           // clientDataHash
		2: map[string]interface{}{"id": rpID, "name": "Example RP"}, // rp
		3: map[string]interface{}{ // user
			"id":          []byte("user-webauthn-test"),
			"name":        "webauthn@example.com",
			"displayName": "WebAuthn Test User",
		},
		4: []interface{}{ // pubKeyCredParams
			map[string]interface{}{
				"type": "public-key",
				"alg":  algorithm,
			},
		},
	}

	makeCredBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	makeCredResp, err := auth.ProcessCBOR(CmdMakeCredential, makeCredBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), makeCredResp[0], "MakeCredential should succeed")

	// Decode MakeCredential response
	var makeCredResult map[int]interface{}
	err = cbor.Unmarshal(makeCredResp[1:], &makeCredResult)
	require.NoError(t, err)

	// Extract authData and parse credential ID + public key
	authData, ok := makeCredResult[2].([]byte)
	require.True(t, ok, "authData should be bytes")
	require.True(t, len(authData) > 37+16+2, "authData should contain attested credential data")

	// Parse attested credential data from authData
	// Layout: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2) + credId(N) + coseKey(...)
	offset := 37 // rpIdHash + flags + signCount
	offset += 16 // aaguid
	credIDLen := int(authData[offset])<<8 | int(authData[offset+1])
	offset += 2
	credentialID := authData[offset : offset+credIDLen]
	offset += credIDLen
	publicKeyCOSE := authData[offset:]

	require.NotEmpty(t, credentialID, "credentialID should not be empty")
	require.NotEmpty(t, publicKeyCOSE, "publicKeyCOSE should not be empty")

	// Decode the COSE public key
	pubKey, decodedAlg, err := DecodeCOSEPublicKey(publicKeyCOSE)
	require.NoError(t, err)
	require.Equal(t, algorithm, decodedAlg)

	// === GetAssertion ===
	assertionClientDataHash := make([]byte, ClientDataHashSize)
	_, err = rand.Read(assertionClientDataHash)
	require.NoError(t, err)

	getAssertionReq := map[int]interface{}{
		1: rpID,                    // rpId
		2: assertionClientDataHash, // clientDataHash
		3: []interface{}{ // allowList
			map[string]interface{}{
				"type": "public-key",
				"id":   credentialID,
			},
		},
	}

	getAssertionBytes, err := cbor.Marshal(getAssertionReq)
	require.NoError(t, err)

	assertionResp, err := auth.ProcessCBOR(CmdGetAssertion, getAssertionBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), assertionResp[0], "GetAssertion should succeed")

	// Decode GetAssertion response
	var assertionResult map[int]interface{}
	err = cbor.Unmarshal(assertionResp[1:], &assertionResult)
	require.NoError(t, err)

	assertionAuthData, ok := assertionResult[2].([]byte)
	require.True(t, ok, "assertion authData should be bytes")

	signature, ok := assertionResult[3].([]byte)
	require.True(t, ok, "signature should be bytes")
	require.NotEmpty(t, signature)

	// === RP-side Signature Verification ===
	// WebAuthn RP verifies: sign(authData || clientDataHash) using ASN.1/DER
	signData := make([]byte, len(assertionAuthData)+len(assertionClientDataHash))
	copy(signData, assertionAuthData)
	copy(signData[len(assertionAuthData):], assertionClientDataHash)

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "public key should be ECDSA")

	// Hash with the correct algorithm
	var hasher hash.Hash
	switch algorithm {
	case COSEAlgES256:
		hasher = sha256.New()
	case COSEAlgES384:
		hasher = sha512.New384()
	case COSEAlgES512:
		hasher = sha512.New()
	default:
		t.Fatalf("unsupported algorithm for hash: %d", algorithm)
	}
	hasher.Write(signData)
	digest := hasher.Sum(nil)

	valid := ecdsa.VerifyASN1(ecPubKey, digest, signature)
	require.True(t, valid, "RP-side signature verification must pass (ASN.1/DER format)")
}

// TestWebAuthnVerification_SoftwareBackend tests the full WebAuthn flow with the
// software key backend producing ASN.1/DER signatures verified RP-side.
func TestWebAuthnVerification_SoftwareBackend(t *testing.T) {
	t.Parallel()

	backend := software.NewSoftwareKeyBackend()
	config := DefaultConfig()
	config.Storage = NewMemoryStorage()
	config.KeyBackend = backend

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	testWebAuthnFlow(t, auth, COSEAlgES256)
}

// TestWebAuthnVerification_SoftwareBackend_ES384 tests the full WebAuthn flow
// with the software key backend using ES384.
func TestWebAuthnVerification_SoftwareBackend_ES384(t *testing.T) {
	t.Parallel()

	backend := software.NewSoftwareKeyBackend()
	config := DefaultConfig()
	config.Storage = NewMemoryStorage()
	config.KeyBackend = backend
	config.SupportedAlgorithms = []int{COSEAlgES256, COSEAlgES384}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	testWebAuthnFlow(t, auth, COSEAlgES384)
}

// mockTPMForWebAuthn implements tpm2.TPMInterface for testing the TPM2 backend
// in the WebAuthn verification flow.
type mockTPMForWebAuthn struct{}

func (m *mockTPMForWebAuthn) GenerateECDSAKey(curve elliptic.Curve) (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func (m *mockTPMForWebAuthn) Sign(privateKey crypto.PrivateKey, digest []byte) ([]byte, error) {
	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, keybackend.ErrInvalidKeyHandle
	}
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest)
	if err != nil {
		return nil, err
	}
	// Return P1363 format (r || s) - the TPM2 backend converts to ASN.1/DER
	keySize := (ecKey.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, keySize*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[keySize*2-len(sBytes):], sBytes)
	return sig, nil
}

func (m *mockTPMForWebAuthn) Close() error { return nil }

// TestWebAuthnVerification_TPM2Backend tests the full WebAuthn flow with the
// TPM2 key backend (using a mock TPM) producing ASN.1/DER signatures.
func TestWebAuthnVerification_TPM2Backend(t *testing.T) {
	t.Parallel()

	backend, err := tpm2.NewTPM2KeyBackend(&tpm2.TPM2Config{
		TPM: &mockTPMForWebAuthn{},
	})
	require.NoError(t, err)

	config := DefaultConfig()
	config.Storage = NewMemoryStorage()
	config.KeyBackend = backend

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	testWebAuthnFlow(t, auth, COSEAlgES256)
}

// TestWebAuthnVerification_LegacyNilBackend tests the full WebAuthn flow with
// nil key backend (legacy crypto.go path) to ensure backward compatibility.
func TestWebAuthnVerification_LegacyNilBackend(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.Storage = NewMemoryStorage()
	// KeyBackend is nil - uses legacy crypto.go path

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	testWebAuthnFlow(t, auth, COSEAlgES256)
}
