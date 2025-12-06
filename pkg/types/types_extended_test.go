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

package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Test ECCAttributes MarshalJSON/UnmarshalJSON
// ========================================================================

func TestECCAttributes_MarshalJSON_AllCurves(t *testing.T) {
	testCases := []struct {
		name     string
		curve    elliptic.Curve
		expected string
	}{
		{"P-224", elliptic.P224(), `{"curve":"P-224"}`},
		{"P-256", elliptic.P256(), `{"curve":"P-256"}`},
		{"P-384", elliptic.P384(), `{"curve":"P-384"}`},
		{"P-521", elliptic.P521(), `{"curve":"P-521"}`},
		{"nil curve", nil, `{"curve":""}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := &ECCAttributes{Curve: tc.curve}
			data, err := json.Marshal(attrs)
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(data))
		})
	}
}

func TestECCAttributes_UnmarshalJSON_AllCurves(t *testing.T) {
	testCases := []struct {
		name      string
		json      string
		expected  elliptic.Curve
		expectErr bool
	}{
		{"P-224", `{"curve":"P-224"}`, elliptic.P224(), false},
		{"P-256", `{"curve":"P-256"}`, elliptic.P256(), false},
		{"P-384", `{"curve":"P-384"}`, elliptic.P384(), false},
		{"P-521", `{"curve":"P-521"}`, elliptic.P521(), false},
		{"empty curve", `{"curve":""}`, nil, false},
		{"unsupported curve", `{"curve":"P-999"}`, nil, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var attrs ECCAttributes
			err := json.Unmarshal([]byte(tc.json), &attrs)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tc.expected == nil {
					assert.Nil(t, attrs.Curve)
				} else {
					assert.Equal(t, tc.expected.Params().Name, attrs.Curve.Params().Name)
				}
			}
		})
	}
}

func TestECCAttributes_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var attrs ECCAttributes
	err := json.Unmarshal([]byte("not valid json"), &attrs)
	assert.Error(t, err)
}

// ========================================================================
// Test ParseSignatureAlgorithm
// ========================================================================

func TestParseSignatureAlgorithm_AllAlgorithms(t *testing.T) {
	testCases := []struct {
		input    string
		expected x509.SignatureAlgorithm
	}{
		{"SHA256-RSA", x509.SHA256WithRSA},
		{"sha256withrsa", x509.SHA256WithRSA},
		{"SHA384-RSA", x509.SHA384WithRSA},
		{"SHA384WITHRSA", x509.SHA384WithRSA},
		{"SHA512-RSA", x509.SHA512WithRSA},
		{"SHA512WITHRSA", x509.SHA512WithRSA},
		{"SHA256-RSA-PSS", x509.SHA256WithRSAPSS},
		{"SHA256-RSAPSS", x509.SHA256WithRSAPSS},
		{"SHA256WITHRSAPSS", x509.SHA256WithRSAPSS},
		{"SHA384-RSA-PSS", x509.SHA384WithRSAPSS},
		{"SHA384-RSAPSS", x509.SHA384WithRSAPSS},
		{"SHA384WITHRSAPSS", x509.SHA384WithRSAPSS},
		{"SHA512-RSA-PSS", x509.SHA512WithRSAPSS},
		{"SHA512-RSAPSS", x509.SHA512WithRSAPSS},
		{"SHA512WITHRSAPSS", x509.SHA512WithRSAPSS},
		{"ECDSA-SHA256", x509.ECDSAWithSHA256},
		{"ECDSAWITHSHA256", x509.ECDSAWithSHA256},
		{"ECDSA-SHA384", x509.ECDSAWithSHA384},
		{"ECDSAWITHSHA384", x509.ECDSAWithSHA384},
		{"ECDSA-SHA512", x509.ECDSAWithSHA512},
		{"ECDSAWITHSHA512", x509.ECDSAWithSHA512},
		{"ED25519", x509.PureEd25519},
		{"PUREED25519", x509.PureEd25519},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result, err := ParseSignatureAlgorithm(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseSignatureAlgorithm_Unknown(t *testing.T) {
	result, err := ParseSignatureAlgorithm("UNKNOWN-ALGO")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownSignatureAlgorithm)
	assert.Equal(t, x509.UnknownSignatureAlgorithm, result)
}

func TestParseSignatureAlgorithm_WhitespaceHandling(t *testing.T) {
	result, err := ParseSignatureAlgorithm("  ED25519  ")
	require.NoError(t, err)
	assert.Equal(t, x509.PureEd25519, result)
}

// ========================================================================
// Test PublicKeyToString
// ========================================================================

func TestPublicKeyToString_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	result := PublicKeyToString(&key.PublicKey)
	assert.Equal(t, "RSA 2048 bits", result)
}

func TestPublicKeyToString_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	result := PublicKeyToString(&key.PublicKey)
	assert.Equal(t, "ECDSA P-256", result)
}

func TestPublicKeyToString_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	result := PublicKeyToString(pub)
	assert.Equal(t, "Ed25519", result)
}

func TestPublicKeyToString_Nil(t *testing.T) {
	result := PublicKeyToString(nil)
	assert.Equal(t, "<nil>", result)
}

func TestPublicKeyToString_UnknownType(t *testing.T) {
	// Use a type that's not RSA/ECDSA/Ed25519
	type unknownKey struct{}
	result := PublicKeyToString(unknownKey{})
	assert.Contains(t, result, "unknownKey")
}

// ========================================================================
// Test SimpleVerifier
// ========================================================================

func TestNewVerifier_NilOpts(t *testing.T) {
	v := NewVerifier(nil)
	assert.NotNil(t, v)
}

func TestNewVerifier_WithOpts(t *testing.T) {
	opts := &VerifyOpts{Hash: crypto.SHA256}
	v := NewVerifier(opts)
	assert.NotNil(t, v)
}

func TestSimpleVerifier_Verify_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	message := []byte("test message")
	h := crypto.SHA256.New()
	h.Write(message)
	digest := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	require.NoError(t, err)

	opts := &VerifyOpts{Hash: crypto.SHA256}
	v := NewVerifier(opts)
	err = v.Verify(&key.PublicKey, digest, signature)
	assert.NoError(t, err)
}

func TestSimpleVerifier_Verify_RSA_InvalidSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	digest := []byte("some digest content that is 32 bytes")[:32]

	opts := &VerifyOpts{Hash: crypto.SHA256}
	v := NewVerifier(opts)
	err = v.Verify(&key.PublicKey, digest, []byte("invalid signature"))
	assert.Error(t, err)
}

func TestSimpleVerifier_Verify_RSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	message := []byte("test message")
	h := crypto.SHA256.New()
	h.Write(message)
	digest := h.Sum(nil)

	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, pssOpts)
	require.NoError(t, err)

	opts := &VerifyOpts{
		Hash:       crypto.SHA256,
		PSSOptions: pssOpts,
	}
	v := NewVerifier(opts)
	err = v.Verify(&key.PublicKey, digest, signature)
	assert.NoError(t, err)
}

func TestSimpleVerifier_Verify_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	h := crypto.SHA256.New()
	h.Write(message)
	digest := h.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
	require.NoError(t, err)

	opts := &VerifyOpts{Hash: crypto.SHA256}
	v := NewVerifier(opts)
	err = v.Verify(&key.PublicKey, digest, signature)
	assert.NoError(t, err)
}

func TestSimpleVerifier_Verify_ECDSA_InvalidSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	opts := &VerifyOpts{Hash: crypto.SHA256}
	v := NewVerifier(opts)
	err = v.Verify(&key.PublicKey, []byte("digest"), []byte("invalid"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ECDSA signature verification failed")
}

func TestSimpleVerifier_Verify_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	opts := &VerifyOpts{}
	v := NewVerifier(opts)
	err = v.Verify(pub, message, signature)
	assert.NoError(t, err)
}

func TestSimpleVerifier_Verify_Ed25519_InvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	opts := &VerifyOpts{}
	v := NewVerifier(opts)
	err = v.Verify(pub, []byte("message"), make([]byte, 64))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Ed25519 signature verification failed")
}

func TestSimpleVerifier_Verify_NilKey(t *testing.T) {
	v := NewVerifier(nil)
	err := v.Verify(nil, []byte("digest"), []byte("sig"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public key is nil")
}

func TestSimpleVerifier_Verify_UnsupportedKeyType(t *testing.T) {
	type unsupportedKey struct{}
	v := NewVerifier(nil)
	err := v.Verify(unsupportedKey{}, []byte("digest"), []byte("sig"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported public key type")
}

// ========================================================================
// Test KeyAttributesFromConfig
// ========================================================================

func TestKeyAttributesFromConfig_RSA(t *testing.T) {
	config := &KeyConfig{
		CN:                 "test-key",
		Algorithm:          "RSA",
		Hash:               "SHA256",
		RSAKeySize:         4096,
		SignatureAlgorithm: "SHA256-RSA",
		StoreType:          "PKCS8",
		KeyType:            "TLS",
	}

	attrs, err := KeyAttributesFromConfig(config)
	require.NoError(t, err)
	assert.Equal(t, "test-key", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.Equal(t, crypto.SHA256, attrs.Hash)
	assert.NotNil(t, attrs.RSAAttributes)
	assert.Equal(t, 4096, attrs.RSAAttributes.KeySize)
}

func TestKeyAttributesFromConfig_RSADefaultKeySize(t *testing.T) {
	config := &KeyConfig{
		CN:        "test-key",
		Algorithm: "RSA",
	}

	attrs, err := KeyAttributesFromConfig(config)
	require.NoError(t, err)
	assert.NotNil(t, attrs.RSAAttributes)
	assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
}

func TestKeyAttributesFromConfig_ECDSA(t *testing.T) {
	config := &KeyConfig{
		CN:        "test-key",
		Algorithm: "ECDSA",
		ECCCurve:  "P-384",
	}

	attrs, err := KeyAttributesFromConfig(config)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.ECCAttributes)
	assert.Equal(t, elliptic.P384().Params().Name, attrs.ECCAttributes.Curve.Params().Name)
}

func TestKeyAttributesFromConfig_ECDSADefaultCurve(t *testing.T) {
	config := &KeyConfig{
		CN:        "test-key",
		Algorithm: "ECDSA",
		ECCCurve:  "",
	}

	attrs, err := KeyAttributesFromConfig(config)
	require.NoError(t, err)
	assert.NotNil(t, attrs.ECCAttributes)
	assert.Equal(t, elliptic.P256().Params().Name, attrs.ECCAttributes.Curve.Params().Name)
}

func TestKeyAttributesFromConfig_NilConfig(t *testing.T) {
	_, err := KeyAttributesFromConfig(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is nil")
}

func TestKeyAttributesFromConfig_InvalidAlgorithm(t *testing.T) {
	config := &KeyConfig{
		Algorithm: "INVALID",
	}

	_, err := KeyAttributesFromConfig(config)
	assert.Error(t, err)
}

func TestKeyAttributesFromConfig_InvalidSignatureAlgorithm(t *testing.T) {
	config := &KeyConfig{
		Algorithm:          "RSA",
		SignatureAlgorithm: "INVALID-SIG-ALGO",
	}

	// Should not fail, just use UnknownSignatureAlgorithm
	attrs, err := KeyAttributesFromConfig(config)
	require.NoError(t, err)
	assert.Equal(t, x509.UnknownSignatureAlgorithm, attrs.SignatureAlgorithm)
}

// ========================================================================
// Test EncodePubKeyPEM
// ========================================================================

func TestEncodePubKeyPEM_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pem, err := EncodePubKeyPEM(&key.PublicKey)
	require.NoError(t, err)
	assert.Contains(t, string(pem), "-----BEGIN PUBLIC KEY-----")
	assert.Contains(t, string(pem), "-----END PUBLIC KEY-----")
}

func TestEncodePubKeyPEM_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pem, err := EncodePubKeyPEM(&key.PublicKey)
	require.NoError(t, err)
	assert.Contains(t, string(pem), "-----BEGIN PUBLIC KEY-----")
}

func TestEncodePubKeyPEM_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pem, err := EncodePubKeyPEM(pub)
	require.NoError(t, err)
	assert.Contains(t, string(pem), "-----BEGIN PUBLIC KEY-----")
}

// ========================================================================
// Test KeySerializer
// ========================================================================

func TestNewKeySerializer_JSON(t *testing.T) {
	s, err := NewKeySerializer(SerializerJSON)
	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, SerializerJSON, s.Type())
}

func TestNewKeySerializer_YAML(t *testing.T) {
	s, err := NewKeySerializer(SerializerYAML)
	require.NoError(t, err)
	assert.NotNil(t, s)
}

func TestNewKeySerializer_UnsupportedType(t *testing.T) {
	_, err := NewKeySerializer(SerializerType(999))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported serializer type")
}

func TestNewSerializer_BackwardCompatibility(t *testing.T) {
	s, err := NewSerializer(SerializerJSON)
	require.NoError(t, err)
	assert.NotNil(t, s)
}

// ========================================================================
// Test KeyMap
// ========================================================================

func TestParseKeyMap_ValidJSON(t *testing.T) {
	data := `{"kty":"RSA","n":"test","e":"AQAB"}`
	km, err := ParseKeyMap(data)
	require.NoError(t, err)
	assert.Equal(t, "RSA", km["kty"])
}

func TestParseKeyMap_InvalidJSON(t *testing.T) {
	_, err := ParseKeyMap("not valid json")
	assert.Error(t, err)
}

func TestKeyMap_JOSESignatureAlgorithm_RSA(t *testing.T) {
	km := KeyMap{"kty": "RSA"}
	algo, err := km.JOSESignatureAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, "RS256", algo)
}

func TestKeyMap_JOSESignatureAlgorithm_EC_P256(t *testing.T) {
	km := KeyMap{"kty": "EC", "crv": "P-256"}
	algo, err := km.JOSESignatureAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, "ES256", algo)
}

func TestKeyMap_JOSESignatureAlgorithm_EC_P384(t *testing.T) {
	km := KeyMap{"kty": "EC", "crv": "P-384"}
	algo, err := km.JOSESignatureAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, "ES384", algo)
}

func TestKeyMap_JOSESignatureAlgorithm_EC_P521(t *testing.T) {
	km := KeyMap{"kty": "EC", "crv": "P-521"}
	algo, err := km.JOSESignatureAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, "ES512", algo)
}

func TestKeyMap_JOSESignatureAlgorithm_EC_Default(t *testing.T) {
	km := KeyMap{"kty": "EC"} // No curve specified
	algo, err := km.JOSESignatureAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, "ES256", algo)
}

func TestKeyMap_JOSESignatureAlgorithm_OKP(t *testing.T) {
	km := KeyMap{"kty": "OKP"}
	algo, err := km.JOSESignatureAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", algo)
}

func TestKeyMap_JOSESignatureAlgorithm_MissingKty(t *testing.T) {
	km := KeyMap{}
	_, err := km.JOSESignatureAlgorithm()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or invalid kty field")
}

func TestKeyMap_JOSESignatureAlgorithm_UnsupportedKty(t *testing.T) {
	km := KeyMap{"kty": "UNKNOWN"}
	_, err := km.JOSESignatureAlgorithm()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestKeyMap_Equal_Same(t *testing.T) {
	km1 := KeyMap{"kty": "RSA", "n": "test"}
	km2 := KeyMap{"kty": "RSA", "n": "test"}
	assert.True(t, km1.Equal(km2))
}

func TestKeyMap_Equal_DifferentLength(t *testing.T) {
	km1 := KeyMap{"kty": "RSA"}
	km2 := KeyMap{"kty": "RSA", "n": "test"}
	assert.False(t, km1.Equal(km2))
}

func TestKeyMap_Equal_DifferentValues(t *testing.T) {
	km1 := KeyMap{"kty": "RSA"}
	km2 := KeyMap{"kty": "EC"}
	assert.False(t, km1.Equal(km2))
}

func TestKeyMap_Equal_MissingKey(t *testing.T) {
	km1 := KeyMap{"kty": "RSA"}
	km2 := KeyMap{"n": "test"}
	assert.False(t, km1.Equal(km2))
}

// ========================================================================
// Test Deserialize
// ========================================================================

func TestDeserialize_InvalidData(t *testing.T) {
	_, err := Deserialize("not valid json")
	assert.Error(t, err)
}

// ========================================================================
// Test PublicKeyID
// ========================================================================

func TestPublicKeyID_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	id := PublicKeyID(&key.PublicKey, SerializerJSON)
	assert.NotEqual(t, uint64(0), id)
}

func TestPublicKeyID_InvalidSerializer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	id := PublicKeyID(&key.PublicKey, SerializerType(999))
	assert.Equal(t, uint64(0), id)
}

// ========================================================================
// Test Capabilities.SupportsSealing
// ========================================================================

func TestCapabilities_SupportsSealing(t *testing.T) {
	caps := Capabilities{Sealing: true}
	assert.True(t, caps.SupportsSealing())

	caps = Capabilities{Sealing: false}
	assert.False(t, caps.SupportsSealing())
}

// ========================================================================
// Test CurveName
// ========================================================================

func TestCurveName_AllCurves(t *testing.T) {
	testCases := []struct {
		curve    elliptic.Curve
		expected string
	}{
		{elliptic.P224(), "P-224"},
		{elliptic.P256(), "P-256"},
		{elliptic.P384(), "P-384"},
		{elliptic.P521(), "P-521"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := CurveName(tc.curve)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCurveName_NilCurve(t *testing.T) {
	result := CurveName(nil)
	assert.Empty(t, result)
}

// ========================================================================
// Test ParseHashFromSignatureAlgorithm
// ========================================================================

func TestParseHashFromSignatureAlgorithm_AllAlgorithms(t *testing.T) {
	testCases := []struct {
		algo     x509.SignatureAlgorithm
		expected crypto.Hash
	}{
		{x509.SHA256WithRSA, crypto.SHA256},
		{x509.SHA384WithRSA, crypto.SHA384},
		{x509.SHA512WithRSA, crypto.SHA512},
		{x509.SHA256WithRSAPSS, crypto.SHA256},
		{x509.SHA384WithRSAPSS, crypto.SHA384},
		{x509.SHA512WithRSAPSS, crypto.SHA512},
		{x509.ECDSAWithSHA256, crypto.SHA256},
		{x509.ECDSAWithSHA384, crypto.SHA384},
		{x509.ECDSAWithSHA512, crypto.SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.algo.String(), func(t *testing.T) {
			algo := tc.algo
			result, err := ParseHashFromSignatureAlgorithm(&algo)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseHashFromSignatureAlgorithm_NilAlgo(t *testing.T) {
	_, err := ParseHashFromSignatureAlgorithm(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature algorithm is nil")
}

func TestParseHashFromSignatureAlgorithm_UnknownAlgo(t *testing.T) {
	algo := x509.UnknownSignatureAlgorithm
	_, err := ParseHashFromSignatureAlgorithm(&algo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signature algorithm")
}
