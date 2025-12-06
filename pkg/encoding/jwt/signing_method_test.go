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

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Test AlgorithmFromKeyAttributes
// ========================================================================

func TestAlgorithmFromKeyAttributes_AllAlgorithms(t *testing.T) {
	testCases := []struct {
		name      string
		sigAlgo   x509.SignatureAlgorithm
		expected  string
		expectErr bool
	}{
		{"PureEd25519", x509.PureEd25519, "EdDSA", false},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, "PS256", false},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, "PS384", false},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS, "PS512", false},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, "ES256", false},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, "ES384", false},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, "ES512", false},
		{"SHA256WithRSA", x509.SHA256WithRSA, "RS256", false},
		{"SHA384WithRSA", x509.SHA384WithRSA, "RS384", false},
		{"SHA512WithRSA", x509.SHA512WithRSA, "RS512", false},
		{"Invalid", x509.MD5WithRSA, "", true},
		{"UnknownAlgorithm", x509.SignatureAlgorithm(999), "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				SignatureAlgorithm: tc.sigAlgo,
			}
			result, err := AlgorithmFromKeyAttributes(keyAttrs)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidSignatureAlgorithm, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// ========================================================================
// Test NewSigningMethodSigner
// ========================================================================

func TestNewSigningMethodSigner_RSA(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "RS256", signer.Alg())
	assert.False(t, signer.isPSS)
}

func TestNewSigningMethodSigner_PSS(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "PS256", signer.Alg())
	assert.True(t, signer.isPSS)
}

func TestNewSigningMethodSigner_ECDSA(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "ES256", signer.Alg())
}

func TestNewSigningMethodSigner_Ed25519(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.PureEd25519,
		KeyAlgorithm:       x509.Ed25519,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "EdDSA", signer.Alg())
}

func TestNewSigningMethodSigner_InvalidAlgorithm(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.MD5WithRSA,
	}

	_, err := NewSigningMethodSigner(keyAttrs)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidSignatureAlgorithm, err)
}

// ========================================================================
// Test Digest
// ========================================================================

func TestDigest_Ed25519_ReturnsRawMessage(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.PureEd25519,
		KeyAlgorithm:       x509.Ed25519,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	message := "test message"
	digest, err := signer.Digest(message)
	require.NoError(t, err)
	assert.Equal(t, []byte(message), digest)
}

func TestDigest_RSA_ReturnsHash(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	message := "test message"
	digest, err := signer.Digest(message)
	require.NoError(t, err)
	assert.Len(t, digest, 32) // SHA-256 produces 32 bytes
	assert.NotEqual(t, []byte(message), digest)
}

func TestDigest_SHA384(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA384WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA384,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	digest, err := signer.Digest("test")
	require.NoError(t, err)
	assert.Len(t, digest, 48) // SHA-384 produces 48 bytes
}

func TestDigest_SHA512(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA512WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA512,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	digest, err := signer.Digest("test")
	require.NoError(t, err)
	assert.Len(t, digest, 64) // SHA-512 produces 64 bytes
}

// ========================================================================
// Test Sign
// ========================================================================

func TestSign_RSA_PKCS1v15(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	signature, err := signer.Sign("test message", key)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSign_RSA_PSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	signature, err := signer.Sign("test message", key)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSign_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyAlgorithm:       x509.ECDSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	signature, err := signer.Sign("test message", key)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSign_Ed25519_SignatureLength(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.PureEd25519,
		KeyAlgorithm:       x509.Ed25519,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	signature, err := signer.Sign("test message", priv)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Len(t, signature, 64) // Ed25519 signatures are 64 bytes
}

func TestSign_InvalidKey(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	_, err = signer.Sign("test", "not a valid key")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidKey, err)
}

// ========================================================================
// Test Verify
// ========================================================================

func TestVerify_RSA_PKCS1v15(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	message := "test message"
	signature, err := signer.Sign(message, key)
	require.NoError(t, err)

	err = signer.Verify(message, signature, &key.PublicKey)
	assert.NoError(t, err)
}

func TestVerify_RSA_PSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	message := "test message"
	signature, err := signer.Sign(message, key)
	require.NoError(t, err)

	err = signer.Verify(message, signature, &key.PublicKey)
	assert.NoError(t, err)
}

func TestVerify_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyAlgorithm:       x509.ECDSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	message := "test message"
	signature, err := signer.Sign(message, key)
	require.NoError(t, err)

	err = signer.Verify(message, signature, &key.PublicKey)
	assert.NoError(t, err)
}

func TestVerify_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.PureEd25519,
		KeyAlgorithm:       x509.Ed25519,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	message := "test message"
	signature, err := signer.Sign(message, priv)
	require.NoError(t, err)

	err = signer.Verify(message, signature, pub)
	assert.NoError(t, err)
}

func TestVerify_InvalidPublicKey(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	err = signer.Verify("message", []byte("signature"), "not a public key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported public key type")
}

func TestVerify_InvalidEd25519Key(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.PureEd25519,
		KeyAlgorithm:       x509.Ed25519,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	// Try to verify Ed25519 signature with RSA public key
	err = signer.Verify("message", []byte("signature"), &rsaKey.PublicKey)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidKey, err)
}

func TestVerify_InvalidSignature_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	err = signer.Verify("message", []byte("invalid signature"), &key.PublicKey)
	assert.Error(t, err)
}

func TestVerify_InvalidSignature_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyAlgorithm:       x509.ECDSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	err = signer.Verify("message", []byte("invalid signature"), &key.PublicKey)
	assert.Error(t, err)
	assert.Equal(t, jwt.ErrSignatureInvalid, err)
}

func TestVerify_InvalidSignature_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.PureEd25519,
		KeyAlgorithm:       x509.Ed25519,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	err = signer.Verify("message", make([]byte, 64), pub)
	assert.Error(t, err)
	assert.Equal(t, jwt.ErrSignatureInvalid, err)
}

func TestVerify_UnsupportedKeyType(t *testing.T) {
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	signer, err := NewSigningMethodSigner(keyAttrs)
	require.NoError(t, err)

	// Use a type that implements crypto.PublicKey but is not RSA/ECDSA/Ed25519
	// We'll use an ECDSA key to verify what should be RSA
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// The signature will be invalid but we're testing that the verify path handles ECDSA too
	err = signer.Verify("message", []byte("signature"), &ecdsaKey.PublicKey)
	// This should still fail since signature is invalid
	assert.Error(t, err)
}

// ========================================================================
// Test SignVerify End-to-End
// ========================================================================

func TestSignVerify_RoundTrip_AllAlgorithms(t *testing.T) {
	testCases := []struct {
		name    string
		keyGen  func() (crypto.Signer, crypto.PublicKey, error)
		sigAlgo x509.SignatureAlgorithm
		keyAlgo x509.PublicKeyAlgorithm
		hash    crypto.Hash
	}{
		{
			name: "RS256",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.SHA256WithRSA,
			keyAlgo: x509.RSA,
			hash:    crypto.SHA256,
		},
		{
			name: "RS384",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.SHA384WithRSA,
			keyAlgo: x509.RSA,
			hash:    crypto.SHA384,
		},
		{
			name: "RS512",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.SHA512WithRSA,
			keyAlgo: x509.RSA,
			hash:    crypto.SHA512,
		},
		{
			name: "PS256",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.SHA256WithRSAPSS,
			keyAlgo: x509.RSA,
			hash:    crypto.SHA256,
		},
		{
			name: "PS384",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.SHA384WithRSAPSS,
			keyAlgo: x509.RSA,
			hash:    crypto.SHA384,
		},
		{
			name: "PS512",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.SHA512WithRSAPSS,
			keyAlgo: x509.RSA,
			hash:    crypto.SHA512,
		},
		{
			name: "ES256",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.ECDSAWithSHA256,
			keyAlgo: x509.ECDSA,
			hash:    crypto.SHA256,
		},
		{
			name: "ES384",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.ECDSAWithSHA384,
			keyAlgo: x509.ECDSA,
			hash:    crypto.SHA384,
		},
		{
			name: "ES512",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return k, &k.PublicKey, err
			},
			sigAlgo: x509.ECDSAWithSHA512,
			keyAlgo: x509.ECDSA,
			hash:    crypto.SHA512,
		},
		{
			name: "EdDSA",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, pub, err
			},
			sigAlgo: x509.PureEd25519,
			keyAlgo: x509.Ed25519,
			hash:    crypto.Hash(0),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer, pubKey, err := tc.keyGen()
			require.NoError(t, err)

			keyAttrs := &types.KeyAttributes{
				SignatureAlgorithm: tc.sigAlgo,
				KeyAlgorithm:       tc.keyAlgo,
				Hash:               tc.hash,
			}

			method, err := NewSigningMethodSigner(keyAttrs)
			require.NoError(t, err)

			message := "This is a test message for signing"

			sig, err := method.Sign(message, signer)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)

			err = method.Verify(message, sig, pubKey)
			assert.NoError(t, err)
		})
	}
}

// ========================================================================
// Test Alg
// ========================================================================

func TestAlg_ReturnsCorrectAlgorithm(t *testing.T) {
	testCases := []struct {
		sigAlgo  x509.SignatureAlgorithm
		expected string
	}{
		{x509.SHA256WithRSA, "RS256"},
		{x509.SHA384WithRSA, "RS384"},
		{x509.SHA512WithRSA, "RS512"},
		{x509.SHA256WithRSAPSS, "PS256"},
		{x509.SHA384WithRSAPSS, "PS384"},
		{x509.SHA512WithRSAPSS, "PS512"},
		{x509.ECDSAWithSHA256, "ES256"},
		{x509.ECDSAWithSHA384, "ES384"},
		{x509.ECDSAWithSHA512, "ES512"},
		{x509.PureEd25519, "EdDSA"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				SignatureAlgorithm: tc.sigAlgo,
				Hash:               crypto.SHA256,
			}
			method, err := NewSigningMethodSigner(keyAttrs)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, method.Alg())
		})
	}
}

// ========================================================================
// Test SignWithSigner and SignWithSignerAndKID
// ========================================================================

func TestSignWithSigner_Success(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	s := &Signer{}
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "Test User",
		"iat":  time.Now().Unix(),
	}

	token, err := s.SignWithSigner(key, claims, keyAttrs)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify the token has 3 parts (header.payload.signature)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)
}

func TestSignWithSigner_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.PureEd25519,
		KeyAlgorithm:       x509.Ed25519,
	}

	s := &Signer{}
	claims := jwt.MapClaims{
		"sub": "1234567890",
	}

	token, err := s.SignWithSigner(priv, claims, keyAttrs)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSignWithSigner_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyAlgorithm:       x509.ECDSA,
		Hash:               crypto.SHA256,
	}

	s := &Signer{}
	claims := jwt.MapClaims{
		"sub": "1234567890",
	}

	token, err := s.SignWithSigner(key, claims, keyAttrs)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSignWithSigner_InvalidKeyAttrs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Use an unsupported algorithm
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.DSAWithSHA256,
	}

	s := &Signer{}
	claims := jwt.MapClaims{
		"sub": "1234567890",
	}

	_, err = s.SignWithSigner(key, claims, keyAttrs)
	assert.Error(t, err)
}

func TestSignWithSignerAndKID_Success(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
	}

	s := &Signer{}
	claims := jwt.MapClaims{
		"sub": "1234567890",
	}

	kid := "my-key-id-123"
	token, err := s.SignWithSignerAndKID(key, claims, keyAttrs, kid)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify the token has 3 parts
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)

	// Decode and verify the header contains the kid
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var header map[string]interface{}
	err = json.Unmarshal(headerJSON, &header)
	require.NoError(t, err)
	assert.Equal(t, kid, header["kid"])
}

func TestSignWithSignerAndKID_InvalidKeyAttrs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Use an unsupported algorithm
	keyAttrs := &types.KeyAttributes{
		SignatureAlgorithm: x509.DSAWithSHA256,
	}

	s := &Signer{}
	claims := jwt.MapClaims{
		"sub": "1234567890",
	}

	_, err = s.SignWithSignerAndKID(key, claims, keyAttrs, "kid")
	assert.Error(t, err)
}
