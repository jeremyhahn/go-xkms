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
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock keychain for testing
type mockKeychain struct {
	keys map[string]crypto.PrivateKey
}

func newMockKeychain() *mockKeychain {
	return &mockKeychain{
		keys: make(map[string]crypto.PrivateKey),
	}
}

func (mk *mockKeychain) addKey(keyID string, key crypto.PrivateKey) {
	mk.keys[keyID] = key
}

func (mk *mockKeychain) getKey(keyID string) (crypto.PrivateKey, error) {
	key, ok := mk.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return key, nil
}

func (mk *mockKeychain) getSigner(keyID string) (crypto.Signer, error) {
	key, err := mk.getKey(keyID)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key is not a crypto.Signer")
	}
	return signer, nil
}

// TestKeychainSigner_SignWithKeyID_RSA tests signing with RSA key from keychain
func TestKeychainSigner_SignWithKeyID_RSA(t *testing.T) {
	// Setup mock keychain
	keychain := newMockKeychain()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keychain.addKey("pkcs11:test-rsa", privateKey)

	// Create keychain signer
	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)

	// Create claims
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Sign with keychain
	tokenString, err := signer.SignWithKeyID("pkcs11:test-rsa", claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify kid is in header
	kid, err := ExtractKID(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "pkcs11:test-rsa", kid)

	// Verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestKeychainSigner_SignWithKeyID_ECDSA tests signing with ECDSA key from keychain
func TestKeychainSigner_SignWithKeyID_ECDSA(t *testing.T) {
	keychain := newMockKeychain()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keychain.addKey("tpm2:test-ecdsa", privateKey)

	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.SignWithKeyID("tpm2:test-ecdsa", claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestKeychainSigner_SignWithKeyID_Ed25519 tests signing with Ed25519 key from keychain
func TestKeychainSigner_SignWithKeyID_Ed25519(t *testing.T) {
	keychain := newMockKeychain()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keychain.addKey("software:test-ed25519", privateKey)

	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.SignWithKeyID("software:test-ed25519", claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestKeychainSigner_SignWithKeyIDAndAlgorithm tests explicit algorithm specification
func TestKeychainSigner_SignWithKeyIDAndAlgorithm(t *testing.T) {
	keychain := newMockKeychain()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keychain.addKey("pkcs11:test-rsa", privateKey)

	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Sign with RS512 explicitly
	tokenString, err := signer.SignWithKeyIDAndAlgorithm("pkcs11:test-rsa", claims, RS512)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the algorithm
		assert.Equal(t, "RS512", token.Method.Alg())
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestKeychainSigner_KeyNotFound tests error when key doesn't exist
func TestKeychainSigner_KeyNotFound(t *testing.T) {
	keychain := newMockKeychain()
	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err := signer.SignWithKeyID("nonexistent:key", claims)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// TestKeychainVerifier_VerifyWithKeyID tests verification with keychain
func TestKeychainVerifier_VerifyWithKeyID(t *testing.T) {
	// Setup
	keychain := newMockKeychain()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keychain.addKey("pkcs11:test-key", privateKey)

	// Sign a token
	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tokenString, err := signer.SignWithKeyID("pkcs11:test-key", claims)
	require.NoError(t, err)

	// Verify with keychain
	verifier := NewKeychainVerifier(keychain.getKey)
	token, err := verifier.VerifyWithKeyID(tokenString, "pkcs11:test-key")
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestKeychainVerifier_VerifyWithAutoKeyID tests auto-extraction of kid
func TestKeychainVerifier_VerifyWithAutoKeyID(t *testing.T) {
	// Setup
	keychain := newMockKeychain()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keychain.addKey("tpm2:signing-key", privateKey)

	// Sign a token
	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tokenString, err := signer.SignWithKeyID("tpm2:signing-key", claims)
	require.NoError(t, err)

	// Verify with auto kid extraction
	verifier := NewKeychainVerifier(keychain.getKey)
	token, err := verifier.VerifyWithAutoKeyID(tokenString)
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestKeychainVerifier_VerifyWithAutoKeyID_NoKID tests error when no kid present
func TestKeychainVerifier_VerifyWithAutoKeyID_NoKID(t *testing.T) {
	keychain := newMockKeychain()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Sign token without kid
	standardSigner := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tokenString, err := standardSigner.Sign(privateKey, claims)
	require.NoError(t, err)

	// Try to verify with auto kid (should fail)
	verifier := NewKeychainVerifier(keychain.getKey)
	_, err = verifier.VerifyWithAutoKeyID(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kid")
}

// TestKeychainVerifier_VerifyWithJWK tests verification with JWK
func TestKeychainVerifier_VerifyWithJWK(t *testing.T) {
	// Generate key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from public key
	pubJWK, err := jwk.FromPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	pubJWK.Kid = "test-key"

	// Sign token
	standardSigner := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tokenString, err := standardSigner.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with JWK
	keychain := newMockKeychain()
	verifier := NewKeychainVerifier(keychain.getKey)
	token, err := verifier.VerifyWithJWK(tokenString, pubJWK)
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestKeychainVerifier_VerifyWithWrongKey tests verification failure with wrong key
func TestKeychainVerifier_VerifyWithWrongKey(t *testing.T) {
	// Setup with two different keys
	keychain := newMockKeychain()
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keychain.addKey("key1", privateKey1)
	keychain.addKey("key2", privateKey2)

	// Sign with key1
	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tokenString, err := signer.SignWithKeyID("key1", claims)
	require.NoError(t, err)

	// Try to verify with key2 (should fail)
	verifier := NewKeychainVerifier(keychain.getKey)
	_, err = verifier.VerifyWithKeyID(tokenString, "key2")
	assert.Error(t, err)
}

// TestRoundTrip_AllAlgorithms tests signing and verification for all algorithms
func TestRoundTrip_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		keyID  string
		keyGen func() crypto.PrivateKey
	}{
		{
			name:  "RSA-2048",
			keyID: "pkcs11:rsa-key",
			keyGen: func() crypto.PrivateKey {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key
			},
		},
		{
			name:  "ECDSA-P256",
			keyID: "tpm2:p256-key",
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key
			},
		},
		{
			name:  "ECDSA-P384",
			keyID: "software:p384-key",
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return key
			},
		},
		{
			name:  "ECDSA-P521",
			keyID: "awskms:p521-key",
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return key
			},
		},
		{
			name:  "Ed25519",
			keyID: "vault:ed25519-key",
			keyGen: func() crypto.PrivateKey {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				return key
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup keychain
			keychain := newMockKeychain()
			key := tt.keyGen()
			keychain.addKey(tt.keyID, key)

			// Sign
			signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)
			claims := jwt.MapClaims{
				"sub": "test-user",
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(time.Hour).Unix(),
			}
			tokenString, err := signer.SignWithKeyID(tt.keyID, claims)
			require.NoError(t, err)

			// Verify with auto kid
			verifier := NewKeychainVerifier(keychain.getKey)
			token, err := verifier.VerifyWithAutoKeyID(tokenString)
			require.NoError(t, err)
			assert.True(t, token.Valid)

			// Verify kid matches
			extractedKID, err := ExtractKID(tokenString)
			require.NoError(t, err)
			assert.Equal(t, tt.keyID, extractedKID)
		})
	}
}

// TestParseAlgorithm tests algorithm string parsing
func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected Algorithm
		wantErr  bool
	}{
		{"RS256", RS256, false},
		{"rs256", RS256, false},
		{"ES256", ES256, false},
		{"EdDSA", EdDSA, false},
		{"eddsa", EdDSA, false},
		{"PS512", PS512, false},
		{"INVALID", "", true},
		{"HS256", "", true}, // Not supported
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			alg, err := ParseAlgorithm(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, alg)
			}
		})
	}
}

// TestKeychainSigner_SignWithKeyID_InvalidAlgorithm tests error when algorithm detection fails
func TestKeychainSigner_SignWithKeyID_InvalidAlgorithm(t *testing.T) {
	keychain := newMockKeychain()

	// Add an invalid key type (byte slice)
	keychain.keys["invalid:key"] = []byte("not-a-real-key")

	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err := signer.SignWithKeyID("invalid:key", claims)
	assert.Error(t, err)
}

// TestKeychainVerifier_VerifyWithKeyID_KeyError tests error when getting key fails
func TestKeychainVerifier_VerifyWithKeyID_KeyError(t *testing.T) {
	keychain := newMockKeychain()
	verifier := NewKeychainVerifier(keychain.getKey)

	_, err := verifier.VerifyWithKeyID("fake-token", "nonexistent:key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// TestKeychainVerifier_VerifyWithJWK_InvalidJWK tests error with invalid JWK
func TestKeychainVerifier_VerifyWithJWK_InvalidJWK(t *testing.T) {
	keychain := newMockKeychain()
	verifier := NewKeychainVerifier(keychain.getKey)

	// Create invalid JWK (missing required fields)
	invalidJWK := &jwk.JWK{
		Kty: "RSA",
		// Missing N and E
	}

	_, err := verifier.VerifyWithJWK("fake-token", invalidJWK)
	assert.Error(t, err)
}

// TestSigningMethodFromPublicKey_UnsupportedType tests error with unsupported public key
func TestSigningMethodFromPublicKey_UnsupportedType(t *testing.T) {
	// This tests the default case in signingMethodFromPublicKey
	_, err := signingMethodFromPublicKey("not-a-public-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported public key type")
}

// TestKeychainSigner_SignWithKeyIDAndAlgorithm_KeyNotFound tests error when key not found
func TestKeychainSigner_SignWithKeyIDAndAlgorithm_KeyNotFound(t *testing.T) {
	keychain := newMockKeychain()
	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err := signer.SignWithKeyIDAndAlgorithm("nonexistent:key", claims, RS256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// TestKeychainSigner_SignWithKeyIDAndAlgorithm_InvalidAlgorithm tests error with invalid algorithm
func TestKeychainSigner_SignWithKeyIDAndAlgorithm_InvalidAlgorithm(t *testing.T) {
	keychain := newMockKeychain()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keychain.addKey("test:key", privateKey)

	signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err = signer.SignWithKeyIDAndAlgorithm("test:key", claims, Algorithm("INVALID"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

// TestKeychainVerifier_VerifyWithKeyID_InvalidToken tests verification with invalid token
func TestKeychainVerifier_VerifyWithKeyID_InvalidToken(t *testing.T) {
	keychain := newMockKeychain()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keychain.addKey("test:key", privateKey)

	verifier := NewKeychainVerifier(keychain.getKey)

	_, err = verifier.VerifyWithKeyID("invalid.token.string", "test:key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify token")
}

// TestKeychainVerifier_VerifyWithAutoKeyID_InvalidToken tests auto verification with invalid token
func TestKeychainVerifier_VerifyWithAutoKeyID_InvalidToken(t *testing.T) {
	keychain := newMockKeychain()
	verifier := NewKeychainVerifier(keychain.getKey)

	_, err := verifier.VerifyWithAutoKeyID("invalid.token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract kid")
}

// TestKeychainVerifier_VerifyWithJWK_InvalidToken tests JWK verification with invalid token
func TestKeychainVerifier_VerifyWithJWK_InvalidToken(t *testing.T) {
	keychain := newMockKeychain()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create valid JWK
	pubJWK, err := jwk.FromPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	verifier := NewKeychainVerifier(keychain.getKey)

	_, err = verifier.VerifyWithJWK("invalid.token", pubJWK)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify token")
}

// TestSigningMethodFromPublicKey_AllKeyTypes tests algorithm detection for all public key types
func TestSigningMethodFromPublicKey_AllKeyTypes(t *testing.T) {
	tests := []struct {
		name     string
		keyGen   func() crypto.PublicKey
		expected Algorithm
	}{
		{
			name: "RSA",
			keyGen: func() crypto.PublicKey {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return &key.PublicKey
			},
			expected: RS256,
		},
		{
			name: "ECDSA-P256",
			keyGen: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &key.PublicKey
			},
			expected: ES256,
		},
		{
			name: "ECDSA-P384",
			keyGen: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return &key.PublicKey
			},
			expected: ES384,
		},
		{
			name: "ECDSA-P521",
			keyGen: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return &key.PublicKey
			},
			expected: ES512,
		},
		{
			name: "Ed25519",
			keyGen: func() crypto.PublicKey {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				return pub
			},
			expected: EdDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey := tt.keyGen()
			alg, err := signingMethodFromPublicKey(pubKey)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, alg)
		})
	}
}

// TestKeychainVerifier_VerifyWithKeyID_NonSignerKey tests error when key doesn't expose public key
func TestKeychainVerifier_VerifyWithKeyID_NonSignerKey(t *testing.T) {
	keychain := newMockKeychain()

	// Add a key that doesn't implement the Public() method
	keychain.keys["invalid:key"] = "not-a-crypto-key"

	verifier := NewKeychainVerifier(keychain.getKey)

	_, err := verifier.VerifyWithKeyID("fake-token", "invalid:key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not expose public key")
}

// TestKeychainSigner_ECDSA_AllCurves tests signing with all ECDSA curves
func TestKeychainSigner_ECDSA_AllCurves(t *testing.T) {
	tests := []struct {
		name     string
		curve    elliptic.Curve
		expected Algorithm
	}{
		{"P256", elliptic.P256(), ES256},
		{"P384", elliptic.P384(), ES384},
		{"P521", elliptic.P521(), ES512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keychain := newMockKeychain()
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)
			keyID := fmt.Sprintf("test:%s", tt.name)
			keychain.addKey(keyID, privateKey)

			signer := NewKeychainSigner(keychain.getKey, keychain.getSigner)

			claims := jwt.MapClaims{
				"sub": "test-user",
				"exp": time.Now().Add(time.Hour).Unix(),
			}

			tokenString, err := signer.SignWithKeyID(keyID, claims)
			require.NoError(t, err)
			assert.NotEmpty(t, tokenString)

			// Verify the token
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return &privateKey.PublicKey, nil
			})
			require.NoError(t, err)
			assert.True(t, token.Valid)

			// Verify the algorithm
			assert.Equal(t, string(tt.expected), token.Method.Alg())
		})
	}
}
