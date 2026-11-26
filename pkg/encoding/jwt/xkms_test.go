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

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-xkms/pkg/encoding/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock xkms for testing
type mockXKMS struct {
	keys map[string]crypto.PrivateKey
}

func newMockXKMS() *mockXKMS {
	return &mockXKMS{
		keys: make(map[string]crypto.PrivateKey),
	}
}

func (mk *mockXKMS) addKey(keyID string, key crypto.PrivateKey) {
	mk.keys[keyID] = key
}

func (mk *mockXKMS) getKey(keyID string) (crypto.PrivateKey, error) {
	key, ok := mk.keys[keyID]
	if !ok {
		return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", keyID)}
	}
	return key, nil
}

func (mk *mockXKMS) getSigner(keyID string) (crypto.Signer, error) {
	key, err := mk.getKey(keyID)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, &errs.Message{Msg: "key is not a crypto.Signer"}
	}
	return signer, nil
}

// TestXKMSSigner_SignWithKeyIDAndAlgorithm tests explicit algorithm specification
func TestXKMSSigner_SignWithKeyIDAndAlgorithm(t *testing.T) {
	xkms := newMockXKMS()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	xkms.addKey("pkcs11:test-rsa", privateKey)

	signer := NewXKMSSigner(xkms.getKey, xkms.getSigner)

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

// TestXKMSSigner_KeyNotFound tests error when key doesn't exist
func TestXKMSSigner_KeyNotFound(t *testing.T) {
	xkms := newMockXKMS()
	signer := NewXKMSSigner(xkms.getKey, xkms.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err := signer.SignWithKeyID("nonexistent:key", claims)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// TestXKMSVerifier_VerifyWithAutoKeyID_NoKID tests error when no kid present
func TestXKMSVerifier_VerifyWithAutoKeyID_NoKID(t *testing.T) {
	xkms := newMockXKMS()
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
	verifier := NewXKMSVerifier(xkms.getKey)
	_, err = verifier.VerifyWithAutoKeyID(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kid")
}

// TestXKMSVerifier_VerifyWithJWK tests verification with JWK
func TestXKMSVerifier_VerifyWithJWK(t *testing.T) {
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
	xkms := newMockXKMS()
	verifier := NewXKMSVerifier(xkms.getKey)
	token, err := verifier.VerifyWithJWK(tokenString, pubJWK)
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestXKMSVerifier_VerifyWithWrongKey tests verification failure with wrong key
func TestXKMSVerifier_VerifyWithWrongKey(t *testing.T) {
	// Setup with two different keys
	xkms := newMockXKMS()
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	xkms.addKey("key1", privateKey1)
	xkms.addKey("key2", privateKey2)

	// Sign with key1
	signer := NewXKMSSigner(xkms.getKey, xkms.getSigner)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tokenString, err := signer.SignWithKeyID("key1", claims)
	require.NoError(t, err)

	// Try to verify with key2 (should fail)
	verifier := NewXKMSVerifier(xkms.getKey)
	_, err = verifier.VerifyWithKeyID(tokenString, "key2")
	assert.Error(t, err)
}

// TestRoundTrip_AllAlgorithms tests signing and verification for all algorithms
func TestRoundTrip_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		keyID  string
		keyGen func() crypto.PrivateKey
		alg    Algorithm
	}{
		{
			name:  "RSA-2048",
			keyID: "pkcs11:rsa-key",
			alg:   RS256,
			keyGen: func() crypto.PrivateKey {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key
			},
		},
		{
			name:  "ECDSA-P256",
			keyID: "tpm2:p256-key",
			alg:   ES256,
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key
			},
		},
		{
			name:  "ECDSA-P384",
			keyID: "software:p384-key",
			alg:   ES384,
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return key
			},
		},
		{
			name:  "ECDSA-P521",
			keyID: "awskms:p521-key",
			alg:   ES512,
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return key
			},
		},
		{
			name:  "Ed25519",
			keyID: "vault:ed25519-key",
			alg:   EdDSA,
			keyGen: func() crypto.PrivateKey {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				return key
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup xkms
			xkms := newMockXKMS()
			key := tt.keyGen()
			xkms.addKey(tt.keyID, key)

			// Sign
			signer := NewXKMSSigner(xkms.getKey, xkms.getSigner)
			claims := jwt.MapClaims{
				"sub": "test-user",
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(time.Hour).Unix(),
			}
			tokenString, err := signer.SignWithKeyID(tt.keyID, claims)
			require.NoError(t, err)

			// Verify with auto kid
			verifier := NewXKMSVerifier(xkms.getKey)
			token, err := verifier.VerifyWithAutoKeyID(tokenString)
			require.NoError(t, err)
			assert.True(t, token.Valid)
			assert.Equal(t, string(tt.alg), token.Method.Alg())

			// Verify kid matches
			extractedKID, err := ExtractKID(tokenString)
			require.NoError(t, err)
			assert.Equal(t, tt.keyID, extractedKID)
		})
	}
}

// TestXKMSSigner_SignWithKeyID_InvalidAlgorithm tests error when algorithm detection fails
func TestXKMSSigner_SignWithKeyID_InvalidAlgorithm(t *testing.T) {
	xkms := newMockXKMS()

	// Add an invalid key type (byte slice)
	xkms.keys["invalid:key"] = []byte("not-a-real-key")

	signer := NewXKMSSigner(xkms.getKey, xkms.getSigner)
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err := signer.SignWithKeyID("invalid:key", claims)
	assert.Error(t, err)
}

// TestXKMSVerifier_VerifyWithKeyID_KeyError tests error when getting key fails
func TestXKMSVerifier_VerifyWithKeyID_KeyError(t *testing.T) {
	xkms := newMockXKMS()
	verifier := NewXKMSVerifier(xkms.getKey)

	_, err := verifier.VerifyWithKeyID("fake-token", "nonexistent:key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// TestXKMSVerifier_VerifyWithJWK_InvalidJWK tests error with invalid JWK
func TestXKMSVerifier_VerifyWithJWK_InvalidJWK(t *testing.T) {
	xkms := newMockXKMS()
	verifier := NewXKMSVerifier(xkms.getKey)

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

// TestXKMSSigner_SignWithKeyIDAndAlgorithm_KeyNotFound tests error when key not found
func TestXKMSSigner_SignWithKeyIDAndAlgorithm_KeyNotFound(t *testing.T) {
	xkms := newMockXKMS()
	signer := NewXKMSSigner(xkms.getKey, xkms.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err := signer.SignWithKeyIDAndAlgorithm("nonexistent:key", claims, RS256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// TestXKMSSigner_SignWithKeyIDAndAlgorithm_InvalidAlgorithm tests error with invalid algorithm
func TestXKMSSigner_SignWithKeyIDAndAlgorithm_InvalidAlgorithm(t *testing.T) {
	xkms := newMockXKMS()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	xkms.addKey("test:key", privateKey)

	signer := NewXKMSSigner(xkms.getKey, xkms.getSigner)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err = signer.SignWithKeyIDAndAlgorithm("test:key", claims, Algorithm("INVALID"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

// TestXKMSVerifier_VerifyWithKeyID_InvalidToken tests verification with invalid token
func TestXKMSVerifier_VerifyWithKeyID_InvalidToken(t *testing.T) {
	xkms := newMockXKMS()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	xkms.addKey("test:key", privateKey)

	verifier := NewXKMSVerifier(xkms.getKey)

	_, err = verifier.VerifyWithKeyID("invalid.token.string", "test:key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify token")
}

// TestXKMSVerifier_VerifyWithAutoKeyID_InvalidToken tests auto verification with invalid token
func TestXKMSVerifier_VerifyWithAutoKeyID_InvalidToken(t *testing.T) {
	xkms := newMockXKMS()
	verifier := NewXKMSVerifier(xkms.getKey)

	_, err := verifier.VerifyWithAutoKeyID("invalid.token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract kid")
}

// TestXKMSVerifier_VerifyWithJWK_InvalidToken tests JWK verification with invalid token
func TestXKMSVerifier_VerifyWithJWK_InvalidToken(t *testing.T) {
	xkms := newMockXKMS()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create valid JWK
	pubJWK, err := jwk.FromPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	verifier := NewXKMSVerifier(xkms.getKey)

	_, err = verifier.VerifyWithJWK("invalid.token", pubJWK)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify token")
}

// TestXKMSVerifier_VerifyWithKeyID_NonSignerKey tests error when key doesn't expose public key
func TestXKMSVerifier_VerifyWithKeyID_NonSignerKey(t *testing.T) {
	xkms := newMockXKMS()

	// Add a key that doesn't implement the Public() method
	xkms.keys["invalid:key"] = "not-a-crypto-key"

	verifier := NewXKMSVerifier(xkms.getKey)

	_, err := verifier.VerifyWithKeyID("fake-token", "invalid:key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not expose public key")
}
