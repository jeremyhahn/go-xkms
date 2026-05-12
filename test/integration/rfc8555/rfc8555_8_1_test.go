// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rfc8555

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyAuthorization_Format tests key authorization string format
func TestKeyAuthorization_Format(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "test_token_12345"
	keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	// Key authorization should be: token || '.' || base64url(Thumbprint(accountKey))
	thumbprint, err := handlers.JWKThumbprint(privateKey.Public())
	require.NoError(t, err)

	expected := token + "." + thumbprint
	assert.Equal(t, expected, keyAuth)
}

// TestKeyAuthorization_TokenFormat tests challenge token format
func TestKeyAuthorization_TokenFormat(t *testing.T) {
	// Tokens should be base64url encoded
	token, err := handlers.GenerateToken()
	require.NoError(t, err)

	// Should be valid base64url
	_, decodeErr := base64.RawURLEncoding.DecodeString(token)
	assert.NoError(t, decodeErr)

	// Should not contain non-URL-safe characters
	assert.NotContains(t, token, "+")
	assert.NotContains(t, token, "/")
	assert.NotContains(t, token, "=")
}

// TestKeyAuthorization_RSA tests key authorization with RSA keys
func TestKeyAuthorization_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "rsa_token_test"
	keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	assert.Contains(t, keyAuth, token)
	assert.Contains(t, keyAuth, ".")

	// Verify format: token.thumbprint
	parts := keyAuth[len(token):]
	assert.True(t, len(parts) > 1)
	assert.Equal(t, ".", string(parts[0]))
}

// TestKeyAuthorization_ECDSA tests key authorization with ECDSA keys
func TestKeyAuthorization_ECDSA(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			token := "ecdsa_token_test"
			keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
			require.NoError(t, err)

			assert.Contains(t, keyAuth, token)
			assert.Contains(t, keyAuth, ".")
		})
	}
}

// TestKeyAuthorization_Deterministic tests that key authorization is deterministic
func TestKeyAuthorization_Deterministic(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "deterministic_test"

	// Generate twice
	keyAuth1, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	keyAuth2, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	// Should be identical
	assert.Equal(t, keyAuth1, keyAuth2)
}

// TestKeyAuthorization_DifferentTokens tests different tokens produce different key auths
func TestKeyAuthorization_DifferentTokens(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token1 := "token_one"
	token2 := "token_two"

	keyAuth1, err := handlers.KeyAuthorization(token1, privateKey.Public())
	require.NoError(t, err)

	keyAuth2, err := handlers.KeyAuthorization(token2, privateKey.Public())
	require.NoError(t, err)

	// Should be different (different tokens)
	assert.NotEqual(t, keyAuth1, keyAuth2)

	// But should have same thumbprint part
	thumbprint, err := handlers.JWKThumbprint(privateKey.Public())
	require.NoError(t, err)

	assert.Contains(t, keyAuth1, thumbprint)
	assert.Contains(t, keyAuth2, thumbprint)
}

// TestKeyAuthorization_DifferentKeys tests different keys produce different key auths
func TestKeyAuthorization_DifferentKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "same_token"

	keyAuth1, err := handlers.KeyAuthorization(token, key1.Public())
	require.NoError(t, err)

	keyAuth2, err := handlers.KeyAuthorization(token, key2.Public())
	require.NoError(t, err)

	// Should be different (different keys)
	assert.NotEqual(t, keyAuth1, keyAuth2)

	// Both should start with same token
	assert.Contains(t, keyAuth1, token)
	assert.Contains(t, keyAuth2, token)
}

// TestKeyAuthorization_SHA256Hash tests that DNS-01 uses SHA-256 of key authorization
func TestKeyAuthorization_SHA256Hash(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "dns_test_token"
	keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	// For DNS-01 challenge, compute SHA-256 hash
	hash := sha256.Sum256([]byte(keyAuth))
	dnsValue := base64.RawURLEncoding.EncodeToString(hash[:])

	assert.NotEmpty(t, dnsValue)
	assert.NotEqual(t, keyAuth, dnsValue)

	// Verify it's valid base64url
	_, err = base64.RawURLEncoding.DecodeString(dnsValue)
	assert.NoError(t, err)
}

// TestKeyAuthorization_HTTP01 tests key authorization for HTTP-01 challenge
func TestKeyAuthorization_HTTP01(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "http01_token"
	keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	// HTTP-01 uses key authorization directly (not hashed)
	// Should be served at: http://<domain>/.well-known/acme-challenge/<token>
	// Content should be: <keyAuthorization>

	assert.NotEmpty(t, keyAuth)
	assert.Contains(t, keyAuth, token)
}

// TestKeyAuthorization_EmptyToken tests error handling for empty token
func TestKeyAuthorization_EmptyToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Empty token should still work (though not practical)
	token := ""
	keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	// Should just be ".thumbprint"
	thumbprint, err := handlers.JWKThumbprint(privateKey.Public())
	require.NoError(t, err)

	assert.Equal(t, "."+thumbprint, keyAuth)
}

// TestKeyAuthorization_SpecialCharacters tests tokens with special characters
func TestKeyAuthorization_SpecialCharacters(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Token should be base64url, but test various inputs
	testTokens := []string{
		"simple",
		"with-dash",
		"with_underscore",
		"MixedCase123",
		"base64url-safe_chars",
	}

	for _, token := range testTokens {
		t.Run(token, func(t *testing.T) {
			keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
			require.NoError(t, err)
			assert.Contains(t, keyAuth, token)
		})
	}
}

// TestKeyAuthorization_Length tests key authorization length
func TestKeyAuthorization_Length(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "length_test_token"
	keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	// Should be longer than just the token
	assert.Greater(t, len(keyAuth), len(token))

	// Should include token + "." + thumbprint
	thumbprint, err := handlers.JWKThumbprint(privateKey.Public())
	require.NoError(t, err)

	expectedLength := len(token) + 1 + len(thumbprint)
	assert.Equal(t, expectedLength, len(keyAuth))
}
