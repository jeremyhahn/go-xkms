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
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJWKThumbprint_RSA tests JWK thumbprint generation for RSA keys per RFC 7638
func TestJWKThumbprint_RSA(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	thumbprint, err := handlers.JWKThumbprint(privateKey.Public())
	require.NoError(t, err)
	assert.NotEmpty(t, thumbprint)

	// Verify thumbprint is base64url encoded
	_, err = base64.RawURLEncoding.DecodeString(thumbprint)
	assert.NoError(t, err)

	// Thumbprint should be deterministic
	thumbprint2, err := handlers.JWKThumbprint(privateKey.Public())
	require.NoError(t, err)
	assert.Equal(t, thumbprint, thumbprint2)
}

// TestJWKThumbprint_ECDSA tests JWK thumbprint generation for ECDSA keys
func TestJWKThumbprint_ECDSA(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			thumbprint, err := handlers.JWKThumbprint(privateKey.Public())
			require.NoError(t, err)
			assert.NotEmpty(t, thumbprint)

			// Verify base64url encoding
			_, err = base64.RawURLEncoding.DecodeString(thumbprint)
			assert.NoError(t, err)

			// Verify deterministic behavior
			thumbprint2, err := handlers.JWKThumbprint(privateKey.Public())
			require.NoError(t, err)
			assert.Equal(t, thumbprint, thumbprint2)
		})
	}
}

// TestKeyAuthorization tests key authorization string generation for challenges
func TestKeyAuthorization(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := "test_token_12345"
	keyAuth, err := handlers.KeyAuthorization(token, privateKey.Public())
	require.NoError(t, err)

	// Key authorization should be token.thumbprint
	thumbprint, err := handlers.JWKThumbprint(privateKey.Public())
	require.NoError(t, err)

	expected := token + "." + thumbprint
	assert.Equal(t, expected, keyAuth)
}

// TestKeyAuthorization_InvalidKey tests error handling for unsupported key types
func TestKeyAuthorization_InvalidKey(t *testing.T) {
	token := "test_token"

	// Use an unsupported key type (string)
	_, err := handlers.KeyAuthorization(token, "invalid-key")
	assert.Error(t, err)
}

// TestAccountIDFromPublicKey tests deterministic account ID generation
func TestAccountIDFromPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	accountID, err := handlers.AccountIDFromPublicKey(privateKey.Public())
	require.NoError(t, err)
	assert.NotZero(t, accountID)

	// Verify deterministic behavior
	accountID2, err := handlers.AccountIDFromPublicKey(privateKey.Public())
	require.NoError(t, err)
	assert.Equal(t, accountID, accountID2)
}

// TestAccountIDFromPublicKey_DifferentKeys tests that different keys produce different IDs
func TestAccountIDFromPublicKey_DifferentKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	id1, err := handlers.AccountIDFromPublicKey(key1.Public())
	require.NoError(t, err)

	id2, err := handlers.AccountIDFromPublicKey(key2.Public())
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2)
}

// TestJWKCanonicalJSON tests that JWK is serialized in canonical form
func TestJWKCanonicalJSON(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKey := privateKey.Public().(*rsa.PublicKey)

	// Create JWK representation
	jwk := map[string]interface{}{
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
	}

	// Serialize to JSON
	jwkJSON, err := json.Marshal(jwk)
	require.NoError(t, err)

	// Verify it's valid JSON
	var decoded map[string]interface{}
	err = json.Unmarshal(jwkJSON, &decoded)
	assert.NoError(t, err)

	// Verify required fields
	assert.Equal(t, "RSA", decoded["kty"])
	assert.NotEmpty(t, decoded["n"])
	assert.NotEmpty(t, decoded["e"])
}

// TestJWKThumbprint_SHA256 tests that thumbprint uses SHA-256
func TestJWKThumbprint_SHA256(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	thumbprint, err := handlers.JWKThumbprint(privateKey.Public())
	require.NoError(t, err)

	// Decode thumbprint
	decoded, err := base64.RawURLEncoding.DecodeString(thumbprint)
	require.NoError(t, err)

	// SHA-256 produces 32 bytes
	assert.Equal(t, sha256.Size, len(decoded))
}
