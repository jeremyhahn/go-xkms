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

package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock keychain getter functions for testing
var (
	testRSAKey, _  = rsa.GenerateKey(rand.Reader, 2048)
	testECKey, _   = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	errKeyNotFound = errors.New("key not found")
)

// TestFromKeychain tests creating a JWK from a keychain key.
func TestFromKeychain(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		getKeyFunc  KeychainKeyGetter
		expectError bool
		validate    func(*testing.T, *JWK)
	}{
		{
			name:  "valid RSA key",
			keyID: "pkcs11:test-rsa-key",
			getKeyFunc: func(keyID string) (crypto.PrivateKey, error) {
				return testRSAKey, nil
			},
			expectError: false,
			validate: func(t *testing.T, jwk *JWK) {
				assert.Equal(t, "pkcs11:test-rsa-key", jwk.Kid)
				assert.Equal(t, string(KeyTypeRSA), jwk.Kty)
				assert.Equal(t, "sig", jwk.Use)
				assert.NotEmpty(t, jwk.N, "RSA modulus should be set")
				assert.NotEmpty(t, jwk.E, "RSA exponent should be set")
				assert.Empty(t, jwk.D, "Private exponent should NOT be set")
				assert.Empty(t, jwk.P, "Prime P should NOT be set")
				assert.Empty(t, jwk.Q, "Prime Q should NOT be set")
			},
		},
		{
			name:  "valid ECDSA key",
			keyID: "tpm2:test-ec-key",
			getKeyFunc: func(keyID string) (crypto.PrivateKey, error) {
				return testECKey, nil
			},
			expectError: false,
			validate: func(t *testing.T, jwk *JWK) {
				assert.Equal(t, "tpm2:test-ec-key", jwk.Kid)
				assert.Equal(t, string(KeyTypeEC), jwk.Kty)
				assert.Equal(t, "sig", jwk.Use)
				assert.Equal(t, string(CurveP256), jwk.Crv)
				assert.NotEmpty(t, jwk.X, "EC X coordinate should be set")
				assert.NotEmpty(t, jwk.Y, "EC Y coordinate should be set")
				assert.Empty(t, jwk.D, "Private key should NOT be set")
			},
		},
		{
			name:  "empty key ID",
			keyID: "",
			getKeyFunc: func(keyID string) (crypto.PrivateKey, error) {
				return testRSAKey, nil
			},
			expectError: true,
		},
		{
			name:  "key not found",
			keyID: "pkcs11:nonexistent",
			getKeyFunc: func(keyID string) (crypto.PrivateKey, error) {
				return nil, errKeyNotFound
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwk, err := FromKeychain(tt.keyID, tt.getKeyFunc)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, jwk)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, jwk)

			if tt.validate != nil {
				tt.validate(t, jwk)
			}
		})
	}
}

// TestLoadKeyFromKeychain tests loading a key from keychain using JWK kid.
func TestLoadKeyFromKeychain(t *testing.T) {
	tests := []struct {
		name        string
		jwk         *JWK
		getKeyFunc  KeychainKeyGetter
		expectError bool
		expectedKey crypto.PrivateKey
	}{
		{
			name: "valid key loading",
			jwk:  &JWK{Kid: "pkcs8:my-key"},
			getKeyFunc: func(keyID string) (crypto.PrivateKey, error) {
				if keyID == "pkcs8:my-key" {
					return testRSAKey, nil
				}
				return nil, errKeyNotFound
			},
			expectError: false,
			expectedKey: testRSAKey,
		},
		{
			name:        "empty kid",
			jwk:         &JWK{},
			getKeyFunc:  nil,
			expectError: true,
		},
		{
			name: "invalid kid format",
			jwk:  &JWK{Kid: "invalid-key-id"},
			getKeyFunc: func(keyID string) (crypto.PrivateKey, error) {
				return testRSAKey, nil
			},
			expectError: true,
		},
		{
			name: "key not found in keychain",
			jwk:  &JWK{Kid: "pkcs11:missing-key"},
			getKeyFunc: func(keyID string) (crypto.PrivateKey, error) {
				return nil, errKeyNotFound
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.jwk.LoadKeyFromKeychain(tt.getKeyFunc)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, key)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, key)
			if tt.expectedKey != nil {
				assert.Equal(t, tt.expectedKey, key)
			}
		})
	}
}

// TestIsKeychainBacked tests the IsKeychainBacked method.
func TestIsKeychainBacked(t *testing.T) {
	tests := []struct {
		name     string
		jwk      *JWK
		expected bool
	}{
		{
			name:     "pkcs8 backend",
			jwk:      &JWK{Kid: "pkcs8:my-key"},
			expected: true,
		},
		{
			name:     "pkcs11 backend",
			jwk:      &JWK{Kid: "pkcs11:hsm-key"},
			expected: true,
		},
		{
			name:     "tpm2 backend",
			jwk:      &JWK{Kid: "tpm2:attestation"},
			expected: true,
		},
		{
			name:     "awskms backend",
			jwk:      &JWK{Kid: "awskms:prod-key"},
			expected: true,
		},
		{
			name:     "gcpkms backend",
			jwk:      &JWK{Kid: "gcpkms:signing-key"},
			expected: true,
		},
		{
			name:     "azurekv backend",
			jwk:      &JWK{Kid: "azurekv:master-key"},
			expected: true,
		},
		{
			name:     "vault backend",
			jwk:      &JWK{Kid: "vault:transit-key"},
			expected: true,
		},
		{
			name:     "aes backend",
			jwk:      &JWK{Kid: "aes:symmetric-key"},
			expected: true,
		},
		{
			name:     "software backend",
			jwk:      &JWK{Kid: "software:dev-key"},
			expected: true,
		},
		{
			name:     "empty kid",
			jwk:      &JWK{Kid: ""},
			expected: false,
		},
		{
			name:     "no kid",
			jwk:      &JWK{},
			expected: false,
		},
		{
			name:     "invalid format - no colon",
			jwk:      &JWK{Kid: "invalid"},
			expected: false,
		},
		{
			name:     "invalid format - multiple colons",
			jwk:      &JWK{Kid: "pkcs8:my:key"},
			expected: false,
		},
		{
			name:     "unknown backend",
			jwk:      &JWK{Kid: "unknown:my-key"},
			expected: false,
		},
		{
			name:     "random key id",
			jwk:      &JWK{Kid: "random-key-identifier-123"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.jwk.IsKeychainBacked()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestToKeychainSigner tests getting a signer from a keychain-backed JWK.
func TestToKeychainSigner(t *testing.T) {
	tests := []struct {
		name           string
		jwk            *JWK
		getSignerFunc  KeychainSignerGetter
		expectError    bool
		expectedSigner crypto.Signer
	}{
		{
			name: "valid keychain-backed JWK",
			jwk:  &JWK{Kid: "pkcs11:signing-key"},
			getSignerFunc: func(keyID string) (crypto.Signer, error) {
				if keyID == "pkcs11:signing-key" {
					return testRSAKey, nil
				}
				return nil, errKeyNotFound
			},
			expectError:    false,
			expectedSigner: testRSAKey,
		},
		{
			name: "not keychain-backed",
			jwk:  &JWK{Kid: "random-id"},
			getSignerFunc: func(keyID string) (crypto.Signer, error) {
				return testRSAKey, nil
			},
			expectError: true,
		},
		{
			name: "signer not found",
			jwk:  &JWK{Kid: "pkcs11:missing"},
			getSignerFunc: func(keyID string) (crypto.Signer, error) {
				return nil, errKeyNotFound
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := tt.jwk.ToKeychainSigner(tt.getSignerFunc)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, signer)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, signer)
			if tt.expectedSigner != nil {
				assert.Equal(t, tt.expectedSigner, signer)
			}
		})
	}
}

// TestJWK_RoundTrip tests creating a JWK from keychain and loading it back.
func TestJWK_RoundTrip(t *testing.T) {
	keyID := "pkcs8:roundtrip-test"

	// Create JWK from keychain
	jwk, err := FromKeychain(keyID, func(kid string) (crypto.PrivateKey, error) {
		return testRSAKey, nil
	})
	require.NoError(t, err)
	require.NotNil(t, jwk)

	// Verify JWK properties
	assert.Equal(t, keyID, jwk.Kid)
	assert.True(t, jwk.IsKeychainBacked())

	// Serialize to JSON
	jwkJSON, err := jwk.Marshal()
	require.NoError(t, err)

	// Deserialize from JSON
	jwk2, err := Unmarshal(jwkJSON)
	require.NoError(t, err)

	// Verify deserialized JWK
	assert.Equal(t, jwk.Kid, jwk2.Kid)
	assert.Equal(t, jwk.Kty, jwk2.Kty)
	assert.Equal(t, jwk.N, jwk2.N)
	assert.Equal(t, jwk.E, jwk2.E)
	assert.True(t, jwk2.IsKeychainBacked())

	// Load key from deserialized JWK
	key, err := jwk2.LoadKeyFromKeychain(func(kid string) (crypto.PrivateKey, error) {
		if kid == keyID {
			return testRSAKey, nil
		}
		return nil, errKeyNotFound
	})
	require.NoError(t, err)
	assert.Equal(t, testRSAKey, key)
}

// TestJWK_NoPrivateKeyMaterial ensures keychain JWKs don't contain private key material.
func TestJWK_NoPrivateKeyMaterial(t *testing.T) {
	tests := []struct {
		name  string
		keyID string
		key   crypto.PrivateKey
	}{
		{
			name:  "RSA key",
			keyID: "pkcs8:rsa-test",
			key:   testRSAKey,
		},
		{
			name:  "ECDSA key",
			keyID: "pkcs8:ec-test",
			key:   testECKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwk, err := FromKeychain(tt.keyID, func(kid string) (crypto.PrivateKey, error) {
				return tt.key, nil
			})
			require.NoError(t, err)

			// Verify NO private key material
			assert.Empty(t, jwk.D, "Private exponent D should be empty")
			assert.Empty(t, jwk.P, "Prime P should be empty")
			assert.Empty(t, jwk.Q, "Prime Q should be empty")
			assert.Empty(t, jwk.DP, "DP should be empty")
			assert.Empty(t, jwk.DQ, "DQ should be empty")
			assert.Empty(t, jwk.QI, "QI should be empty")
			assert.Empty(t, jwk.K, "Symmetric key should be empty")
		})
	}
}
