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

//go:build integration
// +build integration

package integration

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJWKIntegration_KeychainIntegration tests JWK integration with keychain backend
func TestJWKIntegration_KeychainIntegration(t *testing.T) {
	setup := createTestBackend(t)
	defer setup.Close()

	t.Run("RSA_KeychainBackedJWK", func(t *testing.T) {
		// Generate RSA key in backend
		// Use proper keychain Key ID format: "backend:keyname"
		keyID := "pkcs8:rsa-test-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// Create JWK from keychain key
		keychainJWK, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)
		assert.NotNil(t, keychainJWK)
		assert.Equal(t, keyID, keychainJWK.Kid)
		assert.Equal(t, "sig", keychainJWK.Use)
		assert.Equal(t, string(jwk.KeyTypeRSA), keychainJWK.Kty)
		assert.NotEmpty(t, keychainJWK.N)
		assert.NotEmpty(t, keychainJWK.E)
		assert.Empty(t, keychainJWK.D) // Should not expose private key

		// Verify IsKeychainBacked
		assert.True(t, keychainJWK.IsKeychainBacked())

		// Load key from keychain using JWK kid
		loadedKey, err := keychainJWK.LoadKeyFromKeychain(setup.GetKeyByID)
		require.NoError(t, err)
		assert.NotNil(t, loadedKey)

		// Verify it's an RSA key
		rsaKey, ok := loadedKey.(*rsa.PrivateKey)
		assert.True(t, ok)
		assert.NotNil(t, rsaKey)

		// Verify public key matches JWK
		pubJWK, err := jwk.FromPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)
		assert.Equal(t, keychainJWK.N, pubJWK.N)
		assert.Equal(t, keychainJWK.E, pubJWK.E)
	})

	t.Run("ECDSA_P256_KeychainBackedJWK", func(t *testing.T) {
		// Use proper keychain Key ID format: "backend:keyname"
		keyID := "pkcs8:ecdsa-p256-key"
		err := setup.GenerateECDSAKey(keyID, elliptic.P256())
		require.NoError(t, err)

		keychainJWK, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.KeyTypeEC), keychainJWK.Kty)
		assert.Equal(t, string(jwk.CurveP256), keychainJWK.Crv)
		assert.NotEmpty(t, keychainJWK.X)
		assert.NotEmpty(t, keychainJWK.Y)
		assert.Empty(t, keychainJWK.D)
		assert.True(t, keychainJWK.IsKeychainBacked())
	})

	t.Run("ECDSA_P384_KeychainBackedJWK", func(t *testing.T) {
		// Use proper keychain Key ID format: "backend:keyname"
		keyID := "pkcs8:ecdsa-p384-key"
		err := setup.GenerateECDSAKey(keyID, elliptic.P384())
		require.NoError(t, err)

		keychainJWK, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.KeyTypeEC), keychainJWK.Kty)
		assert.Equal(t, string(jwk.CurveP384), keychainJWK.Crv)
		assert.True(t, keychainJWK.IsKeychainBacked())
	})

	t.Run("ECDSA_P521_KeychainBackedJWK", func(t *testing.T) {
		// Use proper keychain Key ID format: "backend:keyname"
		keyID := "pkcs8:ecdsa-p521-key"
		err := setup.GenerateECDSAKey(keyID, elliptic.P521())
		require.NoError(t, err)

		keychainJWK, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.KeyTypeEC), keychainJWK.Kty)
		assert.Equal(t, string(jwk.CurveP521), keychainJWK.Crv)
		assert.True(t, keychainJWK.IsKeychainBacked())
	})

	t.Run("Ed25519_KeychainBackedJWK", func(t *testing.T) {
		// Use proper keychain Key ID format: "backend:keyname"
		keyID := "pkcs8:ed25519-key"
		err := setup.GenerateEd25519Key(keyID)
		require.NoError(t, err)

		keychainJWK, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.KeyTypeOKP), keychainJWK.Kty)
		assert.Equal(t, string(jwk.CurveEd25519), keychainJWK.Crv)
		assert.NotEmpty(t, keychainJWK.X)
		assert.Empty(t, keychainJWK.D)
		assert.True(t, keychainJWK.IsKeychainBacked())
	})
}

// TestJWKIntegration_AllKeyTypes tests all supported key types
func TestJWKIntegration_AllKeyTypes(t *testing.T) {
	t.Run("RSA_2048_RoundTrip", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Private key JWK
		privJWK, err := jwk.FromPrivateKey(privateKey)
		require.NoError(t, err)
		assert.True(t, privJWK.IsPrivate())
		assert.False(t, privJWK.IsPublic())

		// Public key JWK
		pubJWK, err := jwk.FromPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		assert.False(t, pubJWK.IsPrivate())
		assert.True(t, pubJWK.IsPublic())

		// Marshal and unmarshal
		jsonData, err := privJWK.Marshal()
		require.NoError(t, err)
		assert.NotEmpty(t, jsonData)

		recoveredJWK, err := jwk.Unmarshal(jsonData)
		require.NoError(t, err)
		assert.Equal(t, privJWK.Kty, recoveredJWK.Kty)
		assert.Equal(t, privJWK.N, recoveredJWK.N)
		assert.Equal(t, privJWK.E, recoveredJWK.E)
		assert.Equal(t, privJWK.D, recoveredJWK.D)

		// Convert back to key
		recoveredKey, err := recoveredJWK.ToPrivateKey()
		require.NoError(t, err)
		rsaKey, ok := recoveredKey.(*rsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, privateKey.N, rsaKey.N)
		assert.Equal(t, privateKey.E, rsaKey.E)
		assert.Equal(t, privateKey.D, rsaKey.D)
	})

	t.Run("RSA_4096_RoundTrip", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		require.NoError(t, err)

		jwkData, err := jwk.FromPrivateKey(privateKey)
		require.NoError(t, err)

		recoveredKey, err := jwkData.ToPrivateKey()
		require.NoError(t, err)

		rsaKey, ok := recoveredKey.(*rsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, privateKey.N.BitLen(), rsaKey.N.BitLen())
	})

	t.Run("ECDSA_P256_RoundTrip", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privJWK, err := jwk.FromPrivateKey(privateKey)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.CurveP256), privJWK.Crv)

		jsonData, err := privJWK.Marshal()
		require.NoError(t, err)

		recoveredJWK, err := jwk.Unmarshal(jsonData)
		require.NoError(t, err)

		recoveredKey, err := recoveredJWK.ToPrivateKey()
		require.NoError(t, err)

		ecKey, ok := recoveredKey.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, privateKey.X, ecKey.X)
		assert.Equal(t, privateKey.Y, ecKey.Y)
		assert.Equal(t, privateKey.D, ecKey.D)
	})

	t.Run("ECDSA_P384_RoundTrip", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		jwkData, err := jwk.FromPrivateKey(privateKey)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.CurveP384), jwkData.Crv)

		recoveredKey, err := jwkData.ToPrivateKey()
		require.NoError(t, err)

		ecKey, ok := recoveredKey.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, privateKey.Curve.Params().Name, ecKey.Curve.Params().Name)
	})

	t.Run("ECDSA_P521_RoundTrip", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		jwkData, err := jwk.FromPrivateKey(privateKey)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.CurveP521), jwkData.Crv)

		recoveredKey, err := jwkData.ToPrivateKey()
		require.NoError(t, err)

		ecKey, ok := recoveredKey.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, privateKey.Curve.Params().Name, ecKey.Curve.Params().Name)
	})

	t.Run("Ed25519_RoundTrip", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Private key
		privJWK, err := jwk.FromPrivateKey(priv)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.KeyTypeOKP), privJWK.Kty)
		assert.Equal(t, string(jwk.CurveEd25519), privJWK.Crv)
		assert.NotEmpty(t, privJWK.X)
		assert.NotEmpty(t, privJWK.D)

		// Public key
		pubJWK, err := jwk.FromPublicKey(pub)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.KeyTypeOKP), pubJWK.Kty)
		assert.Equal(t, string(jwk.CurveEd25519), pubJWK.Crv)
		assert.NotEmpty(t, pubJWK.X)
		assert.Empty(t, pubJWK.D)

		// Round trip
		recoveredKey, err := privJWK.ToPrivateKey()
		require.NoError(t, err)

		ed25519Key, ok := recoveredKey.(ed25519.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, len(priv), len(ed25519Key))
	})

	t.Run("X25519_RoundTrip", func(t *testing.T) {
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)

		privJWK, err := jwk.FromPrivateKey(privateKey)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.KeyTypeOKP), privJWK.Kty)
		assert.Equal(t, string(jwk.CurveX25519), privJWK.Crv)
		assert.NotEmpty(t, privJWK.X)
		assert.NotEmpty(t, privJWK.D)

		pubKey := privateKey.PublicKey()
		pubJWK, err := jwk.FromPublicKey(pubKey)
		require.NoError(t, err)
		assert.Equal(t, string(jwk.CurveX25519), pubJWK.Crv)
		assert.Empty(t, pubJWK.D)

		// Round trip
		recoveredKey, err := privJWK.ToPrivateKey()
		require.NoError(t, err)

		x25519Key, ok := recoveredKey.(*ecdh.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, string(privateKey.Bytes()), string(x25519Key.Bytes()))
	})

	t.Run("Symmetric_256bit_RoundTrip", func(t *testing.T) {
		keyBytes := make([]byte, 32) // 256-bit
		_, err := rand.Read(keyBytes)
		require.NoError(t, err)

		symJWK, err := jwk.FromSymmetricKey(keyBytes, "A256GCM")
		require.NoError(t, err)
		assert.Equal(t, string(jwk.KeyTypeOct), symJWK.Kty)
		assert.Equal(t, "A256GCM", symJWK.Alg)
		assert.NotEmpty(t, symJWK.K)
		assert.True(t, symJWK.IsSymmetric())
		assert.True(t, symJWK.IsPrivate())

		recoveredKey, err := symJWK.ToSymmetricKey()
		require.NoError(t, err)
		assert.Equal(t, keyBytes, recoveredKey)
	})

	t.Run("Symmetric_128bit_RoundTrip", func(t *testing.T) {
		keyBytes := make([]byte, 16) // 128-bit
		_, err := rand.Read(keyBytes)
		require.NoError(t, err)

		symJWK, err := jwk.FromSymmetricKey(keyBytes, "A128GCM")
		require.NoError(t, err)
		assert.Equal(t, "A128GCM", symJWK.Alg)

		recoveredKey, err := symJWK.ToSymmetricKey()
		require.NoError(t, err)
		assert.Equal(t, keyBytes, recoveredKey)
	})

	t.Run("Symmetric_192bit_RoundTrip", func(t *testing.T) {
		keyBytes := make([]byte, 24) // 192-bit
		_, err := rand.Read(keyBytes)
		require.NoError(t, err)

		symJWK, err := jwk.FromSymmetricKey(keyBytes, "A192GCM")
		require.NoError(t, err)

		recoveredKey, err := symJWK.ToSymmetricKey()
		require.NoError(t, err)
		assert.Equal(t, keyBytes, recoveredKey)
	})
}

// TestJWKIntegration_ErrorHandling tests error handling scenarios
func TestJWKIntegration_ErrorHandling(t *testing.T) {
	t.Run("InvalidKeyID", func(t *testing.T) {
		_, err := jwk.FromKeychain("", func(keyID string) (crypto.PrivateKey, error) {
			return nil, nil
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key ID cannot be empty")
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		_, err := jwk.FromKeychain("nonexistent-key", func(keyID string) (crypto.PrivateKey, error) {
			return nil, assert.AnError
		})
		assert.Error(t, err)
	})

	t.Run("EmptyKID_LoadFromKeychain", func(t *testing.T) {
		testJWK := &jwk.JWK{
			Kty: string(jwk.KeyTypeRSA),
			N:   "test",
			E:   "AQAB",
		}

		_, err := testJWK.LoadKeyFromKeychain(func(keyID string) (crypto.PrivateKey, error) {
			return nil, nil
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no kid field")
	})

	t.Run("InvalidKeyID_LoadFromKeychain", func(t *testing.T) {
		testJWK := &jwk.JWK{
			Kty: string(jwk.KeyTypeRSA),
			Kid: "invalid-format",
			N:   "test",
			E:   "AQAB",
		}

		_, err := testJWK.LoadKeyFromKeychain(func(keyID string) (crypto.PrivateKey, error) {
			return nil, nil
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid keychain Key ID")
	})

	t.Run("IsKeychainBacked_ValidBackends", func(t *testing.T) {
		backends := []string{
			"pkcs8", "aes", "software", "pkcs11", "tpm2",
			"awskms", "gcpkms", "azurekv", "vault",
		}

		for _, backend := range backends {
			testJWK := &jwk.JWK{
				Kid: backend + ":test-key",
			}
			assert.True(t, testJWK.IsKeychainBacked(), "Backend %s should be recognized", backend)
		}
	})

	t.Run("IsKeychainBacked_InvalidBackends", func(t *testing.T) {
		testCases := []string{
			"invalid:key",
			"nocolon",
			"",
			"too:many:colons",
		}

		for _, tc := range testCases {
			testJWK := &jwk.JWK{
				Kid: tc,
			}
			if tc == "invalid:key" {
				assert.False(t, testJWK.IsKeychainBacked(), "Invalid backend should not be recognized")
			} else {
				assert.False(t, testJWK.IsKeychainBacked(), "Invalid format should not be recognized: %s", tc)
			}
		}
	})

	t.Run("EmptySymmetricKey", func(t *testing.T) {
		_, err := jwk.FromSymmetricKey([]byte{}, "A256GCM")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be empty")
	})

	t.Run("ToSymmetricKey_WrongType", func(t *testing.T) {
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		rsaJWK, _ := jwk.FromPublicKey(&rsaKey.PublicKey)

		_, err := rsaJWK.ToSymmetricKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a symmetric key")
	})
}

// TestJWKIntegration_MarshalIndent tests formatted JSON output
func TestJWKIntegration_MarshalIndent(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkData, err := jwk.FromPrivateKey(privateKey)
	require.NoError(t, err)

	indentedJSON, err := jwkData.MarshalIndent("", "  ")
	require.NoError(t, err)
	assert.Contains(t, string(indentedJSON), "  ")
	assert.Contains(t, string(indentedJSON), "\"kty\"")
	assert.Contains(t, string(indentedJSON), "\"RSA\"")

	// Verify it can be unmarshaled
	recoveredJWK, err := jwk.Unmarshal(indentedJSON)
	require.NoError(t, err)
	assert.Equal(t, jwkData.Kty, recoveredJWK.Kty)
}

// TestJWKIntegration_ComplexScenarios tests complex real-world scenarios
func TestJWKIntegration_ComplexScenarios(t *testing.T) {
	t.Run("MultipleKeysInKeychain", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// Generate multiple keys with different types
		// Use proper keychain Key ID format: "backend:keyname"
		testKeys := []struct {
			cn      string
			keyType string
		}{
			{"pkcs8:rsa-key-1", "rsa"},
			{"pkcs8:rsa-key-2", "rsa"},
			{"pkcs8:ecdsa-key-1", "ecdsa"},
			{"pkcs8:ed25519-key-1", "ed25519"},
		}

		for _, tk := range testKeys {
			var err error
			switch tk.keyType {
			case "rsa":
				err = setup.GenerateRSAKey(tk.cn, 2048)
			case "ecdsa":
				err = setup.GenerateECDSAKey(tk.cn, elliptic.P256())
			case "ed25519":
				err = setup.GenerateEd25519Key(tk.cn)
			}
			require.NoError(t, err)
		}

		// Create JWKs for all keys
		jwks := make([]*jwk.JWK, len(testKeys))
		for i, tk := range testKeys {
			var err error
			jwks[i], err = jwk.FromKeychain(tk.cn, setup.GetKeyByID)
			require.NoError(t, err)
			assert.Equal(t, tk.cn, jwks[i].Kid)
			assert.True(t, jwks[i].IsKeychainBacked())
		}

		// Verify each JWK can load its corresponding key
		for i, testJWK := range jwks {
			key, err := testJWK.LoadKeyFromKeychain(setup.GetKeyByID)
			require.NoError(t, err)
			assert.NotNil(t, key)

			// Verify key type
			if i < 2 {
				_, ok := key.(*rsa.PrivateKey)
				assert.True(t, ok, "Expected RSA key for %s", testKeys[i].cn)
			} else if i == 2 {
				_, ok := key.(*ecdsa.PrivateKey)
				assert.True(t, ok, "Expected ECDSA key for %s", testKeys[i].cn)
			} else {
				_, ok := key.(ed25519.PrivateKey)
				assert.True(t, ok, "Expected Ed25519 key for %s", testKeys[i].cn)
			}
		}
	})

	t.Run("PublicKeyExport_PrivateKeySecrecy", func(t *testing.T) {
		// Ensure private keys aren't exposed in public JWKs
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Create public JWK
		pubJWK, err := jwk.FromPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)

		// Verify private fields are empty
		assert.Empty(t, pubJWK.D, "Public JWK should not contain D")
		assert.Empty(t, pubJWK.P, "Public JWK should not contain P")
		assert.Empty(t, pubJWK.Q, "Public JWK should not contain Q")
		assert.Empty(t, pubJWK.DP, "Public JWK should not contain DP")
		assert.Empty(t, pubJWK.DQ, "Public JWK should not contain DQ")
		assert.Empty(t, pubJWK.QI, "Public JWK should not contain QI")

		// Attempting to convert to private key should fail
		_, err = pubJWK.ToPrivateKey()
		assert.Error(t, err)
	})
}
