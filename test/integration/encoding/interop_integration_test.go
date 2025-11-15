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
	"crypto/elliptic"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwe"
	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"
	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncodingInterop_JWK_JWT tests JWK to JWT workflows
func TestEncodingInterop_JWK_JWT(t *testing.T) {
	t.Run("JWK_To_JWT_Signing", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// 1. Generate key in keychain
		keyID := "pkcs8:interop-rsa-jwt-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// 2. Create JWK from keychain key
		jwkKey, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)
		assert.Equal(t, keyID, jwkKey.Kid)
		assert.True(t, jwkKey.IsKeychainBacked())

		// 3. Use keychain to sign JWT (using JWK's kid)
		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{
			"sub": "user123",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		tokenString, err := signer.SignWithKeyID(jwkKey.Kid, claims)
		require.NoError(t, err)

		// 4. Verify JWT kid matches JWK kid
		extractedKid, err := jwt.ExtractKID(tokenString)
		require.NoError(t, err)
		assert.Equal(t, jwkKey.Kid, extractedKid)

		// 5. Verify JWT using keychain verifier
		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		token, err := verifier.VerifyWithAutoKeyID(tokenString)
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// 6. Also verify using JWK's public key
		publicKey, err := jwkKey.ToPublicKey()
		require.NoError(t, err)

		basicVerifier := jwt.NewVerifier()
		token, err = basicVerifier.Verify(tokenString, publicKey)
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("JWK_To_JWT_ECDSA", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:interop-ecdsa-jwt-key"
		err := setup.GenerateECDSAKey(keyID, elliptic.P256())
		require.NoError(t, err)

		// Create JWK
		jwkKey, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)

		// Sign JWT
		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{"sub": "user456"}

		tokenString, err := signer.SignWithKeyID(jwkKey.Kid, claims)
		require.NoError(t, err)

		// Verify using JWK
		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		token, err := verifier.VerifyWithJWK(tokenString, jwkKey)
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})
}

// TestEncodingInterop_JWK_JWE tests JWK to JWE workflows
func TestEncodingInterop_JWK_JWE(t *testing.T) {
	plaintext := []byte("sensitive data to encrypt")

	t.Run("JWK_To_JWE_Encryption", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// 1. Generate key in keychain
		keyID := "pkcs8:interop-rsa-jwe-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// 2. Create JWK from keychain key
		jwkKey, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)
		assert.True(t, jwkKey.IsKeychainBacked())

		// 3. Extract public key from JWK for encryption
		publicKey, err := jwkKey.ToPublicKey()
		require.NoError(t, err)

		// 4. Encrypt using JWE with the JWK's public key
		encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "A256GCM", publicKey)
		require.NoError(t, err)

		jweString, err := encrypter.EncryptWithHeader(plaintext, map[string]interface{}{
			"kid": jwkKey.Kid,
		})
		require.NoError(t, err)

		// 5. Verify kid in JWE header matches JWK
		kid, err := jwe.ExtractKID(jweString)
		require.NoError(t, err)
		assert.Equal(t, jwkKey.Kid, kid)

		// 6. Decrypt using keychain decrypter
		decrypter := jwe.NewKeychainDecrypter(setup.GetDecrypterByID)
		decrypted, err := decrypter.DecryptWithAutoKeyID(jweString)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("JWK_To_JWE_ECDH", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:interop-ecdh-jwe-key"
		err := setup.GenerateECDSAKey(keyID, elliptic.P384())
		require.NoError(t, err)

		// Create JWK
		jwkKey, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)

		// Use JWK for ECDH-based encryption
		publicKey, err := jwkKey.ToPublicKey()
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("ECDH-ES+A256KW", "A256GCM", publicKey)
		require.NoError(t, err)

		jweString, err := encrypter.EncryptWithHeader(plaintext, map[string]interface{}{
			"kid": jwkKey.Kid,
		})
		require.NoError(t, err)

		// Decrypt using the private key from keychain
		privateKey, err := setup.GetKeyByID(keyID)
		require.NoError(t, err)

		basicDecrypter := jwe.NewDecrypter()
		decrypted, err := basicDecrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestEncodingInterop_JWT_JWE tests JWT to JWE workflows (encrypted tokens)
func TestEncodingInterop_JWT_JWE(t *testing.T) {
	t.Run("Encrypted_JWT_Token", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// Generate signing key
		signingKeyID := "pkcs8:interop-signing-key"
		err := setup.GenerateRSAKey(signingKeyID, 2048)
		require.NoError(t, err)

		// Generate encryption key
		encryptionKeyID := "pkcs8:interop-encryption-key"
		err = setup.GenerateRSAKey(encryptionKeyID, 2048)
		require.NoError(t, err)

		// 1. Create and sign JWT
		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{
			"sub":   "user789",
			"email": "user@example.com",
			"role":  "admin",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
		}

		jwtString, err := signer.SignWithKeyID(signingKeyID, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, jwtString)

		// 2. Encrypt the JWT with JWE
		encPublicKey, err := setup.GetPublicKeyByID(encryptionKeyID)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "A256GCM", encPublicKey)
		require.NoError(t, err)

		// Encrypt JWT as plaintext
		encryptedJWT, err := encrypter.EncryptWithHeader([]byte(jwtString), map[string]interface{}{
			"kid": encryptionKeyID,
			"cty": "JWT", // Content type is JWT
		})
		require.NoError(t, err)

		// 3. Decrypt the JWE to get JWT back
		decrypter := jwe.NewKeychainDecrypter(setup.GetDecrypterByID)
		decryptedJWT, err := decrypter.DecryptWithAutoKeyID(encryptedJWT)
		require.NoError(t, err)
		assert.Equal(t, jwtString, string(decryptedJWT))

		// 4. Verify the JWT signature
		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		token, err := verifier.VerifyWithKeyID(string(decryptedJWT), signingKeyID)
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// 5. Validate claims
		tokenClaims, ok := token.Claims.(jwtgo.MapClaims)
		require.True(t, ok)
		assert.Equal(t, "user789", tokenClaims["sub"])
		assert.Equal(t, "user@example.com", tokenClaims["email"])
		assert.Equal(t, "admin", tokenClaims["role"])
	})

	t.Run("NestedJWT_DifferentKeys", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// Use ECDSA for signing, RSA for encryption
		signingKeyID := "pkcs8:ecdsa-signing-key"
		err := setup.GenerateECDSAKey(signingKeyID, elliptic.P256())
		require.NoError(t, err)

		encryptionKeyID := "pkcs8:rsa-encryption-key"
		err = setup.GenerateRSAKey(encryptionKeyID, 2048)
		require.NoError(t, err)

		// Sign with ECDSA
		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{
			"sub": "nested-user",
			"exp": time.Now().Add(30 * time.Minute).Unix(),
		}

		jwtString, err := signer.SignWithKeyID(signingKeyID, claims)
		require.NoError(t, err)

		// Encrypt with RSA
		encPublicKey, err := setup.GetPublicKeyByID(encryptionKeyID)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", encPublicKey)
		require.NoError(t, err)

		encryptedJWT, err := encrypter.EncryptWithHeader([]byte(jwtString), map[string]interface{}{
			"kid": encryptionKeyID,
		})
		require.NoError(t, err)

		// Decrypt and verify
		decrypter := jwe.NewKeychainDecrypter(setup.GetDecrypterByID)
		decrypted, err := decrypter.DecryptWithKeyID(encryptedJWT, encryptionKeyID)
		require.NoError(t, err)

		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		token, err := verifier.VerifyWithKeyID(string(decrypted), signingKeyID)
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})
}

// TestEncodingInterop_FullWorkflow tests complete end-to-end workflows
func TestEncodingInterop_FullWorkflow(t *testing.T) {
	t.Run("Complete_Authentication_Flow", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// === Phase 1: Key Generation ===
		keyID := "pkcs8:auth-server-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// === Phase 2: Export as JWK ===
		serverJWK, err := jwk.FromKeychain(keyID, setup.GetKeyByID)
		require.NoError(t, err)
		assert.Equal(t, keyID, serverJWK.Kid)

		// Verify JWK is keychain-backed
		assert.True(t, serverJWK.IsKeychainBacked())

		// === Phase 3: Sign JWT with authentication claims ===
		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		authClaims := jwtgo.MapClaims{
			"iss":         "auth-server",
			"sub":         "user12345",
			"aud":         "api-gateway",
			"email":       "user@example.com",
			"roles":       []string{"user", "admin"},
			"permissions": []string{"read", "write", "delete"},
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(2 * time.Hour).Unix(),
			"nbf":         time.Now().Unix(),
		}

		authToken, err := signer.SignWithKeyID(serverJWK.Kid, authClaims)
		require.NoError(t, err)
		assert.NotEmpty(t, authToken)

		// === Phase 4: Verify token kid matches JWK ===
		tokenKid, err := jwt.ExtractKID(authToken)
		require.NoError(t, err)
		assert.Equal(t, serverJWK.Kid, tokenKid)

		// === Phase 5: Encrypt JWT for secure transport ===
		transportKeyID := "pkcs8:transport-encryption-key"
		err = setup.GenerateRSAKey(transportKeyID, 2048)
		require.NoError(t, err)

		transportPublicKey, err := setup.GetPublicKeyByID(transportKeyID)
		require.NoError(t, err)

		jweEncrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "A256GCM", transportPublicKey)
		require.NoError(t, err)

		encryptedToken, err := jweEncrypter.EncryptWithHeader([]byte(authToken), map[string]interface{}{
			"kid": transportKeyID,
			"cty": "JWT",
		})
		require.NoError(t, err)

		// === Phase 6: Decrypt JWT ===
		jweDecrypter := jwe.NewKeychainDecrypter(setup.GetDecrypterByID)
		decryptedToken, err := jweDecrypter.DecryptWithAutoKeyID(encryptedToken)
		require.NoError(t, err)
		assert.Equal(t, authToken, string(decryptedToken))

		// === Phase 7: Verify JWT signature ===
		jwtVerifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		verifiedToken, err := jwtVerifier.VerifyWithAutoKeyID(string(decryptedToken))
		require.NoError(t, err)
		assert.True(t, verifiedToken.Valid)

		// === Phase 8: Extract and validate all claims ===
		finalClaims, ok := verifiedToken.Claims.(jwtgo.MapClaims)
		require.True(t, ok)

		assert.Equal(t, "auth-server", finalClaims["iss"])
		assert.Equal(t, "user12345", finalClaims["sub"])
		assert.Equal(t, "api-gateway", finalClaims["aud"])
		assert.Equal(t, "user@example.com", finalClaims["email"])

		// Verify arrays
		roles := finalClaims["roles"].([]interface{})
		assert.Len(t, roles, 2)

		permissions := finalClaims["permissions"].([]interface{})
		assert.Len(t, permissions, 3)

		// === Phase 9: Verify using JWK public key directly ===
		publicKey, err := serverJWK.ToPublicKey()
		require.NoError(t, err)

		basicVerifier := jwt.NewVerifier()
		finalToken, err := basicVerifier.Verify(string(decryptedToken), publicKey)
		require.NoError(t, err)
		assert.True(t, finalToken.Valid)
	})

	t.Run("Multi_Key_Rotation_Workflow", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// Simulate key rotation scenario
		oldKeyID := "pkcs8:old-signing-key"
		newKeyID := "pkcs8:new-signing-key"

		err := setup.GenerateRSAKey(oldKeyID, 2048)
		require.NoError(t, err)
		err = setup.GenerateRSAKey(newKeyID, 2048)
		require.NoError(t, err)

		// Create JWKs for both keys
		oldJWK, err := jwk.FromKeychain(oldKeyID, setup.GetKeyByID)
		require.NoError(t, err)

		newJWK, err := jwk.FromKeychain(newKeyID, setup.GetKeyByID)
		require.NoError(t, err)

		// Sign token with old key
		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{
			"sub": "rotating-user",
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		oldToken, err := signer.SignWithKeyID(oldJWK.Kid, claims)
		require.NoError(t, err)

		// Sign token with new key
		newToken, err := signer.SignWithKeyID(newJWK.Kid, claims)
		require.NoError(t, err)

		// Verify both tokens work
		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)

		oldVerified, err := verifier.VerifyWithKeyID(oldToken, oldKeyID)
		require.NoError(t, err)
		assert.True(t, oldVerified.Valid)

		newVerified, err := verifier.VerifyWithKeyID(newToken, newKeyID)
		require.NoError(t, err)
		assert.True(t, newVerified.Valid)

		// Auto verification should also work
		autoOld, err := verifier.VerifyWithAutoKeyID(oldToken)
		require.NoError(t, err)
		assert.True(t, autoOld.Valid)

		autoNew, err := verifier.VerifyWithAutoKeyID(newToken)
		require.NoError(t, err)
		assert.True(t, autoNew.Valid)
	})
}
