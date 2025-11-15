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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJWTIntegration_BasicSigningVerification tests basic JWT signing and verification
// with different key types and algorithms
func TestJWTIntegration_BasicSigningVerification(t *testing.T) {
	t.Run("RSA_RS256", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{
			"sub": "user123",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		// Sign token
		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify token
		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// Verify claims
		tokenClaims, ok := token.Claims.(jwtgo.MapClaims)
		require.True(t, ok)
		assert.Equal(t, "user123", tokenClaims["sub"])
	})

	t.Run("RSA_RS384", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign with RS384
		tokenString, err := signer.SignWithAlgorithm(privateKey, claims, jwt.RS384)
		require.NoError(t, err)

		// Verify
		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("RSA_RS512", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign with RS512
		tokenString, err := signer.SignWithAlgorithm(privateKey, claims, jwt.RS512)
		require.NoError(t, err)

		// Verify
		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("RSA_PS256", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign with PS256 (RSA-PSS)
		tokenString, err := signer.SignWithAlgorithm(privateKey, claims, jwt.PS256)
		require.NoError(t, err)

		// Verify
		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("ECDSA_ES256", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign
		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		// Verify
		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("ECDSA_ES384", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign
		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		// Verify
		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("ECDSA_ES512", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign
		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		// Verify
		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("Ed25519_EdDSA", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign
		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		// Verify
		token, err := verifier.Verify(tokenString, publicKey)
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})
}

// TestJWTIntegration_KeychainIntegration tests JWT signing and verification
// using keychain-backed keys
func TestJWTIntegration_KeychainIntegration(t *testing.T) {
	t.Run("RSA_KeychainSigning", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// Generate RSA key in keychain
		keyID := "pkcs8:jwt-rsa-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// Create keychain signer
		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)

		claims := jwtgo.MapClaims{
			"sub": "user123",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		// Sign with keychain key
		tokenString, err := signer.SignWithKeyID(keyID, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify the kid is in the header
		token, _, err := jwtgo.NewParser().ParseUnverified(tokenString, jwtgo.MapClaims{})
		require.NoError(t, err)
		assert.Equal(t, keyID, token.Header["kid"])

		// Verify signature using keychain verifier
		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		verifiedToken, err := verifier.VerifyWithKeyID(tokenString, keyID)
		require.NoError(t, err)
		assert.True(t, verifiedToken.Valid)
	})

	t.Run("ECDSA_P256_KeychainSigning", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:jwt-ecdsa-p256-key"
		err := setup.GenerateECDSAKey(keyID, elliptic.P256())
		require.NoError(t, err)

		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{"sub": "user123"}

		tokenString, err := signer.SignWithKeyID(keyID, claims)
		require.NoError(t, err)

		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		token, err := verifier.VerifyWithKeyID(tokenString, keyID)
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("Ed25519_KeychainSigning", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:jwt-ed25519-key"
		err := setup.GenerateEd25519Key(keyID)
		require.NoError(t, err)

		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{"sub": "user123"}

		tokenString, err := signer.SignWithKeyID(keyID, claims)
		require.NoError(t, err)

		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		token, err := verifier.VerifyWithKeyID(tokenString, keyID)
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("AutoKeyID_Verification", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:jwt-auto-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign with kid in header
		tokenString, err := signer.SignWithKeyID(keyID, claims)
		require.NoError(t, err)

		// Verify with automatic kid extraction
		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		token, err := verifier.VerifyWithAutoKeyID(tokenString)
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("ManualAlgorithmSelection", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:jwt-rsa-ps512-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign with PS512 explicitly
		tokenString, err := signer.SignWithKeyIDAndAlgorithm(keyID, claims, jwt.PS512)
		require.NoError(t, err)

		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		token, err := verifier.VerifyWithKeyID(tokenString, keyID)
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// Verify algorithm in header
		assert.Equal(t, "PS512", token.Header["alg"])
	})
}

// TestJWTIntegration_ClaimsValidation tests JWT claims validation
func TestJWTIntegration_ClaimsValidation(t *testing.T) {
	t.Run("StandardClaims", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		now := time.Now()
		claims := jwtgo.MapClaims{
			"iss": "go-keychain",
			"sub": "user123",
			"aud": "my-app",
			"exp": now.Add(time.Hour).Unix(),
			"nbf": now.Unix(),
			"iat": now.Unix(),
			"jti": "unique-token-id",
		}

		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)

		tokenClaims, ok := token.Claims.(jwtgo.MapClaims)
		require.True(t, ok)
		assert.Equal(t, "go-keychain", tokenClaims["iss"])
		assert.Equal(t, "user123", tokenClaims["sub"])
		assert.Equal(t, "my-app", tokenClaims["aud"])
		assert.Equal(t, "unique-token-id", tokenClaims["jti"])
	})

	t.Run("IssuerValidation", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{
			"iss": "go-keychain",
			"sub": "user123",
		}

		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		// Valid issuer
		opts := &jwt.VerifyOptions{
			ValidateIssuer: true,
			ExpectedIssuer: "go-keychain",
		}
		token, err := verifier.VerifyWithOptions(tokenString, privateKey.Public(), opts)
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// Invalid issuer
		opts.ExpectedIssuer = "wrong-issuer"
		_, err = verifier.VerifyWithOptions(tokenString, privateKey.Public(), opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer")
	})

	t.Run("AudienceValidation_SingleAudience", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{
			"aud": "my-app",
			"sub": "user123",
		}

		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		// Valid audience
		opts := &jwt.VerifyOptions{
			ValidateAudience: true,
			ExpectedAudience: "my-app",
		}
		token, err := verifier.VerifyWithOptions(tokenString, privateKey.Public(), opts)
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// Invalid audience
		opts.ExpectedAudience = "wrong-app"
		_, err = verifier.VerifyWithOptions(tokenString, privateKey.Public(), opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audience")
	})

	t.Run("AudienceValidation_MultipleAudiences", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{
			"aud": []string{"app1", "app2", "app3"},
			"sub": "user123",
		}

		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		// Valid audience in list
		opts := &jwt.VerifyOptions{
			ValidateAudience: true,
			ExpectedAudience: "app2",
		}
		token, err := verifier.VerifyWithOptions(tokenString, privateKey.Public(), opts)
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// Audience not in list
		opts.ExpectedAudience = "app4"
		_, err = verifier.VerifyWithOptions(tokenString, privateKey.Public(), opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audience")
	})

	t.Run("CustomClaims", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{
			"sub":         "user123",
			"email":       "user@example.com",
			"role":        "admin",
			"permissions": []string{"read", "write", "delete"},
		}

		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		token, err := verifier.Verify(tokenString, privateKey.Public())
		require.NoError(t, err)

		tokenClaims, ok := token.Claims.(jwtgo.MapClaims)
		require.True(t, ok)
		assert.Equal(t, "user@example.com", tokenClaims["email"])
		assert.Equal(t, "admin", tokenClaims["role"])

		perms, ok := tokenClaims["permissions"].([]interface{})
		require.True(t, ok)
		assert.Len(t, perms, 3)
	})
}

// TestJWTIntegration_ErrorHandling tests error cases and edge conditions
func TestJWTIntegration_ErrorHandling(t *testing.T) {
	t.Run("InvalidSignature", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}
		tokenString, err := signer.Sign(privateKey, claims)
		require.NoError(t, err)

		// Tamper with the token
		tamperedToken := tokenString[:len(tokenString)-10] + "xxxxxxxxxx"

		// Verification should fail
		_, err = verifier.Verify(tamperedToken, privateKey.Public())
		assert.Error(t, err)
	})

	t.Run("WrongPublicKey", func(t *testing.T) {
		privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		verifier := jwt.NewVerifier()

		claims := jwtgo.MapClaims{"sub": "user123"}
		tokenString, err := signer.Sign(privateKey1, claims)
		require.NoError(t, err)

		// Try to verify with different public key
		_, err = verifier.Verify(tokenString, privateKey2.Public())
		assert.Error(t, err)
	})

	t.Run("MalformedToken", func(t *testing.T) {
		verifier := jwt.NewVerifier()
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Test various malformed tokens
		malformedTokens := []string{
			"not.a.jwt",
			"",
			"invalid",
			"header.payload", // Missing signature
		}

		for _, token := range malformedTokens {
			_, err := verifier.Verify(token, publicKey)
			assert.Error(t, err)
		}
	})

	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		claims := jwtgo.MapClaims{"sub": "user123"}

		// Try to use unsupported algorithm
		_, err = signer.SignWithAlgorithm(privateKey, claims, jwt.Algorithm("INVALID"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})

	t.Run("KeychainKeyNotFound", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{"sub": "user123"}

		// Try to sign with non-existent key
		_, err := signer.SignWithKeyID("pkcs8:non-existent-key", claims)
		assert.Error(t, err)
	})

	t.Run("EmptyKID", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// Generate a key
		keyID := "pkcs8:jwt-test-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// Sign without kid
		key, err := setup.GetKeyByID(keyID)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		claims := jwtgo.MapClaims{"sub": "user123"}
		tokenString, err := signer.Sign(key, claims)
		require.NoError(t, err)

		// Try to verify with auto kid (should fail - no kid in header)
		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		_, err = verifier.VerifyWithAutoKeyID(tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kid")
	})
}

// TestJWTIntegration_TokenLifecycle tests complete token lifecycle
func TestJWTIntegration_TokenLifecycle(t *testing.T) {
	t.Run("CreateSignEncodeDecodeVerify", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		// 1. Generate key
		keyID := "pkcs8:lifecycle-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// 2. Create claims
		claims := jwtgo.MapClaims{
			"sub":   "user123",
			"email": "user@example.com",
			"role":  "admin",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
		}

		// 3. Sign
		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		tokenString, err := signer.SignWithKeyID(keyID, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// 4. Token is now encoded (compact serialization)
		assert.Contains(t, tokenString, ".")
		parts := len(tokenString)
		assert.Greater(t, parts, 100) // JWT should be reasonably sized

		// 5. Decode and parse (without verification)
		token, _, err := jwtgo.NewParser().ParseUnverified(tokenString, jwtgo.MapClaims{})
		require.NoError(t, err)
		assert.Equal(t, keyID, token.Header["kid"])

		// 6. Verify signature
		verifier := jwt.NewKeychainVerifier(setup.GetKeyByID)
		verifiedToken, err := verifier.VerifyWithAutoKeyID(tokenString)
		require.NoError(t, err)
		assert.True(t, verifiedToken.Valid)

		// 7. Extract and validate claims
		tokenClaims, ok := verifiedToken.Claims.(jwtgo.MapClaims)
		require.True(t, ok)
		assert.Equal(t, "user123", tokenClaims["sub"])
		assert.Equal(t, "user@example.com", tokenClaims["email"])
		assert.Equal(t, "admin", tokenClaims["role"])
	})
}

// TestJWTIntegration_KIDHeader tests Key ID in JWT header
func TestJWTIntegration_KIDHeader(t *testing.T) {
	t.Run("SignWithKID", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		claims := jwtgo.MapClaims{"sub": "user123"}

		// Sign with kid
		tokenString, err := signer.SignWithKID(privateKey, claims, "my-key-id")
		require.NoError(t, err)

		// Parse and check kid
		token, _, err := jwtgo.NewParser().ParseUnverified(tokenString, jwtgo.MapClaims{})
		require.NoError(t, err)
		assert.Equal(t, "my-key-id", token.Header["kid"])
	})

	t.Run("ExtractKID", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer := jwt.NewSigner()
		claims := jwtgo.MapClaims{"sub": "user123"}

		tokenString, err := signer.SignWithKID(privateKey, claims, "test-key-123")
		require.NoError(t, err)

		// Extract kid
		kid, err := jwt.ExtractKID(tokenString)
		require.NoError(t, err)
		assert.Equal(t, "test-key-123", kid)
	})

	t.Run("KeychainKIDFormat", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:my-signing-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		signer := jwt.NewKeychainSigner(setup.GetKeyByID, setup.GetSignerByID)
		claims := jwtgo.MapClaims{"sub": "user123"}

		tokenString, err := signer.SignWithKeyID(keyID, claims)
		require.NoError(t, err)

		// Verify kid matches keychain format
		kid, err := jwt.ExtractKID(tokenString)
		require.NoError(t, err)
		assert.Equal(t, keyID, kid)
		assert.Contains(t, kid, "pkcs8:")
	})
}
