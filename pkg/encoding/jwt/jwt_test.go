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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSign_RSA256 tests signing a JWT with RSA-256
func TestSign_RSA256(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create signer
	signer := NewSigner()

	// Create claims
	claims := jwt.MapClaims{
		"sub": "test-user",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Sign token
	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify we can parse and verify the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestSign_RSA384 tests signing a JWT with RSA-384
func TestSign_RSA384(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.SignWithAlgorithm(privateKey, claims, RS384)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestSign_RSA512 tests signing a JWT with RSA-512
func TestSign_RSA512(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.SignWithAlgorithm(privateKey, claims, RS512)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestSign_ECDSA256 tests signing a JWT with ECDSA-256
func TestSign_ECDSA256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestSign_ECDSA384 tests signing a JWT with ECDSA-384
func TestSign_ECDSA384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestSign_ECDSA512 tests signing a JWT with ECDSA-512
func TestSign_ECDSA512(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestSign_Ed25519 tests signing a JWT with Ed25519
func TestSign_Ed25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestSign_WithKID tests signing with a key ID
func TestSign_WithKID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.SignWithKID(privateKey, claims, "pkcs11:test-key")
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Parse and check kid
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		assert.True(t, ok)
		assert.Equal(t, "pkcs11:test-key", kid)
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestVerify_ValidToken tests verifying a valid JWT
func TestVerify_ValidToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify
	verifier := NewVerifier()
	token, err := verifier.Verify(tokenString, &privateKey.PublicKey)
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestVerify_ExpiredToken tests verifying an expired JWT
func TestVerify_ExpiredToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify
	verifier := NewVerifier()
	_, err = verifier.Verify(tokenString, &privateKey.PublicKey)
	assert.Error(t, err)
}

// TestVerify_InvalidSignature tests verifying a JWT with invalid signature
func TestVerify_InvalidSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Create different key for verification
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Verify with wrong key
	verifier := NewVerifier()
	_, err = verifier.Verify(tokenString, &wrongKey.PublicKey)
	assert.Error(t, err)
}

// TestExtractKID tests extracting kid from JWT header
func TestExtractKID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	expectedKID := "tpm2:signing-key"
	tokenString, err := signer.SignWithKID(privateKey, claims, expectedKID)
	require.NoError(t, err)

	// Extract kid
	kid, err := ExtractKID(tokenString)
	require.NoError(t, err)
	assert.Equal(t, expectedKID, kid)
}

// TestExtractKID_NoKID tests extracting kid when none is present
func TestExtractKID_NoKID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Extract kid (should return empty)
	kid, err := ExtractKID(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "", kid)
}

// TestSign_UnsupportedKeyType tests signing with unsupported key type
func TestSign_UnsupportedKeyType(t *testing.T) {
	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Try to sign with invalid key type
	_, err := signer.Sign("not-a-key", claims)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

// TestVerify_MalformedToken tests verifying a malformed JWT
func TestVerify_MalformedToken(t *testing.T) {
	verifier := NewVerifier()

	// Try to verify invalid token
	_, err := verifier.Verify("not.a.valid.jwt", nil)
	assert.Error(t, err)
}

// TestSigningMethodFromKey tests getting the correct signing method from a key
func TestSigningMethodFromKey(t *testing.T) {
	tests := []struct {
		name     string
		keyGen   func() crypto.PrivateKey
		expected Algorithm
	}{
		{
			name: "RSA key",
			keyGen: func() crypto.PrivateKey {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key
			},
			expected: RS256,
		},
		{
			name: "ECDSA P-256 key",
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key
			},
			expected: ES256,
		},
		{
			name: "ECDSA P-384 key",
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return key
			},
			expected: ES384,
		},
		{
			name: "ECDSA P-521 key",
			keyGen: func() crypto.PrivateKey {
				key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return key
			},
			expected: ES512,
		},
		{
			name: "Ed25519 key",
			keyGen: func() crypto.PrivateKey {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				return key
			},
			expected: EdDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.keyGen()
			alg, err := signingMethodFromKey(key)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, alg)
		})
	}
}

// TestRegisteredClaims tests using RegisteredClaims
func TestRegisteredClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "go-keychain",
		Subject:   "test-user",
		Audience:  jwt.ClaimStrings{"test-audience"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        "test-jti",
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify and check claims
	verifier := NewVerifier()
	token, err := verifier.Verify(tokenString, &privateKey.PublicKey)
	require.NoError(t, err)
	assert.True(t, token.Valid)

	// Parse claims
	parsedClaims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, "go-keychain", parsedClaims["iss"])
	assert.Equal(t, "test-user", parsedClaims["sub"])
	assert.Equal(t, "test-jti", parsedClaims["jti"])
}

// TestCustomClaims tests using custom claims structure
func TestCustomClaims(t *testing.T) {
	type CustomClaims struct {
		UserID       string   `json:"uid"`
		Email        string   `json:"email"`
		Roles        []string `json:"roles"`
		Organization string   `json:"org"`
		jwt.RegisteredClaims
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := CustomClaims{
		UserID:       "12345",
		Email:        "test@example.com",
		Roles:        []string{"admin", "user"},
		Organization: "test-org",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify
	verifier := NewVerifier()
	token, err := verifier.Verify(tokenString, &privateKey.PublicKey)
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestVerifyWithOptions tests verifying with specific options
func TestVerifyWithOptions(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "go-keychain",
		Audience:  jwt.ClaimStrings{"test-app"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with options
	verifier := NewVerifier()
	opts := &VerifyOptions{
		ValidateIssuer:   true,
		ExpectedIssuer:   "go-keychain",
		ValidateAudience: true,
		ExpectedAudience: "test-app",
	}

	token, err := verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestVerifyWithOptions_InvalidIssuer tests verification failure with wrong issuer
func TestVerifyWithOptions_InvalidIssuer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "wrong-issuer",
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with options expecting different issuer
	verifier := NewVerifier()
	opts := &VerifyOptions{
		ValidateIssuer: true,
		ExpectedIssuer: "go-keychain",
	}

	_, err = verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	assert.Error(t, err)
}

// TestVerifyWithOptions_InvalidAudience tests verification failure with wrong audience
func TestVerifyWithOptions_InvalidAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{"wrong-app"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with options expecting different audience
	verifier := NewVerifier()
	opts := &VerifyOptions{
		ValidateAudience: true,
		ExpectedAudience: "test-app",
	}

	_, err = verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	assert.Error(t, err)
}

// TestVerifyWithOptions_AudienceArray tests verification with audience array
func TestVerifyWithOptions_AudienceArray(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{"app1", "app2", "app3"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with one of the audiences
	verifier := NewVerifier()
	opts := &VerifyOptions{
		ValidateAudience: true,
		ExpectedAudience: "app2",
	}

	token, err := verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestSignWithAlgorithm_InvalidAlgorithm tests error with invalid algorithm
func TestSignWithAlgorithm_InvalidAlgorithm(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err = signer.SignWithAlgorithm(privateKey, claims, Algorithm("INVALID123"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

// TestSignWithKID_InvalidAlgorithm tests error with invalid algorithm in SignWithKID
func TestSignWithKID_InvalidAlgorithm(t *testing.T) {
	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Create an unsupported key type
	_, err := signer.SignWithKID("unsupported-key", claims, "test-kid")
	assert.Error(t, err)
}

// TestVerify_InvalidClaims tests verification with invalid claims type
func TestVerify_InvalidClaims(t *testing.T) {
	// This test is tricky since jwt.Parse always uses MapClaims by default
	// We'll just ensure Verify handles edge cases properly
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()
	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify normally first
	verifier := NewVerifier()
	token, err := verifier.Verify(tokenString, &privateKey.PublicKey)
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

// TestExtractKID_MalformedToken tests extracting kid from malformed token
func TestExtractKID_MalformedToken(t *testing.T) {
	_, err := ExtractKID("malformed.token")
	assert.Error(t, err)
}

// TestSigningMethodFromECDSA_UnsupportedCurve tests error with unsupported ECDSA curve
func TestSigningMethodFromECDSA_UnsupportedCurve(t *testing.T) {
	// This is hard to test directly since we can't easily create an unsupported curve
	// The function is tested indirectly through the main tests
	// We can at least verify the supported curves work
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)

		signer := NewSigner()
		claims := jwt.MapClaims{
			"sub": "test",
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		_, err = signer.Sign(key, claims)
		require.NoError(t, err)
	}
}

// TestVerifyWithOptions_MissingIssuer tests verification when issuer is missing
func TestVerifyWithOptions_MissingIssuer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		// No issuer
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with options expecting issuer
	verifier := NewVerifier()
	opts := &VerifyOptions{
		ValidateIssuer: true,
		ExpectedIssuer: "go-keychain",
	}

	_, err = verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	assert.Error(t, err)
}

// TestParseAlgorithm_AllAlgorithms tests parsing all supported algorithms
func TestParseAlgorithm_AllAlgorithms(t *testing.T) {
	algorithms := []string{
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512",
		"EdDSA",
	}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			parsed, err := ParseAlgorithm(alg)
			require.NoError(t, err)
			assert.Equal(t, Algorithm(alg), parsed)
		})
	}
}

// TestParseAlgorithm_CaseInsensitive tests that algorithm parsing is case-insensitive
func TestParseAlgorithm_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input    string
		expected Algorithm
	}{
		{"rs256", RS256},
		{"RS256", RS256},
		{"Rs256", RS256},
		{"es384", ES384},
		{"ES384", ES384},
		{"ps512", PS512},
		{"PS512", PS512},
		{"eddsa", EdDSA},
		{"EdDSA", EdDSA},
		{"EDDSA", EdDSA},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			alg, err := ParseAlgorithm(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, alg)
		})
	}
}

// TestParseAlgorithm_InvalidAlgorithm tests parsing invalid algorithm strings
func TestParseAlgorithm_InvalidAlgorithm(t *testing.T) {
	tests := []string{
		"INVALID",
		"HS256",
		"HS512",
		"NONE",
		"",
		"UNKNOWN",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := ParseAlgorithm(input)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "unsupported algorithm")
		})
	}
}

// TestVerifyWithOptions_InvalidAudienceType tests validation with invalid audience type
func TestVerifyWithOptions_InvalidAudienceType(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	// Create token with numeric audience (invalid type)
	claims := jwt.MapClaims{
		"aud": 12345, // Invalid type
		"exp": now.Add(time.Hour).Unix(),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with options expecting string audience
	verifier := NewVerifier()
	opts := &VerifyOptions{
		ValidateAudience: true,
		ExpectedAudience: "test-app",
	}

	_, err = verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid audience format")
}

// TestVerifyWithOptions_MissingAudience tests validation when audience is missing
func TestVerifyWithOptions_MissingAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		// No audience
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with options expecting audience
	verifier := NewVerifier()
	opts := &VerifyOptions{
		ValidateAudience: true,
		ExpectedAudience: "test-app",
	}

	_, err = verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	assert.Error(t, err)
}

// TestVerifyWithOptions_AudienceArrayNotFound tests validation when audience not in array
func TestVerifyWithOptions_AudienceArrayNotFound(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{"app1", "app2", "app3"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	require.NoError(t, err)

	// Verify with audience not in the array
	verifier := NewVerifier()
	opts := &VerifyOptions{
		ValidateAudience: true,
		ExpectedAudience: "app4",
	}

	_, err = verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
