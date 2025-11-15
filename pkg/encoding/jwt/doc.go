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

// Package jwt provides JSON Web Token (JWT) signing and verification
// using cryptographic keys from the go-keychain library.
//
// This package integrates the golang-jwt/jwt library with go-keychain,
// allowing you to sign and verify JWTs using hardware-backed keys
// (HSM, TPM, cloud KMS) without exposing private key material.
//
// # Supported Algorithms
//
// The package supports all standard JWT signing algorithms:
//   - RS256, RS384, RS512 (RSA with PKCS#1 v1.5)
//   - PS256, PS384, PS512 (RSA with PSS)
//   - ES256, ES384, ES512 (ECDSA)
//   - EdDSA (Ed25519)
//
// # Basic Usage
//
// Signing a JWT with a standard crypto key:
//
//	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
//	signer := jwt.NewSigner()
//	claims := jwt.MapClaims{
//	    "sub": "user123",
//	    "exp": time.Now().Add(time.Hour).Unix(),
//	}
//	token, err := signer.Sign(privateKey, claims)
//
// Verifying a JWT:
//
//	verifier := jwt.NewVerifier()
//	token, err := verifier.Verify(tokenString, publicKey)
//	if err != nil {
//	    log.Fatal("invalid token")
//	}
//
// # Keychain Integration
//
// The package provides KeychainSigner and KeychainVerifier for
// signing and verifying JWTs using keys from the keychain.
//
// Signing with a keychain key:
//
//	signer := jwt.NewKeychainSigner(
//	    func(keyID string) (crypto.PrivateKey, error) {
//	        return keystore.GetKeyByID(keyID)
//	    },
//	    func(keyID string) (crypto.Signer, error) {
//	        return keystore.GetSignerByID(keyID)
//	    },
//	)
//
//	claims := jwt.MapClaims{
//	    "sub": "user123",
//	    "exp": time.Now().Add(time.Hour).Unix(),
//	}
//	token, err := signer.SignWithKeyID("pkcs11:signing-key", claims)
//
// Verifying with automatic key lookup:
//
//	verifier := jwt.NewKeychainVerifier(func(keyID string) (crypto.PrivateKey, error) {
//	    return keystore.GetKeyByID(keyID)
//	})
//
//	// Automatically extracts kid from JWT header and looks up key
//	token, err := verifier.VerifyWithAutoKeyID(tokenString)
//
// # JWK Integration
//
// The package works seamlessly with JWK (JSON Web Keys):
//
//	jwk, _ := jwk.FromPublicKey(publicKey)
//	token, err := verifier.VerifyWithJWK(tokenString, jwk)
//
// # Key ID (kid) Support
//
// The package supports the kid (Key ID) header for key identification:
//
//	// Sign with kid
//	token, err := signer.SignWithKID(privateKey, claims, "pkcs11:key-1")
//
//	// Extract kid from token
//	kid, err := jwt.ExtractKID(tokenString)
//
// # Custom Claims
//
// You can use custom claims structures:
//
//	type CustomClaims struct {
//	    UserID string   `json:"uid"`
//	    Roles  []string `json:"roles"`
//	    jwt.RegisteredClaims
//	}
//
//	claims := CustomClaims{
//	    UserID: "12345",
//	    Roles:  []string{"admin"},
//	    RegisteredClaims: jwt.RegisteredClaims{
//	        ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
//	    },
//	}
//	token, err := signer.Sign(privateKey, claims)
//
// # Verification Options
//
// Advanced verification with issuer and audience validation:
//
//	opts := &jwt.VerifyOptions{
//	    ValidateIssuer:   true,
//	    ExpectedIssuer:   "go-keychain",
//	    ValidateAudience: true,
//	    ExpectedAudience: "my-app",
//	}
//	token, err := verifier.VerifyWithOptions(tokenString, publicKey, opts)
//
// # Hardware-Backed Keys
//
// The keychain integration allows signing JWTs with keys that never
// leave hardware security modules:
//
//	// Sign with TPM-backed key
//	token, err := signer.SignWithKeyID("tpm2:attestation-key", claims)
//
//	// Sign with HSM-backed key
//	token, err := signer.SignWithKeyID("pkcs11:hsm-key", claims)
//
//	// Sign with cloud KMS key
//	token, err := signer.SignWithKeyID("awskms:prod-signing-key", claims)
//
// # Thread Safety
//
// All types in this package are safe for concurrent use.
package jwt
