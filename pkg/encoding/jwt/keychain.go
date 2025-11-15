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
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"
)

// KeychainSigner signs JWTs using keys from a keychain.
// This allows you to sign JWTs with hardware-backed keys (HSM, TPM, etc.)
// without exposing the private key material.
type KeychainSigner struct {
	getKey    jwk.KeychainKeyGetter
	getSigner jwk.KeychainSignerGetter
}

// NewKeychainSigner creates a new keychain-based JWT signer.
// The getKey and getSigner functions should retrieve keys from your keychain.
//
// Example:
//
//	signer := jwt.NewKeychainSigner(
//	    func(keyID string) (crypto.PrivateKey, error) {
//	        return keystore.GetKeyByID(keyID)
//	    },
//	    func(keyID string) (crypto.Signer, error) {
//	        return keystore.GetSignerByID(keyID)
//	    },
//	)
//	token, err := signer.SignWithKeyID("pkcs11:signing-key", claims)
func NewKeychainSigner(getKey jwk.KeychainKeyGetter, getSigner jwk.KeychainSignerGetter) *KeychainSigner {
	return &KeychainSigner{
		getKey:    getKey,
		getSigner: getSigner,
	}
}

// SignWithKeyID signs a JWT using a key from the keychain identified by Key ID.
// The Key ID format is "backend:keyname" (e.g., "pkcs11:signing-key").
//
// The kid is automatically added to the JWT header for easy key identification.
//
// Example:
//
//	claims := jwt.MapClaims{
//	    "sub": "user123",
//	    "exp": time.Now().Add(time.Hour).Unix(),
//	}
//	token, err := signer.SignWithKeyID("tpm2:attestation-key", claims)
func (ks *KeychainSigner) SignWithKeyID(keyID string, claims jwt.Claims) (string, error) {
	// Get the signer from keychain
	signer, err := ks.getSigner(keyID)
	if err != nil {
		return "", fmt.Errorf("failed to get signer for key %s: %w", keyID, err)
	}

	// Determine algorithm from signer's public key
	alg, err := signingMethodFromPublicKey(signer.Public())
	if err != nil {
		return "", err
	}

	method := jwt.GetSigningMethod(string(alg))
	if method == nil {
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	// Create token with kid in header
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = keyID

	// Sign using the keychain signer
	return token.SignedString(signer)
}

// SignWithKeyIDAndAlgorithm signs a JWT using a specific algorithm.
// This allows overriding the automatic algorithm selection.
//
// Example:
//
//	token, err := signer.SignWithKeyIDAndAlgorithm("pkcs11:rsa-key", claims, jwt.RS512)
func (ks *KeychainSigner) SignWithKeyIDAndAlgorithm(keyID string, claims jwt.Claims, alg Algorithm) (string, error) {
	// Get the signer from keychain
	signer, err := ks.getSigner(keyID)
	if err != nil {
		return "", fmt.Errorf("failed to get signer for key %s: %w", keyID, err)
	}

	method := jwt.GetSigningMethod(string(alg))
	if method == nil {
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	// Create token with kid in header
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = keyID

	// Sign using the keychain signer
	return token.SignedString(signer)
}

// KeychainVerifier verifies JWTs using keys from a keychain or JWKs
type KeychainVerifier struct {
	getKey jwk.KeychainKeyGetter
}

// NewKeychainVerifier creates a new keychain-based JWT verifier.
//
// Example:
//
//	verifier := jwt.NewKeychainVerifier(func(keyID string) (crypto.PrivateKey, error) {
//	    return keystore.GetKeyByID(keyID)
//	})
func NewKeychainVerifier(getKey jwk.KeychainKeyGetter) *KeychainVerifier {
	return &KeychainVerifier{
		getKey: getKey,
	}
}

// VerifyWithKeyID verifies a JWT using a public key from the keychain.
// The Key ID should match the kid in the JWT header.
//
// Example:
//
//	token, err := verifier.VerifyWithKeyID(tokenString, "pkcs11:signing-key")
func (kv *KeychainVerifier) VerifyWithKeyID(tokenString, keyID string) (*jwt.Token, error) {
	// Get the key from keychain
	key, err := kv.getKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", keyID, err)
	}

	// Extract public key
	var publicKey crypto.PublicKey
	if pk, ok := key.(interface{ Public() crypto.PublicKey }); ok {
		publicKey = pk.Public()
	} else {
		return nil, fmt.Errorf("key does not expose public key")
	}

	// Parse and verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	return token, nil
}

// VerifyWithAutoKeyID verifies a JWT by automatically extracting the kid from the header
// and using it to retrieve the verification key from the keychain.
//
// Example:
//
//	token, err := verifier.VerifyWithAutoKeyID(tokenString)
func (kv *KeychainVerifier) VerifyWithAutoKeyID(tokenString string) (*jwt.Token, error) {
	// Extract kid from token
	kid, err := ExtractKID(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to extract kid: %w", err)
	}
	if kid == "" {
		return nil, fmt.Errorf("token does not contain kid header")
	}

	// Verify using the extracted kid
	return kv.VerifyWithKeyID(tokenString, kid)
}

// VerifyWithJWK verifies a JWT using a JWK.
//
// Example:
//
//	jwk := &jwk.JWK{...}
//	token, err := verifier.VerifyWithJWK(tokenString, jwk)
func (kv *KeychainVerifier) VerifyWithJWK(tokenString string, key *jwk.JWK) (*jwt.Token, error) {
	// Convert JWK to public key
	publicKey, err := key.ToPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWK to public key: %w", err)
	}

	// Parse and verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	return token, nil
}

// signingMethodFromPublicKey determines the JWT algorithm from a public key
func signingMethodFromPublicKey(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return RS256, nil
	case *ecdsa.PublicKey:
		return signingMethodFromECDSAPublic(k)
	case ed25519.PublicKey:
		return EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// signingMethodFromECDSAPublic determines the ECDSA algorithm from public key curve
func signingMethodFromECDSAPublic(key *ecdsa.PublicKey) (Algorithm, error) {
	switch key.Curve {
	case elliptic.P256():
		return ES256, nil
	case elliptic.P384():
		return ES384, nil
	case elliptic.P521():
		return ES512, nil
	default:
		return "", fmt.Errorf("unsupported ECDSA curve: %s", key.Curve.Params().Name)
	}
}
