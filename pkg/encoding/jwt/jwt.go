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
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Algorithm represents supported JWT signing algorithms
type Algorithm string

const (
	RS256 Algorithm = "RS256" // RSASSA-PKCS1-v1_5 using SHA-256
	RS384 Algorithm = "RS384" // RSASSA-PKCS1-v1_5 using SHA-384
	RS512 Algorithm = "RS512" // RSASSA-PKCS1-v1_5 using SHA-512
	ES256 Algorithm = "ES256" // ECDSA using P-256 and SHA-256
	ES384 Algorithm = "ES384" // ECDSA using P-384 and SHA-384
	ES512 Algorithm = "ES512" // ECDSA using P-521 and SHA-512
	EdDSA Algorithm = "EdDSA" // EdDSA signature algorithms
	PS256 Algorithm = "PS256" // RSASSA-PSS using SHA-256
	PS384 Algorithm = "PS384" // RSASSA-PSS using SHA-384
	PS512 Algorithm = "PS512" // RSASSA-PSS using SHA-512
)

// Signer signs JWT tokens using cryptographic keys
type Signer struct{}

// NewSigner creates a new JWT signer
func NewSigner() *Signer {
	return &Signer{}
}

// Sign creates and signs a JWT with the given private key and claims.
// The signing algorithm is automatically determined from the key type.
//
// Example:
//
//	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
//	signer := jwt.NewSigner()
//	claims := jwt.MapClaims{
//	    "sub": "user123",
//	    "exp": time.Now().Add(time.Hour).Unix(),
//	}
//	token, err := signer.Sign(privateKey, claims)
func (s *Signer) Sign(key crypto.PrivateKey, claims jwt.Claims) (string, error) {
	alg, err := signingMethodFromKey(key)
	if err != nil {
		return "", err
	}
	return s.SignWithAlgorithm(key, claims, alg)
}

// SignWithAlgorithm creates and signs a JWT with a specific algorithm.
// This allows you to override the default algorithm selection.
//
// Example:
//
//	token, err := signer.SignWithAlgorithm(privateKey, claims, jwt.RS512)
func (s *Signer) SignWithAlgorithm(key crypto.PrivateKey, claims jwt.Claims, alg Algorithm) (string, error) {
	method := jwt.GetSigningMethod(string(alg))
	if method == nil {
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(key)
}

// SignWithKID creates and signs a JWT with a Key ID in the header.
// The kid field is used to identify which key was used to sign the token.
//
// Example:
//
//	token, err := signer.SignWithKID(privateKey, claims, "pkcs11:signing-key")
func (s *Signer) SignWithKID(key crypto.PrivateKey, claims jwt.Claims, kid string) (string, error) {
	alg, err := signingMethodFromKey(key)
	if err != nil {
		return "", err
	}

	method := jwt.GetSigningMethod(string(alg))
	if method == nil {
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid

	return token.SignedString(key)
}

// Verifier verifies JWT tokens
type Verifier struct{}

// NewVerifier creates a new JWT verifier
func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifyOptions contains options for JWT verification
type VerifyOptions struct {
	ValidateIssuer   bool
	ExpectedIssuer   string
	ValidateAudience bool
	ExpectedAudience string
	ValidateExpiry   bool
}

// Verify parses and verifies a JWT token.
// The public key is used to verify the signature.
//
// Example:
//
//	verifier := jwt.NewVerifier()
//	token, err := verifier.Verify(tokenString, publicKey)
//	if err != nil {
//	    log.Fatal("invalid token")
//	}
func (v *Verifier) Verify(tokenString string, publicKey crypto.PublicKey) (*jwt.Token, error) {
	return v.VerifyWithOptions(tokenString, publicKey, nil)
}

// VerifyWithOptions verifies a JWT with additional validation options.
//
// Example:
//
//	opts := &jwt.VerifyOptions{
//	    ValidateIssuer: true,
//	    ExpectedIssuer: "go-keychain",
//	    ValidateAudience: true,
//	    ExpectedAudience: "my-app",
//	}
//	token, err := verifier.VerifyWithOptions(tokenString, publicKey, opts)
func (v *Verifier) VerifyWithOptions(tokenString string, publicKey crypto.PublicKey, opts *VerifyOptions) (*jwt.Token, error) {
	// Parse token with public key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Additional validation if options provided
	if opts != nil {
		if err := v.validateWithOptions(token, opts); err != nil {
			return nil, err
		}
	}

	return token, nil
}

// validateWithOptions performs additional validation based on options
func (v *Verifier) validateWithOptions(token *jwt.Token, opts *VerifyOptions) error {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid claims type")
	}

	if opts.ValidateIssuer {
		iss, ok := claims["iss"].(string)
		if !ok || iss != opts.ExpectedIssuer {
			return fmt.Errorf("invalid issuer: expected %s, got %s", opts.ExpectedIssuer, iss)
		}
	}

	if opts.ValidateAudience {
		// Audience can be string or []string
		aud := claims["aud"]
		switch v := aud.(type) {
		case string:
			if v != opts.ExpectedAudience {
				return fmt.Errorf("invalid audience: expected %s, got %s", opts.ExpectedAudience, v)
			}
		case []interface{}:
			found := false
			for _, a := range v {
				if audStr, ok := a.(string); ok && audStr == opts.ExpectedAudience {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("invalid audience: %s not found in %v", opts.ExpectedAudience, v)
			}
		default:
			return fmt.Errorf("invalid audience format")
		}
	}

	return nil
}

// ExtractKID extracts the Key ID (kid) from a JWT token header without verifying the signature.
// Returns an empty string if no kid is present.
//
// Example:
//
//	kid, err := jwt.ExtractKID(tokenString)
//	if err != nil {
//	    log.Fatal("invalid token format")
//	}
//	fmt.Printf("Token was signed with key: %s\n", kid)
func ExtractKID(tokenString string) (string, error) {
	// Parse without validation to extract header
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", nil
	}

	return kid, nil
}

// signingMethodFromKey determines the appropriate JWT signing algorithm
// based on the type of private key
func signingMethodFromKey(key crypto.PrivateKey) (Algorithm, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return RS256, nil
	case *ecdsa.PrivateKey:
		return signingMethodFromECDSA(k)
	case ed25519.PrivateKey:
		return EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}
}

// signingMethodFromECDSA determines the ECDSA algorithm based on curve
func signingMethodFromECDSA(key *ecdsa.PrivateKey) (Algorithm, error) {
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

// ParseAlgorithm converts an algorithm string to an Algorithm type
func ParseAlgorithm(alg string) (Algorithm, error) {
	// Normalize to uppercase first
	upper := strings.ToUpper(alg)

	// EdDSA is a special case - it should be "EdDSA" not "EDDSA"
	if upper == "EDDSA" {
		return EdDSA, nil
	}

	switch Algorithm(upper) {
	case RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512:
		return Algorithm(upper), nil
	case EdDSA:
		return EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
}
