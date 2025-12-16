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

package webauthn

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	keychainjwt "github.com/jeremyhahn/go-keychain/pkg/encoding/jwt"
)

// DefaultJWTGenerator generates JWT tokens for authenticated WebAuthn users.
type DefaultJWTGenerator struct {
	// privateKey is the key used to sign tokens
	privateKey crypto.PrivateKey
	// publicKey is the key used to verify tokens (for validation)
	publicKey crypto.PublicKey
	// issuer is the JWT issuer claim
	issuer string
	// audience is the JWT audience claim
	audience []string
	// expiresIn is how long tokens are valid
	expiresIn time.Duration
	// keyID is the key identifier for the kid header
	keyID string
	// signer is the JWT signer
	signer *keychainjwt.Signer
}

// JWTGeneratorConfig contains configuration for the JWT generator.
type JWTGeneratorConfig struct {
	// PrivateKey is the key used to sign tokens (required)
	PrivateKey crypto.PrivateKey
	// PublicKey is the key used to verify tokens (optional, derived from PrivateKey if not set)
	PublicKey crypto.PublicKey
	// Issuer is the JWT issuer claim (default: "go-keychain")
	Issuer string
	// Audience is the JWT audience claim (default: ["go-keychain"])
	Audience []string
	// ExpiresIn is how long tokens are valid (default: 1 hour)
	ExpiresIn time.Duration
	// KeyID is the key identifier for the kid header (optional)
	KeyID string
}

// NewDefaultJWTGenerator creates a new JWT generator with the given configuration.
func NewDefaultJWTGenerator(config *JWTGeneratorConfig) (*DefaultJWTGenerator, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if config.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// Set defaults
	issuer := config.Issuer
	if issuer == "" {
		issuer = "go-keychain"
	}

	audience := config.Audience
	if len(audience) == 0 {
		audience = []string{"go-keychain"}
	}

	expiresIn := config.ExpiresIn
	if expiresIn == 0 {
		expiresIn = time.Hour
	}

	// Get public key from private key if not provided
	publicKey := config.PublicKey
	if publicKey == nil {
		type publicKeyGetter interface {
			Public() crypto.PublicKey
		}
		if pk, ok := config.PrivateKey.(publicKeyGetter); ok {
			publicKey = pk.Public()
		}
	}

	return &DefaultJWTGenerator{
		privateKey: config.PrivateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		audience:   audience,
		expiresIn:  expiresIn,
		keyID:      config.KeyID,
		signer:     keychainjwt.NewSigner(),
	}, nil
}

// GenerateToken creates a JWT for the authenticated user.
func (g *DefaultJWTGenerator) GenerateToken(ctx context.Context, user User) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss": g.issuer,
		"aud": g.audience,
		"sub": base64.RawURLEncoding.EncodeToString(user.WebAuthnID()),
		"iat": now.Unix(),
		"exp": now.Add(g.expiresIn).Unix(),
		"nbf": now.Unix(),
		// Custom claims
		"name":     user.WebAuthnDisplayName(),
		"username": user.WebAuthnName(),
	}

	// Add role if the user implements a role interface
	if roleUser, ok := user.(interface{ GetRole() string }); ok {
		claims["role"] = roleUser.GetRole()
	}

	if g.keyID != "" {
		return g.signer.SignWithKID(g.privateKey, claims, g.keyID)
	}

	return g.signer.Sign(g.privateKey, claims)
}

// VerifyToken verifies a JWT and returns the claims.
func (g *DefaultJWTGenerator) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	if g.publicKey == nil {
		return nil, fmt.Errorf("public key not available for verification")
	}

	verifier := keychainjwt.NewVerifier()
	opts := &keychainjwt.VerifyOptions{
		ValidateIssuer:   true,
		ExpectedIssuer:   g.issuer,
		ValidateAudience: len(g.audience) > 0,
		ExpectedAudience: g.audience[0],
		ValidateExpiry:   true,
	}

	token, err := verifier.VerifyWithOptions(tokenString, g.publicKey, opts)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return claims, nil
}

// PublicKey returns the public key for token verification.
func (g *DefaultJWTGenerator) PublicKey() crypto.PublicKey {
	return g.publicKey
}

// Issuer returns the configured issuer.
func (g *DefaultJWTGenerator) Issuer() string {
	return g.issuer
}

// Audience returns the configured audience.
func (g *DefaultJWTGenerator) Audience() []string {
	return g.audience
}

// ExpiresIn returns the token expiration duration.
func (g *DefaultJWTGenerator) ExpiresIn() time.Duration {
	return g.expiresIn
}
