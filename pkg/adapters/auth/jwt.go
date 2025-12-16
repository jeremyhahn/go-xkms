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

package auth

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
)

// JWTAuthenticator authenticates requests using JWT tokens.
type JWTAuthenticator struct {
	// publicKey is used to verify token signatures
	publicKey crypto.PublicKey
	// issuer is the expected issuer claim
	issuer string
	// audience is the expected audience claim
	audience []string
	// headerName is the HTTP header containing the token (default: "Authorization")
	headerName string
}

// JWTConfig configures the JWT authenticator.
type JWTConfig struct {
	// PublicKey is the key used to verify token signatures (required)
	PublicKey crypto.PublicKey
	// Issuer is the expected issuer claim (optional, skips validation if empty)
	Issuer string
	// Audience is the expected audience claim (optional, skips validation if empty)
	Audience []string
	// HeaderName is the HTTP header name (default: "Authorization")
	HeaderName string
}

// NewJWTAuthenticator creates a new JWT authenticator.
func NewJWTAuthenticator(config *JWTConfig) (*JWTAuthenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if config.PublicKey == nil {
		return nil, fmt.Errorf("public key is required")
	}

	headerName := config.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}

	return &JWTAuthenticator{
		publicKey:  config.PublicKey,
		issuer:     config.Issuer,
		audience:   config.Audience,
		headerName: headerName,
	}, nil
}

// AuthenticateHTTP authenticates an HTTP request using a JWT token.
func (a *JWTAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	// Get token from Authorization header
	authHeader := r.Header.Get(a.headerName)
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}

	// Extract Bearer token
	tokenString := ""
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		tokenString = authHeader
	}

	if tokenString == "" {
		return nil, fmt.Errorf("no token provided")
	}

	// Parse and validate token
	identity, err := a.validateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Add HTTP-specific attributes
	identity.Attributes["auth_method"] = "jwt"
	identity.Attributes["remote_addr"] = r.RemoteAddr

	return identity, nil
}

// AuthenticateGRPC authenticates a gRPC request using a JWT token from metadata.
func (a *JWTAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	// Get token from metadata
	var tokenString string

	// Try authorization header
	headerKey := strings.ToLower(a.headerName)
	if values := md.Get(headerKey); len(values) > 0 {
		auth := values[0]
		if strings.HasPrefix(auth, "Bearer ") {
			tokenString = strings.TrimPrefix(auth, "Bearer ")
		} else {
			tokenString = auth
		}
	}

	if tokenString == "" {
		return nil, fmt.Errorf("no token provided in metadata")
	}

	// Parse and validate token
	identity, err := a.validateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Add gRPC-specific attributes
	identity.Attributes["auth_method"] = "jwt"

	return identity, nil
}

// validateToken parses and validates a JWT token.
func (a *JWTAuthenticator) validateToken(tokenString string) (*Identity, error) {
	// Parse token with verification
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return a.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Validate issuer if configured
	if a.issuer != "" {
		iss, ok := claims["iss"].(string)
		if !ok || iss != a.issuer {
			return nil, fmt.Errorf("invalid issuer: expected %s", a.issuer)
		}
	}

	// Validate audience if configured
	if len(a.audience) > 0 {
		if err := a.validateAudience(claims); err != nil {
			return nil, err
		}
	}

	// Extract subject
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("missing subject claim")
	}

	// Build identity
	identity := &Identity{
		Subject:    sub,
		Claims:     make(map[string]interface{}),
		Attributes: make(map[string]string),
	}

	// Copy all claims
	for k, v := range claims {
		identity.Claims[k] = v
	}

	// Extract role if present
	if role, ok := claims["role"].(string); ok {
		identity.Claims["roles"] = []string{role}
	}

	// Extract username if present
	if username, ok := claims["username"].(string); ok {
		identity.Attributes["username"] = username
	}

	// Extract name if present
	if name, ok := claims["name"].(string); ok {
		identity.Attributes["display_name"] = name
	}

	return identity, nil
}

// validateAudience checks if the token audience matches any configured audience.
func (a *JWTAuthenticator) validateAudience(claims jwt.MapClaims) error {
	aud := claims["aud"]
	switch v := aud.(type) {
	case string:
		for _, expected := range a.audience {
			if v == expected {
				return nil
			}
		}
		return fmt.Errorf("invalid audience: %s", v)
	case []interface{}:
		for _, aud := range v {
			if audStr, ok := aud.(string); ok {
				for _, expected := range a.audience {
					if audStr == expected {
						return nil
					}
				}
			}
		}
		return fmt.Errorf("invalid audience: %v", v)
	default:
		return fmt.Errorf("invalid audience format")
	}
}

// Name returns the authenticator name.
func (a *JWTAuthenticator) Name() string {
	return "jwt"
}
