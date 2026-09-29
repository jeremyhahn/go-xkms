// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
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

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
)

// JWTAuthenticator authenticates requests using JWT tokens.
type JWTAuthenticator struct {
	// publicKey is used to verify token signatures
	publicKey crypto.PublicKey
	// validMethods is the set of jwt.SigningMethod names accepted for
	// publicKey's type, pinned at construction time. It never includes an
	// HS* method, so a token forged with alg: HS256 and signed with
	// publicKey's own bytes as an HMAC secret is refused before the key
	// function even runs.
	validMethods []string
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
		return nil, &errs.Message{Msg: "config is required"}
	}
	if config.PublicKey == nil {
		return nil, &errs.Message{Msg: "public key is required"}
	}

	headerName := config.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}

	validMethods, err := validMethodsForKey(config.PublicKey)
	if err != nil {
		return nil, err
	}

	return &JWTAuthenticator{
		publicKey:    config.PublicKey,
		validMethods: validMethods,
		issuer:       config.Issuer,
		audience:     config.Audience,
		headerName:   headerName,
	}, nil
}

// AuthenticateHTTP authenticates an HTTP request using a JWT token.
func (a *JWTAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	// Get token from Authorization header
	authHeader := r.Header.Get(a.headerName)
	if authHeader == "" {
		return nil, &errs.Message{Msg: "no authorization header"}
	}

	// Extract Bearer token
	tokenString := ""
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		tokenString = authHeader
	}

	if tokenString == "" {
		return nil, &errs.Message{Msg: "no token provided"}
	}

	// Parse and validate token
	identity, err := a.validateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Add HTTP-specific attributes
	identity.Metadata["auth_method"] = "jwt"
	identity.Metadata["remote_addr"] = r.RemoteAddr

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
		return nil, &errs.Message{Msg: "no token provided in metadata"}
	}

	// Parse and validate token
	identity, err := a.validateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Add gRPC-specific attributes
	identity.Metadata["auth_method"] = "jwt"

	return identity, nil
}

// validateToken parses and validates a JWT token.
//
// The token's standard claims map onto qrdb's Identity fields:
//   - sub        → Identity.Subject (required)
//   - tenant_id  → Identity.TenantID
//   - role       → Identity.Roles (single role token)
//   - roles      → Identity.Roles (preferred multi-role token)
//   - username   → Identity.Metadata["username"]
//   - name       → Identity.Metadata["display_name"]
//   - email      → Identity.Metadata["email"] (the canonical login key;
//     absent for principals that have none)
//
// RefreshTokenType is the typ claim the token issuer stamps on refresh
// tokens and the marker bearer authentication refuses: a refresh token is
// exchanged at the refresh endpoint only, never presented to a protected
// route.
const RefreshTokenType = "refresh"

func (a *JWTAuthenticator) validateToken(tokenString string) (*Identity, error) {
	// Parse token with verification. WithValidMethods pins the accepted
	// alg header values to publicKey's actual type (RS*/PS* for RSA,
	// ES* for ECDSA, EdDSA for Ed25519) so a token cannot select HS* and
	// have its signature "verified" against publicKey's own bytes used
	// as an HMAC secret.
	// WithExpirationRequired refuses a token that omits the exp claim
	// entirely: without it, jwt/v5's default expiry check is a no-op (a
	// token with no exp claim never expires), which is the same as bearer
	// authentication accepting a permanent credential.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return a.publicKey, nil
	}, jwt.WithValidMethods(a.validMethods), jwt.WithExpirationRequired())
	if err != nil {
		return nil, &errs.Wrapped{Msg: "invalid token", Err: err}
	}

	if !token.Valid {
		return nil, &errs.Message{Msg: "token is not valid"}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &errs.Message{Msg: "invalid claims type"}
	}

	// A refresh token is signed by the same key and carries the same
	// identity snapshot as its access token, but it lives for hours rather
	// than minutes and is meant for one endpoint. Presenting it as a bearer
	// credential would bypass the access token's lifetime, so bearer
	// authentication fails closed on the refresh marker.
	if typ, _ := claims["typ"].(string); typ == RefreshTokenType {
		return nil, &errs.Message{Msg: "refresh token presented as a bearer token"}
	}

	// Validate issuer if configured
	if a.issuer != "" {
		iss, ok := claims["iss"].(string)
		if !ok || iss != a.issuer {
			return nil, &errs.Message{Msg: fmt.Sprintf("invalid issuer: expected %s", a.issuer)}
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
		return nil, &errs.Message{Msg: "missing subject claim"}
	}

	identity := &Identity{
		Subject:  sub,
		Metadata: make(map[string]string),
	}

	// Extract roles. Prefer the multi-role "roles" claim; fall back to a
	// single-role "role" claim for OAuth2 deployments that emit one role.
	identity.Roles = extractRolesClaim(claims)

	// Extract username if present
	if username, ok := claims["username"].(string); ok {
		identity.Metadata["username"] = username
	}

	// Extract name if present
	if name, ok := claims["name"].(string); ok {
		identity.Metadata["display_name"] = name
	}

	// Extract the email login key if present. A token minted for a principal
	// without one carries no claim, and the metadata key stays absent.
	if email, ok := claims["email"].(string); ok && email != "" {
		identity.Metadata["email"] = email
	}

	// Extract tenant_id if present
	if tenantID, ok := claims["tenant_id"].(string); ok {
		identity.TenantID = tenantID
	}

	// Extract the attestation level the PIV login recorded, so a handler or
	// authorizer behind bearer auth can tell a login that proved a smartcard
	// from one the deployment accepted without proof. A token minted by any
	// other flow carries no claim, and the metadata key stays absent.
	if level, ok := claims["attest_level"].(string); ok && level != "" {
		identity.Metadata["attest_level"] = level
	}

	return identity, nil
}

// extractRolesClaim extracts the role list from a JWT claims map. It supports
// the canonical "roles" claim ([]string or []interface{}) and falls back to a
// single-role "role" claim. Returns an empty slice when no role claim is set.
func extractRolesClaim(claims jwt.MapClaims) []string {
	if v, ok := claims["roles"]; ok {
		switch r := v.(type) {
		case []string:
			out := make([]string, len(r))
			copy(out, r)
			return out
		case []interface{}:
			out := make([]string, 0, len(r))
			for _, item := range r {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			return out
		case string:
			if r != "" {
				return []string{r}
			}
		}
	}
	if role, ok := claims["role"].(string); ok && role != "" {
		return []string{role}
	}
	return nil
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
		return &errs.Message{Msg: fmt.Sprintf("invalid audience: %s", v)}
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
		return &errs.Message{Msg: fmt.Sprintf("invalid audience: %v", v)}
	default:
		return &errs.Message{Msg: "invalid audience format"}
	}
}

// Name returns the authenticator name.
func (a *JWTAuthenticator) Name() string {
	return "jwt"
}
