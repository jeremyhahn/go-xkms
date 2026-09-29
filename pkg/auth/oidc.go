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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
)

// closeOIDCResponseBody closes resp.Body and logs a failure at debug level.
// Every call site here has already decided its result (success or error)
// before this deferred call runs, so a close failure changes nothing about
// the caller's outcome.
func closeOIDCResponseBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		slog.Debug("auth: failed to close OIDC HTTP response body", "error", err)
	}
}

// maxOIDCResponseBytes bounds every response body read from the identity
// provider: the discovery document, the JWKS and the userinfo claims. Each
// is a small JSON document; the cap stops a hostile or compromised provider
// from exhausting memory with an endless body.
const maxOIDCResponseBytes = 1 << 20

// readOIDCResponse reads resp's body, refusing one longer than
// maxOIDCResponseBytes with ErrOIDCResponseTooLarge.
func readOIDCResponse(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOIDCResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxOIDCResponseBytes {
		return nil, ErrOIDCResponseTooLarge
	}
	return body, nil
}

// OIDCAuthenticatorError represents an error from the OIDC authenticator.
type OIDCAuthenticatorError struct {
	Message string
	Cause   error
}

// Error returns the error message.
func (e *OIDCAuthenticatorError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap returns the underlying error.
func (e *OIDCAuthenticatorError) Unwrap() error {
	return e.Cause
}

// Sentinel errors for OIDC authentication.
var (
	ErrOIDCConfigRequired       = &OIDCAuthenticatorError{Message: "config is required"}
	ErrOIDCIssuerRequired       = &OIDCAuthenticatorError{Message: "issuer is required"}
	ErrOIDCClientIDRequired     = &OIDCAuthenticatorError{Message: "client ID is required"}
	ErrOIDCNoAuthorizationToken = &OIDCAuthenticatorError{Message: "no authorization token provided"}
	ErrOIDCNoTokenInMetadata    = &OIDCAuthenticatorError{Message: "no token provided in metadata"}
	ErrOIDCTokenValidation      = &OIDCAuthenticatorError{Message: "token validation failed"}
	ErrOIDCDiscoveryFailed      = &OIDCAuthenticatorError{Message: "OIDC discovery failed"}
	ErrOIDCJWKSFetchFailed      = &OIDCAuthenticatorError{Message: "failed to fetch JWKS"}
	ErrOIDCUserInfoFailed       = &OIDCAuthenticatorError{Message: "userinfo request failed"}
	ErrOIDCMissingSubject       = &OIDCAuthenticatorError{Message: "missing subject claim"}
	ErrOIDCInvalidIssuer        = &OIDCAuthenticatorError{Message: "invalid issuer"}
	ErrOIDCInvalidAudience      = &OIDCAuthenticatorError{Message: "invalid audience"}
	ErrOIDCResponseTooLarge     = &OIDCAuthenticatorError{Message: "identity provider response too large"}
)

// OIDCConfig configures the OIDC authenticator.
type OIDCConfig struct {
	// Issuer is the OIDC provider issuer URL (required)
	Issuer string

	// ClientID is the OAuth2 client ID (required)
	ClientID string

	// Audience is the expected audience (optional, defaults to ClientID)
	Audience []string

	// JWKSCacheTTL is the time-to-live for cached JWKS keys (default: 1 hour)
	JWKSCacheTTL time.Duration

	// HTTPClient is the HTTP client used for provider communication (optional)
	HTTPClient *http.Client

	// SkipClientIDCheck skips the client ID validation (for testing)
	SkipClientIDCheck bool

	// SkipIssuerCheck skips the issuer validation (for testing)
	SkipIssuerCheck bool
}

// oidcDiscoveryDocument represents the OpenID Connect discovery document.
type oidcDiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`

	// IDTokenSigningAlgValuesSupported is the IdP's advertised set of ID
	// token signing algorithms (OIDC Discovery 1.0 section 3, REQUIRED
	// metadata field). When present, validateIDToken intersects it with
	// the algorithms permitted by the verification key's own type, so a
	// key served with an algorithm the IdP never advertised is refused
	// even if that algorithm would otherwise be valid for the key type.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// jwksCache holds cached JWKS keys with expiration.
type jwksCache struct {
	keys      *jose.JSONWebKeySet
	expiresAt time.Time
	mu        sync.RWMutex
}

// OIDCAuthenticator validates OIDC ID tokens and access tokens.
type OIDCAuthenticator struct {
	issuer            string
	clientID          string
	audience          []string
	httpClient        *http.Client
	jwksCacheTTL      time.Duration
	skipClientIDCheck bool
	skipIssuerCheck   bool

	// Cached discovery document and JWKS
	discovery atomic.Pointer[oidcDiscoveryDocument]
	jwksCache *jwksCache
}

// NewOIDCAuthenticator creates an OIDC authenticator.
// It performs provider discovery to get JWKS endpoint.
func NewOIDCAuthenticator(ctx context.Context, config *OIDCConfig) (*OIDCAuthenticator, error) {
	if config == nil {
		return nil, ErrOIDCConfigRequired
	}
	if config.Issuer == "" {
		return nil, ErrOIDCIssuerRequired
	}
	if config.ClientID == "" {
		return nil, ErrOIDCClientIDRequired
	}

	// Default audience to client ID if not specified
	audience := config.Audience
	if len(audience) == 0 {
		audience = []string{config.ClientID}
	}

	// Default cache TTL to 1 hour
	cacheTTL := config.JWKSCacheTTL
	if cacheTTL == 0 {
		cacheTTL = time.Hour
	}

	// Default HTTP client
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	auth := &OIDCAuthenticator{
		issuer:            strings.TrimSuffix(config.Issuer, "/"),
		clientID:          config.ClientID,
		audience:          audience,
		httpClient:        httpClient,
		jwksCacheTTL:      cacheTTL,
		skipClientIDCheck: config.SkipClientIDCheck,
		skipIssuerCheck:   config.SkipIssuerCheck,
		jwksCache:         &jwksCache{},
	}

	// Perform discovery
	if err := auth.discover(ctx); err != nil {
		return nil, err
	}

	return auth, nil
}

// AuthenticateHTTP validates the Bearer token from Authorization header.
// Supports both ID tokens and access tokens (via userinfo endpoint).
func (a *OIDCAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, ErrOIDCNoAuthorizationToken
	}

	tokenString := ""
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		tokenString = authHeader
	}

	if tokenString == "" {
		return nil, ErrOIDCNoAuthorizationToken
	}

	identity, err := a.validateToken(r.Context(), tokenString)
	if err != nil {
		return nil, err
	}

	// Add HTTP-specific attributes
	identity.Metadata["auth_method"] = "oidc"
	identity.Metadata["remote_addr"] = r.RemoteAddr

	return identity, nil
}

// AuthenticateGRPC validates the token from gRPC metadata.
func (a *OIDCAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	var tokenString string

	if values := md.Get("authorization"); len(values) > 0 {
		auth := values[0]
		if strings.HasPrefix(auth, "Bearer ") {
			tokenString = strings.TrimPrefix(auth, "Bearer ")
		} else {
			tokenString = auth
		}
	}

	if tokenString == "" {
		return nil, ErrOIDCNoTokenInMetadata
	}

	identity, err := a.validateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// Add gRPC-specific attributes
	identity.Metadata["auth_method"] = "oidc"

	return identity, nil
}

// Name returns "oidc".
func (a *OIDCAuthenticator) Name() string {
	return "oidc"
}

// discover performs OIDC discovery to fetch the provider configuration.
func (a *OIDCAuthenticator) discover(ctx context.Context) error {
	discoveryURL := a.issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return &OIDCAuthenticatorError{Message: "failed to create discovery request", Cause: err}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return &OIDCAuthenticatorError{Message: ErrOIDCDiscoveryFailed.Message, Cause: err}
	}
	defer closeOIDCResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return &OIDCAuthenticatorError{
			Message: ErrOIDCDiscoveryFailed.Message,
			Cause:   &OIDCAuthenticatorError{Message: "HTTP status: " + resp.Status},
		}
	}

	body, err := readOIDCResponse(resp)
	if err != nil {
		return &OIDCAuthenticatorError{Message: "failed to read discovery response", Cause: err}
	}

	var doc oidcDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return &OIDCAuthenticatorError{Message: "failed to parse discovery document", Cause: err}
	}

	a.discovery.Store(&doc)
	return nil
}

// getJWKS retrieves the JWKS, using cache if valid.
func (a *OIDCAuthenticator) getJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	a.jwksCache.mu.RLock()
	if a.jwksCache.keys != nil && time.Now().Before(a.jwksCache.expiresAt) {
		keys := a.jwksCache.keys
		a.jwksCache.mu.RUnlock()
		return keys, nil
	}
	a.jwksCache.mu.RUnlock()

	// Fetch fresh JWKS
	a.jwksCache.mu.Lock()
	defer a.jwksCache.mu.Unlock()

	// Double-check after acquiring write lock
	if a.jwksCache.keys != nil && time.Now().Before(a.jwksCache.expiresAt) {
		return a.jwksCache.keys, nil
	}

	discovery := a.discovery.Load()
	if discovery == nil || discovery.JWKSUri == "" {
		return nil, &OIDCAuthenticatorError{Message: "JWKS URI not available"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.JWKSUri, nil)
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: "failed to create JWKS request", Cause: err}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: ErrOIDCJWKSFetchFailed.Message, Cause: err}
	}
	defer closeOIDCResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, &OIDCAuthenticatorError{
			Message: ErrOIDCJWKSFetchFailed.Message,
			Cause:   &OIDCAuthenticatorError{Message: "HTTP status: " + resp.Status},
		}
	}

	body, err := readOIDCResponse(resp)
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: "failed to read JWKS response", Cause: err}
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, &OIDCAuthenticatorError{Message: "failed to parse JWKS", Cause: err}
	}

	a.jwksCache.keys = &jwks
	a.jwksCache.expiresAt = time.Now().Add(a.jwksCacheTTL)

	return &jwks, nil
}

// validateToken validates the token as an ID token or falls back to userinfo.
func (a *OIDCAuthenticator) validateToken(ctx context.Context, tokenString string) (*Identity, error) {
	// Try to validate as ID token first
	identity, err := a.validateIDToken(ctx, tokenString)
	if err == nil {
		return identity, nil
	}

	// Fall back to userinfo endpoint for access tokens
	return a.validateAccessToken(ctx, tokenString)
}

// validateIDToken validates the token as a JWT ID token.
func (a *OIDCAuthenticator) validateIDToken(ctx context.Context, tokenString string) (*Identity, error) {
	jwks, err := a.getJWKS(ctx)
	if err != nil {
		return nil, err
	}

	// Parse the token to get the key ID
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: "failed to parse token", Cause: err}
	}

	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, &OIDCAuthenticatorError{Message: "token missing kid header"}
	}

	// Find the key in JWKS
	keys := jwks.Key(kid)
	if len(keys) == 0 {
		return nil, &OIDCAuthenticatorError{Message: "key not found in JWKS for kid: " + kid}
	}

	key := keys[0]
	publicKey := key.Key

	// Pin the accepted alg header values to publicKey's actual type. This
	// refuses HS* outright (validMethodsForKey never returns it, and
	// returns UnsupportedVerificationKeyError for anything that isn't an
	// RSA/ECDSA/Ed25519 public key, including the []byte go-jose would
	// hand back for a JWKS "oct" entry) -- so a JWKS response smuggling a
	// symmetric key can never be used to verify an HS*-signed token
	// against a public key's own bytes.
	validMethods, err := validMethodsForKey(publicKey)
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: ErrOIDCTokenValidation.Message, Cause: err}
	}

	// Further narrow to the algorithms the IdP's discovery document
	// advertised, when it published id_token_signing_alg_values_supported.
	if discovery := a.discovery.Load(); discovery != nil {
		narrowed := intersectSigningAlgorithms(validMethods, discovery.IDTokenSigningAlgValuesSupported)
		if len(narrowed) == 0 && len(discovery.IDTokenSigningAlgValuesSupported) > 0 {
			return nil, &OIDCAuthenticatorError{
				Message: ErrOIDCTokenValidation.Message,
				Cause: &NoCommonSigningAlgorithmError{
					KeyAlgorithms:        validMethods,
					AdvertisedAlgorithms: discovery.IDTokenSigningAlgValuesSupported,
				},
			}
		}
		validMethods = narrowed
	}

	// Parse and verify the token
	verifiedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}, jwt.WithValidMethods(validMethods))
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: ErrOIDCTokenValidation.Message, Cause: err}
	}

	if !verifiedToken.Valid {
		return nil, &OIDCAuthenticatorError{Message: "token is not valid"}
	}

	claims, ok := verifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &OIDCAuthenticatorError{Message: "invalid claims type"}
	}

	// Validate issuer
	if !a.skipIssuerCheck {
		iss, ok := claims["iss"].(string)
		if !ok || iss != a.issuer {
			return nil, &OIDCAuthenticatorError{
				Message: ErrOIDCInvalidIssuer.Message,
				Cause:   &OIDCAuthenticatorError{Message: "expected " + a.issuer + ", got " + iss},
			}
		}
	}

	// Validate audience
	if !a.skipClientIDCheck {
		if err := a.validateAudience(claims); err != nil {
			return nil, err
		}
	}

	return a.claimsToIdentity(claims), nil
}

// validateAccessToken validates an access token via the userinfo endpoint.
func (a *OIDCAuthenticator) validateAccessToken(ctx context.Context, tokenString string) (*Identity, error) {
	discovery := a.discovery.Load()
	if discovery == nil || discovery.UserInfoEndpoint == "" {
		return nil, &OIDCAuthenticatorError{Message: "userinfo endpoint not available"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.UserInfoEndpoint, nil)
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: "failed to create userinfo request", Cause: err}
	}

	req.Header.Set("Authorization", "Bearer "+tokenString)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: ErrOIDCUserInfoFailed.Message, Cause: err}
	}
	defer closeOIDCResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, &OIDCAuthenticatorError{
			Message: ErrOIDCUserInfoFailed.Message,
			Cause:   &OIDCAuthenticatorError{Message: "HTTP status: " + resp.Status},
		}
	}

	body, err := readOIDCResponse(resp)
	if err != nil {
		return nil, &OIDCAuthenticatorError{Message: "failed to read userinfo response", Cause: err}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, &OIDCAuthenticatorError{Message: "failed to parse userinfo response", Cause: err}
	}

	return a.claimsToIdentity(claims), nil
}

// validateAudience validates the audience claim.
func (a *OIDCAuthenticator) validateAudience(claims jwt.MapClaims) error {
	aud := claims["aud"]
	switch v := aud.(type) {
	case string:
		for _, expected := range a.audience {
			if v == expected {
				return nil
			}
		}
		return &OIDCAuthenticatorError{
			Message: ErrOIDCInvalidAudience.Message,
			Cause:   &OIDCAuthenticatorError{Message: v},
		}
	case []interface{}:
		for _, audItem := range v {
			if audStr, ok := audItem.(string); ok {
				for _, expected := range a.audience {
					if audStr == expected {
						return nil
					}
				}
			}
		}
		return &OIDCAuthenticatorError{
			Message: ErrOIDCInvalidAudience.Message,
			Cause:   &OIDCAuthenticatorError{Message: "no matching audience found"},
		}
	default:
		return &OIDCAuthenticatorError{Message: "invalid audience format"}
	}
}

// claimsToIdentity converts OIDC claims to an Identity. The OIDC standard
// claims map onto qrdb's Identity fields:
//
//   - sub                 → Identity.Subject
//   - email               → Identity.Metadata["email"]
//   - name                → Identity.Metadata["display_name"]
//   - preferred_username  → Identity.Metadata["username"]
//   - roles / groups /    → Identity.Roles (collected via extractRoles)
//     Keycloak realm_access / resource_access
func (a *OIDCAuthenticator) claimsToIdentity(claims map[string]interface{}) *Identity {
	identity := &Identity{
		Metadata: make(map[string]string),
	}

	// Extract subject
	if sub, ok := claims["sub"].(string); ok {
		identity.Subject = sub
	}

	// Extract email
	if email, ok := claims["email"].(string); ok {
		identity.Metadata["email"] = email
	}

	// Extract name
	if name, ok := claims["name"].(string); ok {
		identity.Metadata["display_name"] = name
	}

	// Extract preferred username
	if username, ok := claims["preferred_username"].(string); ok {
		identity.Metadata["username"] = username
	}

	// Extract roles/groups into the Roles field
	identity.Roles = extractRoles(claims)

	return identity
}

// extractRoles extracts roles from various OIDC claims.
func extractRoles(claims map[string]interface{}) []string {
	var roles []string

	// Try "roles" claim first
	if r, ok := claims["roles"]; ok {
		roles = append(roles, extractStringSlice(r)...)
	}

	// Try "groups" claim
	if g, ok := claims["groups"]; ok {
		roles = append(roles, extractStringSlice(g)...)
	}

	// Try realm_access.roles (Keycloak)
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if r, ok := realmAccess["roles"]; ok {
			roles = append(roles, extractStringSlice(r)...)
		}
	}

	// Try resource_access.{client}.roles (Keycloak client roles)
	if resourceAccess, ok := claims["resource_access"].(map[string]interface{}); ok {
		for _, clientAccess := range resourceAccess {
			if ca, ok := clientAccess.(map[string]interface{}); ok {
				if r, ok := ca["roles"]; ok {
					roles = append(roles, extractStringSlice(r)...)
				}
			}
		}
	}

	return roles
}

// extractStringSlice converts interface{} to []string.
func extractStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case string:
		return []string{val}
	default:
		return nil
	}
}
