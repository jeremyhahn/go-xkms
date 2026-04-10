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

package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// WellKnownPath is the path to the OIDC discovery document.
	WellKnownPath = "/.well-known/openid-configuration"

	// DefaultHTTPTimeout is the default timeout for HTTP requests.
	DefaultHTTPTimeout = 30 * time.Second

	// JWKSCacheDuration is how long to cache JWKS keys.
	JWKSCacheDuration = 1 * time.Hour
)

// DefaultScopes are the default OIDC scopes requested.
// offline_access is required by most providers (Okta, Microsoft, Auth0, Keycloak)
// to issue refresh tokens.
var DefaultScopes = []string{"openid", "profile", "email", "offline_access"}

// ProviderConfig contains the configuration for an OIDC provider.
type ProviderConfig struct {
	// Issuer is the OIDC provider's issuer URL (e.g., "https://accounts.google.com").
	Issuer string

	// ClientID is the OAuth2 client ID.
	ClientID string

	// ClientSecret is the OAuth2 client secret (optional for public clients).
	ClientSecret string

	// RedirectURL is the callback URL for the authorization flow.
	RedirectURL string

	// Scopes are the OIDC scopes to request (defaults to openid, profile, email).
	Scopes []string

	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client

	// SkipDiscovery skips automatic discovery (endpoints must be set manually).
	SkipDiscovery bool
}

// Validate validates the provider configuration.
func (c *ProviderConfig) Validate() error {
	if c.Issuer == "" {
		return ErrInvalidIssuer
	}
	if c.ClientID == "" {
		return ErrInvalidClientID
	}
	if c.RedirectURL == "" {
		return ErrInvalidRedirectURL
	}

	// Validate issuer URL format
	parsed, err := url.Parse(c.Issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ErrInvalidIssuer
	}

	// Validate redirect URL format
	parsed, err = url.Parse(c.RedirectURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ErrInvalidRedirectURL
	}

	return nil
}

// EffectiveScopes returns the scopes to use, defaulting to DefaultScopes if none are set.
func (c *ProviderConfig) EffectiveScopes() []string {
	if len(c.Scopes) == 0 {
		return DefaultScopes
	}
	return c.Scopes
}

// Provider represents an OIDC provider with discovered endpoints.
type Provider struct {
	// Issuer is the issuer identifier.
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the URL for authorization requests.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is the URL for token requests.
	TokenEndpoint string `json:"token_endpoint"`

	// UserinfoEndpoint is the URL for userinfo requests.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// JwksURI is the URL for the JSON Web Key Set.
	JwksURI string `json:"jwks_uri"`

	// RegistrationEndpoint is the URL for dynamic client registration.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// RevocationEndpoint is the URL for token revocation.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// IntrospectionEndpoint is the URL for token introspection.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// EndSessionEndpoint is the URL for ending sessions (logout).
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	// ScopesSupported lists supported scopes.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResponseTypesSupported lists supported response types.
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// ResponseModesSupported lists supported response modes.
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// GrantTypesSupported lists supported grant types.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// SubjectTypesSupported lists supported subject types.
	SubjectTypesSupported []string `json:"subject_types_supported,omitempty"`

	// IDTokenSigningAlgValuesSupported lists supported ID token signing algorithms.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists supported token endpoint auth methods.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// CodeChallengeMethodsSupported lists supported PKCE challenge methods.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// ClaimsSupported lists supported claims.
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// DPoPSigningAlgValuesSupported lists supported DPoP signing algorithms (RFC 9449).
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	httpClient *http.Client
	jwksCache  *JWKSCache
	mu         sync.RWMutex
}

// JWKSCache caches the JWKS keys.
type JWKSCache struct {
	Keys      []JWK
	ExpiresAt time.Time
	mu        sync.RWMutex
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use,omitempty"`
	Kid string   `json:"kid,omitempty"`
	Alg string   `json:"alg,omitempty"`
	N   string   `json:"n,omitempty"`   // RSA modulus
	E   string   `json:"e,omitempty"`   // RSA exponent
	X   string   `json:"x,omitempty"`   // EC x coordinate
	Y   string   `json:"y,omitempty"`   // EC y coordinate
	Crv string   `json:"crv,omitempty"` // EC curve
	X5c []string `json:"x5c,omitempty"` // X.509 certificate chain
}

// JWKSet represents a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// NewProvider creates a new OIDC provider with the given configuration.
// If SkipDiscovery is false, it automatically discovers provider endpoints.
func NewProvider(ctx context.Context, config *ProviderConfig) (*Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: DefaultHTTPTimeout,
		}
	}

	p := &Provider{
		Issuer:     strings.TrimSuffix(config.Issuer, "/"),
		httpClient: httpClient,
		jwksCache:  &JWKSCache{},
	}

	if !config.SkipDiscovery {
		if err := p.Discover(ctx); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// Discover fetches the OIDC discovery document and populates provider endpoints.
func (p *Provider) Discover(ctx context.Context) error {
	discoveryURL := p.Issuer + WellKnownPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d from %s", ErrDiscoveryFailed, resp.StatusCode, discoveryURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: failed to read response body: %v", ErrDiscoveryFailed, err)
	}

	var metadata Provider
	if err := json.Unmarshal(body, &metadata); err != nil {
		return fmt.Errorf("%w: invalid JSON response: %v", ErrDiscoveryFailed, err)
	}

	// Validate required endpoints
	if metadata.AuthorizationEndpoint == "" {
		return ErrMissingAuthEndpoint
	}
	if metadata.TokenEndpoint == "" {
		return ErrMissingTokenEndpoint
	}
	if metadata.JwksURI == "" {
		return ErrMissingJWKSURI
	}

	// Update provider with discovered endpoints
	p.mu.Lock()
	defer p.mu.Unlock()

	p.AuthorizationEndpoint = metadata.AuthorizationEndpoint
	p.TokenEndpoint = metadata.TokenEndpoint
	p.UserinfoEndpoint = metadata.UserinfoEndpoint
	p.JwksURI = metadata.JwksURI
	p.RegistrationEndpoint = metadata.RegistrationEndpoint
	p.RevocationEndpoint = metadata.RevocationEndpoint
	p.IntrospectionEndpoint = metadata.IntrospectionEndpoint
	p.EndSessionEndpoint = metadata.EndSessionEndpoint
	p.ScopesSupported = metadata.ScopesSupported
	p.ResponseTypesSupported = metadata.ResponseTypesSupported
	p.ResponseModesSupported = metadata.ResponseModesSupported
	p.GrantTypesSupported = metadata.GrantTypesSupported
	p.SubjectTypesSupported = metadata.SubjectTypesSupported
	p.IDTokenSigningAlgValuesSupported = metadata.IDTokenSigningAlgValuesSupported
	p.TokenEndpointAuthMethodsSupported = metadata.TokenEndpointAuthMethodsSupported
	p.CodeChallengeMethodsSupported = metadata.CodeChallengeMethodsSupported
	p.ClaimsSupported = metadata.ClaimsSupported
	p.DPoPSigningAlgValuesSupported = metadata.DPoPSigningAlgValuesSupported

	return nil
}

// FetchJWKS fetches the JSON Web Key Set from the provider.
func (p *Provider) FetchJWKS(ctx context.Context) ([]JWK, error) {
	p.mu.RLock()
	jwksURI := p.JwksURI
	p.mu.RUnlock()

	if jwksURI == "" {
		return nil, ErrMissingJWKSURI
	}

	// Check cache
	p.jwksCache.mu.RLock()
	if time.Now().Before(p.jwksCache.ExpiresAt) && len(p.jwksCache.Keys) > 0 {
		keys := make([]JWK, len(p.jwksCache.Keys))
		copy(keys, p.jwksCache.Keys)
		p.jwksCache.mu.RUnlock()
		return keys, nil
	}
	p.jwksCache.mu.RUnlock()

	// Fetch JWKS
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, ErrJWKSFetchFailed
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, ErrJWKSFetchFailed
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrJWKSFetchFailed
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrJWKSFetchFailed
	}

	var jwks JWKSet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, ErrJWKSFetchFailed
	}

	// Update cache
	p.jwksCache.mu.Lock()
	p.jwksCache.Keys = jwks.Keys
	p.jwksCache.ExpiresAt = time.Now().Add(JWKSCacheDuration)
	p.jwksCache.mu.Unlock()

	return jwks.Keys, nil
}

// GetSigningKey returns the signing key with the specified key ID.
// If kid is empty, returns the first signing key found.
func (p *Provider) GetSigningKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	keys, err := p.FetchJWKS(ctx)
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		// Only consider RSA keys used for signing
		if key.Kty != "RSA" {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}

		// Match by key ID if specified
		if kid != "" && key.Kid != kid {
			continue
		}

		// Parse RSA public key
		return parseRSAPublicKey(key)
	}

	return nil, ErrNoSigningKey
}

// parseRSAPublicKey parses an RSA public key from a JWK.
func parseRSAPublicKey(key JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, ErrNoSigningKey
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, ErrNoSigningKey
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// SupportsScope returns true if the provider supports the specified scope.
func (p *Provider) SupportsScope(scope string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, s := range p.ScopesSupported {
		if s == scope {
			return true
		}
	}
	return false
}

// SupportsPKCE returns true if the provider supports PKCE with S256.
func (p *Provider) SupportsPKCE() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, method := range p.CodeChallengeMethodsSupported {
		if method == "S256" {
			return true
		}
	}
	// If not explicitly listed, assume support (most providers support it)
	return len(p.CodeChallengeMethodsSupported) == 0
}

// SupportsSigningAlg returns true if the provider supports the specified signing algorithm.
func (p *Provider) SupportsSigningAlg(alg string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, a := range p.IDTokenSigningAlgValuesSupported {
		if a == alg {
			return true
		}
	}
	return false
}

// SupportsDPoP returns true if the provider advertises DPoP support with ES256.
// RFC 9449 requires the provider to list supported DPoP signing algorithms.
func (p *Provider) SupportsDPoP() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, alg := range p.DPoPSigningAlgValuesSupported {
		if alg == "ES256" {
			return true
		}
	}
	return false
}

// IsInitialized returns true if the provider has been initialized with endpoints.
func (p *Provider) IsInitialized() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.AuthorizationEndpoint != "" && p.TokenEndpoint != "" && p.JwksURI != ""
}
