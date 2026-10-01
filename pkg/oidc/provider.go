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

	"github.com/jeremyhahn/go-xkms/pkg/urlsafety"
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
	// It is implied whenever any manual endpoint below is set, so callers
	// need not set it explicitly once they supply endpoints.
	SkipDiscovery bool

	// AuthorizationEndpoint is the manual authorization endpoint, used
	// instead of discovery when SkipDiscovery is in effect.
	AuthorizationEndpoint string

	// TokenEndpoint is the manual token endpoint, used instead of
	// discovery when SkipDiscovery is in effect.
	TokenEndpoint string

	// JwksURI is the manual JWKS URI, used instead of discovery when
	// SkipDiscovery is in effect.
	JwksURI string

	// UserinfoEndpoint is the manual userinfo endpoint, used instead of
	// discovery when SkipDiscovery is in effect. Optional: some providers
	// (e.g. CLI-only OAuth2 clients) have no userinfo endpoint.
	UserinfoEndpoint string

	// TokenEncoding selects how token requests (authorization code
	// exchange and refresh) are encoded. Defaults to TokenEncodingForm.
	TokenEncoding TokenEncoding

	// DeviceStyle selects the device login protocol (StartDeviceAuthorization
	// and PollDeviceToken). Defaults to DeviceStyleRFC8628.
	DeviceStyle DeviceStyle
}

// hasManualEndpoint returns true if any manual endpoint field is set,
// which implies SkipDiscovery regardless of that field's literal value.
func (c *ProviderConfig) hasManualEndpoint() bool {
	return c.AuthorizationEndpoint != "" || c.TokenEndpoint != "" ||
		c.JwksURI != "" || c.UserinfoEndpoint != ""
}

// skipsDiscovery returns true if discovery should be skipped, either
// because SkipDiscovery was set explicitly or because a manual endpoint
// was supplied.
func (c *ProviderConfig) skipsDiscovery() bool {
	return c.SkipDiscovery || c.hasManualEndpoint()
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

	if err := c.TokenEncoding.Validate(); err != nil {
		return err
	}

	// Manual endpoints are only required once the caller has started
	// supplying them; a bare SkipDiscovery: true with no endpoints at all
	// is the pre-existing "I will populate the Provider myself" contract
	// and is left alone.
	if c.hasManualEndpoint() {
		var missing []string
		if c.AuthorizationEndpoint == "" {
			missing = append(missing, "AuthorizationEndpoint")
		}
		if c.TokenEndpoint == "" {
			missing = append(missing, "TokenEndpoint")
		}
		if c.JwksURI == "" {
			missing = append(missing, "JwksURI")
		}
		if len(missing) > 0 {
			return &DetailError{Err: ErrIncompleteManualEndpoints, Detail: fmt.Sprintf(": %s", strings.Join(missing, ", "))}
		}
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

// EffectiveTokenEncoding returns the token encoding to use, defaulting to
// TokenEncodingForm if none is set.
func (c *ProviderConfig) EffectiveTokenEncoding() TokenEncoding {
	return c.TokenEncoding.orDefault()
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

	// DeviceAuthorizationEndpoint is the URL for RFC 8628 device
	// authorization requests. It is empty for a provider without a device
	// flow.
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

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

	if config.skipsDiscovery() {
		p.AuthorizationEndpoint = config.AuthorizationEndpoint
		p.TokenEndpoint = config.TokenEndpoint
		p.JwksURI = config.JwksURI
		p.UserinfoEndpoint = config.UserinfoEndpoint
	} else if err := p.Discover(ctx); err != nil {
		return nil, err
	}

	return p, nil
}

// Endpoints names a provider's endpoints explicitly, for a provider used
// without discovery. Only Token is required: a credential that is imported,
// refreshed, or logged in through a device flow never needs the
// authorization endpoint or the JWKS.
type Endpoints struct {
	// Authorization is the authorization endpoint (authorization code flow).
	Authorization string

	// Token is the token endpoint. Required.
	Token string

	// DeviceAuthorization is the device authorization endpoint (device flow).
	DeviceAuthorization string

	// Revocation is the token revocation endpoint.
	Revocation string

	// JWKS is the JSON Web Key Set URI (ID token verification).
	JWKS string

	// Userinfo is the userinfo endpoint.
	Userinfo string
}

// NewEndpointProvider returns a Provider over explicit endpoints, without
// discovery. Every endpoint must be https, or http on the loopback
// interface -- the rule discovery applies to a discovered document.
func NewEndpointProvider(issuer string, ep Endpoints, httpClient *http.Client) (*Provider, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, ErrInvalidIssuer
	}
	if ep.Token == "" {
		return nil, ErrMissingTokenEndpoint
	}
	for _, endpoint := range []struct {
		name  string
		value string
	}{
		{"authorization_endpoint", ep.Authorization},
		{"token_endpoint", ep.Token},
		{"device_authorization_endpoint", ep.DeviceAuthorization},
		{"revocation_endpoint", ep.Revocation},
		{"jwks_uri", ep.JWKS},
		{"userinfo_endpoint", ep.Userinfo},
	} {
		if err := validateDiscoveredEndpoint(endpoint.name, endpoint.value); err != nil {
			return nil, err
		}
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return &Provider{
		Issuer:                      strings.TrimSuffix(issuer, "/"),
		AuthorizationEndpoint:       ep.Authorization,
		TokenEndpoint:               ep.Token,
		DeviceAuthorizationEndpoint: ep.DeviceAuthorization,
		RevocationEndpoint:          ep.Revocation,
		JwksURI:                     ep.JWKS,
		UserinfoEndpoint:            ep.Userinfo,
		httpClient:                  httpClient,
		jwksCache:                   &JWKSCache{},
	}, nil
}

// DiscoverProvider fetches issuer's discovery document and returns the
// provider it describes. Unlike NewProvider it needs no client
// configuration: it serves a caller that records the discovered endpoints
// once and uses them later through NewEndpointProvider.
func DiscoverProvider(ctx context.Context, issuer string, httpClient *http.Client) (*Provider, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, ErrInvalidIssuer
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	p := &Provider{
		Issuer:     strings.TrimSuffix(issuer, "/"),
		httpClient: httpClient,
		jwksCache:  &JWKSCache{},
	}
	if err := p.Discover(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// HasTokenEndpoint reports whether the provider has a token endpoint, the
// one endpoint every token request (exchange, refresh, device poll) needs.
func (p *Provider) HasTokenEndpoint() bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.TokenEndpoint != ""
}

// Discover fetches the OIDC discovery document and populates provider endpoints.
func (p *Provider) Discover(ctx context.Context) error {
	discoveryURL := p.Issuer + WellKnownPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrDiscoveryFailed, Cause: err}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrDiscoveryFailed, Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &DetailError{Err: ErrDiscoveryFailed, Detail: fmt.Sprintf(": HTTP %d from %s", resp.StatusCode, discoveryURL)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &DetailError{Err: ErrDiscoveryFailed, Detail: fmt.Sprintf(": failed to read response body: %v", err)}
	}

	var metadata Provider
	if err := json.Unmarshal(body, &metadata); err != nil {
		return &DetailError{Err: ErrDiscoveryFailed, Detail: fmt.Sprintf(": invalid JSON response: %v", err)}
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

	// The discovery document is remote, attacker-influenceable content: a
	// compromised or spoofed IdP could point authorization_endpoint at a
	// URL that ends up opened in the user's browser (go-xkms#1275), or
	// point token_endpoint/jwks_uri/etc. at a plaintext or attacker-owned
	// host. Every endpoint the document supplies must be https, with an
	// exception for the loopback interface that development IdPs commonly
	// run on.
	for _, endpoint := range []struct {
		name  string
		value string
	}{
		{"authorization_endpoint", metadata.AuthorizationEndpoint},
		{"token_endpoint", metadata.TokenEndpoint},
		{"jwks_uri", metadata.JwksURI},
		{"userinfo_endpoint", metadata.UserinfoEndpoint},
		{"registration_endpoint", metadata.RegistrationEndpoint},
		{"revocation_endpoint", metadata.RevocationEndpoint},
		{"introspection_endpoint", metadata.IntrospectionEndpoint},
		{"end_session_endpoint", metadata.EndSessionEndpoint},
		{"device_authorization_endpoint", metadata.DeviceAuthorizationEndpoint},
	} {
		if err := validateDiscoveredEndpoint(endpoint.name, endpoint.value); err != nil {
			return err
		}
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
	p.DeviceAuthorizationEndpoint = metadata.DeviceAuthorizationEndpoint
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

// validateDiscoveredEndpoint enforces that a discovery-supplied endpoint
// URL uses https, with an exception for the loopback interface (127.0.0.1,
// ::1, localhost) commonly used by development identity providers. An
// empty value is not an error here: FetchJWKS, Discover's own required-
// endpoint checks above, and the OIDC client already reject an empty
// endpoint where one is actually required.
func validateDiscoveredEndpoint(name, endpoint string) error {
	if endpoint == "" {
		return nil
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return &DetailError{Err: ErrInsecureEndpoint, Detail: fmt.Sprintf(": %s: %v", name, err)}
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && urlsafety.IsLoopbackHost(u.Host) {
		return nil
	}

	return &DetailError{Err: ErrInsecureEndpoint, Detail: fmt.Sprintf(": %s has scheme %q", name, u.Scheme)}
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
	defer func() { _ = resp.Body.Close() }()

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
