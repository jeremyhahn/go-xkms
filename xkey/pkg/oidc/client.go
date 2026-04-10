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
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// DPoPNonceHeader is the HTTP header used by servers to provide a DPoP nonce.
	DPoPNonceHeader = "DPoP-Nonce"

	// MaxDPoPNonceRetries is the maximum number of DPoP nonce retry attempts.
	MaxDPoPNonceRetries = 3
)

// AuthCodeOptions contains options for the authorization code flow.
type AuthCodeOptions struct {
	// State is the CSRF protection state parameter.
	State string

	// Nonce is the nonce to include in the ID token.
	Nonce string

	// CodeVerifier is the PKCE code verifier (required).
	CodeVerifier string

	// AdditionalParams are additional query parameters for the authorization URL.
	AdditionalParams map[string]string
}

// Validate validates the auth code options.
func (o *AuthCodeOptions) Validate() error {
	if o.State == "" {
		return ErrInvalidState
	}
	if o.CodeVerifier == "" {
		return ErrInvalidCodeVerifier
	}
	return ValidateCodeVerifier(o.CodeVerifier)
}

// Client is an OIDC client for authentication flows.
type Client struct {
	provider  *Provider
	config    *ProviderConfig
	dpopKey   *DPoPKey
	dpopNonce string
	dpopMu    sync.Mutex
}

// NewClient creates a new OIDC client with the given provider and configuration.
func NewClient(provider *Provider, config *ProviderConfig) *Client {
	return &Client{
		provider: provider,
		config:   config,
	}
}

// AuthCodeURL returns the authorization URL for initiating the auth code flow.
// PKCE is required and the code challenge is computed from the code verifier.
func (c *Client) AuthCodeURL(opts *AuthCodeOptions) (string, error) {
	if c.provider == nil || !c.provider.IsInitialized() {
		return "", ErrProviderNotInitialized
	}

	if err := opts.Validate(); err != nil {
		return "", err
	}

	// Build authorization URL
	authURL, err := url.Parse(c.provider.AuthorizationEndpoint)
	if err != nil {
		return "", ErrMissingAuthEndpoint
	}

	// Calculate code challenge
	codeChallenge := GenerateCodeChallenge(opts.CodeVerifier)

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.config.ClientID)
	params.Set("redirect_uri", c.config.RedirectURL)
	params.Set("scope", strings.Join(c.config.EffectiveScopes(), " "))
	params.Set("state", opts.State)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	if opts.Nonce != "" {
		params.Set("nonce", opts.Nonce)
	}

	// Add any additional parameters
	for k, v := range opts.AdditionalParams {
		params.Set(k, v)
	}

	authURL.RawQuery = params.Encode()
	return authURL.String(), nil
}

// Exchange exchanges an authorization code for tokens.
func (c *Client) Exchange(ctx context.Context, code string, opts *AuthCodeOptions) (*TokenResponse, error) {
	if c.provider == nil || !c.provider.IsInitialized() {
		return nil, ErrProviderNotInitialized
	}

	if code == "" {
		return nil, ErrTokenExchangeFailed
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// Build token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.config.RedirectURL)
	data.Set("client_id", c.config.ClientID)
	data.Set("code_verifier", opts.CodeVerifier)

	// Add client secret for confidential clients
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	return c.doTokenRequest(ctx, data)
}

// Refresh exchanges a refresh token for new tokens.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if c.provider == nil || !c.provider.IsInitialized() {
		return nil, ErrProviderNotInitialized
	}

	if refreshToken == "" {
		return nil, ErrMissingRefreshToken
	}

	// Build token request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.config.ClientID)

	// Add client secret for confidential clients
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	return c.doTokenRequest(ctx, data)
}

// doTokenRequest dispatches the token request through the DPoP path when
// a DPoP key is configured, otherwise uses the plain Bearer path.
func (c *Client) doTokenRequest(ctx context.Context, data url.Values) (*TokenResponse, error) {
	c.dpopMu.Lock()
	hasDPoP := c.dpopKey != nil
	c.dpopMu.Unlock()

	if hasDPoP {
		return c.doDPoPTokenRequest(ctx, data)
	}
	return c.doPlainTokenRequest(ctx, data)
}

// doPlainTokenRequest performs a standard token request without DPoP binding.
func (c *Client) doPlainTokenRequest(ctx context.Context, data url.Values) (*TokenResponse, error) {
	httpClient := c.config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.provider.TokenEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, ErrTokenExchangeFailed
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, ErrTokenExchangeFailed
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrTokenExchangeFailed
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseTokenErrorResponse(body, resp.StatusCode)
	}

	return parseTokenSuccessResponse(body)
}

// doDPoPTokenRequest performs a DPoP-bound token request with nonce retry.
// It follows the pattern from RFC 9449 Section 5: the server may respond with
// use_dpop_nonce, requiring the client to retry with the provided nonce.
func (c *Client) doDPoPTokenRequest(ctx context.Context, data url.Values) (*TokenResponse, error) {
	httpClient := c.config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	tokenEndpoint := c.provider.TokenEndpoint

	c.dpopMu.Lock()
	dpopKey := c.dpopKey
	nonce := c.dpopNonce
	c.dpopMu.Unlock()

	for attempt := 0; attempt < MaxDPoPNonceRetries; attempt++ {
		proof, err := dpopKey.GenerateProof(&DPoPProofOptions{
			HTTPMethod: http.MethodPost,
			HTTPUri:    tokenEndpoint,
			Nonce:      nonce,
		})
		if err != nil {
			return nil, ErrDPoPInvalidProof
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
			strings.NewReader(data.Encode()))
		if err != nil {
			return nil, ErrTokenExchangeFailed
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("DPoP", proof)

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, ErrTokenExchangeFailed
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, ErrTokenExchangeFailed
		}

		// Capture server-provided DPoP nonce for subsequent requests.
		if serverNonce := resp.Header.Get(DPoPNonceHeader); serverNonce != "" {
			nonce = serverNonce
			c.dpopMu.Lock()
			c.dpopNonce = serverNonce
			c.dpopMu.Unlock()
		}

		// Handle use_dpop_nonce error — retry with the server nonce.
		if resp.StatusCode == http.StatusBadRequest {
			var errResp struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(body, &errResp) == nil && errResp.Error == "use_dpop_nonce" {
				slog.Debug("DPoP nonce required, retrying", "attempt", attempt+1)
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			return nil, parseTokenErrorResponse(body, resp.StatusCode)
		}

		return parseTokenSuccessResponse(body)
	}

	return nil, ErrDPoPNonceRequired
}

// parseTokenErrorResponse parses an OAuth2 error response body.
func parseTokenErrorResponse(body []byte, statusCode int) *TokenRequestError {
	var errResp struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &errResp)
	return &TokenRequestError{
		Err:         ErrTokenExchangeFailed,
		Code:        errResp.Error,
		Description: errResp.ErrorDescription,
		StatusCode:  statusCode,
	}
}

// parseTokenSuccessResponse parses a successful token endpoint response.
func parseTokenSuccessResponse(body []byte) (*TokenResponse, error) {
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, ErrInvalidResponse
	}

	if tokenResp.ExpiresIn > 0 {
		tokenResp.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return &tokenResp, nil
}

// VerifyIDToken verifies and parses an ID token.
// It validates the signature, issuer, audience, and expiry.
// If nonce is provided, it also validates the nonce claim.
func (c *Client) VerifyIDToken(ctx context.Context, idToken string, nonce string) (*IDTokenClaims, error) {
	if c.provider == nil || !c.provider.IsInitialized() {
		return nil, ErrProviderNotInitialized
	}

	if idToken == "" {
		return nil, ErrInvalidIDToken
	}

	// Parse token to get header (for kid)
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, ErrInvalidIDToken
	}

	// Get the key ID from the token header
	kid := ""
	if kidVal, ok := token.Header["kid"].(string); ok {
		kid = kidVal
	}

	// Get signing key
	pubKey, err := c.provider.GetSigningKey(ctx, kid)
	if err != nil {
		return nil, err
	}

	// Verify and parse token
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithLeeway(time.Minute),
	)

	claims := jwt.MapClaims{}
	_, err = parser.ParseWithClaims(idToken, claims, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		return nil, ErrSignatureVerification
	}

	// Convert to IDTokenClaims
	idClaims, err := parseIDTokenClaims(claims)
	if err != nil {
		return nil, err
	}

	// Validate issuer
	if idClaims.Issuer != c.provider.Issuer {
		return nil, ErrInvalidIssuerClaim
	}

	// Validate audience
	if !idClaims.Audience.Contains(c.config.ClientID) {
		return nil, ErrInvalidAudience
	}

	// Validate expiry
	if idClaims.IsExpired() {
		return nil, ErrIDTokenExpired
	}

	// Validate nonce if provided
	if nonce != "" && idClaims.Nonce != nonce {
		return nil, ErrInvalidNonce
	}

	return idClaims, nil
}

// parseIDTokenClaims converts jwt.MapClaims to IDTokenClaims.
func parseIDTokenClaims(claims jwt.MapClaims) (*IDTokenClaims, error) {
	idClaims := &IDTokenClaims{
		Extra: make(map[string]interface{}),
	}

	// Parse standard claims
	if iss, ok := claims["iss"].(string); ok {
		idClaims.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		idClaims.Subject = sub
	}

	// Parse audience (can be string or array)
	switch aud := claims["aud"].(type) {
	case string:
		idClaims.Audience = Audience{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				idClaims.Audience = append(idClaims.Audience, s)
			}
		}
	}

	// Parse numeric claims
	if exp, ok := claims["exp"].(float64); ok {
		idClaims.Expiry = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		idClaims.IssuedAt = int64(iat)
	}
	if authTime, ok := claims["auth_time"].(float64); ok {
		idClaims.AuthTime = int64(authTime)
	}
	if updatedAt, ok := claims["updated_at"].(float64); ok {
		idClaims.UpdatedAt = int64(updatedAt)
	}

	// Parse string claims
	if nonce, ok := claims["nonce"].(string); ok {
		idClaims.Nonce = nonce
	}
	if azp, ok := claims["azp"].(string); ok {
		idClaims.AuthorizedParty = azp
	}
	if atHash, ok := claims["at_hash"].(string); ok {
		idClaims.AccessTokenHash = atHash
	}
	if cHash, ok := claims["c_hash"].(string); ok {
		idClaims.CodeHash = cHash
	}
	if acr, ok := claims["acr"].(string); ok {
		idClaims.ACR = acr
	}
	if email, ok := claims["email"].(string); ok {
		idClaims.Email = email
	}
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		idClaims.EmailVerified = emailVerified
	}
	if name, ok := claims["name"].(string); ok {
		idClaims.Name = name
	}
	if givenName, ok := claims["given_name"].(string); ok {
		idClaims.GivenName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		idClaims.FamilyName = familyName
	}
	if preferredUsername, ok := claims["preferred_username"].(string); ok {
		idClaims.PreferredUsername = preferredUsername
	}
	if picture, ok := claims["picture"].(string); ok {
		idClaims.Picture = picture
	}
	if profile, ok := claims["profile"].(string); ok {
		idClaims.Profile = profile
	}
	if locale, ok := claims["locale"].(string); ok {
		idClaims.Locale = locale
	}
	if zoneinfo, ok := claims["zoneinfo"].(string); ok {
		idClaims.Zoneinfo = zoneinfo
	}
	if phone, ok := claims["phone_number"].(string); ok {
		idClaims.PhoneNumber = phone
	}
	if phoneVerified, ok := claims["phone_number_verified"].(bool); ok {
		idClaims.PhoneNumberVerified = phoneVerified
	}

	// Parse AMR
	if amr, ok := claims["amr"].([]interface{}); ok {
		for _, a := range amr {
			if s, ok := a.(string); ok {
				idClaims.AMR = append(idClaims.AMR, s)
			}
		}
	}

	// Parse address
	if addr, ok := claims["address"].(map[string]interface{}); ok {
		idClaims.Address = &Address{}
		if formatted, ok := addr["formatted"].(string); ok {
			idClaims.Address.Formatted = formatted
		}
		if street, ok := addr["street_address"].(string); ok {
			idClaims.Address.StreetAddress = street
		}
		if locality, ok := addr["locality"].(string); ok {
			idClaims.Address.Locality = locality
		}
		if region, ok := addr["region"].(string); ok {
			idClaims.Address.Region = region
		}
		if postal, ok := addr["postal_code"].(string); ok {
			idClaims.Address.PostalCode = postal
		}
		if country, ok := addr["country"].(string); ok {
			idClaims.Address.Country = country
		}
	}

	// Store extra claims
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
		"auth_time": true, "nonce": true, "azp": true, "at_hash": true,
		"c_hash": true, "acr": true, "amr": true, "email": true,
		"email_verified": true, "name": true, "given_name": true,
		"family_name": true, "preferred_username": true, "picture": true,
		"profile": true, "locale": true, "zoneinfo": true, "updated_at": true,
		"phone_number": true, "phone_number_verified": true, "address": true,
	}
	for k, v := range claims {
		if !standardClaims[k] {
			idClaims.Extra[k] = v
		}
	}

	return idClaims, nil
}

// UserInfo fetches user information from the userinfo endpoint.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if c.provider == nil || !c.provider.IsInitialized() {
		return nil, ErrProviderNotInitialized
	}

	if c.provider.UserinfoEndpoint == "" {
		return nil, ErrUserInfoFailed
	}

	if accessToken == "" {
		return nil, ErrUserInfoFailed
	}

	httpClient := c.config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.provider.UserinfoEndpoint, nil)
	if err != nil {
		return nil, ErrUserInfoFailed
	}

	// Use DPoP token type when a DPoP key is configured (RFC 9449 Section 7.1).
	c.dpopMu.Lock()
	dpopKey := c.dpopKey
	nonce := c.dpopNonce
	c.dpopMu.Unlock()

	if dpopKey != nil {
		req.Header.Set("Authorization", "DPoP "+accessToken)
		proof, proofErr := dpopKey.GenerateProof(&DPoPProofOptions{
			HTTPMethod:  http.MethodGet,
			HTTPUri:     c.provider.UserinfoEndpoint,
			AccessToken: accessToken,
			Nonce:       nonce,
		})
		if proofErr != nil {
			return nil, ErrUserInfoFailed
		}
		req.Header.Set("DPoP", proof)
	} else {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, ErrUserInfoFailed
	}
	defer resp.Body.Close()

	// Capture server nonce from resource response.
	if serverNonce := resp.Header.Get(DPoPNonceHeader); serverNonce != "" {
		c.dpopMu.Lock()
		c.dpopNonce = serverNonce
		c.dpopMu.Unlock()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ErrUserInfoFailed
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrUserInfoFailed
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, ErrInvalidResponse
	}

	return &userInfo, nil
}

// RevokeToken revokes a token at the revocation endpoint.
func (c *Client) RevokeToken(ctx context.Context, token string, tokenTypeHint string) error {
	if c.provider == nil || !c.provider.IsInitialized() {
		return ErrProviderNotInitialized
	}

	if c.provider.RevocationEndpoint == "" {
		return ErrHTTPRequest
	}

	if token == "" {
		return ErrHTTPRequest
	}

	httpClient := c.config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", c.config.ClientID)

	if tokenTypeHint != "" {
		data.Set("token_type_hint", tokenTypeHint)
	}
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.provider.RevocationEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return ErrHTTPRequest
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Attach DPoP proof if key is configured (RFC 9449 Section 7).
	c.dpopMu.Lock()
	dpopKey := c.dpopKey
	nonce := c.dpopNonce
	c.dpopMu.Unlock()

	if dpopKey != nil {
		proof, proofErr := dpopKey.GenerateProof(&DPoPProofOptions{
			HTTPMethod:  http.MethodPost,
			HTTPUri:     c.provider.RevocationEndpoint,
			AccessToken: token,
			Nonce:       nonce,
		})
		if proofErr == nil {
			req.Header.Set("DPoP", proof)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return ErrHTTPRequest
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return ErrHTTPRequest
	}

	return nil
}

// LogoutURL returns the end session URL for logging out.
func (c *Client) LogoutURL(idTokenHint string, postLogoutRedirectURI string, state string) (string, error) {
	if c.provider == nil || !c.provider.IsInitialized() {
		return "", ErrProviderNotInitialized
	}

	if c.provider.EndSessionEndpoint == "" {
		return "", ErrHTTPRequest
	}

	logoutURL, err := url.Parse(c.provider.EndSessionEndpoint)
	if err != nil {
		return "", ErrHTTPRequest
	}

	params := url.Values{}
	params.Set("client_id", c.config.ClientID)

	if idTokenHint != "" {
		params.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURI != "" {
		params.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	if state != "" {
		params.Set("state", state)
	}

	logoutURL.RawQuery = params.Encode()
	return logoutURL.String(), nil
}

// VerifyAccessTokenHash verifies the at_hash claim in the ID token.
// This is used to validate that the access token matches the ID token.
func VerifyAccessTokenHash(accessToken string, atHash string, signingAlg string) error {
	if atHash == "" {
		// at_hash is optional
		return nil
	}

	var hashFunc crypto.Hash
	switch signingAlg {
	case "RS256", "ES256", "PS256":
		hashFunc = crypto.SHA256
	case "RS384", "ES384", "PS384":
		hashFunc = crypto.SHA384
	case "RS512", "ES512", "PS512":
		hashFunc = crypto.SHA512
	default:
		hashFunc = crypto.SHA256
	}

	hasher := hashFunc.New()
	hasher.Write([]byte(accessToken))
	hash := hasher.Sum(nil)

	// Take the left-most half of the hash
	halfLen := len(hash) / 2
	expected := base64.RawURLEncoding.EncodeToString(hash[:halfLen])

	if expected != atHash {
		return ErrInvalidIDToken
	}

	return nil
}

// GetProvider returns the provider associated with this client.
func (c *Client) GetProvider() *Provider {
	return c.provider
}

// GetConfig returns the configuration associated with this client.
func (c *Client) GetConfig() *ProviderConfig {
	return c.config
}

// SetDPoPKey sets the DPoP key for proof-of-possession token binding (RFC 9449).
func (c *Client) SetDPoPKey(key *DPoPKey) {
	c.dpopMu.Lock()
	defer c.dpopMu.Unlock()
	c.dpopKey = key
}

// GetDPoPKey returns the current DPoP key, if any.
func (c *Client) GetDPoPKey() *DPoPKey {
	c.dpopMu.Lock()
	defer c.dpopMu.Unlock()
	return c.dpopKey
}

// rsaPublicKeyVerifier is a helper for JWT verification.
type rsaPublicKeyVerifier struct {
	key *rsa.PublicKey
}

func (v *rsaPublicKeyVerifier) Verify(signing string, signature []byte) error {
	return nil // Verification is done by jwt-go
}
