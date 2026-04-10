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

package aws

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
)

const (
	// AuthorizeEndpointTemplate is the AWS signin authorize endpoint template.
	// Format: https://{region}.signin.aws.amazon.com/v1/authorize
	AuthorizeEndpointTemplate = "https://%s.signin.aws.amazon.com/v1/authorize"

	// TokenEndpointTemplate is the AWS signin token endpoint template.
	// Format: https://{region}.signin.aws.amazon.com/v1/token
	TokenEndpointTemplate = "https://%s.signin.aws.amazon.com/v1/token"

	// SameDeviceClientID is the client ID for same-device authentication.
	SameDeviceClientID = "arn:aws:signin:::devtools/same-device"

	// CrossDeviceClientID is the client ID for cross-device authentication.
	CrossDeviceClientID = "arn:aws:signin:::devtools/cross-device"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second

	// MaxNonceRetries is the maximum number of retries for nonce errors.
	MaxNonceRetries = 3

	// DPoPNonceHeader is the HTTP header containing the DPoP nonce.
	DPoPNonceHeader = "DPoP-Nonce"
)

// ClientConfig contains configuration for the AWS OIDC client.
type ClientConfig struct {
	// Region is the AWS region.
	Region string

	// ClientID is the OAuth2 client ID.
	// Defaults to SameDeviceClientID.
	ClientID string

	// RedirectURL is the OAuth2 redirect URL.
	RedirectURL string

	// Scopes are the OAuth2 scopes to request.
	Scopes []string

	// CrossDevice enables cross-device authentication.
	CrossDevice bool

	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client

	// AuthorizeEndpointOverride overrides the authorize endpoint (for testing).
	AuthorizeEndpointOverride string

	// TokenEndpointOverride overrides the token endpoint (for testing).
	TokenEndpointOverride string
}

// Validate validates the client configuration.
func (c *ClientConfig) Validate() error {
	if c.Region == "" {
		return ErrMissingRegion
	}
	return nil
}

// EffectiveClientID returns the client ID to use based on configuration.
func (c *ClientConfig) EffectiveClientID() string {
	if c.CrossDevice {
		return CrossDeviceClientID
	}
	if c.ClientID != "" {
		return c.ClientID
	}
	return SameDeviceClientID
}

// EffectiveScopes returns the scopes to use.
func (c *ClientConfig) EffectiveScopes() []string {
	if len(c.Scopes) == 0 {
		return []string{"openid"}
	}
	return c.Scopes
}

// Client is an AWS-specific OIDC client that uses DPoP for authentication.
type Client struct {
	config     *ClientConfig
	dpopKey    *oidc.DPoPKey
	dpopNonce  string
	httpClient *http.Client
}

// NewClient creates a new AWS OIDC client.
func NewClient(config *ClientConfig, dpopKey *oidc.DPoPKey) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: DefaultTimeout,
		}
	}

	return &Client{
		config:     config,
		dpopKey:    dpopKey,
		httpClient: httpClient,
	}, nil
}

// AuthorizeEndpoint returns the authorization endpoint URL for the configured region.
func (c *Client) AuthorizeEndpoint() string {
	if c.config.AuthorizeEndpointOverride != "" {
		return c.config.AuthorizeEndpointOverride
	}
	return fmt.Sprintf(AuthorizeEndpointTemplate, c.config.Region)
}

// TokenEndpoint returns the token endpoint URL for the configured region.
func (c *Client) TokenEndpoint() string {
	if c.config.TokenEndpointOverride != "" {
		return c.config.TokenEndpointOverride
	}
	return fmt.Sprintf(TokenEndpointTemplate, c.config.Region)
}

// AuthCodeOptions contains options for the authorization code flow.
type AuthCodeOptions struct {
	// State is the CSRF protection state parameter.
	State string

	// CodeVerifier is the PKCE code verifier.
	CodeVerifier string

	// Nonce is the nonce for ID token validation.
	Nonce string

	// AdditionalParams are additional query parameters.
	AdditionalParams map[string]string
}

// AuthCodeURL returns the authorization URL for initiating the auth code flow.
func (c *Client) AuthCodeURL(opts *AuthCodeOptions) (string, error) {
	if opts.State == "" {
		return "", oidc.ErrInvalidState
	}
	if opts.CodeVerifier == "" {
		return "", oidc.ErrInvalidCodeVerifier
	}

	authURL, err := url.Parse(c.AuthorizeEndpoint())
	if err != nil {
		return "", err
	}

	codeChallenge := oidc.GenerateCodeChallenge(opts.CodeVerifier)
	// AWS signin requires code_challenge without trailing '=' padding
	codeChallenge = strings.TrimRight(codeChallenge, "=")

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.config.EffectiveClientID())
	params.Set("scope", strings.Join(c.config.EffectiveScopes(), " "))
	params.Set("state", opts.State)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "SHA-256")

	if c.config.RedirectURL != "" {
		params.Set("redirect_uri", c.config.RedirectURL)
	}

	if opts.Nonce != "" {
		params.Set("nonce", opts.Nonce)
	}

	for k, v := range opts.AdditionalParams {
		params.Set(k, v)
	}

	authURL.RawQuery = params.Encode()
	return authURL.String(), nil
}

// Exchange exchanges an authorization code for tokens.
func (c *Client) Exchange(ctx context.Context, code string, opts *AuthCodeOptions) (*TokenResponse, error) {
	if c.dpopKey == nil {
		return nil, ErrMissingDPoPKey
	}

	if code == "" {
		return nil, ErrTokenRequestFailed
	}

	if opts.CodeVerifier == "" {
		return nil, oidc.ErrInvalidCodeVerifier
	}

	// Build token request data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", c.config.EffectiveClientID())
	data.Set("code_verifier", opts.CodeVerifier)

	if c.config.RedirectURL != "" {
		data.Set("redirect_uri", c.config.RedirectURL)
	}

	return c.doTokenRequest(ctx, data)
}

// Refresh exchanges a refresh token for new credentials.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if c.dpopKey == nil {
		return nil, ErrMissingDPoPKey
	}

	if refreshToken == "" {
		return nil, oidc.ErrMissingRefreshToken
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.config.EffectiveClientID())

	return c.doTokenRequest(ctx, data)
}

// doTokenRequest performs the token request with DPoP and nonce retry.
func (c *Client) doTokenRequest(ctx context.Context, data url.Values) (*TokenResponse, error) {
	tokenEndpoint := c.TokenEndpoint()

	for attempt := 0; attempt < MaxNonceRetries; attempt++ {
		// Generate DPoP proof
		dpopProof, err := c.dpopKey.GenerateProof(&oidc.DPoPProofOptions{
			HTTPMethod: http.MethodPost,
			HTTPUri:    tokenEndpoint,
			Nonce:      c.dpopNonce,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTokenRequestFailed, err)
		}

		// Create request
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
			strings.NewReader(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTokenRequestFailed, err)
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("DPoP", dpopProof)

		// Perform request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTokenRequestFailed, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTokenRequestFailed, err)
		}

		// Check for DPoP nonce in response header
		if nonce := resp.Header.Get(DPoPNonceHeader); nonce != "" {
			c.dpopNonce = nonce
		}

		// Handle 400 with use_dpop_nonce error - retry with nonce
		if resp.StatusCode == http.StatusBadRequest {
			tokenResp, _ := ParseTokenResponse(body)
			if tokenResp != nil && tokenResp.Error == "use_dpop_nonce" {
				// Retry with the nonce from the response header
				continue
			}
		}

		// Parse response
		tokenResp, err := ParseTokenResponse(body)
		if err != nil {
			return nil, err
		}

		// Check for errors
		if resp.StatusCode != http.StatusOK || tokenResp.IsError() {
			errMsg := tokenResp.ErrorDescription
			if errMsg == "" {
				errMsg = tokenResp.Error
			}
			return nil, fmt.Errorf("%w: %s", ErrTokenRequestFailed, errMsg)
		}

		return tokenResp, nil
	}

	return nil, ErrNonceRetryExhausted
}

// SetDPoPKey sets the DPoP key for this client.
func (c *Client) SetDPoPKey(key *oidc.DPoPKey) {
	c.dpopKey = key
}

// GetDPoPKey returns the DPoP key for this client.
func (c *Client) GetDPoPKey() *oidc.DPoPKey {
	return c.dpopKey
}

// GetDPoPNonce returns the current DPoP nonce.
func (c *Client) GetDPoPNonce() string {
	return c.dpopNonce
}

// SetDPoPNonce sets the DPoP nonce.
func (c *Client) SetDPoPNonce(nonce string) {
	c.dpopNonce = nonce
}

// GetConfig returns the client configuration.
func (c *Client) GetConfig() *ClientConfig {
	return c.config
}
