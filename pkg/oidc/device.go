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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DeviceStyle selects the device login protocol a provider speaks.
type DeviceStyle string

const (
	// DeviceStyleRFC8628 is the OAuth 2.0 Device Authorization Grant
	// (RFC 8628): a device authorization request, then polling the token
	// endpoint with the device_code grant. It is the default.
	DeviceStyleRFC8628 DeviceStyle = "rfc8628"

	// DeviceStyleOpenAI is the device login of OpenAI's auth service, which
	// is not RFC 8628: a user-code request and a poll under
	// {issuer}/api/accounts/deviceauth/, the poll answering with an
	// authorization code and its PKCE verifier once the user approves,
	// which is then exchanged at the token endpoint (openai/codex
	// codex-rs/login/src/device_code_auth.rs).
	DeviceStyleOpenAI DeviceStyle = "openai"
)

const (
	// deviceGrantType is the RFC 8628 grant type for polling the token
	// endpoint.
	deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// defaultDeviceInterval is RFC 8628's default polling interval when the
	// provider names none.
	defaultDeviceInterval = 5 * time.Second

	// openAIDeviceLifetime is how long an OpenAI device login stays valid;
	// the service does not report it, and codex stops polling after it.
	openAIDeviceLifetime = 15 * time.Minute

	// maxDeviceResponseBodySize bounds a device authorization response.
	maxDeviceResponseBodySize = 1 << 16
)

var (
	// ErrDeviceFlowUnsupported is returned when the provider has no device
	// authorization endpoint.
	ErrDeviceFlowUnsupported = errors.New("oidc: provider has no device authorization endpoint")

	// ErrDeviceAuthorizationFailed is returned when the device authorization
	// request is refused or answered with an unusable body.
	ErrDeviceAuthorizationFailed = errors.New("oidc: device authorization failed")

	// ErrAuthorizationPending is returned by PollDeviceToken while the user
	// has not yet approved the device login. Poll again after the interval.
	ErrAuthorizationPending = errors.New("oidc: device authorization pending")

	// ErrSlowDown is returned by PollDeviceToken when the provider asks the
	// client to poll less often (RFC 8628 section 3.5): add five seconds to
	// the interval.
	ErrSlowDown = errors.New("oidc: device polling too fast")

	// ErrDeviceAccessDenied is returned when the user refused the device
	// login.
	ErrDeviceAccessDenied = errors.New("oidc: device authorization denied")

	// ErrDeviceCodeExpired is returned when the device login expired before
	// the user approved it.
	ErrDeviceCodeExpired = errors.New("oidc: device code expired")

	// ErrUnknownDeviceStyle is returned for a DeviceStyle outside the
	// supported set.
	ErrUnknownDeviceStyle = errors.New("oidc: unknown device style")
)

// SlowDownStep is how much RFC 8628 section 3.5 tells a client to add to
// its polling interval on each slow_down answer.
const SlowDownStep = 5 * time.Second

// Validate returns ErrUnknownDeviceStyle unless s is empty (the RFC 8628
// default) or a supported style.
func (s DeviceStyle) Validate() error {
	switch s {
	case "", DeviceStyleRFC8628, DeviceStyleOpenAI:
		return nil
	default:
		return &DetailError{Err: ErrUnknownDeviceStyle, Detail: ": " + strconv.Quote(string(s))}
	}
}

// DeviceAuthorization is a started device login: the code the user enters
// at the verification URI, and the state a poll presents.
type DeviceAuthorization struct {
	// DeviceCode is the code the client polls with: RFC 8628's device_code,
	// or OpenAI's device_auth_id. It is a secret.
	DeviceCode string `json:"device_code"`

	// UserCode is the code the user enters at VerificationURI.
	UserCode string `json:"user_code"`

	// VerificationURI is where the user approves the login.
	VerificationURI string `json:"verification_uri"`

	// VerificationURIComplete is VerificationURI with the user code
	// embedded, when the provider supplies one.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`

	// Interval is the minimum time between polls.
	Interval time.Duration `json:"interval"`

	// ExpiresAt is when the device login stops being valid.
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the device login has expired at now.
func (d *DeviceAuthorization) Expired(now time.Time) bool {
	return !d.ExpiresAt.IsZero() && !now.Before(d.ExpiresAt)
}

// StartDeviceAuthorization begins a device login in the provider's device
// style. The user approves it at the returned VerificationURI; the caller
// then calls PollDeviceToken no more often than the returned Interval.
func (c *Client) StartDeviceAuthorization(ctx context.Context) (*DeviceAuthorization, error) {
	if err := c.config.DeviceStyle.Validate(); err != nil {
		return nil, err
	}
	if !c.provider.HasTokenEndpoint() {
		return nil, ErrProviderNotInitialized
	}
	if c.config.DeviceStyle == DeviceStyleOpenAI {
		return c.startOpenAIDevice(ctx)
	}
	return c.startRFC8628Device(ctx)
}

// PollDeviceToken polls once for the tokens of a started device login. It
// returns ErrAuthorizationPending until the user approves, ErrSlowDown when
// the provider asks for a longer interval, and ErrDeviceAccessDenied or
// ErrDeviceCodeExpired when the login is over without tokens.
func (c *Client) PollDeviceToken(ctx context.Context, da *DeviceAuthorization) (*TokenResponse, error) {
	if da == nil || da.DeviceCode == "" {
		return nil, ErrDeviceAuthorizationFailed
	}
	if err := c.config.DeviceStyle.Validate(); err != nil {
		return nil, err
	}
	if !c.provider.HasTokenEndpoint() {
		return nil, ErrProviderNotInitialized
	}
	if da.Expired(time.Now()) {
		return nil, ErrDeviceCodeExpired
	}
	if c.config.DeviceStyle == DeviceStyleOpenAI {
		return c.pollOpenAIDevice(ctx, da)
	}
	return c.pollRFC8628Device(ctx, da)
}

// startRFC8628Device sends the RFC 8628 section 3.1 device authorization
// request.
func (c *Client) startRFC8628Device(ctx context.Context) (*DeviceAuthorization, error) {
	endpoint := c.provider.DeviceAuthorizationEndpoint
	if endpoint == "" {
		return nil, ErrDeviceFlowUnsupported
	}
	data := url.Values{}
	data.Set("client_id", c.config.ClientID)
	data.Set("scope", strings.Join(c.config.EffectiveScopes(), " "))
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}
	status, body, err := c.post(ctx, endpoint, "application/x-www-form-urlencoded", []byte(data.Encode()))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, deviceAuthorizationError(body, status)
	}

	var resp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURL         string `json:"verification_url"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAuthorizationFailed, Cause: err}
	}
	// Google names the field verification_url, pre-dating RFC 8628's final
	// spelling; both carry the same URI.
	verification := resp.VerificationURI
	if verification == "" {
		verification = resp.VerificationURL
	}
	if resp.DeviceCode == "" || resp.UserCode == "" || verification == "" {
		return nil, &DetailError{Err: ErrDeviceAuthorizationFailed, Detail: ": response lacks device_code, user_code or verification_uri"}
	}
	interval := defaultDeviceInterval
	if resp.Interval > 0 {
		interval = time.Duration(resp.Interval) * time.Second
	}
	da := &DeviceAuthorization{
		DeviceCode:              resp.DeviceCode,
		UserCode:                resp.UserCode,
		VerificationURI:         verification,
		VerificationURIComplete: resp.VerificationURIComplete,
		Interval:                interval,
	}
	if resp.ExpiresIn > 0 {
		da.ExpiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}
	return da, nil
}

// pollRFC8628Device sends the RFC 8628 section 3.4 device access token
// request and maps the section 3.5 polling errors to typed errors.
func (c *Client) pollRFC8628Device(ctx context.Context, da *DeviceAuthorization) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", deviceGrantType)
	data.Set("device_code", da.DeviceCode)
	data.Set("client_id", c.config.ClientID)
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}
	tokens, err := c.doTokenRequest(ctx, data)
	if err == nil {
		return tokens, nil
	}
	var tokenErr *TokenRequestError
	if !errors.As(err, &tokenErr) {
		return nil, err
	}
	switch tokenErr.Code {
	case "authorization_pending":
		return nil, ErrAuthorizationPending
	case "slow_down":
		return nil, ErrSlowDown
	case "access_denied":
		return nil, ErrDeviceAccessDenied
	case "expired_token":
		return nil, ErrDeviceCodeExpired
	default:
		return nil, err
	}
}

// openAIDeviceBase returns the device-login base of OpenAI's auth service,
// {issuer}/api/accounts.
func (c *Client) openAIDeviceBase() string {
	return strings.TrimSuffix(c.provider.Issuer, "/") + "/api/accounts"
}

// startOpenAIDevice requests a user code from OpenAI's auth service.
func (c *Client) startOpenAIDevice(ctx context.Context) (*DeviceAuthorization, error) {
	reqBody, err := json.Marshal(map[string]string{"client_id": c.config.ClientID})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAuthorizationFailed, Cause: err}
	}
	status, body, err := c.post(ctx, c.openAIDeviceBase()+"/deviceauth/usercode", "application/json", reqBody)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrDeviceFlowUnsupported
	}
	if status != http.StatusOK {
		return nil, deviceAuthorizationError(body, status)
	}

	var resp struct {
		DeviceAuthID string          `json:"device_auth_id"`
		UserCode     string          `json:"user_code"`
		UserCodeAlt  string          `json:"usercode"`
		Interval     json.RawMessage `json:"interval"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAuthorizationFailed, Cause: err}
	}
	userCode := resp.UserCode
	if userCode == "" {
		userCode = resp.UserCodeAlt
	}
	if resp.DeviceAuthID == "" || userCode == "" {
		return nil, &DetailError{Err: ErrDeviceAuthorizationFailed, Detail: ": response lacks device_auth_id or user_code"}
	}
	return &DeviceAuthorization{
		DeviceCode:      resp.DeviceAuthID,
		UserCode:        userCode,
		VerificationURI: strings.TrimSuffix(c.provider.Issuer, "/") + "/codex/device",
		Interval:        flexibleSeconds(resp.Interval),
		ExpiresAt:       time.Now().Add(openAIDeviceLifetime),
	}, nil
}

// pollOpenAIDevice polls OpenAI's auth service once. 403 and 404 mean the
// user has not approved yet; 200 carries an authorization code and its PKCE
// verifier, exchanged at the token endpoint with form encoding against the
// device callback redirect URI.
func (c *Client) pollOpenAIDevice(ctx context.Context, da *DeviceAuthorization) (*TokenResponse, error) {
	reqBody, err := json.Marshal(map[string]string{
		"device_auth_id": da.DeviceCode,
		"user_code":      da.UserCode,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAuthorizationFailed, Cause: err}
	}
	status, body, err := c.post(ctx, c.openAIDeviceBase()+"/deviceauth/token", "application/json", reqBody)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusNotFound:
		return nil, ErrAuthorizationPending
	default:
		return nil, deviceAuthorizationError(body, status)
	}

	var code struct {
		AuthorizationCode string `json:"authorization_code"`
		CodeVerifier      string `json:"code_verifier"`
	}
	if err := json.Unmarshal(body, &code); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAuthorizationFailed, Cause: err}
	}
	if code.AuthorizationCode == "" || code.CodeVerifier == "" {
		return nil, &DetailError{Err: ErrDeviceAuthorizationFailed, Detail: ": response lacks authorization_code or code_verifier"}
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code.AuthorizationCode)
	data.Set("redirect_uri", strings.TrimSuffix(c.provider.Issuer, "/")+"/deviceauth/callback")
	data.Set("client_id", c.config.ClientID)
	data.Set("code_verifier", code.CodeVerifier)
	return c.doTokenRequestEncoded(ctx, data, TokenEncodingForm)
}

// post sends body to endpoint and returns the status and a bounded body.
func (c *Client) post(ctx context.Context, endpoint, contentType string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, &SentinelCauseError{Sentinel: ErrDeviceAuthorizationFailed, Cause: err}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, nil, &SentinelCauseError{Sentinel: ErrDeviceAuthorizationFailed, Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxDeviceResponseBodySize))
	if err != nil {
		return 0, nil, &SentinelCauseError{Sentinel: ErrDeviceAuthorizationFailed, Cause: err}
	}
	return resp.StatusCode, respBody, nil
}

// deviceAuthorizationError wraps a refused device request's OAuth2 error in
// ErrDeviceAuthorizationFailed.
func deviceAuthorizationError(body []byte, status int) error {
	tokenErr := parseTokenErrorResponse(body, status, "")
	tokenErr.Err = ErrDeviceAuthorizationFailed
	return tokenErr
}

// flexibleSeconds reads an interval given as a JSON number or a numeric
// string, defaulting to RFC 8628's five seconds.
func flexibleSeconds(raw json.RawMessage) time.Duration {
	var n float64
	if err := json.Unmarshal(raw, &n); err != nil {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return defaultDeviceInterval
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return defaultDeviceInterval
		}
		n = parsed
	}
	if n <= 0 {
		return defaultDeviceInterval
	}
	return time.Duration(n * float64(time.Second))
}
