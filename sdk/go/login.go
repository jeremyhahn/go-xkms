// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// The session login-plane client for xkmsd's REST session ceremonies:
//
//	POST /api/v1/auth/login/piv  — PIV smartcard login (TLS client cert)
//	POST /api/v1/auth/refresh    — rotate the access/refresh pair
//	POST /api/v1/auth/logout     — revoke the refresh token
//	GET  /api/v1/auth/validate   — check the current access token
//
// PIV login authenticates with the PIV slot certificate presented as the
// TLS CLIENT certificate — possession of the card's private key IS the
// credential — so this client speaks raw mTLS HTTPS rather than the
// six-transport Servicer contract (the same convention as the credential
// and init-officer clients: a credential bound to the TLS layer cannot be
// carried by transports that do not expose it). The WebAuthn (FIDO2)
// login ceremony, which has no such binding, lives on the Servicer
// interface (BeginAuthentication / FinishAuthentication) across all
// transports.

// TokenPair is the access/refresh pair a login or refresh returns.
type TokenPair struct {
	// AccessToken is the bearer token presented on authenticated requests.
	AccessToken string `json:"access_token"`
	// RefreshToken rotates the pair at POST /api/v1/auth/refresh.
	RefreshToken string `json:"refresh_token"`
	// TokenType is the token scheme, "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the access token's lifetime in seconds.
	ExpiresIn int64 `json:"expires_in"`
}

// LoginClientConfig configures a session login-plane client.
type LoginClientConfig struct {
	// BaseURL is the server base, e.g. "https://xkms.example.com:8443".
	BaseURL string

	// ClientCertificate is the TLS client credential. For PIV login this
	// is the PIV slot certificate with its card-backed signer (e.g. from
	// pivcert or a crypto.Signer over the card); for the other session
	// verbs it is optional.
	ClientCertificate *tls.Certificate

	// RootCAs verifies the server. Nil uses the system pool. Ignored when
	// SPKIPin is set.
	RootCAs *x509.CertPool

	// SPKIPin, when set, verifies the server by its SPKI SHA-256 pin
	// (trust-on-first-use) instead of a CA chain, using the same
	// verification NewSPKIPinnedTLSConfig performs. It takes precedence
	// over RootCAs.
	SPKIPin string

	// Timeout bounds each request. Zero selects 30s.
	Timeout time.Duration
}

// LoginClient drives xkmsd's session ceremonies.
type LoginClient struct {
	base string
	http *http.Client
}

// NewLoginClient constructs a session login-plane client.
func NewLoginClient(cfg LoginClientConfig) (*LoginClient, error) {
	if cfg.BaseURL == "" {
		return nil, &LoginClientError{Op: "configure", Reason: "BaseURL is required"}
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	var tlsCfg *tls.Config
	if cfg.SPKIPin != "" {
		tlsCfg = NewSPKIPinnedTLSConfig(cfg.SPKIPin)
	} else {
		tlsCfg = &tls.Config{
			RootCAs:    cfg.RootCAs,
			MinVersion: tls.VersionTLS13,
		}
	}
	if cfg.ClientCertificate != nil {
		tlsCfg.Certificates = []tls.Certificate{*cfg.ClientCertificate}
	}
	return &LoginClient{
		base: cfg.BaseURL,
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// PIVLogin performs the PIV smartcard login: the configured TLS client
// certificate (the PIV slot certificate) authenticates the caller, and the
// server answers with a session token pair. The server verifies the
// certificate's SPKI thumbprint against the enrolled user binding.
func (c *LoginClient) PIVLogin(ctx context.Context) (*TokenPair, error) {
	return c.tokenRequest(ctx, http.MethodPost, "/api/v1/auth/login/piv", nil, "")
}

// Refresh rotates the session pair using refreshToken. The server detects
// refresh-token reuse and revokes the family on replay.
func (c *LoginClient) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	body := map[string]string{"refresh_token": refreshToken}
	return c.tokenRequest(ctx, http.MethodPost, "/api/v1/auth/refresh", body, "")
}

// Logout revokes refreshToken. accessToken authenticates the call.
func (c *LoginClient) Logout(ctx context.Context, accessToken, refreshToken string) error {
	body := map[string]string{"refresh_token": refreshToken}
	_, err := c.tokenRequest(ctx, http.MethodPost, "/api/v1/auth/logout", body, accessToken)
	return err
}

// Validate reports whether accessToken currently authenticates.
func (c *LoginClient) Validate(ctx context.Context, accessToken string) error {
	_, err := c.tokenRequest(ctx, http.MethodGet, "/api/v1/auth/validate", nil, accessToken)
	return err
}

// tokenRequest performs one session-plane request and decodes a token pair
// when the response carries one.
func (c *LoginClient) tokenRequest(ctx context.Context, method, path string, body any, bearer string) (*TokenPair, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, &LoginClientError{Op: path, Reason: "encode request", Err: err}
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, &LoginClientError{Op: path, Reason: "build request", Err: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &LoginClientError{Op: path, Reason: "request failed", Err: err}
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Debug("xkms: failed to close login HTTP response body", "error", cerr)
		}
	}()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &LoginClientError{Op: path, Reason: "read response", Err: err}
	}
	// Logout answers 204 No Content (nothing to decode); the other three
	// verbs answer 200 with a token pair or a validation body. Any other
	// 2xx is treated the same way 200 is: success, decode if there is a
	// body to decode.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &LoginClientError{Op: path, Status: resp.StatusCode, Reason: string(payload)}
	}
	var pair TokenPair
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &pair); err != nil {
			return nil, &LoginClientError{Op: path, Reason: "decode response", Err: err}
		}
	}
	return &pair, nil
}

// LoginClientError reports a session login-plane failure.
type LoginClientError struct {
	// Op is the endpoint path (or "configure").
	Op string
	// Status is the HTTP status for non-200 responses; zero otherwise.
	Status int
	// Reason describes the failure.
	Reason string
	// Err is the underlying error, when one exists.
	Err error
}

// Error describes the failure.
func (e *LoginClientError) Error() string {
	msg := "xkms login client: " + e.Op + ": " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *LoginClientError) Unwrap() error { return e.Err }
