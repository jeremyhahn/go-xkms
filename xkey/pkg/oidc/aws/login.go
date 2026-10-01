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
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
)

// DefaultLoginTimeout bounds how long Login waits for the browser callback
// before it gives up.
const DefaultLoginTimeout = 5 * time.Minute

// LoginOptions configures an interactive AWS sign-in OIDC login.
type LoginOptions struct {
	// Region is the AWS region to authenticate against. Required.
	Region string

	// CrossDevice requests the cross-device authentication client ID, so
	// the authorization URL can be completed on a different device.
	CrossDevice bool

	// Callback is the local callback listener configuration. AWS always
	// redirects to 127.0.0.1 on Callback.Port at the fixed
	// oidc.AWSRedirectPath.
	Callback oidc.Callback

	// Timeout bounds how long Login waits for the browser callback.
	// DefaultLoginTimeout applies when zero.
	Timeout time.Duration

	// HTTPClient overrides the HTTP client used for the token request.
	// Tests use it to point at a mock token endpoint's TLS configuration;
	// production callers leave it nil for the client default.
	HTTPClient *http.Client

	// AuthorizeEndpointOverride overrides the AWS authorize endpoint.
	// Used by tests; production callers leave it empty.
	AuthorizeEndpointOverride string

	// TokenEndpointOverride overrides the AWS token endpoint. Used by
	// tests; production callers leave it empty.
	TokenEndpointOverride string
}

// LoginResult is the outcome of a successful AWS OIDC login.
type LoginResult struct {
	// TokenResponse carries the AWS temporary credentials and refresh
	// token returned by the token exchange.
	TokenResponse *TokenResponse

	// DPoPKey is the key generated for this login. It must be persisted
	// alongside the refresh token to refresh credentials later, since AWS
	// binds the refresh token to the key that requested it.
	DPoPKey *oidc.DPoPKey

	// AuthURL is the authorization URL the browser was sent to.
	AuthURL string
}

// Login runs the interactive AWS sign-in OIDC flow: it builds the
// DPoP-bound PKCE authorization request, starts a local callback listener,
// invokes onAuthURL with the URL to present to the user, waits for the
// redirect, and exchanges the resulting authorization code for AWS
// credentials.
//
// Login is the single implementation of the AWS OIDC login dance: the
// "xkey oidc aws" CLI command and the xKey GUI's OIDC service both call it
// instead of each maintaining their own copy.
//
// onAuthURL is invoked once the authorization URL is ready and before
// Login blocks waiting for the callback; the caller decides how to present
// it (open a browser, print it, display a QR code). onAuthURL may be nil.
func Login(ctx context.Context, opts LoginOptions, onAuthURL func(authURL string)) (*LoginResult, error) {
	if opts.Region == "" {
		return nil, ErrMissingRegion
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultLoginTimeout
	}

	dpopKey, err := oidc.GenerateDPoPKey()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLoginFailed, Cause: err}
	}

	clientConfig := &ClientConfig{
		Region:                    opts.Region,
		CrossDevice:               opts.CrossDevice,
		RedirectURL:               opts.Callback.AWSRedirectURL(),
		HTTPClient:                opts.HTTPClient,
		AuthorizeEndpointOverride: opts.AuthorizeEndpointOverride,
		TokenEndpointOverride:     opts.TokenEndpointOverride,
	}
	client, err := NewClient(clientConfig, dpopKey)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLoginFailed, Cause: err}
	}

	codeVerifier, err := oidc.GenerateCodeVerifier()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLoginFailed, Cause: err}
	}
	state, err := oidc.GenerateState()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLoginFailed, Cause: err}
	}

	authOpts := &AuthCodeOptions{State: state, CodeVerifier: codeVerifier}
	authURL, err := client.AuthCodeURL(authOpts)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLoginFailed, Cause: err}
	}

	listener, err := opts.Callback.AWSListenAddrs()
	if err != nil {
		return nil, err
	}

	loginCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	var receivedState atomic.Value

	mux := http.NewServeMux()
	mux.Handle("/", oidc.ExactPathHandler(listener.Path, func(w http.ResponseWriter, r *http.Request) {
		handleLoginCallback(w, r, codeChan, errChan, &receivedState)
	}))

	listeners, err := oidc.BindCallback(loginCtx, nil, listener.Addrs)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLoginFailed, Cause: err}
	}

	server := &http.Server{Handler: mux}
	oidc.ServeCallback(server, listeners, errChan)
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		// The login outcome above is already decided by the time this
		// runs, so a shutdown failure changes nothing about it -- but it
		// is logged, since it means the callback listener outlived its
		// 5-second grace period instead of releasing its port.
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Debug("oidc/aws: callback server shutdown failed", "error", err)
		}
	}()

	if onAuthURL != nil {
		onAuthURL(authURL)
	}

	var code string
	select {
	case code = <-codeChan:
		// received authorization code
	case cbErr := <-errChan:
		return nil, &SentinelCauseError{Sentinel: ErrCallbackFailed, Cause: cbErr}
	case <-loginCtx.Done():
		return nil, ErrLoginTimeout
	}

	if rs, ok := receivedState.Load().(string); !ok || rs != state {
		return nil, ErrStateMismatch
	}

	tokenResp, err := client.Exchange(loginCtx, code, authOpts)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTokenExchangeFailed, Cause: err}
	}
	if !tokenResp.HasCredentials() {
		return nil, ErrMissingCredentials
	}

	return &LoginResult{TokenResponse: tokenResp, DPoPKey: dpopKey, AuthURL: authURL}, nil
}

// handleLoginCallback handles the OAuth2 redirect for an AWS login.
func handleLoginCallback(w http.ResponseWriter, r *http.Request, codeChan chan<- string, errChan chan<- error, state *atomic.Value) {
	query := r.URL.Query()

	if errParam := query.Get("error"); errParam != "" {
		// A page that cannot reach the browser (it hung up) changes nothing
		// about the login's outcome, so the write error is only logged.
		if err := oidc.WriteCallbackPage(w, oidc.CallbackPage{Title: "AWS Authentication Failed"}); err != nil {
			slog.Debug("oidc/aws: failed to write callback response", "error", err)
		}
		errChan <- &DetailError{Err: ErrAuthorizationFailed, Detail: ": " + oidc.SanitizeProviderText(errParam) + ": " + oidc.SanitizeProviderText(query.Get("error_description"))}
		return
	}

	code := query.Get("code")
	if code == "" {
		if err := oidc.WriteCallbackPage(w, oidc.CallbackPage{Title: "AWS Authentication Failed", Message: "No authorization code received"}); err != nil {
			slog.Debug("oidc/aws: failed to write callback response", "error", err)
		}
		errChan <- ErrNoAuthorizationCode
		return
	}

	state.Store(query.Get("state"))

	if err := oidc.WriteCallbackPage(w, oidc.CallbackPage{Title: "AWS Authentication Successful", Message: "You may close this window."}); err != nil {
		slog.Debug("oidc/aws: failed to write callback response", "error", err)
	}

	codeChan <- code
}

// RefreshCredentials exchanges refreshToken for new AWS credentials using
// client, and returns the refresh token to use for the next refresh: AWS
// may rotate the refresh token, in which case the caller must persist the
// new value; when it does not, the original refreshToken is returned
// unchanged.
//
// RefreshCredentials is shared by every caller that refreshes AWS OIDC
// credentials on a schedule: the CLI's background refresh worker and the
// xKey GUI's OIDC service.
func RefreshCredentials(ctx context.Context, client *Client, refreshToken string) (*TokenResponse, string, error) {
	tokenResp, err := client.Refresh(ctx, refreshToken)
	if err != nil {
		return nil, "", &SentinelCauseError{Sentinel: ErrRefreshFailed, Cause: err}
	}
	if !tokenResp.HasCredentials() {
		return nil, "", ErrMissingCredentials
	}

	next := tokenResp.RefreshToken
	if next == "" {
		next = refreshToken
	}
	return tokenResp, next, nil
}
