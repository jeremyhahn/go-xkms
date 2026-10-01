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

package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/urlsafety"
)

// Default OIDC configuration values.
const (
	defaultOIDCScopes          = "openid,profile,email"
	defaultOIDCTokenStorePath  = "~/.xkey/tokens.json"
	defaultOIDCCallbackTimeout = 5 * time.Minute
	defaultOIDCProviderTimeout = 30 * time.Second
	oidcCodeVerifierLength     = 43
	oidcStateLength            = 32
)

// OIDC command errors.
var (
	ErrOIDCMissingIssuer         = errors.New("oidc: --issuer is required")
	ErrOIDCMissingClientID       = errors.New("oidc: --client-id is required")
	ErrOIDCMissingProviderName   = errors.New("oidc: provider name is required")
	ErrOIDCDiscoveryFailed       = errors.New("oidc: discovery failed")
	ErrOIDCTokenExchangeFailed   = errors.New("oidc: token exchange failed")
	ErrOIDCTokenRefreshFailed    = errors.New("oidc: token refresh failed")
	ErrOIDCTokenValidationFailed = errors.New("oidc: token validation failed")
	ErrOIDCTokenStoreFailed      = errors.New("oidc: failed to store tokens")
	ErrOIDCTokenLoadFailed       = errors.New("oidc: failed to load tokens")
	ErrOIDCNoTokensFound         = errors.New("oidc: no tokens found")
	ErrOIDCCallbackTimeout       = errors.New("oidc: callback timeout")
	ErrOIDCCallbackFailed        = errors.New("oidc: callback failed")
	ErrOIDCStateMismatch         = errors.New("oidc: state mismatch")
	ErrOIDCProviderNotFound      = errors.New("oidc: provider not found")
	ErrOIDCProviderExists        = errors.New("oidc: provider already exists")
	ErrOIDCConfigLoadFailed      = errors.New("oidc: failed to load config")
	ErrOIDCConfigSaveFailed      = errors.New("oidc: failed to save config")
	ErrOIDCInvalidRefreshToken   = errors.New("oidc: invalid or missing refresh token")
	ErrOIDCExecFailed            = errors.New("oidc: exec command failed")
	ErrOIDCIncompleteEndpoints   = errors.New("oidc: incomplete manual endpoint configuration")
	ErrOIDCNoAuthCode            = errors.New("oidc: no authorization code received")
	ErrOIDCMissingProviderArg    = errors.New("oidc: specify provider name or use --all")
	ErrOIDCInvalidLaunchURL      = errors.New("oidc: authorization URL failed launch validation")
)

// openLaunchURL validates url before handing it to the system browser
// opener (github.com/pkg/browser). It is the one place every "xkey oidc"
// subcommand launches a URL through, so authorization URLs -- built around
// an authorization_endpoint that comes from the identity provider, whether
// through discovery or a manually configured endpoint -- can never reach
// the OS launcher with a scheme capable of running code or reading local
// files (go-xkms#1275).
func openLaunchURL(rawURL string) error {
	validated, err := urlsafety.ValidateLaunchURL(rawURL)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCInvalidLaunchURL, Cause: err}
	}
	return browser.OpenURL(validated.String())
}

// OIDCExecPayload is the JSON structure passed to exec scripts.
type OIDCExecPayload struct {
	Provider     string   `json:"provider"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	IDToken      string   `json:"id_token,omitempty"`
	ExpiresAt    string   `json:"expires_at"`
	ExpiresIn    int64    `json:"expires_in"`
	Scopes       []string `json:"scopes"`
	Subject      string   `json:"subject,omitempty"`
	Email        string   `json:"email,omitempty"`
	Name         string   `json:"name,omitempty"`
}

// OIDCDiscoveryDocument represents the OIDC provider configuration.
type OIDCDiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// OIDCTokenResponse represents the token endpoint response.
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OIDCStoredToken represents a token stored in the token store. See
// oidc_token_store.go for its definition: AccessToken, RefreshToken, and
// IDToken live in mlocked protected memory (go-xkms#4) rather than as plain
// Go string fields, reached through the AccessToken()/RefreshToken()/
// IDToken() accessors and the SetAccessToken/SetRefreshToken/SetIDToken
// setters.

// OIDCIDTokenClaims represents standard OIDC ID token claims.
type OIDCIDTokenClaims struct {
	jwt.Claims
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
}

// OIDCProviderType represents the type of OIDC provider.
type OIDCProviderType string

const (
	// OIDCProviderTypeStandard is a standard OIDC provider with discovery.
	OIDCProviderTypeStandard OIDCProviderType = "oidc"
	// OIDCProviderTypeAWS is an AWS signin provider using DPoP.
	OIDCProviderTypeAWS OIDCProviderType = "aws"
)

// OIDCProvider represents a configured OIDC provider.
type OIDCProvider struct {
	Name         string           `json:"name"`
	Type         OIDCProviderType `json:"type,omitempty"` // "oidc" (default) or "aws"
	Issuer       string           `json:"issuer,omitempty"`
	ClientID     string           `json:"client_id,omitempty"`
	ClientSecret string           `json:"client_secret,omitempty"`
	RedirectURL  string           `json:"redirect_url,omitempty"`
	Scopes       []string         `json:"scopes,omitempty"`
	Exec         string           `json:"exec,omitempty"`
	AutoRefresh  int              `json:"auto_refresh,omitempty"`
	Background   bool             `json:"background,omitempty"`
	LogFile      string           `json:"log_file,omitempty"`

	// Manual endpoints. Set together (authorization, token, and jwks are
	// all required; userinfo is optional) to skip discovery entirely, for
	// providers that publish no .well-known/openid-configuration document.
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	JwksURI               string `json:"jwks_uri,omitempty"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`

	// TokenEncoding selects how the token endpoint request body is
	// encoded: "form" (default, RFC 6749) or "json". Empty means form.
	TokenEncoding oidc.TokenEncoding `json:"token_encoding,omitempty"`

	// AWS-specific fields
	AWSRegion          string `json:"aws_region,omitempty"`
	AWSProfile         string `json:"aws_profile,omitempty"`
	AWSCredentialsFile string `json:"aws_credentials_file,omitempty"`
	AWSOutput          string `json:"aws_output,omitempty"`
	AWSCrossDevice     bool   `json:"aws_cross_device,omitempty"`
	AWSSessionStore    string `json:"aws_session_store,omitempty"`
}

// OIDCBackgroundProcess represents a running background refresh process.
type OIDCBackgroundProcess struct {
	Provider  string             `json:"provider"`
	PID       int                `json:"pid"`
	StartedAt time.Time          `json:"started_at"`
	LogFile   string             `json:"log_file"`
	Status    *OIDCRefreshStatus `json:"status,omitempty"`
}

// OIDCRefreshStatus represents the status of a background refresh process.
type OIDCRefreshStatus struct {
	LastRefresh  time.Time `json:"last_refresh"`
	NextRefresh  time.Time `json:"next_refresh"`
	RefreshCount int       `json:"refresh_count"`
	LastStatus   string    `json:"last_status"` // "success" or "error"
	LastError    string    `json:"last_error,omitempty"`
	IntervalSecs int       `json:"interval_secs"`
}

// OIDCConfig represents the OIDC configuration file structure.
type OIDCConfig struct {
	Providers []OIDCProvider `json:"providers"`
}

// OIDCCmd represents the OIDC parent command.
var OIDCCmd = &cobra.Command{
	Use:   "oidc",
	Short: "OpenID Connect authentication",
	Long: `OpenID Connect (OIDC) authentication commands.

Perform browser-based authentication using any OIDC-compliant provider
such as Google, Microsoft, Okta, Auth0, Keycloak, or custom identity providers.

Features:
  - PKCE (Proof Key for Code Exchange) for secure public clients
  - Automatic token refresh
  - Secure token storage
  - Multiple provider support

Examples:
  # Login with Google
  xkey oidc login --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID

  # Display current token info
  xkey oidc token

  # Refresh access token
  xkey oidc refresh

  # Logout (clear tokens)
  xkey oidc logout

  # Manage providers
  xkey oidc providers list
  xkey oidc providers add --name google --issuer https://accounts.google.com --client-id YOUR_ID
  xkey oidc providers remove google`,
}

// oidcProvidersCmd represents the providers parent command.
var oidcProvidersCmd = &cobra.Command{
	Use:   "providers",
	Short: "Manage OIDC providers",
	Long: `Manage configured OIDC identity providers.

Add, list, and remove OIDC provider configurations for use with the login command.

Examples:
  xkey oidc providers list
  xkey oidc providers add --name google --issuer https://accounts.google.com --client-id YOUR_ID
  xkey oidc providers remove google`,
}

// oidcLoginCmd performs browser-based OIDC login.
var oidcLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Interactive browser-based login",
	Long: `Perform interactive browser-based OIDC login.

This command initiates the OAuth2 authorization code flow with PKCE:
1. Generates a PKCE code verifier and state parameter
2. Opens your browser to the authorization URL
3. Starts a local server to receive the callback
4. Exchanges the authorization code for tokens
5. Validates the ID token
6. Stores tokens securely
7. Optionally executes a custom script with the tokens

Use --provider to load configuration from a saved provider (simplifies repeated logins).
Use --no-browser to print the authorization URL instead of opening a browser.
Use --exec to run a custom script after login for automation (e.g., AWS credential exchange).

The --exec script receives a JSON payload via stdin and environment variables:
  - OIDC_ACCESS_TOKEN, OIDC_ID_TOKEN, OIDC_REFRESH_TOKEN
  - OIDC_ISSUER, OIDC_SUBJECT, OIDC_EMAIL, OIDC_NAME
  - OIDC_EXPIRES_AT, OIDC_EXPIRES_IN, OIDC_SCOPES

Examples:
  # Login using saved provider (simplest)
  xkey oidc login --provider okta

  # Login using saved provider with auto-refresh
  xkey oidc login --provider okta-aws --auto-refresh 2700

  # Login with explicit flags
  xkey oidc login --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID

  # Login without opening browser
  xkey oidc login --issuer https://accounts.google.com --client-id YOUR_ID --no-browser

  # Login with custom scopes
  xkey oidc login --issuer https://example.com --client-id ID --scopes "openid,profile,email,groups"

  # Login and execute custom script (e.g., for AWS credential exchange)
  xkey oidc login --issuer https://dev-123.okta.com --client-id ID --exec ./aws-oidc-exchange.sh

  # AWS login with auto-refresh (keeps AWS credentials fresh)
  xkey oidc login --issuer https://okta.com --client-id ID --exec ./aws-oidc-login.sh --auto-refresh 2700`,
	RunE: runOIDCLogin,
}

// oidcTokenCmd displays current token information.
var oidcTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Display current token info",
	Long: `Display information about the current OIDC token.

Shows:
  - Provider issuer URL
  - User subject and email
  - Token expiration time
  - Granted scopes
  - Truncated token values

Examples:
  xkey oidc token
  xkey oidc token --show-full   # Show full token values`,
	RunE: runOIDCToken,
}

// oidcRefreshCmd refreshes the access token.
var oidcRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh access token",
	Long: `Refresh the current access token using the stored refresh token.

This command uses the refresh token to obtain a new access token
without requiring interactive login.

Examples:
  xkey oidc refresh`,
	RunE: runOIDCRefresh,
}

// oidcLogoutCmd clears stored tokens.
var oidcLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored tokens",
	Long: `Clear stored OIDC tokens.

This removes the locally stored tokens. Note that this does not
revoke the tokens at the provider - they may still be valid until
they expire.

Examples:
  xkey oidc logout
  xkey oidc logout --all   # Clear all stored tokens`,
	RunE: runOIDCLogout,
}

// oidcStatusCmd shows running background refresh processes.
var oidcStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show running background refresh processes",
	Long: `Show all running OIDC background refresh processes.

Displays the provider name, process ID, start time, and log file
for each running background refresh.

Examples:
  xkey oidc status`,
	RunE: runOIDCStatus,
}

// oidcStopCmd stops a background refresh process.
var oidcStopCmd = &cobra.Command{
	Use:   "stop [provider]",
	Short: "Stop a background refresh process",
	Long: `Stop a running OIDC background refresh process.

Stops the background refresh for the specified provider by sending
SIGTERM to the process.

Examples:
  xkey oidc stop okta
  xkey oidc stop --all   # Stop all background refreshes`,
	RunE: runOIDCStop,
}

// oidcProvidersListCmd lists configured providers.
var oidcProvidersListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List configured providers",
	Long: `List all configured OIDC providers.

Examples:
  xkey oidc providers list`,
	RunE: runOIDCProvidersList,
}

// oidcProvidersAddCmd adds a new provider.
var oidcProvidersAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a provider",
	Long: `Add a new OIDC provider configuration.

The provider configuration is stored locally and can be used
with 'xkey oidc login --provider NAME' for simplified authentication.

Supports two provider types:
  - Standard OIDC (--type oidc): Any OpenID Connect provider with discovery
  - AWS Console (--type aws): AWS native signin with DPoP authentication

You can also store --exec, --auto-refresh, --background, and --log-file
settings so they're automatically applied when using the provider.

Examples:
  # Basic OIDC provider
  xkey oidc providers add --name google --issuer https://accounts.google.com --client-id YOUR_ID

  # OIDC provider with client secret
  xkey oidc providers add --name okta --issuer https://dev-123.okta.com --client-id ID --client-secret SECRET

  # AWS provider with auto-refresh in background
  xkey oidc providers add --name aws-prod \
    --type aws \
    --region us-east-1 \
    --profile production \
    --auto-refresh 840 \
    --background \
    --log-file ~/.xkey/logs/aws-prod.log

  # Then login simply with:
  xkey oidc login --provider aws-prod`,
	RunE: runOIDCProvidersAdd,
}

// oidcProvidersRemoveCmd removes a provider.
var oidcProvidersRemoveCmd = &cobra.Command{
	Use:     "remove [name]",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a provider",
	Long: `Remove an OIDC provider configuration.

Examples:
  xkey oidc providers remove google`,
	Args: cobra.ExactArgs(1),
	RunE: runOIDCProvidersRemove,
}

// runOIDCLogin executes the OIDC login command.
func runOIDCLogin(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	// Check if running as background worker (internal use)
	backgroundWorker, _ := cmd.Flags().GetBool("background-worker")
	if backgroundWorker {
		return runBackgroundWorker(cmd, args)
	}

	providerName, _ := cmd.Flags().GetString("provider")
	issuer, _ := cmd.Flags().GetString("issuer")
	clientID, _ := cmd.Flags().GetString("client-id")
	clientSecret, _ := cmd.Flags().GetString("client-secret")
	redirectURL, _ := cmd.Flags().GetString("redirect-url")
	scopesStr, _ := cmd.Flags().GetString("scopes")
	tokenStore, _ := cmd.Flags().GetString("token-store")
	noBrowser, _ := cmd.Flags().GetBool("no-browser")
	execCmd, _ := cmd.Flags().GetString("exec")
	autoRefresh, _ := cmd.Flags().GetInt("auto-refresh")
	background, _ := cmd.Flags().GetBool("background")
	logFile, _ := cmd.Flags().GetString("log-file")
	manual, _ := getManualOIDCEndpointFlags(cmd)
	tokenEncodingStr, _ := cmd.Flags().GetString("token-encoding")
	tokenEncoding := oidc.TokenEncoding(tokenEncodingStr)

	// If --provider is specified, load configuration from saved provider
	if providerName != "" {
		configPath := getConfigPath(tokenStore)
		config, err := loadOIDCConfig(configPath)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrOIDCConfigLoadFailed, Cause: err}
		}

		var provider *OIDCProvider
		for i := range config.Providers {
			if config.Providers[i].Name == providerName {
				provider = &config.Providers[i]
				break
			}
		}
		if provider == nil {
			return &DetailError{Err: ErrOIDCProviderNotFound, Detail: fmt.Sprintf(": %s", providerName)}
		}

		// Check if this is an AWS provider - delegate to AWS login flow
		if provider.Type == OIDCProviderTypeAWS {
			return runAWSProviderLogin(cmd, provider)
		}

		// Use provider values as defaults (CLI flags override)
		if issuer == "" {
			issuer = provider.Issuer
		}
		if clientID == "" {
			clientID = provider.ClientID
		}
		if clientSecret == "" {
			clientSecret = provider.ClientSecret
		}
		if !cmd.Flags().Changed("redirect-url") {
			redirectURL = provider.RedirectURL
		}
		if !cmd.Flags().Changed("scopes") {
			scopesStr = strings.Join(provider.Scopes, ",")
		}
		if execCmd == "" && provider.Exec != "" {
			execCmd = provider.Exec
		}
		if autoRefresh == 0 && provider.AutoRefresh > 0 {
			autoRefresh = provider.AutoRefresh
		}
		if !background && provider.Background {
			background = provider.Background
		}
		if logFile == "" && provider.LogFile != "" {
			logFile = provider.LogFile
		}
		if manual.empty() {
			manual = manualOIDCEndpoints{
				AuthorizationEndpoint: provider.AuthorizationEndpoint,
				TokenEndpoint:         provider.TokenEndpoint,
				JwksURI:               provider.JwksURI,
				UserinfoEndpoint:      provider.UserinfoEndpoint,
			}
		}
		if tokenEncoding == "" {
			tokenEncoding = provider.TokenEncoding
		}
	}

	if err := tokenEncoding.Validate(); err != nil {
		return err
	}

	// The callback listener is configuration: oidc.callback_host and
	// oidc.callback_port, overridden by --callback-host and --callback-port.
	callback, err := resolveOIDCCallback(cmd)
	if err != nil {
		return err
	}
	if redirectURL == "" {
		redirectURL = callback.RedirectURL()
	}

	if issuer == "" {
		return ErrOIDCMissingIssuer
	}
	if clientID == "" {
		return ErrOIDCMissingClientID
	}

	scopes := strings.Split(scopesStr, ",")
	for i := range scopes {
		scopes[i] = strings.TrimSpace(scopes[i])
	}

	// Resolve provider endpoints: manual endpoints skip discovery entirely,
	// otherwise fetch the issuer's .well-known discovery document.
	discovery, err := resolveOIDCEndpoints(issuer, manual)
	if err != nil {
		if errors.Is(err, ErrOIDCIncompleteEndpoints) {
			return err
		}
		return &SentinelCauseError{Sentinel: ErrOIDCDiscoveryFailed, Cause: err}
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return &MessageError{Msg: fmt.Sprintf("failed to generate code verifier: %v", err)}
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Generate state parameter
	state, err := generateState()
	if err != nil {
		return &MessageError{Msg: fmt.Sprintf("failed to generate state: %v", err)}
	}

	// Build authorization URL
	authURL := buildAuthorizationURL(discovery.AuthorizationEndpoint, clientID, redirectURL, scopes, state, codeChallenge)

	// The listener serves the redirect URL's port on the configured callback
	// host (both loopback families for localhost), never on every interface
	// unless the operator configured an empty host.
	listener, err := callback.ListenAddrs(redirectURL)
	if err != nil {
		return err
	}

	// Create context with timeout for callback
	ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCCallbackTimeout)
	defer cancel()

	// Channel to receive authorization code
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	receivedState := new(atomic.Value)

	// Start callback server
	mux := http.NewServeMux()
	// The handler answers on exactly the redirect URL's path, so a provider
	// registered with any path reaches it and nothing else does.
	mux.Handle("/", oidc.ExactPathHandler(listener.Path, func(w http.ResponseWriter, r *http.Request) {
		handleOIDCCallback(w, r, codeChan, errChan, receivedState)
	}))

	listeners, err := oidc.BindCallback(ctx, nil, listener.Addrs)
	if err != nil {
		return &MessageError{Msg: fmt.Sprintf("failed to start callback server: %v", err)}
	}

	server := &http.Server{Handler: mux}
	oidc.ServeCallback(server, listeners, errChan)
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		// The login outcome below is already decided by the time this
		// runs, so a shutdown failure changes nothing about it -- but it
		// is logged, since it means the callback listener outlived its
		// 5-second grace period instead of releasing its port.
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Debug("oidc: callback server shutdown failed", "error", err)
		}
	}()

	// Open browser or print URL
	if noBrowser {
		_, _ = fmt.Fprintln(out, "Open the following URL in your browser:")
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, authURL)
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "Waiting for authorization callback...")
	} else {
		_, _ = fmt.Fprintln(out, "Opening browser for authentication...")
		if err := openLaunchURL(authURL); err != nil {
			_, _ = fmt.Fprintf(out, "Failed to open browser: %v\n", err)
			_, _ = fmt.Fprintln(out, "Please open the following URL manually:")
			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintln(out, authURL)
		}
		_, _ = fmt.Fprintln(out, "Waiting for authorization callback...")
	}

	// Wait for callback
	var code string
	select {
	case code = <-codeChan:
		// Success
	case err := <-errChan:
		return &SentinelCauseError{Sentinel: ErrOIDCCallbackFailed, Cause: err}
	case <-ctx.Done():
		return ErrOIDCCallbackTimeout
	}

	// Verify state
	if receivedState.Load() != state {
		return ErrOIDCStateMismatch
	}

	// Exchange code for tokens
	tokens, err := exchangeCodeForTokens(discovery.TokenEndpoint, clientID, clientSecret, code, redirectURL, codeVerifier, tokenEncoding)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCTokenExchangeFailed, Cause: err}
	}

	// Parse and validate ID token
	claims, err := parseIDToken(tokens.IDToken)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCTokenValidationFailed, Cause: err}
	}

	// Store tokens. AccessToken/RefreshToken/IDToken move into mlocked
	// protected memory here (go-xkms#4); storedToken.Destroy wipes them once
	// this command has no further use for them.
	storedToken, err := newOIDCStoredToken(issuer, issuer, clientID, tokens,
		time.Now().Add(time.Duration(tokens.ExpiresIn)*time.Second), scopes)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
	}
	defer storedToken.Destroy()

	tokenCLIStore, err := openOIDCTokenStore(cmd, tokenStore)
	if err != nil {
		return err
	}

	if err := tokenCLIStore.Save(storedToken); err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Login successful!")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "  Provider: %s\n", issuer)
	writeOIDCIdentity(out, claims, "  %-10s%s\n")
	_, _ = fmt.Fprintf(out, "  Expires:  %s\n", storedToken.ExpiresAt.Format(time.RFC3339))

	// Execute custom script if specified
	if execCmd != "" {
		payload := OIDCExecPayload{
			Provider:     issuer,
			Issuer:       issuer,
			ClientID:     clientID,
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			IDToken:      tokens.IDToken,
			ExpiresAt:    storedToken.ExpiresAt.Format(time.RFC3339),
			ExpiresIn:    tokens.ExpiresIn,
			Scopes:       scopes,
			Subject:      claims.Subject,
			Email:        claims.Email,
			Name:         claims.Name,
		}

		if err := executeOIDCScript(out, execCmd, payload); err != nil {
			return &SentinelCauseError{Sentinel: ErrOIDCExecFailed, Cause: err}
		}
	}

	// Start auto-refresh loop if specified
	if autoRefresh > 0 {
		if tokens.RefreshToken == "" {
			_, _ = fmt.Fprintln(out, "\nWarning: No refresh token received. Auto-refresh will not work.")
			_, _ = fmt.Fprintln(out, "Tip: Request the 'offline_access' scope to get a refresh token.")
			return nil
		}

		// Determine log file path
		if logFile == "" {
			logFile = getDefaultLogFile(tokenStore, providerName)
		} else {
			logFile = expandPath(logFile)
		}

		if background {
			// Start background process
			if providerName == "" {
				providerName = "default"
			}
			barrierPasswordFile, _ := cmd.Flags().GetString("barrier-password-file")
			return startBackgroundRefresh(out, providerName, discovery.TokenEndpoint, clientID, tokenStore, execCmd, logFile, barrierPasswordFile, autoRefresh, tokenEncoding)
		}

		_, _ = fmt.Fprintf(out, "\nAuto-refresh enabled: refreshing every %d seconds\n", autoRefresh)
		_, _ = fmt.Fprintln(out, "Press Ctrl+C to stop...")
		_, _ = fmt.Fprintln(out)

		// tokenCLIStore is opened once, here, and reused for every refresh
		// tick below -- not reopened (and, for a barrier-backed store, not
		// re-unsealed) on every interval.
		return runAutoRefresh(discovery.TokenEndpoint, clientID, tokenCLIStore, tokenStore, execCmd, providerName, time.Duration(autoRefresh)*time.Second, nil, tokenEncoding, nil)
	}

	return nil
}

// writeOIDCIdentity prints the ID token's subject, email and name, each
// that is set, one line per claim in layout (a format taking the label and
// the value). The provider signs the claims but chooses their content, so
// each value is sanitised before it reaches the terminal.
func writeOIDCIdentity(out io.Writer, claims *OIDCIDTokenClaims, layout string) {
	for _, claim := range []struct{ label, value string }{
		{"Subject:", claims.Subject},
		{"Email:", claims.Email},
		{"Name:", claims.Name},
	} {
		if claim.value != "" {
			_, _ = fmt.Fprintf(out, layout, claim.label, oidc.SanitizeProviderText(claim.value))
		}
	}
}

// runOIDCToken displays current token information.
func runOIDCToken(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	tokenStore, _ := cmd.Flags().GetString("token-store")
	showFull, _ := cmd.Flags().GetBool("show-full")

	token, err := loadToken(cmd, tokenStore)
	if err != nil {
		if errors.Is(err, ErrOIDCNoTokensFound) {
			_, _ = fmt.Fprintln(out, "No OIDC tokens found. Run 'xkey oidc login' to authenticate.")
			return nil
		}
		return &SentinelCauseError{Sentinel: ErrOIDCTokenLoadFailed, Cause: err}
	}
	defer token.Destroy()

	// Parse ID token for claims
	claims, err := parseIDToken(token.IDToken())
	if err != nil {
		// If we can't parse the ID token, still show what we have
		claims = &OIDCIDTokenClaims{}
	}

	_, _ = fmt.Fprintln(out, "OIDC Token Information")
	_, _ = fmt.Fprintln(out, "======================")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Provider:      %s\n", token.Issuer)
	writeOIDCIdentity(out, claims, "%-15s%s\n")

	// Format expiration
	now := time.Now()
	if token.ExpiresAt.After(now) {
		remaining := token.ExpiresAt.Sub(now)
		_, _ = fmt.Fprintf(out, "Expires:       %s (in %s)\n", token.ExpiresAt.Format("2006-01-02 15:04:05 UTC"), formatDuration(remaining))
	} else {
		_, _ = fmt.Fprintf(out, "Expires:       %s (EXPIRED)\n", token.ExpiresAt.Format("2006-01-02 15:04:05 UTC"))
	}

	if len(token.Scopes) > 0 {
		_, _ = fmt.Fprintf(out, "Scopes:        %s\n", strings.Join(token.Scopes, " "))
	}

	_, _ = fmt.Fprintln(out)
	if showFull {
		_, _ = fmt.Fprintf(out, "Access Token:  %s\n", token.AccessToken())
		if token.IDToken() != "" {
			_, _ = fmt.Fprintf(out, "ID Token:      %s\n", token.IDToken())
		}
		if token.HasRefreshToken() {
			_, _ = fmt.Fprintf(out, "Refresh Token: %s\n", token.RefreshToken())
		}
	} else {
		_, _ = fmt.Fprintf(out, "Access Token:  %s\n", truncateToken(token.AccessToken()))
		if token.IDToken() != "" {
			_, _ = fmt.Fprintf(out, "ID Token:      %s\n", truncateToken(token.IDToken()))
		}
	}

	return nil
}

// runOIDCRefresh refreshes the access token.
func runOIDCRefresh(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	tokenStore, _ := cmd.Flags().GetString("token-store")
	providerName, _ := cmd.Flags().GetString("provider")

	tokenCLIStore, err := openOIDCTokenStore(cmd, tokenStore)
	if err != nil {
		return err
	}

	token, err := tokenCLIStore.Load()
	if err != nil {
		if errors.Is(err, ErrOIDCNoTokensFound) {
			_, _ = fmt.Fprintln(out, "No OIDC tokens found. Run 'xkey oidc login' to authenticate.")
			return nil
		}
		return &SentinelCauseError{Sentinel: ErrOIDCTokenLoadFailed, Cause: err}
	}
	defer token.Destroy()

	if !token.HasRefreshToken() {
		return ErrOIDCInvalidRefreshToken
	}

	// A named provider carries its manual endpoints (if any) and its token
	// encoding; without one, refresh falls back to discovering the issuer's
	// endpoints and posting the request as a form, exactly as before.
	var tokenEndpoint string
	tokenEncoding := oidc.TokenEncodingForm
	if providerName != "" {
		provider, loadErr := loadProvider(tokenStore, providerName)
		if loadErr != nil {
			return &DetailError{Err: ErrOIDCProviderNotFound, Detail: fmt.Sprintf(": %s", providerName)}
		}
		tokenEncoding = provider.TokenEncoding
		manual := manualOIDCEndpoints{
			AuthorizationEndpoint: provider.AuthorizationEndpoint,
			TokenEndpoint:         provider.TokenEndpoint,
			JwksURI:               provider.JwksURI,
			UserinfoEndpoint:      provider.UserinfoEndpoint,
		}
		discovery, resolveErr := resolveOIDCEndpoints(token.Issuer, manual)
		if resolveErr != nil {
			if errors.Is(resolveErr, ErrOIDCIncompleteEndpoints) {
				return resolveErr
			}
			return &SentinelCauseError{Sentinel: ErrOIDCDiscoveryFailed, Cause: resolveErr}
		}
		tokenEndpoint = discovery.TokenEndpoint
	} else {
		discovery, discoverErr := discoverOIDCProvider(token.Issuer)
		if discoverErr != nil {
			return &SentinelCauseError{Sentinel: ErrOIDCDiscoveryFailed, Cause: discoverErr}
		}
		tokenEndpoint = discovery.TokenEndpoint
	}

	// Refresh tokens
	newTokens, err := refreshTokens(tokenEndpoint, token.ClientID, token.RefreshToken(), tokenEncoding)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCTokenRefreshFailed, Cause: err}
	}

	// Update stored token
	if err := token.SetAccessToken(newTokens.AccessToken); err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
	}
	if newTokens.RefreshToken != "" {
		if err := token.SetRefreshToken(newTokens.RefreshToken); err != nil {
			return &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
		}
	}
	if newTokens.IDToken != "" {
		if err := token.SetIDToken(newTokens.IDToken); err != nil {
			return &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
		}
	}
	token.ExpiresAt = time.Now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)

	if err := tokenCLIStore.Save(token); err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(out, "Token refreshed successfully!")
	_, _ = fmt.Fprintf(out, "  New expiration: %s\n", token.ExpiresAt.Format(time.RFC3339))

	return nil
}

// runOIDCLogout clears stored tokens. The CLI keeps exactly one active
// session (openOIDCTokenStore), so --all and the default form are
// equivalent: both remove that one stored entry. --all is kept only for
// CLI-surface compatibility with earlier releases' flag set.
func runOIDCLogout(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	tokenStore, _ := cmd.Flags().GetString("token-store")
	all, _ := cmd.Flags().GetBool("all")

	tokenCLIStore, err := openOIDCTokenStore(cmd, tokenStore)
	if err != nil {
		return err
	}

	existed, err := tokenCLIStore.Clear()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
	}

	if !existed {
		_, _ = fmt.Fprintln(out, "No tokens to clear.")
		return nil
	}

	if all {
		_, _ = fmt.Fprintln(out, "All tokens cleared.")
		return nil
	}
	_, _ = fmt.Fprintln(out, "Tokens cleared.")
	return nil
}

// runOIDCProvidersList lists configured providers.
func runOIDCProvidersList(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	tokenStore, _ := cmd.Flags().GetString("token-store")
	configPath := getConfigPath(tokenStore)

	config, err := loadOIDCConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintln(out, "No OIDC providers configured.")
			return nil
		}
		return &SentinelCauseError{Sentinel: ErrOIDCConfigLoadFailed, Cause: err}
	}

	if len(config.Providers) == 0 {
		_, _ = fmt.Fprintln(out, "No OIDC providers configured.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "OIDC Providers (%d):\n\n", len(config.Providers))

	for _, provider := range config.Providers {
		_, _ = fmt.Fprintf(out, "  Name:         %s\n", provider.Name)

		// Display type
		pType := provider.Type
		if pType == "" {
			pType = OIDCProviderTypeStandard
		}
		_, _ = fmt.Fprintf(out, "  Type:         %s\n", pType)

		if pType == OIDCProviderTypeAWS {
			// AWS-specific display
			_, _ = fmt.Fprintf(out, "  Region:       %s\n", provider.AWSRegion)
			if provider.AWSProfile != "" {
				_, _ = fmt.Fprintf(out, "  Profile:      %s\n", provider.AWSProfile)
			}
			if provider.AWSCredentialsFile != "" {
				_, _ = fmt.Fprintf(out, "  Credentials:  %s\n", provider.AWSCredentialsFile)
			}
			if provider.AWSOutput != "" {
				_, _ = fmt.Fprintf(out, "  Output:       %s\n", provider.AWSOutput)
			}
			if provider.AWSCrossDevice {
				_, _ = fmt.Fprintf(out, "  Cross-Device: yes\n")
			}
			if provider.AWSSessionStore != "" {
				_, _ = fmt.Fprintf(out, "  Session Store: %s\n", provider.AWSSessionStore)
			}
		} else {
			// Standard OIDC display
			_, _ = fmt.Fprintf(out, "  Issuer:       %s\n", provider.Issuer)
			_, _ = fmt.Fprintf(out, "  Client ID:    %s\n", provider.ClientID)
			if provider.ClientSecret != "" {
				_, _ = fmt.Fprintf(out, "  Client Secret: ***\n")
			}
			if provider.RedirectURL != "" {
				_, _ = fmt.Fprintf(out, "  Redirect URL: %s\n", provider.RedirectURL)
			}
			if len(provider.Scopes) > 0 {
				_, _ = fmt.Fprintf(out, "  Scopes:       %s\n", strings.Join(provider.Scopes, ", "))
			}
		}

		// Common fields
		if provider.Exec != "" {
			_, _ = fmt.Fprintf(out, "  Exec:         %s\n", provider.Exec)
		}
		if provider.AutoRefresh > 0 {
			_, _ = fmt.Fprintf(out, "  Auto-Refresh: %d seconds\n", provider.AutoRefresh)
		}
		if provider.Background {
			_, _ = fmt.Fprintf(out, "  Background:   yes\n")
		}
		if provider.LogFile != "" {
			_, _ = fmt.Fprintf(out, "  Log File:     %s\n", provider.LogFile)
		}
		_, _ = fmt.Fprintln(out)
	}

	return nil
}

// runOIDCProvidersAdd adds a new provider.
func runOIDCProvidersAdd(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	name, _ := cmd.Flags().GetString("name")
	providerType, _ := cmd.Flags().GetString("type")
	issuer, _ := cmd.Flags().GetString("issuer")
	clientID, _ := cmd.Flags().GetString("client-id")
	clientSecret, _ := cmd.Flags().GetString("client-secret")
	redirectURL, _ := cmd.Flags().GetString("redirect-url")
	scopesStr, _ := cmd.Flags().GetString("scopes")
	execCmd, _ := cmd.Flags().GetString("exec")
	autoRefresh, _ := cmd.Flags().GetInt("auto-refresh")
	background, _ := cmd.Flags().GetBool("background")
	logFile, _ := cmd.Flags().GetString("log-file")
	tokenStore, _ := cmd.Flags().GetString("token-store")

	// AWS-specific flags
	awsRegion, _ := cmd.Flags().GetString("region")
	awsProfile, _ := cmd.Flags().GetString("profile")
	awsCredentialsFile, _ := cmd.Flags().GetString("credentials-file")
	awsOutput, _ := cmd.Flags().GetString("output")
	awsCrossDevice, _ := cmd.Flags().GetBool("cross-device")
	awsSessionStore, _ := cmd.Flags().GetString("session-store")

	manual, err := getManualOIDCEndpointFlags(cmd)
	if err != nil {
		return err
	}
	tokenEncodingStr, _ := cmd.Flags().GetString("token-encoding")
	tokenEncoding := oidc.TokenEncoding(tokenEncodingStr)
	if err := tokenEncoding.Validate(); err != nil {
		return err
	}

	if name == "" {
		return ErrOIDCMissingProviderName
	}

	// Determine provider type
	pType := OIDCProviderType(providerType)
	if pType == "" {
		pType = OIDCProviderTypeStandard
	}

	// Validate based on type
	if pType == OIDCProviderTypeAWS {
		if awsRegion == "" {
			return ErrAWSMissingRegion
		}
	} else {
		// Standard OIDC requires issuer and client-id
		if issuer == "" {
			// Provide helpful hint if --region was specified without --type aws
			if awsRegion != "" {
				return &DetailError{Err: ErrOIDCMissingIssuer, Detail: " (hint: use --type aws for AWS providers)"}
			}
			return ErrOIDCMissingIssuer
		}
		if clientID == "" {
			return ErrOIDCMissingClientID
		}
		// A partial set of manual endpoints is refused up front so the
		// mistake surfaces at `providers add` time, not at the next login.
		if !manual.empty() {
			var missing []string
			if manual.AuthorizationEndpoint == "" {
				missing = append(missing, "--authorization-endpoint")
			}
			if manual.TokenEndpoint == "" {
				missing = append(missing, "--token-endpoint")
			}
			if manual.JwksURI == "" {
				missing = append(missing, "--jwks-uri")
			}
			if len(missing) > 0 {
				return &DetailError{Err: ErrOIDCIncompleteEndpoints, Detail: fmt.Sprintf(": %s", strings.Join(missing, ", "))}
			}
		}
	}

	var scopes []string
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, ",")
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}

	configPath := getConfigPath(tokenStore)

	config, err := loadOIDCConfig(configPath)
	if err != nil && !os.IsNotExist(err) {
		return &SentinelCauseError{Sentinel: ErrOIDCConfigLoadFailed, Cause: err}
	}
	if config == nil {
		config = &OIDCConfig{Providers: []OIDCProvider{}}
	}

	// Check if provider already exists
	for _, p := range config.Providers {
		if p.Name == name {
			return ErrOIDCProviderExists
		}
	}

	// Convert relative log file path to absolute at storage time
	if logFile != "" {
		logFile = expandPath(logFile)
	}
	// AWSSessionStore is only persisted when --session-store was actually
	// set on this command: an unset value lets runAWSProviderLogin (oidc.go)
	// take the barrier-or-fallback path at login time, the same as `xkey
	// oidc aws` run directly without --session-store, rather than silently
	// pinning every provider added without the flag to the flag's default
	// literal and bypassing barrier auto-detection for all of them.
	if cmd.Flags().Changed("session-store") {
		awsSessionStore = expandPath(awsSessionStore)
	} else {
		awsSessionStore = ""
	}

	if redirectURL == "" && pType != OIDCProviderTypeAWS {
		callback, err := resolveOIDCCallback(cmd)
		if err != nil {
			return err
		}
		redirectURL = callback.RedirectURL()
	}

	provider := OIDCProvider{
		Name:         name,
		Type:         pType,
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Exec:         execCmd,
		AutoRefresh:  autoRefresh,
		Background:   background,
		LogFile:      logFile,
		// Manual endpoints (standard OIDC only; empty unless supplied)
		AuthorizationEndpoint: manual.AuthorizationEndpoint,
		TokenEndpoint:         manual.TokenEndpoint,
		JwksURI:               manual.JwksURI,
		UserinfoEndpoint:      manual.UserinfoEndpoint,
		TokenEncoding:         tokenEncoding,
		// AWS fields
		AWSRegion:          awsRegion,
		AWSProfile:         awsProfile,
		AWSCredentialsFile: awsCredentialsFile,
		AWSOutput:          awsOutput,
		AWSCrossDevice:     awsCrossDevice,
		AWSSessionStore:    awsSessionStore,
	}

	config.Providers = append(config.Providers, provider)

	if err := saveOIDCConfig(configPath, *config); err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCConfigSaveFailed, Cause: err}
	}

	if pType == OIDCProviderTypeAWS {
		_, _ = fmt.Fprintf(out, "Added AWS OIDC provider: %s (region: %s)\n", name, awsRegion)
	} else {
		_, _ = fmt.Fprintf(out, "Added OIDC provider: %s\n", name)
	}
	return nil
}

// runOIDCProvidersRemove removes a provider.
func runOIDCProvidersRemove(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	name := args[0]
	tokenStore, _ := cmd.Flags().GetString("token-store")

	configPath := getConfigPath(tokenStore)

	config, err := loadOIDCConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrOIDCProviderNotFound
		}
		return &SentinelCauseError{Sentinel: ErrOIDCConfigLoadFailed, Cause: err}
	}

	found := false
	newProviders := make([]OIDCProvider, 0, len(config.Providers))
	for _, p := range config.Providers {
		if p.Name == name {
			found = true
			continue
		}
		newProviders = append(newProviders, p)
	}

	if !found {
		return ErrOIDCProviderNotFound
	}

	// Stop any running background refresh process for this provider
	pidFile := getPIDFile(tokenStore, name)
	if _, running := isProcessRunning(pidFile); running {
		if err := stopProcess(out, pidFile, name); err != nil {
			// Log warning but don't fail the removal
			fmt.Fprintf(os.Stderr, "Warning: failed to stop background refresh for '%s': %v\n", name, err)
		} else {
			_, _ = fmt.Fprintf(out, "Stopped background refresh for '%s'\n", name)
		}
	}

	config.Providers = newProviders

	if err := saveOIDCConfig(configPath, *config); err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCConfigSaveFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Removed OIDC provider: %s\n", name)
	return nil
}

// discoverOIDCProvider fetches the OIDC discovery document.
func discoverOIDCProvider(issuer string) (*OIDCDiscoveryDocument, error) {
	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCProviderTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &MessageError{Msg: fmt.Sprintf("discovery endpoint returned status %d", resp.StatusCode)}
	}

	var doc OIDCDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

// manualOIDCEndpoints is the manual-endpoint half of resolveOIDCEndpoints'
// input: the four endpoint flags a caller may supply to bypass discovery.
type manualOIDCEndpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	JwksURI               string
	UserinfoEndpoint      string
}

// empty returns true if none of the manual endpoints are set.
func (m manualOIDCEndpoints) empty() bool {
	return m.AuthorizationEndpoint == "" && m.TokenEndpoint == "" &&
		m.JwksURI == "" && m.UserinfoEndpoint == ""
}

// resolveOIDCEndpoints returns the provider's endpoints. When any manual
// endpoint is supplied it skips discovery entirely and requires the
// authorization, token, and jwks endpoints (mirroring pkg/oidc's
// ProviderConfig.SkipDiscovery contract); a caller who supplies only some of
// them is refused with a typed error naming what's missing. Otherwise it
// falls back to fetching the issuer's .well-known discovery document.
func resolveOIDCEndpoints(issuer string, manual manualOIDCEndpoints) (*OIDCDiscoveryDocument, error) {
	if manual.empty() {
		return discoverOIDCProvider(issuer)
	}

	var missing []string
	if manual.AuthorizationEndpoint == "" {
		missing = append(missing, "--authorization-endpoint")
	}
	if manual.TokenEndpoint == "" {
		missing = append(missing, "--token-endpoint")
	}
	if manual.JwksURI == "" {
		missing = append(missing, "--jwks-uri")
	}
	if len(missing) > 0 {
		return nil, &DetailError{Err: ErrOIDCIncompleteEndpoints, Detail: fmt.Sprintf(": %s", strings.Join(missing, ", "))}
	}

	return &OIDCDiscoveryDocument{
		Issuer:                issuer,
		AuthorizationEndpoint: manual.AuthorizationEndpoint,
		TokenEndpoint:         manual.TokenEndpoint,
		JwksURI:               manual.JwksURI,
		UserinfoEndpoint:      manual.UserinfoEndpoint,
	}, nil
}

// getManualOIDCEndpointFlags reads the --authorization-endpoint,
// --token-endpoint, --jwks-uri, and --userinfo-endpoint flags from cmd.
func getManualOIDCEndpointFlags(cmd *cobra.Command) (manualOIDCEndpoints, error) {
	authEndpoint, err := cmd.Flags().GetString("authorization-endpoint")
	if err != nil {
		return manualOIDCEndpoints{}, err
	}
	tokenEndpoint, err := cmd.Flags().GetString("token-endpoint")
	if err != nil {
		return manualOIDCEndpoints{}, err
	}
	jwksURI, err := cmd.Flags().GetString("jwks-uri")
	if err != nil {
		return manualOIDCEndpoints{}, err
	}
	userinfoEndpoint, err := cmd.Flags().GetString("userinfo-endpoint")
	if err != nil {
		return manualOIDCEndpoints{}, err
	}
	return manualOIDCEndpoints{
		AuthorizationEndpoint: authEndpoint,
		TokenEndpoint:         tokenEndpoint,
		JwksURI:               jwksURI,
		UserinfoEndpoint:      userinfoEndpoint,
	}, nil
}

// generateCodeVerifier generates a PKCE code verifier.
func generateCodeVerifier() (string, error) {
	b := make([]byte, oidcCodeVerifierLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge generates a PKCE code challenge from a verifier.
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateState generates a random state parameter.
func generateState() (string, error) {
	b := make([]byte, oidcStateLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// buildAuthorizationURL builds the authorization endpoint URL.
func buildAuthorizationURL(endpoint, clientID, redirectURL string, scopes []string, state, codeChallenge string) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURL},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return endpoint + "?" + params.Encode()
}

// handleOIDCCallback handles the OAuth2 callback.
func handleOIDCCallback(w http.ResponseWriter, r *http.Request, codeChan chan<- string, errChan chan<- error, state *atomic.Value) {
	query := r.URL.Query()

	if errParam := query.Get("error"); errParam != "" {
		// The provider, or anyone who can steer the browser to the loopback
		// URL, controls both parameters, so they reach the terminal only
		// sanitised.
		msg := oidc.SanitizeProviderText(errParam) + ": " + oidc.SanitizeProviderText(query.Get("error_description"))
		// A page that cannot reach the browser (it hung up) changes nothing
		// about the login's outcome, so the write error is only logged.
		if err := oidc.WriteCallbackPage(w, oidc.CallbackPage{Title: "Authentication Failed", Message: msg}); err != nil {
			slog.Debug("oidc: failed to write callback response", "error", err)
		}

		errChan <- &MessageError{Msg: msg}
		return
	}

	code := query.Get("code")
	if code == "" {
		if err := oidc.WriteCallbackPage(w, oidc.CallbackPage{Title: "Authentication Failed", Message: "No authorization code received"}); err != nil {
			slog.Debug("oidc: failed to write callback response", "error", err)
		}
		errChan <- ErrOIDCNoAuthCode
		return
	}

	state.Store(query.Get("state"))

	if err := oidc.WriteCallbackPage(w, oidc.CallbackPage{Title: "Authentication Successful", Message: "You may close this window."}); err != nil {
		slog.Debug("oidc: failed to write callback response", "error", err)
	}

	codeChan <- code
}

// exchangeCodeForTokens exchanges an authorization code for tokens.
// encoding selects the token request body format ("form" or "json",
// defaulting to form); the actual encoding decision is made by
// pkg/oidc.EncodeTokenRequestBody so the CLI and the pkg/oidc.Client used by
// the GUI never diverge on how a provider's token endpoint is addressed.
func exchangeCodeForTokens(endpoint, clientID, clientSecret, code, redirectURL, codeVerifier string, encoding oidc.TokenEncoding) (*OIDCTokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURL},
		"code_verifier": {codeVerifier},
	}

	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	return doOIDCTokenRequest(endpoint, data, encoding)
}

// refreshTokens refreshes tokens using a refresh token.
// encoding selects the token request body format; see exchangeCodeForTokens.
func refreshTokens(endpoint, clientID, refreshToken string, encoding oidc.TokenEncoding) (*OIDCTokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	}

	return doOIDCTokenRequest(endpoint, data, encoding)
}

// doOIDCTokenRequest POSTs a token request body to endpoint, encoded per
// encoding via pkg/oidc.EncodeTokenRequestBody, and decodes the response.
func doOIDCTokenRequest(endpoint string, data url.Values, encoding oidc.TokenEncoding) (*OIDCTokenResponse, error) {
	body, contentType, err := oidc.EncodeTokenRequestBody(encoding, data)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCProviderTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &MessageError{Msg: fmt.Sprintf("token endpoint returned status %d", resp.StatusCode)}
	}

	var tokens OIDCTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

// parseIDToken parses an ID token and extracts claims.
func parseIDToken(idToken string) (*OIDCIDTokenClaims, error) {
	if idToken == "" {
		return &OIDCIDTokenClaims{}, nil
	}

	token, err := jwt.ParseSigned(idToken, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
	})
	if err != nil {
		return nil, err
	}

	var claims OIDCIDTokenClaims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// expandPath expands ~ to the user's home directory and converts relative paths to absolute.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	// Convert relative paths to absolute paths
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return path
		}
		return absPath
	}
	return path
}

// getConfigPath returns the OIDC config path based on the token store path.
func getConfigPath(tokenStore string) string {
	path := expandPath(tokenStore)
	dir := filepath.Dir(path)
	return filepath.Join(dir, "oidc-providers.json")
}

// loadOIDCConfig loads the OIDC configuration file.
func loadOIDCConfig(path string) (*OIDCConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config OIDCConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// loadProvider loads a specific provider by name from the OIDC config.
func loadProvider(tokenStore, providerName string) (*OIDCProvider, error) {
	configPath := getConfigPath(tokenStore)
	config, err := loadOIDCConfig(configPath)
	if err != nil {
		return nil, err
	}

	for i := range config.Providers {
		if strings.EqualFold(config.Providers[i].Name, providerName) {
			return &config.Providers[i], nil
		}
	}

	return nil, &MessageError{Msg: fmt.Sprintf("provider not found: %s", providerName)}
}

// saveOIDCConfig saves the OIDC configuration file.
func saveOIDCConfig(path string, config OIDCConfig) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// truncateTokenPrefixLen is the maximum number of leading token characters
// truncateToken ever reveals.
const truncateTokenPrefixLen = 8

// truncateToken formats a token for display without --full. It never prints
// a full token, however short: the result is at most an 8-character prefix
// followed by the token's total length, e.g. "abcd1234… (1234 chars)". An
// empty token formats as "(0 chars)".
func truncateToken(token string) string {
	prefix := token
	if len(prefix) > truncateTokenPrefixLen {
		prefix = prefix[:truncateTokenPrefixLen]
	}
	if prefix == "" {
		return fmt.Sprintf("(%d chars)", len(token))
	}
	return fmt.Sprintf("%s… (%d chars)", prefix, len(token))
}

// formatDuration formats a duration for human-readable display.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if minutes > 0 {
		return fmt.Sprintf("%d hours %d minutes", hours, minutes)
	}
	return fmt.Sprintf("%d hours", hours)
}

// runAutoRefresh runs a loop that periodically refreshes the token. store is
// opened once by the caller (runOIDCLogin or runBackgroundWorker) and reused
// for every tick below, so a barrier-backed store is unsealed once for the
// life of the loop rather than on every interval (go-xkms#4). If logWriter
// is nil, output goes to stdout. encoding selects the token request body
// format used for every refresh in the loop.
//
// stop, when non-nil, ends the loop the same way an OS interrupt does; every
// production call site passes nil, so only an OS signal can stop it there.
// It exists so a test can end the loop deterministically after a known
// number of ticks instead of sending the process a real signal.
func runAutoRefresh(tokenEndpoint, clientID string, store *oidcCLITokenStore, tokenStorePath, execCmd, providerName string, interval time.Duration, logWriter io.Writer, encoding oidc.TokenEncoding, stop <-chan struct{}) error {
	if logWriter == nil {
		logWriter = os.Stdout
	}
	log := func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(logWriter, format, args...)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	refreshCount := 0
	intervalSecs := int(interval.Seconds())

	// Helper to save status
	updateStatus := func(lastStatus, lastError string) {
		status := &OIDCRefreshStatus{
			LastRefresh:  time.Now(),
			NextRefresh:  time.Now().Add(interval),
			RefreshCount: refreshCount,
			LastStatus:   lastStatus,
			LastError:    lastError,
			IntervalSecs: intervalSecs,
		}
		if err := saveRefreshStatus(tokenStorePath, providerName, status); err != nil {
			log("  Warning: failed to save status: %v\n", err)
		}
	}

	// doTick performs one load -> refresh -> save -> (optional exec) cycle.
	// It is a function literal, not inlined in the select below, so that
	// `defer token.Destroy()` fires at the end of THIS call rather than at
	// the end of runAutoRefresh: without that, a long-running background
	// worker would accumulate one mlocked buffer per tick for the life of
	// the process instead of releasing each one before the next tick loads
	// a fresh token. Returns true when the loop must stop.
	doTick := func() (stop bool) {
		refreshCount++
		log("[%s] Refreshing token (#%d)...\n", time.Now().Format("2006-01-02 15:04:05"), refreshCount)

		// Load current token
		token, err := store.Load()
		if err != nil {
			log("  Error loading token: %v\n", err)
			updateStatus("error", fmt.Sprintf("failed to load token: %v", err))
			return false
		}
		defer token.Destroy()

		if !token.HasRefreshToken() {
			log("  Error: No refresh token available. Stopping auto-refresh.\n")
			updateStatus("error", "no refresh token available")
			return true
		}

		// Refresh the token
		newTokens, err := refreshTokens(tokenEndpoint, clientID, token.RefreshToken(), encoding)
		if err != nil {
			log("  Error refreshing: %v\n", err)
			updateStatus("error", fmt.Sprintf("refresh failed: %v", err))
			return false
		}

		// Update stored token
		if err := token.SetAccessToken(newTokens.AccessToken); err != nil {
			log("  Error storing token: %v\n", err)
			updateStatus("error", fmt.Sprintf("failed to store token: %v", err))
			return false
		}
		if newTokens.RefreshToken != "" {
			if err := token.SetRefreshToken(newTokens.RefreshToken); err != nil {
				log("  Error storing token: %v\n", err)
				updateStatus("error", fmt.Sprintf("failed to store token: %v", err))
				return false
			}
		}
		if newTokens.IDToken != "" {
			if err := token.SetIDToken(newTokens.IDToken); err != nil {
				log("  Error storing token: %v\n", err)
				updateStatus("error", fmt.Sprintf("failed to store token: %v", err))
				return false
			}
		}
		token.ExpiresAt = time.Now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)

		if err := store.Save(token); err != nil {
			log("  Error storing token: %v\n", err)
			updateStatus("error", fmt.Sprintf("failed to store token: %v", err))
			return false
		}

		log("  Token refreshed. New expiration: %s\n", token.ExpiresAt.Format(time.RFC3339))
		updateStatus("success", "")

		// Execute script if specified
		if execCmd != "" {
			claims, err := parseIDToken(token.IDToken())
			if err != nil {
				// A malformed ID token means the claims below cannot be
				// trusted; skip this cycle's exec hook rather than run it
				// with an empty Subject/Email/Name.
				log("  Error parsing ID token, skipping exec hook: %v\n", err)
			} else {
				payload := OIDCExecPayload{
					Provider:     token.Issuer,
					Issuer:       token.Issuer,
					ClientID:     token.ClientID,
					AccessToken:  token.AccessToken(),
					RefreshToken: token.RefreshToken(),
					IDToken:      token.IDToken(),
					ExpiresAt:    token.ExpiresAt.Format(time.RFC3339),
					ExpiresIn:    newTokens.ExpiresIn,
					Scopes:       token.Scopes,
					Subject:      claims.Subject,
					Email:        claims.Email,
					Name:         claims.Name,
				}

				if err := executeOIDCScript(logWriter, execCmd, payload); err != nil {
					log("  Script error: %v\n", err)
				}
			}
		}
		return false
	}

	for {
		select {
		case <-sigChan:
			log("\n[%s] Auto-refresh stopped.\n", time.Now().Format("2006-01-02 15:04:05"))
			return nil

		case <-stop:
			log("\n[%s] Auto-refresh stopped.\n", time.Now().Format("2006-01-02 15:04:05"))
			return nil

		case <-ticker.C:
			if doTick() {
				return ErrOIDCInvalidRefreshToken
			}
		}
	}
}

// executeOIDCScript executes a custom script with the OIDC response.
// The payload is passed as JSON via stdin and also as environment variables.
func executeOIDCScript(out io.Writer, cmdStr string, payload OIDCExecPayload) error {
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Executing: %s\n", cmdStr)

	// Parse the command - support shell execution
	cmd := exec.Command("sh", "-c", cmdStr)

	// Pass payload as JSON via stdin
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return &WrappedError{Msg: "failed to marshal payload", Err: err}
	}
	cmd.Stdin = bytes.NewReader(payloadJSON)

	// Also set environment variables for simpler scripts
	cmd.Env = append(os.Environ(),
		"OIDC_PROVIDER="+payload.Provider,
		"OIDC_ISSUER="+payload.Issuer,
		"OIDC_CLIENT_ID="+payload.ClientID,
		"OIDC_ACCESS_TOKEN="+payload.AccessToken,
		"OIDC_REFRESH_TOKEN="+payload.RefreshToken,
		"OIDC_ID_TOKEN="+payload.IDToken,
		"OIDC_EXPIRES_AT="+payload.ExpiresAt,
		"OIDC_EXPIRES_IN="+fmt.Sprintf("%d", payload.ExpiresIn),
		"OIDC_SCOPES="+strings.Join(payload.Scopes, " "),
		"OIDC_SUBJECT="+payload.Subject,
		"OIDC_EMAIL="+payload.Email,
		"OIDC_NAME="+payload.Name,
	)

	// Capture output
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return &WrappedError{Msg: "script execution failed", Err: err}
	}

	return nil
}

// getDefaultLogFile returns the default log file path for a provider.
func getDefaultLogFile(tokenStore, providerName string) string {
	dir := filepath.Dir(expandPath(tokenStore))
	logsDir := filepath.Join(dir, "logs")
	if providerName == "" {
		providerName = "default"
	}
	return filepath.Join(logsDir, providerName+".log")
}

// getPIDDir returns the directory for PID files.
func getPIDDir(tokenStore string) string {
	dir := filepath.Dir(expandPath(tokenStore))
	return filepath.Join(dir, "pids")
}

// getPIDFile returns the PID file path for a provider.
func getPIDFile(tokenStore, providerName string) string {
	if providerName == "" {
		providerName = "default"
	}
	return filepath.Join(getPIDDir(tokenStore), providerName+".pid")
}

// getStatusFile returns the status file path for a provider.
func getStatusFile(tokenStore, providerName string) string {
	if providerName == "" {
		providerName = "default"
	}
	return filepath.Join(getPIDDir(tokenStore), providerName+".status.json")
}

// saveRefreshStatus saves the refresh status to disk.
func saveRefreshStatus(tokenStore, providerName string, status *OIDCRefreshStatus) error {
	statusFile := getStatusFile(tokenStore, providerName)
	dir := filepath.Dir(statusFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statusFile, data, 0600)
}

// loadRefreshStatus loads the refresh status from disk.
func loadRefreshStatus(tokenStore, providerName string) (*OIDCRefreshStatus, error) {
	statusFile := getStatusFile(tokenStore, providerName)
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return nil, err
	}
	var status OIDCRefreshStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// startBackgroundRefresh starts a background refresh process.
//
// barrierPasswordFile, if non-empty, is forwarded to the detached process as
// --barrier-password-file so it can unseal a barrier-backed token store
// non-interactively (go-xkms#4). A --barrier-password VALUE is never
// forwarded on argv: that would put the barrier password in `ps` output for
// any local user to read. A password supplied only via --barrier-password
// (not --barrier-password-file or XKEY_BARRIER_PASSWORD, which the detached
// process inherits from its environment like any other exec.Command with no
// Env override) does not reach the background worker; use one of the other
// two non-interactive sources for --background --auto-refresh.
func startBackgroundRefresh(out io.Writer, providerName, tokenEndpoint, clientID, tokenStorePath, execCmd, logFile, barrierPasswordFile string, autoRefresh int, encoding oidc.TokenEncoding) error {
	// Ensure log directory exists
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return &WrappedError{Msg: "failed to create log directory", Err: err}
	}

	// Ensure PID directory exists
	pidDir := getPIDDir(tokenStorePath)
	if err := os.MkdirAll(pidDir, 0700); err != nil {
		return &WrappedError{Msg: "failed to create PID directory", Err: err}
	}

	// Check if already running
	pidFile := getPIDFile(tokenStorePath, providerName)
	if pid, running := isProcessRunning(pidFile); running {
		return &MessageError{Msg: fmt.Sprintf("background refresh for '%s' is already running (PID %d)", providerName, pid)}
	}

	// Open log file
	logFileHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return &WrappedError{Msg: "failed to open log file", Err: err}
	}

	// Build command to run ourselves with special --background-worker flag
	executable, err := os.Executable()
	if err != nil {
		return &WrappedError{Msg: "failed to get executable path", Err: errors.Join(err, logFileHandle.Close())}
	}

	args := []string{
		"oidc", "login",
		"--background-worker",
		"--token-endpoint", tokenEndpoint,
		"--client-id", clientID,
		"--token-store", tokenStorePath,
		"--auto-refresh", strconv.Itoa(autoRefresh),
		"--log-file", logFile,
		"--provider-name", providerName,
	}
	if execCmd != "" {
		args = append(args, "--exec", execCmd)
	}
	if encoding != "" {
		args = append(args, "--token-encoding", string(encoding))
	}
	if barrierPasswordFile != "" {
		args = append(args, "--barrier-password-file", barrierPasswordFile)
	}

	cmd := exec.Command(executable, args...)
	cmd.Stdout = logFileHandle
	cmd.Stderr = logFileHandle

	// Start the process
	if err := cmd.Start(); err != nil {
		return &WrappedError{Msg: "failed to start background process", Err: errors.Join(err, logFileHandle.Close())}
	}

	// Write PID file
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		killErr := cmd.Process.Kill()
		return &WrappedError{Msg: "failed to write PID file", Err: errors.Join(err, killErr, logFileHandle.Close())}
	}

	// Don't wait for the process - let it run in background. There is no
	// caller left to report a cleanup failure to at this point, so each is
	// logged instead of dropped.
	go func() {
		if waitErr := cmd.Wait(); waitErr != nil {
			slog.Debug("oidc login: background worker exited with an error", "error", waitErr)
		}
		if closeErr := logFileHandle.Close(); closeErr != nil {
			slog.Warn("oidc login: failed to close background worker log file", "error", closeErr)
		}
		if rmErr := os.Remove(pidFile); rmErr != nil { // Clean up PID file when process exits
			slog.Warn("oidc login: failed to remove PID file", "error", rmErr)
		}
	}()

	_, _ = fmt.Fprintf(out, "Background refresh started for '%s'\n", providerName)
	_, _ = fmt.Fprintf(out, "  PID:      %d\n", cmd.Process.Pid)
	_, _ = fmt.Fprintf(out, "  Log file: %s\n", logFile)
	_, _ = fmt.Fprintf(out, "\nUse 'xkey oidc status' to see running refreshes\n")
	_, _ = fmt.Fprintf(out, "Use 'xkey oidc stop %s' to stop\n", providerName)

	return nil
}

// runBackgroundWorker runs the actual auto-refresh loop (called by background process).
func runBackgroundWorker(cmd *cobra.Command, args []string) (err error) {
	tokenEndpoint, _ := cmd.Flags().GetString("token-endpoint")
	clientID, _ := cmd.Flags().GetString("client-id")
	tokenStore, _ := cmd.Flags().GetString("token-store")
	execCmd, _ := cmd.Flags().GetString("exec")
	autoRefresh, _ := cmd.Flags().GetInt("auto-refresh")
	logFile, _ := cmd.Flags().GetString("log-file")
	providerName, _ := cmd.Flags().GetString("provider-name")
	tokenEncodingStr, _ := cmd.Flags().GetString("token-encoding")
	tokenEncoding := oidc.TokenEncoding(tokenEncodingStr)

	// Open log file for writing
	var logWriter io.Writer = os.Stdout
	if logFile != "" {
		f, openErr := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if openErr != nil {
			return &WrappedError{Msg: "failed to open log file", Err: openErr}
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}()
		logWriter = f
	}

	_, _ = fmt.Fprintf(logWriter, "[%s] Background refresh started for '%s'\n", time.Now().Format("2006-01-02 15:04:05"), providerName)
	_, _ = fmt.Fprintf(logWriter, "  Token endpoint: %s\n", tokenEndpoint)
	_, _ = fmt.Fprintf(logWriter, "  Refresh interval: %d seconds\n", autoRefresh)
	if execCmd != "" {
		_, _ = fmt.Fprintf(logWriter, "  Exec command: %s\n", execCmd)
	}
	_, _ = fmt.Fprintf(logWriter, "\n")

	// Opened once for the life of this (detached) process, exactly as the
	// foreground loop opens it once for the life of runOIDCLogin: a
	// barrier-backed store is unsealed here, not re-unsealed on every tick.
	tokenCLIStore, err := openOIDCTokenStore(cmd, tokenStore)
	if err != nil {
		return err
	}

	return runAutoRefresh(tokenEndpoint, clientID, tokenCLIStore, tokenStore, execCmd, providerName, time.Duration(autoRefresh)*time.Second, logWriter, tokenEncoding, nil)
}

// isProcessRunning checks if a process with the given PID file is running.
func isProcessRunning(pidFile string) (int, bool) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}

	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return pid, false
	}

	// On Unix, FindProcess always succeeds. Send signal 0 to check if process exists.
	err = process.Signal(syscall.Signal(0))
	return pid, err == nil
}

// runOIDCStatus shows running background refresh processes.
func runOIDCStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	tokenStore, _ := cmd.Flags().GetString("token-store")
	pidDir := getPIDDir(tokenStore)

	entries, err := os.ReadDir(pidDir)
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintln(out, "No background refresh processes running.")
			return nil
		}
		return &WrappedError{Msg: "failed to read PID directory", Err: err}
	}

	var running []OIDCBackgroundProcess
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pid") {
			continue
		}

		providerName := strings.TrimSuffix(entry.Name(), ".pid")
		pidFile := filepath.Join(pidDir, entry.Name())

		pid, isRunning := isProcessRunning(pidFile)
		if !isRunning {
			// Clean up stale PID file. A failure here is not fatal to
			// listing (the next invocation will retry), but it is logged
			// since a persistently unremovable PID file would otherwise
			// keep reappearing here silently.
			if rmErr := os.Remove(pidFile); rmErr != nil {
				slog.Debug("oidc: failed to remove stale PID file", "path", pidFile, "error", rmErr)
			}
			continue
		}

		info, _ := entry.Info()
		startTime := time.Time{}
		if info != nil {
			startTime = info.ModTime()
		}

		// Try to get log file from provider config, fall back to default
		logFile := ""
		if provider, err := loadProvider(tokenStore, providerName); err == nil && provider.LogFile != "" {
			// Provider log file is already stored as absolute path
			logFile = provider.LogFile
		}
		if logFile == "" {
			logFile = getDefaultLogFile(tokenStore, providerName)
		}

		// Try to load refresh status
		var status *OIDCRefreshStatus
		if s, err := loadRefreshStatus(tokenStore, providerName); err == nil {
			status = s
		}

		running = append(running, OIDCBackgroundProcess{
			Provider:  providerName,
			PID:       pid,
			StartedAt: startTime,
			LogFile:   logFile,
			Status:    status,
		})
	}

	if len(running) == 0 {
		_, _ = fmt.Fprintln(out, "No background refresh processes running.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Background Refresh Processes (%d):\n\n", len(running))
	for _, proc := range running {
		_, _ = fmt.Fprintf(out, "  Provider:     %s\n", proc.Provider)
		_, _ = fmt.Fprintf(out, "  PID:          %d\n", proc.PID)
		if !proc.StartedAt.IsZero() {
			_, _ = fmt.Fprintf(out, "  Started:      %s (%s ago)\n", proc.StartedAt.Format("2006-01-02 15:04:05"), formatDuration(time.Since(proc.StartedAt)))
		}
		// Display refresh status if available
		if proc.Status != nil {
			statusIcon := "✓"
			if proc.Status.LastStatus == "error" {
				statusIcon = "✗"
			}
			if !proc.Status.LastRefresh.IsZero() {
				_, _ = fmt.Fprintf(out, "  Last Refresh: %s (%s ago) %s\n",
					proc.Status.LastRefresh.Format("2006-01-02 15:04:05"),
					formatDuration(time.Since(proc.Status.LastRefresh)),
					statusIcon)
			}
			if !proc.Status.NextRefresh.IsZero() && proc.Status.NextRefresh.After(time.Now()) {
				_, _ = fmt.Fprintf(out, "  Next Refresh: in %s\n", formatDuration(time.Until(proc.Status.NextRefresh)))
			}
			_, _ = fmt.Fprintf(out, "  Refreshes:    %d", proc.Status.RefreshCount)
			switch {
			case proc.Status.LastStatus == "success":
				_, _ = fmt.Fprintf(out, " successful\n")
			case proc.Status.LastError != "":
				_, _ = fmt.Fprintf(out, " (last error: %s)\n", proc.Status.LastError)
			default:
				_, _ = fmt.Fprintln(out)
			}
		}
		_, _ = fmt.Fprintf(out, "  Log file:     %s\n", proc.LogFile)
		_, _ = fmt.Fprintln(out)
	}

	return nil
}

// runOIDCStop stops a background refresh process.
func runOIDCStop(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	tokenStore, _ := cmd.Flags().GetString("token-store")
	stopAll, _ := cmd.Flags().GetBool("all")

	pidDir := getPIDDir(tokenStore)

	if stopAll {
		entries, err := os.ReadDir(pidDir)
		if err != nil {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintln(out, "No background refresh processes running.")
				return nil
			}
			return &WrappedError{Msg: "failed to read PID directory", Err: err}
		}

		stopped := 0
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".pid") {
				continue
			}

			providerName := strings.TrimSuffix(entry.Name(), ".pid")
			pidFile := filepath.Join(pidDir, entry.Name())

			if err := stopProcess(out, pidFile, providerName); err != nil {
				fmt.Fprintf(os.Stderr, "  %s: %v\n", providerName, err)
			} else {
				stopped++
			}
		}

		if stopped == 0 {
			_, _ = fmt.Fprintln(out, "No background refresh processes were running.")
		} else {
			_, _ = fmt.Fprintf(out, "Stopped %d background refresh process(es).\n", stopped)
		}
		return nil
	}

	if len(args) == 0 {
		return ErrOIDCMissingProviderArg
	}

	providerName := args[0]
	pidFile := getPIDFile(tokenStore, providerName)

	return stopProcess(out, pidFile, providerName)
}

// stopProcess stops a process by PID file.
func stopProcess(out io.Writer, pidFile, providerName string) error {
	pid, running := isProcessRunning(pidFile)
	if !running {
		// Clean up the stale file; a failed removal doesn't change that
		// there is no running process to stop, but it is joined in so it
		// isn't lost. The file already being gone is not a failure worth
		// reporting.
		notRunningErr := &MessageError{Msg: fmt.Sprintf("no running process for '%s'", providerName)}
		if rmErr := os.Remove(pidFile); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return errors.Join(notRunningErr, rmErr)
		}
		return notRunningErr
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return &WrappedError{Msg: "failed to find process", Err: err}
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return &WrappedError{Msg: "failed to stop process", Err: err}
	}

	// Wait a moment for graceful shutdown
	time.Sleep(100 * time.Millisecond)

	// The process is already stopped at this point, so a failure removing
	// its PID file is reported to the user rather than the command, which
	// has already succeeded at what it was asked to do.
	if rmErr := os.Remove(pidFile); rmErr != nil {
		_, _ = fmt.Fprintf(out, "Warning: failed to remove PID file %s: %v\n", pidFile, rmErr)
	}

	_, _ = fmt.Fprintf(out, "Stopped background refresh for '%s' (PID %d)\n", providerName, pid)
	return nil
}

// runAWSProviderLogin handles login for AWS-type providers.
func runAWSProviderLogin(cmd *cobra.Command, provider *OIDCProvider) error {
	// Get CLI flag overrides
	background, _ := cmd.Flags().GetBool("background")
	logFile, _ := cmd.Flags().GetString("log-file")
	autoRefresh, _ := cmd.Flags().GetInt("auto-refresh")
	execCmd, _ := cmd.Flags().GetString("exec")

	// Apply provider defaults
	if !background && provider.Background {
		background = provider.Background
	}
	if logFile == "" && provider.LogFile != "" {
		logFile = provider.LogFile
	}
	if autoRefresh == 0 && provider.AutoRefresh > 0 {
		autoRefresh = provider.AutoRefresh
	}
	if execCmd == "" && provider.Exec != "" {
		execCmd = provider.Exec
	}

	region := provider.AWSRegion
	profile := provider.AWSProfile
	if profile == "" {
		profile = "default"
	}
	credentialsFile := provider.AWSCredentialsFile
	if credentialsFile == "" {
		credentialsFile = "~/.aws/credentials"
	}
	output := provider.AWSOutput
	if output == "" {
		output = "aws-credentials"
	}
	crossDevice := provider.AWSCrossDevice
	// sessionStoreExplicit reflects whether this provider was actually
	// configured with a --session-store value at `providers add` time
	// (runOIDCProvidersAdd only persists AWSSessionStore when its own
	// --session-store flag was explicitly set): a real configuration choice
	// bypasses barrier auto-detection for a plain file at that exact path,
	// exactly like `xkey oidc aws --session-store` does directly; an unset
	// provider follows the barrier-or-fallback decision, rooted at the
	// shared xkey data directory.
	sessionStoreExplicit := provider.AWSSessionStore != ""
	sessionStore := provider.AWSSessionStore
	if sessionStore == "" {
		sessionStore = "~/.xkey/aws-session.json"
	}

	callback, err := resolveOIDCCallback(cmd)
	if err != nil {
		return err
	}

	// Call the AWS login implementation directly
	return runAWSLogin(
		cmd,
		cmd.OutOrStdout(),
		region,
		profile,
		crossDevice,
		false, // noBrowser
		output,
		credentialsFile,
		execCmd,
		autoRefresh,
		sessionStore,
		sessionStoreExplicit,
		background,
		logFile,
		provider.Name,
		callback,
	)
}

func init() {
	// Register oidc command with root
	RootCmd.AddCommand(OIDCCmd)

	// Add subcommands to oidc command
	OIDCCmd.AddCommand(oidcLoginCmd)
	OIDCCmd.AddCommand(oidcTokenCmd)
	OIDCCmd.AddCommand(oidcRefreshCmd)
	OIDCCmd.AddCommand(oidcLogoutCmd)
	OIDCCmd.AddCommand(oidcProvidersCmd)
	OIDCCmd.AddCommand(oidcStatusCmd)
	OIDCCmd.AddCommand(oidcStopCmd)

	// Add provider subcommands
	oidcProvidersCmd.AddCommand(oidcProvidersListCmd)
	oidcProvidersCmd.AddCommand(oidcProvidersAddCmd)
	oidcProvidersCmd.AddCommand(oidcProvidersRemoveCmd)

	// oidc login flags
	oidcLoginCmd.Flags().String("provider", "", "Use saved provider configuration by name")
	oidcLoginCmd.Flags().String("issuer", "", "OIDC provider issuer URL")
	oidcLoginCmd.Flags().String("client-id", "", "OAuth2 client ID")
	oidcLoginCmd.Flags().String("client-secret", "", "OAuth2 client secret (optional)")
	oidcLoginCmd.Flags().String("redirect-url", "", "Callback URL (default: http://localhost:<oidc.callback_port>/callback)")
	registerOIDCCallbackFlags(oidcLoginCmd.Flags())
	oidcLoginCmd.Flags().String("scopes", defaultOIDCScopes, "Scopes to request (comma-separated)")
	oidcLoginCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
	oidcLoginCmd.Flags().Bool("no-browser", false, "Don't open browser, print URL instead")
	oidcLoginCmd.Flags().String("exec", "", "Execute script after login (receives JSON payload via stdin)")
	oidcLoginCmd.Flags().Int("auto-refresh", 0, "Auto-refresh interval in seconds (0 to disable)")
	oidcLoginCmd.Flags().Bool("background", false, "Run auto-refresh in background (requires --auto-refresh)")
	oidcLoginCmd.Flags().String("log-file", "", "Log file for background refresh (default: auto-generated)")
	oidcLoginCmd.Flags().String("authorization-endpoint", "", "Manual authorization endpoint (skips discovery; requires --token-endpoint and --jwks-uri)")
	oidcLoginCmd.Flags().String("token-endpoint", "", "Manual token endpoint (skips discovery; requires --authorization-endpoint and --jwks-uri)")
	oidcLoginCmd.Flags().String("jwks-uri", "", "Manual JWKS URI (skips discovery; requires --authorization-endpoint and --token-endpoint)")
	oidcLoginCmd.Flags().String("userinfo-endpoint", "", "Manual userinfo endpoint (optional; only used with manual endpoints)")
	oidcLoginCmd.Flags().String("token-encoding", "", "Token request body encoding: form (default) or json")
	addBarrierPasswordFlags(oidcLoginCmd)

	// Hidden flags for background worker mode (used internally). Note
	// --token-endpoint above is dual-purpose: a user-supplied manual
	// endpoint and the resolved endpoint carried across the re-exec.
	oidcLoginCmd.Flags().Bool("background-worker", false, "Internal: run as background worker")
	oidcLoginCmd.Flags().String("provider-name", "", "Internal: provider name for PID file")
	_ = oidcLoginCmd.Flags().MarkHidden("background-worker")
	_ = oidcLoginCmd.Flags().MarkHidden("provider-name")

	// oidc token flags
	oidcTokenCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
	oidcTokenCmd.Flags().Bool("show-full", false, "Show full token values")
	addBarrierPasswordFlags(oidcTokenCmd)

	// oidc refresh flags
	oidcRefreshCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
	oidcRefreshCmd.Flags().String("provider", "", "Use saved provider configuration by name (required for manual-endpoint providers)")
	addBarrierPasswordFlags(oidcRefreshCmd)

	// oidc logout flags
	oidcLogoutCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
	oidcLogoutCmd.Flags().Bool("all", false, "Clear all stored tokens")
	addBarrierPasswordFlags(oidcLogoutCmd)

	// oidc status flags
	oidcStatusCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")

	// oidc stop flags
	oidcStopCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
	oidcStopCmd.Flags().Bool("all", false, "Stop all background refresh processes")

	// oidc providers list flags
	oidcProvidersListCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")

	// oidc providers add flags
	oidcProvidersAddCmd.Flags().String("name", "", "Provider name (required)")
	oidcProvidersAddCmd.Flags().String("type", "oidc", "Provider type: oidc (default) or aws")

	// Standard OIDC flags
	oidcProvidersAddCmd.Flags().String("issuer", "", "OIDC provider issuer URL (required for type=oidc)")
	oidcProvidersAddCmd.Flags().String("client-id", "", "OAuth2 client ID (required for type=oidc)")
	oidcProvidersAddCmd.Flags().String("client-secret", "", "OAuth2 client secret (optional)")
	oidcProvidersAddCmd.Flags().String("redirect-url", "", "Callback URL (default: http://localhost:<oidc.callback_port>/callback)")
	registerOIDCCallbackFlags(oidcProvidersAddCmd.Flags())
	oidcProvidersAddCmd.Flags().String("scopes", "", "Scopes to request (comma-separated)")
	oidcProvidersAddCmd.Flags().String("authorization-endpoint", "", "Manual authorization endpoint (skips discovery; requires --token-endpoint and --jwks-uri)")
	oidcProvidersAddCmd.Flags().String("token-endpoint", "", "Manual token endpoint (skips discovery; requires --authorization-endpoint and --jwks-uri)")
	oidcProvidersAddCmd.Flags().String("jwks-uri", "", "Manual JWKS URI (skips discovery; requires --authorization-endpoint and --token-endpoint)")
	oidcProvidersAddCmd.Flags().String("userinfo-endpoint", "", "Manual userinfo endpoint (optional; only used with manual endpoints)")
	oidcProvidersAddCmd.Flags().String("token-encoding", "", "Token request body encoding: form (default) or json")

	// AWS-specific flags
	oidcProvidersAddCmd.Flags().StringP("region", "r", "", "AWS region (required for type=aws)")
	oidcProvidersAddCmd.Flags().String("profile", "default", "AWS profile name")
	oidcProvidersAddCmd.Flags().String("credentials-file", "~/.aws/credentials", "AWS credentials file path")
	oidcProvidersAddCmd.Flags().StringP("output", "o", "aws-credentials", "AWS output mode: aws-credentials, json, exec, none")
	oidcProvidersAddCmd.Flags().Bool("cross-device", false, "Enable AWS cross-device authentication")
	oidcProvidersAddCmd.Flags().String("session-store", "~/.xkey/aws-session.json", "AWS session store path")

	// Common flags
	oidcProvidersAddCmd.Flags().String("exec", "", "Script to execute after login")
	oidcProvidersAddCmd.Flags().Int("auto-refresh", 0, "Auto-refresh interval in seconds (0 to disable)")
	oidcProvidersAddCmd.Flags().Bool("background", false, "Run auto-refresh in background by default")
	oidcProvidersAddCmd.Flags().String("log-file", "", "Log file for background refresh")
	oidcProvidersAddCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")

	// oidc providers remove flags
	oidcProvidersRemoveCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
}
