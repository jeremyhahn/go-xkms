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
	"net"
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
)

// Default OIDC configuration values.
const (
	defaultOIDCRedirectURL     = "http://localhost:8085/callback"
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
)

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

// OIDCStoredToken represents a token stored in the token store.
type OIDCStoredToken struct {
	Provider     string    `json:"provider"`
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes"`
}

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

// OIDCTokenStore represents the token storage file structure.
type OIDCTokenStore struct {
	Tokens []OIDCStoredToken `json:"tokens"`
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

	// If --provider is specified, load configuration from saved provider
	if providerName != "" {
		configPath := getConfigPath(tokenStore)
		config, err := loadOIDCConfig(configPath)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrOIDCConfigLoadFailed, err)
		}

		var provider *OIDCProvider
		for i := range config.Providers {
			if config.Providers[i].Name == providerName {
				provider = &config.Providers[i]
				break
			}
		}
		if provider == nil {
			return fmt.Errorf("%w: %s", ErrOIDCProviderNotFound, providerName)
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

	// Discover provider configuration
	discovery, err := discoverOIDCProvider(issuer)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCDiscoveryFailed, err)
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return fmt.Errorf("failed to generate code verifier: %v", err)
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Generate state parameter
	state, err := generateState()
	if err != nil {
		return fmt.Errorf("failed to generate state: %v", err)
	}

	// Build authorization URL
	authURL := buildAuthorizationURL(discovery.AuthorizationEndpoint, clientID, redirectURL, scopes, state, codeChallenge)

	// Parse redirect URL to get port
	parsedRedirect, err := url.Parse(redirectURL)
	if err != nil {
		return fmt.Errorf("invalid redirect URL: %v", err)
	}
	port := parsedRedirect.Port()
	if port == "" {
		port = "8085"
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
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		handleOIDCCallback(w, r, codeChan, errChan, receivedState)
	})

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to start callback server: %v", err)
	}

	server := &http.Server{Handler: mux}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			errChan <- serveErr
		}
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	// Open browser or print URL
	if noBrowser {
		fmt.Println("Open the following URL in your browser:")
		fmt.Println()
		fmt.Println(authURL)
		fmt.Println()
		fmt.Println("Waiting for authorization callback...")
	} else {
		fmt.Println("Opening browser for authentication...")
		if err := browser.OpenURL(authURL); err != nil {
			fmt.Printf("Failed to open browser: %v\n", err)
			fmt.Println("Please open the following URL manually:")
			fmt.Println()
			fmt.Println(authURL)
		}
		fmt.Println("Waiting for authorization callback...")
	}

	// Wait for callback
	var code string
	select {
	case code = <-codeChan:
		// Success
	case err := <-errChan:
		return fmt.Errorf("%w: %v", ErrOIDCCallbackFailed, err)
	case <-ctx.Done():
		return ErrOIDCCallbackTimeout
	}

	// Verify state
	if receivedState.Load() != state {
		return ErrOIDCStateMismatch
	}

	// Exchange code for tokens
	tokens, err := exchangeCodeForTokens(discovery.TokenEndpoint, clientID, clientSecret, code, redirectURL, codeVerifier)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCTokenExchangeFailed, err)
	}

	// Parse and validate ID token
	claims, err := parseIDToken(tokens.IDToken)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCTokenValidationFailed, err)
	}

	// Store tokens
	storedToken := OIDCStoredToken{
		Provider:     issuer,
		Issuer:       issuer,
		ClientID:     clientID,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
		Scopes:       scopes,
	}

	if err := storeToken(tokenStore, storedToken); err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCTokenStoreFailed, err)
	}

	fmt.Println()
	fmt.Println("Login successful!")
	fmt.Println()
	fmt.Printf("  Provider: %s\n", issuer)
	if claims.Subject != "" {
		fmt.Printf("  Subject:  %s\n", claims.Subject)
	}
	if claims.Email != "" {
		fmt.Printf("  Email:    %s\n", claims.Email)
	}
	if claims.Name != "" {
		fmt.Printf("  Name:     %s\n", claims.Name)
	}
	fmt.Printf("  Expires:  %s\n", storedToken.ExpiresAt.Format(time.RFC3339))

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

		if err := executeOIDCScript(execCmd, payload); err != nil {
			return fmt.Errorf("%w: %v", ErrOIDCExecFailed, err)
		}
	}

	// Start auto-refresh loop if specified
	if autoRefresh > 0 {
		if tokens.RefreshToken == "" {
			fmt.Println("\nWarning: No refresh token received. Auto-refresh will not work.")
			fmt.Println("Tip: Request the 'offline_access' scope to get a refresh token.")
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
			return startBackgroundRefresh(providerName, discovery.TokenEndpoint, clientID, tokenStore, execCmd, logFile, autoRefresh)
		}

		fmt.Printf("\nAuto-refresh enabled: refreshing every %d seconds\n", autoRefresh)
		fmt.Println("Press Ctrl+C to stop...")
		fmt.Println()

		return runAutoRefresh(discovery.TokenEndpoint, clientID, tokenStore, execCmd, providerName, time.Duration(autoRefresh)*time.Second, nil)
	}

	return nil
}

// runOIDCToken displays current token information.
func runOIDCToken(cmd *cobra.Command, args []string) error {
	tokenStore, _ := cmd.Flags().GetString("token-store")
	showFull, _ := cmd.Flags().GetBool("show-full")

	token, err := loadToken(tokenStore)
	if err != nil {
		if errors.Is(err, ErrOIDCNoTokensFound) {
			fmt.Println("No OIDC tokens found. Run 'xkey oidc login' to authenticate.")
			return nil
		}
		return fmt.Errorf("%w: %v", ErrOIDCTokenLoadFailed, err)
	}

	// Parse ID token for claims
	claims, err := parseIDToken(token.IDToken)
	if err != nil {
		// If we can't parse the ID token, still show what we have
		claims = &OIDCIDTokenClaims{}
	}

	fmt.Println("OIDC Token Information")
	fmt.Println("======================")
	fmt.Println()
	fmt.Printf("Provider:      %s\n", token.Issuer)
	if claims.Subject != "" {
		fmt.Printf("Subject:       %s\n", claims.Subject)
	}
	if claims.Email != "" {
		fmt.Printf("Email:         %s\n", claims.Email)
	}
	if claims.Name != "" {
		fmt.Printf("Name:          %s\n", claims.Name)
	}

	// Format expiration
	now := time.Now()
	if token.ExpiresAt.After(now) {
		remaining := token.ExpiresAt.Sub(now)
		fmt.Printf("Expires:       %s (in %s)\n", token.ExpiresAt.Format("2006-01-02 15:04:05 UTC"), formatDuration(remaining))
	} else {
		fmt.Printf("Expires:       %s (EXPIRED)\n", token.ExpiresAt.Format("2006-01-02 15:04:05 UTC"))
	}

	if len(token.Scopes) > 0 {
		fmt.Printf("Scopes:        %s\n", strings.Join(token.Scopes, " "))
	}

	fmt.Println()
	if showFull {
		fmt.Printf("Access Token:  %s\n", token.AccessToken)
		if token.IDToken != "" {
			fmt.Printf("ID Token:      %s\n", token.IDToken)
		}
		if token.RefreshToken != "" {
			fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
		}
	} else {
		fmt.Printf("Access Token:  %s... (truncated)\n", truncateToken(token.AccessToken, 40))
		if token.IDToken != "" {
			fmt.Printf("ID Token:      %s... (truncated)\n", truncateToken(token.IDToken, 40))
		}
	}

	return nil
}

// runOIDCRefresh refreshes the access token.
func runOIDCRefresh(cmd *cobra.Command, args []string) error {
	tokenStore, _ := cmd.Flags().GetString("token-store")

	token, err := loadToken(tokenStore)
	if err != nil {
		if errors.Is(err, ErrOIDCNoTokensFound) {
			fmt.Println("No OIDC tokens found. Run 'xkey oidc login' to authenticate.")
			return nil
		}
		return fmt.Errorf("%w: %v", ErrOIDCTokenLoadFailed, err)
	}

	if token.RefreshToken == "" {
		return ErrOIDCInvalidRefreshToken
	}

	// Discover provider configuration
	discovery, err := discoverOIDCProvider(token.Issuer)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCDiscoveryFailed, err)
	}

	// Refresh tokens
	newTokens, err := refreshTokens(discovery.TokenEndpoint, token.ClientID, token.RefreshToken)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCTokenRefreshFailed, err)
	}

	// Update stored token
	token.AccessToken = newTokens.AccessToken
	if newTokens.RefreshToken != "" {
		token.RefreshToken = newTokens.RefreshToken
	}
	if newTokens.IDToken != "" {
		token.IDToken = newTokens.IDToken
	}
	token.ExpiresAt = time.Now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)

	if err := storeToken(tokenStore, *token); err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCTokenStoreFailed, err)
	}

	fmt.Println("Token refreshed successfully!")
	fmt.Printf("  New expiration: %s\n", token.ExpiresAt.Format(time.RFC3339))

	return nil
}

// runOIDCLogout clears stored tokens.
func runOIDCLogout(cmd *cobra.Command, args []string) error {
	tokenStore, _ := cmd.Flags().GetString("token-store")
	all, _ := cmd.Flags().GetBool("all")

	storePath := expandPath(tokenStore)

	if all {
		if err := os.Remove(storePath); err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No tokens to clear.")
				return nil
			}
			return fmt.Errorf("failed to clear tokens: %v", err)
		}
		fmt.Println("All tokens cleared.")
		return nil
	}

	// Clear current token
	store := OIDCTokenStore{Tokens: []OIDCStoredToken{}}
	if err := saveTokenStore(storePath, store); err != nil {
		return fmt.Errorf("failed to clear tokens: %v", err)
	}

	fmt.Println("Tokens cleared.")
	return nil
}

// runOIDCProvidersList lists configured providers.
func runOIDCProvidersList(cmd *cobra.Command, args []string) error {
	tokenStore, _ := cmd.Flags().GetString("token-store")
	configPath := getConfigPath(tokenStore)

	config, err := loadOIDCConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No OIDC providers configured.")
			return nil
		}
		return fmt.Errorf("%w: %v", ErrOIDCConfigLoadFailed, err)
	}

	if len(config.Providers) == 0 {
		fmt.Println("No OIDC providers configured.")
		return nil
	}

	fmt.Printf("OIDC Providers (%d):\n\n", len(config.Providers))

	for _, provider := range config.Providers {
		fmt.Printf("  Name:         %s\n", provider.Name)

		// Display type
		pType := provider.Type
		if pType == "" {
			pType = OIDCProviderTypeStandard
		}
		fmt.Printf("  Type:         %s\n", pType)

		if pType == OIDCProviderTypeAWS {
			// AWS-specific display
			fmt.Printf("  Region:       %s\n", provider.AWSRegion)
			if provider.AWSProfile != "" {
				fmt.Printf("  Profile:      %s\n", provider.AWSProfile)
			}
			if provider.AWSCredentialsFile != "" {
				fmt.Printf("  Credentials:  %s\n", provider.AWSCredentialsFile)
			}
			if provider.AWSOutput != "" {
				fmt.Printf("  Output:       %s\n", provider.AWSOutput)
			}
			if provider.AWSCrossDevice {
				fmt.Printf("  Cross-Device: yes\n")
			}
			if provider.AWSSessionStore != "" {
				fmt.Printf("  Session Store: %s\n", provider.AWSSessionStore)
			}
		} else {
			// Standard OIDC display
			fmt.Printf("  Issuer:       %s\n", provider.Issuer)
			fmt.Printf("  Client ID:    %s\n", provider.ClientID)
			if provider.ClientSecret != "" {
				fmt.Printf("  Client Secret: ***\n")
			}
			if provider.RedirectURL != "" {
				fmt.Printf("  Redirect URL: %s\n", provider.RedirectURL)
			}
			if len(provider.Scopes) > 0 {
				fmt.Printf("  Scopes:       %s\n", strings.Join(provider.Scopes, ", "))
			}
		}

		// Common fields
		if provider.Exec != "" {
			fmt.Printf("  Exec:         %s\n", provider.Exec)
		}
		if provider.AutoRefresh > 0 {
			fmt.Printf("  Auto-Refresh: %d seconds\n", provider.AutoRefresh)
		}
		if provider.Background {
			fmt.Printf("  Background:   yes\n")
		}
		if provider.LogFile != "" {
			fmt.Printf("  Log File:     %s\n", provider.LogFile)
		}
		fmt.Println()
	}

	return nil
}

// runOIDCProvidersAdd adds a new provider.
func runOIDCProvidersAdd(cmd *cobra.Command, args []string) error {
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
				return fmt.Errorf("%w (hint: use --type aws for AWS providers)", ErrOIDCMissingIssuer)
			}
			return ErrOIDCMissingIssuer
		}
		if clientID == "" {
			return ErrOIDCMissingClientID
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
		return fmt.Errorf("%w: %v", ErrOIDCConfigLoadFailed, err)
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
	if awsSessionStore != "" {
		awsSessionStore = expandPath(awsSessionStore)
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
		return fmt.Errorf("%w: %v", ErrOIDCConfigSaveFailed, err)
	}

	if pType == OIDCProviderTypeAWS {
		fmt.Printf("Added AWS OIDC provider: %s (region: %s)\n", name, awsRegion)
	} else {
		fmt.Printf("Added OIDC provider: %s\n", name)
	}
	return nil
}

// runOIDCProvidersRemove removes a provider.
func runOIDCProvidersRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	tokenStore, _ := cmd.Flags().GetString("token-store")

	configPath := getConfigPath(tokenStore)

	config, err := loadOIDCConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrOIDCProviderNotFound
		}
		return fmt.Errorf("%w: %v", ErrOIDCConfigLoadFailed, err)
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
		if err := stopProcess(pidFile, name); err != nil {
			// Log warning but don't fail the removal
			fmt.Fprintf(os.Stderr, "Warning: failed to stop background refresh for '%s': %v\n", name, err)
		} else {
			fmt.Printf("Stopped background refresh for '%s'\n", name)
		}
	}

	config.Providers = newProviders

	if err := saveOIDCConfig(configPath, *config); err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCConfigSaveFailed, err)
	}

	fmt.Printf("Removed OIDC provider: %s\n", name)
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
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var doc OIDCDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
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
		errDesc := query.Get("error_description")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmt.Sprintf("<html><body><h1>Authentication Failed</h1><p>%s: %s</p></body></html>", errParam, errDesc)))
		errChan <- fmt.Errorf("%s: %s", errParam, errDesc)
		return
	}

	code := query.Get("code")
	if code == "" {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>Authentication Failed</h1><p>No authorization code received</p></body></html>"))
		errChan <- errors.New("no authorization code received")
		return
	}

	state.Store(query.Get("state"))

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html><body><h1>Authentication Successful</h1><p>You may close this window.</p></body></html>"))

	codeChan <- code
}

// exchangeCodeForTokens exchanges an authorization code for tokens.
func exchangeCodeForTokens(endpoint, clientID, clientSecret, code, redirectURL, codeVerifier string) (*OIDCTokenResponse, error) {
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

	ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCProviderTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tokens OIDCTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

// refreshTokens refreshes tokens using a refresh token.
func refreshTokens(endpoint, clientID, refreshToken string) (*OIDCTokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCProviderTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
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

// storeToken stores a token in the token store.
func storeToken(storePath string, token OIDCStoredToken) error {
	path := expandPath(storePath)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	store := OIDCTokenStore{Tokens: []OIDCStoredToken{token}}
	return saveTokenStore(path, store)
}

// loadToken loads the current token from the token store.
func loadToken(storePath string) (*OIDCStoredToken, error) {
	path := expandPath(storePath)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrOIDCNoTokensFound
		}
		return nil, err
	}

	var store OIDCTokenStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	if len(store.Tokens) == 0 {
		return nil, ErrOIDCNoTokensFound
	}

	return &store.Tokens[0], nil
}

// saveTokenStore saves the token store to disk.
func saveTokenStore(path string, store OIDCTokenStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
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

	return nil, fmt.Errorf("provider not found: %s", providerName)
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

// truncateToken truncates a token for display.
func truncateToken(token string, maxLen int) string {
	if len(token) <= maxLen {
		return token
	}
	return token[:maxLen]
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

// runAutoRefresh runs a loop that periodically refreshes the token.
// If logWriter is nil, output goes to stdout.
func runAutoRefresh(tokenEndpoint, clientID, tokenStorePath, execCmd, providerName string, interval time.Duration, logWriter io.Writer) error {
	if logWriter == nil {
		logWriter = os.Stdout
	}
	log := func(format string, args ...interface{}) {
		fmt.Fprintf(logWriter, format, args...)
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

	for {
		select {
		case <-sigChan:
			log("\n[%s] Auto-refresh stopped.\n", time.Now().Format("2006-01-02 15:04:05"))
			return nil

		case <-ticker.C:
			refreshCount++
			log("[%s] Refreshing token (#%d)...\n", time.Now().Format("2006-01-02 15:04:05"), refreshCount)

			// Load current token
			token, err := loadToken(tokenStorePath)
			if err != nil {
				log("  Error loading token: %v\n", err)
				updateStatus("error", fmt.Sprintf("failed to load token: %v", err))
				continue
			}

			if token.RefreshToken == "" {
				log("  Error: No refresh token available. Stopping auto-refresh.\n")
				updateStatus("error", "no refresh token available")
				return ErrOIDCInvalidRefreshToken
			}

			// Refresh the token
			newTokens, err := refreshTokens(tokenEndpoint, clientID, token.RefreshToken)
			if err != nil {
				log("  Error refreshing: %v\n", err)
				updateStatus("error", fmt.Sprintf("refresh failed: %v", err))
				continue
			}

			// Update stored token
			token.AccessToken = newTokens.AccessToken
			if newTokens.RefreshToken != "" {
				token.RefreshToken = newTokens.RefreshToken
			}
			if newTokens.IDToken != "" {
				token.IDToken = newTokens.IDToken
			}
			token.ExpiresAt = time.Now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)

			if err := storeToken(tokenStorePath, *token); err != nil {
				log("  Error storing token: %v\n", err)
				updateStatus("error", fmt.Sprintf("failed to store token: %v", err))
				continue
			}

			log("  Token refreshed. New expiration: %s\n", token.ExpiresAt.Format(time.RFC3339))
			updateStatus("success", "")

			// Execute script if specified
			if execCmd != "" {
				claims, _ := parseIDToken(token.IDToken)
				if claims == nil {
					claims = &OIDCIDTokenClaims{}
				}

				payload := OIDCExecPayload{
					Provider:     token.Issuer,
					Issuer:       token.Issuer,
					ClientID:     token.ClientID,
					AccessToken:  token.AccessToken,
					RefreshToken: token.RefreshToken,
					IDToken:      token.IDToken,
					ExpiresAt:    token.ExpiresAt.Format(time.RFC3339),
					ExpiresIn:    newTokens.ExpiresIn,
					Scopes:       token.Scopes,
					Subject:      claims.Subject,
					Email:        claims.Email,
					Name:         claims.Name,
				}

				if err := executeOIDCScript(execCmd, payload); err != nil {
					log("  Script error: %v\n", err)
				}
			}
		}
	}
}

// executeOIDCScript executes a custom script with the OIDC response.
// The payload is passed as JSON via stdin and also as environment variables.
func executeOIDCScript(cmdStr string, payload OIDCExecPayload) error {
	fmt.Println()
	fmt.Printf("Executing: %s\n", cmdStr)

	// Parse the command - support shell execution
	cmd := exec.Command("sh", "-c", cmdStr)

	// Pass payload as JSON via stdin
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
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
		return fmt.Errorf("script execution failed: %w", err)
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
func startBackgroundRefresh(providerName, tokenEndpoint, clientID, tokenStorePath, execCmd, logFile string, autoRefresh int) error {
	// Ensure log directory exists
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Ensure PID directory exists
	pidDir := getPIDDir(tokenStorePath)
	if err := os.MkdirAll(pidDir, 0700); err != nil {
		return fmt.Errorf("failed to create PID directory: %w", err)
	}

	// Check if already running
	pidFile := getPIDFile(tokenStorePath, providerName)
	if pid, running := isProcessRunning(pidFile); running {
		return fmt.Errorf("background refresh for '%s' is already running (PID %d)", providerName, pid)
	}

	// Open log file
	logFileHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Build command to run ourselves with special --background-worker flag
	executable, err := os.Executable()
	if err != nil {
		logFileHandle.Close()
		return fmt.Errorf("failed to get executable path: %w", err)
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

	cmd := exec.Command(executable, args...)
	cmd.Stdout = logFileHandle
	cmd.Stderr = logFileHandle

	// Start the process
	if err := cmd.Start(); err != nil {
		logFileHandle.Close()
		return fmt.Errorf("failed to start background process: %w", err)
	}

	// Write PID file
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		cmd.Process.Kill()
		logFileHandle.Close()
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Don't wait for the process - let it run in background
	go func() {
		cmd.Wait()
		logFileHandle.Close()
		os.Remove(pidFile) // Clean up PID file when process exits
	}()

	fmt.Printf("Background refresh started for '%s'\n", providerName)
	fmt.Printf("  PID:      %d\n", cmd.Process.Pid)
	fmt.Printf("  Log file: %s\n", logFile)
	fmt.Printf("\nUse 'xkey oidc status' to see running refreshes\n")
	fmt.Printf("Use 'xkey oidc stop %s' to stop\n", providerName)

	return nil
}

// runBackgroundWorker runs the actual auto-refresh loop (called by background process).
func runBackgroundWorker(cmd *cobra.Command, args []string) error {
	tokenEndpoint, _ := cmd.Flags().GetString("token-endpoint")
	clientID, _ := cmd.Flags().GetString("client-id")
	tokenStore, _ := cmd.Flags().GetString("token-store")
	execCmd, _ := cmd.Flags().GetString("exec")
	autoRefresh, _ := cmd.Flags().GetInt("auto-refresh")
	logFile, _ := cmd.Flags().GetString("log-file")
	providerName, _ := cmd.Flags().GetString("provider-name")

	// Open log file for writing
	var logWriter io.Writer = os.Stdout
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		defer f.Close()
		logWriter = f
	}

	fmt.Fprintf(logWriter, "[%s] Background refresh started for '%s'\n", time.Now().Format("2006-01-02 15:04:05"), providerName)
	fmt.Fprintf(logWriter, "  Token endpoint: %s\n", tokenEndpoint)
	fmt.Fprintf(logWriter, "  Refresh interval: %d seconds\n", autoRefresh)
	if execCmd != "" {
		fmt.Fprintf(logWriter, "  Exec command: %s\n", execCmd)
	}
	fmt.Fprintf(logWriter, "\n")

	return runAutoRefresh(tokenEndpoint, clientID, tokenStore, execCmd, providerName, time.Duration(autoRefresh)*time.Second, logWriter)
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
	tokenStore, _ := cmd.Flags().GetString("token-store")
	pidDir := getPIDDir(tokenStore)

	entries, err := os.ReadDir(pidDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No background refresh processes running.")
			return nil
		}
		return fmt.Errorf("failed to read PID directory: %w", err)
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
			// Clean up stale PID file
			os.Remove(pidFile)
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
		fmt.Println("No background refresh processes running.")
		return nil
	}

	fmt.Printf("Background Refresh Processes (%d):\n\n", len(running))
	for _, proc := range running {
		fmt.Printf("  Provider:     %s\n", proc.Provider)
		fmt.Printf("  PID:          %d\n", proc.PID)
		if !proc.StartedAt.IsZero() {
			fmt.Printf("  Started:      %s (%s ago)\n", proc.StartedAt.Format("2006-01-02 15:04:05"), formatDuration(time.Since(proc.StartedAt)))
		}
		// Display refresh status if available
		if proc.Status != nil {
			statusIcon := "✓"
			if proc.Status.LastStatus == "error" {
				statusIcon = "✗"
			}
			if !proc.Status.LastRefresh.IsZero() {
				fmt.Printf("  Last Refresh: %s (%s ago) %s\n",
					proc.Status.LastRefresh.Format("2006-01-02 15:04:05"),
					formatDuration(time.Since(proc.Status.LastRefresh)),
					statusIcon)
			}
			if !proc.Status.NextRefresh.IsZero() && proc.Status.NextRefresh.After(time.Now()) {
				fmt.Printf("  Next Refresh: in %s\n", formatDuration(time.Until(proc.Status.NextRefresh)))
			}
			fmt.Printf("  Refreshes:    %d", proc.Status.RefreshCount)
			if proc.Status.LastStatus == "success" {
				fmt.Printf(" successful\n")
			} else if proc.Status.LastError != "" {
				fmt.Printf(" (last error: %s)\n", proc.Status.LastError)
			} else {
				fmt.Println()
			}
		}
		fmt.Printf("  Log file:     %s\n", proc.LogFile)
		fmt.Println()
	}

	return nil
}

// runOIDCStop stops a background refresh process.
func runOIDCStop(cmd *cobra.Command, args []string) error {
	tokenStore, _ := cmd.Flags().GetString("token-store")
	stopAll, _ := cmd.Flags().GetBool("all")

	pidDir := getPIDDir(tokenStore)

	if stopAll {
		entries, err := os.ReadDir(pidDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No background refresh processes running.")
				return nil
			}
			return fmt.Errorf("failed to read PID directory: %w", err)
		}

		stopped := 0
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".pid") {
				continue
			}

			providerName := strings.TrimSuffix(entry.Name(), ".pid")
			pidFile := filepath.Join(pidDir, entry.Name())

			if err := stopProcess(pidFile, providerName); err != nil {
				fmt.Fprintf(os.Stderr, "  %s: %v\n", providerName, err)
			} else {
				stopped++
			}
		}

		if stopped == 0 {
			fmt.Println("No background refresh processes were running.")
		} else {
			fmt.Printf("Stopped %d background refresh process(es).\n", stopped)
		}
		return nil
	}

	if len(args) == 0 {
		return errors.New("specify provider name or use --all")
	}

	providerName := args[0]
	pidFile := getPIDFile(tokenStore, providerName)

	return stopProcess(pidFile, providerName)
}

// stopProcess stops a process by PID file.
func stopProcess(pidFile, providerName string) error {
	pid, running := isProcessRunning(pidFile)
	if !running {
		os.Remove(pidFile) // Clean up stale file
		return fmt.Errorf("no running process for '%s'", providerName)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop process: %w", err)
	}

	// Wait a moment for graceful shutdown
	time.Sleep(100 * time.Millisecond)

	// Remove PID file
	os.Remove(pidFile)

	fmt.Printf("Stopped background refresh for '%s' (PID %d)\n", providerName, pid)
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
	sessionStore := provider.AWSSessionStore
	if sessionStore == "" {
		sessionStore = "~/.xkey/aws-session.json"
	}

	// Call the AWS login implementation directly
	return runAWSLogin(
		region,
		profile,
		crossDevice,
		false, // noBrowser
		output,
		credentialsFile,
		execCmd,
		autoRefresh,
		sessionStore,
		background,
		logFile,
		provider.Name,
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
	oidcLoginCmd.Flags().String("redirect-url", defaultOIDCRedirectURL, "Callback URL")
	oidcLoginCmd.Flags().String("scopes", defaultOIDCScopes, "Scopes to request (comma-separated)")
	oidcLoginCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
	oidcLoginCmd.Flags().Bool("no-browser", false, "Don't open browser, print URL instead")
	oidcLoginCmd.Flags().String("exec", "", "Execute script after login (receives JSON payload via stdin)")
	oidcLoginCmd.Flags().Int("auto-refresh", 0, "Auto-refresh interval in seconds (0 to disable)")
	oidcLoginCmd.Flags().Bool("background", false, "Run auto-refresh in background (requires --auto-refresh)")
	oidcLoginCmd.Flags().String("log-file", "", "Log file for background refresh (default: auto-generated)")

	// Hidden flags for background worker mode (used internally)
	oidcLoginCmd.Flags().Bool("background-worker", false, "Internal: run as background worker")
	oidcLoginCmd.Flags().String("token-endpoint", "", "Internal: token endpoint URL")
	oidcLoginCmd.Flags().String("provider-name", "", "Internal: provider name for PID file")
	_ = oidcLoginCmd.Flags().MarkHidden("background-worker")
	_ = oidcLoginCmd.Flags().MarkHidden("token-endpoint")
	_ = oidcLoginCmd.Flags().MarkHidden("provider-name")

	// oidc token flags
	oidcTokenCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
	oidcTokenCmd.Flags().Bool("show-full", false, "Show full token values")

	// oidc refresh flags
	oidcRefreshCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")

	// oidc logout flags
	oidcLogoutCmd.Flags().String("token-store", defaultOIDCTokenStorePath, "Path to token store")
	oidcLogoutCmd.Flags().Bool("all", false, "Clear all stored tokens")

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
	oidcProvidersAddCmd.Flags().String("redirect-url", defaultOIDCRedirectURL, "Callback URL")
	oidcProvidersAddCmd.Flags().String("scopes", "", "Scopes to request (comma-separated)")

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
