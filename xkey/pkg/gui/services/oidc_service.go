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

package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/pkg/browser"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// Default OIDC service configuration values.
const (
	oidcCallbackPort    = "8085"
	oidcCallbackPath    = "/callback"
	oidcCallbackTimeout = 5 * time.Minute
	oidcProvidersFile   = "oidc-providers.json"
	oidcTokensFile      = "tokens.json"
	oidcTokenEncKey     = "xkey-oidc-token-store-encryption"
	oidcScriptsDir      = "oidc-scripts"

	// oidcProvidersBackendKey is the storage key used for provider
	// configuration when persisting through a storage.Backend.
	oidcProvidersBackendKey = "providers.json"
)

// OIDCProviderType distinguishes standard OIDC from AWS.
type OIDCProviderType string

const (
	// OIDCProviderTypeStandard is a standard OIDC provider with discovery.
	OIDCProviderTypeStandard OIDCProviderType = "oidc"

	// OIDCProviderTypeAWS is an AWS signin provider.
	OIDCProviderTypeAWS OIDCProviderType = "aws"
)

// OIDCProviderEntry is the GUI-facing provider configuration.
type OIDCProviderEntry struct {
	Name         string           `json:"name"`
	Type         OIDCProviderType `json:"type"`
	Template     string           `json:"template,omitempty"`
	Issuer       string           `json:"issuer"`
	ClientID     string           `json:"client_id"`
	ClientSecret string           `json:"client_secret,omitempty"`
	RedirectURL  string           `json:"redirect_url"`
	Scopes       []string         `json:"scopes"`
	Exec         string           `json:"exec,omitempty"`
	AutoRefresh  int              `json:"auto_refresh"`
	Background   bool             `json:"background"`
	LogFile      string           `json:"log_file,omitempty"`
	DPoP         bool             `json:"dpop,omitempty"`
	// AWS-specific fields.
	AWSRegion          string `json:"aws_region,omitempty"`
	AWSProfile         string `json:"aws_profile,omitempty"`
	AWSCredentialsFile string `json:"aws_credentials_file,omitempty"`
	AWSOutput          string `json:"aws_output,omitempty"`
	AWSCrossDevice     bool   `json:"aws_cross_device,omitempty"`
	AWSSessionStore    string `json:"aws_session_store,omitempty"`
}

// OIDCProviderTemplateInfo is the GUI-facing template summary.
type OIDCProviderTemplateInfo struct {
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	Issuer         string           `json:"issuer"`
	Scopes         []string         `json:"scopes"`
	RequiresRegion bool             `json:"requires_region"`
	RequiresIssuer bool             `json:"requires_issuer"`
	Type           OIDCProviderType `json:"type"`
	DPoP           bool             `json:"dpop"`
}

// OIDCTokenInfo is the GUI-facing token information.
type OIDCTokenInfo struct {
	Provider   string   `json:"provider"`
	Issuer     string   `json:"issuer"`
	Subject    string   `json:"subject"`
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	ExpiresAt  string   `json:"expires_at"`
	ExpiresIn  int64    `json:"expires_in"`
	Scopes     []string `json:"scopes"`
	IsExpired  bool     `json:"is_expired"`
	HasRefresh bool     `json:"has_refresh"`
	HasDPoP    bool     `json:"has_dpop"`
}

// OIDCLoginResult contains the result of a login operation.
type OIDCLoginResult struct {
	Success bool           `json:"success"`
	Token   *OIDCTokenInfo `json:"token,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// OIDCRefreshStatus represents background refresh status.
type OIDCRefreshStatus struct {
	Provider     string `json:"provider"`
	Running      bool   `json:"running"`
	LastRefresh  string `json:"last_refresh,omitempty"`
	NextRefresh  string `json:"next_refresh,omitempty"`
	RefreshCount int    `json:"refresh_count"`
	LastStatus   string `json:"last_status,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}

// OIDCExecResult contains the result of script execution.
type OIDCExecResult struct {
	Success  bool   `json:"success"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Error    string `json:"error,omitempty"`
}

// OIDCSavedScript describes a script saved to the data directory.
type OIDCSavedScript struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
}

// oidcExecPayload is the JSON structure passed to exec scripts.
type oidcExecPayload struct {
	Provider     string   `json:"provider"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	IDToken      string   `json:"id_token,omitempty"`
	ExpiresAt    string   `json:"expires_at"`
	ExpiresIn    int      `json:"expires_in"`
	Scopes       []string `json:"scopes"`
	Subject      string   `json:"subject,omitempty"`
	Email        string   `json:"email,omitempty"`
	Name         string   `json:"name,omitempty"`
}

// oidcProvidersConfig is the on-disk provider configuration file structure.
type oidcProvidersConfig struct {
	Providers []OIDCProviderEntry `json:"providers"`
}

// refreshProcess tracks a background refresh goroutine.
type refreshProcess struct {
	provider string
	cancel   context.CancelFunc
	status   atomic.Pointer[OIDCRefreshStatus]
}

// BrowserOpenFunc allows tests to replace the browser open call.
type BrowserOpenFunc func(url string) error

// OIDCService manages OIDC authentication for the xKey GUI. It is bound
// to the Wails runtime so every exported method is callable from the frontend.
type OIDCService struct {
	ctx           context.Context
	log           *slog.Logger
	dataDir       string
	backend       storage.Backend
	backendPrefix string
	tokenStore    oidc.TokenStore
	providers     map[string]*OIDCProviderEntry
	providersMu   sync.RWMutex
	refreshProcs  map[string]*refreshProcess
	refreshMu     sync.Mutex
	browserOpen   BrowserOpenFunc
}

// NewOIDCService creates a new OIDCService.
func NewOIDCService(log *slog.Logger) *OIDCService {
	if log == nil {
		log = slog.Default()
	}
	return &OIDCService{
		log:          log.With("service", "oidc"),
		providers:    make(map[string]*OIDCProviderEntry),
		refreshProcs: make(map[string]*refreshProcess),
		browserOpen:  browser.OpenURL,
	}
}

// SetDataDir initializes the token store and loads providers from the
// specified data directory. This is the plain filesystem fallback used
// when no barrier backend is available.
func (s *OIDCService) SetDataDir(dir string) {
	s.dataDir = dir

	tokensPath := filepath.Join(dir, oidcTokensFile)
	store, err := oidc.NewFileTokenStore(tokensPath, []byte(oidcTokenEncKey))
	if err != nil {
		s.log.Warn("failed to open OIDC token store", "error", err)
		store, _ = oidc.NewFileTokenStore(tokensPath, nil)
	}
	s.tokenStore = store

	if err := s.loadProviders(); err != nil {
		s.log.Warn("failed to load OIDC providers", "error", err)
	}
}

// SetBackend configures the OIDC service to persist providers and tokens
// through the given storage.Backend (typically a barrier backend for
// transparent AES-256-GCM encryption). The prefix is prepended to all
// storage keys (e.g., "oidc/"). When a backend is set, SetDataDir is
// not required -- all data flows through the backend.
func (s *OIDCService) SetBackend(backend storage.Backend, prefix string) error {
	if backend == nil {
		return ErrOIDCTokenStoreUnavailable
	}

	s.backend = backend
	s.backendPrefix = prefix

	// Create token store backed by the barrier.
	tokenStore, err := oidc.NewBackendTokenStore(backend, prefix+"tokens/")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCTokenStoreUnavailable, err)
	}
	s.tokenStore = tokenStore

	// Load providers from the backend.
	if loadErr := s.loadProviders(); loadErr != nil {
		s.log.Warn("failed to load OIDC providers from backend", "error", loadErr)
	}

	return nil
}

// SetTokenStore sets the token store (used for testing).
func (s *OIDCService) SetTokenStore(store oidc.TokenStore) {
	s.tokenStore = store
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *OIDCService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetBrowserOpen allows replacing the browser open function (for testing).
func (s *OIDCService) SetBrowserOpen(fn BrowserOpenFunc) {
	s.browserOpen = fn
}

// Close stops all background refresh goroutines and closes the token store.
func (s *OIDCService) Close() error {
	if err := s.StopAllRefresh(); err != nil {
		s.log.Warn("failed to stop all refresh processes", "error", err)
	}
	if s.tokenStore != nil {
		return s.tokenStore.Close()
	}
	return nil
}

// --- Provider management ---

// GetTemplates returns all available provider templates for the GUI template selector.
func (s *OIDCService) GetTemplates() []OIDCProviderTemplateInfo {
	templates := make([]OIDCProviderTemplateInfo, 0, len(oidc.BuiltinTemplates)+1)

	for _, tmpl := range oidc.BuiltinTemplates {
		provType := OIDCProviderTypeStandard
		if tmpl.CustomResponseHandler == "aws" {
			provType = OIDCProviderTypeAWS
		}

		templates = append(templates, OIDCProviderTemplateInfo{
			Name:           tmpl.Name,
			Description:    tmpl.Description,
			Issuer:         tmpl.Issuer,
			Scopes:         tmpl.Scopes,
			RequiresRegion: tmpl.RequiresRegion,
			RequiresIssuer: tmpl.Issuer == "",
			Type:           provType,
			DPoP:           tmpl.DPoP,
		})
	}

	// Add synthetic "custom" entry for manual configuration.
	templates = append(templates, OIDCProviderTemplateInfo{
		Name:           "custom",
		Description:    "Custom OIDC provider",
		RequiresIssuer: true,
		Type:           OIDCProviderTypeStandard,
	})

	return templates
}

// GetProviders returns all configured OIDC providers.
func (s *OIDCService) GetProviders() []OIDCProviderEntry {
	s.providersMu.RLock()
	defer s.providersMu.RUnlock()

	entries := make([]OIDCProviderEntry, 0, len(s.providers))
	for _, p := range s.providers {
		entries = append(entries, *p)
	}
	return entries
}

// GetProvider returns a single provider by name.
func (s *OIDCService) GetProvider(name string) (*OIDCProviderEntry, error) {
	if name == "" {
		return nil, ErrOIDCProviderNameRequired
	}
	s.providersMu.RLock()
	defer s.providersMu.RUnlock()

	p, ok := s.providers[name]
	if !ok {
		return nil, ErrOIDCProviderNotFound
	}
	cpy := *p
	return &cpy, nil
}

// AddProvider adds a new OIDC provider configuration.
// When entry.Template is set, template defaults (issuer, scopes, client_id,
// auto_refresh) are applied before saving -- the same pattern as ApplyTemplate
// in oidc/templates.go.
func (s *OIDCService) AddProvider(entry *OIDCProviderEntry) error {
	if entry == nil {
		return ErrOIDCInvalidProvider
	}
	if entry.Name == "" {
		return ErrOIDCProviderNameRequired
	}

	// Apply template defaults when a template is specified.
	if entry.Template != "" && entry.Template != "custom" {
		if err := s.applyTemplate(entry); err != nil {
			return err
		}
	}

	s.providersMu.Lock()
	defer s.providersMu.Unlock()

	if _, exists := s.providers[entry.Name]; exists {
		return ErrOIDCProviderExists
	}

	if entry.Type == "" {
		entry.Type = OIDCProviderTypeStandard
	}
	if entry.RedirectURL == "" {
		entry.RedirectURL = fmt.Sprintf("http://localhost:%s%s", oidcCallbackPort, oidcCallbackPath)
	}

	cpy := *entry
	s.providers[entry.Name] = &cpy
	return s.saveProviders()
}

// applyTemplate applies defaults from a builtin template to the entry,
// without overwriting values already set by the user.
func (s *OIDCService) applyTemplate(entry *OIDCProviderEntry) error {
	tmpl, err := oidc.GetTemplate(entry.Template)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrOIDCTemplateNotFound, entry.Template)
	}

	// Set provider type based on template.
	if tmpl.CustomResponseHandler == "aws" {
		entry.Type = OIDCProviderTypeAWS
	} else if entry.Type == "" {
		entry.Type = OIDCProviderTypeStandard
	}

	// Apply defaults without overwriting user-provided values.
	if entry.Issuer == "" && tmpl.Issuer != "" {
		entry.Issuer = tmpl.Issuer
	}
	if len(entry.Scopes) == 0 && len(tmpl.Scopes) > 0 {
		entry.Scopes = make([]string, len(tmpl.Scopes))
		copy(entry.Scopes, tmpl.Scopes)
	}
	if entry.ClientID == "" && tmpl.ClientID != "" {
		entry.ClientID = tmpl.ClientID
	}
	if entry.AutoRefresh == 0 && tmpl.DefaultAutoRefresh > 0 {
		entry.AutoRefresh = tmpl.DefaultAutoRefresh
	}
	if entry.AWSProfile == "" && tmpl.DefaultAWSProfile != "" {
		entry.AWSProfile = tmpl.DefaultAWSProfile
	}
	if tmpl.DPoP && !entry.DPoP {
		entry.DPoP = true
	}

	return nil
}

// UpdateProvider updates an existing OIDC provider configuration.
func (s *OIDCService) UpdateProvider(name string, entry *OIDCProviderEntry) error {
	if name == "" {
		return ErrOIDCProviderNameRequired
	}
	if entry == nil {
		return ErrOIDCInvalidProvider
	}

	s.providersMu.Lock()
	defer s.providersMu.Unlock()

	if _, exists := s.providers[name]; !exists {
		return ErrOIDCProviderNotFound
	}

	// If renaming, remove old key.
	if entry.Name != name {
		delete(s.providers, name)
	}

	cpy := *entry
	s.providers[cpy.Name] = &cpy
	return s.saveProviders()
}

// DeleteProvider removes a provider and stops any running refresh for it.
func (s *OIDCService) DeleteProvider(name string) error {
	if name == "" {
		return ErrOIDCProviderNameRequired
	}

	// Stop refresh first (outside provider lock to avoid deadlock).
	_ = s.StopAutoRefresh(name)

	s.providersMu.Lock()
	defer s.providersMu.Unlock()

	if _, exists := s.providers[name]; !exists {
		return ErrOIDCProviderNotFound
	}

	delete(s.providers, name)
	return s.saveProviders()
}

// DiscoverProvider discovers OIDC endpoints from an issuer URL.
func (s *OIDCService) DiscoverProvider(issuer string) (*oidc.Provider, error) {
	if issuer == "" {
		return nil, ErrOIDCInvalidIssuer
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	cfg := &oidc.ProviderConfig{
		Issuer:      issuer,
		ClientID:    "discovery",
		RedirectURL: "http://localhost/callback",
	}

	provider, err := oidc.NewProvider(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCDiscoveryFailed, err)
	}

	return provider, nil
}

// --- Login / Token ---

// Login initiates a browser-based OIDC login with PKCE for the named provider.
func (s *OIDCService) Login(providerName string) (*OIDCLoginResult, error) {
	entry, err := s.GetProvider(providerName)
	if err != nil {
		s.log.Warn("login failed: provider lookup", "provider", providerName, "error", err)
		return &OIDCLoginResult{Success: false, Error: err.Error()}, nil
	}

	if entry.Type == OIDCProviderTypeAWS {
		return &OIDCLoginResult{Success: false, Error: "AWS login is not yet supported in the GUI"}, nil
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Discover provider endpoints.
	provCfg := &oidc.ProviderConfig{
		Issuer:       entry.Issuer,
		ClientID:     entry.ClientID,
		ClientSecret: entry.ClientSecret,
		RedirectURL:  entry.RedirectURL,
		Scopes:       entry.Scopes,
	}

	oidcProvider, err := oidc.NewProvider(ctx, provCfg)
	if err != nil {
		s.log.Warn("login failed: provider discovery", "provider", providerName, "error", err)
		return &OIDCLoginResult{Success: false, Error: err.Error()}, nil
	}

	client := oidc.NewClient(oidcProvider, provCfg)

	// Generate DPoP key only when explicitly enabled by the user.
	// Auto-detection via SupportsDPoP() is available for UI hints but
	// should not auto-enable DPoP — the user must opt in.
	var dpopKey *oidc.DPoPKey
	if entry.DPoP {
		dpopKey, err = oidc.GenerateDPoPKey()
		if err != nil {
			s.log.Warn("failed to generate DPoP key", "error", err)
		} else {
			client.SetDPoPKey(dpopKey)
			s.log.Info("enabling DPoP token binding", "provider", providerName)
		}
	}

	// Generate PKCE parameters.
	pkceParams, err := oidc.GeneratePKCEParams()
	if err != nil {
		s.log.Warn("login failed: PKCE generation", "provider", providerName, "error", err)
		return &OIDCLoginResult{Success: false, Error: "failed to generate PKCE: " + err.Error()}, nil
	}

	state, err := oidc.GenerateState()
	if err != nil {
		s.log.Warn("login failed: state generation", "provider", providerName, "error", err)
		return &OIDCLoginResult{Success: false, Error: "failed to generate state: " + err.Error()}, nil
	}

	authOpts := &oidc.AuthCodeOptions{
		State:        state,
		CodeVerifier: pkceParams.CodeVerifier,
	}

	authURL, err := client.AuthCodeURL(authOpts)
	if err != nil {
		s.log.Warn("login failed: auth URL generation", "provider", providerName, "error", err)
		return &OIDCLoginResult{Success: false, Error: err.Error()}, nil
	}

	// Parse redirect URL for port.
	parsedRedirect, err := url.Parse(entry.RedirectURL)
	if err != nil {
		s.log.Warn("login failed: invalid redirect URL", "provider", providerName, "error", err)
		return &OIDCLoginResult{Success: false, Error: "invalid redirect URL: " + err.Error()}, nil
	}
	port := parsedRedirect.Port()
	if port == "" {
		port = oidcCallbackPort
	}

	// Start local callback server.
	callbackCtx, callbackCancel := context.WithTimeout(ctx, oidcCallbackTimeout)
	defer callbackCancel()

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	var receivedState atomic.Value

	mux := http.NewServeMux()
	mux.HandleFunc(oidcCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if errParam := query.Get("error"); errParam != "" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>Authentication Failed</h1></body></html>"))
			errChan <- fmt.Errorf("%s: %s", errParam, query.Get("error_description"))
			return
		}

		code := query.Get("code")
		if code == "" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>Authentication Failed</h1><p>No code received</p></body></html>"))
			errChan <- ErrOIDCCallbackNoCode
			return
		}

		receivedState.Store(query.Get("state"))

		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>Authentication Successful</h1><p>You may close this window.</p></body></html>"))
		codeChan <- code
	})

	lc := net.ListenConfig{
		Control: setReuseAddr,
	}
	listener, err := lc.Listen(ctx, "tcp", ":"+port)
	if err != nil {
		s.log.Warn("login failed: callback server", "provider", providerName, "port", port, "error", err)
		return &OIDCLoginResult{Success: false, Error: "failed to start callback server on port " + port + ": " + err.Error()}, nil
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

	// Open browser.
	if s.browserOpen != nil {
		if browserErr := s.browserOpen(authURL); browserErr != nil {
			s.log.Warn("failed to open browser", "error", browserErr)
		}
	}

	// Wait for callback.
	var code string
	select {
	case code = <-codeChan:
		// received authorization code
	case cbErr := <-errChan:
		s.log.Warn("login failed: callback error", "provider", providerName, "error", cbErr)
		return &OIDCLoginResult{Success: false, Error: cbErr.Error()}, nil
	case <-callbackCtx.Done():
		s.log.Warn("login failed: callback timeout", "provider", providerName)
		return &OIDCLoginResult{Success: false, Error: "callback timeout waiting for authorization"}, nil
	}

	// Verify state.
	if rs, ok := receivedState.Load().(string); !ok || rs != state {
		s.log.Warn("login failed: state mismatch", "provider", providerName)
		return &OIDCLoginResult{Success: false, Error: "state mismatch — possible CSRF attack"}, nil
	}

	// Exchange code for tokens.
	tokenResp, err := client.Exchange(ctx, code, authOpts)
	if err != nil {
		s.log.Warn("login failed: token exchange", "provider", providerName, "error", err)
		return &OIDCLoginResult{Success: false, Error: err.Error()}, nil
	}

	// Persist DPoP key with tokens for refresh continuity.
	if dpopKey != nil {
		if setErr := tokenResp.SetDPoPKey(dpopKey); setErr != nil {
			s.log.Warn("failed to persist DPoP key", "error", setErr)
		}
	}

	// Log token exchange result for diagnostics.
	s.log.Info("OIDC token exchange complete",
		"provider", providerName,
		"has_refresh_token", tokenResp.RefreshToken != "",
		"has_id_token", tokenResp.IDToken != "",
		"has_dpop_key", tokenResp.DPoPKeyPEM != "",
		"expires_in", tokenResp.ExpiresIn,
	)

	// Store tokens.
	if s.tokenStore != nil {
		if storeErr := s.tokenStore.Save(entry.Issuer, tokenResp); storeErr != nil {
			s.log.Warn("failed to store OIDC tokens", "error", storeErr)
		}
	}

	// Build token info.
	info := s.tokenResponseToInfo(providerName, entry, tokenResp)

	// Execute script if configured.
	if entry.Exec != "" {
		go func() {
			if _, execErr := s.ExecuteScript(providerName, entry.Exec); execErr != nil {
				s.log.Warn("post-login script failed", "provider", providerName, "error", execErr)
			}
		}()
	}

	// Start auto-refresh if configured.
	if entry.AutoRefresh > 0 && tokenResp.RefreshToken != "" {
		go func() {
			if startErr := s.StartAutoRefresh(providerName); startErr != nil {
				s.log.Warn("auto-refresh start failed", "provider", providerName, "error", startErr)
			}
		}()
	}

	return &OIDCLoginResult{Success: true, Token: info}, nil
}

// GetTokenInfo returns the current token information for the named provider.
func (s *OIDCService) GetTokenInfo(providerName string) (*OIDCTokenInfo, error) {
	entry, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	if s.tokenStore == nil {
		return nil, ErrOIDCTokenStoreUnavailable
	}

	tokenResp, err := s.tokenStore.Load(entry.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCTokenNotFound, err)
	}

	return s.tokenResponseToInfo(providerName, entry, tokenResp), nil
}

// GetRawTokenResponse returns the raw JSON token response for the named
// provider. This includes the access token, refresh token, ID token, and
// all other fields from the provider's token endpoint response.
func (s *OIDCService) GetRawTokenResponse(providerName string) (string, error) {
	entry, err := s.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	if s.tokenStore == nil {
		return "", ErrOIDCTokenStoreUnavailable
	}

	tokenResp, err := s.tokenStore.Load(entry.Issuer)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOIDCTokenNotFound, err)
	}

	data, err := json.MarshalIndent(tokenResp, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// GetAccessToken returns only the access token string for the named provider.
// Unlike GetRawTokenResponse which returns the full JSON, this returns just
// the bearer token suitable for Authorization headers.
func (s *OIDCService) GetAccessToken(providerName string) (string, error) {
	entry, err := s.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	if s.tokenStore == nil {
		return "", ErrOIDCTokenStoreUnavailable
	}

	tokenResp, err := s.tokenStore.Load(entry.Issuer)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOIDCTokenNotFound, err)
	}

	accessToken := tokenResp.AccessToken

	// Defensive: if the stored access token looks like a JSON object (e.g.,
	// the full token response was accidentally stored as the access_token),
	// extract just the access_token field from the nested JSON.
	if trimmed := strings.TrimSpace(accessToken); strings.HasPrefix(trimmed, "{") {
		var nested struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal([]byte(trimmed), &nested) == nil && nested.AccessToken != "" {
			s.log.Warn("access_token contained nested JSON, extracted inner access_token",
				"provider", providerName)
			return nested.AccessToken, nil
		}
	}

	return accessToken, nil
}

// RefreshToken refreshes the access token for the named provider.
func (s *OIDCService) RefreshToken(providerName string) (*OIDCTokenInfo, error) {
	entry, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	if s.tokenStore == nil {
		return nil, ErrOIDCTokenStoreUnavailable
	}

	tokenResp, err := s.tokenStore.Load(entry.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCTokenNotFound, err)
	}

	if tokenResp.RefreshToken == "" {
		s.log.Warn("no refresh token in stored response",
			"provider", providerName,
			"issuer", entry.Issuer,
			"configured_scopes", entry.Scopes,
		)
		return nil, ErrOIDCNoRefreshToken
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	provCfg := &oidc.ProviderConfig{
		Issuer:       entry.Issuer,
		ClientID:     entry.ClientID,
		ClientSecret: entry.ClientSecret,
		RedirectURL:  entry.RedirectURL,
		Scopes:       entry.Scopes,
	}

	oidcProvider, err := oidc.NewProvider(ctx, provCfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCRefreshFailed, err)
	}

	client := oidc.NewClient(oidcProvider, provCfg)

	// Restore DPoP key from stored tokens for binding continuity.
	if tokenResp.DPoPKeyPEM != "" {
		dpopKey, dpopErr := tokenResp.GetDPoPKey()
		if dpopErr == nil {
			client.SetDPoPKey(dpopKey)
		} else {
			s.log.Warn("failed to restore DPoP key for refresh", "error", dpopErr)
		}
	}

	newTokens, err := client.Refresh(ctx, tokenResp.RefreshToken)
	if err != nil {
		var tokenErr *oidc.TokenRequestError
		if errors.As(err, &tokenErr) && tokenErr.Description != "" {
			return nil, fmt.Errorf("%w: %s", ErrOIDCRefreshFailed, tokenErr.Description)
		}
		return nil, fmt.Errorf("%w: %v", ErrOIDCRefreshFailed, err)
	}

	// Preserve refresh token if not rotated.
	if newTokens.RefreshToken == "" {
		newTokens.RefreshToken = tokenResp.RefreshToken
	}

	// Preserve DPoP key across refresh (same key must be used for binding).
	if tokenResp.DPoPKeyPEM != "" && newTokens.DPoPKeyPEM == "" {
		newTokens.DPoPKeyPEM = tokenResp.DPoPKeyPEM
	}

	if storeErr := s.tokenStore.Save(entry.Issuer, newTokens); storeErr != nil {
		s.log.Warn("failed to store refreshed tokens", "error", storeErr)
	}

	return s.tokenResponseToInfo(providerName, entry, newTokens), nil
}

// Logout clears stored tokens for the named provider.
func (s *OIDCService) Logout(providerName string) error {
	entry, err := s.GetProvider(providerName)
	if err != nil {
		return err
	}

	_ = s.StopAutoRefresh(providerName)

	if s.tokenStore == nil {
		return ErrOIDCTokenStoreUnavailable
	}

	if err := s.tokenStore.Delete(entry.Issuer); err != nil {
		// Treat "not found" as success.
		if err == oidc.ErrTokenNotFound {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrOIDCLogoutFailed, err)
	}
	return nil
}

// GetAllTokens returns token information for all providers that have stored tokens.
func (s *OIDCService) GetAllTokens() []OIDCTokenInfo {
	s.providersMu.RLock()
	defer s.providersMu.RUnlock()

	var infos []OIDCTokenInfo
	if s.tokenStore == nil {
		return infos
	}

	for name, entry := range s.providers {
		tokenResp, err := s.tokenStore.Load(entry.Issuer)
		if err != nil {
			continue
		}
		infos = append(infos, *s.tokenResponseToInfo(name, entry, tokenResp))
	}

	return infos
}

// --- Background Refresh ---

// StartAutoRefresh starts a goroutine-based refresh loop for the named provider.
func (s *OIDCService) StartAutoRefresh(providerName string) error {
	entry, err := s.GetProvider(providerName)
	if err != nil {
		return err
	}

	if entry.AutoRefresh <= 0 {
		return ErrOIDCAutoRefreshDisabled
	}

	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	if _, exists := s.refreshProcs[providerName]; exists {
		return ErrOIDCRefreshAlreadyRunning
	}

	refreshCtx, cancel := context.WithCancel(context.Background())

	proc := &refreshProcess{
		provider: providerName,
		cancel:   cancel,
	}

	initialStatus := &OIDCRefreshStatus{
		Provider: providerName,
		Running:  true,
	}
	proc.status.Store(initialStatus)

	s.refreshProcs[providerName] = proc

	go s.refreshLoop(refreshCtx, proc, entry)

	s.log.Info("started auto-refresh", "provider", providerName, "interval_secs", entry.AutoRefresh)
	return nil
}

// StopAutoRefresh stops the background refresh loop for the named provider.
func (s *OIDCService) StopAutoRefresh(providerName string) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	proc, exists := s.refreshProcs[providerName]
	if !exists {
		return nil // Not running, treat as success.
	}

	proc.cancel()
	delete(s.refreshProcs, providerName)

	s.log.Info("stopped auto-refresh", "provider", providerName)
	return nil
}

// StopAllRefresh stops all running background refresh goroutines.
func (s *OIDCService) StopAllRefresh() error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	for name, proc := range s.refreshProcs {
		proc.cancel()
		delete(s.refreshProcs, name)
	}
	return nil
}

// GetRefreshStatus returns the status of the background refresh for the named provider.
func (s *OIDCService) GetRefreshStatus(providerName string) (*OIDCRefreshStatus, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	proc, exists := s.refreshProcs[providerName]
	if !exists {
		return &OIDCRefreshStatus{Provider: providerName, Running: false}, nil
	}

	status := proc.status.Load()
	if status == nil {
		return &OIDCRefreshStatus{Provider: providerName, Running: true}, nil
	}

	cpy := *status
	return &cpy, nil
}

// GetAllRefreshStatus returns refresh status for all providers.
func (s *OIDCService) GetAllRefreshStatus() []OIDCRefreshStatus {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	result := make([]OIDCRefreshStatus, 0, len(s.refreshProcs))
	for _, proc := range s.refreshProcs {
		if status := proc.status.Load(); status != nil {
			cpy := *status
			result = append(result, cpy)
		}
	}
	return result
}

// --- Script Execution ---

// ExecuteScript runs a shell script with OIDC token data available via
// stdin (JSON) and environment variables.
func (s *OIDCService) ExecuteScript(providerName string, script string) (*OIDCExecResult, error) {
	if script == "" {
		return nil, ErrOIDCExecEmpty
	}

	entry, err := s.GetProvider(providerName)
	if err != nil {
		return &OIDCExecResult{Success: false, Error: err.Error()}, err
	}

	var tokenResp *oidc.TokenResponse
	if s.tokenStore != nil {
		tokenResp, _ = s.tokenStore.Load(entry.Issuer)
	}

	payload := s.buildExecPayload(providerName, entry, tokenResp)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return &OIDCExecResult{Success: false, Error: "failed to marshal payload"}, fmt.Errorf("%w: %v", ErrOIDCExecFailed, err)
	}

	cmd := exec.Command("sh", "-c", script)
	cmd.Stdin = bytes.NewReader(payloadJSON)

	envVars := []string{
		"OIDC_PROVIDER=" + payload.Provider,
		"OIDC_ISSUER=" + payload.Issuer,
		"OIDC_CLIENT_ID=" + payload.ClientID,
		"OIDC_ACCESS_TOKEN=" + payload.AccessToken,
		"OIDC_REFRESH_TOKEN=" + payload.RefreshToken,
		"OIDC_ID_TOKEN=" + payload.IDToken,
		"OIDC_EXPIRES_AT=" + payload.ExpiresAt,
		"OIDC_EXPIRES_IN=" + fmt.Sprintf("%d", payload.ExpiresIn),
		"OIDC_SCOPES=" + strings.Join(payload.Scopes, " "),
		"OIDC_SUBJECT=" + payload.Subject,
		"OIDC_EMAIL=" + payload.Email,
		"OIDC_NAME=" + payload.Name,
	}
	cmd.Env = append(os.Environ(), envVars...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return &OIDCExecResult{
				Success:  false,
				ExitCode: -1,
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				Error:    runErr.Error(),
			}, fmt.Errorf("%w: %v", ErrOIDCExecFailed, runErr)
		}
	}

	return &OIDCExecResult{
		Success:  exitCode == 0,
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}

// ExecuteProgram runs a program with the OIDC token payload passed via stdin
// and environment variables. Unlike ExecuteScript which runs through sh -c,
// this executes the program binary directly.
func (s *OIDCService) ExecuteProgram(providerName string, programPath string) (*OIDCExecResult, error) {
	if programPath == "" {
		return nil, ErrOIDCExecEmpty
	}

	entry, err := s.GetProvider(providerName)
	if err != nil {
		return &OIDCExecResult{Success: false, Error: err.Error()}, err
	}

	var tokenResp *oidc.TokenResponse
	if s.tokenStore != nil {
		tokenResp, _ = s.tokenStore.Load(entry.Issuer)
	}

	payload := s.buildExecPayload(providerName, entry, tokenResp)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return &OIDCExecResult{Success: false, Error: "failed to marshal payload"}, fmt.Errorf("%w: %v", ErrOIDCExecFailed, err)
	}

	cmd := exec.Command(programPath)
	cmd.Stdin = bytes.NewReader(payloadJSON)

	envVars := []string{
		"OIDC_PROVIDER=" + payload.Provider,
		"OIDC_ISSUER=" + payload.Issuer,
		"OIDC_CLIENT_ID=" + payload.ClientID,
		"OIDC_ACCESS_TOKEN=" + payload.AccessToken,
		"OIDC_REFRESH_TOKEN=" + payload.RefreshToken,
		"OIDC_ID_TOKEN=" + payload.IDToken,
		"OIDC_EXPIRES_AT=" + payload.ExpiresAt,
		"OIDC_EXPIRES_IN=" + fmt.Sprintf("%d", payload.ExpiresIn),
		"OIDC_SCOPES=" + strings.Join(payload.Scopes, " "),
		"OIDC_SUBJECT=" + payload.Subject,
		"OIDC_EMAIL=" + payload.Email,
		"OIDC_NAME=" + payload.Name,
	}
	cmd.Env = append(os.Environ(), envVars...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return &OIDCExecResult{
				Success:  false,
				ExitCode: -1,
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				Error:    runErr.Error(),
			}, fmt.Errorf("%w: %v", ErrOIDCExecFailed, runErr)
		}
	}

	return &OIDCExecResult{
		Success:  exitCode == 0,
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}

// SaveScript saves a script to the OIDC scripts directory under the data
// directory. The script is written as an executable shell script.
func (s *OIDCService) SaveScript(name string, content string) (*OIDCSavedScript, error) {
	if name == "" {
		return nil, ErrOIDCScriptNameRequired
	}
	if content == "" {
		return nil, ErrOIDCScriptContentRequired
	}

	dir, err := s.scriptsDir()
	if err != nil {
		return nil, err
	}

	// Sanitize the name to a safe filename.
	safeName := sanitizeScriptName(name)
	fileName := safeName + ".sh"
	path := filepath.Join(dir, fileName)

	if err := os.WriteFile(path, []byte(content), 0700); err != nil {
		return nil, fmt.Errorf("oidc_service: failed to save script: %w", err)
	}

	s.log.Info("OIDC script saved", "name", name, "path", path)
	return &OIDCSavedScript{Name: name, FileName: fileName}, nil
}

// ListScripts returns the scripts saved in the OIDC scripts directory.
func (s *OIDCService) ListScripts() ([]*OIDCSavedScript, error) {
	dir, err := s.scriptsDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("oidc_service: failed to list scripts: %w", err)
	}

	scripts := make([]*OIDCSavedScript, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		scripts = append(scripts, &OIDCSavedScript{
			Name:     strings.TrimSuffix(name, ".sh"),
			FileName: name,
		})
	}

	return scripts, nil
}

// GetScriptContent returns the content of a saved script.
func (s *OIDCService) GetScriptContent(fileName string) (string, error) {
	if fileName == "" {
		return "", ErrOIDCScriptNameRequired
	}

	dir, err := s.scriptsDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, filepath.Base(fileName))
	data, err := os.ReadFile(path) // #nosec G304 -- filename validated via scriptsDir
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrOIDCScriptNotFound
		}
		return "", fmt.Errorf("oidc_service: failed to read script: %w", err)
	}

	return string(data), nil
}

// DeleteScript removes a saved script from the scripts directory.
func (s *OIDCService) DeleteScript(fileName string) error {
	if fileName == "" {
		return ErrOIDCScriptNameRequired
	}

	dir, err := s.scriptsDir()
	if err != nil {
		return err
	}

	path := filepath.Join(dir, filepath.Base(fileName))
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrOIDCScriptNotFound
		}
		return fmt.Errorf("oidc_service: failed to delete script: %w", err)
	}

	s.log.Info("OIDC script deleted", "fileName", fileName)
	return nil
}

// ExecuteScriptFile executes a script file from disk (either a saved script
// or a user-browsed path) with OIDC token environment variables.
func (s *OIDCService) ExecuteScriptFile(providerName string, filePath string) (*OIDCExecResult, error) {
	if filePath == "" {
		return nil, ErrOIDCExecEmpty
	}

	data, err := os.ReadFile(filePath) // #nosec G304 -- user-selected file via dialog or saved scripts
	if err != nil {
		return &OIDCExecResult{
			Success:  false,
			ExitCode: -1,
			Error:    fmt.Sprintf("failed to read script: %v", err),
		}, fmt.Errorf("oidc_service: failed to read script file: %w", err)
	}

	return s.ExecuteScript(providerName, string(data))
}

// BrowseScriptFile opens a native file dialog for the user to select a script
// file. Returns the selected file path, or an empty string if cancelled.
func (s *OIDCService) BrowseScriptFile() (string, error) {
	filePath, err := wailsruntime.OpenFileDialog(s.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select Script",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "Shell Scripts", Pattern: "*.sh;*.bash"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("oidc_service: file dialog error: %w", err)
	}
	return filePath, nil
}

// GetSavedScriptPath returns the full path to a saved script file.
func (s *OIDCService) GetSavedScriptPath(fileName string) (string, error) {
	if fileName == "" {
		return "", ErrOIDCScriptNameRequired
	}

	dir, err := s.scriptsDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, filepath.Base(fileName))
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", ErrOIDCScriptNotFound
		}
		return "", fmt.Errorf("oidc_service: failed to stat script: %w", err)
	}

	return path, nil
}

// scriptsDir returns the OIDC scripts directory, creating it if needed.
func (s *OIDCService) scriptsDir() (string, error) {
	if s.dataDir == "" {
		return "", ErrOIDCScriptDirUnavailable
	}
	dir := filepath.Join(s.dataDir, oidcScriptsDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("oidc_service: failed to create scripts dir: %w", err)
	}
	return dir, nil
}

// sanitizeScriptName converts a human-readable script name into a safe filename.
func sanitizeScriptName(name string) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		if r == ' ' {
			return '_'
		}
		return -1 // drop
	}, name)
	if safe == "" {
		safe = "script"
	}
	return safe
}

// --- Internal helpers ---

// refreshLoop runs the periodic token refresh in a goroutine.
func (s *OIDCService) refreshLoop(ctx context.Context, proc *refreshProcess, entry *OIDCProviderEntry) {
	ticker := time.NewTicker(time.Duration(entry.AutoRefresh) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			status := proc.status.Load()
			if status != nil {
				updated := *status
				updated.Running = false
				proc.status.Store(&updated)
			}
			return

		case <-ticker.C:
			_, err := s.RefreshToken(proc.provider)

			status := proc.status.Load()
			if status == nil {
				status = &OIDCRefreshStatus{Provider: proc.provider, Running: true}
			}
			updated := *status
			updated.RefreshCount++
			updated.LastRefresh = time.Now().Format(time.RFC3339)
			updated.NextRefresh = time.Now().Add(time.Duration(entry.AutoRefresh) * time.Second).Format(time.RFC3339)

			if err != nil {
				updated.LastStatus = "error"
				updated.LastError = err.Error()
				s.log.Warn("auto-refresh failed", "provider", proc.provider, "error", err)
			} else {
				updated.LastStatus = "success"
				updated.LastError = ""

				// Execute script if configured.
				if entry.Exec != "" {
					if _, execErr := s.ExecuteScript(proc.provider, entry.Exec); execErr != nil {
						s.log.Warn("post-refresh script failed", "provider", proc.provider, "error", execErr)
					}
				}
			}
			proc.status.Store(&updated)
		}
	}
}

// tokenResponseToInfo converts an oidc.TokenResponse to an OIDCTokenInfo.
func (s *OIDCService) tokenResponseToInfo(providerName string, entry *OIDCProviderEntry, tokenResp *oidc.TokenResponse) *OIDCTokenInfo {
	info := &OIDCTokenInfo{
		Provider:   providerName,
		Issuer:     entry.Issuer,
		Scopes:     entry.Scopes,
		HasRefresh: tokenResp.RefreshToken != "",
		HasDPoP:    tokenResp.DPoPKeyPEM != "",
	}

	if tokenResp.Expiry.IsZero() && tokenResp.ExpiresIn > 0 {
		info.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339)
		info.ExpiresIn = int64(tokenResp.ExpiresIn)
		info.IsExpired = false
	} else if !tokenResp.Expiry.IsZero() {
		info.ExpiresAt = tokenResp.Expiry.Format(time.RFC3339)
		info.ExpiresIn = int64(time.Until(tokenResp.Expiry).Seconds())
		info.IsExpired = tokenResp.IsExpired()
	}

	// Parse scope from token response if available.
	if tokenResp.Scope != "" && len(info.Scopes) == 0 {
		info.Scopes = strings.Split(tokenResp.Scope, " ")
	}

	// Try to extract claims from the ID token (best-effort, no verification).
	if tokenResp.IDToken != "" {
		s.extractIDTokenClaims(tokenResp.IDToken, info)
	}

	return info
}

// extractIDTokenClaims extracts basic claims from an ID token without
// signature verification (display-only, used after a verified exchange).
func (s *OIDCService) extractIDTokenClaims(idToken string, info *OIDCTokenInfo) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if json.Unmarshal(decoded, &claims) == nil {
		info.Subject = claims.Sub
		info.Email = claims.Email
		info.Name = claims.Name
	}
}

// buildExecPayload constructs the JSON payload for script execution.
func (s *OIDCService) buildExecPayload(providerName string, entry *OIDCProviderEntry, tokenResp *oidc.TokenResponse) oidcExecPayload {
	payload := oidcExecPayload{
		Provider: providerName,
		Issuer:   entry.Issuer,
		ClientID: entry.ClientID,
		Scopes:   entry.Scopes,
	}

	if tokenResp != nil {
		payload.AccessToken = tokenResp.AccessToken
		payload.RefreshToken = tokenResp.RefreshToken
		payload.IDToken = tokenResp.IDToken
		payload.ExpiresIn = tokenResp.ExpiresIn

		if !tokenResp.Expiry.IsZero() {
			payload.ExpiresAt = tokenResp.Expiry.Format(time.RFC3339)
		}
	}

	return payload
}

// loadProviders loads the provider configuration. When a storage.Backend
// is configured (barrier mode), providers are read from the backend.
// Otherwise, they are read from the filesystem data directory.
func (s *OIDCService) loadProviders() error {
	if s.backend != nil {
		return s.loadProvidersFromBackend()
	}
	return s.loadProvidersFromFile()
}

// loadProvidersFromBackend loads providers from the storage.Backend.
func (s *OIDCService) loadProvidersFromBackend() error {
	key := s.backendPrefix + oidcProvidersBackendKey
	data, err := s.backend.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return err
	}

	var config oidcProvidersConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	s.providers = make(map[string]*OIDCProviderEntry, len(config.Providers))
	for i := range config.Providers {
		p := config.Providers[i]
		s.providers[p.Name] = &p
	}

	return nil
}

// loadProvidersFromFile loads providers from the filesystem data directory.
func (s *OIDCService) loadProvidersFromFile() error {
	if s.dataDir == "" {
		return nil
	}

	path := filepath.Join(s.dataDir, oidcProvidersFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var config oidcProvidersConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	s.providers = make(map[string]*OIDCProviderEntry, len(config.Providers))
	for i := range config.Providers {
		p := config.Providers[i]
		s.providers[p.Name] = &p
	}

	return nil
}

// saveProviders persists the provider configuration. When a storage.Backend
// is configured (barrier mode), providers are written to the backend.
// Otherwise, they are written to the filesystem data directory.
// Caller must hold s.providersMu.
func (s *OIDCService) saveProviders() error {
	if s.backend != nil {
		return s.saveProvidersToBackend()
	}
	return s.saveProvidersToFile()
}

// saveProvidersToBackend persists providers to the storage.Backend.
func (s *OIDCService) saveProvidersToBackend() error {
	config := oidcProvidersConfig{
		Providers: make([]OIDCProviderEntry, 0, len(s.providers)),
	}
	for _, p := range s.providers {
		config.Providers = append(config.Providers, *p)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	key := s.backendPrefix + oidcProvidersBackendKey
	return s.backend.Put(context.Background(), key, data)
}

// saveProvidersToFile persists providers to the filesystem data directory.
func (s *OIDCService) saveProvidersToFile() error {
	if s.dataDir == "" {
		return nil
	}

	config := oidcProvidersConfig{
		Providers: make([]OIDCProviderEntry, 0, len(s.providers)),
	}
	for _, p := range s.providers {
		config.Providers = append(config.Providers, *p)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(s.dataDir, oidcProvidersFile)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}
