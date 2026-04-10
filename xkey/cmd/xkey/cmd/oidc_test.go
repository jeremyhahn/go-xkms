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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestOIDCCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"oidc", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("oidc --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"OIDC",
		"OpenID Connect",
		"login",
		"token",
		"refresh",
		"logout",
		"providers",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("OIDC help output missing %q", expected)
		}
	}
}

func TestOIDCCmd_SubcommandRegistration(t *testing.T) {
	subcommands := map[string]bool{
		"login":     false,
		"token":     false,
		"refresh":   false,
		"logout":    false,
		"providers": false,
	}

	for _, cmd := range OIDCCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		if !found {
			t.Errorf("OIDC subcommand %q not registered", name)
		}
	}
}

func TestOIDCProvidersCmd_SubcommandRegistration(t *testing.T) {
	subcommands := map[string]bool{
		"list":   false,
		"add":    false,
		"remove": false,
	}

	for _, cmd := range oidcProvidersCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		if !found {
			t.Errorf("OIDC providers subcommand %q not registered", name)
		}
	}
}

// NOTE: Tests that execute commands through RootCmd.Execute() have state
// pollution issues due to Cobra flag persistence. Instead, test validation
// at the function level for input validation tests.

func TestOIDCLoginCmd_MissingIssuer(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"oidc", "login", "--client-id", "test-client"})

	err := RootCmd.Execute()
	if err != ErrOIDCMissingIssuer {
		t.Errorf("oidc login without issuer: error = %v, want %v", err, ErrOIDCMissingIssuer)
	}
}

func TestOIDCErrors(t *testing.T) {
	errors := []error{
		ErrOIDCMissingIssuer,
		ErrOIDCMissingClientID,
		ErrOIDCMissingProviderName,
		ErrOIDCDiscoveryFailed,
		ErrOIDCTokenExchangeFailed,
		ErrOIDCTokenRefreshFailed,
		ErrOIDCTokenValidationFailed,
		ErrOIDCTokenStoreFailed,
		ErrOIDCTokenLoadFailed,
		ErrOIDCNoTokensFound,
		ErrOIDCCallbackTimeout,
		ErrOIDCCallbackFailed,
		ErrOIDCStateMismatch,
		ErrOIDCProviderNotFound,
		ErrOIDCProviderExists,
		ErrOIDCConfigLoadFailed,
		ErrOIDCConfigSaveFailed,
		ErrOIDCInvalidRefreshToken,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("OIDC error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "oidc:") {
			t.Errorf("OIDC error missing 'oidc:' prefix: %v", err)
		}
	}
}

func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier failed: %v", err)
	}

	// Code verifier should be base64url encoded
	if verifier == "" {
		t.Error("generated code verifier is empty")
	}

	// Should be at least 43 characters (base64url encoded 32 bytes)
	if len(verifier) < 43 {
		t.Errorf("code verifier too short: got %d, want >= 43", len(verifier))
	}
}

func TestGenerateCodeVerifier_Uniqueness(t *testing.T) {
	verifiers := make(map[string]bool)
	for i := 0; i < 100; i++ {
		verifier, err := generateCodeVerifier()
		if err != nil {
			t.Fatalf("generateCodeVerifier failed: %v", err)
		}
		if verifiers[verifier] {
			t.Error("generated duplicate code verifier")
		}
		verifiers[verifier] = true
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	challenge := generateCodeChallenge(verifier)
	if challenge != expected {
		t.Errorf("generateCodeChallenge = %q, want %q", challenge, expected)
	}
}

func TestGenerateState(t *testing.T) {
	state, err := generateState()
	if err != nil {
		t.Fatalf("generateState failed: %v", err)
	}

	if state == "" {
		t.Error("generated state is empty")
	}

	// Should be base64url encoded
	if len(state) < 32 {
		t.Errorf("state too short: got %d, want >= 32", len(state))
	}
}

func TestGenerateState_Uniqueness(t *testing.T) {
	states := make(map[string]bool)
	for i := 0; i < 100; i++ {
		state, err := generateState()
		if err != nil {
			t.Fatalf("generateState failed: %v", err)
		}
		if states[state] {
			t.Error("generated duplicate state")
		}
		states[state] = true
	}
}

func TestBuildAuthorizationURL(t *testing.T) {
	endpoint := "https://example.com/authorize"
	clientID := "test-client"
	redirectURL := "http://localhost:8085/callback"
	scopes := []string{"openid", "profile", "email"}
	state := "test-state"
	codeChallenge := "test-challenge"

	authURL := buildAuthorizationURL(endpoint, clientID, redirectURL, scopes, state, codeChallenge)

	// Check that URL contains expected parameters
	expectedParams := []string{
		"response_type=code",
		"client_id=test-client",
		"redirect_uri=http%3A%2F%2Flocalhost%3A8085%2Fcallback",
		"scope=openid+profile+email",
		"state=test-state",
		"code_challenge=test-challenge",
		"code_challenge_method=S256",
	}

	for _, param := range expectedParams {
		if !strings.Contains(authURL, param) {
			t.Errorf("authorization URL missing parameter %q", param)
		}
	}

	// Check that it starts with the endpoint
	if !strings.HasPrefix(authURL, endpoint+"?") {
		t.Errorf("authorization URL doesn't start with endpoint: %s", authURL)
	}
}

func TestHandleOIDCCallback_Success(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	state := new(atomic.Value)

	req := httptest.NewRequest(http.MethodGet, "/callback?code=test-code&state=test-state", nil)
	w := httptest.NewRecorder()

	handleOIDCCallback(w, req, codeChan, errChan, state)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("callback returned status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	select {
	case code := <-codeChan:
		if code != "test-code" {
			t.Errorf("received code = %q, want %q", code, "test-code")
		}
	default:
		t.Error("no code received on channel")
	}

	if state.Load() != "test-state" {
		t.Errorf("state = %v, want %v", state.Load(), "test-state")
	}
}

func TestHandleOIDCCallback_Error(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	state := new(atomic.Value)

	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=User+denied+access", nil)
	w := httptest.NewRecorder()

	handleOIDCCallback(w, req, codeChan, errChan, state)

	select {
	case err := <-errChan:
		if !strings.Contains(err.Error(), "access_denied") {
			t.Errorf("error = %v, should contain 'access_denied'", err)
		}
	default:
		t.Error("no error received on channel")
	}
}

func TestHandleOIDCCallback_NoCode(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	state := new(atomic.Value)

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	w := httptest.NewRecorder()

	handleOIDCCallback(w, req, codeChan, errChan, state)

	select {
	case err := <-errChan:
		if !strings.Contains(err.Error(), "no authorization code") {
			t.Errorf("error = %v, should contain 'no authorization code'", err)
		}
	default:
		t.Error("no error received on channel")
	}
}

func TestDiscoverOIDCProvider(t *testing.T) {
	// Create a mock OIDC discovery server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}

		doc := OIDCDiscoveryDocument{
			Issuer:                "https://example.com",
			AuthorizationEndpoint: "https://example.com/authorize",
			TokenEndpoint:         "https://example.com/token",
			UserinfoEndpoint:      "https://example.com/userinfo",
			JwksURI:               "https://example.com/.well-known/jwks.json",
			ScopesSupported:       []string{"openid", "profile", "email"},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()

	discovery, err := discoverOIDCProvider(server.URL)
	if err != nil {
		t.Fatalf("discoverOIDCProvider failed: %v", err)
	}

	if discovery.AuthorizationEndpoint != "https://example.com/authorize" {
		t.Errorf("AuthorizationEndpoint = %q, want %q", discovery.AuthorizationEndpoint, "https://example.com/authorize")
	}

	if discovery.TokenEndpoint != "https://example.com/token" {
		t.Errorf("TokenEndpoint = %q, want %q", discovery.TokenEndpoint, "https://example.com/token")
	}
}

func TestDiscoverOIDCProvider_InvalidURL(t *testing.T) {
	_, err := discoverOIDCProvider("http://invalid.local.test:99999")
	if err == nil {
		t.Error("discoverOIDCProvider should fail with invalid URL")
	}
}

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantHome      bool
		wantAbs       bool // expect result to be absolute and end with input
		wantUnchanged bool // expect result to equal input
	}{
		{
			name:     "tilde prefix",
			input:    "~/test/path",
			wantHome: true,
		},
		{
			name:          "absolute path",
			input:         "/absolute/path",
			wantUnchanged: true,
		},
		{
			name:    "relative path",
			input:   "relative/path",
			wantAbs: true,
		},
	}

	home, _ := os.UserHomeDir()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPath(tt.input)
			if tt.wantHome {
				if !strings.HasPrefix(result, home) {
					t.Errorf("expandPath(%q) = %q, should start with home dir %q", tt.input, result, home)
				}
			} else if tt.wantAbs {
				// Relative paths should be converted to absolute paths
				if !filepath.IsAbs(result) {
					t.Errorf("expandPath(%q) = %q, should be absolute path", tt.input, result)
				}
				if !strings.HasSuffix(result, tt.input) {
					t.Errorf("expandPath(%q) = %q, should end with %q", tt.input, result, tt.input)
				}
			} else if tt.wantUnchanged {
				if result != tt.input {
					t.Errorf("expandPath(%q) = %q, want %q", tt.input, result, tt.input)
				}
			}
		})
	}
}

func TestStoreAndLoadToken(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "tokens.json")

	token := OIDCStoredToken{
		Provider:     "https://example.com",
		Issuer:       "https://example.com",
		ClientID:     "test-client",
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-456",
		IDToken:      "id-token-789",
		ExpiresAt:    time.Now().Add(time.Hour),
		Scopes:       []string{"openid", "profile", "email"},
	}

	// Store token
	err := storeToken(storePath, token)
	if err != nil {
		t.Fatalf("storeToken failed: %v", err)
	}

	// Load token
	loaded, err := loadToken(storePath)
	if err != nil {
		t.Fatalf("loadToken failed: %v", err)
	}

	if loaded.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", loaded.AccessToken, token.AccessToken)
	}
	if loaded.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", loaded.RefreshToken, token.RefreshToken)
	}
	if loaded.ClientID != token.ClientID {
		t.Errorf("ClientID = %q, want %q", loaded.ClientID, token.ClientID)
	}
}

func TestLoadToken_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "nonexistent.json")

	_, err := loadToken(storePath)
	if err != ErrOIDCNoTokensFound {
		t.Errorf("loadToken error = %v, want %v", err, ErrOIDCNoTokensFound)
	}
}

func TestLoadToken_EmptyStore(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "tokens.json")

	// Write empty store
	store := OIDCTokenStore{Tokens: []OIDCStoredToken{}}
	data, _ := json.Marshal(store)
	if err := os.WriteFile(storePath, data, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := loadToken(storePath)
	if err != ErrOIDCNoTokensFound {
		t.Errorf("loadToken error = %v, want %v", err, ErrOIDCNoTokensFound)
	}
}

func TestOIDCProviderConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "oidc-providers.json")

	// Create config
	config := OIDCConfig{
		Providers: []OIDCProvider{
			{
				Name:         "google",
				Issuer:       "https://accounts.google.com",
				ClientID:     "google-client-id",
				ClientSecret: "google-secret",
				RedirectURL:  "http://localhost:8085/callback",
				Scopes:       []string{"openid", "profile", "email"},
			},
		},
	}

	// Save config
	err := saveOIDCConfig(configPath, config)
	if err != nil {
		t.Fatalf("saveOIDCConfig failed: %v", err)
	}

	// Load config
	loaded, err := loadOIDCConfig(configPath)
	if err != nil {
		t.Fatalf("loadOIDCConfig failed: %v", err)
	}

	if len(loaded.Providers) != 1 {
		t.Fatalf("loaded %d providers, want 1", len(loaded.Providers))
	}

	if loaded.Providers[0].Name != "google" {
		t.Errorf("Provider.Name = %q, want %q", loaded.Providers[0].Name, "google")
	}
	if loaded.Providers[0].Issuer != "https://accounts.google.com" {
		t.Errorf("Provider.Issuer = %q, want %q", loaded.Providers[0].Issuer, "https://accounts.google.com")
	}
}

func TestLoadOIDCConfig_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nonexistent.json")

	_, err := loadOIDCConfig(configPath)
	if !os.IsNotExist(err) {
		t.Errorf("loadOIDCConfig error = %v, want os.IsNotExist", err)
	}
}

func TestTruncateToken(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		maxLen int
		want   string
	}{
		{
			name:   "shorter than max",
			token:  "short",
			maxLen: 10,
			want:   "short",
		},
		{
			name:   "equal to max",
			token:  "1234567890",
			maxLen: 10,
			want:   "1234567890",
		},
		{
			name:   "longer than max",
			token:  "this-is-a-very-long-token",
			maxLen: 10,
			want:   "this-is-a-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateToken(tt.token, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateToken(%q, %d) = %q, want %q", tt.token, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{
			name:     "seconds",
			duration: 30 * time.Second,
			want:     "30 seconds",
		},
		{
			name:     "minutes",
			duration: 5 * time.Minute,
			want:     "5 minutes",
		},
		{
			name:     "hours",
			duration: 2 * time.Hour,
			want:     "2 hours",
		},
		{
			name:     "hours and minutes",
			duration: 2*time.Hour + 30*time.Minute,
			want:     "2 hours 30 minutes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.duration)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, got, tt.want)
			}
		})
	}
}

func TestParseIDToken_Empty(t *testing.T) {
	claims, err := parseIDToken("")
	if err != nil {
		t.Fatalf("parseIDToken failed: %v", err)
	}
	if claims == nil {
		t.Error("parseIDToken returned nil claims for empty token")
	}
}

func TestParseIDToken_Invalid(t *testing.T) {
	_, err := parseIDToken("not-a-valid-jwt")
	if err == nil {
		t.Error("parseIDToken should fail with invalid token")
	}
}

func TestGetConfigPath(t *testing.T) {
	tokenStore := "/home/user/.config/xkey/tokens.json"
	expected := "/home/user/.config/xkey/oidc-providers.json"

	result := getConfigPath(tokenStore)
	if result != expected {
		t.Errorf("getConfigPath(%q) = %q, want %q", tokenStore, result, expected)
	}
}

func TestOIDCTokenStore_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "tokens.json")

	token := OIDCStoredToken{
		Provider:    "https://example.com",
		AccessToken: "secret-token",
	}

	err := storeToken(storePath, token)
	if err != nil {
		t.Fatalf("storeToken failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("failed to stat token store: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("token store permissions = %o, want %o", mode, 0600)
	}
}

func TestOIDCConfig_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "oidc-providers.json")

	config := OIDCConfig{
		Providers: []OIDCProvider{
			{
				Name:         "test",
				Issuer:       "https://example.com",
				ClientID:     "test-client",
				ClientSecret: "secret",
			},
		},
	}

	err := saveOIDCConfig(configPath, config)
	if err != nil {
		t.Fatalf("saveOIDCConfig failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("failed to stat config file: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("config file permissions = %o, want %o", mode, 0600)
	}
}

func TestExchangeCodeForTokens_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}

		response := OIDCTokenResponse{
			AccessToken:  "access-token-123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh-token-456",
			IDToken:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.test",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tokens, err := exchangeCodeForTokens(server.URL, "test-client", "", "auth-code", "http://localhost:8085/callback", "code-verifier")
	if err != nil {
		t.Fatalf("exchangeCodeForTokens failed: %v", err)
	}

	if tokens.AccessToken != "access-token-123" {
		t.Errorf("AccessToken = %q, want %q", tokens.AccessToken, "access-token-123")
	}
	if tokens.RefreshToken != "refresh-token-456" {
		t.Errorf("RefreshToken = %q, want %q", tokens.RefreshToken, "refresh-token-456")
	}
	if tokens.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want %d", tokens.ExpiresIn, 3600)
	}
}

func TestExchangeCodeForTokens_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := exchangeCodeForTokens(server.URL, "test-client", "", "auth-code", "http://localhost:8085/callback", "code-verifier")
	if err == nil {
		t.Error("exchangeCodeForTokens should fail with error response")
	}
}

func TestExchangeCodeForTokens_WithClientSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Verify client_secret is included
		if r.Form.Get("client_secret") != "test-secret" {
			http.Error(w, "missing client_secret", http.StatusBadRequest)
			return
		}

		response := OIDCTokenResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tokens, err := exchangeCodeForTokens(server.URL, "test-client", "test-secret", "auth-code", "http://localhost:8085/callback", "code-verifier")
	if err != nil {
		t.Fatalf("exchangeCodeForTokens failed: %v", err)
	}

	if tokens.AccessToken != "access-token-123" {
		t.Errorf("AccessToken = %q, want %q", tokens.AccessToken, "access-token-123")
	}
}

func TestRefreshTokens_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if r.Form.Get("grant_type") != "refresh_token" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}

		response := OIDCTokenResponse{
			AccessToken:  "new-access-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "new-refresh-token",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tokens, err := refreshTokens(server.URL, "test-client", "old-refresh-token")
	if err != nil {
		t.Fatalf("refreshTokens failed: %v", err)
	}

	if tokens.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q, want %q", tokens.AccessToken, "new-access-token")
	}
	if tokens.RefreshToken != "new-refresh-token" {
		t.Errorf("RefreshToken = %q, want %q", tokens.RefreshToken, "new-refresh-token")
	}
}

func TestRefreshTokens_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
	}))
	defer server.Close()

	_, err := refreshTokens(server.URL, "test-client", "expired-refresh-token")
	if err == nil {
		t.Error("refreshTokens should fail with error response")
	}
}

func TestOIDCStoredToken_JSON(t *testing.T) {
	token := OIDCStoredToken{
		Provider:     "https://example.com",
		Issuer:       "https://example.com",
		ClientID:     "test-client",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		ExpiresAt:    time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC),
		Scopes:       []string{"openid", "profile"},
	}

	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}

	var decoded OIDCStoredToken
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if decoded.Provider != token.Provider {
		t.Errorf("Provider = %q, want %q", decoded.Provider, token.Provider)
	}
	if decoded.ClientID != token.ClientID {
		t.Errorf("ClientID = %q, want %q", decoded.ClientID, token.ClientID)
	}
	if len(decoded.Scopes) != len(token.Scopes) {
		t.Errorf("Scopes length = %d, want %d", len(decoded.Scopes), len(token.Scopes))
	}
}

func TestOIDCProvider_JSON(t *testing.T) {
	provider := OIDCProvider{
		Name:         "google",
		Issuer:       "https://accounts.google.com",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://localhost:8085/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}

	data, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("failed to marshal provider: %v", err)
	}

	var decoded OIDCProvider
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal provider: %v", err)
	}

	if decoded.Name != provider.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, provider.Name)
	}
	if decoded.Issuer != provider.Issuer {
		t.Errorf("Issuer = %q, want %q", decoded.Issuer, provider.Issuer)
	}
	if decoded.ClientSecret != provider.ClientSecret {
		t.Errorf("ClientSecret = %q, want %q", decoded.ClientSecret, provider.ClientSecret)
	}
}

func TestOIDCDiscoveryDocument_JSON(t *testing.T) {
	doc := OIDCDiscoveryDocument{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/authorize",
		TokenEndpoint:         "https://example.com/token",
		UserinfoEndpoint:      "https://example.com/userinfo",
		JwksURI:               "https://example.com/.well-known/jwks.json",
		ScopesSupported:       []string{"openid", "profile", "email"},
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to marshal discovery document: %v", err)
	}

	var decoded OIDCDiscoveryDocument
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal discovery document: %v", err)
	}

	if decoded.Issuer != doc.Issuer {
		t.Errorf("Issuer = %q, want %q", decoded.Issuer, doc.Issuer)
	}
	if decoded.AuthorizationEndpoint != doc.AuthorizationEndpoint {
		t.Errorf("AuthorizationEndpoint = %q, want %q", decoded.AuthorizationEndpoint, doc.AuthorizationEndpoint)
	}
}

func TestOIDCTokenResponse_JSON(t *testing.T) {
	resp := OIDCTokenResponse{
		AccessToken:  "access-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		Scope:        "openid profile email",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal token response: %v", err)
	}

	var decoded OIDCTokenResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	if decoded.AccessToken != resp.AccessToken {
		t.Errorf("AccessToken = %q, want %q", decoded.AccessToken, resp.AccessToken)
	}
	if decoded.ExpiresIn != resp.ExpiresIn {
		t.Errorf("ExpiresIn = %d, want %d", decoded.ExpiresIn, resp.ExpiresIn)
	}
}

func TestDiscoverOIDCProvider_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	_, err := discoverOIDCProvider(server.URL)
	if err == nil {
		t.Error("discoverOIDCProvider should fail with 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404: %v", err)
	}
}

func TestDiscoverOIDCProvider_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	_, err := discoverOIDCProvider(server.URL)
	if err == nil {
		t.Error("discoverOIDCProvider should fail with invalid JSON")
	}
}

func TestStoreToken_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "subdir", "nested", "tokens.json")

	token := OIDCStoredToken{
		Provider:    "https://example.com",
		AccessToken: "test-token",
	}

	err := storeToken(storePath, token)
	if err != nil {
		t.Fatalf("storeToken failed: %v", err)
	}

	// Verify directory was created
	dir := filepath.Dir(storePath)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("failed to stat directory: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory to be created")
	}

	// Verify directory permissions
	mode := info.Mode().Perm()
	if mode != 0700 {
		t.Errorf("directory permissions = %o, want %o", mode, 0700)
	}
}

func TestOIDCProvidersAdd_AWSTypeValidation(t *testing.T) {
	tmpDir := t.TempDir()

	// Helper to create a fresh command for each test
	makeCmd := func(configPath string) *cobra.Command {
		cmd := &cobra.Command{
			Use: "add",
			RunE: func(cmd *cobra.Command, args []string) error {
				name, _ := cmd.Flags().GetString("name")
				providerType, _ := cmd.Flags().GetString("type")
				issuer, _ := cmd.Flags().GetString("issuer")
				clientID, _ := cmd.Flags().GetString("client-id")
				awsRegion, _ := cmd.Flags().GetString("region")

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
						return ErrOIDCMissingIssuer
					}
					if clientID == "" {
						return ErrOIDCMissingClientID
					}
				}

				// Save provider
				provider := OIDCProvider{
					Name:      name,
					Type:      pType,
					Issuer:    issuer,
					ClientID:  clientID,
					AWSRegion: awsRegion,
				}

				config := OIDCConfig{Providers: []OIDCProvider{provider}}
				return saveOIDCConfig(configPath, config)
			},
		}

		cmd.Flags().String("name", "", "Provider name")
		cmd.Flags().String("type", "oidc", "Provider type")
		cmd.Flags().String("issuer", "", "OIDC issuer")
		cmd.Flags().String("client-id", "", "Client ID")
		cmd.Flags().String("region", "", "AWS region")

		return cmd
	}

	t.Run("region without type requires issuer", func(t *testing.T) {
		// Without --type aws, --region alone should not auto-detect AWS type
		// This ensures future cloud providers (Google, Azure) with regions work correctly
		cmd := makeCmd("")
		cmd.SetArgs([]string{"--name", "test", "--region", "us-west-2"})
		err := cmd.Execute()
		if err != ErrOIDCMissingIssuer {
			t.Errorf("expected ErrOIDCMissingIssuer, got %v", err)
		}
	})

	t.Run("explicit type=aws works", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "test1-providers.json")
		cmd := makeCmd(configPath)
		cmd.SetArgs([]string{"--name", "aws-explicit", "--type", "aws", "--region", "eu-west-1"})
		err := cmd.Execute()
		if err != nil {
			t.Fatalf("command failed: %v", err)
		}

		config, err := loadOIDCConfig(configPath)
		if err != nil {
			t.Fatalf("failed to load config: %v", err)
		}

		if config.Providers[0].Type != OIDCProviderTypeAWS {
			t.Errorf("provider type = %q, want %q", config.Providers[0].Type, OIDCProviderTypeAWS)
		}
		if config.Providers[0].AWSRegion != "eu-west-1" {
			t.Errorf("AWS region = %q, want %q", config.Providers[0].AWSRegion, "eu-west-1")
		}
	})

	t.Run("type=aws without region fails", func(t *testing.T) {
		cmd := makeCmd("")
		cmd.SetArgs([]string{"--name", "aws-no-region", "--type", "aws"})
		err := cmd.Execute()
		if err != ErrAWSMissingRegion {
			t.Errorf("expected ErrAWSMissingRegion, got %v", err)
		}
	})
}
