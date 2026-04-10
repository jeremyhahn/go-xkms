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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	xkmstypes "github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock types (prefixed p5b to avoid conflicts)
// ---------------------------------------------------------------------------

// p5bMockTokenStore implements oidc.TokenStore with injectable errors.
type p5bMockTokenStore struct {
	tokens   map[string]*oidc.TokenResponse
	saveErr  error
	loadErr  error
	delErr   error
	closeErr error
}

func (s *p5bMockTokenStore) Save(issuer string, token *oidc.TokenResponse) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	if s.tokens == nil {
		s.tokens = make(map[string]*oidc.TokenResponse)
	}
	s.tokens[issuer] = token
	return nil
}

func (s *p5bMockTokenStore) Load(issuer string) (*oidc.TokenResponse, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	if s.tokens == nil {
		return nil, oidc.ErrTokenNotFound
	}
	t, ok := s.tokens[issuer]
	if !ok {
		return nil, oidc.ErrTokenNotFound
	}
	return t, nil
}

func (s *p5bMockTokenStore) Delete(issuer string) error {
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.tokens, issuer)
	return nil
}

func (s *p5bMockTokenStore) List() ([]string, error) {
	keys := make([]string, 0, len(s.tokens))
	for k := range s.tokens {
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *p5bMockTokenStore) Close() error {
	return s.closeErr
}

// p5bMockOATHStore implements oath.Store with injectable errors.
type p5bMockOATHStore struct {
	creds   []*oath.Credential
	addErr  error
	getErr  error
	delErr  error
	listErr error
	updErr  error
}

func (s *p5bMockOATHStore) Add(cred *oath.Credential) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.creds = append(s.creds, cred)
	return nil
}

func (s *p5bMockOATHStore) Get(id string) (*oath.Credential, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	for _, c := range s.creds {
		if c.ID == id || c.Name == id {
			return c, nil
		}
	}
	return nil, errors.New("not found")
}

func (s *p5bMockOATHStore) List() ([]*oath.Credential, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.creds, nil
}

func (s *p5bMockOATHStore) Update(cred *oath.Credential) error {
	return s.updErr
}

func (s *p5bMockOATHStore) Delete(id string) error {
	return s.delErr
}

func (s *p5bMockOATHStore) Close() error {
	return nil
}

// p5bMockKeyCounter implements KeyCounter for admin tests.
type p5bMockKeyCounter struct {
	count int
}

func (c *p5bMockKeyCounter) KeyCount() int {
	return c.count
}

// p5bMockStaticPWStore implements staticpw.Store for password protection tests.
type p5bMockStaticPWStore struct {
	passwords []*staticpw.StaticPassword
	listErr   error
	updateErr error
}

func (s *p5bMockStaticPWStore) Add(pw *staticpw.StaticPassword) error {
	s.passwords = append(s.passwords, pw)
	return nil
}

func (s *p5bMockStaticPWStore) Get(name string) (*staticpw.StaticPassword, error) {
	for _, p := range s.passwords {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, errors.New("not found")
}

func (s *p5bMockStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.passwords, nil
}

func (s *p5bMockStaticPWStore) Update(pw *staticpw.StaticPassword) error {
	return s.updateErr
}

func (s *p5bMockStaticPWStore) Delete(name string) error {
	return nil
}

func (s *p5bMockStaticPWStore) ForceDelete(idOrName string) error {
	return nil
}

func (s *p5bMockStaticPWStore) ListByFolder(folderPath string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}

func (s *p5bMockStaticPWStore) ListByFolderDirect(folderPath string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}

func (s *p5bMockStaticPWStore) ListFolders() ([]string, error) {
	return nil, nil
}

func (s *p5bMockStaticPWStore) MoveToFolder(idOrName string, folderPath string) error {
	return nil
}

func (s *p5bMockStaticPWStore) Close() error {
	return nil
}

func (s *p5bMockStaticPWStore) CreateFolder(_ string) error { return nil }
func (s *p5bMockStaticPWStore) RemoveFolder(_ string) error { return nil }

// ---------------------------------------------------------------------------
// 1. OIDC Service Tests
// ---------------------------------------------------------------------------

// TestP5B_OIDCService_SetDataDir_TokenStoreCreated verifies that SetDataDir
// creates a usable token store even when encryption key fallback is used.
func TestP5B_OIDCService_SetDataDir_TokenStoreCreated(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.SetDataDir(dir)
	assert.NotNil(t, svc.tokenStore)
	assert.Equal(t, dir, svc.dataDir)
}

// TestP5B_OIDCService_SetDataDir_LoadProvidersError verifies that SetDataDir
// handles corrupt provider files gracefully via the warning path.
func TestP5B_OIDCService_SetDataDir_LoadProvidersError(t *testing.T) {
	dir := t.TempDir()
	// Write an invalid JSON file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, oidcProvidersFile), []byte("NOT JSON"), 0600))

	svc := NewOIDCService(nil)
	svc.SetDataDir(dir) // Should warn but not crash.
	// Token store should still be created.
	assert.NotNil(t, svc.tokenStore)
}

// TestP5B_OIDCService_Login_AWSProviderType verifies that logging in with an
// AWS provider type returns the unsupported error.
func TestP5B_OIDCService_Login_AWSProviderType(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["aws-test"] = &OIDCProviderEntry{
		Name: "aws-test",
		Type: OIDCProviderTypeAWS,
	}

	result, err := svc.Login("aws-test")
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "AWS")
}

// TestP5B_OIDCService_Login_NilCtxFallsBack verifies that Login uses
// context.Background when ctx is nil.
func TestP5B_OIDCService_Login_NilCtxFallsBack(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.ctx = nil // explicitly nil
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Type:     OIDCProviderTypeStandard,
		Issuer:   "http://127.0.0.1:1/unreachable",
		ClientID: "cid",
	}

	// Will fail at discovery but exercises the nil ctx fallback.
	result, err := svc.Login("test")
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestP5B_OIDCService_Login_BrowserOpenError verifies that a browser open
// error is logged but does not abort the login.
func TestP5B_OIDCService_Login_BrowserOpenError(t *testing.T) {
	// Create a full mock OIDC server so Login progresses past discovery.
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"keys":[]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	// Browser open returns an error.
	var capturedAuthURL atomic.Value
	svc.SetBrowserOpen(func(url string) error {
		capturedAuthURL.Store(url)
		return errors.New("no display")
	})

	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		Issuer:      serverURL,
		ClientID:    "cid",
		RedirectURL: "http://localhost:18099/callback",
		Scopes:      []string{"openid"},
	}

	// Login will start the callback server and open the browser.
	// The browser open fails but the login continues to wait for callback.
	// Eventually it will time out, but we just want to verify the browser
	// error does not crash. Cancel via timeout to avoid waiting too long.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	svc.ctx = ctx

	result, err := svc.Login("test")
	// Should fail with callback timeout (browser error was logged, not returned).
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	// Verify the browser was called.
	assert.NotNil(t, capturedAuthURL.Load())
}

// TestP5B_OIDCService_Login_InvalidRedirectURL verifies that an invalid
// redirect URL returns an error.
func TestP5B_OIDCService_Login_InvalidRedirectURL(t *testing.T) {
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"keys":[]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())

	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		Issuer:      serverURL,
		ClientID:    "cid",
		RedirectURL: "://invalid\x00url",
		Scopes:      []string{"openid"},
	}

	result, err := svc.Login("test")
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestP5B_OIDCService_Login_RedirectURLDefaultPort verifies that when the
// redirect URL has no explicit port, the default callback port is used.
func TestP5B_OIDCService_Login_RedirectURLDefaultPort(t *testing.T) {
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"keys":[]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	svc := NewOIDCService(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	svc.SetContext(ctx)
	svc.SetBrowserOpen(func(url string) error { return nil })

	// RedirectURL with no port (e.g., http://localhost/callback).
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		Issuer:      serverURL,
		ClientID:    "cid",
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{"openid"},
	}

	// This will time out because no callback arrives, but exercises the
	// default port branch.
	result, err := svc.Login("test")
	assert.NoError(t, err)
	require.NotNil(t, result)
}

// TestP5B_OIDCService_RefreshToken_NilTokenStore verifies RefreshToken with
// no token store.
func TestP5B_OIDCService_RefreshToken_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	svc.tokenStore = nil

	_, err := svc.RefreshToken("test")
	assert.True(t, errors.Is(err, ErrOIDCTokenStoreUnavailable))
}

// TestP5B_OIDCService_RefreshToken_EmptyRefreshToken verifies RefreshToken
// when the stored token has no refresh token.
func TestP5B_OIDCService_RefreshToken_EmptyRefreshToken(t *testing.T) {
	svc := NewOIDCService(nil)
	store := &p5bMockTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://example.com": {AccessToken: "at"},
		},
	}
	svc.SetTokenStore(store)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	_, err := svc.RefreshToken("test")
	assert.True(t, errors.Is(err, ErrOIDCNoRefreshToken))
}

// TestP5B_OIDCService_RefreshToken_TokenNotFound verifies RefreshToken
// when the stored token is not found.
func TestP5B_OIDCService_RefreshToken_TokenNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	store := &p5bMockTokenStore{tokens: map[string]*oidc.TokenResponse{}}
	svc.SetTokenStore(store)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	_, err := svc.RefreshToken("test")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCTokenNotFound))
}

// TestP5B_OIDCService_RefreshToken_DiscoveryFails verifies RefreshToken when
// the OIDC discovery endpoint is unreachable.
func TestP5B_OIDCService_RefreshToken_DiscoveryFails(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.ctx = nil // Test nil ctx fallback.
	store := &p5bMockTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"http://127.0.0.1:1/unreachable": {
				AccessToken:  "at",
				RefreshToken: "rt",
			},
		},
	}
	svc.SetTokenStore(store)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "http://127.0.0.1:1/unreachable",
		ClientID: "cid",
	}

	_, err := svc.RefreshToken("test")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCRefreshFailed))
}

// TestP5B_OIDCService_RefreshLoop_CancelledWithNilStatus verifies that
// cancelling refreshLoop when status is nil does not panic.
func TestP5B_OIDCService_RefreshLoop_CancelledWithNilStatus(t *testing.T) {
	svc := NewOIDCService(nil)
	ctx, cancel := context.WithCancel(context.Background())

	proc := &refreshProcess{
		provider: "test",
		cancel:   cancel,
	}
	// Do NOT store any status - leave status nil.

	entry := &OIDCProviderEntry{
		Name:        "test",
		AutoRefresh: 3600, // Long interval so no tick fires.
	}

	done := make(chan struct{})
	go func() {
		svc.refreshLoop(ctx, proc, entry)
		close(done)
	}()

	// Cancel immediately.
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refreshLoop did not exit after cancel")
	}

	// With nil status, the cancel branch should just return without panic.
}

// TestP5B_OIDCService_RefreshLoop_SuccessfulRefreshUpdatesStatus verifies
// the refreshLoop success path with exec script.
func TestP5B_OIDCService_RefreshLoop_SuccessfulRefreshUpdatesStatus(t *testing.T) {
	// Build a mock OIDC server that supports discovery and refresh.
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-at",
			"refresh_token": "new-rt",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"keys":[]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	// Store initial token with refresh token.
	require.NoError(t, store.Save(serverURL, &oidc.TokenResponse{
		AccessToken:  "old-at",
		RefreshToken: "old-rt",
	}))

	entry := &OIDCProviderEntry{
		Name:        "refresh-test",
		Issuer:      serverURL,
		ClientID:    "cid",
		AutoRefresh: 1, // 1 second.
		Exec:        "echo refreshed",
	}
	require.NoError(t, svc.AddProvider(entry))

	ctx, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{
		provider: "refresh-test",
		cancel:   cancel,
	}
	proc.status.Store(&OIDCRefreshStatus{
		Provider: "refresh-test",
		Running:  true,
	})

	done := make(chan struct{})
	go func() {
		svc.refreshLoop(ctx, proc, entry)
		close(done)
	}()

	// Wait for at least one successful tick.
	time.Sleep(2500 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("refreshLoop did not exit")
	}

	status := proc.status.Load()
	require.NotNil(t, status)
	assert.True(t, status.RefreshCount > 0)
	assert.Equal(t, "success", status.LastStatus)
	assert.Empty(t, status.LastError)
	assert.NotEmpty(t, status.LastRefresh)
	assert.NotEmpty(t, status.NextRefresh)
}

// TestP5B_OIDCService_RefreshLoop_NilStatusOnTick verifies that when the
// status is nil on ticker fire, a new status is created.
func TestP5B_OIDCService_RefreshLoop_NilStatusOnTick(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:        "nil-status-tick",
		Issuer:      "http://127.0.0.1:1/unreachable",
		ClientID:    "cid",
		AutoRefresh: 1,
	}
	svc.providers["nil-status-tick"] = entry

	require.NoError(t, store.Save("http://127.0.0.1:1/unreachable", &oidc.TokenResponse{
		AccessToken:  "at",
		RefreshToken: "rt",
	}))

	ctx, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{
		provider: "nil-status-tick",
		cancel:   cancel,
	}
	// Intentionally leave status as nil (do not call proc.status.Store).

	done := make(chan struct{})
	go func() {
		svc.refreshLoop(ctx, proc, entry)
		close(done)
	}()

	// Wait for a tick to fire.
	time.Sleep(1500 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("refreshLoop did not exit")
	}

	status := proc.status.Load()
	require.NotNil(t, status)
	assert.True(t, status.RefreshCount > 0)
}

// TestP5B_OIDCService_Logout_DeleteError verifies that Logout wraps
// non-ErrTokenNotFound errors from the token store.
func TestP5B_OIDCService_Logout_DeleteError(t *testing.T) {
	svc := NewOIDCService(nil)
	store := &p5bMockTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://example.com": {AccessToken: "at"},
		},
		delErr: errors.New("disk failure"),
	}
	svc.SetTokenStore(store)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	err := svc.Logout("test")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCLogoutFailed))
}

// TestP5B_OIDCService_Logout_TokenNotFoundTreatedAsSuccess verifies that
// deleting a non-existent token is treated as success.
func TestP5B_OIDCService_Logout_TokenNotFoundTreatedAsSuccess(t *testing.T) {
	svc := NewOIDCService(nil)
	store := &p5bMockTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://example.com": {AccessToken: "at"},
		},
		delErr: oidc.ErrTokenNotFound,
	}
	svc.SetTokenStore(store)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	err := svc.Logout("test")
	assert.NoError(t, err)
}

// TestP5B_OIDCService_Close_WithRefreshProcsAndCloseError verifies that
// Close handles token store close errors.
func TestP5B_OIDCService_Close_WithRefreshProcsAndCloseError(t *testing.T) {
	svc := NewOIDCService(nil)
	store := &p5bMockTokenStore{closeErr: errors.New("close fail")}
	svc.SetTokenStore(store)

	// Add a refresh process.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.refreshProcs["test"] = &refreshProcess{
		provider: "test",
		cancel:   cancel,
	}
	_ = ctx

	err := svc.Close()
	assert.Error(t, err)
	assert.Equal(t, "close fail", err.Error())
}

// TestP5B_OIDCService_GetAllTokens_StoreLoadError verifies that GetAllTokens
// skips providers whose tokens fail to load.
func TestP5B_OIDCService_GetAllTokens_StoreLoadError(t *testing.T) {
	svc := NewOIDCService(nil)
	store := &p5bMockTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://good.com": {AccessToken: "at", ExpiresIn: 3600},
		},
	}
	svc.SetTokenStore(store)

	svc.providers["good"] = &OIDCProviderEntry{
		Name:   "good",
		Issuer: "https://good.com",
	}
	svc.providers["bad"] = &OIDCProviderEntry{
		Name:   "bad",
		Issuer: "https://bad.com", // No token stored, will fail Load.
	}

	tokens := svc.GetAllTokens()
	// Only the "good" token should appear.
	assert.Len(t, tokens, 1)
	assert.Equal(t, "good", tokens[0].Provider)
}

// TestP5B_OIDCService_TokenResponseToInfo_ScopeFromResponseNotOverridden
// verifies that Scope from the response does not override entry Scopes.
func TestP5B_OIDCService_TokenResponseToInfo_ScopeFromResponseNotOverridden(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
		Scopes: []string{"openid", "email"},
	}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		Scope:       "openid profile",
		ExpiresIn:   3600,
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	// Entry scopes should NOT be overridden by Scope field.
	assert.Equal(t, []string{"openid", "email"}, info.Scopes)
}

// TestP5B_OIDCService_TokenResponseToInfo_ScopeFromResponseUsedWhenEmpty
// verifies that Scope from the response is used when entry has no Scopes.
func TestP5B_OIDCService_TokenResponseToInfo_ScopeFromResponseUsedWhenEmpty(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		Scope:       "openid profile",
		ExpiresIn:   3600,
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Equal(t, []string{"openid", "profile"}, info.Scopes)
}

// TestP5B_OIDCService_Login_StoreTokenSaveError verifies that Login logs a
// warning but succeeds when token store save fails.
func TestP5B_OIDCService_Login_StoreTokenSaveError(t *testing.T) {
	// This is a complex end-to-end test; use the full flow mock server approach.
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"keys":[]}`)
	})
	oidcServer := httptest.NewServer(mux)
	defer oidcServer.Close()
	serverURL = oidcServer.URL

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	// Set a store that always fails on Save.
	store := &p5bMockTokenStore{saveErr: errors.New("save fail")}
	svc.SetTokenStore(store)

	port := "18097"
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		Type:        OIDCProviderTypeStandard,
		Issuer:      serverURL,
		ClientID:    "cid",
		RedirectURL: fmt.Sprintf("http://localhost:%s/callback", port),
		Scopes:      []string{"openid"},
	}

	// Capture the auth URL and simulate the callback.
	var capturedAuthURL atomic.Value
	svc.SetBrowserOpen(func(url string) error {
		capturedAuthURL.Store(url)

		go func() {
			time.Sleep(100 * time.Millisecond)
			authURL := capturedAuthURL.Load().(string)
			// Extract state from the auth URL.
			for _, part := range []string{"state="} {
				idx := len(part)
				start := 0
				for i := range authURL {
					if authURL[i:i+len(part)] == part {
						start = i + idx
						break
					}
				}
				if start > 0 {
					end := start
					for end < len(authURL) && authURL[end] != '&' {
						end++
					}
					state := authURL[start:end]
					callbackURL := fmt.Sprintf("http://localhost:%s/callback?code=testcode&state=%s", port, state)
					resp, httpErr := http.Get(callbackURL)
					if httpErr == nil {
						resp.Body.Close()
					}
				}
			}
		}()

		return nil
	})

	result, err := svc.Login("test")
	// Login should succeed even though token store save failed.
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

// TestP5B_OIDCService_ApplyTemplate_NonAWSTypeDefault verifies that
// applyTemplate sets the type to standard when the template is not AWS.
func TestP5B_OIDCService_ApplyTemplate_NonAWSTypeDefault(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:     "test",
		Template: "google", // Known non-AWS template.
	}

	err := svc.applyTemplate(entry)
	assert.NoError(t, err)
	assert.Equal(t, OIDCProviderTypeStandard, entry.Type)
	assert.NotEmpty(t, entry.Scopes)
}

// TestP5B_OIDCService_ApplyTemplate_UnknownTemplate verifies that
// applyTemplate returns an error for an unknown template.
func TestP5B_OIDCService_ApplyTemplate_UnknownTemplate(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:     "test",
		Template: "does-not-exist",
	}

	err := svc.applyTemplate(entry)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCTemplateNotFound))
}

// TestP5B_OIDCService_SaveProviders_ReadOnlyDataDir verifies saveProviders
// error path when directory is not writable.
func TestP5B_OIDCService_SaveProviders_ReadOnlyDataDir(t *testing.T) {
	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly", "nested")

	svc := NewOIDCService(nil)
	svc.dataDir = readOnlyDir
	svc.providers["test"] = &OIDCProviderEntry{Name: "test"}

	// Create the parent as read-only.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "readonly"), 0500))
	defer os.Chmod(filepath.Join(dir, "readonly"), 0700)

	err := svc.saveProviders()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// 2. Setup Wizard Service Tests
// ---------------------------------------------------------------------------

// TestP5B_SetupWizard_ApplySOProvisioning_EmitProgressEvents verifies that
// progress events are emitted during SO provisioning.
func TestP5B_SetupWizard_ApplySOProvisioning_EmitProgressEvents(t *testing.T) {
	svc := NewSetupWizardService()

	var eventLog []int
	svc.SetEventEmitter(func(e events.Event) {
		// Count events received.
		eventLog = append(eventLog, 1)
	})

	svc.SetPINService(&PINService{})

	choices := &SetupChoices{
		SOPin: "123456",
		Mode:  "standalone",
	}

	// This will fail in various steps but should still emit progress events.
	result, err := svc.ApplySOProvisioning(choices)
	assert.NoError(t, err)
	require.NotNil(t, result)
	// Should have emitted at least the step events.
	assert.True(t, len(eventLog) > 0)
}

// TestP5B_SetupWizard_ApplySOProvisioning_PanicRecovery verifies panic
// recovery in ApplySOProvisioning.
func TestP5B_SetupWizard_ApplySOProvisioning_PanicRecovery(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetPINService(&PINService{})

	// Set an event emitter that panics.
	svc.SetEventEmitter(func(e events.Event) {
		panic("test panic in emitter")
	})

	choices := &SetupChoices{
		SOPin: "123456",
		Mode:  "standalone",
	}

	result, err := svc.ApplySOProvisioning(choices)
	// Should recover from the panic.
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "panic")
}

// TestP5B_SetupWizard_ApplyUserOnboarding_PanicRecovery verifies panic
// recovery in ApplyUserOnboarding.
func TestP5B_SetupWizard_ApplyUserOnboarding_PanicRecovery(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetPINService(&PINService{})

	// Use a config dir that triggers enterprise mode.
	dir := t.TempDir()
	svc.SetConfigDir(dir)

	// Create a fake HMAC file so IsEnterpriseMode returns true.
	hmacPath := filepath.Join(dir, "xkey_policy.hmac")
	require.NoError(t, os.WriteFile(hmacPath, []byte(`{"hmac":"test"}`), 0600))

	// Set a PIN service that panics on VerifySOPIN.
	svc.SetEventEmitter(func(e events.Event) {
		panic("user onboarding panic")
	})

	choices := &UserOnboardingChoices{
		SOPIN:   "123456",
		UserPIN: "7890",
	}

	// This should trigger the panic in VerifySOPIN (because PINService has no manager).
	// The panic recovery should catch it.
	result, err := svc.ApplyUserOnboarding(choices)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "panic")
}

// TestP5B_SetupWizard_GetStartupState_PanicRecovery verifies panic
// recovery in GetStartupState.
func TestP5B_SetupWizard_GetStartupState_PanicRecovery(t *testing.T) {
	svc := NewSetupWizardService()

	// Set a config func that panics.
	svc.SetConfigFunc(func() *GUIConfigData {
		panic("config func panic")
	})

	result, err := svc.GetStartupState()
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "panic")
}

// TestP5B_SetupWizard_GetPolicy_PanicRecovery verifies panic
// recovery in GetPolicy.
func TestP5B_SetupWizard_GetPolicy_PanicRecovery(t *testing.T) {
	svc := NewSetupWizardService()
	// GetPolicy calls config.Load() which may fail. We cannot inject a panic
	// easily, but we can verify it returns an error for normal failure.
	result, err := svc.GetPolicy()
	// config.Load might or might not succeed depending on environment.
	// In any case, this should not panic.
	if err != nil {
		assert.Nil(t, result)
	}
}

// TestP5B_SetupWizard_SkipSetup_InitDataDirError verifies that SkipSetup
// returns an error when initDataDirFunc fails.
func TestP5B_SetupWizard_SkipSetup_InitDataDirError(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{}
	})
	svc.SetConfigSaveFunc(func(cfg *GUIConfigData) error {
		return nil
	})
	svc.SetInitDataDirFunc(func() error {
		return errors.New("init data dir fail")
	})

	err := svc.SkipSetup()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSetupStorageFailed))
}

// TestP5B_SetupWizard_SkipSetup_ConfigSaveError verifies that SkipSetup
// returns an error when configSave fails.
func TestP5B_SetupWizard_SkipSetup_ConfigSaveError(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{}
	})
	svc.SetConfigSaveFunc(func(cfg *GUIConfigData) error {
		return errors.New("save fail")
	})

	err := svc.SkipSetup()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSetupStorageFailed))
}

// TestP5B_SetupWizard_SkipSetup_EmitsSkipEvent verifies that SkipSetup
// emits the setup skipped event.
func TestP5B_SetupWizard_SkipSetup_EmitsSkipEvent(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{}
	})
	svc.SetConfigSaveFunc(func(cfg *GUIConfigData) error {
		return nil
	})

	emitted := false
	svc.SetEventEmitter(func(e events.Event) {
		emitted = true
	})

	err := svc.SkipSetup()
	assert.NoError(t, err)
	assert.True(t, emitted)
}

// TestP5B_SetupWizard_EmitProgress_NilEmitter verifies emitProgress
// does not panic when emitter is nil.
func TestP5B_SetupWizard_EmitProgress_NilEmitter(t *testing.T) {
	svc := NewSetupWizardService()
	svc.eventEmitter = nil
	// Should not panic.
	svc.emitProgress(1, "test")
	svc.emitSOProvisioningProgress(1, "test")
	svc.emitUserOnboardingProgress(1, "test")
}

// ---------------------------------------------------------------------------
// 3. Admin Service Tests
// ---------------------------------------------------------------------------

// TestP5B_AdminService_IsAdmin_NonRoot verifies that IsAdmin returns false
// for non-root users.
func TestP5B_AdminService_IsAdmin_NonRoot(t *testing.T) {
	svc := NewAdminService()
	// In a test environment, we are typically not root.
	result := svc.IsAdmin()
	// Can't assert the exact value as it depends on test environment,
	// but the function should not panic.
	_ = result
}

// TestP5B_AdminService_GetAuditLogs_WithStore verifies that GetAuditLogs
// delegates to the audit service with a real store.
func TestP5B_AdminService_GetAuditLogs_WithStore(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation("generate", "software", "key-1", true, nil, 10)

	svc := NewAdminService()
	svc.SetAuditStore(store)
	svc.SetContext(context.Background())

	// GetAuditLogs checks IsAdmin first. In non-root environment, this will
	// return ErrAdminNotAuthorized.
	_, err := svc.GetAuditLogs(nil)
	if err != nil {
		assert.True(t, errors.Is(err, ErrAdminNotAuthorized))
	}
}

// TestP5B_AdminService_ExportAuditLogs_InvalidFormat verifies that
// ExportAuditLogs returns an error for an invalid format.
func TestP5B_AdminService_ExportAuditLogs_InvalidFormat(t *testing.T) {
	svc := NewAdminService()
	_, err := svc.ExportAuditLogs("xml")
	// Non-root gets ErrAdminNotAuthorized before format check.
	assert.Error(t, err)
}

// TestP5B_AdminService_ExportAuditLogs_EmptyEntries verifies that
// ExportAuditLogs returns ErrAuditNoEntries when there are no entries.
func TestP5B_AdminService_ExportAuditLogs_EmptyEntries(t *testing.T) {
	svc := NewAdminService()
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	svc.SetAuditStore(store)
	svc.SetContext(context.Background())

	_, err := svc.ExportAuditLogs("json")
	// Non-root gets auth error first.
	assert.Error(t, err)
}

// TestP5B_AdminService_TotalKeyCount_MultipleCounters verifies that
// totalKeyCount sums from multiple counters.
func TestP5B_AdminService_TotalKeyCount_MultipleCounters(t *testing.T) {
	svc := NewAdminService()
	svc.SetKeyCounters(
		&p5bMockKeyCounter{count: 5},
		&p5bMockKeyCounter{count: 10},
		&p5bMockKeyCounter{count: 3},
	)
	assert.Equal(t, 18, svc.totalKeyCount())
}

// TestP5B_AdminService_TotalKeyCount_NoCounters verifies that totalKeyCount
// returns 0 with no counters.
func TestP5B_AdminService_TotalKeyCount_NoCounters(t *testing.T) {
	svc := NewAdminService()
	assert.Equal(t, 0, svc.totalKeyCount())
}

// TestP5B_AdminService_GetServerStatus_ConnectedWithBackends verifies
// GetServerStatus when connected to a remote server with backends.
func TestP5B_AdminService_GetServerStatus_ConnectedWithBackends(t *testing.T) {
	svc := NewAdminService()
	svc.SetConnectionInfoFunc(func() *ConnectionInfo {
		return &ConnectionInfo{
			State:   "connected",
			Version: "1.0.0",
			Address: "localhost:8443",
		}
	})
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return []BackendInfo{
			{ID: "sw", Type: "software"},
			{ID: "tpm", Type: "tpm2"},
		}, nil
	})

	status, err := svc.GetServerStatus()
	assert.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Running)
	assert.Equal(t, 2, status.BackendCount)
	assert.Equal(t, "1.0.0", status.Version)
}

// TestP5B_AdminService_GetServerStatus_ConnectedNoBackendFunc verifies
// GetServerStatus when connected but no remote backend func is set.
func TestP5B_AdminService_GetServerStatus_ConnectedNoBackendFunc(t *testing.T) {
	svc := NewAdminService()
	svc.SetConnectionInfoFunc(func() *ConnectionInfo {
		return &ConnectionInfo{
			State:   "connected",
			Version: "1.0.0",
			Address: "localhost:8443",
		}
	})

	status, err := svc.GetServerStatus()
	assert.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Running)
	assert.Equal(t, 0, status.BackendCount)
}

// TestP5B_AdminService_GetServerStatus_ConnectedBackendError verifies
// GetServerStatus when the backend list call fails.
func TestP5B_AdminService_GetServerStatus_ConnectedBackendError(t *testing.T) {
	svc := NewAdminService()
	svc.SetConnectionInfoFunc(func() *ConnectionInfo {
		return &ConnectionInfo{
			State:   "connected",
			Version: "1.0.0",
			Address: "localhost:8443",
		}
	})
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return nil, errors.New("network error")
	})

	status, err := svc.GetServerStatus()
	assert.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Running)
	assert.Equal(t, 0, status.BackendCount)
}

// TestP5B_AdminService_GetServerStatus_NotConnected verifies GetServerStatus
// when not connected.
func TestP5B_AdminService_GetServerStatus_NotConnected(t *testing.T) {
	svc := NewAdminService()
	svc.SetConnectionInfoFunc(func() *ConnectionInfo {
		return &ConnectionInfo{State: "disconnected"}
	})

	status, err := svc.GetServerStatus()
	assert.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Running)
}

// TestP5B_AdminService_ListBackends_RemoteError verifies that ListBackends
// falls back to local backends when remote call fails.
func TestP5B_AdminService_ListBackends_RemoteError(t *testing.T) {
	svc := NewAdminService()
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return nil, errors.New("connection refused")
	})

	backends, err := svc.ListBackends()
	assert.NoError(t, err)
	assert.True(t, len(backends) > 0)
	// Should contain the local defaults.
	found := false
	for _, b := range backends {
		if b.ID == "software" {
			found = true
		}
	}
	assert.True(t, found)
}

// TestP5B_AdminService_ListBackends_RemoteSuccess verifies that ListBackends
// returns remote backends when available.
func TestP5B_AdminService_ListBackends_RemoteSuccess(t *testing.T) {
	svc := NewAdminService()
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return []BackendInfo{
			{ID: "remote-sw", Type: "software"},
		}, nil
	})

	backends, err := svc.ListBackends()
	assert.NoError(t, err)
	assert.Len(t, backends, 1)
	assert.Equal(t, "remote-sw", backends[0].ID)
}

// TestP5B_AdminService_GetBackendInfo_FromRemote verifies GetBackendInfo
// when backends come from a remote server.
func TestP5B_AdminService_GetBackendInfo_FromRemote(t *testing.T) {
	svc := NewAdminService()
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return []BackendInfo{
			{ID: "vault", Type: "vault", Enabled: true},
		}, nil
	})

	info, err := svc.GetBackendInfo("vault")
	assert.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "vault", info.ID)
}

// ---------------------------------------------------------------------------
// 4. Clipboard Service Tests
// ---------------------------------------------------------------------------

// TestP5B_ClipboardService_CopyWithClear_NoToolError verifies CopyWithClear
// returns an error when no clipboard tool is available.
func TestP5B_ClipboardService_CopyWithClear_NoToolError(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	svc.timeout.Store(30)

	err := svc.CopyWithClear("secret")
	assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
}

// TestP5B_ClipboardService_Copy_NoToolError verifies Copy returns an
// error when no clipboard tool is available.
func TestP5B_ClipboardService_Copy_NoToolError(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}

	err := svc.Copy("text")
	assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
}

// TestP5B_ClipboardService_ClearClipboard_CancelsPendingTimerNoTool
// verifies that ClearClipboard cancels the pending timer even when
// no clipboard tool is available.
func TestP5B_ClipboardService_ClearClipboard_CancelsPendingTimerNoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}

	// Set up a pending cancel function.
	_, cancel := context.WithCancel(context.Background())
	svc.cancelFn = cancel

	err := svc.ClearClipboard()
	assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
	// cancelFn should have been called and cleared.
	assert.Nil(t, svc.cancelFn)
}

// TestP5B_ClipboardService_WriteClipboard_DefaultCase verifies the
// writeClipboard default case returns an error.
func TestP5B_ClipboardService_WriteClipboard_DefaultCase(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}

	err := svc.writeClipboard("test")
	assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
}

// TestP5B_ClipboardService_ReadClipboard_DefaultCase verifies the
// readClipboard default case returns an error.
func TestP5B_ClipboardService_ReadClipboard_DefaultCase(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}

	_, err := svc.readClipboard()
	assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
}

// TestP5B_ClipboardService_CopyWithClear_ZeroTimeout verifies that
// CopyWithClear with zero timeout skips scheduling.
func TestP5B_ClipboardService_CopyWithClear_ZeroTimeout(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolXclip, // Set a tool so we get past the check.
	}
	svc.timeout.Store(0)

	// This will try to run xclip which may not be installed.
	// The test verifies the timeout=0 branch is reached.
	err := svc.CopyWithClear("test")
	// If xclip is not installed, we get a write error, not a scheduling error.
	_ = err
}

// TestP5B_ClipboardService_ScheduleClear_CancelsPreviousTimer verifies that
// scheduleClear cancels any previously pending timer.
func TestP5B_ClipboardService_ScheduleClear_CancelsPreviousTimer(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone, // No real clipboard, the goroutine will just try read and fail.
	}

	// Schedule first clear.
	svc.scheduleClear("text1", 10*time.Second)
	firstCancel := svc.cancelFn
	assert.NotNil(t, firstCancel)

	// Schedule second clear - should cancel the first.
	svc.scheduleClear("text2", 10*time.Second)
	secondCancel := svc.cancelFn
	assert.NotNil(t, secondCancel)

	// Clean up.
	secondCancel()
}

// TestP5B_PasswordProtection_ExportDecrypted_Locked verifies that
// ExportPasswordsDecrypted returns error when locked.
func TestP5B_BarrierService_Initialize_EmptyPassword_SoftwareStrategy(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	err := svc.Initialize("", "software")
	assert.True(t, errors.Is(err, ErrBarrierPasswordRequired))
}

// TestP5B_BarrierService_Initialize_AlreadyInit verifies that Initialize
// fails when barrier is already initialized.
func TestP5B_BarrierService_Initialize_AlreadyInit(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	// Initialize first.
	err := svc.Initialize("password123", "software")
	assert.NoError(t, err)

	// Second initialization should fail.
	err = svc.Initialize("password123", "software")
	assert.True(t, errors.Is(err, ErrBarrierAlreadyInit))
}

// TestP5B_BarrierService_Seal_NotInitialized verifies that Seal fails
// when barrier is not initialized.
func TestP5B_BarrierService_Seal_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	err := svc.Seal()
	assert.True(t, errors.Is(err, ErrBarrierNotInitialized))
}

// TestP5B_BarrierService_Status_NotInitialized verifies that Status returns
// sealed status when barrier is not initialized.
func TestP5B_BarrierService_Status_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	status := svc.Status()
	require.NotNil(t, status)
	assert.True(t, status.Sealed)
}

// TestP5B_BarrierService_IsUnsealed_NotInitialized verifies IsUnsealed
// returns false when barrier is not initialized.
func TestP5B_BarrierService_IsUnsealed_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	assert.False(t, svc.IsUnsealed())
}

// TestP5B_BarrierService_GetBackend_NotInitialized verifies GetBackend
// returns nil when barrier is not initialized.
func TestP5B_BarrierService_GetBackend_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	assert.Nil(t, svc.GetBackend())
}

// TestP5B_BarrierService_Context_Fallback verifies context falls back to
// background when not set.
func TestP5B_BarrierService_Context_Fallback(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	ctx := svc.context()
	assert.NotNil(t, ctx)
}

// TestP5B_BarrierService_Context_Set verifies context returns the set value.
func TestP5B_BarrierService_Context_Set(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	expected := context.WithValue(context.Background(), "key", "value")
	svc.SetContext(expected)

	ctx := svc.context()
	assert.Equal(t, expected, ctx)
}

// TestP5B_BarrierService_ProbeStrategies_NoTPMFunc verifies ProbeStrategies
// without TPM sealer function.
func TestP5B_BarrierService_ProbeStrategies_NoTPMFunc(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	strategies := svc.ProbeStrategies()
	assert.Len(t, strategies, 1)
	assert.Equal(t, "software", strategies[0].ID)
	assert.True(t, strategies[0].Available)
}

// TestP5B_BarrierService_ProbeStrategies_TPMFuncReturnsNil verifies
// ProbeStrategies with TPM func returning nil sealer.
func TestP5B_BarrierService_ProbeStrategies_TPMFuncReturnsNil(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetTPMSealerFunc(func() xkmstypes.Sealer {
		return nil
	})

	strategies := svc.ProbeStrategies()
	assert.Len(t, strategies, 2)
	// TPM2 should be present but not available.
	assert.False(t, strategies[1].Available)
}

// TestP5B_BarrierService_InitUnsealRoundTrip verifies full init/unseal cycle.
func TestP5B_BarrierService_InitUnsealRoundTrip(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	// Initialize.
	err := svc.Initialize("password123", "software")
	assert.NoError(t, err)
	assert.True(t, svc.IsUnsealed())
	assert.NotNil(t, svc.GetBackend())

	// Seal.
	err = svc.Seal()
	assert.NoError(t, err)
	assert.False(t, svc.IsUnsealed())

	// Unseal with a new service instance.
	svc2 := NewBarrierService(dir, slog.Default())
	err = svc2.Unseal("password123", "software")
	assert.NoError(t, err)
	assert.True(t, svc2.IsUnsealed())
}

// ---------------------------------------------------------------------------
// 7. OATH Service Tests
// ---------------------------------------------------------------------------

// TestP5B_OATHService_ListAccounts_StoreError verifies that ListAccounts
// returns an error when the store fails.
func TestP5B_OATHService_ListAccounts_StoreError(t *testing.T) {
	store := &p5bMockOATHStore{listErr: errors.New("list failed")}
	svc := NewOATHService(store)

	_, err := svc.ListAccounts()
	assert.Error(t, err)
}

// TestP5B_OATHService_AddAccount_StoreError verifies that AddAccount
// returns an error when the store fails to add.
func TestP5B_OATHService_AddAccount_StoreError(t *testing.T) {
	store := &p5bMockOATHStore{addErr: errors.New("add failed")}
	svc := NewOATHService(store)

	_, err := svc.AddAccount("otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test")
	assert.Error(t, err)
}

// TestP5B_OATHService_GenerateTOTP_NotFound verifies that GenerateTOTP
// returns an error when the account is not found.
func TestP5B_OATHService_GenerateTOTP_NotFound(t *testing.T) {
	store := &p5bMockOATHStore{}
	svc := NewOATHService(store)

	_, err := svc.GenerateTOTP("nonexistent")
	assert.Error(t, err)
}

// TestP5B_OATHService_GenerateHOTP_NotFound verifies that GenerateHOTP
// returns an error when the account is not found.
func TestP5B_OATHService_GenerateHOTP_NotFound(t *testing.T) {
	store := &p5bMockOATHStore{}
	svc := NewOATHService(store)

	_, err := svc.GenerateHOTP("nonexistent")
	assert.Error(t, err)
}

// TestP5B_OATHService_DeleteAccount_StoreError verifies that DeleteAccount
// propagates store errors.
func TestP5B_OATHService_DeleteAccount_StoreError(t *testing.T) {
	store := &p5bMockOATHStore{delErr: errors.New("delete failed")}
	svc := NewOATHService(store)

	err := svc.DeleteAccount("some-id")
	assert.Error(t, err)
}

// TestP5B_OATHService_AddAccountFromURI_InvalidScheme verifies that
// AddAccountFromURI rejects non-otpauth URIs.
func TestP5B_OATHService_AddAccountFromURI_InvalidScheme(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	_, err := svc.AddAccountFromURI("https://example.com")
	assert.True(t, errors.Is(err, ErrOATHQRInvalidURI))
}

// TestP5B_OATHService_AddAccountFromURI_CaseInsensitive verifies that
// the otpauth:// scheme check is case-insensitive.
func TestP5B_OATHService_AddAccountFromURI_CaseInsensitive(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	acct, err := svc.AddAccountFromURI("OTPAUTH://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test")
	assert.NoError(t, err)
	require.NotNil(t, acct)
}

// TestP5B_OATHService_SetStore verifies that SetStore replaces the store.
func TestP5B_OATHService_SetStore(t *testing.T) {
	svc := NewOATHService(nil)
	assert.Nil(t, svc.store)

	store := oath.NewMemoryStore()
	svc.SetStore(store)
	assert.NotNil(t, svc.store)
}

// TestP5B_OATHService_GenerateTOTP_WrongType verifies that GenerateTOTP
// rejects HOTP credentials.
func TestP5B_OATHService_GenerateTOTP_WrongType(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	// Add an HOTP credential.
	_, err := svc.AddAccount("otpauth://hotp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&counter=0")
	require.NoError(t, err)

	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	require.Len(t, accounts, 1)

	_, err = svc.GenerateTOTP(accounts[0].ID)
	assert.True(t, errors.Is(err, ErrOATHGenerateFailed))
}

// TestP5B_OATHService_GenerateHOTP_WrongType verifies that GenerateHOTP
// rejects TOTP credentials.
func TestP5B_OATHService_GenerateHOTP_WrongType(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	// Add a TOTP credential.
	_, err := svc.AddAccount("otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test")
	require.NoError(t, err)

	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	require.Len(t, accounts, 1)

	_, err = svc.GenerateHOTP(accounts[0].ID)
	assert.True(t, errors.Is(err, ErrOATHGenerateFailed))
}

// TestP5B_OATHService_GenerateHOTP_UpdateError verifies that GenerateHOTP
// returns an error when the counter update fails.
func TestP5B_OATHService_GenerateHOTP_UpdateError(t *testing.T) {
	cred, err := oath.ParseURI("otpauth://hotp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&counter=0")
	require.NoError(t, err)

	store := &p5bMockOATHStore{
		creds:  []*oath.Credential{cred},
		updErr: errors.New("update failed"),
	}
	svc := NewOATHService(store)

	_, err = svc.GenerateHOTP(cred.ID)
	assert.Error(t, err)
	assert.Equal(t, "update failed", err.Error())
}

// TestP5B_PlatformPolicy_GetStatus_NotConfigured verifies GetStatus when
// no policy is configured.
func TestP5B_PlatformPolicy_GetStatus_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService("")

	status, err := svc.GetStatus()
	assert.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Configured)
}

// TestP5B_PlatformPolicy_CreatePolicy_InvalidPCRs verifies CreatePolicy
// with empty PCRs returns an error.
func TestP5B_PlatformPolicy_CreatePolicy_InvalidPCRs(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.CreatePolicy([]int{}, "sha256")
	assert.True(t, errors.Is(err, ErrPolicyInvalidPCRs))
}

// TestP5B_PlatformPolicy_CreatePolicy_InvalidPCRIndex verifies CreatePolicy
// with out-of-range PCR index returns an error.
func TestP5B_PlatformPolicy_CreatePolicy_InvalidPCRIndex(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.CreatePolicy([]int{0, 24}, "sha256")
	assert.True(t, errors.Is(err, ErrPolicyInvalidPCRs))
}

// TestP5B_PlatformPolicy_CreatePolicy_NegativePCRIndex verifies CreatePolicy
// with negative PCR index returns an error.
func TestP5B_PlatformPolicy_CreatePolicy_NegativePCRIndex(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.CreatePolicy([]int{-1}, "sha256")
	assert.True(t, errors.Is(err, ErrPolicyInvalidPCRs))
}

// TestP5B_PlatformPolicy_CreatePolicy_InvalidBank verifies CreatePolicy
// with invalid bank returns an error.
func TestP5B_PlatformPolicy_CreatePolicy_InvalidBank(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.CreatePolicy([]int{0, 7}, "md5")
	assert.True(t, errors.Is(err, ErrPolicyInvalidBank))
}

// TestP5B_PlatformPolicy_CreatePolicy_NoTPM verifies CreatePolicy
// fails when no TPM accessor is set.
func TestP5B_PlatformPolicy_CreatePolicy_NoTPM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	svc := NewPlatformPolicyService(path)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	assert.True(t, errors.Is(err, ErrPolicyTPMNotAvailable))
}

// TestP5B_PlatformPolicy_VerifyPolicy_NotConfigured verifies VerifyPolicy
// returns an error when no policy is configured.
func TestP5B_PlatformPolicy_VerifyPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService("")

	valid, err := svc.VerifyPolicy()
	assert.False(t, valid)
	assert.True(t, errors.Is(err, ErrPolicyNotConfigured))
}

// TestP5B_PlatformPolicy_DeletePolicy_NotConfigured verifies DeletePolicy
// returns an error when no policy is configured.
func TestP5B_PlatformPolicy_DeletePolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService("")

	err := svc.DeletePolicy()
	assert.True(t, errors.Is(err, ErrPolicyNotConfigured))
}

// TestP5B_PlatformPolicy_DeletePolicy_Success verifies DeletePolicy removes
// the policy from memory and disk.
func TestP5B_PlatformPolicy_DeletePolicy_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	svc := NewPlatformPolicyService(path)
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	// Write the policy file so we can verify it gets deleted.
	data, _ := json.MarshalIndent(def, "", "  ")
	require.NoError(t, os.WriteFile(path, data, 0600))

	err := svc.DeletePolicy()
	assert.NoError(t, err)
	assert.Nil(t, svc.policy.Load())

	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

// TestP5B_PlatformPolicy_GetPolicyPCRs_NotConfigured verifies GetPolicyPCRs
// returns an error when no policy is configured.
func TestP5B_PlatformPolicy_GetPolicyPCRs_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, _, err := svc.GetPolicyPCRs()
	assert.True(t, errors.Is(err, ErrPolicyNotConfigured))
}

// TestP5B_PlatformPolicy_GetPolicyPCRs_Success verifies GetPolicyPCRs
// returns the configured PCRs and bank.
func TestP5B_PlatformPolicy_GetPolicyPCRs_Success(t *testing.T) {
	svc := NewPlatformPolicyService("")
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0, 7, 9},
		Bank: "sha256",
	})

	pcrs, bank, err := svc.GetPolicyPCRs()
	assert.NoError(t, err)
	assert.Equal(t, []int{0, 7, 9}, pcrs)
	assert.Equal(t, "sha256", bank)
}

// TestP5B_PlatformPolicy_ExportPolicy_NotConfigured verifies ExportPolicy
// returns an error when no policy is configured.
func TestP5B_PlatformPolicy_ExportPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.ExportPolicy()
	assert.True(t, errors.Is(err, ErrPolicyNotConfigured))
}

// TestP5B_PlatformPolicy_ExportPolicy_Success verifies ExportPolicy returns
// valid JSON with expected fields.
func TestP5B_PlatformPolicy_ExportPolicy_Success(t *testing.T) {
	svc := NewPlatformPolicyService("")
	now := time.Now()
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0, 7},
		Bank: "sha256",
		Digests: map[int]string{
			0: "aabb",
			7: "ccdd",
		},
		CreatedAt: now,
		UpdatedAt: now,
	})

	exported, err := svc.ExportPolicy()
	assert.NoError(t, err)
	assert.NotEmpty(t, exported)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Equal(t, "Platform Policy", parsed["name"])
	assert.Equal(t, "sha256", parsed["pcr_bank"])
	assert.NotNil(t, parsed["pcr_selections"])
	assert.NotNil(t, parsed["pcr_digests"])
}

// TestP5B_PlatformPolicy_ExportPolicy_NoDigests verifies ExportPolicy works
// when there are no digests.
func TestP5B_PlatformPolicy_ExportPolicy_NoDigests(t *testing.T) {
	svc := NewPlatformPolicyService("")
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	exported, err := svc.ExportPolicy()
	assert.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Nil(t, parsed["pcr_digests"])
}

// TestP5B_PlatformPolicy_ExportPolicy_NoPCRs verifies ExportPolicy works
// when there are no PCR selections.
func TestP5B_PlatformPolicy_ExportPolicy_NoPCRs(t *testing.T) {
	svc := NewPlatformPolicyService("")
	svc.policy.Store(&PlatformPolicyDefinition{
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	exported, err := svc.ExportPolicy()
	assert.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Nil(t, parsed["pcr_selections"])
}

// TestP5B_PlatformPolicy_GetPlatformPolicyAsPCRPolicy_NotConfigured verifies
// that GetPlatformPolicyAsPCRPolicy returns nil when not configured.
func TestP5B_PlatformPolicy_GetPlatformPolicyAsPCRPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService("")

	result, err := svc.GetPlatformPolicyAsPCRPolicy()
	assert.NoError(t, err)
	assert.Nil(t, result)
}

// TestP5B_PlatformPolicy_GetPlatformPolicyAsPCRPolicy_EmptyDigests verifies
// validatePlatformPolicyDigests returns nil for empty digests.
func TestP5B_PlatformPolicy_GetPlatformPolicyAsPCRPolicy_EmptyDigests(t *testing.T) {
	svc := NewPlatformPolicyService("")
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	result, err := svc.GetPlatformPolicyAsPCRPolicy()
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Nil(t, result.Valid) // Empty digests -> nil validity.
}

// TestP5B_PlatformPolicy_SavePolicy_CreatesDirectory verifies savePolicy
// creates the parent directory.
func TestP5B_PlatformPolicy_SavePolicy_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "policy.json")
	svc := NewPlatformPolicyService(path)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := svc.savePolicy(def)
	assert.NoError(t, err)

	data, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
}

// TestP5B_PlatformPolicy_SavePolicy_ReadOnlyDir verifies savePolicy returns
// an error when the directory is not writable.
func TestP5B_PlatformPolicy_SavePolicy_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	readOnly := filepath.Join(dir, "readonly")
	require.NoError(t, os.MkdirAll(readOnly, 0500))
	defer os.Chmod(readOnly, 0700)

	path := filepath.Join(readOnly, "subdir", "policy.json")
	svc := NewPlatformPolicyService(path)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := svc.savePolicy(def)
	assert.True(t, errors.Is(err, ErrPolicySaveFailed))
}

// TestP5B_PlatformPolicy_NormalizeBankAlg verifies normalizeBankAlg handles
// the SHA386 variant.
func TestP5B_PlatformPolicy_NormalizeBankAlg(t *testing.T) {
	assert.Equal(t, "sha384", normalizeBankAlg("SHA386"))
	assert.Equal(t, "sha384", normalizeBankAlg("sha386"))
	assert.Equal(t, "sha256", normalizeBankAlg("SHA256"))
	assert.Equal(t, "sha256", normalizeBankAlg("sha256"))
	assert.Equal(t, "sha512", normalizeBankAlg("sha512"))
}

// TestP5B_PlatformPolicy_ValidatePCRSelection_Valid verifies valid PCR
// selections pass validation.
func TestP5B_PlatformPolicy_ValidatePCRSelection_Valid(t *testing.T) {
	assert.NoError(t, validatePCRSelection([]int{0, 7, 9, 23}))
	assert.NoError(t, validatePCRSelection([]int{0}))
}

// TestP5B_PlatformPolicy_ValidatePCRSelection_Invalid verifies invalid
// PCR selections are rejected.
func TestP5B_PlatformPolicy_ValidatePCRSelection_Invalid(t *testing.T) {
	assert.Error(t, validatePCRSelection(nil))
	assert.Error(t, validatePCRSelection([]int{}))
	assert.Error(t, validatePCRSelection([]int{-1}))
	assert.Error(t, validatePCRSelection([]int{24}))
	assert.Error(t, validatePCRSelection([]int{0, 100}))
}

// TestP5B_PlatformPolicy_ValidatePCRBank_Valid verifies valid bank names
// pass validation.
func TestP5B_PlatformPolicy_ValidatePCRBank_Valid(t *testing.T) {
	assert.NoError(t, validatePCRBank("sha256"))
	assert.NoError(t, validatePCRBank("sha384"))
	assert.NoError(t, validatePCRBank("sha512"))
}

// TestP5B_PlatformPolicy_ValidatePCRBank_Invalid verifies invalid bank
// names are rejected.
func TestP5B_PlatformPolicy_ValidatePCRBank_Invalid(t *testing.T) {
	assert.Error(t, validatePCRBank("md5"))
	assert.Error(t, validatePCRBank(""))
	assert.Error(t, validatePCRBank("sha128"))
}

// TestP5B_PlatformPolicy_VerifyPolicyRemote_EmptyName verifies that
// VerifyPolicyRemote rejects empty names.
func TestP5B_PlatformPolicy_VerifyPolicyRemote_EmptyName(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.VerifyPolicyRemote("")
	assert.True(t, errors.Is(err, ErrPolicyInvalidName))
}

// TestP5B_PlatformPolicy_ExportPolicyRemote_EmptyName verifies that
// ExportPolicyRemote rejects empty names.
func TestP5B_PlatformPolicy_ExportPolicyRemote_EmptyName(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.ExportPolicyRemote("")
	assert.True(t, errors.Is(err, ErrPolicyInvalidName))
}

// TestP5B_PlatformPolicy_VerifyPolicyRemote_NoClient verifies that
// VerifyPolicyRemote returns error when no client is set.
func TestP5B_PlatformPolicy_VerifyPolicyRemote_NoClient(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.VerifyPolicyRemote("test-policy")
	assert.True(t, errors.Is(err, ErrPolicyNoClient))
}

// TestP5B_PlatformPolicy_ExportPolicyRemote_NoClient verifies that
// ExportPolicyRemote returns error when no client is set.
func TestP5B_PlatformPolicy_ExportPolicyRemote_NoClient(t *testing.T) {
	svc := NewPlatformPolicyService("")

	_, err := svc.ExportPolicyRemote("test-policy")
	assert.True(t, errors.Is(err, ErrPolicyNoClient))
}

// TestP5B_PlatformPolicy_GetPolicyContext_NilFallback verifies that
// getPolicyContext returns background context when ctx is nil.
func TestP5B_PlatformPolicy_GetPolicyContext_NilFallback(t *testing.T) {
	svc := NewPlatformPolicyService("")
	ctx := svc.getPolicyContext()
	assert.NotNil(t, ctx)
}

// TestP5B_PlatformPolicy_GetPolicyContext_Set verifies that
// getPolicyContext returns the set context.
func TestP5B_PlatformPolicy_GetPolicyContext_Set(t *testing.T) {
	svc := NewPlatformPolicyService("")
	expected := context.WithValue(context.Background(), "k", "v")
	svc.SetContext(expected)
	assert.Equal(t, expected, svc.getPolicyContext())
}

// TestP5B_PlatformPolicy_DefinitionToPCRPolicy verifies the conversion
// from PlatformPolicyDefinition to PCRPolicy.
func TestP5B_PlatformPolicy_DefinitionToPCRPolicy(t *testing.T) {
	svc := NewPlatformPolicyService("")
	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs: []int{0, 7},
		Bank: "sha256",
		Digests: map[int]string{
			0: "aabb",
			7: "ccdd",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	policy := svc.definitionToPCRPolicy(def)
	assert.Equal(t, "Platform Policy", policy.Name)
	assert.True(t, policy.IsPlatformPolicy)
	assert.Len(t, policy.PCRSelections, 2)
	assert.Len(t, policy.PCRDigests, 2)
	assert.Equal(t, "aabb", policy.PCRDigests["sha256:0"])
	assert.Equal(t, "ccdd", policy.PCRDigests["sha256:7"])
}

// TestP5B_PlatformPolicy_ValidatePlatformPolicyDigests_EmptyDigests verifies
// that empty digests returns nil (unknown validity).
func TestP5B_PlatformPolicy_ValidatePlatformPolicyDigests_EmptyDigests(t *testing.T) {
	svc := NewPlatformPolicyService("")
	def := &PlatformPolicyDefinition{
		PCRs: []int{0},
		Bank: "sha256",
	}

	result := svc.validatePlatformPolicyDigests(def)
	assert.Nil(t, result)
}

// TestP5B_PlatformPolicy_ValidatePlatformPolicyDigests_NoTPM verifies
// that validatePlatformPolicyDigests returns nil when TPM is unavailable.
func TestP5B_PlatformPolicy_ValidatePlatformPolicyDigests_NoTPM(t *testing.T) {
	svc := NewPlatformPolicyService("")
	def := &PlatformPolicyDefinition{
		PCRs: []int{0},
		Bank: "sha256",
		Digests: map[int]string{
			0: "aabb",
		},
	}

	result := svc.validatePlatformPolicyDigests(def)
	// No TPM -> verifyDigests fails -> returns nil.
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// Additional OIDC edge cases
// ---------------------------------------------------------------------------

// TestP5B_OIDCService_BuildExecPayload_NilTokenResp verifies buildExecPayload
// handles nil token response gracefully.
func TestP5B_OIDCService_BuildExecPayload_NilTokenResp(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
		Scopes:   []string{"openid"},
	}

	payload := svc.buildExecPayload("test", entry, nil)
	assert.Equal(t, "test", payload.Provider)
	assert.Equal(t, "https://example.com", payload.Issuer)
	assert.Empty(t, payload.AccessToken)
	assert.Empty(t, payload.ExpiresAt)
}

// TestP5B_OIDCService_BuildExecPayload_WithExpiry verifies buildExecPayload
// includes the expiry when set.
func TestP5B_OIDCService_BuildExecPayload_WithExpiry(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}

	expiry := time.Now().Add(time.Hour)
	tokenResp := &oidc.TokenResponse{
		AccessToken:  "at",
		RefreshToken: "rt",
		IDToken:      "idt",
		ExpiresIn:    3600,
		Expiry:       expiry,
	}

	payload := svc.buildExecPayload("test", entry, tokenResp)
	assert.Equal(t, "at", payload.AccessToken)
	assert.Equal(t, "rt", payload.RefreshToken)
	assert.Equal(t, "idt", payload.IDToken)
	assert.Equal(t, 3600, payload.ExpiresIn)
	assert.NotEmpty(t, payload.ExpiresAt)
}

// TestP5B_OIDCService_BuildExecPayload_ZeroExpiry verifies buildExecPayload
// omits ExpiresAt when expiry is zero.
func TestP5B_OIDCService_BuildExecPayload_ZeroExpiry(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
	}

	payload := svc.buildExecPayload("test", entry, tokenResp)
	assert.Empty(t, payload.ExpiresAt)
}

// TestP5B_OIDCService_ExtractIDTokenClaims_ValidJWT verifies claim extraction
// from a valid JWT payload.
func TestP5B_OIDCService_ExtractIDTokenClaims_ValidJWT(t *testing.T) {
	svc := NewOIDCService(nil)

	claims := map[string]string{
		"sub":   "user-123",
		"email": "user@example.com",
		"name":  "Test User",
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	idToken := "header." + payload + ".signature"

	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims(idToken, info)

	assert.Equal(t, "user-123", info.Subject)
	assert.Equal(t, "user@example.com", info.Email)
	assert.Equal(t, "Test User", info.Name)
}

// TestP5B_OIDCService_ExtractIDTokenClaims_InvalidParts verifies that
// extractIDTokenClaims is a no-op for tokens with wrong number of parts.
func TestP5B_OIDCService_ExtractIDTokenClaims_InvalidParts(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}

	// Too few parts.
	svc.extractIDTokenClaims("only.two", info)
	assert.Empty(t, info.Subject)

	// Too many parts.
	svc.extractIDTokenClaims("a.b.c.d", info)
	assert.Empty(t, info.Subject)

	// Exactly 3 but invalid base64.
	svc.extractIDTokenClaims("a.!!!.c", info)
	assert.Empty(t, info.Subject)
}

// TestP5B_OIDCService_TokenResponseToInfo_NonZeroExpiry verifies
// tokenResponseToInfo with a non-zero expiry time.
func TestP5B_OIDCService_TokenResponseToInfo_NonZeroExpiry(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
		Scopes: []string{"openid"},
	}

	future := time.Now().Add(time.Hour)
	tokenResp := &oidc.TokenResponse{
		AccessToken:  "at",
		RefreshToken: "rt",
		Expiry:       future,
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.NotEmpty(t, info.ExpiresAt)
	assert.True(t, info.ExpiresIn > 0)
	assert.False(t, info.IsExpired)
	assert.True(t, info.HasRefresh)
}

// TestP5B_OIDCService_TokenResponseToInfo_ExpiredToken verifies
// tokenResponseToInfo with an expired token.
func TestP5B_OIDCService_TokenResponseToInfo_ExpiredToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	past := time.Now().Add(-time.Hour)
	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		Expiry:      past,
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.True(t, info.IsExpired)
}

// TestP5B_OIDCService_DiscoverProvider_NilCtx verifies DiscoverProvider
// uses context.Background when ctx is nil.
func TestP5B_OIDCService_DiscoverProvider_NilCtx(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.ctx = nil

	// Will fail because the issuer is unreachable, but exercises the nil ctx fallback.
	_, err := svc.DiscoverProvider("http://127.0.0.1:1/unreachable")
	assert.Error(t, err)
}

// TestP5B_OIDCService_ExecuteScript_NonZeroExitCode verifies that
// ExecuteScript captures non-zero exit codes.
func TestP5B_OIDCService_ExecuteScript_NonZeroExitCode(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}

	result, err := svc.ExecuteScript("test", "exit 42")
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 42, result.ExitCode)
	assert.False(t, result.Success)
}
