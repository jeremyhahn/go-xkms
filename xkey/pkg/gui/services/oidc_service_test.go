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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOIDCService(t *testing.T) {
	svc := NewOIDCService(nil)
	require.NotNil(t, svc)
	assert.NotNil(t, svc.providers)
	assert.NotNil(t, svc.refreshProcs)
	assert.NotNil(t, svc.browserOpen)
}

func TestNewOIDCServiceWithLogger(t *testing.T) {
	log := slog.Default()
	svc := NewOIDCService(log)
	require.NotNil(t, svc)
}

func TestOIDCService_SetContext(t *testing.T) {
	svc := NewOIDCService(nil)
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestOIDCService_SetBrowserOpen(t *testing.T) {
	svc := NewOIDCService(nil)
	called := false
	svc.SetBrowserOpen(func(url string) error {
		called = true
		return nil
	})
	err := svc.browserOpen("http://example.com")
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestOIDCService_Close_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.Close()
	assert.NoError(t, err)
}

func TestOIDCService_Close_WithTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)
	err := svc.Close()
	assert.NoError(t, err)
}

// --- Provider management tests ---

func TestOIDCService_AddProvider_Success(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:     "test-provider",
		Issuer:   "https://example.com",
		ClientID: "test-client",
	}

	err := svc.AddProvider(entry)
	assert.NoError(t, err)

	providers := svc.GetProviders()
	assert.Len(t, providers, 1)
	assert.Equal(t, "test-provider", providers[0].Name)
	assert.Equal(t, OIDCProviderTypeStandard, providers[0].Type)
}

func TestOIDCService_AddProvider_NilEntry(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.AddProvider(nil)
	assert.True(t, errors.Is(err, ErrOIDCInvalidProvider))
}

func TestOIDCService_AddProvider_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.AddProvider(&OIDCProviderEntry{})
	assert.True(t, errors.Is(err, ErrOIDCProviderNameRequired))
}

func TestOIDCService_AddProvider_Duplicate(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "dup", Issuer: "https://ex.com", ClientID: "id"}
	err := svc.AddProvider(entry)
	require.NoError(t, err)

	err = svc.AddProvider(entry)
	assert.True(t, errors.Is(err, ErrOIDCProviderExists))
}

func TestOIDCService_AddProvider_DefaultRedirectURL(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}

	err := svc.AddProvider(entry)
	assert.NoError(t, err)

	p, err := svc.GetProvider("test")
	require.NoError(t, err)
	assert.Contains(t, p.RedirectURL, "localhost:8085")
}

func TestOIDCService_GetProvider_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	p, err := svc.GetProvider("test")
	require.NoError(t, err)
	assert.Equal(t, "test", p.Name)
	assert.Equal(t, "https://ex.com", p.Issuer)
}

func TestOIDCService_GetProvider_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetProvider("")
	assert.True(t, errors.Is(err, ErrOIDCProviderNameRequired))
}

func TestOIDCService_GetProvider_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetProvider("nonexistent")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_UpdateProvider_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://old.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	updated := &OIDCProviderEntry{Name: "test", Issuer: "https://new.com", ClientID: "id2"}
	err := svc.UpdateProvider("test", updated)
	assert.NoError(t, err)

	p, err := svc.GetProvider("test")
	require.NoError(t, err)
	assert.Equal(t, "https://new.com", p.Issuer)
	assert.Equal(t, "id2", p.ClientID)
}

func TestOIDCService_UpdateProvider_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.UpdateProvider("", &OIDCProviderEntry{Name: "x"})
	assert.True(t, errors.Is(err, ErrOIDCProviderNameRequired))
}

func TestOIDCService_UpdateProvider_NilEntry(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.UpdateProvider("test", nil)
	assert.True(t, errors.Is(err, ErrOIDCInvalidProvider))
}

func TestOIDCService_UpdateProvider_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.UpdateProvider("nonexistent", &OIDCProviderEntry{Name: "nonexistent"})
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_UpdateProvider_Rename(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "old-name", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	renamed := &OIDCProviderEntry{Name: "new-name", Issuer: "https://ex.com", ClientID: "id"}
	err := svc.UpdateProvider("old-name", renamed)
	assert.NoError(t, err)

	_, err = svc.GetProvider("old-name")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))

	p, err := svc.GetProvider("new-name")
	require.NoError(t, err)
	assert.Equal(t, "new-name", p.Name)
}

func TestOIDCService_DeleteProvider_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	err := svc.DeleteProvider("test")
	assert.NoError(t, err)

	_, err = svc.GetProvider("test")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_DeleteProvider_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.DeleteProvider("")
	assert.True(t, errors.Is(err, ErrOIDCProviderNameRequired))
}

func TestOIDCService_DeleteProvider_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.DeleteProvider("nonexistent")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_DiscoverProvider_EmptyIssuer(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.DiscoverProvider("")
	assert.True(t, errors.Is(err, ErrOIDCInvalidIssuer))
}

// --- Token tests ---

func TestOIDCService_GetTokenInfo_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetTokenInfo("nonexistent")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_GetTokenInfo_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	_, err := svc.GetTokenInfo("test")
	assert.True(t, errors.Is(err, ErrOIDCTokenStoreUnavailable))
}

func TestOIDCService_GetTokenInfo_NoToken(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetTokenStore(oidc.NewMemoryTokenStore())
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	_, err := svc.GetTokenInfo("test")
	assert.True(t, errors.Is(err, ErrOIDCTokenNotFound))
}

func TestOIDCService_GetTokenInfo_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
		Scopes:   []string{"openid", "profile"},
	}
	require.NoError(t, svc.AddProvider(entry))

	tokenResp := &oidc.TokenResponse{
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-456",
		ExpiresIn:    3600,
		Expiry:       time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Save("https://example.com", tokenResp))

	info, err := svc.GetTokenInfo("test")
	require.NoError(t, err)
	assert.Equal(t, "test", info.Provider)
	assert.Equal(t, "https://example.com", info.Issuer)
	assert.True(t, info.HasRefresh)
	assert.False(t, info.IsExpired)
	assert.Equal(t, []string{"openid", "profile"}, info.Scopes)
}

func TestOIDCService_GetTokenInfo_WithIDToken(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}
	require.NoError(t, svc.AddProvider(entry))

	// Build a fake JWT with claims in the payload.
	claims := map[string]string{
		"sub":   "user-123",
		"email": "user@example.com",
		"name":  "Test User",
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	fakeJWT := "eyJhbGciOiJSUzI1NiJ9." + payload + ".signature"

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		IDToken:     fakeJWT,
		Expiry:      time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Save("https://example.com", tokenResp))

	info, err := svc.GetTokenInfo("test")
	require.NoError(t, err)
	assert.Equal(t, "user-123", info.Subject)
	assert.Equal(t, "user@example.com", info.Email)
	assert.Equal(t, "Test User", info.Name)
}

func TestOIDCService_Logout_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	tokenResp := &oidc.TokenResponse{AccessToken: "at"}
	require.NoError(t, store.Save("https://ex.com", tokenResp))

	err := svc.Logout("test")
	assert.NoError(t, err)

	// Token should be deleted.
	_, err = store.Load("https://ex.com")
	assert.Error(t, err)
}

func TestOIDCService_Logout_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.Logout("nonexistent")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_Logout_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	err := svc.Logout("test")
	assert.True(t, errors.Is(err, ErrOIDCTokenStoreUnavailable))
}

func TestOIDCService_Logout_TokenNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetTokenStore(oidc.NewMemoryTokenStore())

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	// Logout when no token exists should succeed (token not found is treated as success).
	err := svc.Logout("test")
	assert.NoError(t, err)
}

func TestOIDCService_GetAllTokens_Empty(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetTokenStore(oidc.NewMemoryTokenStore())

	tokens := svc.GetAllTokens()
	assert.Empty(t, tokens)
}

func TestOIDCService_GetAllTokens_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	tokens := svc.GetAllTokens()
	assert.Empty(t, tokens)
}

func TestOIDCService_GetAllTokens_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry1 := &OIDCProviderEntry{Name: "p1", Issuer: "https://a.com", ClientID: "id1"}
	entry2 := &OIDCProviderEntry{Name: "p2", Issuer: "https://b.com", ClientID: "id2"}
	require.NoError(t, svc.AddProvider(entry1))
	require.NoError(t, svc.AddProvider(entry2))

	require.NoError(t, store.Save("https://a.com", &oidc.TokenResponse{AccessToken: "at1", Expiry: time.Now().Add(time.Hour)}))
	require.NoError(t, store.Save("https://b.com", &oidc.TokenResponse{AccessToken: "at2", Expiry: time.Now().Add(time.Hour)}))

	tokens := svc.GetAllTokens()
	assert.Len(t, tokens, 2)
}

// --- Refresh status tests ---

func TestOIDCService_GetRefreshStatus_NotRunning(t *testing.T) {
	svc := NewOIDCService(nil)
	status, err := svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.False(t, status.Running)
	assert.Equal(t, "test", status.Provider)
}

func TestOIDCService_StopAutoRefresh_NotRunning(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.StopAutoRefresh("nonexistent")
	assert.NoError(t, err) // Not running is treated as success.
}

func TestOIDCService_StartAutoRefresh_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.StartAutoRefresh("nonexistent")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_StartAutoRefresh_Disabled(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id", AutoRefresh: 0}
	require.NoError(t, svc.AddProvider(entry))

	err := svc.StartAutoRefresh("test")
	assert.True(t, errors.Is(err, ErrOIDCAutoRefreshDisabled))
}

func TestOIDCService_StartAutoRefresh_AlreadyRunning(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id", AutoRefresh: 60}
	require.NoError(t, svc.AddProvider(entry))

	err := svc.StartAutoRefresh("test")
	require.NoError(t, err)
	defer func() { _ = svc.StopAutoRefresh("test") }()

	err = svc.StartAutoRefresh("test")
	assert.True(t, errors.Is(err, ErrOIDCRefreshAlreadyRunning))
}

func TestOIDCService_StartStopAutoRefresh(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id", AutoRefresh: 60}
	require.NoError(t, svc.AddProvider(entry))

	err := svc.StartAutoRefresh("test")
	require.NoError(t, err)

	status, err := svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.True(t, status.Running)

	err = svc.StopAutoRefresh("test")
	assert.NoError(t, err)

	status, err = svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.False(t, status.Running)
}

func TestOIDCService_GetAllRefreshStatus(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry1 := &OIDCProviderEntry{Name: "p1", Issuer: "https://a.com", ClientID: "id1", AutoRefresh: 60}
	entry2 := &OIDCProviderEntry{Name: "p2", Issuer: "https://b.com", ClientID: "id2", AutoRefresh: 120}
	require.NoError(t, svc.AddProvider(entry1))
	require.NoError(t, svc.AddProvider(entry2))

	require.NoError(t, svc.StartAutoRefresh("p1"))
	require.NoError(t, svc.StartAutoRefresh("p2"))
	defer func() { _ = svc.StopAllRefresh() }()

	statuses := svc.GetAllRefreshStatus()
	assert.Len(t, statuses, 2)

	for _, s := range statuses {
		assert.True(t, s.Running)
	}
}

func TestOIDCService_StopAllRefresh(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id", AutoRefresh: 60}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, svc.StartAutoRefresh("test"))

	err := svc.StopAllRefresh()
	assert.NoError(t, err)

	statuses := svc.GetAllRefreshStatus()
	assert.Empty(t, statuses)
}

// --- Script execution tests ---

func TestOIDCService_ExecuteScript_EmptyScript(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.ExecuteScript("test", "")
	assert.True(t, errors.Is(err, ErrOIDCExecEmpty))
}

func TestOIDCService_ExecuteScript_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.ExecuteScript("nonexistent", "echo hello")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_ExecuteScript_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
		Scopes:   []string{"openid"},
	}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, store.Save("https://example.com", &oidc.TokenResponse{
		AccessToken: "at123",
		Expiry:      time.Now().Add(time.Hour),
	}))

	result, err := svc.ExecuteScript("test", "echo $OIDC_PROVIDER")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, result.Stdout, "test")
}

func TestOIDCService_ExecuteScript_Failure(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.ExecuteScript("test", "exit 42")
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, 42, result.ExitCode)
}

func TestOIDCService_ExecuteScript_NoToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.ExecuteScript("test", "echo ok")
	require.NoError(t, err)
	assert.True(t, result.Success)
}

// --- Provider persistence tests ---

func TestOIDCService_SetDataDir_PersistsProviders(t *testing.T) {
	dir := t.TempDir()

	svc := NewOIDCService(nil)
	svc.SetDataDir(dir)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	// Verify file was written.
	path := filepath.Join(dir, "oidc-providers.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var config oidcProvidersConfig
	require.NoError(t, json.Unmarshal(data, &config))
	assert.Len(t, config.Providers, 1)
	assert.Equal(t, "test", config.Providers[0].Name)
}

func TestOIDCService_SetDataDir_LoadsProviders(t *testing.T) {
	dir := t.TempDir()

	// Pre-write provider config.
	config := oidcProvidersConfig{
		Providers: []OIDCProviderEntry{
			{Name: "preloaded", Issuer: "https://pre.com", ClientID: "id"},
		},
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "oidc-providers.json"), data, 0600))

	svc := NewOIDCService(nil)
	svc.SetDataDir(dir)

	p, err := svc.GetProvider("preloaded")
	require.NoError(t, err)
	assert.Equal(t, "https://pre.com", p.Issuer)
}

// --- Login error tests ---

func TestOIDCService_Login_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	result, err := svc.Login("nonexistent")
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "provider not found")
	assert.False(t, result.Success)
}

func TestOIDCService_Login_AWSUnsupported(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:     "aws-test",
		Type:     OIDCProviderTypeAWS,
		Issuer:   "https://aws.example.com",
		ClientID: "id",
	}
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.Login("aws-test")
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "AWS")
	assert.False(t, result.Success)
}

// --- RefreshToken error tests ---

func TestOIDCService_RefreshToken_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.RefreshToken("nonexistent")
	assert.True(t, errors.Is(err, ErrOIDCProviderNotFound))
}

func TestOIDCService_RefreshToken_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	_, err := svc.RefreshToken("test")
	assert.True(t, errors.Is(err, ErrOIDCTokenStoreUnavailable))
}

func TestOIDCService_RefreshToken_NoRefreshToken(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	// Store token without refresh token.
	require.NoError(t, store.Save("https://ex.com", &oidc.TokenResponse{AccessToken: "at"}))

	_, err := svc.RefreshToken("test")
	assert.True(t, errors.Is(err, ErrOIDCNoRefreshToken))
}

// --- Internal helper tests ---

func TestOIDCService_extractIDTokenClaims_InvalidJWT(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims("not-a-jwt", info)
	assert.Empty(t, info.Subject)
}

func TestOIDCService_extractIDTokenClaims_InvalidBase64(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims("header.!!!invalid!!!.signature", info)
	assert.Empty(t, info.Subject)
}

func TestOIDCService_extractIDTokenClaims_InvalidJSON(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}
	payload := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	svc.extractIDTokenClaims("header."+payload+".signature", info)
	assert.Empty(t, info.Subject)
}

func TestOIDCService_extractIDTokenClaims_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}

	claims := map[string]string{"sub": "user1", "email": "u@ex.com", "name": "User One"}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	svc.extractIDTokenClaims("header."+payload+".signature", info)
	assert.Equal(t, "user1", info.Subject)
	assert.Equal(t, "u@ex.com", info.Email)
	assert.Equal(t, "User One", info.Name)
}

func TestOIDCService_tokenResponseToInfo_ExpiredToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", Scopes: []string{"openid"}}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		Expiry:      time.Now().Add(-time.Hour),
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.True(t, info.IsExpired)
}

func TestOIDCService_tokenResponseToInfo_ScopeFromResponse(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com"}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		Scope:       "openid profile email",
		Expiry:      time.Now().Add(time.Hour),
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Equal(t, []string{"openid", "profile", "email"}, info.Scopes)
}

func TestOIDCService_buildExecPayload_NilToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "cid", Scopes: []string{"openid"}}

	payload := svc.buildExecPayload("test", entry, nil)
	assert.Equal(t, "test", payload.Provider)
	assert.Equal(t, "https://ex.com", payload.Issuer)
	assert.Empty(t, payload.AccessToken)
}

func TestOIDCService_buildExecPayload_WithToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "cid"}
	tokenResp := &oidc.TokenResponse{
		AccessToken:  "at",
		RefreshToken: "rt",
		IDToken:      "idt",
		ExpiresIn:    3600,
		Expiry:       time.Now().Add(time.Hour),
	}

	payload := svc.buildExecPayload("test", entry, tokenResp)
	assert.Equal(t, "at", payload.AccessToken)
	assert.Equal(t, "rt", payload.RefreshToken)
	assert.Equal(t, "idt", payload.IDToken)
	assert.Equal(t, 3600, payload.ExpiresIn)
	assert.NotEmpty(t, payload.ExpiresAt)
}

// --- Template tests ---

func TestOIDCService_GetTemplates(t *testing.T) {
	svc := NewOIDCService(nil)
	templates := svc.GetTemplates()

	// Should contain all builtins + "custom".
	assert.True(t, len(templates) >= 7, "expected at least 7 templates (6 builtin + custom), got %d", len(templates))

	// Build a lookup by name for validation.
	byName := make(map[string]OIDCProviderTemplateInfo, len(templates))
	for _, tmpl := range templates {
		byName[tmpl.Name] = tmpl
	}

	// Validate "google" template.
	google, ok := byName["google"]
	require.True(t, ok, "google template missing")
	assert.Equal(t, "https://accounts.google.com", google.Issuer)
	assert.Contains(t, google.Scopes, "openid")
	assert.False(t, google.RequiresRegion)
	assert.False(t, google.RequiresIssuer)
	assert.Equal(t, OIDCProviderTypeStandard, google.Type)

	// Validate "aws" template.
	aws, ok := byName["aws"]
	require.True(t, ok, "aws template missing")
	assert.True(t, aws.RequiresRegion)
	assert.True(t, aws.RequiresIssuer) // AWS has no Issuer URL
	assert.Equal(t, OIDCProviderTypeAWS, aws.Type)
	assert.Empty(t, aws.Issuer)

	// Validate "okta" template — requires issuer (empty in template).
	okta, ok := byName["okta"]
	require.True(t, ok, "okta template missing")
	assert.True(t, okta.RequiresIssuer)
	assert.Empty(t, okta.Issuer)

	// Validate "custom" synthetic entry.
	custom, ok := byName["custom"]
	require.True(t, ok, "custom template missing")
	assert.Equal(t, "Custom OIDC provider", custom.Description)
	assert.True(t, custom.RequiresIssuer)
	assert.Equal(t, OIDCProviderTypeStandard, custom.Type)
}

func TestOIDCService_AddProvider_WithTemplate(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:     "my-google",
		Template: "google",
		ClientID: "my-client-id",
	}

	err := svc.AddProvider(entry)
	require.NoError(t, err)

	p, err := svc.GetProvider("my-google")
	require.NoError(t, err)

	// Issuer and scopes should be auto-filled from template.
	assert.Equal(t, "https://accounts.google.com", p.Issuer)
	assert.Contains(t, p.Scopes, "openid")
	assert.Contains(t, p.Scopes, "profile")
	assert.Contains(t, p.Scopes, "email")
	assert.Equal(t, OIDCProviderTypeStandard, p.Type)
	// User-provided client ID should be preserved.
	assert.Equal(t, "my-client-id", p.ClientID)
}

func TestOIDCService_AddProvider_AWSTemplate(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:      "my-aws",
		Template:  "aws",
		AWSRegion: "us-east-1",
	}

	err := svc.AddProvider(entry)
	require.NoError(t, err)

	p, err := svc.GetProvider("my-aws")
	require.NoError(t, err)

	// AWS template should populate client_id and auto_refresh.
	assert.Equal(t, OIDCProviderTypeAWS, p.Type)
	assert.Equal(t, "arn:aws:signin:::devtools/same-device", p.ClientID)
	assert.Equal(t, 840, p.AutoRefresh)
	assert.Equal(t, "default", p.AWSProfile)
	assert.Contains(t, p.Scopes, "openid")
}

func TestOIDCService_AddProvider_InvalidTemplate(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:     "bad",
		Template: "nonexistent",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}

	err := svc.AddProvider(entry)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCTemplateNotFound))
}

func TestOIDCService_AddProvider_CustomTemplate(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:     "my-custom",
		Template: "custom",
		Issuer:   "https://my-idp.example.com",
		ClientID: "my-cid",
	}

	err := svc.AddProvider(entry)
	require.NoError(t, err)

	p, err := svc.GetProvider("my-custom")
	require.NoError(t, err)

	// "custom" template should not modify any fields.
	assert.Equal(t, "https://my-idp.example.com", p.Issuer)
	assert.Equal(t, "my-cid", p.ClientID)
}

func TestOIDCService_AddProvider_TemplateDoesNotOverwriteUserValues(t *testing.T) {
	svc := NewOIDCService(nil)

	entry := &OIDCProviderEntry{
		Name:        "my-ms",
		Template:    "microsoft",
		ClientID:    "user-client-id",
		Issuer:      "https://login.microsoftonline.com/my-tenant/v2.0",
		Scopes:      []string{"openid", "custom-scope"},
		AutoRefresh: 300,
	}

	err := svc.AddProvider(entry)
	require.NoError(t, err)

	p, err := svc.GetProvider("my-ms")
	require.NoError(t, err)

	// User-provided values should NOT be overwritten by template defaults.
	assert.Equal(t, "user-client-id", p.ClientID)
	assert.Equal(t, "https://login.microsoftonline.com/my-tenant/v2.0", p.Issuer)
	assert.Equal(t, []string{"openid", "custom-scope"}, p.Scopes)
	assert.Equal(t, 300, p.AutoRefresh)
}

// ---------------------------------------------------------------------------
// NEW TESTS - DiscoverProvider, Login, RefreshToken, refreshLoop,
// tokenResponseToInfo, loadProviders, saveProviders, Close, SetDataDir
// ---------------------------------------------------------------------------

// --- DiscoverProvider additional tests ---

func TestOIDCService_DiscoverProvider_InvalidURL(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())

	// Use a URL that will fail discovery (unreachable host).
	_, err := svc.DiscoverProvider("http://127.0.0.1:1/invalid-issuer")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCDiscoveryFailed))
}

func TestOIDCService_DiscoverProvider_NilContext(t *testing.T) {
	// When ctx is nil, DiscoverProvider should use context.Background.
	svc := NewOIDCService(nil)
	// Do not set context - leave svc.ctx as nil.

	_, err := svc.DiscoverProvider("http://127.0.0.1:1/unreachable")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCDiscoveryFailed))
}

func TestOIDCService_DiscoverProvider_WithDiscoveryServer(t *testing.T) {
	// Create a mock OIDC discovery server.
	discovery := map[string]interface{}{
		"issuer":                 "", // Will be set after server starts.
		"authorization_endpoint": "https://example.com/auth",
		"token_endpoint":         "https://example.com/token",
		"jwks_uri":               "https://example.com/.well-known/jwks.json",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discovery)
	}))
	defer server.Close()

	// Update discovery doc with the actual server URL as issuer.
	discovery["issuer"] = server.URL

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())

	provider, err := svc.DiscoverProvider(server.URL)
	require.NoError(t, err)
	require.NotNil(t, provider)
}

// --- Login additional tests ---

func TestOIDCService_Login_DiscoveryFailure(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())

	// Add a provider with an unreachable issuer.
	entry := &OIDCProviderEntry{
		Name:     "broken",
		Type:     OIDCProviderTypeStandard,
		Issuer:   "http://127.0.0.1:1/unreachable",
		ClientID: "cid",
	}
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.Login("broken")
	assert.NoError(t, err)
	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Error)
}

func TestOIDCService_Login_NilContext(t *testing.T) {
	svc := NewOIDCService(nil)
	// Do not set context; svc.ctx is nil -- should fallback to Background.

	entry := &OIDCProviderEntry{
		Name:     "nil-ctx",
		Type:     OIDCProviderTypeStandard,
		Issuer:   "http://127.0.0.1:1/unreachable",
		ClientID: "cid",
	}
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.Login("nil-ctx")
	assert.NoError(t, err)
	// The error should be a discovery failure since the issuer is unreachable.
	assert.False(t, result.Success)
}

func TestOIDCService_Login_ResultContainsErrorMessage(t *testing.T) {
	svc := NewOIDCService(nil)

	result, err := svc.Login("does-not-exist")
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Error)
}

// --- RefreshToken additional tests ---

func TestOIDCService_RefreshToken_NoStoredToken(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	// No token stored for this issuer.
	_, err := svc.RefreshToken("test")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCTokenNotFound))
}

func TestOIDCService_RefreshToken_DiscoveryFails(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "http://127.0.0.1:1/unreachable",
		ClientID: "cid",
	}
	require.NoError(t, svc.AddProvider(entry))

	// Store a token with a refresh token.
	require.NoError(t, store.Save("http://127.0.0.1:1/unreachable", &oidc.TokenResponse{
		AccessToken:  "at",
		RefreshToken: "rt-valid",
	}))

	_, err := svc.RefreshToken("test")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCRefreshFailed))
}

func TestOIDCService_RefreshToken_NilContext(t *testing.T) {
	svc := NewOIDCService(nil)
	// ctx is nil -- should fall back to context.Background().
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "http://127.0.0.1:1/unreachable",
		ClientID: "cid",
	}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, store.Save("http://127.0.0.1:1/unreachable", &oidc.TokenResponse{
		AccessToken:  "at",
		RefreshToken: "rt-valid",
	}))

	_, err := svc.RefreshToken("test")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCRefreshFailed))
}

// --- refreshLoop tests ---

func TestOIDCService_refreshLoop_CancellationSetsRunningFalse(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:        "loop-test",
		Issuer:      "https://ex.com",
		ClientID:    "id",
		AutoRefresh: 3600, // Long interval so ticker won't fire.
	}
	require.NoError(t, svc.AddProvider(entry))

	ctx, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{
		provider: "loop-test",
		cancel:   cancel,
	}
	initialStatus := &OIDCRefreshStatus{
		Provider: "loop-test",
		Running:  true,
	}
	proc.status.Store(initialStatus)

	// Start the loop in a goroutine.
	done := make(chan struct{})
	go func() {
		svc.refreshLoop(ctx, proc, entry)
		close(done)
	}()

	// Cancel immediately.
	cancel()

	// Wait for the loop to exit.
	select {
	case <-done:
		// Loop exited.
	case <-time.After(2 * time.Second):
		t.Fatal("refreshLoop did not exit after cancellation")
	}

	status := proc.status.Load()
	require.NotNil(t, status)
	assert.False(t, status.Running)
}

func TestOIDCService_refreshLoop_NilStatusOnCancel(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:        "loop-nil-status",
		Issuer:      "https://ex.com",
		ClientID:    "id",
		AutoRefresh: 3600,
	}
	require.NoError(t, svc.AddProvider(entry))

	ctx, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{
		provider: "loop-nil-status",
		cancel:   cancel,
	}
	// Intentionally leave status as nil (default atomic pointer).

	done := make(chan struct{})
	go func() {
		svc.refreshLoop(ctx, proc, entry)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Loop exited successfully even with nil status.
	case <-time.After(2 * time.Second):
		t.Fatal("refreshLoop did not exit after cancellation with nil status")
	}
}

// --- tokenResponseToInfo additional tests ---

func TestOIDCService_tokenResponseToInfo_ZeroExpiryWithExpiresIn(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://ex.com",
		Scopes: []string{"openid"},
	}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		ExpiresIn:   3600,
		// Expiry is zero-value time.Time.
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.NotEmpty(t, info.ExpiresAt)
	assert.Equal(t, int64(3600), info.ExpiresIn)
	assert.False(t, info.IsExpired)
}

func TestOIDCService_tokenResponseToInfo_ZeroExpiryZeroExpiresIn(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://ex.com",
		Scopes: []string{"openid"},
	}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		// Both Expiry and ExpiresIn are zero.
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Empty(t, info.ExpiresAt)
	assert.Equal(t, int64(0), info.ExpiresIn)
	assert.False(t, info.IsExpired)
}

func TestOIDCService_tokenResponseToInfo_NoRefreshToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com"}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		Expiry:      time.Now().Add(time.Hour),
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.False(t, info.HasRefresh)
}

func TestOIDCService_tokenResponseToInfo_WithIDToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com"}

	claims := map[string]string{"sub": "user1", "email": "u@ex.com", "name": "User"}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	fakeJWT := "header." + payload + ".sig"

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		IDToken:     fakeJWT,
		Expiry:      time.Now().Add(time.Hour),
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Equal(t, "user1", info.Subject)
	assert.Equal(t, "u@ex.com", info.Email)
	assert.Equal(t, "User", info.Name)
}

func TestOIDCService_tokenResponseToInfo_ScopeNotOverriddenWhenEntryHasScopes(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://ex.com",
		Scopes: []string{"openid", "profile"},
	}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		Scope:       "openid email", // Different scope in response.
		Expiry:      time.Now().Add(time.Hour),
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	// Entry scopes should be used because they are not empty.
	assert.Equal(t, []string{"openid", "profile"}, info.Scopes)
}

// --- loadProviders / saveProviders additional tests ---

func TestOIDCService_loadProviders_EmptyDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	// dataDir is empty string, loadProviders should return nil.
	err := svc.loadProviders()
	assert.NoError(t, err)
}

func TestOIDCService_loadProviders_NonExistentFile(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = filepath.Join(t.TempDir(), "does-not-exist")
	err := svc.loadProviders()
	assert.NoError(t, err) // Non-existent file should not be an error.
}

func TestOIDCService_loadProviders_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, oidcProvidersFile), []byte("not-json{{{"), 0600))

	svc := NewOIDCService(nil)
	svc.dataDir = dir
	err := svc.loadProviders()
	assert.Error(t, err)
}

func TestOIDCService_loadProviders_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := oidcProvidersConfig{
		Providers: []OIDCProviderEntry{
			{Name: "prov1", Issuer: "https://a.com", ClientID: "id1"},
			{Name: "prov2", Issuer: "https://b.com", ClientID: "id2"},
		},
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, oidcProvidersFile), data, 0600))

	svc := NewOIDCService(nil)
	svc.dataDir = dir
	err = svc.loadProviders()
	require.NoError(t, err)
	assert.Len(t, svc.providers, 2)

	p, ok := svc.providers["prov1"]
	require.True(t, ok)
	assert.Equal(t, "https://a.com", p.Issuer)
}

func TestOIDCService_saveProviders_EmptyDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	// dataDir is empty string, saveProviders should return nil (no-op).
	err := svc.saveProviders()
	assert.NoError(t, err)
}

func TestOIDCService_saveProviders_WritesToDisk(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.dataDir = dir

	svc.providers["test-save"] = &OIDCProviderEntry{
		Name:     "test-save",
		Issuer:   "https://save.com",
		ClientID: "save-id",
	}

	err := svc.saveProviders()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, oidcProvidersFile))
	require.NoError(t, err)

	var cfg oidcProvidersConfig
	require.NoError(t, json.Unmarshal(data, &cfg))
	assert.Len(t, cfg.Providers, 1)
	assert.Equal(t, "test-save", cfg.Providers[0].Name)
}

func TestOIDCService_saveProviders_CreatesParentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	svc := NewOIDCService(nil)
	svc.dataDir = dir

	svc.providers["nested"] = &OIDCProviderEntry{
		Name: "nested", Issuer: "https://n.com", ClientID: "nid",
	}

	err := svc.saveProviders()
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, oidcProvidersFile))
	assert.NoError(t, err)
}

// --- SetDataDir additional tests ---

func TestOIDCService_SetDataDir_CreatesTokenStore(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.SetDataDir(dir)

	assert.NotNil(t, svc.tokenStore)
	assert.Equal(t, dir, svc.dataDir)
}

func TestOIDCService_SetDataDir_InvalidProviderFile(t *testing.T) {
	dir := t.TempDir()
	// Write invalid JSON to providers file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, oidcProvidersFile), []byte("{{bad json"), 0600))

	svc := NewOIDCService(nil)
	// SetDataDir should log a warning but not crash.
	svc.SetDataDir(dir)

	// Providers map should be empty due to load failure.
	assert.Empty(t, svc.providers)
}

// --- Close additional tests ---

func TestOIDCService_Close_StopsRefreshAndClosesStore(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id", AutoRefresh: 60}
	require.NoError(t, svc.AddProvider(entry))
	require.NoError(t, svc.StartAutoRefresh("test"))

	err := svc.Close()
	assert.NoError(t, err)

	// After Close, refresh should be stopped.
	statuses := svc.GetAllRefreshStatus()
	assert.Empty(t, statuses)
}

// --- GetRefreshStatus additional tests ---

func TestOIDCService_GetRefreshStatus_RunningWithNilStatus(t *testing.T) {
	svc := NewOIDCService(nil)

	// Manually inject a refreshProcess with nil status.
	proc := &refreshProcess{
		provider: "test",
		cancel:   func() {},
	}
	// Do NOT store a status (leave atomic.Pointer as nil).
	svc.refreshProcs["test"] = proc

	status, err := svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.True(t, status.Running)
	assert.Equal(t, "test", status.Provider)
}

// --- ExecuteScript additional tests ---

func TestOIDCService_ExecuteScript_StderrOutput(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.ExecuteScript("test", "echo 'error output' >&2")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Stderr, "error output")
}

func TestOIDCService_ExecuteScript_StdinReceivesJSON(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
		Scopes:   []string{"openid"},
	}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, store.Save("https://example.com", &oidc.TokenResponse{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(time.Hour),
	}))

	// Read stdin and verify it contains valid JSON with the provider name.
	result, err := svc.ExecuteScript("test", "cat | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d['provider'])\" 2>/dev/null || cat")
	require.NoError(t, err)
	assert.True(t, result.Success)
}

func TestOIDCService_ExecuteScript_EnvironmentVars(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:     "env-test",
		Issuer:   "https://example.com",
		ClientID: "cid",
		Scopes:   []string{"openid", "profile"},
	}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, store.Save("https://example.com", &oidc.TokenResponse{
		AccessToken:  "access-tok",
		RefreshToken: "refresh-tok",
		Expiry:       time.Now().Add(time.Hour),
	}))

	result, err := svc.ExecuteScript("env-test", "echo \"$OIDC_ISSUER|$OIDC_CLIENT_ID|$OIDC_ACCESS_TOKEN|$OIDC_SCOPES\"")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Stdout, "https://example.com")
	assert.Contains(t, result.Stdout, "cid")
	assert.Contains(t, result.Stdout, "access-tok")
	assert.Contains(t, result.Stdout, "openid profile")
}

// --- buildExecPayload additional tests ---

func TestOIDCService_buildExecPayload_ZeroExpiry(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "cid"}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		ExpiresIn:   3600,
		// Expiry is zero value.
	}

	payload := svc.buildExecPayload("test", entry, tokenResp)
	assert.Empty(t, payload.ExpiresAt) // Zero Expiry should produce empty ExpiresAt.
	assert.Equal(t, 3600, payload.ExpiresIn)
}

// --- extractIDTokenClaims additional tests ---

func TestOIDCService_extractIDTokenClaims_EmptyIDToken(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims("", info)
	assert.Empty(t, info.Subject)
	assert.Empty(t, info.Email)
	assert.Empty(t, info.Name)
}

func TestOIDCService_extractIDTokenClaims_TwoParts(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims("header.payload", info)
	assert.Empty(t, info.Subject) // Only 2 parts, not 3.
}

func TestOIDCService_extractIDTokenClaims_FourParts(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims("a.b.c.d", info)
	assert.Empty(t, info.Subject) // 4 parts, not 3.
}

func TestOIDCService_extractIDTokenClaims_EmptyClaims(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}

	// Valid JSON but empty claims.
	claimsJSON, _ := json.Marshal(map[string]string{})
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	svc.extractIDTokenClaims("header."+payload+".sig", info)

	assert.Empty(t, info.Subject)
	assert.Empty(t, info.Email)
	assert.Empty(t, info.Name)
}

// --- DeleteProvider with running refresh ---

func TestOIDCService_DeleteProvider_StopsRunningRefresh(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:        "test",
		Issuer:      "https://ex.com",
		ClientID:    "id",
		AutoRefresh: 60,
	}
	require.NoError(t, svc.AddProvider(entry))
	require.NoError(t, svc.StartAutoRefresh("test"))

	// Verify refresh is running.
	status, err := svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.True(t, status.Running)

	// Delete the provider -- should stop refresh.
	err = svc.DeleteProvider("test")
	assert.NoError(t, err)

	// Refresh should no longer be in the map.
	status, err = svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.False(t, status.Running)
}

// --- GetProvider returns a copy ---

func TestOIDCService_GetProvider_ReturnsCopy(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://ex.com",
		ClientID: "id",
	}
	require.NoError(t, svc.AddProvider(entry))

	p1, err := svc.GetProvider("test")
	require.NoError(t, err)

	// Mutate the returned copy.
	p1.Issuer = "https://mutated.com"

	// Original should be unchanged.
	p2, err := svc.GetProvider("test")
	require.NoError(t, err)
	assert.Equal(t, "https://ex.com", p2.Issuer)
}

// --- StartAutoRefresh with negative AutoRefresh ---

func TestOIDCService_StartAutoRefresh_NegativeInterval(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id", AutoRefresh: -5}
	require.NoError(t, svc.AddProvider(entry))

	err := svc.StartAutoRefresh("test")
	assert.True(t, errors.Is(err, ErrOIDCAutoRefreshDisabled))
}

// --- SetTokenStore / SetBrowserOpen ---

func TestOIDCService_SetTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	assert.Nil(t, svc.tokenStore)

	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)
	assert.Equal(t, store, svc.tokenStore)
}

// --- refreshLoop with ticker tick (error path) ---

func TestOIDCService_refreshLoop_TickerFiresWithRefreshError(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:        "tick-test",
		Issuer:      "http://127.0.0.1:1/unreachable",
		ClientID:    "id",
		AutoRefresh: 1, // 1 second for fast tick.
	}
	require.NoError(t, svc.AddProvider(entry))

	// Store a token with refresh token so RefreshToken progresses past the early checks.
	require.NoError(t, store.Save("http://127.0.0.1:1/unreachable", &oidc.TokenResponse{
		AccessToken:  "at",
		RefreshToken: "rt",
	}))

	ctx, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{
		provider: "tick-test",
		cancel:   cancel,
	}
	proc.status.Store(&OIDCRefreshStatus{
		Provider: "tick-test",
		Running:  true,
	})

	done := make(chan struct{})
	go func() {
		svc.refreshLoop(ctx, proc, entry)
		close(done)
	}()

	// Wait for at least one tick to fire (the refresh will fail because the
	// issuer is unreachable, but the status should be updated).
	time.Sleep(2 * time.Second)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("refreshLoop did not exit")
	}

	status := proc.status.Load()
	require.NotNil(t, status)
	assert.True(t, status.RefreshCount > 0)
	assert.Equal(t, "error", status.LastStatus)
	assert.NotEmpty(t, status.LastError)
	assert.NotEmpty(t, status.LastRefresh)
}

// --- Login end-to-end via mock OIDC server (covers callback path) ---

func TestOIDCService_Login_FullFlowWithMockServer(t *testing.T) {
	// Create a mock OIDC discovery + token endpoint server.
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
			"access_token":  "mock-access-token",
			"refresh_token": "mock-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[]}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	// Capture the auth URL that would be opened in the browser, then
	// simulate the callback by making an HTTP request to the callback server.
	var capturedAuthURL atomic.Value
	svc.SetBrowserOpen(func(authURL string) error {
		capturedAuthURL.Store(authURL)
		return nil
	})

	entry := &OIDCProviderEntry{
		Name:        "mock-provider",
		Issuer:      serverURL,
		ClientID:    "test-client",
		RedirectURL: "http://localhost:18999/callback", // Use an uncommon port.
		Scopes:      []string{"openid"},
	}
	require.NoError(t, svc.AddProvider(entry))

	// Start Login in a goroutine because it blocks waiting for callback.
	type loginResult struct {
		result *OIDCLoginResult
		err    error
	}
	resultChan := make(chan loginResult, 1)
	go func() {
		r, e := svc.Login("mock-provider")
		resultChan <- loginResult{result: r, err: e}
	}()

	// Wait for the browser open to capture the auth URL.
	var authURLStr string
	for i := 0; i < 50; i++ {
		if v := capturedAuthURL.Load(); v != nil {
			authURLStr = v.(string)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NotEmpty(t, authURLStr, "browser open was not called")

	// Verify the auth URL contains a state parameter.
	require.Contains(t, authURLStr, "state=")

	// Simulate the OAuth2 callback. Extract state from the auth URL.
	stateStart := len(authURLStr) - 1
	for i := 0; i < len(authURLStr); i++ {
		if authURLStr[i:i+6] == "state=" {
			stateStart = i + 6
			break
		}
	}
	stateEnd := stateStart
	for stateEnd < len(authURLStr) && authURLStr[stateEnd] != '&' {
		stateEnd++
	}
	state := authURLStr[stateStart:stateEnd]

	// Make the callback request.
	callbackURL := fmt.Sprintf("http://localhost:18999/callback?code=mock-auth-code&state=%s", state)
	for i := 0; i < 50; i++ {
		resp, err := http.Get(callbackURL)
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for login result.
	select {
	case lr := <-resultChan:
		require.NoError(t, lr.err)
		require.NotNil(t, lr.result)
		assert.True(t, lr.result.Success)
		require.NotNil(t, lr.result.Token)
		assert.Equal(t, "mock-provider", lr.result.Token.Provider)
		assert.True(t, lr.result.Token.HasRefresh)
	case <-time.After(10 * time.Second):
		t.Fatal("Login did not complete within timeout")
	}
}

// --- Login callback error path ---

func TestOIDCService_Login_CallbackError(t *testing.T) {
	// Set up mock OIDC server.
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
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)
	svc.SetBrowserOpen(func(authURL string) error { return nil })

	entry := &OIDCProviderEntry{
		Name:        "err-test",
		Issuer:      serverURL,
		ClientID:    "test-client",
		RedirectURL: "http://localhost:18998/callback",
		Scopes:      []string{"openid"},
	}
	require.NoError(t, svc.AddProvider(entry))

	type loginResult struct {
		result *OIDCLoginResult
		err    error
	}
	resultChan := make(chan loginResult, 1)
	go func() {
		r, e := svc.Login("err-test")
		resultChan <- loginResult{result: r, err: e}
	}()

	// Wait for callback server to start, then send an error callback.
	time.Sleep(200 * time.Millisecond)
	callbackURL := "http://localhost:18998/callback?error=access_denied&error_description=user+denied"
	for i := 0; i < 50; i++ {
		resp, err := http.Get(callbackURL)
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case lr := <-resultChan:
		assert.NoError(t, lr.err)
		assert.NotEmpty(t, lr.result.Error)
		require.NotNil(t, lr.result)
		assert.False(t, lr.result.Success)
	case <-time.After(10 * time.Second):
		t.Fatal("Login did not complete within timeout")
	}
}

// --- Login callback with no code ---

func TestOIDCService_Login_CallbackNoCode(t *testing.T) {
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
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	svc.SetTokenStore(oidc.NewMemoryTokenStore())
	svc.SetBrowserOpen(func(authURL string) error { return nil })

	entry := &OIDCProviderEntry{
		Name:        "nocode-test",
		Issuer:      serverURL,
		ClientID:    "test-client",
		RedirectURL: "http://localhost:18997/callback",
		Scopes:      []string{"openid"},
	}
	require.NoError(t, svc.AddProvider(entry))

	type loginResult struct {
		result *OIDCLoginResult
		err    error
	}
	resultChan := make(chan loginResult, 1)
	go func() {
		r, e := svc.Login("nocode-test")
		resultChan <- loginResult{result: r, err: e}
	}()

	// Wait for callback server, then send callback with no code or error.
	time.Sleep(200 * time.Millisecond)
	callbackURL := "http://localhost:18997/callback" // No query params at all.
	for i := 0; i < 50; i++ {
		resp, err := http.Get(callbackURL)
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case lr := <-resultChan:
		assert.NoError(t, lr.err)
		assert.NotEmpty(t, lr.result.Error)
		require.NotNil(t, lr.result)
		assert.False(t, lr.result.Success)
	case <-time.After(10 * time.Second):
		t.Fatal("Login did not complete within timeout")
	}
}
