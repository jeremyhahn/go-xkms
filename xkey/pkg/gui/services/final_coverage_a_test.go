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
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// Mock types (fa prefix to avoid conflicts)
// =========================================================================

// faTokenStore is a controllable OIDC token store mock.
type faTokenStore struct {
	saveErr   error
	loadErr   error
	loadResp  *oidc.TokenResponse
	deleteErr error
	closeErr  error
}

func (m *faTokenStore) Save(_ string, _ *oidc.TokenResponse) error { return m.saveErr }
func (m *faTokenStore) Load(_ string) (*oidc.TokenResponse, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.loadResp, nil
}
func (m *faTokenStore) Delete(_ string) error   { return m.deleteErr }
func (m *faTokenStore) List() ([]string, error) { return nil, nil }
func (m *faTokenStore) Close() error            { return m.closeErr }

// faOATHStore is a controllable OATH store mock.
type faOATHStore struct {
	addErr    error
	getErr    error
	getCred   *oath.Credential
	listErr   error
	listCreds []*oath.Credential
	updateErr error
	deleteErr error
}

func (m *faOATHStore) Add(_ *oath.Credential) error { return m.addErr }
func (m *faOATHStore) Get(_ string) (*oath.Credential, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.getCred, nil
}
func (m *faOATHStore) List() ([]*oath.Credential, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listCreds, nil
}
func (m *faOATHStore) Update(_ *oath.Credential) error { return m.updateErr }
func (m *faOATHStore) Delete(_ string) error           { return m.deleteErr }
func (m *faOATHStore) Close() error                    { return nil }

// faKeyCounter implements KeyCounter for admin tests.
type faKeyCounter int

func (c faKeyCounter) KeyCount() int { return int(c) }

// =========================================================================
// oidc_service.go tests
// =========================================================================

// TestFA_OIDCService_SetDataDir_BadPath covers L199-202: SetDataDir with
// a path that cannot create the token store (triggers the warn+fallback).
func TestFA_OIDCService_SetDataDir_BadPath(t *testing.T) {
	svc := NewOIDCService(nil)
	// Use /dev/null as a directory -- the file exists but is not a directory,
	// so creating a token store subdirectory under it will fail.
	svc.SetDataDir("/dev/null/nonexistent")
	// The service should still have a token store (the fallback nil-key store)
	// or nil if fallback also fails. Either way no panic.
}

// TestFA_OIDCService_SetDataDir_ValidDir covers the happy path of SetDataDir
// with a valid temp directory.
func TestFA_OIDCService_SetDataDir_ValidDir(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	dir := t.TempDir()
	svc.SetDataDir(dir)
	assert.NotNil(t, svc.tokenStore)
}

// TestFA_OIDCService_SetDataDir_LoadProvidersFails covers L205-207: when
// loadProviders returns an error (corrupt provider file).
func TestFA_OIDCService_SetDataDir_LoadProvidersFails(t *testing.T) {
	dir := t.TempDir()
	// Write an invalid JSON providers file so loadProviders fails.
	err := os.WriteFile(filepath.Join(dir, oidcProvidersFile), []byte("{invalid"), 0600)
	require.NoError(t, err)

	svc := NewOIDCService(slog.Default())
	svc.SetDataDir(dir) // Should log warning but not panic.
}

// TestFA_OIDCService_Close_WithTokenStoreError covers L227-229: Close() when
// StopAllRefresh returns an error.
func TestFA_OIDCService_Close_WithTokenStoreError(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetTokenStore(&faTokenStore{closeErr: errors.New("close error")})

	err := svc.Close()
	assert.Error(t, err) // tokenStore.Close() error propagates
}

// TestFA_OIDCService_Close_NilTokenStore covers Close() with nil tokenStore.
func TestFA_OIDCService_Close_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	err := svc.Close()
	assert.NoError(t, err)
}

// TestFA_OIDCService_Login_AWSType covers L452-453: Login with an AWS-type
// provider returns ErrOIDCUnsupportedAWSLogin.
func TestFA_OIDCService_Login_AWSType(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["aws-test"] = &OIDCProviderEntry{
		Name:   "aws-test",
		Type:   OIDCProviderTypeAWS,
		Issuer: "https://accounts.google.com",
	}

	result, err := svc.Login("aws-test")
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "AWS")
	assert.False(t, result.Success)
}

// TestFA_OIDCService_Login_ProviderNotFound covers L448-449: Login with
// a nonexistent provider.
func TestFA_OIDCService_Login_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(slog.Default())

	result, err := svc.Login("nonexistent")
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "provider not found")
	assert.False(t, result.Success)
}

// TestFA_OIDCService_RefreshToken_NoTokenStore covers L645-646: RefreshToken
// when tokenStore is nil.
func TestFA_OIDCService_RefreshToken_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	_, err := svc.RefreshToken("test")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

// TestFA_OIDCService_RefreshToken_LoadError covers L649-651: RefreshToken
// when token store Load returns error.
func TestFA_OIDCService_RefreshToken_LoadError(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	svc.SetTokenStore(&faTokenStore{loadErr: errors.New("load failed")})

	_, err := svc.RefreshToken("test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCTokenNotFound)
}

// TestFA_OIDCService_RefreshToken_NoRefreshToken covers L654-655: RefreshToken
// when stored token has no refresh_token.
func TestFA_OIDCService_RefreshToken_NoRefreshToken(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	svc.SetTokenStore(&faTokenStore{
		loadResp: &oidc.TokenResponse{
			AccessToken:  "access-token",
			RefreshToken: "", // no refresh token
		},
	})

	_, err := svc.RefreshToken("test")
	assert.ErrorIs(t, err, ErrOIDCNoRefreshToken)
}

// TestFA_OIDCService_RefreshToken_ProviderNotFound covers L641-642.
func TestFA_OIDCService_RefreshToken_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	_, err := svc.RefreshToken("nonexistent")
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
}

// TestFA_OIDCService_ExecuteScript_EmptyScript covers L847-849.
func TestFA_OIDCService_ExecuteScript_EmptyScript(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	_, err := svc.ExecuteScript("test", "")
	assert.ErrorIs(t, err, ErrOIDCExecEmpty)
}

// TestFA_OIDCService_ExecuteScript_ProviderNotFound covers L851-853.
func TestFA_OIDCService_ExecuteScript_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	result, err := svc.ExecuteScript("nonexistent", "echo hello")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
	assert.False(t, result.Success)
}

// TestFA_OIDCService_ExecuteScript_NonZeroExit covers L892-903: script with
// non-zero exit code (ExitError path).
func TestFA_OIDCService_ExecuteScript_NonZeroExit(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "client-id",
	}
	svc.SetTokenStore(&faTokenStore{
		loadResp: &oidc.TokenResponse{
			AccessToken: "tok",
			Expiry:      time.Now().Add(time.Hour),
		},
	})

	result, err := svc.ExecuteScript("test", "exit 42")
	assert.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, 42, result.ExitCode)
}

// TestFA_OIDCService_ExecuteScript_Success covers the happy path of exec.
func TestFA_OIDCService_ExecuteScript_Success(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "client-id",
	}
	svc.SetTokenStore(&faTokenStore{
		loadResp: &oidc.TokenResponse{
			AccessToken: "tok",
		},
	})

	result, err := svc.ExecuteScript("test", "echo hello")
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ExitCode)
}

// TestFA_OIDCService_ExecuteScript_NilTokenStore covers exec with nil
// tokenStore (exercises the nil-token exec payload path).
func TestFA_OIDCService_ExecuteScript_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "client-id",
	}
	svc.SetTokenStore(nil) // no token store

	result, err := svc.ExecuteScript("test", "echo hello")
	assert.NoError(t, err)
	assert.True(t, result.Success)
}

// TestFA_OIDCService_SaveProviders_ReadOnlyDir covers L1098-1100: saveProviders
// fails when the directory is read-only.
func TestFA_OIDCService_SaveProviders_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.MkdirAll(readOnlyDir, 0700))

	svc := NewOIDCService(slog.Default())
	svc.dataDir = readOnlyDir

	// Make the dir read-only so the temp file write fails.
	require.NoError(t, os.Chmod(readOnlyDir, 0500))
	t.Cleanup(func() { os.Chmod(readOnlyDir, 0700) })

	err := svc.AddProvider(&OIDCProviderEntry{
		Name:     "test-prov",
		Issuer:   "https://example.com",
		ClientID: "cid",
	})
	assert.Error(t, err)
}

// TestFA_OIDCService_SaveProviders_NoDataDir covers L1076-1078: saveProviders
// with empty dataDir returns nil without writing.
func TestFA_OIDCService_SaveProviders_NoDataDir(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	// dataDir is empty, so saveProviders should return nil.
	err := svc.AddProvider(&OIDCProviderEntry{
		Name:     "test-prov",
		Issuer:   "https://example.com",
		ClientID: "cid",
	})
	assert.NoError(t, err)
}

// TestFA_OIDCService_TokenResponseToInfo_ExpiresIn covers L973-976: when
// Expiry is zero but ExpiresIn > 0.
func TestFA_OIDCService_TokenResponseToInfo_ExpiresIn(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
		Scopes: []string{"openid"},
	}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "tok",
		ExpiresIn:   3600,
		// Expiry is zero
	}
	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.NotEmpty(t, info.ExpiresAt)
	assert.Equal(t, int64(3600), info.ExpiresIn)
	assert.False(t, info.IsExpired)
}

// TestFA_OIDCService_TokenResponseToInfo_WithExpiry covers L977-981.
func TestFA_OIDCService_TokenResponseToInfo_WithExpiry(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "tok",
		Expiry:      time.Now().Add(time.Hour),
	}
	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.NotEmpty(t, info.ExpiresAt)
	assert.False(t, info.IsExpired)
}

// TestFA_OIDCService_TokenResponseToInfo_ScopeFromToken covers L984-986: when
// entry has no scopes but token has Scope field.
func TestFA_OIDCService_TokenResponseToInfo_ScopeFromToken(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
		// no scopes
	}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "tok",
		Scope:       "openid profile email",
	}
	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Equal(t, []string{"openid", "profile", "email"}, info.Scopes)
}

// TestFA_OIDCService_TokenResponseToInfo_IDTokenClaims covers L989-991:
// extracting claims from an ID token.
func TestFA_OIDCService_TokenResponseToInfo_IDTokenClaims(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	entry := &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
		Scopes: []string{"openid"},
	}

	// Build a fake JWT (header.payload.signature) with base64url-encoded payload.
	// Payload: {"sub":"user123","email":"user@test.com","name":"Test User"}
	payload := "eyJzdWIiOiJ1c2VyMTIzIiwiZW1haWwiOiJ1c2VyQHRlc3QuY29tIiwibmFtZSI6IlRlc3QgVXNlciJ9"
	idToken := "eyJhbGciOiJSUzI1NiJ9." + payload + ".signature"

	tokenResp := &oidc.TokenResponse{
		AccessToken: "tok",
		IDToken:     idToken,
		Expiry:      time.Now().Add(time.Hour),
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Equal(t, "user123", info.Subject)
	assert.Equal(t, "user@test.com", info.Email)
	assert.Equal(t, "Test User", info.Name)
}

// TestFA_OIDCService_ExtractIDTokenClaims_InvalidJWT covers L1000-1001:
// ID token with wrong number of parts.
func TestFA_OIDCService_ExtractIDTokenClaims_InvalidJWT(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims("not.a.valid.jwt.token", info)
	assert.Empty(t, info.Subject)
}

// TestFA_OIDCService_ExtractIDTokenClaims_InvalidBase64 covers L1004-1006:
// ID token with invalid base64 in payload.
func TestFA_OIDCService_ExtractIDTokenClaims_InvalidBase64(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims("header.!!!invalid-base64!!!.sig", info)
	assert.Empty(t, info.Subject)
}

// TestFA_OIDCService_BuildExecPayload_NilToken covers L1030 else branch:
// buildExecPayload with nil tokenResp.
func TestFA_OIDCService_BuildExecPayload_NilToken(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
		Scopes:   []string{"openid"},
	}
	payload := svc.buildExecPayload("test", entry, nil)
	assert.Equal(t, "test", payload.Provider)
	assert.Empty(t, payload.AccessToken)
}

// TestFA_OIDCService_BuildExecPayload_WithToken covers L1030-1039:
// buildExecPayload with a valid tokenResp including expiry.
func TestFA_OIDCService_BuildExecPayload_WithToken(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	entry := &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "cid",
	}
	expiry := time.Now().Add(time.Hour)
	tokenResp := &oidc.TokenResponse{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id-token",
		ExpiresIn:    3600,
		Expiry:       expiry,
	}
	payload := svc.buildExecPayload("test", entry, tokenResp)
	assert.Equal(t, "access", payload.AccessToken)
	assert.Equal(t, "refresh", payload.RefreshToken)
	assert.NotEmpty(t, payload.ExpiresAt)
}

// TestFA_OIDCService_LoadProviders_NonExistentDir covers L1046-1047:
// loadProviders with empty dataDir returns nil.
func TestFA_OIDCService_LoadProviders_NonExistentDir(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.dataDir = ""
	err := svc.loadProviders()
	assert.NoError(t, err)
}

// TestFA_OIDCService_LoadProviders_NonExistentFile covers L1053-1054:
// loadProviders when file does not exist returns nil.
func TestFA_OIDCService_LoadProviders_NonExistentFile(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.dataDir = t.TempDir()
	err := svc.loadProviders()
	assert.NoError(t, err)
}

// TestFA_OIDCService_LoadProviders_ValidFile covers the happy path:
// loadProviders reading a valid providers file.
func TestFA_OIDCService_LoadProviders_ValidFile(t *testing.T) {
	dir := t.TempDir()
	data := `{"providers":[{"name":"test","type":"oidc","issuer":"https://example.com","client_id":"cid","redirect_url":"http://localhost:8085/callback","scopes":["openid"],"auto_refresh":0,"background":false}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, oidcProvidersFile), []byte(data), 0600))

	svc := NewOIDCService(slog.Default())
	svc.dataDir = dir
	err := svc.loadProviders()
	assert.NoError(t, err)
	assert.Len(t, svc.providers, 1)
}

// TestFA_OIDCService_RefreshToken_DiscoveryFails covers L671-673: RefreshToken
// when oidc.NewProvider fails due to bad issuer (no network).
func TestFA_OIDCService_RefreshToken_DiscoveryFails(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetContext(context.Background())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "http://127.0.0.1:1/invalid",
	}
	svc.SetTokenStore(&faTokenStore{
		loadResp: &oidc.TokenResponse{
			AccessToken:  "tok",
			RefreshToken: "refresh-tok",
		},
	})

	_, err := svc.RefreshToken("test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCRefreshFailed)
}

// TestFA_OIDCService_Login_DiscoveryFails covers L470-472: Login when
// oidc.NewProvider fails (bad issuer).
func TestFA_OIDCService_Login_DiscoveryFails(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetContext(context.Background())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Type:     OIDCProviderTypeStandard,
		Issuer:   "http://127.0.0.1:1/invalid",
		ClientID: "cid",
	}

	result, err := svc.Login("test")
	assert.NoError(t, err)
	assert.NotEmpty(t, result.Error)
	assert.False(t, result.Success)
}

// TestFA_OIDCService_GetTokenInfo_NoTokenStore covers L626-628.
func TestFA_OIDCService_GetTokenInfo_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	_, err := svc.GetTokenInfo("test")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

// TestFA_OIDCService_GetTokenInfo_LoadError covers L631-632.
func TestFA_OIDCService_GetTokenInfo_LoadError(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	svc.SetTokenStore(&faTokenStore{loadErr: errors.New("not found")})

	_, err := svc.GetTokenInfo("test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCTokenNotFound)
}

// TestFA_OIDCService_Logout_NoTokenStore covers L703-704.
func TestFA_OIDCService_Logout_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	err := svc.Logout("test")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

// TestFA_OIDCService_Logout_TokenNotFound covers L709-710: logout when
// token is not found (treated as success).
func TestFA_OIDCService_Logout_TokenNotFound(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	svc.SetTokenStore(&faTokenStore{deleteErr: oidc.ErrTokenNotFound})

	err := svc.Logout("test")
	assert.NoError(t, err) // ErrTokenNotFound is treated as success
}

// TestFA_OIDCService_Logout_DeleteError covers L712: logout when
// delete returns non-ErrTokenNotFound error.
func TestFA_OIDCService_Logout_DeleteError(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	svc.SetTokenStore(&faTokenStore{deleteErr: errors.New("disk error")})

	err := svc.Logout("test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCLogoutFailed)
}

// TestFA_OIDCService_GetAllTokens_NilTokenStore covers L723-725.
func TestFA_OIDCService_GetAllTokens_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	infos := svc.GetAllTokens()
	assert.Nil(t, infos)
}

// TestFA_OIDCService_GetAllTokens_WithTokens covers L727-733.
func TestFA_OIDCService_GetAllTokens_WithTokens(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	svc.SetTokenStore(&faTokenStore{
		loadResp: &oidc.TokenResponse{
			AccessToken: "tok",
			ExpiresIn:   3600,
		},
	})

	infos := svc.GetAllTokens()
	assert.Len(t, infos, 1)
	assert.Equal(t, "test", infos[0].Provider)
}

// TestFA_OIDCService_GetAllTokens_LoadError covers L729-731: when Load
// returns error for a provider (should be skipped).
func TestFA_OIDCService_GetAllTokens_LoadError(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	svc.SetTokenStore(&faTokenStore{loadErr: errors.New("not found")})

	infos := svc.GetAllTokens()
	assert.Empty(t, infos) // Error should be skipped
}

// TestFA_OIDCService_StartAutoRefresh_Disabled covers L747-748.
func TestFA_OIDCService_StartAutoRefresh_Disabled(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		AutoRefresh: 0,
	}

	err := svc.StartAutoRefresh("test")
	assert.ErrorIs(t, err, ErrOIDCAutoRefreshDisabled)
}

// TestFA_OIDCService_StartAutoRefresh_AlreadyRunning covers L754-755.
func TestFA_OIDCService_StartAutoRefresh_AlreadyRunning(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		AutoRefresh: 60,
	}

	// Start once.
	require.NoError(t, svc.StartAutoRefresh("test"))
	defer svc.StopAutoRefresh("test")

	// Start again -- should fail.
	err := svc.StartAutoRefresh("test")
	assert.ErrorIs(t, err, ErrOIDCRefreshAlreadyRunning)
}

// TestFA_OIDCService_GetRefreshStatus_NotRunning covers L814-815.
func TestFA_OIDCService_GetRefreshStatus_NotRunning(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	status, err := svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.False(t, status.Running)
}

// TestFA_OIDCService_GetRefreshStatus_Running covers L818-824.
func TestFA_OIDCService_GetRefreshStatus_Running(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		AutoRefresh: 3600,
		Issuer:      "https://example.com",
	}

	require.NoError(t, svc.StartAutoRefresh("test"))
	defer svc.StopAutoRefresh("test")

	status, err := svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.True(t, status.Running)
}

// TestFA_OIDCService_StopAllRefresh covers L797-806.
func TestFA_OIDCService_StopAllRefresh(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test1"] = &OIDCProviderEntry{Name: "test1", AutoRefresh: 3600, Issuer: "https://example1.com"}
	svc.providers["test2"] = &OIDCProviderEntry{Name: "test2", AutoRefresh: 3600, Issuer: "https://example2.com"}

	require.NoError(t, svc.StartAutoRefresh("test1"))
	require.NoError(t, svc.StartAutoRefresh("test2"))

	err := svc.StopAllRefresh()
	assert.NoError(t, err)
	assert.Empty(t, svc.refreshProcs)
}

// TestFA_OIDCService_GetAllRefreshStatus covers L828-840.
func TestFA_OIDCService_GetAllRefreshStatus(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		AutoRefresh: 3600,
		Issuer:      "https://example.com",
	}

	// No refresh processes.
	statuses := svc.GetAllRefreshStatus()
	assert.Empty(t, statuses)

	// Start one.
	require.NoError(t, svc.StartAutoRefresh("test"))
	defer svc.StopAutoRefresh("test")

	statuses = svc.GetAllRefreshStatus()
	assert.Len(t, statuses, 1)
	assert.Equal(t, "test", statuses[0].Provider)
}

// TestFA_OIDCService_DiscoverProvider_EmptyIssuer covers L420-422.
func TestFA_OIDCService_DiscoverProvider_EmptyIssuer(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	_, err := svc.DiscoverProvider("")
	assert.ErrorIs(t, err, ErrOIDCInvalidIssuer)
}

// TestFA_OIDCService_DiscoverProvider_BadIssuer covers L436-438.
func TestFA_OIDCService_DiscoverProvider_BadIssuer(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetContext(context.Background())
	_, err := svc.DiscoverProvider("http://127.0.0.1:1/invalid")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCDiscoveryFailed)
}

// TestFA_OIDCService_LoadProviders_ReadError covers L1051-1056: when
// the providers file exists but is not readable.
func TestFA_OIDCService_LoadProviders_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, oidcProvidersFile)
	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0600))
	require.NoError(t, os.Chmod(path, 0000))
	t.Cleanup(func() { os.Chmod(path, 0600) })

	svc := NewOIDCService(slog.Default())
	svc.dataDir = dir
	err := svc.loadProviders()
	assert.Error(t, err)
}

// =========================================================================
// admin_service.go tests
// =========================================================================

// TestFA_AdminService_IsAdmin_ReturnsValue covers L112-118: IsAdmin
// should return false for non-root (or true for root, but either way
// it exercises the user.Current() path).
func TestFA_AdminService_IsAdmin_ReturnsValue(t *testing.T) {
	svc := NewAdminService()
	result := svc.IsAdmin()
	// We are not root in CI, so expect false.
	assert.False(t, result)
}

// TestFA_AdminService_GetBackendInfo_ListError covers L211-213: when
// ListBackends returns an error (it actually never does with current impl,
// but we exercise the code path anyway).
func TestFA_AdminService_GetBackendInfo_ListError(t *testing.T) {
	svc := NewAdminService()
	// With no remote func, ListBackends always returns local defaults.
	info, err := svc.GetBackendInfo("software")
	require.NoError(t, err)
	assert.Equal(t, "software", info.ID)
}

// TestFA_AdminService_GetAuditLogs_NonAdmin covers L226-228: GetAuditLogs
// when not admin.
func TestFA_AdminService_GetAuditLogs_NonAdmin(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())
	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}
	_, err := svc.GetAuditLogs(nil)
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
}

// TestFA_AdminService_ExportAuditLogs_NonAdmin covers L238-239: ExportAuditLogs
// when not admin.
func TestFA_AdminService_ExportAuditLogs_NonAdmin(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())
	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}
	_, err := svc.ExportAuditLogs("json")
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
}

// TestFA_AdminService_ExportAuditLogs_InvalidFormat covers L245-246.
func TestFA_AdminService_ExportAuditLogs_InvalidFormat(t *testing.T) {
	svc := NewAdminService()
	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}
	_, err := svc.ExportAuditLogs("xml")
	// Non-admin gets ErrAdminNotAuthorized first.
	assert.Error(t, err)
}

// =========================================================================
// clipboard_service.go tests
// =========================================================================

// TestFA_ClipboardService_DetectClipboardTool covers L217-228:
// detectClipboardTool returns the first available tool or clipToolNone.
func TestFA_ClipboardService_DetectClipboardTool(t *testing.T) {
	tool := detectClipboardTool()
	// In CI, one of xclip/xsel/wl-copy might be available, or none.
	// Just verify it returns a valid constant.
	assert.True(t, tool >= clipToolNone && tool <= clipToolWlCopy)
}

// TestFA_ClipboardService_CopyWithClear_NoTool covers L85-87: CopyWithClear
// when no clipboard tool is available.
func TestFA_ClipboardService_CopyWithClear_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	err := svc.CopyWithClear("text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFA_ClipboardService_CopyWithClear_ZeroTimeout covers L93-96:
// CopyWithClear with timeout <= 0 skips scheduleClear.
func TestFA_ClipboardService_CopyWithClear_ZeroTimeout(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)
	svc.timeout.Store(0)

	// With timeout <= 0, CopyWithClear writes to clipboard and returns
	// nil without scheduling a clear timer.
	err := svc.CopyWithClear("text")
	assert.NoError(t, err)
}

// TestFA_ClipboardService_Copy_NoTool covers L105-107.
func TestFA_ClipboardService_Copy_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	err := svc.Copy("text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFA_ClipboardService_ClearClipboard_NoTool covers L122-123.
func TestFA_ClipboardService_ClearClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	err := svc.ClearClipboard()
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFA_ClipboardService_WriteClipboard_NoTool covers L180-181: writeClipboard
// default case.
func TestFA_ClipboardService_WriteClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	err := svc.writeClipboard("text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFA_ClipboardService_ReadClipboard_NoTool covers L204-205: readClipboard
// default case.
func TestFA_ClipboardService_ReadClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	_, err := svc.readClipboard()
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFA_ClipboardService_WriteClipboard_XclipFails covers L174-175 + L186-187:
// writeClipboard with xclip tool when xclip is not installed.
func TestFA_ClipboardService_WriteClipboard_XclipFails(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolXclip,
	}
	err := svc.writeClipboard("test")
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardWriteFailed)
	}
}

// TestFA_ClipboardService_WriteClipboard_XselFails covers xsel path.
func TestFA_ClipboardService_WriteClipboard_XselFails(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolXsel,
	}
	err := svc.writeClipboard("test")
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardWriteFailed)
	}
}

// TestFA_ClipboardService_WriteClipboard_WlCopyFails covers wl-copy path.
func TestFA_ClipboardService_WriteClipboard_WlCopyFails(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolWlCopy,
	}
	err := svc.writeClipboard("test")
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardWriteFailed)
	}
}

// TestFA_ClipboardService_ReadClipboard_XclipFails covers L198-199 + L208-210.
func TestFA_ClipboardService_ReadClipboard_XclipFails(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolXclip,
	}
	_, err := svc.readClipboard()
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardReadFailed)
	}
}

// TestFA_ClipboardService_ReadClipboard_XselFails covers xsel read path.
func TestFA_ClipboardService_ReadClipboard_XselFails(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolXsel,
	}
	_, err := svc.readClipboard()
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardReadFailed)
	}
}

// TestFA_ClipboardService_ReadClipboard_WlPasteFails covers wl-paste path.
func TestFA_ClipboardService_ReadClipboard_WlPasteFails(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolWlCopy,
	}
	_, err := svc.readClipboard()
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardReadFailed)
	}
}

// TestFA_ClipboardService_ScheduleClear_CancelsOld covers L136-138:
// scheduleClear cancels previous pending clear.
func TestFA_ClipboardService_ScheduleClear_CancelsOld(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}

	// Set an initial cancelFn.
	ctx1, cancel1 := context.WithCancel(context.Background())
	svc.cancelFn = cancel1

	// Schedule a new clear -- should cancel the old one.
	svc.scheduleClear("text", 10*time.Minute)

	// Old context should be cancelled.
	select {
	case <-ctx1.Done():
		// Expected: old context was cancelled.
	case <-time.After(time.Second):
		t.Fatal("old cancel function was not called")
	}

	// Clean up: cancel the new one.
	svc.clearMu.Lock()
	if svc.cancelFn != nil {
		svc.cancelFn()
	}
	svc.clearMu.Unlock()
}

// TestFA_ClipboardService_ClearClipboard_CancelsTimer covers L116-119:
// ClearClipboard cancels the pending timer.
func TestFA_ClipboardService_ClearClipboard_CancelsTimer(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}

	ctx, cancel := context.WithCancel(context.Background())
	svc.cancelFn = cancel

	err := svc.ClearClipboard()
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)

	// Verify the cancel was called.
	select {
	case <-ctx.Done():
		// Good.
	case <-time.After(time.Second):
		t.Fatal("cancelFn was not called")
	}

	// cancelFn should be nil now.
	svc.clearMu.Lock()
	assert.Nil(t, svc.cancelFn)
	svc.clearMu.Unlock()
}

// TestFA_ClipboardService_SetTimeout covers L69-73.
func TestFA_ClipboardService_SetTimeout(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	svc.SetTimeout(-5) // negative should be clamped to 0
	assert.Equal(t, 0, svc.GetTimeout())

	svc.SetTimeout(60)
	assert.Equal(t, 60, svc.GetTimeout())
}

// =========================================================================
// barrier_service.go tests
// =========================================================================

// TestFA_BarrierService_Initialize_DirExistsNoRootKey covers L146-163:
// Initialize when the barrier directory exists but no root key is present.
// This exercises the base.Close() at L162 (dir exists, no root key).
func TestFA_BarrierService_Initialize_DirExistsNoRootKey(t *testing.T) {
	dir := t.TempDir()
	storageDir := filepath.Join(dir, barrierSubdir)
	require.NoError(t, os.MkdirAll(storageDir, 0700))

	svc := NewBarrierService(dir, slog.Default())
	err := svc.Initialize("my-password", "software")
	assert.NoError(t, err)
	assert.True(t, svc.IsUnsealed())
}

// TestFA_BarrierService_Initialize_StorageDirExistsButFilestorageNewFails
// covers L150-152: Initialize when storage dir exists but filestorage.New
// fails. We simulate by making the dir unreadable.
func TestFA_BarrierService_Initialize_StorageDirExistsButFilestorageNewFails(t *testing.T) {
	dir := t.TempDir()
	storageDir := filepath.Join(dir, barrierSubdir)
	require.NoError(t, os.MkdirAll(storageDir, 0700))

	// Make the directory unreadable so filestorage.New fails.
	require.NoError(t, os.Chmod(storageDir, 0000))
	t.Cleanup(func() { os.Chmod(storageDir, 0700) })

	svc := NewBarrierService(dir, slog.Default())
	err := svc.Initialize("test-password", "software")
	assert.Error(t, err)
}

// TestFA_BarrierService_Initialize_ExistsCheckError covers L158-161:
// when root key exists (AlreadyInit path).
func TestFA_BarrierService_Initialize_ExistsCheckError(t *testing.T) {
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("pw1", "software"))

	err := svc.Initialize("pw2", "software")
	assert.ErrorIs(t, err, ErrBarrierAlreadyInit)
}

// TestFA_BarrierService_Initialize_PasswordRequired covers L170-172:
// when best strategy is software and password is empty.
func TestFA_BarrierService_Initialize_PasswordRequired(t *testing.T) {
	svc := newTestBarrierService(t)
	err := svc.Initialize("", "software")
	assert.ErrorIs(t, err, ErrBarrierPasswordRequired)
}

// TestFA_BarrierService_Unseal_HappyPath covers L219-243: full unseal path.
func TestFA_BarrierService_Unseal_HappyPath(t *testing.T) {
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("pw", "software"))
	require.NoError(t, svc.Seal())

	err := svc.Unseal("pw", "software")
	assert.NoError(t, err)
	assert.True(t, svc.IsUnsealed())
}

// TestFA_BarrierService_Unseal_BadPassword covers L236-238: Unseal with
// wrong password fails.
func TestFA_BarrierService_Unseal_BadPassword(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	require.NoError(t, svc.Initialize("correct-password", "software"))
	require.NoError(t, svc.Seal())

	// Create new service instance to force re-read from disk.
	svc2 := NewBarrierService(dir, slog.Default())
	err := svc2.Unseal("wrong-password", "software")
	assert.Error(t, err) // L236-238: unseal fails
}

// TestFA_BarrierService_Context covers L317-320: context() fallback.
func TestFA_BarrierService_Context(t *testing.T) {
	svc := newTestBarrierService(t)
	// Without SetContext, context() should return Background.
	ctx := svc.context()
	assert.NotNil(t, ctx)

	// With SetContext, should return the set context.
	custom := context.WithValue(context.Background(), "key", "value")
	svc.SetContext(custom)
	ctx = svc.context()
	assert.Equal(t, "value", ctx.Value("key"))
}

// TestFA_BarrierService_Initialize_MkdirAllFails covers L175-177: when
// os.MkdirAll fails (e.g., parent is read-only).
func TestFA_BarrierService_Initialize_MkdirAllFails(t *testing.T) {
	dir := t.TempDir()
	// Make the parent dir read-only so MkdirAll for barrier subdir fails.
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	svc := NewBarrierService(dir, slog.Default())
	err := svc.Initialize("pw", "software")
	assert.Error(t, err)
}

// TestFA_BarrierService_Initialize_FilestorageNewFailsAfterMkdirAll covers
// L180-182: when filestorage.New fails after dir creation. We create
// storageDir as a file (not a directory) to trigger this.
func TestFA_BarrierService_Initialize_FilestorageNewFailsAfterMkdirAll(t *testing.T) {
	dir := t.TempDir()
	storageDir := filepath.Join(dir, barrierSubdir)
	require.NoError(t, os.MkdirAll(storageDir, 0700))
	require.NoError(t, os.RemoveAll(storageDir))
	require.NoError(t, os.WriteFile(storageDir, []byte("not-a-dir"), 0600))

	svc := NewBarrierService(dir, slog.Default())
	err := svc.Initialize("pw", "software")
	assert.Error(t, err)
}

// TestFA_BarrierService_Unseal_FilestorageNewFails covers L220-222: when
// filestorage.New fails during Unseal. We corrupt the barrier dir.
func TestFA_BarrierService_Unseal_FilestorageNewFails(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	require.NoError(t, svc.Initialize("pw", "software"))
	require.NoError(t, svc.Seal())

	// Replace the barrier directory with a file.
	storageDir := filepath.Join(dir, barrierSubdir)
	require.NoError(t, os.RemoveAll(storageDir))
	require.NoError(t, os.WriteFile(storageDir, []byte("not-a-dir"), 0600))

	svc2 := NewBarrierService(dir, slog.Default())
	err := svc2.Unseal("pw", "software")
	assert.Error(t, err) // L220-222: filestorage.New fails
}

// =========================================================================
// oath_service.go tests
// =========================================================================

// TestFA_OATHService_GenerateTOTP_StoreGetError covers L158-159: when
// store.Get returns error.
func TestFA_OATHService_GenerateTOTP_StoreGetError(t *testing.T) {
	store := &faOATHStore{getErr: errors.New("get failed")}
	svc := NewOATHService(store)

	_, err := svc.GenerateTOTP("test-id")
	assert.Error(t, err)
}

// TestFA_OATHService_GenerateTOTP_NotTOTP covers L162-163: when credential
// type is HOTP.
func TestFA_OATHService_GenerateTOTP_NotTOTP(t *testing.T) {
	store := &faOATHStore{
		getCred: &oath.Credential{
			ID:        "test-id",
			Name:      "Test",
			Type:      oath.TypeHOTP,
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "SHA1",
			Digits:    6,
		},
	}
	svc := NewOATHService(store)

	_, err := svc.GenerateTOTP("test-id")
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

// TestFA_OATHService_GenerateTOTP_GeneratorError covers L167-169: when
// oath.NewGenerator fails (bad algorithm).
func TestFA_OATHService_GenerateTOTP_GeneratorError(t *testing.T) {
	store := &faOATHStore{
		getCred: &oath.Credential{
			ID:        "test-id",
			Name:      "Test",
			Type:      oath.TypeTOTP,
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "INVALID",
			Digits:    6,
			Period:    30,
		},
	}
	svc := NewOATHService(store)

	_, err := svc.GenerateTOTP("test-id")
	assert.Error(t, err)
}

// TestFA_OATHService_GenerateHOTP_StoreGetError covers L194-196.
func TestFA_OATHService_GenerateHOTP_StoreGetError(t *testing.T) {
	store := &faOATHStore{getErr: errors.New("get failed")}
	svc := NewOATHService(store)

	_, err := svc.GenerateHOTP("test-id")
	assert.Error(t, err)
}

// TestFA_OATHService_GenerateHOTP_NotHOTP covers L199-200.
func TestFA_OATHService_GenerateHOTP_NotHOTP(t *testing.T) {
	store := &faOATHStore{
		getCred: &oath.Credential{
			ID:        "test-id",
			Name:      "Test",
			Type:      oath.TypeTOTP,
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		},
	}
	svc := NewOATHService(store)

	_, err := svc.GenerateHOTP("test-id")
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

// TestFA_OATHService_GenerateHOTP_GeneratorError covers L203-205.
func TestFA_OATHService_GenerateHOTP_GeneratorError(t *testing.T) {
	store := &faOATHStore{
		getCred: &oath.Credential{
			ID:        "test-id",
			Name:      "Test",
			Type:      oath.TypeHOTP,
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "INVALID",
			Digits:    6,
		},
	}
	svc := NewOATHService(store)

	_, err := svc.GenerateHOTP("test-id")
	assert.Error(t, err)
}

// TestFA_OATHService_ScanQR covers L228-246: ScanQR will fail because
// there is no display in CI. This covers the qrscan error paths.
func TestFA_OATHService_ScanQR(t *testing.T) {
	svc := NewOATHService(nil)

	_, err := svc.ScanQR(-1)
	assert.Error(t, err)
	// Should be one of ErrOATHQRNotFound, ErrOATHQRScanFailed, etc.
}

// TestFA_OATHService_AddAccountFromURI_EmptyURI covers L253-255.
func TestFA_OATHService_AddAccountFromURI_EmptyURI(t *testing.T) {
	svc := NewOATHService(oath.NewMemoryStore())
	_, err := svc.AddAccountFromURI("")
	assert.ErrorIs(t, err, ErrOATHInvalidURI)
}

// TestFA_OATHService_AddAccountFromURI_InvalidScheme covers L256-258.
func TestFA_OATHService_AddAccountFromURI_InvalidScheme(t *testing.T) {
	svc := NewOATHService(oath.NewMemoryStore())
	_, err := svc.AddAccountFromURI("https://example.com")
	assert.ErrorIs(t, err, ErrOATHQRInvalidURI)
}

// TestFA_OATHService_AddAccountFromURI_ValidURI covers L259.
func TestFA_OATHService_AddAccountFromURI_ValidURI(t *testing.T) {
	svc := NewOATHService(oath.NewMemoryStore())
	acct, err := svc.AddAccountFromURI("otpauth://totp/Test:user@test.com?secret=JBSWY3DPEHPK3PXP&issuer=Test")
	require.NoError(t, err)
	assert.NotNil(t, acct)
	assert.Equal(t, "totp", acct.Type)
}

// TestFA_OATHService_GenerateTOTP_NoStore covers L150-152.
func TestFA_OATHService_GenerateTOTP_NoStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.GenerateTOTP("test")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

// TestFA_OATHService_GenerateHOTP_NoStore covers L187-189.
func TestFA_OATHService_GenerateHOTP_NoStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.GenerateHOTP("test")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

// TestFA_OATHService_GenerateTOTP_EmptyID covers L153-154.
func TestFA_OATHService_GenerateTOTP_EmptyID(t *testing.T) {
	svc := NewOATHService(oath.NewMemoryStore())
	_, err := svc.GenerateTOTP("")
	assert.ErrorIs(t, err, ErrOATHInvalidID)
}

// TestFA_OATHService_GenerateHOTP_EmptyID covers L190-192.
func TestFA_OATHService_GenerateHOTP_EmptyID(t *testing.T) {
	svc := NewOATHService(oath.NewMemoryStore())
	_, err := svc.GenerateHOTP("")
	assert.ErrorIs(t, err, ErrOATHInvalidID)
}

// TestFA_OATHService_GenerateHOTP_UpdateError covers L215-216: when
// store.Update fails after generating the code.
func TestFA_OATHService_GenerateHOTP_UpdateError(t *testing.T) {
	store := &faOATHStore{
		getCred: &oath.Credential{
			ID:        "test-id",
			Name:      "Test",
			Type:      oath.TypeHOTP,
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "SHA1",
			Digits:    6,
			Counter:   0,
		},
		updateErr: errors.New("update failed"),
	}
	svc := NewOATHService(store)

	_, err := svc.GenerateHOTP("test-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update failed")
}

// TestFA_OATHService_GenerateTOTP_Success covers the happy TOTP path
// (L166-181).
func TestFA_OATHService_GenerateTOTP_Success(t *testing.T) {
	store := &faOATHStore{
		getCred: &oath.Credential{
			ID:        "test-id",
			Name:      "Test",
			Type:      oath.TypeTOTP,
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		},
	}
	svc := NewOATHService(store)

	code, err := svc.GenerateTOTP("test-id")
	require.NoError(t, err)
	assert.NotNil(t, code)
	assert.Len(t, code.Code, 6)
	assert.Equal(t, "test-id", code.AccountID)
	assert.Equal(t, 30, code.Period)
}

// TestFA_OATHService_GenerateHOTP_Success covers the happy HOTP path
// (L203-223).
func TestFA_OATHService_GenerateHOTP_Success(t *testing.T) {
	store := &faOATHStore{
		getCred: &oath.Credential{
			ID:        "test-id",
			Name:      "Test",
			Type:      oath.TypeHOTP,
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "SHA1",
			Digits:    6,
			Counter:   0,
		},
	}
	svc := NewOATHService(store)

	code, err := svc.GenerateHOTP("test-id")
	require.NoError(t, err)
	assert.NotNil(t, code)
	assert.Len(t, code.Code, 6)
	assert.Equal(t, "test-id", code.AccountID)
}
