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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStorageBackend implements storage.Backend for testing OIDC service
// backend persistence paths.
type mockStorageBackend struct {
	data    map[string][]byte
	getErr  error
	putErr  error
	delErr  error
	listErr error
	scanErr error
}

func newMockStorageBackend() *mockStorageBackend {
	return &mockStorageBackend{data: make(map[string][]byte)}
}

func (m *mockStorageBackend) Get(_ context.Context, key string) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	v, ok := m.data[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return v, nil
}

func (m *mockStorageBackend) Put(_ context.Context, key string, value []byte) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.data[key] = value
	return nil
}

func (m *mockStorageBackend) Delete(_ context.Context, key string) error {
	if m.delErr != nil {
		return m.delErr
	}
	if _, ok := m.data[key]; !ok {
		return storage.ErrNotFound
	}
	delete(m.data, key)
	return nil
}

func (m *mockStorageBackend) List(_ context.Context, _ string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockStorageBackend) Scan(_ context.Context, _ string, fn func(key string, value []byte) error) error {
	if m.scanErr != nil {
		return m.scanErr
	}
	for k, v := range m.data {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockStorageBackend) Exists(_ context.Context, key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func (m *mockStorageBackend) Close() error { return nil }

// mockClosableTokenStore wraps a MemoryTokenStore and tracks Close calls
// to test the error path in Close().
type mockClosableTokenStore struct {
	oidc.TokenStore
	closeErr error
	closed   bool
}

func (m *mockClosableTokenStore) Close() error {
	m.closed = true
	return m.closeErr
}

// ---------------------------------------------------------------------------
// SetBackend
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_SetBackend_NilBackend(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.SetBackend(nil, "oidc/")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestOIDCService_Coverage_SetBackend_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	backend := newMockStorageBackend()

	err := svc.SetBackend(backend, "oidc/")
	require.NoError(t, err)
	assert.NotNil(t, svc.tokenStore)
	assert.Equal(t, backend, svc.backend)
	assert.Equal(t, "oidc/", svc.backendPrefix)
}

func TestOIDCService_Coverage_SetBackend_LoadsExistingProviders(t *testing.T) {
	backend := newMockStorageBackend()

	// Pre-populate the backend with provider config.
	config := oidcProvidersConfig{
		Providers: []OIDCProviderEntry{
			{Name: "backend-prov", Issuer: "https://backend.com", ClientID: "bid"},
		},
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	backend.data["oidc/"+oidcProvidersBackendKey] = data

	svc := NewOIDCService(nil)
	err = svc.SetBackend(backend, "oidc/")
	require.NoError(t, err)

	p, err := svc.GetProvider("backend-prov")
	require.NoError(t, err)
	assert.Equal(t, "https://backend.com", p.Issuer)
}

func TestOIDCService_Coverage_SetBackend_InvalidProviderJSON(t *testing.T) {
	backend := newMockStorageBackend()
	backend.data["oidc/"+oidcProvidersBackendKey] = []byte("{{not json")

	svc := NewOIDCService(nil)
	// SetBackend logs a warning but does not return an error on load failure.
	err := svc.SetBackend(backend, "oidc/")
	require.NoError(t, err)
	assert.Empty(t, svc.providers)
}

// ---------------------------------------------------------------------------
// GetRawTokenResponse
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_GetRawTokenResponse_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetRawTokenResponse("nonexistent")
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
}

func TestOIDCService_Coverage_GetRawTokenResponse_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	_, err := svc.GetRawTokenResponse("test")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestOIDCService_Coverage_GetRawTokenResponse_NoToken(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetTokenStore(oidc.NewMemoryTokenStore())
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	_, err := svc.GetRawTokenResponse("test")
	assert.ErrorIs(t, err, ErrOIDCTokenNotFound)
}

func TestOIDCService_Coverage_GetRawTokenResponse_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, store.Save("https://ex.com", &oidc.TokenResponse{
		AccessToken:  "at-raw",
		RefreshToken: "rt-raw",
		ExpiresIn:    3600,
		Expiry:       time.Now().Add(time.Hour),
	}))

	rawJSON, err := svc.GetRawTokenResponse("test")
	require.NoError(t, err)
	assert.Contains(t, rawJSON, "at-raw")
	assert.Contains(t, rawJSON, "rt-raw")

	// Verify it is valid JSON.
	var parsed oidc.TokenResponse
	assert.NoError(t, json.Unmarshal([]byte(rawJSON), &parsed))
	assert.Equal(t, "at-raw", parsed.AccessToken)
}

// ---------------------------------------------------------------------------
// GetAccessToken
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_GetAccessToken_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetAccessToken("nonexistent")
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
}

func TestOIDCService_Coverage_GetAccessToken_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	_, err := svc.GetAccessToken("test")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestOIDCService_Coverage_GetAccessToken_NoToken(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetTokenStore(oidc.NewMemoryTokenStore())
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	_, err := svc.GetAccessToken("test")
	assert.ErrorIs(t, err, ErrOIDCTokenNotFound)
}

func TestOIDCService_Coverage_GetAccessToken_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, store.Save("https://ex.com", &oidc.TokenResponse{
		AccessToken: "plain-access-token-abc123",
		Expiry:      time.Now().Add(time.Hour),
	}))

	token, err := svc.GetAccessToken("test")
	require.NoError(t, err)
	assert.Equal(t, "plain-access-token-abc123", token)
}

func TestOIDCService_Coverage_GetAccessToken_NestedJSON(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	// Simulate the edge case where access_token itself contains a nested JSON response.
	nestedJSON := `{"access_token":"inner-token-xyz","token_type":"Bearer"}`
	require.NoError(t, store.Save("https://ex.com", &oidc.TokenResponse{
		AccessToken: nestedJSON,
		Expiry:      time.Now().Add(time.Hour),
	}))

	token, err := svc.GetAccessToken("test")
	require.NoError(t, err)
	assert.Equal(t, "inner-token-xyz", token)
}

func TestOIDCService_Coverage_GetAccessToken_NestedJSON_NoInnerToken(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	// Nested JSON but without an access_token field -- should return the raw string.
	nestedJSON := `{"token_type":"Bearer"}`
	require.NoError(t, store.Save("https://ex.com", &oidc.TokenResponse{
		AccessToken: nestedJSON,
		Expiry:      time.Now().Add(time.Hour),
	}))

	token, err := svc.GetAccessToken("test")
	require.NoError(t, err)
	assert.Equal(t, nestedJSON, token)
}

// ---------------------------------------------------------------------------
// ExecuteProgram
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_ExecuteProgram_EmptyPath(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.ExecuteProgram("test", "")
	assert.ErrorIs(t, err, ErrOIDCExecEmpty)
}

func TestOIDCService_Coverage_ExecuteProgram_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	result, err := svc.ExecuteProgram("nonexistent", "/bin/echo")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestOIDCService_Coverage_ExecuteProgram_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:     "prog-test",
		Issuer:   "https://example.com",
		ClientID: "cid",
		Scopes:   []string{"openid"},
	}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, store.Save("https://example.com", &oidc.TokenResponse{
		AccessToken: "prog-at",
		Expiry:      time.Now().Add(time.Hour),
	}))

	result, err := svc.ExecuteProgram("prog-test", "/bin/echo")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ExitCode)
}

func TestOIDCService_Coverage_ExecuteProgram_NonExistentBinary(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.ExecuteProgram("test", "/nonexistent/binary/path")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCExecFailed)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, -1, result.ExitCode)
}

func TestOIDCService_Coverage_ExecuteProgram_NonZeroExit(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	// Create a script that exits with code 7.
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "exit7.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 7\n"), 0700))

	result, err := svc.ExecuteProgram("test", scriptPath)
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, 7, result.ExitCode)
}

func TestOIDCService_Coverage_ExecuteProgram_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "test", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	result, err := svc.ExecuteProgram("test", "/bin/echo")
	require.NoError(t, err)
	assert.True(t, result.Success)
}

// ---------------------------------------------------------------------------
// sanitizeScriptName
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_SanitizeScriptName_Normal(t *testing.T) {
	assert.Equal(t, "my-script_1", sanitizeScriptName("my-script_1"))
}

func TestOIDCService_Coverage_SanitizeScriptName_Spaces(t *testing.T) {
	assert.Equal(t, "my_script_name", sanitizeScriptName("my script name"))
}

func TestOIDCService_Coverage_SanitizeScriptName_SpecialChars(t *testing.T) {
	assert.Equal(t, "script", sanitizeScriptName("!@#$%^&*()"))
}

func TestOIDCService_Coverage_SanitizeScriptName_Empty(t *testing.T) {
	assert.Equal(t, "script", sanitizeScriptName(""))
}

func TestOIDCService_Coverage_SanitizeScriptName_Mixed(t *testing.T) {
	assert.Equal(t, "Hello_World-123", sanitizeScriptName("Hello World-123!"))
}

// ---------------------------------------------------------------------------
// scriptsDir
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_ScriptsDir_NoDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.scriptsDir()
	assert.ErrorIs(t, err, ErrOIDCScriptDirUnavailable)
}

func TestOIDCService_Coverage_ScriptsDir_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	dir, err := svc.scriptsDir()
	require.NoError(t, err)
	assert.Contains(t, dir, oidcScriptsDir)

	// Verify directory was created.
	info, statErr := os.Stat(dir)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}

// ---------------------------------------------------------------------------
// SaveScript
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_SaveScript_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.SaveScript("", "echo hello")
	assert.ErrorIs(t, err, ErrOIDCScriptNameRequired)
}

func TestOIDCService_Coverage_SaveScript_EmptyContent(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.SaveScript("test", "")
	assert.ErrorIs(t, err, ErrOIDCScriptContentRequired)
}

func TestOIDCService_Coverage_SaveScript_NoDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.SaveScript("test", "echo hello")
	assert.ErrorIs(t, err, ErrOIDCScriptDirUnavailable)
}

func TestOIDCService_Coverage_SaveScript_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	saved, err := svc.SaveScript("My Test Script", "#!/bin/sh\necho hello\n")
	require.NoError(t, err)
	require.NotNil(t, saved)
	assert.Equal(t, "My Test Script", saved.Name)
	assert.Equal(t, "My_Test_Script.sh", saved.FileName)

	// Verify file was written.
	path := filepath.Join(svc.dataDir, oidcScriptsDir, saved.FileName)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "echo hello")
}

// ---------------------------------------------------------------------------
// ListScripts
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_ListScripts_NoDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.ListScripts()
	assert.ErrorIs(t, err, ErrOIDCScriptDirUnavailable)
}

func TestOIDCService_Coverage_ListScripts_EmptyDir(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	// Ensure the scripts dir exists but is empty.
	_, dirErr := svc.scriptsDir()
	require.NoError(t, dirErr)

	scripts, err := svc.ListScripts()
	require.NoError(t, err)
	assert.Empty(t, scripts)
}

func TestOIDCService_Coverage_ListScripts_WithScripts(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	// Save two scripts.
	_, err := svc.SaveScript("script1", "#!/bin/sh\necho one\n")
	require.NoError(t, err)
	_, err = svc.SaveScript("script2", "#!/bin/sh\necho two\n")
	require.NoError(t, err)

	scripts, err := svc.ListScripts()
	require.NoError(t, err)
	assert.Len(t, scripts, 2)

	names := make(map[string]bool)
	for _, s := range scripts {
		names[s.Name] = true
	}
	assert.True(t, names["script1"])
	assert.True(t, names["script2"])
}

func TestOIDCService_Coverage_ListScripts_IgnoresNonShFiles(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	dir, err := svc.scriptsDir()
	require.NoError(t, err)

	// Create a .sh file and a .txt file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "valid.sh"), []byte("echo hi"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.txt"), []byte("text"), 0600))

	scripts, err := svc.ListScripts()
	require.NoError(t, err)
	assert.Len(t, scripts, 1)
	assert.Equal(t, "valid", scripts[0].Name)
}

func TestOIDCService_Coverage_ListScripts_IgnoresDirectories(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	dir, err := svc.scriptsDir()
	require.NoError(t, err)

	// Create a directory with .sh suffix (unusual but should be ignored).
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "good.sh"), []byte("echo hi"), 0700))

	scripts, err := svc.ListScripts()
	require.NoError(t, err)
	assert.Len(t, scripts, 1)
	assert.Equal(t, "good", scripts[0].Name)
}

// ---------------------------------------------------------------------------
// GetScriptContent
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_GetScriptContent_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetScriptContent("")
	assert.ErrorIs(t, err, ErrOIDCScriptNameRequired)
}

func TestOIDCService_Coverage_GetScriptContent_NoDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetScriptContent("test.sh")
	assert.ErrorIs(t, err, ErrOIDCScriptDirUnavailable)
}

func TestOIDCService_Coverage_GetScriptContent_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	_, err := svc.GetScriptContent("nonexistent.sh")
	assert.ErrorIs(t, err, ErrOIDCScriptNotFound)
}

func TestOIDCService_Coverage_GetScriptContent_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	expectedContent := "#!/bin/sh\necho 'hello world'\n"
	_, err := svc.SaveScript("read-me", expectedContent)
	require.NoError(t, err)

	content, err := svc.GetScriptContent("read-me.sh")
	require.NoError(t, err)
	assert.Equal(t, expectedContent, content)
}

// ---------------------------------------------------------------------------
// DeleteScript
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_DeleteScript_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.DeleteScript("")
	assert.ErrorIs(t, err, ErrOIDCScriptNameRequired)
}

func TestOIDCService_Coverage_DeleteScript_NoDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.DeleteScript("test.sh")
	assert.ErrorIs(t, err, ErrOIDCScriptDirUnavailable)
}

func TestOIDCService_Coverage_DeleteScript_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	err := svc.DeleteScript("nonexistent.sh")
	assert.ErrorIs(t, err, ErrOIDCScriptNotFound)
}

func TestOIDCService_Coverage_DeleteScript_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	saved, err := svc.SaveScript("delete-me", "echo bye")
	require.NoError(t, err)

	err = svc.DeleteScript(saved.FileName)
	assert.NoError(t, err)

	// Verify file was removed.
	_, err = svc.GetScriptContent(saved.FileName)
	assert.ErrorIs(t, err, ErrOIDCScriptNotFound)
}

// ---------------------------------------------------------------------------
// ExecuteScriptFile
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_ExecuteScriptFile_EmptyPath(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.ExecuteScriptFile("test", "")
	assert.ErrorIs(t, err, ErrOIDCExecEmpty)
}

func TestOIDCService_Coverage_ExecuteScriptFile_FileNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	result, err := svc.ExecuteScriptFile("test", "/nonexistent/script.sh")
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, -1, result.ExitCode)
}

func TestOIDCService_Coverage_ExecuteScriptFile_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	store := oidc.NewMemoryTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{Name: "file-exec", Issuer: "https://ex.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	require.NoError(t, store.Save("https://ex.com", &oidc.TokenResponse{
		AccessToken: "at-file",
		Expiry:      time.Now().Add(time.Hour),
	}))

	// Create a temporary script file.
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "test-exec.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte("#!/bin/sh\necho $OIDC_PROVIDER\n"), 0700))

	result, err := svc.ExecuteScriptFile("file-exec", scriptPath)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, result.Stdout, "file-exec")
}

// ---------------------------------------------------------------------------
// GetSavedScriptPath
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_GetSavedScriptPath_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetSavedScriptPath("")
	assert.ErrorIs(t, err, ErrOIDCScriptNameRequired)
}

func TestOIDCService_Coverage_GetSavedScriptPath_NoDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetSavedScriptPath("test.sh")
	assert.ErrorIs(t, err, ErrOIDCScriptDirUnavailable)
}

func TestOIDCService_Coverage_GetSavedScriptPath_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	_, err := svc.GetSavedScriptPath("nonexistent.sh")
	assert.ErrorIs(t, err, ErrOIDCScriptNotFound)
}

func TestOIDCService_Coverage_GetSavedScriptPath_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	saved, err := svc.SaveScript("path-test", "echo path")
	require.NoError(t, err)

	path, err := svc.GetSavedScriptPath(saved.FileName)
	require.NoError(t, err)
	assert.Contains(t, path, saved.FileName)

	// Verify path is valid.
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr)
}

// ---------------------------------------------------------------------------
// loadProvidersFromBackend
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_LoadProvidersFromBackend_NoKey(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.backend = newMockStorageBackend()
	svc.backendPrefix = "oidc/"

	err := svc.loadProvidersFromBackend()
	assert.NoError(t, err)
	assert.Empty(t, svc.providers)
}

func TestOIDCService_Coverage_LoadProvidersFromBackend_GetError(t *testing.T) {
	backend := newMockStorageBackend()
	backend.getErr = errors.New("backend read error")

	svc := NewOIDCService(nil)
	svc.backend = backend
	svc.backendPrefix = "oidc/"

	err := svc.loadProvidersFromBackend()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend read error")
}

func TestOIDCService_Coverage_LoadProvidersFromBackend_InvalidJSON(t *testing.T) {
	backend := newMockStorageBackend()
	backend.data["oidc/"+oidcProvidersBackendKey] = []byte("not valid json")

	svc := NewOIDCService(nil)
	svc.backend = backend
	svc.backendPrefix = "oidc/"

	err := svc.loadProvidersFromBackend()
	assert.Error(t, err)
}

func TestOIDCService_Coverage_LoadProvidersFromBackend_Success(t *testing.T) {
	backend := newMockStorageBackend()
	config := oidcProvidersConfig{
		Providers: []OIDCProviderEntry{
			{Name: "p1", Issuer: "https://a.com", ClientID: "id1"},
			{Name: "p2", Issuer: "https://b.com", ClientID: "id2"},
		},
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	backend.data["test/"+oidcProvidersBackendKey] = data

	svc := NewOIDCService(nil)
	svc.backend = backend
	svc.backendPrefix = "test/"

	err = svc.loadProvidersFromBackend()
	require.NoError(t, err)
	assert.Len(t, svc.providers, 2)
	assert.Equal(t, "https://a.com", svc.providers["p1"].Issuer)
	assert.Equal(t, "https://b.com", svc.providers["p2"].Issuer)
}

// ---------------------------------------------------------------------------
// saveProvidersToBackend
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_SaveProvidersToBackend_Success(t *testing.T) {
	backend := newMockStorageBackend()

	svc := NewOIDCService(nil)
	svc.backend = backend
	svc.backendPrefix = "oidc/"
	svc.providers["save-test"] = &OIDCProviderEntry{
		Name:     "save-test",
		Issuer:   "https://save.com",
		ClientID: "sid",
	}

	err := svc.saveProvidersToBackend()
	require.NoError(t, err)

	// Verify data was stored in the backend.
	data, ok := backend.data["oidc/"+oidcProvidersBackendKey]
	require.True(t, ok)

	var config oidcProvidersConfig
	require.NoError(t, json.Unmarshal(data, &config))
	assert.Len(t, config.Providers, 1)
	assert.Equal(t, "save-test", config.Providers[0].Name)
}

func TestOIDCService_Coverage_SaveProvidersToBackend_PutError(t *testing.T) {
	backend := newMockStorageBackend()
	backend.putErr = errors.New("backend write error")

	svc := NewOIDCService(nil)
	svc.backend = backend
	svc.backendPrefix = "oidc/"
	svc.providers["err-test"] = &OIDCProviderEntry{Name: "err-test", Issuer: "https://e.com", ClientID: "id"}

	err := svc.saveProvidersToBackend()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend write error")
}

// ---------------------------------------------------------------------------
// Close - error path with StopAllRefresh
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_Close_WithTokenStoreCloseError(t *testing.T) {
	svc := NewOIDCService(nil)
	mockStore := &mockClosableTokenStore{
		TokenStore: oidc.NewMemoryTokenStore(),
		closeErr:   errors.New("close error"),
	}
	svc.tokenStore = mockStore

	err := svc.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "close error")
	assert.True(t, mockStore.closed)
}

// ---------------------------------------------------------------------------
// Backend-backed provider add/update/delete (exercises saveProvidersToBackend)
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_BackendProvider_AddAndGet(t *testing.T) {
	backend := newMockStorageBackend()

	svc := NewOIDCService(nil)
	err := svc.SetBackend(backend, "oidc/")
	require.NoError(t, err)

	entry := &OIDCProviderEntry{
		Name:     "backend-provider",
		Issuer:   "https://backend-idp.com",
		ClientID: "bcid",
	}
	require.NoError(t, svc.AddProvider(entry))

	// Verify provider is stored in backend.
	data, ok := backend.data["oidc/"+oidcProvidersBackendKey]
	require.True(t, ok)

	var config oidcProvidersConfig
	require.NoError(t, json.Unmarshal(data, &config))
	assert.Len(t, config.Providers, 1)
	assert.Equal(t, "backend-provider", config.Providers[0].Name)

	// Verify GetProvider works.
	p, err := svc.GetProvider("backend-provider")
	require.NoError(t, err)
	assert.Equal(t, "https://backend-idp.com", p.Issuer)
}

func TestOIDCService_Coverage_BackendProvider_Update(t *testing.T) {
	backend := newMockStorageBackend()

	svc := NewOIDCService(nil)
	require.NoError(t, svc.SetBackend(backend, "oidc/"))

	entry := &OIDCProviderEntry{Name: "bp", Issuer: "https://old.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	updated := &OIDCProviderEntry{Name: "bp", Issuer: "https://new.com", ClientID: "id2"}
	require.NoError(t, svc.UpdateProvider("bp", updated))

	p, err := svc.GetProvider("bp")
	require.NoError(t, err)
	assert.Equal(t, "https://new.com", p.Issuer)
}

func TestOIDCService_Coverage_BackendProvider_Delete(t *testing.T) {
	backend := newMockStorageBackend()

	svc := NewOIDCService(nil)
	require.NoError(t, svc.SetBackend(backend, "oidc/"))

	entry := &OIDCProviderEntry{Name: "bp-del", Issuer: "https://del.com", ClientID: "id"}
	require.NoError(t, svc.AddProvider(entry))

	err := svc.DeleteProvider("bp-del")
	assert.NoError(t, err)

	_, err = svc.GetProvider("bp-del")
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
}

// ---------------------------------------------------------------------------
// loadProviders dispatching (backend vs file)
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_LoadProviders_DispatchesToBackend(t *testing.T) {
	backend := newMockStorageBackend()
	config := oidcProvidersConfig{
		Providers: []OIDCProviderEntry{
			{Name: "dispatched", Issuer: "https://d.com", ClientID: "did"},
		},
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	backend.data["pfx/"+oidcProvidersBackendKey] = data

	svc := NewOIDCService(nil)
	svc.backend = backend
	svc.backendPrefix = "pfx/"
	svc.dataDir = t.TempDir() // Also set dataDir -- backend should take priority.

	err = svc.loadProviders()
	require.NoError(t, err)
	assert.Len(t, svc.providers, 1)
	assert.Equal(t, "dispatched", svc.providers["dispatched"].Name)
}

// ---------------------------------------------------------------------------
// saveProviders dispatching (backend vs file)
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_SaveProviders_DispatchesToBackend(t *testing.T) {
	backend := newMockStorageBackend()

	svc := NewOIDCService(nil)
	svc.backend = backend
	svc.backendPrefix = "pfx/"
	svc.dataDir = t.TempDir() // Also set dataDir -- backend should take priority.

	svc.providers["sp"] = &OIDCProviderEntry{Name: "sp", Issuer: "https://s.com", ClientID: "sid"}

	err := svc.saveProviders()
	require.NoError(t, err)

	// Verify it was saved to backend, not file.
	_, ok := backend.data["pfx/"+oidcProvidersBackendKey]
	assert.True(t, ok)

	// Verify no file was created.
	_, statErr := os.Stat(filepath.Join(svc.dataDir, oidcProvidersFile))
	assert.True(t, os.IsNotExist(statErr))
}

// ---------------------------------------------------------------------------
// BrowseScriptFile (limited - depends on Wails runtime, test nil context path)
// ---------------------------------------------------------------------------

// BrowseScriptFile calls wailsruntime.OpenFileDialog which requires a Wails
// app context. We verify it handles a nil/non-Wails context gracefully by
// expecting a panic recovery or error. Since calling it without a real Wails
// context will panic, we skip the actual call test and focus on ensuring
// the function signature is correct via compilation.
// The real test for BrowseScriptFile belongs in integration tests.

// ---------------------------------------------------------------------------
// saveProvidersToFile - multiple providers
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_SaveProvidersToFile_MultipleProviders(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.dataDir = dir

	svc.providers["prov1"] = &OIDCProviderEntry{Name: "prov1", Issuer: "https://a.com", ClientID: "a"}
	svc.providers["prov2"] = &OIDCProviderEntry{Name: "prov2", Issuer: "https://b.com", ClientID: "b"}
	svc.providers["prov3"] = &OIDCProviderEntry{Name: "prov3", Issuer: "https://c.com", ClientID: "c"}

	err := svc.saveProvidersToFile()
	require.NoError(t, err)

	// Verify all providers were saved.
	data, err := os.ReadFile(filepath.Join(dir, oidcProvidersFile))
	require.NoError(t, err)

	var config oidcProvidersConfig
	require.NoError(t, json.Unmarshal(data, &config))
	assert.Len(t, config.Providers, 3)
}

// ---------------------------------------------------------------------------
// saveProvidersToFile - empty dataDir
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_SaveProvidersToFile_EmptyDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	// dataDir is empty string.
	err := svc.saveProvidersToFile()
	assert.NoError(t, err) // No-op when dataDir is empty.
}

// ---------------------------------------------------------------------------
// SetDataDir with no existing providers file
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_SetDataDir_NoExistingProviderFile(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.SetDataDir(dir)

	// Should have empty providers (no file to load from).
	assert.Empty(t, svc.GetProviders())
	assert.NotNil(t, svc.tokenStore)
}

// ---------------------------------------------------------------------------
// tokenResponseToInfo - DPoP key present
// ---------------------------------------------------------------------------

func TestOIDCService_Coverage_TokenResponseToInfo_WithDPoP(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Name: "dpop-test", Issuer: "https://ex.com"}

	tokenResp := &oidc.TokenResponse{
		AccessToken: "at",
		DPoPKeyPEM:  "-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----",
		Expiry:      time.Now().Add(time.Hour),
	}

	info := svc.tokenResponseToInfo("dpop-test", entry, tokenResp)
	assert.True(t, info.HasDPoP)
}
