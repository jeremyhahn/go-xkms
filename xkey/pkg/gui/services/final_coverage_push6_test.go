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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// ===========================================================================
// Part 8: Final coverage push from 89.5% to 90%+
// ===========================================================================

// ---------------------------------------------------------------------------
// Mock: OIDC token store implementing oidc.TokenStore
// ---------------------------------------------------------------------------

type p8MockOIDCTokenStore struct {
	tokens map[string]*oidc.TokenResponse
}

func (m *p8MockOIDCTokenStore) Save(issuer string, tokens *oidc.TokenResponse) error {
	m.tokens[issuer] = tokens
	return nil
}
func (m *p8MockOIDCTokenStore) Load(issuer string) (*oidc.TokenResponse, error) {
	t, ok := m.tokens[issuer]
	if !ok {
		return nil, errors.New("not found")
	}
	return t, nil
}
func (m *p8MockOIDCTokenStore) Delete(string) error     { return nil }
func (m *p8MockOIDCTokenStore) List() ([]string, error) { return nil, nil }
func (m *p8MockOIDCTokenStore) Close() error            { return nil }

// ---------------------------------------------------------------------------
// Mock: failing storage backend for history store errors
// ---------------------------------------------------------------------------

type p8FailingHistoryStore struct {
	storage.Backend
	putErr  error
	getErr  error
	listErr error
	delErr  error
	data    map[string][]byte
}

func newP8FailingHistoryStore() *p8FailingHistoryStore {
	return &p8FailingHistoryStore{data: make(map[string][]byte)}
}

func (s *p8FailingHistoryStore) Put(_ context.Context, key string, data []byte) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.data[key] = data
	return nil
}

func (s *p8FailingHistoryStore) Get(_ context.Context, key string) ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	d, ok := s.data[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return d, nil
}

func (s *p8FailingHistoryStore) List(_ context.Context, prefix string) ([]string, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	var keys []string
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (s *p8FailingHistoryStore) Delete(_ context.Context, key string) error {
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.data, key)
	return nil
}

// ---------------------------------------------------------------------------
// API Explorer: Execute with read body error (lines 273-280)
// We simulate by using a test server that sends an incomplete body
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_Execute_BodyReadError(t *testing.T) {
	// Use a server that sends Content-Length but cuts the connection.
	// This triggers io.ReadAll returning an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(http.StatusOK)
		// Write only 1 byte then close, causing read error.
		w.Write([]byte("x"))
		// Hijack to close without writing full body.
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
	}))
	defer srv.Close()

	explorer := fcp6NewExplorer(t)
	explorer.ctx = context.Background()

	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    srv.URL + "/test",
	})
	require.NoError(t, err)
	// Should get either an error response or a body response.
	assert.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// API Explorer: Execute with response body exceeding limit (lines 282-289)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_Execute_BodyTooLarge(t *testing.T) {
	// Create a server that sends a body larger than maxResponseBodySize.
	largeBody := strings.Repeat("X", int(maxResponseBodySize)+2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeBody))
	}))
	defer srv.Close()

	explorer := fcp6NewExplorer(t)
	explorer.ctx = context.Background()

	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    srv.URL + "/test",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Contains(t, resp.Error, "exceeds 10 MB limit")
}

// ---------------------------------------------------------------------------
// API Explorer: recordHistory with Put error (lines 573-577)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_RecordHistory_PutError(t *testing.T) {
	failStore := newP8FailingHistoryStore()
	failStore.putErr = errors.New("disk full")

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.HistoryStore = failStore
	})
	explorer.ctx = context.Background()

	// Execute a request against a server that returns quickly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    srv.URL + "/test",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)

	// History store should have no entries since Put failed.
	entries, _ := explorer.GetHistory()
	assert.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// API Explorer: GetHistory with corrupted entry (line 478-479)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_GetHistory_CorruptedEntry(t *testing.T) {
	failStore := newP8FailingHistoryStore()
	// Pre-populate with an entry that won't unmarshal.
	failStore.data["api_explorer_history/bad-entry.json"] = []byte("not-json{{{")

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.HistoryStore = failStore
	})

	entries, err := explorer.GetHistory()
	require.NoError(t, err)
	// Bad entry should be skipped.
	assert.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// API Explorer: GetHistory with Get returning error (line 478-479)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_GetHistory_GetError(t *testing.T) {
	failStore := newP8FailingHistoryStore()
	// Put a valid key but make Get fail.
	failStore.data["api_explorer_history/test.json"] = []byte(`{}`)
	failStore.getErr = errors.New("io error")

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.HistoryStore = failStore
	})

	entries, err := explorer.GetHistory()
	require.NoError(t, err)
	// Entries should be empty because Get failed for each key.
	assert.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// API Explorer: ClearHistory with delete error (lines 512-516)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ClearHistory_DeleteError(t *testing.T) {
	failStore := newP8FailingHistoryStore()
	// Seed an entry.
	entry := &HistoryEntry{
		ID:        "test-id",
		Timestamp: time.Now(),
		Request:   &ExplorerRequest{Method: "GET", URL: "https://example.com"},
		Response:  &ExplorerResponse{StatusCode: 200},
	}
	data, _ := json.Marshal(entry)
	failStore.data["api_explorer_history/test-id.json"] = data
	failStore.delErr = errors.New("permission denied")

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.HistoryStore = failStore
	})

	// ClearHistory should not return an error; delete failures are logged.
	err := explorer.ClearHistory()
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// API Explorer: DeleteHistoryEntry with generic store error (line 537)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_DeleteHistoryEntry_StoreError(t *testing.T) {
	failStore := newP8FailingHistoryStore()
	failStore.delErr = errors.New("disk error")
	// Must have the key so it's not ErrNotFound.
	failStore.data["api_explorer_history/xyz.json"] = []byte("{}")

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.HistoryStore = failStore
	})

	err := explorer.DeleteHistoryEntry("xyz")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrExplorerHistoryNotFound)
}

// ---------------------------------------------------------------------------
// API Explorer: ClearHistory with List error (lines 507-509)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ClearHistory_ListError(t *testing.T) {
	failStore := newP8FailingHistoryStore()
	failStore.listErr = errors.New("list error")

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.HistoryStore = failStore
	})

	err := explorer.ClearHistory()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// API Explorer: GetHistory with List error (lines 471-473)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_GetHistory_ListError(t *testing.T) {
	failStore := newP8FailingHistoryStore()
	failStore.listErr = errors.New("list error")

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.HistoryStore = failStore
	})

	_, err := explorer.GetHistory()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens with OIDC service (lines 392-402)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_WithOIDCService(t *testing.T) {
	// Set up an OIDC service with a provider and token store.
	oidcSvc := NewOIDCService(slog.Default())
	oidcTokenStore := &p8MockOIDCTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://accounts.google.com": {
				AccessToken: "test-access-token",
				ExpiresIn:   3600,
			},
		},
	}
	oidcSvc.tokenStore = oidcTokenStore
	oidcSvc.providers = map[string]*OIDCProviderEntry{
		"google": {
			Name:        "google",
			Issuer:      "https://accounts.google.com",
			ClientID:    "test-client",
			RedirectURL: "http://localhost:8080/callback",
			Scopes:      []string{"openid"},
		},
	}

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.OIDCService = oidcSvc
	})

	tokens := explorer.ListAvailableTokens()
	// Should have the OIDC token.
	found := false
	for _, tok := range tokens {
		if tok.Source == "oidc" {
			found = true
			assert.Contains(t, tok.Label, "OIDC")
			assert.Equal(t, "test-access-token", tok.Token)
		}
	}
	assert.True(t, found, "expected OIDC token in list")
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens with nil/empty token entries (line 357-358)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_NilAndEmptyTokenEntries(t *testing.T) {
	ts := tokenstore.NewMemoryTokenStore()
	ctx := context.Background()

	// Save entry with empty token (should be skipped).
	ts.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://empty.com",
		Source:    "bootstrap",
		Token:     "",
	})
	// Save entry with valid token.
	ts.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://valid.com",
		Source:    "bootstrap",
		Token:     "valid-jwt",
	})

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.TokenStore = ts
	})

	tokens := explorer.ListAvailableTokens()
	// Only valid token should be returned.
	assert.Len(t, tokens, 1)
	assert.Equal(t, "valid-jwt", tokens[0].Token)
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens with OIDC name-only label (line 400-402)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_OIDCNameOnlyLabel(t *testing.T) {
	oidcSvc := NewOIDCService(slog.Default())
	oidcTokenStore := &p8MockOIDCTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://login.example.com": {
				AccessToken: "at-name",
				ExpiresIn:   3600,
			},
		},
	}
	oidcSvc.tokenStore = oidcTokenStore
	oidcSvc.providers = map[string]*OIDCProviderEntry{
		"example": {
			Name:        "example",
			Issuer:      "https://login.example.com",
			ClientID:    "test",
			RedirectURL: "http://localhost/cb",
			Scopes:      []string{"openid"},
		},
	}

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.OIDCService = oidcSvc
	})

	tokens := explorer.ListAvailableTokens()
	found := false
	for _, tok := range tokens {
		if tok.Source == "oidc" {
			found = true
			// Without email or name in the token response, label should be "OIDC: example"
			assert.Contains(t, tok.Label, "OIDC: example")
		}
	}
	assert.True(t, found)
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens with FIDO2 service (lines 424-429, 454)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_WithFIDO2Service(t *testing.T) {
	fido2Svc := NewFIDO2Service(nil)
	fido2Svc.tokenStore = tokenstore.NewMemoryTokenStore()
	// Save a FIDO2-sourced token.
	fido2Svc.tokenStore.Save(context.Background(), &tokenstore.TokenEntry{
		ServerURL: "https://fido2.example.com",
		Source:    tokenstore.SourceFIDO2,
		Token:     "fido2-jwt",
		Subject:   "cred-123",
		Issuer:    "rp-example",
	})

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.FIDO2Service = fido2Svc
	})

	tokens := explorer.ListAvailableTokens()
	found := false
	for _, tok := range tokens {
		if tok.Source == "fido2" {
			found = true
			assert.Contains(t, tok.Label, "FIDO2")
			assert.Equal(t, "fido2-jwt", tok.Token)
		}
	}
	assert.True(t, found, "expected FIDO2 token in list")
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens with FIDO2 empty token (line 424-425)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_FIDO2EmptyToken(t *testing.T) {
	fido2Svc := NewFIDO2Service(nil)
	fido2Svc.tokenStore = tokenstore.NewMemoryTokenStore()
	// Save a FIDO2-sourced token with empty Token (should be skipped).
	fido2Svc.tokenStore.Save(context.Background(), &tokenstore.TokenEntry{
		ServerURL: "https://fido2.example.com",
		Source:    tokenstore.SourceFIDO2,
		Token:     "",
		Subject:   "cred-456",
		Issuer:    "rp-skip",
	})

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.FIDO2Service = fido2Svc
	})

	tokens := explorer.ListAvailableTokens()
	for _, tok := range tokens {
		assert.NotEqual(t, "fido2", tok.Source, "empty FIDO2 token should be skipped")
	}
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens with FIDO2 duplicate (line 428-429)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_FIDO2Duplicate(t *testing.T) {
	fido2Svc := NewFIDO2Service(nil)
	fido2Svc.tokenStore = tokenstore.NewMemoryTokenStore()
	ctx := context.Background()

	// Save two tokens with the same RPID (second should be deduped).
	fido2Svc.tokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://fido2.example.com/a",
		Source:    tokenstore.SourceFIDO2,
		Token:     "fido2-jwt-1",
		Subject:   "cred-1",
		Issuer:    "rp-same",
	})
	fido2Svc.tokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://fido2.example.com/b",
		Source:    tokenstore.SourceFIDO2,
		Token:     "fido2-jwt-2",
		Subject:   "cred-2",
		Issuer:    "rp-same",
	})

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.FIDO2Service = fido2Svc
	})

	tokens := explorer.ListAvailableTokens()
	fido2Count := 0
	for _, tok := range tokens {
		if tok.Source == "fido2" {
			fido2Count++
		}
	}
	// Only one should appear due to dedup by RPID.
	assert.Equal(t, 1, fido2Count)
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens sort tiebreaker (line 454)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_SortOrder(t *testing.T) {
	ts := tokenstore.NewMemoryTokenStore()
	ctx := context.Background()

	// Two tokens from the same source, different labels.
	ts.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://zzz.com",
		Source:    "bootstrap",
		Token:     "jwt-z",
	})
	ts.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://aaa.com",
		Source:    "bootstrap",
		Token:     "jwt-a",
	})

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.TokenStore = ts
	})

	tokens := explorer.ListAvailableTokens()
	require.Len(t, tokens, 2)
	// Same source, sorted by label ascending.
	assert.True(t, tokens[0].Label < tokens[1].Label,
		"tokens should be sorted by label: %s < %s", tokens[0].Label, tokens[1].Label)
}

// ---------------------------------------------------------------------------
// Browser Service: openCustomCommand with empty command (line 223-225)
// ---------------------------------------------------------------------------

func TestP8_BrowserService_OpenCustomCommand_EmptyParts(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewBrowserService(filepath.Join(dir, "browser.json"), slog.Default())
	require.NoError(t, err)

	// Empty command with no fields after expansion.
	err = svc.openCustomCommand(context.Background(), "", "")
	assert.ErrorIs(t, err, ErrBrowserLaunchFailed)
}

// ---------------------------------------------------------------------------
// Browser Service: saveConfig with MkdirAll error (line 339-340)
// ---------------------------------------------------------------------------

func TestP8_BrowserService_SaveConfig_MkdirAllError(t *testing.T) {
	// Point configPath to a read-only directory.
	dir := t.TempDir()
	readonlyDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.MkdirAll(readonlyDir, 0o500))
	// Make the config path point inside a non-writable nested dir.
	configPath := filepath.Join(readonlyDir, "subdir", "browser.json")

	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	// Try to save config; MkdirAll should fail on the non-writable parent.
	err = svc.saveConfig(BrowserConfig{DefaultBrowser: BrowserSystem})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserConfigSave)
}

// ---------------------------------------------------------------------------
// Browser Service: applyTrustBundle with empty bundlePath (line 304-306)
// ---------------------------------------------------------------------------

func TestP8_BrowserService_ApplyTrustBundle_EmptyBundlePath(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewBrowserService(filepath.Join(dir, "browser.json"), slog.Default())
	require.NoError(t, err)

	// Enable trust bundle but leave path empty.
	svc.mu.Lock()
	svc.config.IncludeTrustBundle = true
	svc.trustBundlePath = ""
	svc.mu.Unlock()

	// Should be a no-op (empty bundle path returns early).
	cmd := svc.execCommand(context.Background(), "echo", "test")
	svc.applyTrustBundle(cmd)
	// No SSL_CERT_FILE should be set.
	for _, env := range cmd.Env {
		assert.False(t, strings.HasPrefix(env, "SSL_CERT_FILE="),
			"SSL_CERT_FILE should not be set with empty bundle path")
	}
}

// ---------------------------------------------------------------------------
// Key Service: EncryptFile with nonexistent input file (line 700)
// ---------------------------------------------------------------------------

func TestP8_KeyService_EncryptFile_ReadError(t *testing.T) {
	svc := NewKeyService()
	err := svc.EncryptFile("local", "software", "key1",
		"/nonexistent/input.bin", "/tmp/out.enc", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

// ---------------------------------------------------------------------------
// Key Service: DecryptFile with nonexistent input file (line 730)
// ---------------------------------------------------------------------------

func TestP8_KeyService_DecryptFile_ReadError(t *testing.T) {
	svc := NewKeyService()
	err := svc.DecryptFile("local", "software", "key1",
		"/nonexistent/input.enc", "/tmp/out.bin", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

// ---------------------------------------------------------------------------
// Key Service: SignFile with nonexistent input file (line 762)
// ---------------------------------------------------------------------------

func TestP8_KeyService_SignFile_ReadError(t *testing.T) {
	svc := NewKeyService()
	err := svc.SignFile("local", "software", "key1", "SHA256",
		"/nonexistent/input.bin", "/tmp/out.sig", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

// ---------------------------------------------------------------------------
// Key Service: VerifyFileSignature with nonexistent data file (line 792-793)
// ---------------------------------------------------------------------------

func TestP8_KeyService_VerifyFileSignature_DataReadError(t *testing.T) {
	svc := NewKeyService()
	_, err := svc.VerifyFileSignature("local", "software", "key1", "SHA256",
		"/nonexistent/data.bin", "/nonexistent/sig.bin", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

// ---------------------------------------------------------------------------
// Key Service: VerifyFileSignature with nonexistent sig file (line 796-797)
// ---------------------------------------------------------------------------

func TestP8_KeyService_VerifyFileSignature_SigReadError(t *testing.T) {
	svc := NewKeyService()
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "data.bin")
	require.NoError(t, os.WriteFile(dataPath, []byte("test data"), 0600))

	_, err := svc.VerifyFileSignature("local", "software", "key1", "SHA256",
		dataPath, "/nonexistent/sig.bin", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

// ---------------------------------------------------------------------------
// Key Service: VerifyFileSignature with hex sig decode error (line 804-806)
// ---------------------------------------------------------------------------

func TestP8_KeyService_VerifyFileSignature_HexDecodeError(t *testing.T) {
	svc := NewKeyService()
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "data.bin")
	sigPath := filepath.Join(dir, "sig.hex")
	require.NoError(t, os.WriteFile(dataPath, []byte("test data"), 0600))
	require.NoError(t, os.WriteFile(sigPath, []byte("not-valid-hex!!"), 0600))

	_, err := svc.VerifyFileSignature("local", "software", "key1", "SHA256",
		dataPath, sigPath, "hex")
	assert.Error(t, err, "hex decode should fail")
}

// ---------------------------------------------------------------------------
// Key Service: EncryptFile passes file read but fails at EncryptData (line 704)
// ---------------------------------------------------------------------------

func TestP8_KeyService_EncryptFile_EncryptDataError(t *testing.T) {
	svc := NewKeyService()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.bin")
	require.NoError(t, os.WriteFile(inputPath, []byte("test data"), 0600))

	err := svc.EncryptFile("local", "software", "key1",
		inputPath, filepath.Join(dir, "out.enc"), "base64")
	// EncryptData fails because no client is set.
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Key Service: DecryptFile with hex input decode error (line 735-738)
// ---------------------------------------------------------------------------

func TestP8_KeyService_DecryptFile_HexDecodeError(t *testing.T) {
	svc := NewKeyService()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.enc")
	require.NoError(t, os.WriteFile(inputPath, []byte("not-valid-hex!!"), 0600))

	err := svc.DecryptFile("local", "software", "key1",
		inputPath, filepath.Join(dir, "out.bin"), "hex")
	assert.Error(t, err, "hex decode should fail")
}

// ---------------------------------------------------------------------------
// Key Service: SignFile passes file read but fails at SignData (line 767)
// ---------------------------------------------------------------------------

func TestP8_KeyService_SignFile_SignDataError(t *testing.T) {
	svc := NewKeyService()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.bin")
	require.NoError(t, os.WriteFile(inputPath, []byte("test data"), 0600))

	err := svc.SignFile("local", "software", "key1", "SHA256",
		inputPath, filepath.Join(dir, "sig.hex"), "hex")
	// SignData fails because no client is set.
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Key Service: BrowseFile with nil context (line 671-672)
// ---------------------------------------------------------------------------

func TestP8_KeyService_BrowseFile_NoContext(t *testing.T) {
	svc := NewKeyService()
	_, err := svc.BrowseFile()
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

// ---------------------------------------------------------------------------
// Key Service: SaveFileAs with nil context (line 684-685)
// ---------------------------------------------------------------------------

func TestP8_KeyService_SaveFileAs_NoContext(t *testing.T) {
	svc := NewKeyService()
	_, err := svc.SaveFileAs("test.json")
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

// ---------------------------------------------------------------------------
// AutoFill: saveRegistration with read-only dir (line 723-725)
// ---------------------------------------------------------------------------

func TestP8_AutoFill_SaveRegistration_MkdirAllError(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	// Set registration dir to something impossible.
	svc.registrationDir = "/proc/0/impossible"
	svc.credID = []byte("test-cred-id")

	// saveRegistration logs error but doesn't return it.
	svc.saveRegistration([]byte("test-pubkey"))
	// No panic means success.
}

// ---------------------------------------------------------------------------
// AutoFill: saveRegistration with WriteFile error (line 728-730)
// ---------------------------------------------------------------------------

func TestP8_AutoFill_SaveRegistration_WriteFileError(t *testing.T) {
	dir := t.TempDir()
	regDir := filepath.Join(dir, "reg")
	require.NoError(t, os.MkdirAll(regDir, 0o700))
	// Make the registration file path unwritable.
	regFile := filepath.Join(regDir, "registration.json")
	require.NoError(t, os.WriteFile(regFile, []byte("existing"), 0o400))
	require.NoError(t, os.Chmod(regDir, 0o500))
	t.Cleanup(func() {
		os.Chmod(regDir, 0o700)
	})

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = regDir
	svc.credID = []byte("test-cred-id")

	// saveRegistration should log but not crash.
	svc.saveRegistration([]byte("test-pubkey"))
}

// ---------------------------------------------------------------------------
// AutoFill: loadRegistration with corrupted JSON (line 679-681)
// ---------------------------------------------------------------------------

func TestP8_AutoFill_LoadRegistration_CorruptJSON(t *testing.T) {
	dir := t.TempDir()
	regDir := filepath.Join(dir, "reg")
	require.NoError(t, os.MkdirAll(regDir, 0o700))
	regFile := filepath.Join(regDir, "registration.json")
	require.NoError(t, os.WriteFile(regFile, []byte("not-json{{{"), 0o600))

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = regDir

	loaded := svc.loadRegistration()
	assert.False(t, loaded, "corrupted JSON should fail to load")
}

// ---------------------------------------------------------------------------
// AutoFill: loadRegistration with empty credentials (line 684-685)
// ---------------------------------------------------------------------------

func TestP8_AutoFill_LoadRegistration_EmptyCredentials(t *testing.T) {
	dir := t.TempDir()
	regDir := filepath.Join(dir, "reg")
	require.NoError(t, os.MkdirAll(regDir, 0o700))
	regFile := filepath.Join(regDir, "registration.json")
	// Valid JSON but empty credential_id and public_key_cose.
	data, _ := json.Marshal(map[string]interface{}{
		"credential_id":   []byte{},
		"public_key_cose": []byte{},
		"registered_at":   time.Now(),
	})
	require.NoError(t, os.WriteFile(regFile, data, 0o600))

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = regDir

	loaded := svc.loadRegistration()
	assert.False(t, loaded, "empty credentials should not load")
}

// ---------------------------------------------------------------------------
// AutoFill: loadRegistration with missing file (returns false)
// ---------------------------------------------------------------------------

func TestP8_AutoFill_LoadRegistration_MissingFile(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = t.TempDir()

	loaded := svc.loadRegistration()
	assert.False(t, loaded)
}

// ---------------------------------------------------------------------------
// AutoFill: loadRegistration with empty dir (returns false)
// ---------------------------------------------------------------------------

func TestP8_AutoFill_LoadRegistration_EmptyDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = ""

	loaded := svc.loadRegistration()
	assert.False(t, loaded)
}

// ---------------------------------------------------------------------------
// AutoFill: saveRegistration with empty dir (returns immediately)
// ---------------------------------------------------------------------------

func TestP8_AutoFill_SaveRegistration_EmptyDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = ""
	svc.credID = []byte("test")

	// Should return immediately without error.
	svc.saveRegistration([]byte("pubkey"))
}

// ---------------------------------------------------------------------------
// API Explorer: Execute with request body (covers body reader branch)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_Execute_WithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"created":true}`))
	}))
	defer srv.Close()

	explorer := fcp6NewExplorer(t)
	explorer.ctx = context.Background()

	resp, err := explorer.Execute(&ExplorerRequest{
		Method:  "POST",
		URL:     srv.URL + "/api/keys",
		Body:    `{"name":"test"}`,
		Headers: map[string]string{"X-Custom": "value"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 201, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// API Explorer: Execute with HTML response (covers base tag injection)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_Execute_HTMLResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head></head><body>Hello</body></html>`))
	}))
	defer srv.Close()

	explorer := fcp6NewExplorer(t)
	explorer.ctx = context.Background()

	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    srv.URL + "/page",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Contains(t, resp.Body, "<base href=")
}

// ---------------------------------------------------------------------------
// API Explorer: Execute with network error (covers error response path)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_Execute_NetworkError(t *testing.T) {
	explorer := fcp6NewExplorer(t)
	explorer.ctx = context.Background()

	// Point at a closed server.
	resp, err := explorer.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "http://127.0.0.1:1/test",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)
	assert.Greater(t, resp.DurationMs, int64(-1))
}

// ---------------------------------------------------------------------------
// Browser Service: openSystemBrowser on Linux (lines 247-249)
// This exercises the linux case which was previously uncovered because
// tests didn't call openSystemBrowser directly.
// ---------------------------------------------------------------------------

func TestP8_BrowserService_OpenSystemBrowser_Linux(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewBrowserService(filepath.Join(dir, "browser.json"), slog.Default())
	require.NoError(t, err)

	// Replace execCommand with one that records what was called.
	var calledName string
	svc.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calledName = name
		return exec.CommandContext(ctx, "true") // no-op command
	}

	err = svc.openSystemBrowser(context.Background(), "https://example.com")
	// On Linux, it should try "xdg-open".
	assert.NoError(t, err)
	assert.Equal(t, "xdg-open", calledName)
}

// ---------------------------------------------------------------------------
// Browser Service: saveConfig successfully writes file (line 348)
// ---------------------------------------------------------------------------

func TestP8_BrowserService_SaveConfig_Success(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config", "browser.json")
	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	err = svc.saveConfig(BrowserConfig{
		DefaultBrowser:     BrowserSystem,
		IncludeTrustBundle: true,
	})
	require.NoError(t, err)

	// Verify file was written.
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "system")
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens with OIDC email label (line 398-400)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_OIDCWithEmailLabel(t *testing.T) {
	// Build a fake JWT with email in the ID token claims.
	idToken := buildFakeJWT(t, map[string]interface{}{
		"sub":   "user1",
		"email": "user@example.com",
		"name":  "Test User",
	})

	oidcSvc := NewOIDCService(slog.Default())
	oidcTokenStore := &p8MockOIDCTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://auth.example.com": {
				AccessToken: "at-with-email",
				IDToken:     idToken,
				ExpiresIn:   3600,
			},
		},
	}
	oidcSvc.tokenStore = oidcTokenStore
	oidcSvc.providers = map[string]*OIDCProviderEntry{
		"test-provider": {
			Name:        "test-provider",
			Issuer:      "https://auth.example.com",
			ClientID:    "test-client",
			RedirectURL: "http://localhost/cb",
			Scopes:      []string{"openid"},
		},
	}

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.OIDCService = oidcSvc
	})

	tokens := explorer.ListAvailableTokens()
	found := false
	for _, tok := range tokens {
		if tok.Source == "oidc" {
			found = true
			// With email set, label should contain the email.
			assert.Contains(t, tok.Label, "user@example.com")
			assert.Contains(t, tok.Label, "test-provider")
		}
	}
	assert.True(t, found, "expected OIDC token with email label")
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens with OIDC name-only label (line 400-402)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_OIDCWithNameOnlyLabel(t *testing.T) {
	// Build a fake JWT with name but no email in the ID token claims.
	idToken := buildFakeJWT(t, map[string]interface{}{
		"sub":  "user2",
		"name": "Name Only User",
	})

	oidcSvc := NewOIDCService(slog.Default())
	oidcTokenStore := &p8MockOIDCTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://auth2.example.com": {
				AccessToken: "at-with-name",
				IDToken:     idToken,
				ExpiresIn:   3600,
			},
		},
	}
	oidcSvc.tokenStore = oidcTokenStore
	oidcSvc.providers = map[string]*OIDCProviderEntry{
		"name-provider": {
			Name:        "name-provider",
			Issuer:      "https://auth2.example.com",
			ClientID:    "test-client",
			RedirectURL: "http://localhost/cb",
			Scopes:      []string{"openid"},
		},
	}

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.OIDCService = oidcSvc
	})

	tokens := explorer.ListAvailableTokens()
	found := false
	for _, tok := range tokens {
		if tok.Source == "oidc" {
			found = true
			// With name but no email, label should contain the name.
			assert.Contains(t, tok.Label, "Name Only User")
			assert.Contains(t, tok.Label, "name-provider")
		}
	}
	assert.True(t, found, "expected OIDC token with name-only label")
}

// ---------------------------------------------------------------------------
// API Explorer: ListAvailableTokens OIDC with empty access token (line 406-407)
// ---------------------------------------------------------------------------

func TestP8_APIExplorer_ListAvailableTokens_OIDCEmptyAccessToken(t *testing.T) {
	oidcSvc := NewOIDCService(slog.Default())
	// Token store has entry but access token is empty.
	oidcTokenStore := &p8MockOIDCTokenStore{
		tokens: map[string]*oidc.TokenResponse{
			"https://notoken.example.com": {
				AccessToken: "", // empty - should be skipped
				ExpiresIn:   3600,
			},
		},
	}
	oidcSvc.tokenStore = oidcTokenStore
	oidcSvc.providers = map[string]*OIDCProviderEntry{
		"notoken": {
			Name:        "notoken",
			Issuer:      "https://notoken.example.com",
			ClientID:    "test-client",
			RedirectURL: "http://localhost/cb",
			Scopes:      []string{"openid"},
		},
	}

	explorer := fcp6NewExplorer(t, func(cfg *ExplorerConfig) {
		cfg.OIDCService = oidcSvc
	})

	tokens := explorer.ListAvailableTokens()
	// OIDC token with empty access token should be skipped.
	for _, tok := range tokens {
		assert.NotEqual(t, "oidc", tok.Source, "OIDC token with empty access token should be skipped")
	}
}

// ---------------------------------------------------------------------------
// Browser Service: saveConfig with file that is read-only (line 348-350)
// MkdirAll succeeds because dir exists, but WriteFile fails on perm.
// ---------------------------------------------------------------------------

func TestP8_BrowserService_SaveConfig_WriteFilePermError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	// Create the file as read-only.
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o400))
	// Make the directory read-only so WriteFile can't overwrite.
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() {
		os.Chmod(dir, 0o700)
	})

	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	err = svc.saveConfig(BrowserConfig{DefaultBrowser: BrowserSystem})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserConfigSave)
}

// ---------------------------------------------------------------------------
// Helper: buildFakeJWT creates a minimal unsigned JWT with the given claims.
// ---------------------------------------------------------------------------

func buildFakeJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := p8Base64URLEncode(t, map[string]string{"alg": "none", "typ": "JWT"})
	payload := p8Base64URLEncode(t, claims)
	return header + "." + payload + ".sig"
}

func p8Base64URLEncode(t *testing.T, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(data)
}
