// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// go-qrdb's seal barrier is the ONE at-rest encryption xkey relies on for
// OIDC tokens; xkey no longer "encrypts" tokens.json with a key compiled
// into the binary, and no longer falls back to plaintext (go-xkms#1203).
// These tests pin the replacement behavior: without a barrier, OIDC tokens
// live in memory only for the life of the process -- nothing named
// "tokens.json" is ever created -- and the operator is warned exactly once;
// with a barrier, tokens persist and round-trip through the encrypted
// backend as before.

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOIDCService_SetDataDir_NoBarrier_NoTokenFileWritten proves that the
// no-barrier fallback path never creates a token file on disk, even after a
// token is saved and loaded within the running session.
func TestOIDCService_SetDataDir_NoBarrier_NoTokenFileWritten(t *testing.T) {
	dir := t.TempDir()

	svc := NewOIDCService(nil)
	svc.SetDataDir(dir)

	token := &oidc.TokenResponse{
		AccessToken:  "session-access-token",
		RefreshToken: "session-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, svc.tokenStore.Save("https://issuer.example.com", token))

	loaded, err := svc.tokenStore.Load("https://issuer.example.com")
	require.NoError(t, err, "the in-memory store must serve tokens within the same session")
	assert.Equal(t, "session-access-token", loaded.AccessToken)
	assert.Equal(t, "session-refresh-token", loaded.RefreshToken)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.NotContains(t, entry.Name(), "tokens",
			"no barrier means no token file of any name may land on disk, found %q", entry.Name())
	}
	_, statErr := os.Stat(filepath.Join(dir, "tokens.json"))
	assert.True(t, os.IsNotExist(statErr), "tokens.json must not exist without a barrier")
}

// TestOIDCService_SetDataDir_NoBarrier_WarnsOnce proves the no-barrier
// fallback logs exactly one warning naming the exposure (tokens do not
// survive a restart) rather than silently degrading.
func TestOIDCService_SetDataDir_NoBarrier_WarnsOnce(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	svc := NewOIDCService(slog.New(slog.NewTextHandler(&buf, nil)))
	svc.SetDataDir(dir)

	got := buf.String()
	assert.Contains(t, got, "OIDC tokens are kept in memory only",
		"the no-barrier fallback must warn that tokens are session-only")
	assert.Contains(t, got, "will not survive a restart",
		"the warning must state the consequence, not just the mechanism")

	// Exactly one such warning: SetDataDir does not log it per Save/Load.
	assert.Equal(t, 1, bytes.Count([]byte(got), []byte("OIDC tokens are kept in memory only")))
}

// TestOIDCService_SetDataDir_NoBarrier_UsesMemoryTokenStore proves the token
// store SetDataDir installs is the package's MemoryTokenStore, not a
// FileTokenStore of any kind (encrypted or otherwise).
func TestOIDCService_SetDataDir_NoBarrier_UsesMemoryTokenStore(t *testing.T) {
	dir := t.TempDir()

	svc := NewOIDCService(nil)
	svc.SetDataDir(dir)

	_, ok := svc.tokenStore.(*oidc.MemoryTokenStore)
	assert.True(t, ok, "no-barrier fallback must use oidc.MemoryTokenStore, got %T", svc.tokenStore)
}

// TestOIDCService_SetBackend_TokenRoundTrip proves the barrier-backed path
// still persists and round-trips OIDC tokens through the storage backend
// (unchanged behavior when a barrier is available), now via go-qrdb's
// DAO/entity pattern (oidc.DAOStore) rather than a raw Put/Get pair keyed by
// SetBackend's prefix argument. The DAO owns its own key layout -- a
// "oidc_tokens/<entity id>" namespace, go-qrdb's GenericDAO convention, not
// SetBackend's prefix -- so this test checks that namespace instead of the
// old "oidc/tokens/" prefix literal.
func TestOIDCService_SetBackend_TokenRoundTrip(t *testing.T) {
	backend := newMockStorageBackend()

	svc := NewOIDCService(nil)
	require.NoError(t, svc.SetBackend(backend, "oidc/"))

	token := &oidc.TokenResponse{
		AccessToken:  "barrier-access-token",
		RefreshToken: "barrier-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, svc.tokenStore.Save("https://issuer.example.com", token))

	loaded, err := svc.tokenStore.Load("https://issuer.example.com")
	require.NoError(t, err)
	assert.Equal(t, "barrier-access-token", loaded.AccessToken)
	assert.Equal(t, "barrier-refresh-token", loaded.RefreshToken)

	// The backend actually received something under the DAO's entity
	// namespace.
	assert.NotEmpty(t, backend.data)
	const entityNamespace = "oidc_tokens/"
	found := false
	for key := range backend.data {
		if len(key) > len(entityNamespace) && key[:len(entityNamespace)] == entityNamespace {
			found = true
		}
	}
	assert.True(t, found, "expected a key under the %q namespace, got %v", entityNamespace, backend.data)
}
