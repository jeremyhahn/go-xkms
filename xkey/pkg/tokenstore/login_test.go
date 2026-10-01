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

package tokenstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen_PersistsAcrossReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	ctx := context.Background()

	store, err := Open(dir)
	require.NoError(t, err)
	require.NoError(t, store.Save(ctx, &TokenEntry{ServerURL: "https://xkms.example:8443", Token: "jwt"}))
	require.NoError(t, store.Close())

	reopened, err := Open(dir)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	entry, err := reopened.Load(ctx, "https://xkms.example:8443")
	require.NoError(t, err)
	assert.Equal(t, "jwt", entry.Token)
}

func TestOpen_EmptyDirRefused(t *testing.T) {
	_, err := Open("")
	assert.ErrorIs(t, err, ErrInvalidDir)
}

func TestOpen_UnusableDirFails(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err := Open(filepath.Join(file, "auth"))
	assert.Error(t, err)
}

// saveLogin stores a login the way `xkey auth login` does.
func saveLogin(t *testing.T, store TokenStore, url, id, name, token string, expires time.Time) {
	t.Helper()
	require.NoError(t, store.Save(context.Background(), &TokenEntry{
		ServerURL: url, ServerID: id, ServerName: name, Token: token,
		IssuedAt: time.Now(), ExpiresAt: expires,
	}))
}

func TestLoginToken_ByServerID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTokenStore()
	saveLogin(t, store, "https://xkms.example:8443", "id-a", "xkms.example", "a.jwt", time.Now().Add(time.Hour))
	saveLogin(t, store, "https://xkms.example:9443", "id-b", "xkms.example", "b.jwt", time.Now().Add(time.Hour))

	token, err := LoginToken(ctx, store, ServerRef{ID: "id-a"})
	require.NoError(t, err)
	assert.Equal(t, "a.jwt", token, "the login made through any URL serves its server's identity")

	token, err = LoginToken(ctx, store, ServerRef{ID: "id-unknown", Name: "xkms.example"})
	require.NoError(t, err)
	assert.Empty(t, token, "a server with another certificate on the same host gets no login")
}

func TestLoginToken_NewestLoginOfTheServerWins(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTokenStore()
	require.NoError(t, store.Save(ctx, &TokenEntry{ServerURL: "https://a:1", ServerID: "id", Token: "old", IssuedAt: time.Now().Add(-time.Hour)}))
	require.NoError(t, store.Save(ctx, &TokenEntry{ServerURL: "https://a:2", ServerID: "id", Token: "new", IssuedAt: time.Now()}))

	token, err := LoginToken(ctx, store, ServerRef{ID: "id"})
	require.NoError(t, err)
	assert.Equal(t, "new", token)
}

func TestLoginToken_ByServerName(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTokenStore()
	saveLogin(t, store, "https://Local.Example:8443", "id-a", "local.example", "a.jwt", time.Now().Add(time.Hour))

	token, err := LoginToken(ctx, store, ServerRef{Name: "LOCAL.example"})
	require.NoError(t, err)
	assert.Equal(t, "a.jwt", token)

	token, err = LoginToken(ctx, store, ServerRef{})
	require.NoError(t, err)
	assert.Empty(t, token, "no identity and no name selects nothing")
}

func TestLoginToken_AmbiguousServerNameRefused(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTokenStore()
	saveLogin(t, store, "https://h:1", "id-a", "h", "a", time.Now().Add(time.Hour))
	saveLogin(t, store, "https://h:2", "id-b", "h", "b", time.Now().Add(time.Hour))

	_, err := LoginToken(ctx, store, ServerRef{Name: "h"})
	var ambiguous *AmbiguousServerNameError
	require.True(t, errors.As(err, &ambiguous), "two servers under one name never guess: %v", err)
	assert.Equal(t, "h", ambiguous.Name)
	assert.Equal(t, 2, ambiguous.Servers)
}

func TestLoginToken_ExpiredLoginFails(t *testing.T) {
	store := NewMemoryTokenStore()
	saveLogin(t, store, "https://old.example", "id-old", "old.example", "old", time.Now().Add(-time.Minute))

	_, err := LoginToken(context.Background(), store, ServerRef{ID: "id-old"})
	var expired *LoginExpiredError
	require.True(t, errors.As(err, &expired), "an expired login fails loudly: %v", err)
	assert.Equal(t, "https://old.example", expired.ServerURL)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestLoginToken_StoreFailureSurfaces(t *testing.T) {
	store := NewMemoryTokenStore()
	require.NoError(t, store.Close())
	_, err := LoginToken(context.Background(), store, ServerRef{ID: "x"})
	assert.ErrorIs(t, err, ErrStoreClosed)
}
