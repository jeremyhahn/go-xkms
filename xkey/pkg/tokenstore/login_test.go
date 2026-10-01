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

func TestLoginToken(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTokenStore()
	require.NoError(t, store.Save(ctx, &TokenEntry{
		ServerURL: "https://live.example", Token: "live", ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, store.Save(ctx, &TokenEntry{
		ServerURL: "https://old.example", Token: "old", ExpiresAt: time.Now().Add(-time.Minute),
	}))

	token, err := LoginToken(ctx, store, "HTTPS://live.example/")
	require.NoError(t, err)
	assert.Equal(t, "live", token, "the lookup normalizes the URL as Save does")

	token, err = LoginToken(ctx, store, "https://never.example")
	require.NoError(t, err, "no login for the server is not an error")
	assert.Empty(t, token)

	_, err = LoginToken(ctx, store, "https://old.example")
	var expired *LoginExpiredError
	require.True(t, errors.As(err, &expired), "an expired login fails loudly: %v", err)
	assert.Equal(t, "https://old.example", expired.ServerURL)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestLoginToken_StoreFailureSurfaces(t *testing.T) {
	store := NewMemoryTokenStore()
	require.NoError(t, store.Close())
	_, err := LoginToken(context.Background(), store, "https://x.example")
	assert.ErrorIs(t, err, ErrStoreClosed)
}
