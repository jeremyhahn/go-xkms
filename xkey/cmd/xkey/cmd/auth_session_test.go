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

package cmd

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func authServerCmd(serverURL string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", serverURL, "")
	return cmd
}

// --- runAuthRefresh ---

func TestRunAuthRefresh_MissingServer(t *testing.T) {
	err := runAuthRefresh(authServerCmd(""), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthRefresh_TokenNotFound(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := runAuthRefresh(authServerCmd("https://nonexistent.example.com:8443"), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthTokenLoadFailed)
}

func TestRunAuthRefresh_NoRefreshToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const serverURL = "https://webauthn.example.com:8443"

	require.NoError(t, storeAuthToken(context.Background(), slog.Default(), loginServer{URL: serverURL}, makeTestJWT(t)))

	err := runAuthRefresh(authServerCmd(serverURL), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthRefreshTokenMissing)
}

func TestRunAuthRefresh_ServerNotRegistered(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const serverURL = "https://piv.example.com:8443"

	require.NoError(t, storeAuthTokenPair(context.Background(), slog.Default(), loginServer{URL: serverURL}, tokenstore.SourcePIV,
		&xkms.TokenPair{AccessToken: "at", RefreshToken: "rt"}))

	// The token is stored, but the server was never registered, so the
	// trust-path lookup for the refresh client fails.
	err := runAuthRefresh(authServerCmd(serverURL), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerLookupFailed)
}

// --- runAuthLogout ---

func TestRunAuthLogout_MissingServer(t *testing.T) {
	err := runAuthLogout(authServerCmd(""), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthLogout_TokenNotFound(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := runAuthLogout(authServerCmd("https://nonexistent.example.com:8443"), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthTokenLoadFailed)
}

// TestRunAuthLogout_NoRefreshToken_DeletesLocalOnly proves a WebAuthn-issued
// session (no refresh token, nothing to revoke server-side) is removed
// locally without attempting a network call.
func TestRunAuthLogout_NoRefreshToken_DeletesLocalOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const serverURL = "https://webauthn.example.com:8443"

	require.NoError(t, storeAuthToken(context.Background(), slog.Default(), loginServer{URL: serverURL}, makeTestJWT(t)))

	err := runAuthLogout(authServerCmd(serverURL), nil)
	require.NoError(t, err)

	tokens, cleanup, err := openTokenStore(slog.Default())
	require.NoError(t, err)
	defer cleanup()
	_, err = tokens.Load(context.Background(), serverURL)
	assert.Error(t, err, "the local session must be gone after logout")
}

// TestRunAuthLogout_RefreshTokenPresent_ServerUnreachable proves a session
// with a refresh token is left intact locally when the server-side revoke
// cannot be attempted (registered, but unreachable): logout must not delete
// a credential the server may still honor.
func TestRunAuthLogout_RefreshTokenPresent_ServerUnreachable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const serverURL = "https://127.0.0.1:1"

	registerTestServer(t, serverURL)
	require.NoError(t, storeAuthTokenPair(context.Background(), slog.Default(), loginServer{URL: serverURL}, tokenstore.SourcePIV,
		&xkms.TokenPair{AccessToken: "at", RefreshToken: "rt"}))

	err := runAuthLogout(authServerCmd(serverURL), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthLogoutFailed)

	tokens, cleanup, err := openTokenStore(slog.Default())
	require.NoError(t, err)
	defer cleanup()
	_, loadErr := tokens.Load(context.Background(), serverURL)
	assert.NoError(t, loadErr, "the local session must survive a failed server-side revoke")
}

// --- storeAuthTokenPair ---

func TestStoreAuthTokenPair_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const serverURL = "https://piv.example.com:8443"

	pair := &xkms.TokenPair{AccessToken: "at", RefreshToken: "rt", TokenType: "Bearer", ExpiresIn: 900}
	require.NoError(t, storeAuthTokenPair(context.Background(), slog.Default(), loginServer{URL: serverURL}, tokenstore.SourcePIV, pair))

	tokens, cleanup, err := openTokenStore(slog.Default())
	require.NoError(t, err)
	defer cleanup()

	entry, err := tokens.Load(context.Background(), serverURL)
	require.NoError(t, err)
	assert.Equal(t, "at", entry.Token)
	assert.Equal(t, "rt", entry.RefreshToken)
	assert.Equal(t, tokenstore.SourcePIV, entry.Source)
	assert.True(t, entry.HasRefreshToken())
	assert.False(t, entry.IsExpired())
}

func TestStoreAuthTokenPair_StorageFailure(t *testing.T) {
	// authStoragePath resolves through the shared data-dir chain; an
	// XKEY_HOME that cannot be created (nested under a regular file)
	// makes resolution fail, exercising the error path.
	isolateDataDirSources(t)
	blocker := filepath.Join(t.TempDir(), "blocker-file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	t.Setenv("XKEY_HOME", filepath.Join(blocker, "nested"))

	err := storeAuthTokenPair(context.Background(), slog.Default(), loginServer{URL: "https://example.com"}, tokenstore.SourcePIV,
		&xkms.TokenPair{AccessToken: "at"})
	assert.Error(t, err)
}

// --- newSessionLoginClient ---

func TestNewSessionLoginClient_Success(t *testing.T) {
	client, err := newSessionLoginClient(&serverregistry.ServerEntry{URL: "https://example.com:8443"})
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewSessionLoginClient_RequiresURL(t *testing.T) {
	_, err := newSessionLoginClient(&serverregistry.ServerEntry{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthSessionClientCreationFailed)
}

// makeTestJWT returns a syntactically-valid, unsigned JWT string suitable
// for applyJWTClaims (which parses claims without verifying the signature)
// so tests never need a real signing key.
func makeTestJWT(t *testing.T) string {
	t.Helper()
	// header.payload.signature, all base64url; content does not matter
	// beyond being valid JSON so jwt.ParseUnverified succeeds.
	return "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."
}
