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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
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

// sessionTestServer is a pinned TLS server speaking the session plane's
// refresh and logout verbs, registered in the server registry the way an
// enrolled server is.
type sessionTestServer struct {
	*httptest.Server
	status int // answered by every verb when non-zero

	mu       sync.Mutex
	requests []sessionTestRequest
}

type sessionTestRequest struct {
	path          string
	authorization string
	refreshToken  string
}

func newSessionTestServer(t *testing.T) *sessionTestServer {
	t.Helper()
	s := &sessionTestServer{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode %s request: %v", r.URL.Path, err)
		}
		s.mu.Lock()
		s.requests = append(s.requests, sessionTestRequest{
			path:          r.URL.Path,
			authorization: r.Header.Get("Authorization"),
			refreshToken:  body.RefreshToken,
		})
		s.mu.Unlock()

		switch {
		case s.status != 0:
			http.Error(w, "refresh token reused", s.status)
		case r.URL.Path == "/api/v1/auth/refresh":
			writeTestJSON(t, w, http.StatusOK, map[string]any{
				"access_token":  "rotated-access-token",
				"refresh_token": "rotated-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    900,
			})
		case r.URL.Path == "/api/v1/auth/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)

	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	defer cleanup()
	require.NoError(t, registry.Register(context.Background(), &serverregistry.ServerEntry{
		URL:           s.URL,
		Name:          "session",
		Protocol:      serverregistry.ProtocolREST,
		CAFingerprint: tlsServerPin(t, s.Server),
	}))
	return s
}

func (s *sessionTestServer) received() []sessionTestRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sessionTestRequest(nil), s.requests...)
}

func loadStoredSession(t *testing.T, serverURL string) (*tokenstore.TokenEntry, error) {
	t.Helper()
	tokens, cleanup, err := openTokenStore(slog.Default())
	require.NoError(t, err)
	defer cleanup()
	return tokens.Load(context.Background(), serverURL)
}

func TestRunAuthRefresh_RotatesTheStoredPair(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := newSessionTestServer(t)
	require.NoError(t, storeAuthTokenPair(context.Background(), slog.Default(), loginServer{URL: srv.URL}, tokenstore.SourcePIV,
		&xkms.TokenPair{AccessToken: "old-access-token", RefreshToken: "old-refresh-token", ExpiresIn: 900}))

	cmd := authServerCmd(srv.URL)
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, runAuthRefresh(cmd, nil))
	assert.Contains(t, out.String(), "Session refreshed for "+srv.URL)

	got := srv.received()
	require.Len(t, got, 1)
	assert.Equal(t, "/api/v1/auth/refresh", got[0].path)
	assert.Equal(t, "old-refresh-token", got[0].refreshToken)

	entry, err := loadStoredSession(t, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "rotated-access-token", entry.Token)
	assert.Equal(t, "rotated-refresh-token", entry.RefreshToken)
	assert.Equal(t, tokenstore.SourcePIV, entry.Source, "a refresh keeps the login's source")
}

func TestRunAuthRefresh_ServerRefusalKeepsTheStoredPair(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := newSessionTestServer(t)
	srv.status = http.StatusUnauthorized
	require.NoError(t, storeAuthTokenPair(context.Background(), slog.Default(), loginServer{URL: srv.URL}, tokenstore.SourcePIV,
		&xkms.TokenPair{AccessToken: "old-access-token", RefreshToken: "old-refresh-token", ExpiresIn: 900}))

	err := runAuthRefresh(authServerCmd(srv.URL), nil)
	require.ErrorIs(t, err, ErrAuthRefreshFailed)

	entry, err := loadStoredSession(t, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "old-refresh-token", entry.RefreshToken)
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

func TestRunAuthLogout_RevokesServerSideThenDeletesLocally(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := newSessionTestServer(t)
	require.NoError(t, storeAuthTokenPair(context.Background(), slog.Default(), loginServer{URL: srv.URL}, tokenstore.SourcePIV,
		&xkms.TokenPair{AccessToken: "live-access-token", RefreshToken: "live-refresh-token", ExpiresIn: 900}))

	cmd := authServerCmd(srv.URL)
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, runAuthLogout(cmd, nil))
	assert.Contains(t, out.String(), "Logged out of "+srv.URL)

	got := srv.received()
	require.Len(t, got, 1)
	assert.Equal(t, "/api/v1/auth/logout", got[0].path)
	assert.Equal(t, "Bearer live-access-token", got[0].authorization)
	assert.Equal(t, "live-refresh-token", got[0].refreshToken)

	_, err := loadStoredSession(t, srv.URL)
	assert.Error(t, err, "the local session is removed once the server revoked it")
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
