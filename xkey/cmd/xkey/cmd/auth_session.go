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
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/spf13/cobra"
)

// tokenstoreSourcePIV is the token-store source tag for sessions minted by
// PIV login. Kept as its own identifier so auth_piv.go does not need to
// import tokenstore solely for this constant.
const tokenstoreSourcePIV = tokenstore.SourcePIV

// Session refresh/logout errors.
var (
	// ErrAuthSessionClientCreationFailed indicates the session login-plane
	// client could not be constructed.
	ErrAuthSessionClientCreationFailed = errors.New("auth: failed to create session client")

	// ErrAuthRefreshTokenMissing indicates the stored session has no
	// refresh token to rotate, because it was not issued by the session
	// login-plane (e.g. it came from the WebAuthn ceremony, which mints a
	// single access token with no refresh).
	ErrAuthRefreshTokenMissing = errors.New("auth: no refresh token stored for this server; the session was not established via a refreshable login (e.g. PIV)")

	// ErrAuthRefreshFailed indicates the server rejected the refresh
	// request.
	ErrAuthRefreshFailed = errors.New("auth: failed to refresh session")

	// ErrAuthRefreshSaveFailed indicates the rotated pair could not be
	// persisted.
	ErrAuthRefreshSaveFailed = errors.New("auth: failed to store the refreshed token pair")

	// ErrAuthLogoutFailed indicates the server rejected the logout
	// (revoke) request. The local session is left intact so "auth status"
	// keeps reporting its true state.
	ErrAuthLogoutFailed = errors.New("auth: failed to revoke session on the server")

	// ErrAuthLogoutDeleteFailed indicates the local token entry could not
	// be removed after a successful (or unnecessary) server-side revoke.
	ErrAuthLogoutDeleteFailed = errors.New("auth: failed to delete the local session")
)

// authRefreshCmd rotates a stored access/refresh token pair.
var authRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Rotate the stored access/refresh token pair",
	Long: `Rotate a stored session's access/refresh token pair.

Only sessions established through the session login-plane (currently "xkey
auth login --piv") carry a refresh token; a WebAuthn session has none to
rotate and this command reports ErrAuthRefreshTokenMissing for it.

The server detects refresh-token reuse (replay of an already-rotated token)
and revokes the whole token family; a refresh failure after that point means
the session must be re-established with a fresh login.

Flags:
  --server  Server URL (required)

Examples:
  # Rotate the session for a server
  xkey auth refresh --server https://xkms.example.com:8443`,
	RunE: runAuthRefresh,
}

// authLogoutCmd revokes and deletes a stored session.
var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke the stored session and remove it locally",
	Long: `Revoke a stored session and remove it from the local token store.

When the session carries a refresh token (PIV login), the refresh token is
revoked on the server first; the local entry is only deleted once that
revoke succeeds, so "auth status" never reports a session as gone while the
server still honors it. Sessions with no refresh token (WebAuthn) have
nothing to revoke server-side — the access token simply expires on its own
— so this command only removes the local entry for them.

Flags:
  --server  Server URL (required)

Examples:
  # Log out of a server
  xkey auth logout --server https://xkms.example.com:8443`,
	RunE: runAuthLogout,
}

func init() {
	authCmd.AddCommand(authRefreshCmd)
	authCmd.AddCommand(authLogoutCmd)

	authRefreshCmd.Flags().String("server", "", "Server URL (required)")
	authLogoutCmd.Flags().String("server", "", "Server URL (required)")
}

// newSessionLoginClient builds a session login-plane client for entry,
// reusing the server's TOFU-pinned CA fingerprint when the registry recorded
// one — the same trust path "auth login" and "auth login --piv" use. Without a
// pin the roots come from the xKey trust store and the system pool, so a CA
// added with "xkey trust add" reaches these verbs too (#250).
func newSessionLoginClient(entry *serverregistry.ServerEntry) (*xkms.LoginClient, error) {
	var roots *x509.CertPool
	if entry.CAFingerprint == "" {
		// LoginClientConfig ignores RootCAs when SPKIPin is set, so only build
		// the pool when there is no pin to be the trust anchor.
		pool, err := authRootPool("")
		if err != nil {
			return nil, err
		}
		roots = pool
	}

	client, err := xkms.NewLoginClient(xkms.LoginClientConfig{
		BaseURL: entry.URL,
		SPKIPin: entry.CAFingerprint,
		RootCAs: roots,
		Timeout: defaultAuthTimeout,
	})
	if err != nil {
		return nil, errors.Join(ErrAuthSessionClientCreationFailed, err)
	}
	return client, nil
}

// storeAuthTokenPair persists a session login-plane token pair (access +
// refresh) in the token store, alongside best-effort JWT metadata read from
// the access token. It is the token-pair counterpart to storeAuthToken,
// which only ever stores a single opaque token.
func storeAuthTokenPair(ctx context.Context, logger *slog.Logger, server loginServer, source string, pair *xkms.TokenPair) error {
	tokens, cleanup, err := openTokenStore(logger)
	if err != nil {
		return err
	}
	defer cleanup()

	entry := &tokenstore.TokenEntry{
		ServerURL:    server.URL,
		ServerID:     server.Ref.ID,
		ServerName:   server.Ref.Name,
		TokenType:    tokenstore.TypeBearer,
		Source:       source,
		Token:        pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		IssuedAt:     time.Now().UTC(),
	}
	applyJWTClaims(entry, pair.AccessToken)
	if pair.ExpiresIn > 0 {
		entry.ExpiresAt = time.Now().UTC().Add(time.Duration(pair.ExpiresIn) * time.Second)
	}

	if err := tokens.Save(ctx, entry); err != nil {
		return errors.Join(ErrAuthTokenSaveFailed, err)
	}
	return nil
}

// runAuthRefresh executes the auth refresh command.
func runAuthRefresh(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	tokens, tokenCleanup, err := openTokenStore(logger)
	if err != nil {
		return err
	}
	defer tokenCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), defaultAuthTimeout)
	defer cancel()

	entry, err := tokens.Load(ctx, serverURL)
	if err != nil {
		return errors.Join(ErrAuthTokenLoadFailed, err)
	}
	if !entry.HasRefreshToken() {
		return ErrAuthRefreshTokenMissing
	}

	registry, registryCleanup, err := openServerRegistry(logger)
	if err != nil {
		return err
	}
	defer registryCleanup()

	serverEntry, err := registry.Lookup(ctx, serverURL)
	if err != nil {
		return errors.Join(ErrAuthServerLookupFailed, err)
	}

	client, err := newSessionLoginClient(serverEntry)
	if err != nil {
		return err
	}

	pair, err := client.Refresh(ctx, entry.RefreshToken)
	if err != nil {
		return errors.Join(ErrAuthRefreshFailed, err)
	}

	server, err := identifyLoginServer(ctx, authClientConfig{ServerURL: serverURL, SPKIPin: serverEntry.CAFingerprint})
	if err != nil {
		return err
	}
	if err := storeAuthTokenPair(ctx, logger, server, entry.Source, pair); err != nil {
		return errors.Join(ErrAuthRefreshSaveFailed, err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Session refreshed for %s.\n", serverURL)
	return nil
}

// runAuthLogout executes the auth logout command.
func runAuthLogout(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	out := cmd.OutOrStdout()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	tokens, tokenCleanup, err := openTokenStore(logger)
	if err != nil {
		return err
	}
	defer tokenCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), defaultAuthTimeout)
	defer cancel()

	entry, err := tokens.Load(ctx, serverURL)
	if err != nil {
		return errors.Join(ErrAuthTokenLoadFailed, err)
	}

	if entry.HasRefreshToken() {
		registry, registryCleanup, err := openServerRegistry(logger)
		if err != nil {
			return err
		}
		defer registryCleanup()

		serverEntry, err := registry.Lookup(ctx, serverURL)
		if err != nil {
			return errors.Join(ErrAuthServerLookupFailed, err)
		}

		client, err := newSessionLoginClient(serverEntry)
		if err != nil {
			return err
		}

		if err := client.Logout(ctx, entry.Token, entry.RefreshToken); err != nil {
			// The session is left intact locally: report the failure
			// rather than deleting a credential the server still honors.
			return errors.Join(ErrAuthLogoutFailed, err)
		}
	} else {
		logger.Debug("no refresh token stored; nothing to revoke server-side, removing local session only",
			slog.String("server", serverURL))
	}

	if err := tokens.Delete(ctx, serverURL); err != nil {
		return errors.Join(ErrAuthLogoutDeleteFailed, err)
	}

	_, _ = fmt.Fprintf(out, "Logged out of %s.\n", serverURL)
	return nil
}
