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

// Tests for the barrier-aware "xkey oidc" token store (go-xkms#4, gap 1): a
// barrier-backed store when a barrier is initialized, the historical
// unencrypted file with one warning otherwise, a typed refusal when an
// initialized barrier cannot be opened, and the auto-refresh loop reusing
// one already-open store rather than reopening it on every tick. This
// mirrors oath_barrier_test.go's coverage of the identical decision `xkey
// oath` makes.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// newDetachedOIDCCmd builds a private copy of an oidc subcommand's flags,
// the same way newDetachedOATHCmd (oath_barrier_test.go) does, but WITHOUT
// forcing --token-store. oidcTestCmd cannot be reused here: it always sets
// --token-store, which is exactly the escape hatch that bypasses barrier
// auto-detection, and these tests need Flags().Changed("token-store") to
// stay false so openOIDCTokenStore's barrier decision actually runs.
// Operating on a detached copy also keeps a --barrier-password set in one
// test from leaking into another.
func newDetachedOIDCCmd(t *testing.T, template *cobra.Command) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: template.Use, RunE: template.RunE}
	template.Flags().VisitAll(func(f *pflag.Flag) {
		cmd.Flags().AddFlag(&pflag.Flag{
			Name:     f.Name,
			Usage:    f.Usage,
			Value:    newFlagValue(f),
			DefValue: f.DefValue,
		})
	})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func TestOpenOIDCTokenStore_NoBarrier_WarnsAndUsesFileStore(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	logBuf := captureDefaultLog(t)

	cmd, _ := newDetachedOIDCCmd(t, oidcTokenCmd)

	tok := mustOIDCStoredToken(t, "", "https://example.okta.com", "client",
		"access-1", "", "", time.Now().Add(time.Hour), nil)
	defer tok.Destroy()
	require.NoError(t, storeToken(cmd, defaultOIDCTokenStorePath, tok))

	logged := logBuf.String()
	assert.Contains(t, logged, "unencrypted at rest", "the CLI must warn when no barrier protects the store")
	assert.Contains(t, logged, "store=OIDC")
	assert.Contains(t, logged, "xkey barrier init")

	// The token lands in the historical unencrypted file, readable without a
	// barrier -- the no-barrier default is unchanged.
	raw, err := os.ReadFile(filepath.Join(backupTestDataDir(home), "oidc", "tokens.json"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), "access-1")
	assert.Contains(t, string(raw), "https://example.okta.com")

	loaded, err := loadToken(cmd, defaultOIDCTokenStorePath)
	require.NoError(t, err)
	defer loaded.Destroy()
	assert.Equal(t, "access-1", string(loaded.AccessToken()))
}

func TestOpenOIDCTokenStore_BarrierInitialized_WritesCiphertextNotPlaintext(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	const password = "correct-horse-battery-staple"
	// initTestOATHBarrier (oath_barrier_test.go) initializes the ONE xkey
	// barrier every store shares; nothing about it is OATH-specific.
	dataDir := initTestOATHBarrier(t, home, password)

	saveCmd, _ := newDetachedOIDCCmd(t, oidcTokenCmd)
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	tok := mustOIDCStoredToken(t, "", "https://example.okta.com", "client",
		"secret-access-token", "secret-refresh-token", "", time.Now().Add(time.Hour), nil)
	defer tok.Destroy()
	require.NoError(t, storeToken(saveCmd, defaultOIDCTokenStorePath, tok))

	// The raw bytes barrier storage wrote to disk must never contain the
	// plaintext tokens.
	raw, err := os.ReadFile(filepath.Join(dataDir, "oidc", "tokens.json"))
	require.NoError(t, err, "the barrier-encrypted OIDC token entry must exist on disk")
	assert.NotContains(t, string(raw), "secret-access-token")
	assert.NotContains(t, string(raw), "secret-refresh-token")

	// A second, independent CLI invocation (its own BarrierService, exactly
	// like a separate process) must unseal and read the token back.
	loadCmd, _ := newDetachedOIDCCmd(t, oidcTokenCmd)
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	loaded, err := loadToken(loadCmd, defaultOIDCTokenStorePath)
	require.NoError(t, err)
	defer loaded.Destroy()
	assert.Equal(t, "secret-access-token", string(loaded.AccessToken()))
	assert.Equal(t, "secret-refresh-token", string(loaded.RefreshToken()))
}

func TestOpenOIDCTokenStore_BarrierWrongPassword_TypedRefusal(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	initTestOATHBarrier(t, home, "correct-password")

	cmd, _ := newDetachedOIDCCmd(t, oidcTokenCmd)
	t.Setenv("XKEY_BARRIER_PASSWORD", "wrong-password")

	_, err := loadToken(cmd, defaultOIDCTokenStorePath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCTokenStoreFailed)
	assert.ErrorIs(t, err, ErrBarrierStoreOpenFailed,
		"a barrier that exists but cannot be opened must be a typed refusal")
}

func TestOpenOIDCTokenStore_BarrierNoPasswordSupplied_TypedRefusal(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	initTestOATHBarrier(t, home, "correct-password")

	// No --barrier-password, no --barrier-password-file, no
	// XKEY_BARRIER_PASSWORD, and no terminal to prompt on: resolveBarrierPassword
	// has nothing left to try.
	cmd, _ := newDetachedOIDCCmd(t, oidcTokenCmd)

	_, err := loadToken(cmd, defaultOIDCTokenStorePath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCTokenStoreFailed)
	assert.ErrorIs(t, err, ErrBarrierStoreOpenFailed)
}

func TestOpenOIDCTokenStore_ExplicitTokenStoreFlagBypassesBarrier(t *testing.T) {
	home := isolatedBackupHome(t)
	initTestOATHBarrier(t, home, "correct-password")

	store := filepath.Join(t.TempDir(), "tokens.json")
	cmd, _ := newDetachedOIDCCmd(t, oidcTokenCmd)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "token-store", store))

	tok := mustOIDCStoredToken(t, "", "https://explicit.example.com", "client",
		"explicit-access", "", "", time.Now().Add(time.Hour), nil)
	defer tok.Destroy()

	// No --barrier-password is supplied; this must still succeed because an
	// explicit --token-store bypasses barrier auto-detection entirely.
	require.NoError(t, storeToken(cmd, store, tok))
	assert.FileExists(t, store)

	loaded, err := loadToken(cmd, store)
	require.NoError(t, err)
	defer loaded.Destroy()
	assert.Equal(t, "explicit-access", string(loaded.AccessToken()))
}

// TestRunAutoRefresh_ReusesTheSameOpenBarrier_NotReopenedPerTick proves the
// auto-refresh loop opens its barrier-backed store once and reuses that
// handle for every tick (go-xkms#4) rather than reopening -- and,
// for a barrier-backed store, re-unsealing -- it on every interval: the
// barrier password on cmd is invalidated immediately after the store is
// opened, so a second (or third) resolveSecretStoreBackend call anywhere in
// the loop would fail closed instead of the loop completing three
// successful refreshes.
func TestRunAutoRefresh_ReusesTheSameOpenBarrier_NotReopenedPerTick(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	const password = "correct-horse-battery-staple"
	initTestOATHBarrier(t, home, password)

	// refreshes counts token requests. Ticks run sequentially, so a fourth
	// request only arrives once the third tick has finished saving through
	// the store, and waiting on it avoids reading the loop's log buffer while
	// the loop is still writing to it.
	var refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OIDCTokenResponse{
			AccessToken:  xkms.SecretBytes("rotated-access"),
			RefreshToken: xkms.SecretBytes("rotated-refresh"),
			ExpiresIn:    3600,
		})
	}))
	defer server.Close()

	cmd, _ := newDetachedOIDCCmd(t, oidcTokenCmd)
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	store, err := openOIDCTokenStore(cmd, defaultOIDCTokenStorePath)
	require.NoError(t, err)

	seed := mustOIDCStoredToken(t, "", "https://example.okta.com", "client",
		"seed-access", "seed-refresh", "", time.Now().Add(-time.Minute), nil)
	defer seed.Destroy()
	require.NoError(t, store.Save(seed))

	// store is already open; any later resolveBarrierPassword call would see
	// this wrong password instead of the one that unsealed the barrier above.
	t.Setenv("XKEY_BARRIER_PASSWORD", "now-the-wrong-password")

	var buf bytes.Buffer
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runAutoRefresh(server.URL, "client", store, defaultOIDCTokenStorePath, "", "", 10*time.Millisecond, &buf, oidc.TokenEncodingForm, stop)
	}()

	require.Eventually(t, func() bool {
		return refreshes.Load() >= 4
	}, 5*time.Second, 10*time.Millisecond, "fewer than 4 refresh ticks before the deadline")
	close(stop)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("runAutoRefresh did not stop after its stop channel closed")
	}

	// The loop has returned, so buf is no longer written concurrently.
	require.GreaterOrEqual(t, strings.Count(buf.String(), "Token refreshed."), 3,
		"fewer than 3 successful ticks before the deadline; log:\n%s", buf.String())

	assert.NotContains(t, buf.String(), "Error", "every tick must have reused the already-open store, never reopened it")

	loaded, err := store.Load()
	require.NoError(t, err)
	defer loaded.Destroy()
	assert.Equal(t, "rotated-access", string(loaded.AccessToken()))
}
