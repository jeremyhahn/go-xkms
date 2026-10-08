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

// Tests for the barrier-aware AWS DPoP session store (go-xkms#1325): a
// barrier-backed store when a barrier is initialized, the historical
// unencrypted file with one warning otherwise, a typed refusal when an
// initialized barrier cannot be opened, and an explicit --session-store
// bypassing barrier auto-detection entirely. This mirrors
// oidc_barrier_test.go's coverage of the identical decision the OIDC RP
// token store makes, and oath_barrier_test.go's coverage for `xkey oath`.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAWSSessionStore_NoBarrier_WarnsAndUsesFileStore(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	logBuf := captureDefaultLog(t)

	cmd, _ := newDetachedOIDCCmd(t, oidcAWSCmd)

	session := AWSStoredSession{
		Region:       "us-east-1",
		RefreshToken: "refresh-1",
		DPoPKeyPEM:   "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----",
	}
	require.NoError(t, storeAWSSession(cmd, "", session))

	logged := logBuf.String()
	assert.Contains(t, logged, "unencrypted at rest", "the CLI must warn when no barrier protects the store")
	assert.Contains(t, logged, `store="AWS session"`)
	assert.Contains(t, logged, "xkey barrier init")

	// The session lands unencrypted in the data directory's storage,
	// readable without a barrier -- the no-barrier default is unchanged.
	raw := readStorageEntry(t, backupTestDataDir(home), awsSessionStoreKey)
	assert.Contains(t, string(raw), "refresh-1")

	loaded, err := loadAWSSession(cmd, "")
	require.NoError(t, err)
	assert.Equal(t, "refresh-1", loaded.RefreshToken)
}

func TestOpenAWSSessionStore_BarrierInitialized_WritesCiphertextNotPlaintext(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	const password = "correct-horse-battery-staple"
	dataDir := initTestOATHBarrier(t, home, password)

	saveCmd, _ := newDetachedOIDCCmd(t, oidcAWSCmd)
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	session := AWSStoredSession{
		Region:       "us-east-1",
		RefreshToken: "secret-refresh-token",
		DPoPKeyPEM:   "-----BEGIN EC PRIVATE KEY-----\nsecret-key-material\n-----END EC PRIVATE KEY-----",
		Expiration:   time.Now().Add(time.Hour),
	}
	require.NoError(t, storeAWSSession(saveCmd, "", session))

	// The raw bytes barrier storage wrote to disk must never contain the
	// plaintext refresh token or DPoP key.
	raw := readStorageEntry(t, dataDir, awsSessionStoreKey)
	assert.NotContains(t, string(raw), "secret-refresh-token")
	assert.NotContains(t, string(raw), "secret-key-material")

	// A second, independent CLI invocation (its own BarrierService, exactly
	// like a separate process) must unseal and read the session back.
	loadCmd, _ := newDetachedOIDCCmd(t, oidcAWSCmd)
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	loaded, err := loadAWSSession(loadCmd, "")
	require.NoError(t, err)
	assert.Equal(t, "secret-refresh-token", loaded.RefreshToken)
	assert.Contains(t, loaded.DPoPKeyPEM, "secret-key-material")
}

func TestOpenAWSSessionStore_BarrierWrongPassword_TypedRefusal(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	initTestOATHBarrier(t, home, "correct-password")

	cmd, _ := newDetachedOIDCCmd(t, oidcAWSCmd)
	t.Setenv("XKEY_BARRIER_PASSWORD", "wrong-password")

	_, err := loadAWSSession(cmd, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAWSSessionStoreFailed)
	assert.ErrorIs(t, err, ErrBarrierStoreOpenFailed,
		"a barrier that exists but cannot be opened must be a typed refusal")
}

func TestOpenAWSSessionStore_BarrierNoPasswordSupplied_TypedRefusal(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	initTestOATHBarrier(t, home, "correct-password")

	// No --barrier-password-stdin, no --barrier-password-file, no
	// XKEY_BARRIER_PASSWORD, and no terminal to prompt on:
	// resolveBarrierPassword has nothing left to try.
	cmd, _ := newDetachedOIDCCmd(t, oidcAWSCmd)

	_, err := loadAWSSession(cmd, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAWSSessionStoreFailed)
	assert.ErrorIs(t, err, ErrBarrierStoreOpenFailed)
}

func TestOpenAWSSessionStore_ExplicitSessionStoreFlagBypassesBarrier(t *testing.T) {
	home := isolatedBackupHome(t)
	initTestOATHBarrier(t, home, "correct-password")

	store := filepath.Join(t.TempDir(), "aws-session")
	cmd, _ := newDetachedOIDCCmd(t, oidcAWSCmd)

	session := AWSStoredSession{Region: "us-east-1", RefreshToken: "explicit-refresh"}

	// No --barrier-password is supplied; this must still succeed because an
	// explicit session store path bypasses barrier auto-detection entirely.
	require.NoError(t, storeAWSSession(cmd, store, session))
	assert.Contains(t, string(readStorageEntry(t, store, awsSessionStoreKey)), "explicit-refresh",
		"the explicit store holds the session unencrypted")

	loaded, err := loadAWSSession(cmd, store)
	require.NoError(t, err)
	assert.Equal(t, "explicit-refresh", loaded.RefreshToken)
}
