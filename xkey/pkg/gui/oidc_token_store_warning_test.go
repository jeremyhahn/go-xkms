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

package gui

// go-qrdb's seal barrier is the ONE at-rest encryption xkey relies on for the
// OIDC token store; xkey no longer "encrypts" tokens.json with a key
// compiled into the binary, and no longer falls back to plaintext
// (go-xkms#1203). When initializeDataDir() falls back to the no-barrier
// path, OIDC tokens are held in memory only for the session: nothing named
// "tokens.json" is ever written, and the operator is warned once. These
// tests pin that behavior end to end through the same startup path
// fido2_passkey_store_warning_test.go exercises for the FIDO2 passkey store.

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitializeDataDir_WarnsWhenOIDCTokenStoreInMemory proves the
// no-barrier fallback path (app.go's plain-data-dir branch for OIDC token
// storage) emits a slog.Warn naming the exposure -- tokens will not survive
// a restart -- rather than refusing, silently degrading, or writing a file
// "encrypted" with a hardcoded key.
func TestInitializeDataDir_WarnsWhenOIDCTokenStoreInMemory(t *testing.T) {
	app := newMinimalApp(t)

	var buf bytes.Buffer
	app.oidcService = services.NewOIDCService(slog.New(slog.NewTextHandler(&buf, nil)))

	err := app.initializeDataDir()
	require.NoError(t, err)

	got := buf.String()
	assert.Contains(t, got, "OIDC tokens are kept in memory only",
		"the no-barrier fallback must warn that OIDC tokens are session-only")
	assert.Contains(t, got, "will not survive a restart",
		"the warning must state the consequence")
}

// TestInitializeDataDir_NoOIDCTokenFileWithoutBarrier proves the no-barrier
// fallback never creates a token file under the OIDC data directory: OIDC
// tokens live in memory only, never on disk, without a barrier.
func TestInitializeDataDir_NoOIDCTokenFileWithoutBarrier(t *testing.T) {
	app := newMinimalApp(t)

	err := app.initializeDataDir()
	require.NoError(t, err)

	oidcDir := filepath.Join(app.dataDir, "oidc")
	entries, readErr := os.ReadDir(oidcDir)
	require.NoError(t, readErr, "the oidc data directory must still exist for provider config and scripts")

	for _, entry := range entries {
		assert.NotContains(t, entry.Name(), "tokens",
			"no barrier means no token file of any name may land on disk, found %q", entry.Name())
	}
}

// TestInitializeDataDir_NoOIDCWarningWhenBarrierActive proves the warning is
// specific to the no-barrier fallback: once the barrier is initialized and
// unsealed, OIDC tokens are barrier-backed and the in-memory-only warning
// must not fire.
func TestInitializeDataDir_NoOIDCWarningWhenBarrierActive(t *testing.T) {
	app := newMinimalApp(t)

	require.NoError(t, app.barrierService.Initialize("test-password", "passphrase"),
		"precondition: barrier must initialize successfully")
	require.NotNil(t, app.barrierService.GetBackend(),
		"precondition: an initialized barrier must expose a backend")

	var buf bytes.Buffer
	app.oidcService = services.NewOIDCService(slog.New(slog.NewTextHandler(&buf, nil)))

	err := app.initializeDataDir()
	require.NoError(t, err)

	got := buf.String()
	assert.NotContains(t, got, "OIDC tokens are kept in memory only",
		"a barrier-backed OIDC token store must not carry the in-memory-only warning")
}
