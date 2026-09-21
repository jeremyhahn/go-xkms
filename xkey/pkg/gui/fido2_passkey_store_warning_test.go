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
// FIDO2 passkey store; xkey adds no per-credential wrap of its own. When
// initializeDataDir() falls back to a plain file store because no barrier is
// active, the operator has no other signal that private keys are landing on
// disk unencrypted. These tests pin that the fallback logs exactly one
// warning naming the exposure and the remedy (#181), and that the warning
// does not fire once a barrier is active.

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitializeDataDir_WarnsWhenFIDO2StoreUnencrypted proves the no-barrier
// fallback path (app.go's plain-file branch for FIDO2 credential storage)
// emits a slog.Warn naming the store as unencrypted and pointing at the
// remedy, rather than refusing or silently falling back.
func TestInitializeDataDir_WarnsWhenFIDO2StoreUnencrypted(t *testing.T) {
	app := newMinimalApp(t)

	var buf bytes.Buffer
	app.log = slog.New(slog.NewTextHandler(&buf, nil))

	err := app.initializeDataDir()
	require.NoError(t, err)

	got := buf.String()
	assert.Contains(t, got, "passkey store is unencrypted at rest",
		"the no-barrier fallback must warn that the passkey store is plaintext")
	assert.Contains(t, got, "xkey barrier init",
		"the warning must point the operator at the remedy")
}

// TestInitializeDataDir_NoWarningWhenBarrierActive proves the warning is
// specific to the no-barrier fallback: once the barrier is initialized and
// unsealed, the FIDO2 store is barrier-backed and the plaintext warning must
// not fire.
func TestInitializeDataDir_NoWarningWhenBarrierActive(t *testing.T) {
	app := newMinimalApp(t)

	require.NoError(t, app.barrierService.Initialize("test-password", "passphrase"),
		"precondition: barrier must initialize successfully")
	require.NotNil(t, app.barrierService.GetBackend(),
		"precondition: an initialized barrier must expose a backend")

	var buf bytes.Buffer
	app.log = slog.New(slog.NewTextHandler(&buf, nil))

	err := app.initializeDataDir()
	require.NoError(t, err)

	got := buf.String()
	assert.NotContains(t, got, "passkey store is unencrypted at rest",
		"a barrier-backed FIDO2 store must not carry the plaintext warning")
}
