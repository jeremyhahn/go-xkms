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

package gui

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// isolateUnifiedConfig points the unified xkey config at an empty temporary
// directory and returns the path of its xkey.yaml (not yet written).
func isolateUnifiedConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.SetConfigDir(dir)
	t.Cleanup(config.ResetConfigDir)
	return filepath.Join(dir, "xkey.yaml")
}

// newAuthenticatorApp returns a lifecycle App with in-memory FIDO2 storage,
// the one precondition initializeAuthenticator has.
func newAuthenticatorApp(t *testing.T) *App {
	t.Helper()
	app := newLifecycleApp(t)
	app.fido2Storage = newMemoryFIDO2Storage(t, xkms.NewStorageMemory())
	return app
}

// newMemoryFIDO2Storage returns FIDO2 credential storage over backend under
// the prefix xkey uses.
func newMemoryFIDO2Storage(t *testing.T, backend xkms.StorageBackend) authenticator.StatefulCredentialStorage {
	t.Helper()
	storage, err := authenticator.NewBackendStorage(backend, "xkey/")
	require.NoError(t, err)
	return storage
}

func TestApp_InitializeAuthenticator_NoStorageBuildsNothing(t *testing.T) {
	isolateUnifiedConfig(t)
	app := newLifecycleApp(t)
	require.Nil(t, app.fido2Storage)

	app.initializeAuthenticator()

	assert.Nil(t, app.authenticatorInstance, "no authenticator may exist without credential storage")
	assert.Nil(t, app.fido2KeyBackend)
}

// The GUI must honour fido2.attestation from the unified config; it once
// pinned every registration to "none" regardless of configuration.
func TestApp_InitializeAuthenticator_AttestationFromUnifiedConfig(t *testing.T) {
	tests := []struct {
		name string
		yaml string // empty: no config file
		want string
	}{
		{name: "no file uses the config default", want: config.DefaultConfig().FIDO2.Attestation},
		{name: "file selects none", yaml: "fido2:\n  attestation: none\n", want: authenticator.AttestationFormatNone},
		{name: "unreadable file falls back to none", yaml: "fido2: [unterminated\n", want: authenticator.AttestationFormatNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := isolateUnifiedConfig(t)
			if tt.yaml != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0600))
			}
			app := newAuthenticatorApp(t)

			app.initializeAuthenticator()

			require.NotNil(t, app.authenticatorInstance)
			assert.Equal(t, tt.want, app.authenticatorInstance.Config().AttestationFormat)
		})
	}
}

func TestApp_InitializeAuthenticator_PresenceSettingsFromGUIConfig(t *testing.T) {
	isolateUnifiedConfig(t)
	app := newAuthenticatorApp(t)
	app.config.FIDO2RequireUserPresence = false
	app.config.FIDO2UserIntentCheck = true

	app.initializeAuthenticator()

	require.NotNil(t, app.authenticatorInstance)
	cfg := app.authenticatorInstance.Config()
	assert.False(t, cfg.RequireUserPresence)
	assert.True(t, cfg.EnableUserIntentCheck)
	assert.Same(t, app.fido2KeyBackend, cfg.KeyBackend, "the composite backend is the authenticator's key backend")
}

func TestApp_InitializeAuthenticator_AuditsToTheAppAuditStore(t *testing.T) {
	isolateUnifiedConfig(t)
	app := newAuthenticatorApp(t)

	app.initializeAuthenticator()

	require.NotNil(t, app.authenticatorInstance)
	require.NoError(t, app.authenticatorInstance.SetInitialPIN([]byte("246813")))
	seeded := app.auditStore.Query(audit.QueryFilter{Operation: audit.OpPINSeeded})
	assert.Len(t, seeded, 1, "establishing the FIDO2 PIN is recorded in the GUI's audit store")
}

func TestApp_InitializeAuthenticator_CreatesPrivateAutofillDir(t *testing.T) {
	isolateUnifiedConfig(t)
	app := newAuthenticatorApp(t)
	app.dataDir = t.TempDir()

	app.initializeAuthenticator()

	info, err := os.Stat(filepath.Join(app.dataDir, "extension", "autofill"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm(), "autofill registrations are private to the user")
}

// TestApp_InitializeAuthenticator_UnusableDataDirStillServes verifies an
// autofill registration directory that cannot be created does not stop the
// authenticator being built.
func TestApp_InitializeAuthenticator_UnusableDataDirStillServes(t *testing.T) {
	isolateUnifiedConfig(t)
	app := newAuthenticatorApp(t)
	notADir := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	app.dataDir = notADir

	app.initializeAuthenticator()

	assert.NotNil(t, app.authenticatorInstance)
}

// TestApp_InitializeAuthenticator_CorruptStateServesNoAuthenticator verifies
// persisted authenticator state that cannot be decoded is not replaced with
// a fresh one: a fresh state would reset the PIN retry counter.
func TestApp_InitializeAuthenticator_CorruptStateServesNoAuthenticator(t *testing.T) {
	isolateUnifiedConfig(t)
	app := newLifecycleApp(t)
	backend := xkms.NewStorageMemory()
	require.NoError(t, backend.Put(context.Background(), "xkey/state", []byte("not json")))
	app.fido2Storage = newMemoryFIDO2Storage(t, backend)

	app.initializeAuthenticator()

	assert.Nil(t, app.authenticatorInstance)
}

// TestApp_InitializeAuthenticator_SealedPolicyKeepsSecureDefaults verifies a
// sealed enterprise policy imposes its secure defaults before SO login, over
// a GUI setting that turned user presence off.
func TestApp_InitializeAuthenticator_SealedPolicyKeepsSecureDefaults(t *testing.T) {
	dir := useRelaxedConfigDir(t)
	sealRelaxedPolicy(t, dir, "so-pin-12345")
	app := newAuthenticatorApp(t)
	app.config.FIDO2RequireUserPresence = false
	app.configDirPath = dir

	app.initializeAuthenticator()

	require.NotNil(t, app.authenticatorInstance)
	assert.True(t, app.authenticatorInstance.Config().RequireUserPresence)
}

// The GUI login must bind the callback the unified config names, the same
// host and port the CLI uses.
func TestApp_InitializeDataDir_OIDCCallbackFromUnifiedConfig(t *testing.T) {
	path := isolateUnifiedConfig(t)
	require.NoError(t, os.WriteFile(path,
		[]byte("oidc:\n  callback_host: 127.0.0.1\n  callback_port: 18765\n"), 0600))
	app := newLifecycleApp(t)

	require.NoError(t, app.InitializeDataDir())

	cb := app.oidcService.Callback()
	assert.Equal(t, "127.0.0.1", cb.Host)
	assert.Equal(t, 18765, cb.Port)
}
