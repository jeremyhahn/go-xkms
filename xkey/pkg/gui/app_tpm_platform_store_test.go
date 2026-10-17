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

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

var errFakePKSInit = errors.New("platform key store: init failed")

// fakePlatformKeyStore records whether getTPM auto-initializes it.
type fakePlatformKeyStore struct {
	xkmssdk.PlatformKeyStorer
	initialized bool
	initErr     error
	initCalls   int
}

func (s *fakePlatformKeyStore) IsInitialized() bool { return s.initialized }

func (s *fakePlatformKeyStore) InitializeWithDefaults() error {
	s.initCalls++
	if s.initErr != nil {
		return s.initErr
	}
	s.initialized = true
	return nil
}

// platformStoreTPM is a TPM that already carries a platform key store, so
// xkmssdk.AttachPlatformKeyStore returns it as is. A nil store makes the
// TPM unattachable: it has no SetPlatformKeyStore.
type platformStoreTPM struct {
	xkmssdk.TrustedPlatformModule
	pks xkmssdk.PlatformKeyStorer
}

func (t *platformStoreTPM) PlatformKeyStore() xkmssdk.PlatformKeyStorer { return t.pks }

func (t *platformStoreTPM) Close() error { return nil }

// platformSRKApp returns an app whose TPM device is present, whose config
// asks for a Platform SRK and whose TPM opens as tpm.
func platformSRKApp(t *testing.T, tpm xkmssdk.TrustedPlatformModule, setupComplete bool) *App {
	t.Helper()
	device := filepath.Join(t.TempDir(), "tpmrm0")
	require.NoError(t, os.WriteFile(device, nil, 0o600))

	app := &App{log: lifecycleTestLogger(), config: DefaultGUIConfig(), dataDir: t.TempDir()}
	app.config.SetupComplete = setupComplete
	app.newTPM = func(*xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		return tpm, nil
	}
	presetTPMConfig(app, xkmssdk.TPMConfig{Device: device, PlatformSRK: &xkmssdk.PlatformSRKConfig{}})
	t.Cleanup(func() {
		if app.tpmStorageFactory != nil {
			assert.NoError(t, app.tpmStorageFactory.Close())
		}
	})
	return app
}

// TestApp_GetTPM_ReturningUserAutoInitializesPlatformKeyStore verifies a
// returning user's uninitialized platform key store is created on open.
func TestApp_GetTPM_ReturningUserAutoInitializesPlatformKeyStore(t *testing.T) {
	pks := &fakePlatformKeyStore{}
	tpm := &platformStoreTPM{pks: pks}
	app := platformSRKApp(t, tpm, true)

	assert.Same(t, tpm, app.getTPM())
	assert.Equal(t, 1, pks.initCalls)
	assert.True(t, pks.initialized)
}

// TestApp_GetTPM_FirstRunLeavesPlatformKeyStoreToTheWizard verifies the
// platform key store is not auto-initialized before setup completes: the
// wizard creates the SRK with the user PIN, and an empty-auth SRK made here
// would race it.
func TestApp_GetTPM_FirstRunLeavesPlatformKeyStoreToTheWizard(t *testing.T) {
	pks := &fakePlatformKeyStore{}
	tpm := &platformStoreTPM{pks: pks}
	app := platformSRKApp(t, tpm, false)

	assert.Same(t, tpm, app.getTPM())
	assert.Zero(t, pks.initCalls)
}

// TestApp_GetTPM_InitializedPlatformKeyStoreIsNotReinitialized verifies an
// already initialized platform key store is left alone.
func TestApp_GetTPM_InitializedPlatformKeyStoreIsNotReinitialized(t *testing.T) {
	pks := &fakePlatformKeyStore{initialized: true}
	tpm := &platformStoreTPM{pks: pks}
	app := platformSRKApp(t, tpm, true)

	assert.Same(t, tpm, app.getTPM())
	assert.Zero(t, pks.initCalls)
}

// TestApp_GetTPM_PlatformKeyStoreFailuresKeepTheTPM verifies neither a
// failed auto-init nor an unattachable TPM stops the TPM being served: the
// TPM view and the non-SRK operations still work.
func TestApp_GetTPM_PlatformKeyStoreFailuresKeepTheTPM(t *testing.T) {
	t.Run("auto-init fails", func(t *testing.T) {
		pks := &fakePlatformKeyStore{initErr: errFakePKSInit}
		tpm := &platformStoreTPM{pks: pks}
		app := platformSRKApp(t, tpm, true)

		assert.Same(t, tpm, app.getTPM())
		assert.Equal(t, 1, pks.initCalls)
		assert.False(t, pks.initialized)
		assert.Same(t, tpm, app.tpmInstance)
	})

	t.Run("not attachable", func(t *testing.T) {
		tpm := &platformStoreTPM{}
		app := platformSRKApp(t, tpm, true)

		assert.Same(t, tpm, app.getTPM())
		assert.Same(t, tpm, app.tpmInstance)
	})
}

// TestApp_GetTPM_UnusableDataDirOpensWithoutPersistentStorage verifies a
// data directory the TPM storage cannot be created under does not stop the
// TPM opening: it opens without a key backend.
func TestApp_GetTPM_UnusableDataDirOpensWithoutPersistentStorage(t *testing.T) {
	tpm := &closingTPM{}
	var opened *xkmssdk.TPMParams
	app := &App{log: lifecycleTestLogger(), config: DefaultGUIConfig()}
	app.newTPM = func(params *xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		opened = params
		return tpm, nil
	}
	presentTPMDevice(t, app)
	notADir := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	app.dataDir = notADir

	assert.Same(t, tpm, app.getTPM())
	require.NotNil(t, opened)
	assert.Nil(t, opened.Backend, "no storage factory means no key backend")
	assert.Nil(t, app.tpmStorageFactory)
}
