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

package services

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pinstrategy"
)

// fakePlatformKeyStorer is a minimal xkms.PlatformKeyStorer for
// ResolvePINBackend tests.
type fakePlatformKeyStorer struct {
	initialized bool
	authReady   bool
	provisioned bool
}

func (f *fakePlatformKeyStorer) SRKAttributes() *xkms.KeyAttributes          { return nil }
func (f *fakePlatformKeyStorer) Backend() xkms.TPMKeyBackend                 { return nil }
func (f *fakePlatformKeyStorer) Initialize(string, string) error             { return nil }
func (f *fakePlatformKeyStorer) EnrollPlatformSRK(string, string) error      { return nil }
func (f *fakePlatformKeyStorer) InitializeWithDefaults() error               { return nil }
func (f *fakePlatformKeyStorer) IsInitialized() bool                         { return f.initialized }
func (f *fakePlatformKeyStorer) PINBackend() qrdbsdk.PINBackend              { return nil }
func (f *fakePlatformKeyStorer) PlatformPolicyEnabled() bool                 { return false }
func (f *fakePlatformKeyStorer) VerifyAuth(string) error                     { return nil }
func (f *fakePlatformKeyStorer) ChangeAuth(string, string) error             { return nil }
func (f *fakePlatformKeyStorer) GetLockoutInfo() (int, int, int, int, error) { return 0, 0, 0, 0, nil }
func (f *fakePlatformKeyStorer) DictionaryAttackLockoutReset([]byte) error   { return nil }
func (f *fakePlatformKeyStorer) IsProvisioned() bool                         { return f.provisioned }
func (f *fakePlatformKeyStorer) IsAuthReady() bool                           { return f.authReady }
func (f *fakePlatformKeyStorer) SetAuthReady(ready bool)                     { f.authReady = ready }

var _ xkms.PlatformKeyStorer = (*fakePlatformKeyStorer)(nil)

// pinStrategyStubTPM is a minimal TrustedPlatformModule stand-in whose
// PlatformKeyStore() is overridden; every other method panics if called
// (ResolvePINBackend never needs them).
type pinStrategyStubTPM struct {
	xkms.TrustedPlatformModule
	pks xkms.PlatformKeyStorer
}

func (t *pinStrategyStubTPM) PlatformKeyStore() xkms.PlatformKeyStorer { return t.pks }

func TestResolvePINBackend_FreshDataDirWithNoTPMAccessorSelectsSoftware(t *testing.T) {
	dataDir := t.TempDir()

	backend, strategy, err := ResolvePINBackend(nil, dataDir, "", xkms.StorageEngineFile, nil)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, strategy)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, backend.Strategy())

	persisted, err := pinstrategy.Load(filepath.Join(dataDir, "pin"))
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, persisted)
}

func TestResolvePINBackend_ReadySRKSelectsTPM2(t *testing.T) {
	dataDir := t.TempDir()
	pks := &fakePlatformKeyStorer{initialized: true, authReady: true, provisioned: true}
	accessor := NewTPMAccessor(func() xkms.TrustedPlatformModule {
		return &pinStrategyStubTPM{pks: pks}
	})

	backend, strategy, err := ResolvePINBackend(accessor, dataDir, "", xkms.StorageEngineFile, nil)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, strategy)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, backend.Strategy())
}

func TestResolvePINBackend_MigratesLegacyGUIStrategyBeforeResolving(t *testing.T) {
	dataDir := t.TempDir()

	// The legacy GUIConfig field says tpm2 (an install that predates the
	// shared strategy file), but no TPM is reachable from this process:
	// the migration must still record tpm2 as governing, and Resolve must
	// then refuse rather than silently answering from software.
	_, _, err := ResolvePINBackend(nil, dataDir, string(qrdbsdk.PINStrategyTPM2), xkms.StorageEngineFile, nil)

	var unavailable *pinstrategy.ProviderUnavailableError
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, unavailable.Strategy)

	persisted, loadErr := pinstrategy.Load(filepath.Join(dataDir, "pin"))
	require.NoError(t, loadErr)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, persisted, "the legacy strategy must have been migrated into the shared file")
}

func TestResolvePINBackend_PersistedStrategyGovernsOverStaleLegacyField(t *testing.T) {
	dataDir := t.TempDir()
	pinDir := filepath.Join(dataDir, "pin")
	require.NoError(t, pinstrategy.Save(pinDir, qrdbsdk.PINStrategySoftware))

	// A stale legacy field claiming tpm2 must not override an
	// already-persisted software strategy.
	backend, strategy, err := ResolvePINBackend(nil, dataDir, "tpm2", xkms.StorageEngineFile, nil)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, strategy)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, backend.Strategy())
}

func TestMigrateLegacyPINStrategy_EmptyLegacyIsNoop(t *testing.T) {
	migrated, err := migrateLegacyPINStrategy(filepath.Join(t.TempDir(), "pin"), "")
	require.NoError(t, err)
	assert.False(t, migrated)
}

func TestMigrateLegacyPINStrategy_AlreadyPersistedIsNoop(t *testing.T) {
	pinDir := filepath.Join(t.TempDir(), "pin")
	require.NoError(t, pinstrategy.Save(pinDir, qrdbsdk.PINStrategySoftware))

	migrated, err := migrateLegacyPINStrategy(pinDir, "tpm2")
	require.NoError(t, err)
	assert.False(t, migrated)

	persisted, loadErr := pinstrategy.Load(pinDir)
	require.NoError(t, loadErr)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, persisted, "an existing record must not be overwritten by the legacy field")
}

func TestMigrateLegacyPINStrategy_MigratesWhenUnpersisted(t *testing.T) {
	pinDir := filepath.Join(t.TempDir(), "pin")

	migrated, err := migrateLegacyPINStrategy(pinDir, "tpm2")
	require.NoError(t, err)
	assert.True(t, migrated)

	persisted, loadErr := pinstrategy.Load(pinDir)
	require.NoError(t, loadErr)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, persisted)
}

func TestMigrateLegacyPINStrategy_LoadFailurePropagates(t *testing.T) {
	pinDir := t.TempDir()
	// A directory at the strategy file's own path makes os.ReadFile fail
	// with something other than "not exist", exercising the propagation
	// branch rather than the ordinary "nothing persisted yet" one.
	require.NoError(t, os.MkdirAll(filepath.Join(pinDir, "strategy"), 0700))

	_, err := migrateLegacyPINStrategy(pinDir, "tpm2")
	var loadErr *pinstrategy.LoadError
	assert.True(t, errors.As(err, &loadErr), "expected *pinstrategy.LoadError, got %T: %v", err, err)
}
