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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
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

	backend, strategy, err := ResolvePINBackend(nil, dataDir, xkms.StorageEngineFile, nil)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, strategy)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, backend.Strategy())

	persisted, err := xkms.LoadPINStrategy(filepath.Join(dataDir, "pin"))
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, persisted)
}

func TestResolvePINBackend_ReadySRKSelectsTPM2(t *testing.T) {
	dataDir := t.TempDir()
	pks := &fakePlatformKeyStorer{initialized: true, authReady: true, provisioned: true}
	accessor := NewTPMAccessor(func() xkms.TrustedPlatformModule {
		return &pinStrategyStubTPM{pks: pks}
	})

	backend, strategy, err := ResolvePINBackend(accessor, dataDir, xkms.StorageEngineFile, nil)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, strategy)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, backend.Strategy())
}

func TestResolvePINBackend_PersistedStrategyGoverns(t *testing.T) {
	dataDir := t.TempDir()
	pinDir := filepath.Join(dataDir, "pin")
	// A previous run opened the PIN store before persisting its strategy
	// beside it, as ResolvePINBackend does.
	store, err := xkms.NewFileStorageBackend(pinDir)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	require.NoError(t, xkms.SavePINStrategy(pinDir, qrdbsdk.PINStrategySoftware))

	backend, strategy, err := ResolvePINBackend(nil, dataDir, xkms.StorageEngineFile, nil)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, strategy)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, backend.Strategy())
}
