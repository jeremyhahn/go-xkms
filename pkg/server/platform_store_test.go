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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// platformStoreTestConfig returns a minimal, valid config for exercising
// initializePlatformStore directly against newMinimalServer: an in-memory
// storage backend (fast, no filesystem) and the given credential strategy.
func platformStoreTestConfig(strategy string) *config.Config {
	return &config.Config{
		Datastore:   config.DatastoreConfig{Engine: "memory"},
		Credentials: config.CredentialsConfig{SealStrategy: strategy},
	}
}

// ============================================================================
// Tests — initializePlatformStore: skip strategies
// ============================================================================

func TestInitializePlatformStore_ManualSkips(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("manual"))

	require.NoError(t, s.initializePlatformStore())
	assert.Nil(t, s.platformStore, "manual never uses the platform store")
}

func TestInitializePlatformStore_EmptyStrategyDefaultsToManualAndSkips(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig(""))

	require.NoError(t, s.initializePlatformStore())
	assert.Nil(t, s.platformStore, "empty strategy defaults to manual and skips")
}

func TestInitializePlatformStore_BarrierSkips(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("barrier"))

	require.NoError(t, s.initializePlatformStore())
	assert.Nil(t, s.platformStore, "the barrier strategy stores directly in s.barrier, never the platform store")
}

// ============================================================================
// Tests — initializePlatformStore: fails closed, never a silent skip
// ============================================================================

func TestInitializePlatformStore_UnknownStrategyFailsClosed(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("bogus-strategy"))

	err := s.initializePlatformStore()
	require.Error(t, err)
	assert.Nil(t, s.platformStore)

	var buildErr *ErrPlatformStoreBuild
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, "bogus-strategy", buildErr.Strategy)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
}

// TestInitializePlatformStore_PassphraseFailsClosed is the regression test
// for the owner ruling on go-xkms#718: a previous version of this code
// derived the passphrase strategy's seal key from a random secret persisted
// UNSEALED next to the data it protected, which is not sealing. Until the
// owner rules on where an operator passphrase actually comes from
// (CredentialsConfig has no field for one today), the strategy must fail
// closed with a typed error rather than fabricate a root of trust.
func TestInitializePlatformStore_PassphraseFailsClosed(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("passphrase"))

	err := s.initializePlatformStore()
	require.Error(t, err)
	assert.Nil(t, s.platformStore)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "passphrase", unavailableErr.Strategy)
}

func TestInitializePlatformStore_PKCS11StrategyFailsClosed(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("pkcs11"))

	err := s.initializePlatformStore()
	require.Error(t, err, "pkcs11 needs a PIN this phase of startup cannot resolve (go-xkms#677); it must fail, not skip silently")
	assert.Nil(t, s.platformStore)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "pkcs11", unavailableErr.Strategy)
}

func TestInitializePlatformStore_VaultStrategyFailsClosed(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("vault"))

	err := s.initializePlatformStore()
	require.Error(t, err)
	assert.Nil(t, s.platformStore)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "vault", unavailableErr.Strategy)
}

func TestInitializePlatformStore_TPM2NotConfiguredFailsClosed(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("tpm2"))
	// Backends.TPM2 left nil: no TPM configured at all.

	err := s.initializePlatformStore()
	require.Error(t, err)
	assert.Nil(t, s.platformStore)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "tpm2", unavailableErr.Strategy)
}

// TestInitializePlatformStore_TPM2WithoutEnrolledPSRKFailsClosed moved to
// platform_store_no_simulator_test.go (build tag !tpm_simulator): see that
// file's doc comment for why it cannot live in a file built with
// tpm_simulator.

// ============================================================================
// Tests — credential service integration through the platform store
// ============================================================================

// TestInitializeCredentialService_PlatformStrategyWithoutPlatformStoreFails
// is the regression test for go-xkms#718: before this change,
// initializePlatformStore never assigned s.platformStore, so every
// credentials.seal_strategy other than manual/barrier made
// credentials.New return ErrNilPlatformStore. This proves the failure mode
// credentialspkg.New itself still enforces when platformStore is genuinely
// absent (e.g. a caller that skips initializePlatformStore). "passphrase" is
// used here purely as a valid credentialspkg strategy NAME; this test never
// calls initializePlatformStore, so it is unaffected by that strategy
// failing closed at the platform-store layer.
func TestInitializeCredentialService_PlatformStrategyWithoutPlatformStoreFails(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("passphrase"))
	// Deliberately do not call initializePlatformStore: s.platformStore stays nil.

	err := s.initializeCredentialService()
	require.Error(t, err)
	assert.ErrorIs(t, err, credentialspkg.ErrNilPlatformStore)
}

// ============================================================================
// Tests — Server.New end-to-end boot with a non-manual credential strategy
// ============================================================================

// TestServerNew_UnavailableStrategyAbortsStartup proves a chosen strategy
// this phase cannot build a sealer for fails Server.New closed rather than
// booting with a half-configured credential subsystem.
func TestServerNew_UnavailableStrategyAbortsStartup(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Credentials = config.CredentialsConfig{SealStrategy: "pkcs11"}

	s, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, s)

	var svcErr *ErrServiceInit
	require.ErrorAs(t, err, &svcErr)
	assert.Equal(t, "platform store", svcErr.Service)
}

// ============================================================================
// Tests — buildPlatformSealer dispatch (unit-level)
// ============================================================================

func TestBuildPlatformSealer_UnknownStrategy(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("bogus"))

	sealer, err := s.buildPlatformSealer("bogus")
	require.Error(t, err)
	assert.Nil(t, sealer)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "bogus", unavailableErr.Strategy)
}
