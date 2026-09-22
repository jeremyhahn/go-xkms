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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pinstrategy"
)

// This file tests the go-xkms#307 fix at the `xkey pin` command boundary:
// the persisted, governing PIN strategy resolves through the same shared
// pinstrategy package the GUI and daemon use, and a governing strategy
// that needs an unavailable provider is refused rather than silently
// answered from the software store.

func TestRunPINStatus_NamesGoverningStrategy(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	// No TPM is reachable in the test environment, so the fresh-install
	// auto-selection falls through to software, and `pin status` must
	// name exactly that governing strategy.
	out, err := runPINCmd(t, runPINStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Strategy:         software")
}

func TestRunPINSetSO_PersistsTheAutoSelectedStrategy(t *testing.T) {
	dataDir := isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	persisted, err := pinstrategy.Load(pinStateDir(dataDir))
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, persisted)
}

func TestRunPINVerify_RefusesWhenGoverningTPM2StrategyIsUnavailable(t *testing.T) {
	dataDir := isolatePIN(t)

	// Establish PIN state the ordinary way (software, the only backend
	// reachable in the test environment)...
	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)
	pipePIN(t, "so-pin-one", "user-pin-1", "user-pin-1")
	_, err = runPINCmd(t, runPINSetUser)
	require.NoError(t, err)

	// ...then simulate a device whose governing strategy is tpm2 (as the
	// GUI's wizard would have persisted after enrolling a Platform SRK),
	// with no TPM reachable from this process.
	require.NoError(t, pinstrategy.Save(pinStateDir(dataDir), qrdbsdk.PINStrategyTPM2))

	pinVerifyType = "user"
	pipePIN(t, "user-pin-1")
	out, err := runPINCmd(t, runPINVerify)

	// The governing strategy is unavailable: verify must refuse with a
	// typed error, never answer VALID from the software store it can
	// still open underneath.
	require.Error(t, err)
	var unavailable *pinstrategy.ProviderUnavailableError
	assert.True(t, errors.As(err, &unavailable), "expected a wrapped *pinstrategy.ProviderUnavailableError, got %T: %v", err, err)
	assert.NotContains(t, out, "VALID")
}

func TestRunPINStatus_RefusesWhenGoverningTPM2StrategyIsUnavailable(t *testing.T) {
	dataDir := isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	require.NoError(t, pinstrategy.Save(pinStateDir(dataDir), qrdbsdk.PINStrategyTPM2))

	_, err = runPINCmd(t, runPINStatus)
	require.Error(t, err)
	var unavailable *pinstrategy.ProviderUnavailableError
	assert.True(t, errors.As(err, &unavailable), "expected a wrapped *pinstrategy.ProviderUnavailableError, got %T: %v", err, err)
}

func TestRunPINSetUser_PersistedSoftwareStrategyGovernsEvenWithPreferredHardwarePreference(t *testing.T) {
	dataDir := isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	// Once a strategy is persisted, later commands must not silently
	// re-probe and switch strategies out from under an established store.
	persisted, err := pinstrategy.Load(pinStateDir(dataDir))
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, persisted)

	pipePIN(t, "so-pin-one", "user-pin-1", "user-pin-1")
	_, err = runPINCmd(t, runPINSetUser)
	require.NoError(t, err)

	persistedAfter, err := pinstrategy.Load(pinStateDir(dataDir))
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, persistedAfter)
}
