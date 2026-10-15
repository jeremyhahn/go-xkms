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

//go:build tpm_simulator

package server

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/pinselect"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tpm2PINConfig is a minimal xkmsd config with the simulator TPM2 backend and
// PIN management on under the given strategy.
func tpm2PINConfig(t *testing.T, strategy string) *config.Config {
	t.Helper()
	cfg := createMinimalConfig(t)
	cfg.Backends.TPM2 = &config.TPM2Config{Enabled: true, UseSimulator: true}
	cfg.PIN = config.PINConfig{Enabled: true, Strategy: strategy}
	cfg.CA = testFirstBootCAConfig()
	return cfg
}

// TestInitializePINManager_TPM2StrategyGovernsWithThePlatformSRK proves
// pin.strategy: tpm2 makes the TPM's Platform SRK the user-PIN store, exactly
// as xKey does: the PIN is the SRK's auth value, verified in hardware, and
// the choice is recorded beside the PIN state so every entry point agrees.
func TestInitializePINManager_TPM2StrategyGovernsWithThePlatformSRK(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := tpm2PINConfig(t, "tpm2")
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	backend := server.PINBackend()
	require.NotNil(t, backend)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, backend.Strategy())

	persisted, err := pinselect.LoadStrategy(filepath.Join(cfg.Datastore.Path, "pin"))
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategyTPM2, persisted)

	// The simulator's Platform SRK is provisioned with an empty auth value;
	// setting the user PIN changes that auth in the TPM.
	require.NoError(t, backend.ChangeUserPIN("", "246810"))
	require.NoError(t, backend.VerifyUserPIN("246810"))
	wrongErr := backend.VerifyUserPIN("135791")
	require.Error(t, wrongErr, "a wrong PIN must be refused by the TPM")
	assert.Contains(t, wrongErr.Error(), "invalid PIN")
}

// TestInitializePINManager_TPM2StrategyWithoutATPMIsRefused proves an
// explicit tpm2 strategy never falls back to software when xkmsd has no TPM.
func TestInitializePINManager_TPM2StrategyWithoutATPMIsRefused(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.PIN = config.PINConfig{Enabled: true, Strategy: "tpm2"}

	_, err := New(cfg)
	var unavailable *pinselect.ProviderUnavailableError
	require.True(t, errors.As(err, &unavailable), "want *pinselect.ProviderUnavailableError, got %v", err)

	_, loadErr := pinselect.LoadStrategy(filepath.Join(cfg.Datastore.Path, "pin"))
	assert.ErrorIs(t, loadErr, pinselect.ErrStrategyNotPersisted, "a refused strategy must not be recorded")
}

// TestInitializePINManager_AutoNeverAdoptsAnUnconfirmedSRK proves auto
// behaves as it does in xKey: a TPM whose Platform SRK auth nobody has
// confirmed is not offered, so auto records software.
func TestInitializePINManager_AutoNeverAdoptsAnUnconfirmedSRK(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := tpm2PINConfig(t, "auto")
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Equal(t, qrdbsdk.PINStrategySoftware, server.PINBackend().Strategy())
	persisted, err := pinselect.LoadStrategy(filepath.Join(cfg.Datastore.Path, "pin"))
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.PINStrategySoftware, persisted)
}

// TestInitializePINManager_StrategyChangeAgainstRecordIsRefused proves an
// operator cannot silently switch a PIN directory from software to tpm2:
// every PIN set under the recorded backend would be orphaned.
func TestInitializePINManager_StrategyChangeAgainstRecordIsRefused(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := tpm2PINConfig(t, "tpm2")
	require.NoError(t, pinselect.SaveStrategy(filepath.Join(cfg.Datastore.Path, "pin"), qrdbsdk.PINStrategySoftware))

	_, err := New(cfg)
	var mismatch *pinselect.StrategyMismatchError
	require.True(t, errors.As(err, &mismatch), "want *pinselect.StrategyMismatchError, got %v", err)
}
