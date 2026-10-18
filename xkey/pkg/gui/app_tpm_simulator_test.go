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

package gui

// These tests open the in-process TPM 2.0 simulator, which is linked in only
// by the tpm_simulator build tag.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/xkmstest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// provisionedSimulatorTPM opens the in-process TPM simulator through the
// constructor getTPM uses, then provisions it with the default key templates
// and enrolls the Platform SRK.
func provisionedSimulatorTPM(params *xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
	cfg := xkmssdk.DefaultTPMConfig
	cfg.UseSimulator = true
	params.Config = &cfg
	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil && !errors.Is(err, xkmssdk.ErrTPMNotInitialized) {
		return nil, err
	}
	if err := tpm.Provision(nil); err != nil {
		return nil, errors.Join(err, tpm.Close())
	}
	if err := xkmstest.EnrollPlatformSRK(tpm, &cfg); err != nil {
		return nil, errors.Join(err, tpm.Close())
	}
	return tpm, nil
}

func TestApp_EnsureLocalTPMPolicies_OpensServiceAndShutdownDetachesIt(t *testing.T) {
	app := fakeTPMApp(t, nil)
	app.newTPM = provisionedSimulatorTPM

	app.ensureLocalTPMPolicies()

	local := app.tpmPolicyService.Local()
	require.NotNil(t, local, "a TPM with a Platform SRK and an open data directory must hold TPM policies")
	status, err := app.barrierAutoUnsealService.GetAutoUnsealStatus()
	require.NoError(t, err)
	assert.True(t, status.Available, "barrier auto-unseal must reach the same local policy service")

	app.ensureLocalTPMPolicies()
	assert.Same(t, local, app.tpmPolicyService.Local(), "an open service must not be reopened")

	app.shutdown(app.ctx)

	assert.Nil(t, app.tpmPolicyService.Local(), "shutdown must detach the local policy service before closing its TPM")
	status, err = app.barrierAutoUnsealService.GetAutoUnsealStatus()
	require.NoError(t, err)
	assert.False(t, status.Available, "auto-unseal must not keep a closed policy service")
}

// A returning user's tpm2 barrier with auto-unseal enabled opens at startup
// without a password: no TPM auto-unseal policy blob exists, so startup falls
// back to unsealing the barrier with its TPM-sealed key, unlocks the app and
// tells the frontend the barrier is open.
func TestApp_StartupReturningUser_TPM2BarrierAutoUnseals(t *testing.T) {
	app := fakeTPMApp(t, nil)
	app.newTPM = provisionedSimulatorTPM
	window := &recordingWindow{}
	app.ui = window
	app.ctx = t.Context()
	app.config.StorageType = "barrier"
	app.config.BarrierInitialized = true
	app.config.BarrierStrategy = string(xkmssdk.StrategyTPM2)
	app.config.BarrierAutoUnsealEnabled = true
	require.NoError(t, app.barrierService.Initialize("", string(xkmssdk.StrategyTPM2)))
	require.NoError(t, app.barrierService.Seal())
	t.Cleanup(func() { app.shutdown(app.ctx) })

	app.startupReturningUser(app.ctx)

	assert.True(t, app.barrierService.IsUnsealed(), "a tpm2 barrier must auto-unseal with its TPM-sealed key")
	assert.Contains(t, window.Events(), string(events.EventBarrierUnlocked))
	assert.NotContains(t, window.Events(), string(events.EventBarrierLocked))
	assert.False(t, app.appLockService.IsLocked(), "an auto-unsealed barrier must unlock the app")
}

// The setup wizard's environment probe reports the TPM NewApp wires into it:
// a provisioned TPM is both present and available.
func TestApp_SetupWizardProbe_ReportsTheAppTPM(t *testing.T) {
	app := fakeTPMApp(t, nil)
	app.newTPM = provisionedSimulatorTPM
	t.Cleanup(func() { app.shutdown(t.Context()) })

	probe, err := app.setupWizardService.ProbeEnvironment()

	require.NoError(t, err)
	assert.True(t, probe.TPMDeviceExists, "the wizard must see the app's TPM device")
	assert.True(t, probe.TPMAvailable, "the wizard must see the app's TPM as usable")
	assert.Empty(t, probe.TPMInitError)
}

// TestApp_GetTPM_UnprovisionedTPMIsCached verifies that a TPM which answers
// but has no persistent EK yet is still surfaced (and cached with its
// storage factory) so the TPM view can show real device values before
// provisioning.
func TestApp_GetTPM_UnprovisionedTPMIsCached(t *testing.T) {
	cfg := xkmssdk.DefaultTPMConfig
	cfg.UseSimulator = true
	cfg.Device = t.TempDir() // present for the existence probe; the simulator serves the commands

	app := &App{log: lifecycleTestLogger(), newTPM: xkmssdk.NewTPM2, dataDir: t.TempDir()}
	presetTPMConfig(app, cfg)

	tpm := app.getTPM()
	require.NotNil(t, tpm, "a fresh simulator has no EK but must still be returned")
	t.Cleanup(func() {
		assert.NoError(t, tpm.Close())
		assert.NoError(t, app.tpmStorageFactory.Close())
	})

	assert.Same(t, tpm, app.tpmInstance)
	assert.NotNil(t, app.tpmStorageFactory, "the storage factory stays open with the cached TPM")
	assert.Same(t, tpm, app.getTPM(), "later calls return the cached TPM without re-opening")
}

// TestApp_InitializeAuthenticator_OffersTheTPM2BackendToFIDO2 verifies a
// registered xkms tpm2 backend becomes a FIDO2 key backend, so credentials
// can be created on the TPM.
func TestApp_InitializeAuthenticator_OffersTheTPM2BackendToFIDO2(t *testing.T) {
	app, _ := tpm2SimKeyStoreApp(t)
	app.fido2Storage = newMemoryFIDO2Storage(t, xkmssdk.NewStorageMemory())

	app.initializeAuthenticator()

	require.NotNil(t, app.authenticatorInstance)
	assert.Contains(t, app.fido2KeyBackend.Backends(), xkmssdk.BackendTypeTPM2)
}

// A cloud KMS backend that is configured (registered under its xkms name) is
// offered to FIDO2 under its own backend type; one that is not configured is
// skipped.
func TestApp_InitializeAuthenticator_OffersConfiguredCloudBackendsToFIDO2(t *testing.T) {
	app, _ := tpm2SimKeyStoreApp(t)
	app.fido2Storage = newMemoryFIDO2Storage(t, xkmssdk.NewStorageMemory())

	tpm2Backend, err := xkmssdk.GetBackend("tpm2")
	require.NoError(t, err)
	require.NoError(t, xkmssdk.RegisterServiceBackend("gcpkms", tpm2Backend))
	t.Cleanup(func() { xkmssdk.UnregisterBackend("gcpkms") })

	app.initializeAuthenticator()

	require.NotNil(t, app.authenticatorInstance)
	backends := app.fido2KeyBackend.Backends()
	assert.Contains(t, backends, xkmssdk.BackendTypeGCPKMS)
	assert.NotContains(t, backends, xkmssdk.BackendTypeAWSKMS, "an unconfigured cloud backend must not be offered")
	assert.NotContains(t, backends, xkmssdk.BackendTypeAzureKV, "an unconfigured cloud backend must not be offered")
}
