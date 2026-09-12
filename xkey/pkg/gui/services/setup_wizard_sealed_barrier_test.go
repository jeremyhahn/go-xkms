// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package services

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// TestApplySetupDoesNotFallBackOverAnExistingBarrier covers the gate on the
// wizard's hardware->passphrase fallback (#510).
//
// The fallback exists for a real case: a hardware strategy that cannot
// INITIALIZE a barrier, where nothing is stored yet and retrying under
// passphrase costs nothing. It must not fire for the other case -- a barrier
// that already EXISTS and would not unseal -- because there the retry reaches
// a different strategy than the one the deployment asked for.
//
// The setup makes the consequence visible. A barrier already exists under
// `passphrase`; the wizard is then run asking for `tpm2` with the password
// that DOES open the existing barrier. Without the gate the fallback silently
// unseals it under passphrase, discards the tpm2 failure on the way past
// (result.Errors[:barrierErrCount]), and reports success -- so a deployment
// that asked for hardware sealing gets a software barrier and is told setup
// worked. With the gate the tpm2 failure survives and is reported.
//
// This is the same machinery that produced the reported harm: on the burn-in
// host the second attempt also failed, the run ended with setup_complete
// false, and the next launch re-ran the wizard and minted a NEW User PIN.
func TestApplySetupDoesNotFallBackOverAnExistingBarrier(t *testing.T) {
	const barrierPassword = "correct-horse-battery-staple"

	dir := t.TempDir()

	// A barrier already exists, sealed under passphrase.
	preInit := NewBarrierService(dir, slog.Default())
	require.NoError(t, preInit.Initialize(barrierPassword, "passphrase"))

	cfg := &GUIConfigData{}
	tw := newTestSetupWizard(cfg)
	tw.svc.SetBarrierService(NewBarrierService(dir, slog.Default()))
	tw.svc.initDataDirFunc = func() error { return nil }

	choices := &SetupChoices{
		Mode:              "standalone",
		SOPin:             "so-pin-value",
		UserPin:           barrierPassword,
		SealerBackend:     "tpm2",
		PasswordStoreMode: "none",
	}

	result, err := tw.svc.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.Success,
		"a barrier that exists and would not unseal under the configured strategy is a failed run, "+
			"not a silent downgrade")
	assert.True(t, containsSubstring(result.Errors, "barrier unseal failed"),
		"the real failure must survive rather than being discarded by the fallback, got errors=%v warnings=%v",
		result.Errors, result.Warnings)
	assert.Equal(t, "tpm2", choices.SealerBackend,
		"the configured strategy must not be rewritten to passphrase behind the operator's back")
}

// TestApplyUserOnboardingDoesNotCompleteWithAnUnusableBarrier is the review
// finding on #553: the enterprise onboarding path had the same defect
// ApplySetup did, one step further on.
//
// Every write after step 3 is a completion write — SetupComplete in the GUI
// config and in the unified config, result.SetupComplete, and the
// UserOnboarded event — and they ran unconditionally. So an onboarding run
// whose barrier could not be opened still marked the install complete with its
// encrypted storage unusable. Step 2 has already changed the User PIN by then,
// so the combination strands the new PIN behind a barrier that was never
// opened, and says the setup finished.
func TestApplyUserOnboardingDoesNotCompleteWithAnUnusableBarrier(t *testing.T) {
	const (
		existingBarrierPassword = "the-password-that-opens-it"
		wrongBarrierPassword    = "not-the-password"
	)

	tmpDir := t.TempDir()

	// Enterprise mode: ApplyUserOnboarding refuses to run without it.
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	require.NoError(t, config.WritePolicyHMAC(config.DefaultPolicy(), testSOPin, hmacPath))

	// A barrier already exists — as it would after SO provisioning — and the
	// onboarding run will not have the password that opens it.
	barrierDir := filepath.Join(tmpDir, "barrier")
	preInit := NewBarrierService(barrierDir, slog.Default())
	require.NoError(t, preInit.Initialize(existingBarrierPassword, "passphrase"))

	cfg := &GUIConfigData{}
	tw := newTestSetupWizard(cfg)
	tw.svc.SetPINService(newWizardPINService(&wizardMockPINBackend{
		strategy: qrdbsdk.PINStrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}))
	tw.svc.SetConfigDir(tmpDir)

	barrierSvc := NewBarrierService(barrierDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)

	isolateHome(t)
	require.NoError(t, config.Save(config.DefaultConfig()))

	result, err := tw.svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:           testSOPin,
		UserPIN:         testUserPin,
		BarrierPassword: wrongBarrierPassword,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.SetupComplete,
		"an install whose encrypted storage could not be opened is not a completed setup")
	assert.False(t, result.Success, "the run failed")
	require.NotEmpty(t, result.Errors, "the barrier failure must be reported")

	// The persisted state must agree with the result, or the next launch skips
	// the wizard and the operator can never retry.
	saved := tw.configFunc()
	require.NotNil(t, saved)
	assert.False(t, saved.SetupComplete,
		"SetupComplete must not be persisted for a run that could not open the barrier")

	unified, loadErr := config.Load()
	require.NoError(t, loadErr)
	assert.False(t, unified.State.SetupComplete,
		"the unified config must not record completion either")
}
