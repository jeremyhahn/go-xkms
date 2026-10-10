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

package services

// These tests pin the #290 ruling: a recovery credential must not live
// inside the thing it recovers. The SO PIN resets a forgotten User PIN, and
// the password store is unlocked by the User PIN, so the wizard must never
// write the SO PIN into that store. Quick setup shows the generated SO PIN
// once and refuses to apply until the operator acknowledges recording it.

import (
	"context"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// soPINWizardFixture bundles a wizard wired with a real in-memory password
// store, a software PIN backend and a barrier so that ApplySetup reaches
// Step 8 (the only step that writes to the password store).
type soPINWizardFixture struct {
	tw         *testSetupWizard
	pwSvc      *StaticPasswordService
	pinBackend *wizardMockPINBackend
}

func newSOPINWizardFixture(t *testing.T) *soPINWizardFixture {
	t.Helper()

	memBackend, err := xkms.NewMemoryBackend()
	require.NoError(t, err)
	pwSvc := NewStaticPasswordService(newTestPasswordStore(t, memBackend))

	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	barrierSvc.SetContext(context.Background())

	pinBackend := &wizardMockPINBackend{strategy: qrdbsdk.PINStrategySoftware}

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)
	tw.svc.SetPINService(newWizardPINService(pinBackend))
	tw.svc.SetStaticPasswordService(pwSvc)

	return &soPINWizardFixture{tw: tw, pwSvc: pwSvc, pinBackend: pinBackend}
}

// quickSetupPersonalChoices returns the choices the frontend sends after the
// operator took the Quick Setup path and acknowledged the generated SO PIN.
func quickSetupPersonalChoices() *SetupChoices {
	return &SetupChoices{
		Mode:              "standalone",
		SOPin:             testSOPin,
		UserPin:           testUserPin,
		PasswordStoreMode: "aes_software",
		SealerBackend:     "passphrase",
		StorageType:       "barrier",
		BarrierPassword:   "testbarrier123",
		QuickSetup:        true,
		DeploymentMode:    "personal",
		SOPINRecorded:     true,
	}
}

// assertSOPINAbsentFromStore asserts the SO PIN value is unreachable through
// every read path the password store offers: listing, lookup by the name the
// wizard used to write it, and free-text search over the value itself.
func assertSOPINAbsentFromStore(t *testing.T, pwSvc *StaticPasswordService) {
	t.Helper()

	entries, err := pwSvc.ListPasswords()
	require.NoError(t, err)
	for _, entry := range entries {
		assert.NotEqual(t, "SO PIN", entry.Name,
			"an entry named %q is the #290 defect: the SO PIN was written to the device's own password store", entry.Name)
		assert.NotEqual(t, testSOPin, entry.Password,
			"entry %q holds the SO PIN value; the device must keep no retrievable copy", entry.Name)
	}

	_, err = pwSvc.GetPassword("SO PIN")
	assert.Error(t, err, "looking the SO PIN up by name must fail: nothing was stored under that name")

	hits, err := pwSvc.SearchPasswords(testSOPin)
	require.NoError(t, err)
	assert.Empty(t, hits, "searching the store for the SO PIN value must find nothing")
}

// TestApplySetup_QuickSetupPersonal_NeverStoresSOPIN is the regression test
// for #290. Quick-setup personal mode used to write the SO PIN as a password
// entry; it must now persist only the PIN service's verifier. The User PIN
// entry is the positive control proving Step 8 actually ran.
func TestApplySetup_QuickSetupPersonal_NeverStoresSOPIN(t *testing.T) {
	fx := newSOPINWizardFixture(t)

	result, err := fx.tw.svc.ApplySetup(quickSetupPersonalChoices())
	require.NoError(t, err)
	require.NotNil(t, result)

	// Positive control: the store write step ran, so an absent SO PIN entry
	// is a decision, not a skipped step.
	userEntry, err := fx.pwSvc.GetPassword("User PIN")
	require.NoError(t, err, "Step 8 must still save the auto-generated User PIN; got entries: %v", result.Warnings)
	assert.Equal(t, testUserPin, userEntry.Password)

	assertSOPINAbsentFromStore(t, fx.pwSvc)

	// Only what verification needs survives: the PIN backend holds the SO
	// PIN verifier, so SO-gated operations still authenticate.
	assert.True(t, fx.pinBackend.soPINSet, "the SO PIN verifier must still be established through the PIN service")
	assert.Equal(t, 1, fx.pinBackend.setSOPINCalls)
}

// TestApplySetup_ManualSaveToStore_NeverStoresSOPIN covers the manual-setup
// opt-in. "Save PINs to password store" now saves the User PIN only.
func TestApplySetup_ManualSaveToStore_NeverStoresSOPIN(t *testing.T) {
	fx := newSOPINWizardFixture(t)

	choices := quickSetupPersonalChoices()
	choices.QuickSetup = false
	choices.DeploymentMode = ""
	choices.SOPINRecorded = false
	choices.SavePinsToStore = true

	result, err := fx.tw.svc.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)

	userEntry, err := fx.pwSvc.GetPassword("User PIN")
	require.NoError(t, err, "SavePinsToStore must still save the User PIN")
	assert.Equal(t, testUserPin, userEntry.Password)

	assertSOPINAbsentFromStore(t, fx.pwSvc)
}

// TestApplySetup_QuickSetup_RefusesUnacknowledgedSOPIN is the acknowledgement
// gate: a generated SO PIN is shown once, so setup must not apply until the
// operator confirms it has been recorded out of band. Nothing may be
// persisted or emitted before the refusal.
func TestApplySetup_QuickSetup_RefusesUnacknowledgedSOPIN(t *testing.T) {
	fx := newSOPINWizardFixture(t)

	choices := quickSetupPersonalChoices()
	choices.SOPINRecorded = false

	result, err := fx.tw.svc.ApplySetup(choices)
	require.ErrorIs(t, err, ErrSetupSOPINNotRecorded)
	assert.Nil(t, result)

	assert.Equal(t, 0, fx.pinBackend.setSOPINCalls, "no PIN may be established before the acknowledgement gate passes")
	assert.False(t, fx.tw.configFunc().SetupComplete, "setup must not be marked complete")
	assert.Empty(t, *fx.tw.eventLog, "no progress or completion events may be emitted before the gate")

	entries, err := fx.pwSvc.ListPasswords()
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing may reach the password store before the gate")
}

// TestApplySetup_QuickSetup_AcknowledgedSOPINApplies is the positive side of
// the gate: the same choices with the acknowledgement set proceed.
func TestApplySetup_QuickSetup_AcknowledgedSOPINApplies(t *testing.T) {
	fx := newSOPINWizardFixture(t)

	result, err := fx.tw.svc.ApplySetup(quickSetupPersonalChoices())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, *fx.tw.eventLog, "an acknowledged quick setup must run the apply flow")
}

// TestApplySetup_ManualSetup_NeedsNoSOPINAcknowledgement: the gate is for a
// PIN the operator never typed. Manual setup, where the operator chose and
// confirmed the SO PIN, must not be blocked by the acknowledgement flag.
func TestApplySetup_ManualSetup_NeedsNoSOPINAcknowledgement(t *testing.T) {
	fx := newSOPINWizardFixture(t)

	choices := quickSetupPersonalChoices()
	choices.QuickSetup = false
	choices.SOPINRecorded = false

	result, err := fx.tw.svc.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, fx.pinBackend.setSOPINCalls)
}

// TestApplySetup_SOPINRequiredBeforeAcknowledgementGate orders the checks:
// a missing SO PIN is reported as missing, not as unacknowledged.
func TestApplySetup_SOPINRequiredBeforeAcknowledgementGate(t *testing.T) {
	fx := newSOPINWizardFixture(t)

	choices := quickSetupPersonalChoices()
	choices.SOPin = ""
	choices.SOPINRecorded = false

	_, err := fx.tw.svc.ApplySetup(choices)
	require.ErrorIs(t, err, ErrSetupSOPINRequired)
}
