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

const credentialSourceMasterPassword = "independent-master-password"

// recordedCredentialSource reads the credential source recorded beside the
// barrier in dir.
func recordedCredentialSource(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, barrierCredentialSourceFile))
	require.NoError(t, err, "the barrier's credential source is recorded")
	return string(data)
}

// enterpriseWizard is a setup wizard in enterprise mode over a barrier
// service in barrierDir.
func enterpriseWizard(t *testing.T, barrierDir string) *testSetupWizard {
	t.Helper()
	tmpDir := t.TempDir()
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	require.NoError(t, config.WritePolicyHMAC(config.DefaultPolicy(), testSOPin, hmacPath))

	tw := newTestSetupWizard(&GUIConfigData{})
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
	return tw
}

// Every setup path that creates or reopens the barrier records which
// credential it is sealed under.
func TestSetupPaths_RecordTheBarrierCredentialSource(t *testing.T) {
	t.Run("ApplySetup", func(t *testing.T) {
		for _, tc := range []struct {
			name               string
			useUserPinAsMaster bool
			want               string
		}{
			{name: "independent password", want: barrierCredentialSourceIndependent},
			{name: "user PIN", useUserPinAsMaster: true, want: barrierCredentialSourceUserPIN},
		} {
			t.Run(tc.name, func(t *testing.T) {
				barrierDir := t.TempDir()
				barrierSvc := NewBarrierService(barrierDir, slog.Default())
				barrierSvc.SetContext(context.Background())
				tw := newTestSetupWizard(&GUIConfigData{})
				tw.svc.SetBarrierService(barrierSvc)
				result, err := tw.svc.ApplySetup(&SetupChoices{
					Mode:               "standalone",
					SOPin:              testSOPin,
					UserPin:            testUserPin,
					PasswordStoreMode:  "aes_software",
					SealerBackend:      "passphrase",
					StorageType:        "barrier",
					BarrierPassword:    credentialSourceMasterPassword,
					UseUserPinAsMaster: tc.useUserPinAsMaster,
				})
				require.NoError(t, err)
				require.True(t, result.Success, "setup errors: %v", result.Errors)
				assert.Equal(t, tc.want, recordedCredentialSource(t, barrierDir))
			})
		}
	})

	t.Run("ApplySOProvisioning", func(t *testing.T) {
		// The SO seals the barrier under its own password before the
		// user has a PIN at all.
		barrierDir := t.TempDir()
		tw := enterpriseWizard(t, barrierDir)
		result, err := tw.svc.ApplySOProvisioning(&SetupChoices{
			Mode:            "standalone",
			SOPin:           testSOPin,
			StorageType:     "barrier",
			SealerBackend:   "passphrase",
			BarrierPassword: credentialSourceMasterPassword,
		})
		require.NoError(t, err)
		require.True(t, result.Success, "SO provisioning errors: %v", result.Errors)
		assert.Equal(t, barrierCredentialSourceIndependent, recordedCredentialSource(t, barrierDir))
	})

	t.Run("ApplyUserOnboarding", func(t *testing.T) {
		for _, tc := range []struct {
			name            string
			existing        string
			barrierPassword string
			want            string
		}{
			// The barrier the SO provisioned, reopened under its password.
			{name: "independent password", existing: credentialSourceMasterPassword, barrierPassword: credentialSourceMasterPassword, want: barrierCredentialSourceIndependent},
			// No barrier yet: onboarding creates it under the user PIN.
			{name: "user PIN", want: barrierCredentialSourceUserPIN},
		} {
			t.Run(tc.name, func(t *testing.T) {
				barrierDir := t.TempDir()
				if tc.existing != "" {
					provisioned := NewBarrierService(barrierDir, slog.Default())
					require.NoError(t, provisioned.Initialize(tc.existing, "passphrase"))
					require.NoError(t, provisioned.Seal())
				}
				tw := enterpriseWizard(t, barrierDir)
				result, err := tw.svc.ApplyUserOnboarding(&UserOnboardingChoices{
					SOPIN:           testSOPin,
					UserPIN:         testUserPin,
					BarrierPassword: tc.barrierPassword,
				})
				require.NoError(t, err)
				require.True(t, result.SetupComplete, "onboarding errors: %v", result.Errors)
				assert.Equal(t, tc.want, recordedCredentialSource(t, barrierDir))
			})
		}
	})
}

// An install from before the credential source was recorded has no record.
// A user PIN change settles it from the barrier itself: the current PIN
// opens a PIN-bound barrier, which is rewrapped, and does not open one under
// an independent password, which is left under that password.
func TestPINService_ChangeUserPIN_PreUpgradeInstallWithoutRecordedSource(t *testing.T) {
	const newPIN = "112233"
	for _, tc := range []struct {
		name           string
		credential     string
		afterChange    string
		notAfterChange string
		recorded       string
	}{
		{name: "independent password", credential: credentialSourceMasterPassword, afterChange: credentialSourceMasterPassword, notAfterChange: newPIN, recorded: barrierCredentialSourceIndependent},
		{name: "user PIN", credential: testUserPin, afterChange: newPIN, notAfterChange: testUserPin, recorded: barrierCredentialSourceUserPIN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			barrierDir := t.TempDir()
			installed := NewBarrierService(barrierDir, slog.Default())
			require.NoError(t, installed.Initialize(tc.credential, "passphrase"))
			require.NoError(t, installed.Seal())
			_, err := os.Stat(filepath.Join(barrierDir, barrierCredentialSourceFile))
			require.ErrorIs(t, err, os.ErrNotExist, "a pre-upgrade install records no credential source")

			restarted := NewBarrierService(barrierDir, slog.Default())
			require.NoError(t, restarted.Unseal(tc.credential, "passphrase"))
			backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware, userPINSet: true}
			svc := newTestPINService(backend)
			svc.SetBarrierService(restarted)

			require.NoError(t, svc.ChangeUserPIN(testUserPin, newPIN))
			assert.Equal(t, int32(1), backend.changeUserCalls.Load())
			assert.Equal(t, tc.recorded, recordedCredentialSource(t, barrierDir))

			require.NoError(t, restarted.Seal())
			reopened := NewBarrierService(barrierDir, slog.Default())
			require.Error(t, reopened.Unseal(tc.notAfterChange, "passphrase"))
			require.NoError(t, reopened.Unseal(tc.afterChange, "passphrase"))
		})
	}
}

// A barrier recorded as PIN-bound that the current PIN does not open cannot
// be rewrapped: the PIN change is refused before the PIN backend commits
// it, so the PIN and the barrier never fall out of step.
func TestPINService_ChangeUserPIN_PINBoundBarrierTheCurrentPINDoesNotOpenIsRefusedBeforeThePINChanges(t *testing.T) {
	const newPIN = "112233"
	barrierDir := t.TempDir()
	barrierSvc := NewBarrierService(barrierDir, slog.Default())
	require.NoError(t, barrierSvc.Initialize(credentialSourceMasterPassword, "passphrase"))
	require.NoError(t, barrierSvc.recordCredentialSource(false))
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware, userPINSet: true}
	svc := newTestPINService(backend)
	svc.SetBarrierService(barrierSvc)

	err := svc.ChangeUserPIN(testUserPin, newPIN)
	require.ErrorIs(t, err, ErrBarrierResealFailed)
	assert.Equal(t, int32(0), backend.changeUserCalls.Load(), "the PIN backend never commits a change the barrier cannot follow")

	require.NoError(t, barrierSvc.Seal())
	reopened := NewBarrierService(barrierDir, slog.Default())
	require.NoError(t, reopened.Unseal(credentialSourceMasterPassword, "passphrase"), "the barrier is left under its credential")
}

// A barrier that is not initialized cannot follow a PIN change either; the
// change is refused before the PIN backend commits it.
func TestPINService_ChangeUserPIN_UninitializedBarrierIsRefusedBeforeThePINChanges(t *testing.T) {
	backend := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware, userPINSet: true}
	svc := newTestPINService(backend)
	svc.SetBarrierService(NewBarrierService(t.TempDir(), slog.Default()))

	err := svc.ChangeUserPIN("old-pin", "new-pin")
	require.ErrorIs(t, err, ErrBarrierResealFailed)
	assert.Equal(t, int32(0), backend.changeUserCalls.Load())
}
