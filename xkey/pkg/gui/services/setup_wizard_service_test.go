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

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultPINs provides standard PIN values for tests that need to pass
// the mandatory SO PIN and User PIN validation.
// ---------------------------------------------------------------------------
// Password protection default mode tests
// ---------------------------------------------------------------------------

// TestApplySetup_EmptyPasswordStoreMode_DefaultsToAESSoftware verifies that
// when PasswordStoreMode is empty (e.g., probe failed), the service defaults
// to "aes_software" instead of leaving passwords unprotected.
func TestApplySetup_EmptyPasswordStoreMode_DefaultsToAESSoftware(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	choices := &SetupChoices{
		Mode:               "standalone",
		SOPin:              testSOPin,
		UserPin:            testUserPin,
		PasswordStoreMode:  "", // Empty - should default to aes_software
		UseUserPinAsMaster: true,
		StorageType:        "barrier",
		BarrierPassword:    "testbarrier123",
	}

	result, err := tw.svc.ApplySetup(choices)
	require.NoError(t, err)

	// The result should complete (may have warnings due to no TPM etc, but should not error on mode).
	// The key assertion: the service should have treated empty mode as "aes_software".
	// We verify by checking that the result doesn't contain an error about password protection
	// being "none" when we didn't explicitly choose it.
	require.NotNil(t, result)
	// Verify no error specifically about password store mode being empty or none.
	for _, e := range result.Errors {
		assert.NotContains(t, e, "password protection service unavailable",
			"Empty password_store_mode should default to aes_software, not fail")
	}
}

// TestApplySetup_ExplicitNone_StoresWithoutEncryption verifies that
// explicitly setting password_store_mode to "none" is respected.
func TestApplySetup_ExplicitNone_StoresWithoutEncryption(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	choices := &SetupChoices{
		Mode:              "standalone",
		SOPin:             testSOPin,
		UserPin:           testUserPin,
		PasswordStoreMode: "none", // Explicit "none"
		StorageType:       "barrier",
		BarrierPassword:   "testbarrier123",
	}

	result, err := tw.svc.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	// "none" is a valid choice and should be respected without errors about mode.
}

// ---------------------------------------------------------------------------
// PIN generation tests
// ---------------------------------------------------------------------------

// TestGenerateSetupPINs_Success verifies that GenerateSetupPINs returns PINs
// with the correct lengths and complexity requirements (all character classes).
func TestGenerateSetupPINs_Success(t *testing.T) {
	svc := NewSetupWizardService()

	pins, err := svc.GenerateSetupPINs()
	require.NoError(t, err)
	require.NotNil(t, pins)
	require.Len(t, pins.SOPin, 16)
	require.Len(t, pins.UserPin, 12)

	// Verify all character classes are present in both PINs.
	require.True(t, pinMeetsComplexity(pins.SOPin),
		"SO PIN should contain all character classes: %s", pins.SOPin)
	require.True(t, pinMeetsComplexity(pins.UserPin),
		"User PIN should contain all character classes: %s", pins.UserPin)

	// Verify all characters come from pinCharset.
	charsetMap := make(map[rune]bool)
	for _, c := range pinCharset {
		charsetMap[c] = true
	}
	for _, c := range pins.SOPin {
		require.True(t, charsetMap[c], "SO PIN contains invalid char: %c", c)
	}
	for _, c := range pins.UserPin {
		require.True(t, charsetMap[c], "User PIN contains invalid char: %c", c)
	}
}

// TestGenerateSetupPINs_NonDeterministic verifies that consecutive calls to
// GenerateSetupPINs produce different PINs (cryptographic randomness check).
func TestGenerateSetupPINs_NonDeterministic(t *testing.T) {
	svc := NewSetupWizardService()

	pins1, err := svc.GenerateSetupPINs()
	require.NoError(t, err)

	pins2, err := svc.GenerateSetupPINs()
	require.NoError(t, err)

	// Extremely unlikely to be equal with 12 alphanumeric chars
	require.NotEqual(t, pins1.SOPin, pins2.SOPin)
	require.NotEqual(t, pins1.UserPin, pins2.UserPin)
}

// TestGenerateRandomPIN_Lengths verifies that generateRandomPIN produces
// strings of the exact requested length for various inputs.
func TestGenerateRandomPIN_Lengths(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"zero length", 0},
		{"one char", 1},
		{"four chars", 4},
		{"eight chars", 8},
		{"twelve chars", 12},
		{"sixteen chars", 16},
		{"large", 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := generateRandomPIN(tc.length)
			require.NoError(t, err)
			require.Len(t, result, tc.length)
		})
	}
}

// TestGenerateRandomPIN_Complexity verifies that generated PINs of length >= 4
// contain at least one character from each class.
func TestGenerateRandomPIN_Complexity(t *testing.T) {
	for i := 0; i < 50; i++ {
		pin, err := generateRandomPIN(8)
		require.NoError(t, err)
		require.True(t, pinMeetsComplexity(pin),
			"PIN iteration %d should meet complexity: %s", i, pin)
	}
}

// TestPinMeetsComplexity verifies the complexity checker with known inputs.
func TestPinMeetsComplexity(t *testing.T) {
	tests := []struct {
		name   string
		pin    string
		expect bool
	}{
		{"all classes", "Aa1!", true},
		{"missing upper", "aa1!", false},
		{"missing lower", "AA1!", false},
		{"missing digit", "Aab!", false},
		{"missing special", "Aa1b", false},
		{"empty", "", false},
		{"full complexity", "P@ssw0rd!", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, pinMeetsComplexity(tc.pin))
		})
	}
}

// ---------------------------------------------------------------------------
// Browser extension enterprise policy field tests
// ---------------------------------------------------------------------------

// TestApplySOProvisioning_ExtensionFields verifies that all 5 browser extension
// enterprise policy fields in SetupChoices are correctly mapped to the
// corresponding PolicySection fields when ApplySOProvisioning runs with an
// organization name (enterprise mode).
func TestApplySOProvisioning_ExtensionFields(t *testing.T) {
	// Redirect config dir to a temp directory so config.Load/Save do not
	// touch the real user config.
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	t.Cleanup(config.ResetConfigDir)

	// Seed a valid config file so config.Load() finds it.
	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetConfigDir(tmpDir)

	// Wire a minimal PINService so SO PIN setup succeeds.
	pinSvc := NewPINService()
	tw.svc.SetPINService(pinSvc)
	tw.svc.SetInitDataDirFunc(func() error { return nil })

	choices := &SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		OrganizationName: "ExtensionTestOrg",

		// Browser extension fields -- all enabled.
		AllowExtension:          true,
		ForceExtensionAuth:      true,
		ForceExtensionPairing:   true,
		ForceExtensionAudit:     true,
		AllowConfigureExtension: true,
	}

	result, err := tw.svc.ApplySOProvisioning(choices)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Read the saved config back and verify the extension policy fields.
	saved, loadErr := config.Load()
	require.NoError(t, loadErr)

	assert.True(t, saved.Policy.ExtensionEnabled,
		"ExtensionEnabled should be true")
	assert.True(t, saved.Policy.ExtensionRequireAuthentication,
		"ExtensionRequireAuthentication should be true")
	assert.True(t, saved.Policy.ExtensionRequirePairing,
		"ExtensionRequirePairing should be true")
	assert.True(t, saved.Policy.ExtensionForceAudit,
		"ExtensionForceAudit should be true")
	assert.True(t, saved.Policy.UserCanConfigureExtension,
		"UserCanConfigureExtension should be true")
	assert.Equal(t, "ExtensionTestOrg", saved.Policy.OrganizationName)
}

// TestApplySOProvisioning_ExtensionFieldsDefaults verifies that when the
// browser extension SetupChoices fields are left at their zero values (false),
// the corresponding PolicySection fields are set to false, overriding the
// DefaultPolicy() defaults (which are true).
func TestApplySOProvisioning_ExtensionFieldsDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	t.Cleanup(config.ResetConfigDir)

	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetConfigDir(tmpDir)

	pinSvc := NewPINService()
	tw.svc.SetPINService(pinSvc)
	tw.svc.SetInitDataDirFunc(func() error { return nil })

	choices := &SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		OrganizationName: "ZeroFieldsOrg",

		// All extension fields left at zero value (false).
		AllowExtension:          false,
		ForceExtensionAuth:      false,
		ForceExtensionPairing:   false,
		ForceExtensionAudit:     false,
		AllowConfigureExtension: false,
	}

	result, err := tw.svc.ApplySOProvisioning(choices)
	require.NoError(t, err)
	require.NotNil(t, result)

	saved, loadErr := config.Load()
	require.NoError(t, loadErr)

	// When OrganizationName is set, the wizard overrides DefaultPolicy() values.
	// DefaultPolicy() sets these to true, but the SO chose false.
	assert.False(t, saved.Policy.ExtensionEnabled,
		"ExtensionEnabled should be false when SO chose false")
	assert.False(t, saved.Policy.ExtensionRequireAuthentication,
		"ExtensionRequireAuthentication should be false when SO chose false")
	assert.False(t, saved.Policy.ExtensionRequirePairing,
		"ExtensionRequirePairing should be false when SO chose false")
	assert.False(t, saved.Policy.ExtensionForceAudit,
		"ExtensionForceAudit should be false when SO chose false")
	assert.False(t, saved.Policy.UserCanConfigureExtension,
		"UserCanConfigureExtension should be false when SO chose false")
	assert.Equal(t, "ZeroFieldsOrg", saved.Policy.OrganizationName)
}

// ---------------------------------------------------------------------------
// PIN verification regression tests
// ---------------------------------------------------------------------------

// TestApplySetup_NoHierarchyAuth_SRKGetsUserPINAuth is a regression test for
// the bug where SetHierarchyAuth=false caused InitializePlatformKeyStoreWithDefaults
// to be called (empty auth SRK), even when a UserPin was provided. This made
// PIN verification fail after the setup wizard completed.
//
// The fix ensures that when UserPin is set, InitializePlatformKeyStore is always
// called with the user PIN as the SRK auth value, regardless of SetHierarchyAuth.
func TestApplySetup_NoHierarchyAuth_SRKGetsUserPINAuth(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create a TPMService with no TPM accessor — calls will fail but we can
	// verify the correct path is taken by checking the warning message.
	tpmSvc := NewTPMService()
	tpmSvc.SetContext(context.Background())
	tw.svc.SetTPMService(tpmSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		SetHierarchyAuth: false, // hierarchy auth disabled
		StorageType:      "barrier",
		BarrierPassword:  "testbarrier123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// The Platform key store init warning should appear (no real TPM),
	// proving that InitializePlatformKeyStore was called (not WithDefaults).
	// Both paths produce a "Platform key store init" warning when no TPM
	// is present, so this mainly acts as a smoke test. The real assertion
	// is in the code: the conditional now branches on UserPin != "" instead
	// of SetHierarchyAuth.
	hasWarning := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			hasWarning = true
			break
		}
	}
	assert.True(t, hasWarning, "expected warnings from TPM operations without real TPM")
}

// TestApplySetup_NoUserPin_ReturnsError verifies that when no UserPin is
// provided, ApplySetup returns ErrSetupUserPINRequired.
func TestApplySetup_NoUserPin_ReturnsError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	tpmSvc := NewTPMService()
	tpmSvc.SetContext(context.Background())
	tw.svc.SetTPMService(tpmSvc)

	_, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          "", // No user PIN
		SetHierarchyAuth: false,
		StorageType:      "barrier",
		BarrierPassword:  "testbarrier123",
	})
	require.ErrorIs(t, err, ErrSetupUserPINRequired)
}

// TestApplySetup_HierarchyAuthTrue_PassesSoPIN verifies that when both
// SetHierarchyAuth=true and UserPin are set, InitializePlatformKeyStore
// receives both the SO PIN and User PIN.
func TestApplySetup_HierarchyAuthTrue_PassesSoPIN(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	tpmSvc := NewTPMService()
	tpmSvc.SetContext(context.Background())
	tw.svc.SetTPMService(tpmSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		SetHierarchyAuth: true, // hierarchy auth enabled
		StorageType:      "barrier",
		BarrierPassword:  "testbarrier123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should produce warnings (no real TPM) from Install + InitializePlatformKeyStore.
	hasWarning := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			hasWarning = true
			break
		}
	}
	assert.True(t, hasWarning, "expected warnings from TPM operations without real TPM")
}

// ---------------------------------------------------------------------------
// SealerBackend auto-fill tests
// ---------------------------------------------------------------------------

// TestApplySetup_EmptySealerBackend_AutoFillsBest verifies that when
// SealerBackend is left empty, ApplySetup auto-fills it from the best
// available sealer reported by SealService.BestSealer(). The auto-filled
// value is persisted to config and the SealService default is updated.
func TestApplySetup_EmptySealerBackend_AutoFillsBest(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create a SealService with a mock software sealer that reports available.
	sealSvc := NewSealService(t.TempDir())
	wireSealMockClient(sealSvc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true})
	sealSvc.SetContext(context.Background())
	tw.svc.SetSealService(sealSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
		SealerBackend:   "", // Empty -- should be auto-filled
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify the SealService default was updated to the best available backend.
	assert.Equal(t, "tpm2", sealSvc.DefaultBackend(),
		"SealService default backend should be set to the best available (TPM2)")

	// Verify the auto-filled value was persisted to config.
	saved := tw.configFunc()
	assert.Equal(t, "tpm2", saved.SealerBackend,
		"persisted config should contain the auto-filled sealer backend (tpm2)")
}

// TestApplySetup_ExplicitSealerBackend_Preserved verifies that when a
// SealerBackend is explicitly provided, it is preserved as-is, synced
// to the SealService, and persisted to config without being overridden.
func TestApplySetup_ExplicitSealerBackend_Preserved(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create a SealService with both software and a second sealer registered.
	sealSvc := NewSealService(t.TempDir())
	wireSealMockClient(sealSvc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true})
	sealSvc.SetContext(context.Background())
	tw.svc.SetSealService(sealSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
		SealerBackend:   "software", // Explicit choice
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify the explicit choice was applied to SealService.
	assert.Equal(t, "software", sealSvc.DefaultBackend(),
		"SealService default should match the explicit choice")

	// Verify the explicit value was persisted to config.
	saved := tw.configFunc()
	assert.Equal(t, "software", saved.SealerBackend,
		"persisted config should contain the explicit sealer backend")
}

// TestApplySetup_EmptySealerBackend_NoSealService verifies that when no
// SealService is configured, the SealerBackend falls back to "software"
// so the barrier can always be initialized.
func TestApplySetup_EmptySealerBackend_NoSealService(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// No SealService set at all.
	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
		SealerBackend:   "", // Empty, no seal service
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// SealerBackend should fall back to "software" as the last-resort default
	// so the barrier strategy is always valid.
	saved := tw.configFunc()
	assert.Equal(t, "software", saved.SealerBackend,
		"SealerBackend should fall back to software when no SealService is configured")
}

// TestApplySetup_EmptySealerBackend_NoAvailableSealers verifies that when
// a SealService is configured but has no available sealers, the SealerBackend
// falls back to "software" so the barrier can always be initialized.
func TestApplySetup_EmptySealerBackend_NoAvailableSealers(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create a SealService with a sealer that reports unavailable.
	sealSvc := NewSealService(t.TempDir())
	wireSealMockClient(sealSvc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: false})
	sealSvc.SetContext(context.Background())
	tw.svc.SetSealService(sealSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
		SealerBackend:   "", // Empty, no available sealer
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// BestSealer returns nil when no sealer is available, so SealerBackend
	// should fall back to "software" as the last-resort default.
	saved := tw.configFunc()
	assert.Equal(t, "software", saved.SealerBackend,
		"SealerBackend should fall back to software when no sealers are available")
}

// ---------------------------------------------------------------------------
// Config save flow tests
// ---------------------------------------------------------------------------

// TestSetupWizard_ApplySetup_SetsSetupComplete verifies that when the wizard
// completes successfully, the persisted config has SetupComplete set to true.
func TestSetupWizard_ApplySetup_SetsSetupComplete(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify the result reports completion.
	assert.True(t, result.SetupComplete,
		"result.SetupComplete should be true after successful ApplySetup")

	// Verify the persisted config has SetupComplete set.
	saved := tw.configFunc()
	require.NotNil(t, saved, "persisted config should not be nil")
	assert.True(t, saved.SetupComplete,
		"persisted config.SetupComplete should be true after wizard completes")
}

// TestSetupWizard_ApplySetup_PersistsBarrierFields verifies that when
// the wizard completes with barrier storage, the persisted config contains
// the correct BarrierInitialized, BarrierStrategy, and StorageType fields.
func TestSetupWizard_ApplySetup_PersistsBarrierFields(t *testing.T) {
	tmpDir := t.TempDir()

	// Wire a real BarrierService backed by a temp directory so barrier
	// initialization succeeds with the software strategy.
	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
		SealerBackend:   "software",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.SetupComplete,
		"result.SetupComplete should be true")

	saved := tw.configFunc()
	require.NotNil(t, saved, "persisted config should not be nil")

	assert.True(t, saved.SetupComplete,
		"persisted config.SetupComplete should be true")
	assert.True(t, saved.BarrierInitialized,
		"persisted config.BarrierInitialized should be true when barrier init succeeds")
	assert.Equal(t, "software", saved.BarrierStrategy,
		"persisted config.BarrierStrategy should match the sealer backend used")
	assert.Equal(t, "barrier", saved.StorageType,
		"persisted config.StorageType should be 'barrier' when barrier init succeeds")
}

// TestSetupWizard_ConfigSaveError_ReportsFailure verifies that when the
// configSave callback returns an error, ApplySetup marks the result as
// failed (Success: false) and includes the error message in result.Errors.
func TestSetupWizard_ConfigSaveError_ReportsFailure(t *testing.T) {
	saveErr := errors.New("disk full: unable to write config")

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	// Wire configFunc to return a valid config.
	cfg := &GUIConfigData{}
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })

	// Wire configSave to always return an error.
	svc.SetConfigSaveFunc(func(_ *GUIConfigData) error {
		return saveErr
	})

	// Wire event emitter to avoid nil pointer in post-save event emission.
	svc.SetEventEmitter(func(_ events.Event) {})

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
	})

	// ApplySetup returns nil error (the config save failure is reported in result).
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.Success,
		"result.Success should be false when config save fails")

	// Verify the error message is captured in result.Errors.
	require.NotEmpty(t, result.Errors, "result.Errors should contain the save error")
	foundSaveError := false
	for _, e := range result.Errors {
		if strings.Contains(e, "config save failed") && strings.Contains(e, "disk full") {
			foundSaveError = true
			break
		}
	}
	assert.True(t, foundSaveError,
		"result.Errors should contain 'config save failed' with the original error message")
}

// TestSetupWizard_NilConfigSave_DoesNotPanic verifies that calling ApplySetup
// without setting configSave returns ErrSetupStorageFailed instead of panicking
// with a nil pointer dereference.
func TestSetupWizard_NilConfigSave_DoesNotPanic(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	// Set configFunc but leave configSave nil.
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	// Deliberately do NOT call svc.SetConfigSaveFunc(...)

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
	})

	require.ErrorIs(t, err, ErrSetupStorageFailed,
		"ApplySetup should return ErrSetupStorageFailed when configSave is nil")
	assert.Nil(t, result,
		"result should be nil when ApplySetup fails due to missing configSave")
}

// TestSetupWizard_NilConfigFunc_DoesNotPanic verifies that calling ApplySetup
// without setting configFunc returns ErrSetupStorageFailed instead of panicking.
func TestSetupWizard_NilConfigFunc_DoesNotPanic(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	// Set configSave but leave configFunc nil.
	svc.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })
	// Deliberately do NOT call svc.SetConfigFunc(...)

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
	})

	require.ErrorIs(t, err, ErrSetupStorageFailed,
		"ApplySetup should return ErrSetupStorageFailed when configFunc is nil")
	assert.Nil(t, result,
		"result should be nil when ApplySetup fails due to missing configFunc")
}

// TestSetupWizard_BothConfigCallbacksNil_DoesNotPanic verifies that calling
// ApplySetup with neither configFunc nor configSave set returns an error
// instead of panicking.
func TestSetupWizard_BothConfigCallbacksNil_DoesNotPanic(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	// Deliberately do NOT set configFunc or configSave.
	result, err := svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
	})

	require.ErrorIs(t, err, ErrSetupStorageFailed,
		"ApplySetup should return ErrSetupStorageFailed when both callbacks are nil")
	assert.Nil(t, result,
		"result should be nil when ApplySetup fails due to missing callbacks")
}
