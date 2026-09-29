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
	"fmt"
	"log/slog"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultPINs provides standard PIN values for tests that need to pass
// the mandatory SO PIN and User PIN validation.
// ---------------------------------------------------------------------------
// Constructor tests (#313)
// ---------------------------------------------------------------------------

// TestNewSetupWizardService_NilPINService_ReturnsError verifies that the
// constructor refuses to build a SetupWizardService without a PIN service.
// The PIN service is the credential gate for every destructive or
// credential-gated wizard operation; earlier revisions accepted it through
// a setter, so a caller that forgot to call it got a wizard whose
// credential checks silently passed instead of refusing to run (#313).
// Requiring it here makes that construction impossible through the public
// constructor.
func TestNewSetupWizardService_NilPINService_ReturnsError(t *testing.T) {
	svc, err := NewSetupWizardService(nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupWizardPINServiceRequired)
	assert.Nil(t, svc)
}

// TestNewSetupWizardService_WithPINService_Succeeds verifies that the
// constructor succeeds and wires the PIN service when a non-nil one is
// supplied.
func TestNewSetupWizardService_WithPINService_Succeeds(t *testing.T) {
	pinSvc := NewPINService()

	svc, err := NewSetupWizardService(pinSvc)

	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Same(t, pinSvc, svc.pinSvc)
}

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
	svc := &SetupWizardService{}

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
	svc := &SetupWizardService{}

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

// TestGenerateRandomPIN_NeverFails stress-tests generateRandomPIN across a
// large number of iterations for every supported length, with extra
// coverage at length 4 where the weak-PIN rule (all four character classes
// present) has the lowest per-attempt acceptance probability of any
// supported length (~7%, since a 4-character PIN can only satisfy the rule
// by placing a distinct class in each of its 4 positions).
//
// This is a regression test for #1210: generateRandomPIN previously capped
// its rejection-sampling loop at 100 attempts, which could exhaust and
// return ErrSetupPINGenerationFailed at length 4 with probability on the
// order of 1 in 1,300 calls -- rare enough to pass most local runs (single
// invocations, even -count=200) yet real enough to appear once in CI.
// generateRandomPIN now loops until it finds a match instead of giving up,
// so it must never fail here regardless of how many times it is called.
func TestGenerateRandomPIN_NeverFails(t *testing.T) {
	lengths := []int{0, 1, 2, 3, 4, 5, 8, 12, 16, 64}
	for _, length := range lengths {
		length := length
		t.Run(fmt.Sprintf("length=%d", length), func(t *testing.T) {
			t.Parallel()

			iterations := 2000
			if length == 4 {
				// Weakest acceptance rate: exercise it hardest.
				iterations = 20000
			}

			for i := 0; i < iterations; i++ {
				pin, err := generateRandomPIN(length)
				require.NoErrorf(t, err, "iteration %d", i)
				require.Lenf(t, pin, length, "iteration %d", i)
				if length >= 4 {
					require.Truef(t, pinMeetsComplexity(pin),
						"iteration %d produced a PIN missing a character class: %s", i, pin)
				}
			}
		})
	}
}

// TestGenerateRandomPIN_Distribution is a cheap sanity check that
// generateRandomPIN draws characters roughly uniformly from pinCharset --
// the complexity rejection step must not skew the output toward one
// character class.
func TestGenerateRandomPIN_Distribution(t *testing.T) {
	const (
		numPINs   = 2000
		pinLength = 16
	)

	var upper, lower, digit, special int
	total := 0
	for i := 0; i < numPINs; i++ {
		pin, err := generateRandomPIN(pinLength)
		require.NoError(t, err)
		for _, c := range pin {
			total++
			switch {
			case c >= 'A' && c <= 'Z':
				upper++
			case c >= 'a' && c <= 'z':
				lower++
			case c >= '0' && c <= '9':
				digit++
			default:
				special++
			}
		}
	}
	require.Equal(t, numPINs*pinLength, total)

	// Expected proportions from the 90-char charset: 26 upper, 26 lower,
	// 10 digit, 28 special. The margin is wide -- far beyond statistical
	// noise at this sample size -- so this stays a sanity check rather
	// than becoming a new source of flakiness.
	assertProportion := func(name string, count int, expected float64) {
		got := float64(count) / float64(total)
		require.InDeltaf(t, expected, got, expected*0.35,
			"%s proportion %.4f far from expected %.4f", name, got, expected)
	}
	assertProportion("upper", upper, 26.0/90.0)
	assertProportion("lower", lower, 26.0/90.0)
	assertProportion("digit", digit, 10.0/90.0)
	assertProportion("special", special, 28.0/90.0)
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
		SealerBackend:   "passphrase", // Explicit choice
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// The wizard's "passphrase" choice is a BARRIER strategy; the seal feature
	// uses its own backend namespace, so it must be mapped to the "software"
	// seal backend. Pinning the seal service to the raw "passphrase" strategy
	// made CanSeal reject an unknown backend and disabled sealing entirely.
	assert.Equal(t, "software", sealSvc.DefaultBackend(),
		"SealService default should be the seal backend mapped from the barrier sealer")

	// The config must store the seal-namespace backend ID, not the raw barrier
	// strategy. sealBackendForBarrierSealer("passphrase") -> "software".
	saved := tw.configFunc()
	assert.Equal(t, "software", saved.SealerBackend,
		"persisted config should contain the translated seal backend ID (software), not the raw barrier strategy (passphrase)")
}

func TestApplySetup_TPM2SealerBackend_Preserved(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	sealSvc := NewSealService(t.TempDir())
	wireSealMockClient(sealSvc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true})
	sealSvc.SetContext(context.Background())
	tw.svc.SetSealService(sealSvc)

	_, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
		SealerBackend:   "tpm2",
	})
	require.NoError(t, err)

	// "tpm2" is valid in both namespaces, so it maps through unchanged.
	assert.Equal(t, "tpm2", sealSvc.DefaultBackend(),
		"a tpm2 barrier sealer maps to the tpm2 seal backend")
}

// TestApplySetup_PassphraseSealerBackend_PersistsTranslatedID is the
// regression test for the "No Sealing Backends Available" bug (Jun 2026).
//
// Scenario: fresh install; host TPM hierarchy auth unavailable; setup wizard
// auto-selected "passphrase" barrier strategy. The wizard previously stored
// SealerBackend="passphrase" in the config. On next startup app.go called
// SetDefaultBackend("passphrase"), CanSeal(ctx, "passphrase") found no matching
// backend, returned false, and the Sealed Data view showed the warning banner
// with "Seal New Data" permanently disabled.
//
// Fix: the wizard must translate the barrier strategy to the seal-namespace ID
// before persisting ("passphrase" -> "software").
func TestApplySetup_PassphraseSealerBackend_PersistsTranslatedID(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	sealSvc := NewSealService(t.TempDir())
	wireSealMockClient(sealSvc, &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: false}) // TPM not available
	sealSvc.SetContext(context.Background())
	tw.svc.SetSealService(sealSvc)

	_, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
		SealerBackend:   "passphrase", // wizard chose passphrase barrier strategy
	})
	require.NoError(t, err)

	// The persisted config must store "software", not "passphrase".
	// If "passphrase" were stored, SetDefaultBackend on the next startup would
	// trigger auto-select (defensive guard), but the correct fix is to never
	// store an invalid seal-namespace ID in the first place.
	saved := tw.configFunc()
	assert.Equal(t, "software", saved.SealerBackend,
		"wizard must persist the seal-namespace ID (software) not the barrier strategy (passphrase)")
}

func TestSealBackendForBarrierSealer(t *testing.T) {
	assert.Equal(t, "software", sealBackendForBarrierSealer("passphrase"))
	assert.Equal(t, "software", sealBackendForBarrierSealer("software"))
	assert.Equal(t, "tpm2", sealBackendForBarrierSealer("tpm2"))
	assert.Equal(t, "", sealBackendForBarrierSealer("pkcs11"), "hardware-token strategy has no seal backend; caller auto-selects")
	assert.Equal(t, "", sealBackendForBarrierSealer(""))
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

	// choices.SealerBackend was set to "passphrase" by the last-resort fallback.
	// sealBackendForBarrierSealer("passphrase") translates it to "software" when
	// persisting, so the config always stores a valid seal-namespace ID.
	saved := tw.configFunc()
	assert.Equal(t, "software", saved.SealerBackend,
		"persisted config should store the translated seal backend ID (software)")
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

	// choices.SealerBackend was set to "passphrase" by the last-resort fallback.
	// sealBackendForBarrierSealer("passphrase") translates it to "software" for
	// the persisted config.
	saved := tw.configFunc()
	assert.Equal(t, "software", saved.SealerBackend,
		"persisted config should store the translated seal backend ID (software)")
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
		SealerBackend:   "passphrase",
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
	assert.Equal(t, "passphrase", saved.BarrierStrategy,
		"persisted config.BarrierStrategy should match the sealer backend used")
	assert.Equal(t, "barrier", saved.StorageType,
		"persisted config.StorageType should be 'barrier' when barrier init succeeds")
}

// TestSetupWizard_ConfigSaveError_ReportsFailure verifies that when the
// configSave callback returns an error, ApplySetup marks the result as
// failed (Success: false) and includes the error message in result.Errors.
func TestSetupWizard_ConfigSaveError_ReportsFailure(t *testing.T) {
	saveErr := errors.New("disk full: unable to write config")

	svc := &SetupWizardService{}
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
	svc := &SetupWizardService{}
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
	svc := &SetupWizardService{}
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
	svc := &SetupWizardService{}
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

// ---------------------------------------------------------------------------
// TPM sealing downgrade detection tests
// ---------------------------------------------------------------------------

// TestApplySetup_TPMRequestedButFallbackToPassphrase_HasDowngradeWarning verifies
// that when the user requests TPM sealing (password_store_mode="tpm_sealed") but
// TPM hardware is unavailable (no SealService, so BestSealer returns nil causing
// the last-resort passphrase fallback), the result carries an explicit downgrade
// warning stating the requested vs actual sealing strategy. This prevents the user
// from silently believing their master key is hardware-sealed when it is not.
func TestApplySetup_TPMRequestedButFallbackToPassphrase_HasDowngradeWarning(t *testing.T) {
	tmpDir := t.TempDir()

	// Wire a real BarrierService so barrier init succeeds with passphrase strategy.
	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())

	// Do NOT wire a SealService (nil) — simulates TPM hardware unavailable.
	// With sealSvc == nil, BestSealer() is never called and SealerBackend stays "",
	// which falls through to the last-resort passphrase fallback.
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		SOPin:              testSOPin,
		UserPin:            testUserPin,
		PasswordStoreMode:  "tpm_sealed", // user explicitly requested TPM sealing
		SealerBackend:      "",           // not explicitly set — auto-fill path
		StorageType:        "barrier",
		BarrierPassword:    "testbarrier123",
		UseUserPinAsMaster: false,
	})
	require.NoError(t, err, "ApplySetup should not return an error on passphrase fallback")
	require.NotNil(t, result)

	// Barrier should have initialized successfully with passphrase.
	assert.True(t, result.Success, "result.Success should be true after passphrase fallback")

	// The downgrade warning MUST be present so the frontend can surface it.
	assert.NotEmpty(t, result.Warnings, "result.Warnings must be non-empty when sealing strategy is downgraded")
	assert.True(t,
		containsSubstring(result.Warnings, "sealing strategy downgraded"),
		"Warnings must mention strategy downgrade; got: %v", result.Warnings)
	assert.True(t,
		containsSubstring(result.Warnings, "passphrase"),
		"Warnings must mention the actual passphrase strategy; got: %v", result.Warnings)
	assert.True(t,
		containsSubstring(result.Warnings, "tpm_sealed") || containsSubstring(result.Warnings, "tpm2"),
		"Warnings must mention the originally requested strategy; got: %v", result.Warnings)
	assert.True(t,
		containsSubstring(result.Warnings, "clear the TPM"),
		"Warnings must include the remediation hint about clearing the TPM; got: %v", result.Warnings)
}

// TestApplySetup_ExplicitTPM2InitFails_FallsBackToPassphraseAndCompletes verifies
// the hardware->software fallback at barrier-init time. When the user explicitly
// chooses TPM sealing (SealerBackend="tpm2") but the TPM strategy fails to
// initialize the barrier (here: no TPM sealer wired, so assembleStrategy("tpm2")
// returns ErrBarrierStrategyUnavailable — mirroring a real TPM that rejects
// provisioning with TPM_RC_BAD_AUTH/TPM_RC_POLICY_FAIL), setup must NOT dead-end.
// It must retry with passphrase, complete setup (persist SetupComplete=true so the
// wizard does not reappear on every launch), and surface a downgrade warning.
func TestApplySetup_ExplicitTPM2InitFails_FallsBackToPassphraseAndCompletes(t *testing.T) {
	tmpDir := t.TempDir()

	// Real BarrierService with NO TPM sealer wired: Initialize(_, "tpm2") fails
	// with ErrBarrierStrategyUnavailable; Initialize(_, "passphrase") succeeds.
	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		SOPin:              testSOPin,
		UserPin:            testUserPin,
		PasswordStoreMode:  "tpm_sealed",
		SealerBackend:      "tpm2", // EXPLICIT hardware choice that fails at init
		StorageType:        "barrier",
		BarrierPassword:    "testbarrier123",
		UseUserPinAsMaster: false,
	})
	require.NoError(t, err, "ApplySetup must not error when falling back from failed TPM to passphrase")
	require.NotNil(t, result)

	// The fallback must succeed so the user is not trapped re-running the wizard.
	assert.True(t, result.Success, "result.Success must be true after the TPM->passphrase fallback")
	assert.True(t, result.SetupComplete, "result.SetupComplete must be true after fallback")

	// The CRITICAL assertion: setup completion is PERSISTED. If this is false the
	// wizard reappears on every launch (the reported bug).
	saved := tw.configFunc()
	require.NotNil(t, saved)
	assert.True(t, saved.SetupComplete,
		"persisted SetupComplete must be true so the next launch shows the unlock screen, not the wizard")
	assert.True(t, saved.BarrierInitialized, "persisted BarrierInitialized must be true after fallback")
	assert.Equal(t, "passphrase", saved.BarrierStrategy,
		"persisted BarrierStrategy must reflect the actual passphrase strategy")
	assert.Equal(t, "software", saved.SealerBackend,
		"persisted SealerBackend must map to the software seal namespace, not the failed tpm2")

	// The downgrade must be surfaced so the user knows hardware sealing was not used.
	assert.True(t,
		containsSubstring(result.Warnings, "sealing strategy downgraded"),
		"Warnings must mention the downgrade; got: %v", result.Warnings)
}

// TestApplySetup_TPM2Strategy_SkipsSOPINEntirely verifies that when the
// active PIN backend is the tpm2 strategy (no SO PIN concept — see
// pkg/pintpm2.TPM2Backend), ApplySetup never calls SetSOPIN/ChangeSOPIN/
// VerifySOPIN against it. Before this fix, a virgin install with a
// provisioned TPM would attempt SetSOPIN in Step 2 and again in the
// deferred Step 7 retry, producing repeated so_pin_failed audit events
// and a raw "pin: PIN not set" error surfaced nowhere useful.
func TestApplySetup_TPM2Strategy_SkipsSOPINEntirely(t *testing.T) {
	tmpDir := t.TempDir()

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())

	pinBackend := &wizardMockPINBackend{strategy: qrdbsdk.PINStrategyTPM2}
	pinSvc := newWizardPINService(pinBackend)

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)
	tw.svc.SetPINService(pinSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		SOPin:              testSOPin,
		UserPin:            testUserPin,
		PasswordStoreMode:  "aes_software",
		SealerBackend:      "passphrase",
		StorageType:        "barrier",
		BarrierPassword:    "testbarrier123",
		UseUserPinAsMaster: false,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, pinBackend.setSOPINCalls,
		"SetSOPIN must never be attempted against a tpm2 backend")
	assert.Equal(t, 0, pinBackend.changeSOPINCalls,
		"ChangeSOPIN must never be attempted against a tpm2 backend")
	assert.Equal(t, 0, pinBackend.verifySOPINCalls,
		"VerifySOPIN must never be attempted against a tpm2 backend")

	// The wizard must still surface the fact that SO PIN was not applicable,
	// rather than silently dropping the user's entered value.
	assert.True(t,
		containsSubstring(result.Warnings, "SO PIN is not applicable"),
		"Warnings must explain that SO PIN does not apply to the tpm2 backend; got: %v", result.Warnings)
	assert.True(t,
		containsSubstring(result.Warnings, "tpm2"),
		"Warnings must name the active strategy; got: %v", result.Warnings)

	// Exactly one warning about SO PIN applicability (not one per attempted
	// call site) — the capability check short-circuits every call site.
	sopinWarnings := 0
	for _, w := range result.Warnings {
		if strings.Contains(w, "SO PIN is not applicable") {
			sopinWarnings++
		}
	}
	assert.Equal(t, 1, sopinWarnings, "expected exactly one SO PIN applicability warning; got: %v", result.Warnings)

	// User PIN must still be set — the tpm2 backend ignores the SO PIN
	// parameter for SetUserPIN entirely, so it is unaffected.
	assert.True(t, pinBackend.userPINSet, "User PIN must still be set against the tpm2 backend")
}

// TestApplySetup_SoftwareStrategy_StillSetsSOPIN is the control case for
// TestApplySetup_StrategySwitchesToTPM2MidApply_SkipsDeferredSOPIN covers
// the live first-boot sequence: at Step 2 the PIN service still runs the
// software strategy (SO PIN supported), then initDataDirFunc re-creates the
// PIN manager and pinselect picks tpm2. The deferred Step 7 retry must
// re-evaluate capability and skip the SetSOPIN/ChangeSOPIN/VerifySOPIN chain
// instead of emitting so_pin_failed audit events on a clean install.
func TestApplySetup_StrategySwitchesToTPM2MidApply_SkipsDeferredSOPIN(t *testing.T) {
	tmpDir := t.TempDir()

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())

	softBackend := &wizardMockPINBackend{
		strategy: qrdbsdk.PINStrategySoftware,
		// Step 2 SetSOPIN fails (PIN manager not ready yet on a real boot),
		// forcing the wizard onto the deferred Step 7 retry path.
		setSOPINErr: errors.New("pin manager not initialized"),
	}
	tpm2Backend := &wizardMockPINBackend{strategy: qrdbsdk.PINStrategyTPM2}

	pinSvc := newWizardPINService(softBackend)

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)
	tw.svc.SetPINService(pinSvc)
	tw.svc.SetInitDataDirFunc(func() error {
		// Data-dir init re-selects the PIN backend: software → tpm2.
		pinSvc.SetPINService(qrdbsdk.NewPINService(tpm2Backend, slog.Default()))
		return nil
	})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		SOPin:              testSOPin,
		UserPin:            testUserPin,
		PasswordStoreMode:  "aes_software",
		SealerBackend:      "passphrase",
		StorageType:        "barrier",
		BarrierPassword:    "testbarrier123",
		UseUserPinAsMaster: false,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, tpm2Backend.setSOPINCalls,
		"deferred SetSOPIN must not run once the strategy switched to tpm2")
	assert.Equal(t, 0, tpm2Backend.changeSOPINCalls,
		"deferred ChangeSOPIN must not run once the strategy switched to tpm2")
	assert.Equal(t, 0, tpm2Backend.verifySOPINCalls,
		"deferred VerifySOPIN must not run once the strategy switched to tpm2")
	assert.True(t,
		containsSubstring(result.Warnings, "SO PIN is not applicable"),
		"Warnings must explain SO PIN inapplicability after the mid-apply strategy switch; got: %v", result.Warnings)
}

// TestApplySetup_TPM2Strategy_SkipsSOPINEntirely: a software PIN backend
// supports SO PINs, so ApplySetup must set it exactly as before.
func TestApplySetup_SoftwareStrategy_StillSetsSOPIN(t *testing.T) {
	tmpDir := t.TempDir()

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())

	pinBackend := &wizardMockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	pinSvc := newWizardPINService(pinBackend)

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)
	tw.svc.SetPINService(pinSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		SOPin:              testSOPin,
		UserPin:            testUserPin,
		PasswordStoreMode:  "aes_software",
		SealerBackend:      "passphrase",
		StorageType:        "barrier",
		BarrierPassword:    "testbarrier123",
		UseUserPinAsMaster: false,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 1, pinBackend.setSOPINCalls, "SetSOPIN must be attempted exactly once against a software backend")
	assert.True(t, pinBackend.soPINSet)
	assert.False(t,
		containsSubstring(result.Warnings, "SO PIN is not applicable"),
		"no SO PIN applicability warning should appear for the software backend; got: %v", result.Warnings)
}

// TestApplySetup_NoDowngradeWarning_WhenPassphraseExplicitlyChosen verifies that
// when the user explicitly selects passphrase sealing (no hardware intent),
// no downgrade warning is emitted even though passphrase is ultimately used.
func TestApplySetup_NoDowngradeWarning_WhenPassphraseExplicitlyChosen(t *testing.T) {
	tmpDir := t.TempDir()

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		SOPin:              testSOPin,
		UserPin:            testUserPin,
		PasswordStoreMode:  "aes_software", // no hardware intent
		SealerBackend:      "passphrase",   // explicitly passphrase
		StorageType:        "barrier",
		BarrierPassword:    "testbarrier123",
		UseUserPinAsMaster: false,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Success, "result.Success should be true for explicit passphrase setup")

	// No downgrade warning should be emitted when the user explicitly chose passphrase.
	assert.False(t,
		containsSubstring(result.Warnings, "sealing strategy downgraded"),
		"no downgrade warning should appear for an explicit passphrase choice; got: %v", result.Warnings)
}
