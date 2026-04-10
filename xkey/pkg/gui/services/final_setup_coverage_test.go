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
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SetTPMStatusFunc (L185-187)
// ---------------------------------------------------------------------------

func TestFSC_SetTPMStatusFunc(t *testing.T) {
	svc := NewSetupWizardService()
	assert.Nil(t, svc.tpmStatusFn)

	called := false
	svc.SetTPMStatusFunc(func() (bool, bool, bool) {
		called = true
		return true, true, false
	})

	require.NotNil(t, svc.tpmStatusFn)
	devExists, avail, prov := svc.tpmStatusFn()
	assert.True(t, called)
	assert.True(t, devExists)
	assert.True(t, avail)
	assert.False(t, prov)
}

// ---------------------------------------------------------------------------
// IsSetupComplete (L218-226) - all branches
// ---------------------------------------------------------------------------

func TestFSC_IsSetupComplete_NilConfigFunc(t *testing.T) {
	svc := NewSetupWizardService()
	// configFunc is nil => assume complete
	assert.True(t, svc.IsSetupComplete())
}

func TestFSC_IsSetupComplete_NilConfig(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData { return nil })
	// configFunc returns nil => assume complete
	assert.True(t, svc.IsSetupComplete())
}

func TestFSC_IsSetupComplete_NotComplete(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})
	assert.False(t, svc.IsSetupComplete())
}

func TestFSC_IsSetupComplete_Complete(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: true}
	})
	assert.True(t, svc.IsSetupComplete())
}

// ---------------------------------------------------------------------------
// ProbeEnvironment uncovered branches (L236-239, L256-258, L261-266)
// ---------------------------------------------------------------------------

func TestFSC_ProbeEnvironment_TPMStatusFunc(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetTPMStatusFunc(func() (bool, bool, bool) {
		return true, true, false
	})

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.True(t, probe.TPMAvailable)
}

func TestFSC_ProbeEnvironment_BarrierStrategies(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	svc.SetBarrierService(barrierSvc)

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.NotEmpty(t, probe.BarrierStrategies)
	// Software strategy should always be available.
	assert.Equal(t, "software", probe.BarrierStrategies[0].ID)
}

func TestFSC_ProbeEnvironment_ConfigFunc(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{
			SetupComplete: true,
			ServerAddress: "localhost:9443",
		}
	})

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.True(t, probe.SetupComplete)
	assert.Equal(t, "localhost:9443", probe.ServerAddress)
}

func TestFSC_ProbeEnvironment_ConfigFuncNilResult(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return nil })

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	// Should not panic and should not set setupComplete.
	assert.False(t, probe.SetupComplete)
}

// ---------------------------------------------------------------------------
// ApplySetup validation errors (L289-312)
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_NilConfigFunc(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	// configFunc and configSave are nil
	result, err := svc.ApplySetup(&SetupChoices{Mode: "standalone", SOPin: "123456", UserPin: "654321"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestFSC_ApplySetup_NilConfigSave(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	// configSave is nil
	result, err := svc.ApplySetup(&SetupChoices{Mode: "standalone", SOPin: "123456", UserPin: "654321"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestFSC_ApplySetup_NilConfig(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return nil })
	svc.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })

	result, err := svc.ApplySetup(&SetupChoices{Mode: "standalone", SOPin: "123456", UserPin: "654321"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestFSC_ApplySetup_AlreadyComplete(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: true})
	result, err := tw.svc.ApplySetup(&SetupChoices{Mode: "standalone", SOPin: "123456", UserPin: "654321"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupAlreadyComplete)
}

func TestFSC_ApplySetup_InvalidMode(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	result, err := tw.svc.ApplySetup(&SetupChoices{Mode: "invalid_mode", SOPin: "123456", UserPin: "654321"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupInvalidMode)
}

func TestFSC_ApplySetup_EmptySOPin(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	result, err := tw.svc.ApplySetup(&SetupChoices{Mode: "standalone", SOPin: "", UserPin: "654321"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupSOPINRequired)
}

func TestFSC_ApplySetup_EmptyUserPin(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	result, err := tw.svc.ApplySetup(&SetupChoices{Mode: "standalone", SOPin: "123456", UserPin: ""})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrSetupUserPINRequired)
}

// ---------------------------------------------------------------------------
// ApplySetup LUKS storage: storageSvc present + CreateVolume call (L329-337)
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_LUKSStorageNilService(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	// storageSvc is nil, so LUKS path adds a warning.
	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:          "standalone",
		SOPin:         testSOPin,
		UserPin:       testUserPin,
		StorageType:   "luks",
		EnableStorage: true,
		StorageSizeGB: 1,
		StoragePass:   "passphrase12345",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Warnings, "storage service unavailable")
}

func TestFSC_ApplySetup_LUKSStorageCreateVolumeError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	storageSvc := NewStorageService()
	storageSvc.SetContext(context.Background())
	tw.svc.SetStorageService(storageSvc)

	// CreateVolume will fail because we're not running as root.
	// The important thing is that the code path is reached (L329-337).
	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:          "standalone",
		SOPin:         testSOPin,
		UserPin:       testUserPin,
		StorageType:   "luks",
		EnableStorage: true,
		StorageSizeGB: 1,
		StoragePass:   "passphrase12345",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Should have an error about storage creation.
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "storage creation failed"))
}

// ---------------------------------------------------------------------------
// ApplySetup barrier UseUserPinAsMaster (L351-353)
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_BarrierUseUserPinAsMaster(t *testing.T) {
	tmpDir := t.TempDir()
	tw := newTestSetupWizard(&GUIConfigData{})

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		SOPin:              testSOPin,
		UserPin:            testUserPin,
		StorageType:        "barrier",
		UseUserPinAsMaster: true, // L351: triggers barrierPW = choices.UserPin
		SealerBackend:      "software",
		// BarrierPassword left empty so UserPin is used instead.
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Check that barrier was initialized (setup saved BarrierInitialized=true).
	savedCfg := tw.configFunc()
	assert.True(t, savedCfg.BarrierInitialized)
	assert.Equal(t, "software", savedCfg.BarrierStrategy)
}

// ---------------------------------------------------------------------------
// ApplySetup barrier init error path (L358-363)
// The barrier Initialize returns error => stored in errors, barrierInitialized stays false.
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_BarrierAlreadyInit_UnsealSucceeds(t *testing.T) {
	tmpDir := t.TempDir()
	tw := newTestSetupWizard(&GUIConfigData{})

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)

	// First, initialize barrier to trigger ErrBarrierAlreadyInit on the second call.
	err := barrierSvc.Initialize("test-password", "software")
	require.NoError(t, err)

	// Create a fresh barrier service pointing at the same directory (already initialized).
	barrierSvc2 := NewBarrierService(tmpDir, slog.Default())
	barrierSvc2.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc2)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "test-password",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Barrier already initialized -> unseal succeeds with correct password.
	assert.True(t, result.Success, "expected success when barrier unseal works, errors: %v", result.Errors)
}

// ---------------------------------------------------------------------------
// ApplySetup platform policy enabled with service present (L382-394)
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_PlatformPolicyServicePresent(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create a PlatformPolicyService (no TPM, so CreatePolicy fails).
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "platform-policy.json")
	ppSvc := NewPlatformPolicyService(policyPath)
	ppSvc.SetContext(context.Background())
	tw.svc.SetPlatformPolicyService(ppSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:    "standalone",
		SOPin:   testSOPin,
		UserPin: testUserPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// CreatePolicy fails (no TPM), so it goes to the warning path.
	assert.True(t, containsSubstring(result.Warnings, "platform policy creation failed"))
}

// ---------------------------------------------------------------------------
// ApplySetup TPM provisioning steps 6+7 (L420-444)
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_TPMProvisioningWithHierarchyAuth(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create TPMService with no TPM accessor (getTPM returns error).
	tpmSvc := NewTPMService()
	tpmSvc.SetContext(context.Background())
	tw.svc.SetTPMService(tpmSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		SetHierarchyAuth: true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// TPM operations fail with warnings since no TPM accessor is set.
	assert.True(t, containsSubstring(result.Warnings, "TPM provisioning"))
	assert.True(t, containsSubstring(result.Warnings, "Platform key store init"))
}

func TestFSC_ApplySetup_TPMProvisioningWithDefaults(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create TPMService with no TPM accessor.
	tpmSvc := NewTPMService()
	tpmSvc.SetContext(context.Background())
	tw.svc.SetTPMService(tpmSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		SetHierarchyAuth: false, // L440: goes to InitializePlatformKeyStoreWithDefaults
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Both Install and InitializePlatformKeyStoreWithDefaults fail with warnings.
	assert.True(t, containsSubstring(result.Warnings, "TPM provisioning"))
	assert.True(t, containsSubstring(result.Warnings, "Platform key store init"))
}

// ---------------------------------------------------------------------------
// ApplySetup auto-unseal with LUKS, nil auto-unseal service (L512-515, L527-529)
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_AutoUnsealLUKSNilService(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		EnableAutoUnseal: true,
		StorageType:      "luks",
		EnableStorage:    true,
		StoragePass:      "passphrase12345",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Auto-unseal service is nil, so we get a warning.
	assert.True(t, containsSubstring(result.Warnings, "auto-unseal service unavailable"))
}

// ---------------------------------------------------------------------------
// ApplySetup config save with server mode (L538-555)
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_ServerMode(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:           "server",
		SOPin:          testSOPin,
		UserPin:        testUserPin,
		ServerAddress:  "xkms.example.com:9443",
		ServerProtocol: "grpc",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.SetupComplete)

	// Verify server config was saved.
	savedCfg := tw.configFunc()
	assert.Equal(t, "xkms.example.com:9443", savedCfg.ServerAddress)
	assert.Equal(t, "grpc", savedCfg.ServerProtocol)
	assert.True(t, savedCfg.ServerAutoConnect)
}

func TestFSC_ApplySetup_BothMode(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:          "both",
		SOPin:         testSOPin,
		UserPin:       testUserPin,
		ServerAddress: "xkms.example.com:9443",
		// ServerProtocol is empty.
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	savedCfg := tw.configFunc()
	assert.Equal(t, "xkms.example.com:9443", savedCfg.ServerAddress)
	assert.True(t, savedCfg.ServerAutoConnect)
	// ServerProtocol was empty, so it should not be overwritten.
	assert.Equal(t, "", savedCfg.ServerProtocol)
}

func TestFSC_ApplySetup_ConfigSaveError(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	cfg := &GUIConfigData{}
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(_ *GUIConfigData) error {
		return errors.New("disk full")
	})

	var eventLog []*events.Event
	svc.SetEventEmitter(func(e events.Event) {
		eventLog = append(eventLog, &e)
	})

	result, err := svc.ApplySetup(&SetupChoices{
		Mode:    "standalone",
		SOPin:   testSOPin,
		UserPin: testUserPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "config save failed"))
	// SetupComplete is still set to true regardless of save error.
	assert.True(t, result.SetupComplete)
}

// ---------------------------------------------------------------------------
// SkipSetup error paths (L578-585)
// ---------------------------------------------------------------------------

func TestFSC_SkipSetup_NilConfigFunc(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	err := svc.SkipSetup()
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestFSC_SkipSetup_NilConfigSave(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	err := svc.SkipSetup()
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestFSC_SkipSetup_NilConfigResult(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return nil })
	svc.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })
	err := svc.SkipSetup()
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

// ---------------------------------------------------------------------------
// FactoryReset: verify event emission (L1067-1072)
// ---------------------------------------------------------------------------

func TestFSC_FactoryReset_EmitsEvent(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: true})

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	err := tw.svc.FactoryReset(testSOPin)
	require.NoError(t, err)

	// Check that the event was emitted.
	found := lastEventOfType(tw.eventLog, events.EventSetupSkipped)
	require.NotNil(t, found)
	payload, ok := found.Payload.(events.SetupSkippedPayload)
	require.True(t, ok)
	assert.Equal(t, "factory reset performed", payload.Reason)
}

func TestFSC_FactoryReset_NoEventEmitter(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	svc.SetPINService(pinSvc)

	// No event emitter set - should not panic.
	err := svc.FactoryReset(testSOPin)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// FactoryReset: HMAC removal with real file (L1042-1047)
// ---------------------------------------------------------------------------

func TestFSC_FactoryReset_RemovesHMACFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an HMAC file.
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	require.NoError(t, os.WriteFile(hmacPath, []byte("test-hmac"), 0600))
	require.FileExists(t, hmacPath)

	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: true})
	tw.svc.SetConfigDir(tmpDir)

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	err := tw.svc.FactoryReset(testSOPin)
	require.NoError(t, err)

	// HMAC file should be removed.
	_, statErr := os.Stat(hmacPath)
	assert.True(t, os.IsNotExist(statErr))
}

// ---------------------------------------------------------------------------
// FactoryReset: GUI config reset path (L1056-1064)
// ---------------------------------------------------------------------------

func TestFSC_FactoryReset_ResetsGUIConfig(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{
		SetupComplete:      true,
		BarrierInitialized: true,
		StorageType:        "barrier",
		ServerAddress:      "example.com",
	})

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	err := tw.svc.FactoryReset(testSOPin)
	require.NoError(t, err)

	// Config should be reset to zero values.
	savedCfg := tw.configFunc()
	assert.False(t, savedCfg.SetupComplete)
	assert.False(t, savedCfg.BarrierInitialized)
	assert.Equal(t, "", savedCfg.StorageType)
	assert.Equal(t, "", savedCfg.ServerAddress)
}

// ---------------------------------------------------------------------------
// FactoryReset: errors accumulated (L1074-1076)
// ---------------------------------------------------------------------------

func TestFSC_FactoryReset_AccumulatedErrors(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: true})

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	tw.svc.SetConfigDir(t.TempDir())

	// Set a TPMService that fails (no TPM accessor).
	tpmSvc := NewTPMService()
	tpmSvc.SetContext(context.Background())
	tw.svc.SetTPMService(tpmSvc)

	err := tw.svc.FactoryReset(testSOPin)
	// TPM reset fails but is accumulated; the overall error includes it.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "factory reset completed with errors")
}

// ---------------------------------------------------------------------------
// ApplySOProvisioning: enterprise policy fields (L783-812)
// ---------------------------------------------------------------------------

func TestFSC_ApplySOProvisioning_EnterprisePolicyFields(t *testing.T) {
	tmpDir := t.TempDir()
	tw := newTestSetupWizard(&GUIConfigData{})

	pinMgr := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	// Create a valid config file for config.Load()/Save().
	cfgPath := config.ConfigPath()
	cfgDir := filepath.Dir(cfgPath)
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))
	t.Cleanup(func() { os.Remove(cfgPath) })

	tw.svc.SetConfigDir(tmpDir)

	result, err := tw.svc.ApplySOProvisioning(&SetupChoices{
		Mode:                    "standalone",
		SOPin:                   testSOPin,
		StorageType:             "barrier",
		PasswordStoreMode:       "tpm_sealed",
		MinPinLength:            8,
		OrganizationName:        "Test Corp",
		RequireEncryptedStorage: true,
		RequireTPM:              true,
		AllowAutoUnseal:         false,
		AllowTheme:              true,
		AllowTrustStore:         true,
		AllowAuditLog:           true,
		AllowSealedData:         true,
		AllowChangePIN:          true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.SetupComplete, "SO provisioning should not mark setup complete")
}

// ---------------------------------------------------------------------------
// ApplySOProvisioning: HMAC write failure (L832-836)
// ---------------------------------------------------------------------------

func TestFSC_ApplySOProvisioning_PolicyHMACWriteError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	pinMgr := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	// Set configDir to a non-existent non-writable path for HMAC failure.
	tw.svc.SetConfigDir("/nonexistent/path/that/cannot/exist")

	cfgPath := config.ConfigPath()
	cfgDir := filepath.Dir(cfgPath)
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))
	t.Cleanup(func() { os.Remove(cfgPath) })

	result, err := tw.svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: testSOPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// HMAC write should fail.
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "policy HMAC write failed"))
}

// ---------------------------------------------------------------------------
// ApplySOProvisioning: config.Load error (L816-820) via corrupt YAML
// ---------------------------------------------------------------------------

func TestFSC_ApplySOProvisioning_ConfigLoadError(t *testing.T) {
	// Redirect config directory to a temp dir with corrupt YAML.
	tmpCfgDir := t.TempDir()
	config.SetConfigDir(tmpCfgDir)
	t.Cleanup(func() { config.ResetConfigDir() })

	corruptYAML := []byte("policy:\n  - invalid: [unclosed bracket\n\ttabs: bad")
	cfgPath := filepath.Join(tmpCfgDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, corruptYAML, 0600))

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetConfigDir(t.TempDir())

	pinMgr := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	result, err := tw.svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: testSOPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// config.Load should fail => "config load failed" error in result.
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "config load failed"))
}

// ---------------------------------------------------------------------------
// ApplySOProvisioning: config.Save error (L822-826) via read-only dir
// ---------------------------------------------------------------------------

func TestFSC_ApplySOProvisioning_ConfigSaveError(t *testing.T) {
	// Create a valid config in a temp dir, then make the dir read-only
	// so config.Save fails.
	tmpCfgDir := t.TempDir()
	config.SetConfigDir(tmpCfgDir)
	t.Cleanup(func() {
		// Restore writable so cleanup works.
		os.Chmod(tmpCfgDir, 0700)
		config.ResetConfigDir()
	})

	defaultCfg := config.DefaultConfig()
	cfgPath := filepath.Join(tmpCfgDir, "xkey.yaml")
	require.NoError(t, config.Save(defaultCfg))
	require.FileExists(t, cfgPath)

	// Make config file and directory read-only so Save fails.
	require.NoError(t, os.Chmod(cfgPath, 0444))
	require.NoError(t, os.Chmod(tmpCfgDir, 0555))

	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetConfigDir(t.TempDir())

	pinMgr := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	result, err := tw.svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: testSOPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// config.Save should fail => "config save failed" error in result.
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "config save failed"))
}

// ---------------------------------------------------------------------------
// ApplyUserOnboarding: barrier unseal succeeds (L906, L914-916)
// ---------------------------------------------------------------------------

func TestFSC_ApplyUserOnboarding_BarrierUnsealSucceeds(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up the HMAC file to pass enterprise mode check.
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	policy := config.DefaultPolicy()
	require.NoError(t, config.WritePolicyHMAC(policy, testSOPin, hmacPath))

	tw := newTestSetupWizard(&GUIConfigData{})

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)
	tw.svc.SetConfigDir(tmpDir)

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	// Initialize the barrier first so unseal can succeed.
	require.NoError(t, barrierSvc.Initialize(testUserPin, "software"))

	// Create a fresh barrier service that points at the same directory.
	barrierSvc2 := NewBarrierService(tmpDir, slog.Default())
	barrierSvc2.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc2)

	// Set up unified config.
	cfgPath := config.ConfigPath()
	cfgDir := filepath.Dir(cfgPath)
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))
	t.Cleanup(func() { os.Remove(cfgPath) })

	result, err := tw.svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:   testSOPin,
		UserPIN: testUserPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.SetupComplete)
}

// ---------------------------------------------------------------------------
// ApplyUserOnboarding: barrier unseal fails, initialize succeeds (L908-913)
// ---------------------------------------------------------------------------

func TestFSC_ApplyUserOnboarding_BarrierUnsealFailsInitSucceeds(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up the HMAC file for enterprise mode.
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	policy := config.DefaultPolicy()
	require.NoError(t, config.WritePolicyHMAC(policy, testSOPin, hmacPath))

	tw := newTestSetupWizard(&GUIConfigData{})

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)
	tw.svc.SetConfigDir(tmpDir)

	// Create a barrier service with no existing barrier (unseal will fail, init succeeds).
	barrierDir := filepath.Join(tmpDir, "barrier-new")
	barrierSvc := NewBarrierService(barrierDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)

	// Set up unified config.
	cfgPath := config.ConfigPath()
	cfgDir := filepath.Dir(cfgPath)
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))
	t.Cleanup(func() { os.Remove(cfgPath) })

	result, err := tw.svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:           testSOPin,
		UserPIN:         testUserPin,
		BarrierPassword: "barrier-pw-123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.SetupComplete)
}

// ---------------------------------------------------------------------------
// ApplyUserOnboarding: barrier init error after unseal error (L908-911)
// Both Unseal and Initialize fail. Unseal fails because wrong password;
// Initialize fails because barrier already exists.
// ---------------------------------------------------------------------------

func TestFSC_ApplyUserOnboarding_BarrierBothUnsealAndInitFail(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up the HMAC file for enterprise mode.
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	policy := config.DefaultPolicy()
	require.NoError(t, config.WritePolicyHMAC(policy, testSOPin, hmacPath))

	tw := newTestSetupWizard(&GUIConfigData{})

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)
	tw.svc.SetConfigDir(tmpDir)

	// Create and initialize barrier with one password.
	barrierDir := filepath.Join(tmpDir, "barrier-init")
	barrierSvc := NewBarrierService(barrierDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	require.NoError(t, barrierSvc.Initialize("correct-password", "software"))

	// Create a fresh barrier service pointing at the same directory.
	// Unseal will fail with wrong password, Initialize will fail with ErrBarrierAlreadyInit.
	barrierSvc2 := NewBarrierService(barrierDir, slog.Default())
	barrierSvc2.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc2)

	// Set up unified config.
	cfgPath := config.ConfigPath()
	cfgDir := filepath.Dir(cfgPath)
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))
	t.Cleanup(func() { os.Remove(cfgPath) })

	result, err := tw.svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:           testSOPin,
		UserPIN:         testUserPin,
		BarrierPassword: "wrong-password", // Unseal fails, Initialize also fails (already init)
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Barrier exists (ErrBarrierAlreadyInit) → unseal with wrong password fails.
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "barrier unseal failed"))
}

// ---------------------------------------------------------------------------
// ApplyUserOnboarding: config save error (L939-943)
// ---------------------------------------------------------------------------

func TestFSC_ApplyUserOnboarding_GUIConfigSaveError(t *testing.T) {
	tmpDir := t.TempDir()

	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	policy := config.DefaultPolicy()
	require.NoError(t, config.WritePolicyHMAC(policy, testSOPin, hmacPath))

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigDir(tmpDir)

	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	svc.SetConfigSaveFunc(func(_ *GUIConfigData) error {
		return fmt.Errorf("disk full")
	})

	var eventLog []*events.Event
	svc.SetEventEmitter(func(e events.Event) {
		eventLog = append(eventLog, &e)
	})

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	svc.SetPINService(pinSvc)

	// Set up unified config.
	cfgPath := config.ConfigPath()
	cfgDir := filepath.Dir(cfgPath)
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))
	t.Cleanup(func() { os.Remove(cfgPath) })

	result, err := svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:   testSOPin,
		UserPIN: testUserPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "GUI config save failed"))
}

// ---------------------------------------------------------------------------
// GetPolicy: success path (L992-1007)
// ---------------------------------------------------------------------------

func TestFSC_GetPolicy_Success(t *testing.T) {
	cfgPath := config.ConfigPath()
	cfgDir := filepath.Dir(cfgPath)
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	defaultCfg := config.DefaultConfig()
	require.NoError(t, config.Save(defaultCfg))
	t.Cleanup(func() { os.Remove(cfgPath) })

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	policyMap, err := svc.GetPolicy()
	require.NoError(t, err)
	require.NotNil(t, policyMap)
	_, hasVersion := policyMap["policy_version"]
	assert.True(t, hasVersion, "policy map should contain policy_version")
}

// ---------------------------------------------------------------------------
// GetPolicy: config.Load error triggered by corrupt YAML
// ---------------------------------------------------------------------------

func TestFSC_GetPolicy_ConfigLoadError(t *testing.T) {
	// Redirect config directory to a temp dir so we can write corrupt YAML
	// without affecting the real config. config.Load() reads from ConfigPath()
	// which uses ConfigDir(), so overriding it routes the read to our file.
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.ResetConfigDir() })

	// Write an invalid YAML file that will cause a parse error in config.Load().
	corruptYAML := []byte("policy:\n  - invalid: [unclosed bracket\n\ttabs mixed with spaces: bad")
	cfgPath := filepath.Join(tmpDir, "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, corruptYAML, 0600))

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	_, err := svc.GetPolicy()
	assert.Error(t, err, "GetPolicy should return error when config.Load fails due to corrupt YAML")
}

// ---------------------------------------------------------------------------
// FactoryReset: HMAC removal error (non-NotExist) (L1044-1046)
// Create a non-empty directory at the HMAC path so os.Remove fails
// with ENOTEMPTY (which is not os.IsNotExist).
// ---------------------------------------------------------------------------

func TestFSC_FactoryReset_HMACRemovalError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a non-empty directory at the HMAC path.
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(hmacPath, 0700))
	// Place a file inside so os.Remove returns ENOTEMPTY.
	require.NoError(t, os.WriteFile(filepath.Join(hmacPath, "dummy"), []byte("x"), 0600))

	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: true})
	tw.svc.SetConfigDir(tmpDir)

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	err := tw.svc.FactoryReset(testSOPin)
	// Should complete with accumulated errors.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC removal")
}

// ---------------------------------------------------------------------------
// FactoryReset: config file removal error (non-NotExist) (L1051-1053)
// Create a non-empty directory at the config file path so os.Remove
// fails with ENOTEMPTY.
// ---------------------------------------------------------------------------

func TestFSC_FactoryReset_ConfigRemovalError(t *testing.T) {
	// Redirect config directory so we can manipulate the config path.
	tmpCfgDir := t.TempDir()
	config.SetConfigDir(tmpCfgDir)
	t.Cleanup(func() { config.ResetConfigDir() })

	// Replace xkey.yaml with a non-empty directory so os.Remove fails.
	cfgFilePath := filepath.Join(tmpCfgDir, "xkey.yaml")
	require.NoError(t, os.MkdirAll(cfgFilePath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(cfgFilePath, "dummy"), []byte("x"), 0600))

	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: true})
	tw.svc.SetConfigDir(t.TempDir()) // Empty config dir for HMAC (no error there)

	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    testSOPin,
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	err := tw.svc.FactoryReset(testSOPin)
	// Should complete with accumulated errors.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config removal")
}

// ---------------------------------------------------------------------------
// ApplySetup: barrier success with BestStrategy
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_BarrierSuccessWithBestStrategy(t *testing.T) {
	tmpDir := t.TempDir()
	tw := newTestSetupWizard(&GUIConfigData{})

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "test-barrier-pw",
		SealerBackend:   "software",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	savedCfg := tw.configFunc()
	assert.True(t, savedCfg.BarrierInitialized)
	assert.Equal(t, "software", savedCfg.BarrierStrategy)
}

// ---------------------------------------------------------------------------
// ApplySetup: setup completed event with server mode and barrier
// ---------------------------------------------------------------------------

func TestFSC_ApplySetup_SetupCompletedEventPayload(t *testing.T) {
	tmpDir := t.TempDir()
	tw := newTestSetupWizard(&GUIConfigData{})

	pinMgr := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "server",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		SetHierarchyAuth: true,
		ServerAddress:    "localhost:9443",
		ServerProtocol:   "rest",
		StorageType:      "barrier",
		BarrierPassword:  "test-pw",
		SealerBackend:    "software",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	completedEvt := lastEventOfType(tw.eventLog, events.EventSetupCompleted)
	require.NotNil(t, completedEvt)
	payload, ok := completedEvt.Payload.(events.SetupCompletedPayload)
	require.True(t, ok)
	assert.Equal(t, "server", payload.Mode)
	assert.True(t, payload.BarrierInitialized)
	assert.Equal(t, "software", payload.BarrierStrategy)
	assert.True(t, payload.UserPINSet)
	assert.True(t, payload.SOPINSet)
}

// ---------------------------------------------------------------------------
// TestSetupCov_* prefix tests targeting remaining uncovered lines
// ---------------------------------------------------------------------------

// TestSetupCov_TPMSealedPasswordProtection covers the tpm_sealed path in
// ApplySetup step 8. When barrier is unavailable and PasswordStoreMode is
// "tpm_sealed", ppSvc.SetModeTPMSealed() is invoked.
func TestSetupCov_TPMSealedPasswordProtection(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock TPM that supports sealing for the PasswordProtectionService.
	ppMockTPM := &sealMockTPM{
		mockTPM: *defaultMockTPM(),
		canSeal: true,
	}

	// Create a SealService for the PasswordProtectionService.
	ppSealSvc := NewSealService(filepath.Join(tmpDir, "pp-seals"))
	wireSealMockClient(ppSealSvc, ppMockTPM)
	ppSealSvc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return ppMockTPM
	}))
	ppSealSvc.SetContext(context.Background())

	// Create the PasswordProtectionService backed by the working SealService.
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	staticPWSvc := NewStaticPasswordService(store)
	staticPWSvc.SetContext(context.Background())

	configPath := filepath.Join(tmpDir, "encryption.json")
	ppSvc := NewPasswordProtectionService(configPath, staticPWSvc, ppSealSvc)
	ppSvc.SetContext(context.Background())

	// Wire up the setup wizard WITHOUT barrier service — this forces the
	// tpm_sealed code path in step 8 (barrier takes precedence when available).
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetPasswordProtectionService(ppSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             testSOPin,
		UserPin:           testUserPin,
		StorageType:       "barrier",
		BarrierPassword:   "testbarrier123",
		PasswordStoreMode: "tpm_sealed",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Barrier is unavailable (barrierSvc nil), so the tpm_sealed path runs.
	// platform policy service is also nil → warning expected.
	assert.True(t, containsSubstring(result.Warnings, "platform policy"),
		"expected platform policy warning, got warnings=%v", result.Warnings)
	assert.True(t, containsSubstring(result.Warnings, "barrier service unavailable"),
		"expected barrier service unavailable warning, got warnings=%v", result.Warnings)
}

// TestSetupCov_TPMSealedUserPinSealSuccess covers the success path
// at L471 in ApplySetup where SealData succeeds for user_pin.
func TestSetupCov_TPMSealedUserPinSealSuccess(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a working mock TPM.
	mockTPMInst := &sealMockTPM{
		mockTPM: *defaultMockTPM(),
		canSeal: true,
	}

	// Shared SealService for both PP and wizard.
	sealSvc := NewSealService(filepath.Join(tmpDir, "seals"))
	wireSealMockClient(sealSvc, mockTPMInst)
	sealSvc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return mockTPMInst
	}))
	sealSvc.SetContext(context.Background())

	// PlatformPolicyService.
	policyPath := filepath.Join(tmpDir, "platform_policy.json")
	policyMock := &mockTPM{
		device: "/dev/tpmrm0",
		pcrBanks: []tpm2pkg.PCRBank{{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA}},
				{ID: 7, Value: []byte{0xBB}},
			},
		}},
	}
	ppPolicySvc := NewPlatformPolicyService(policyPath)
	ppPolicySvc.SetContext(context.Background())
	ppPolicySvc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return policyMock
	}))
	_, err := ppPolicySvc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)
	sealSvc.SetPlatformPolicyService(ppPolicySvc)

	// PasswordProtectionService.
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	staticPWSvc := NewStaticPasswordService(store)
	staticPWSvc.SetContext(context.Background())

	configPath := filepath.Join(tmpDir, "encryption.json")
	ppSvc := NewPasswordProtectionService(configPath, staticPWSvc, sealSvc)
	ppSvc.SetContext(context.Background())

	// Wire up the setup wizard with the SAME working SealService.
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetPasswordProtectionService(ppSvc)
	tw.svc.SetSealService(sealSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             testSOPin,
		UserPin:           testUserPin,
		StorageType:       "barrier",
		BarrierPassword:   "testbarrier123",
		PasswordStoreMode: "tpm_sealed",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Both SetModeTPMSealed and user_pin seal should succeed.
	// No warnings about user_pin seal.
	for _, w := range result.Warnings {
		assert.NotContains(t, w, "user_pin seal:",
			"user_pin seal should succeed, got warning: %s", w)
	}
}

// TestSetupCov_SkipSetup_InitDataDirFails covers the SkipSetup path where
// initDataDirFunc returns an error (L588-591).
func TestSetupCov_SkipSetup_InitDataDirFails(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetInitDataDirFunc(func() error {
		return errors.New("permission denied")
	})
	err := tw.svc.SkipSetup()
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

// TestSetupCov_SkipSetup_ConfigSaveFails covers the SkipSetup path where
// configSave returns an error (L596-598).
func TestSetupCov_SkipSetup_ConfigSaveFails(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	svc.SetConfigSaveFunc(func(_ *GUIConfigData) error {
		return errors.New("write error")
	})

	err := svc.SkipSetup()
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

// TestSetupCov_SkipSetup_Success covers the full SkipSetup success path
// including initDataDir, config save, and event emission (L577-607).
func TestSetupCov_SkipSetup_Success(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetInitDataDirFunc(func() error { return nil })

	err := tw.svc.SkipSetup()
	require.NoError(t, err)

	cfg := tw.configFunc()
	assert.True(t, cfg.SetupComplete)

	// Verify skip event was emitted.
	require.NotEmpty(t, *tw.eventLog)
	lastEvt := (*tw.eventLog)[len(*tw.eventLog)-1]
	assert.Equal(t, events.EventSetupSkipped, lastEvt.Type)
}

// TestSetupCov_GetStartupState_SetupNotComplete_EnterpriseMode covers
// GetStartupState (L646-693) with enterprise mode (HMAC file present)
// and setup not complete.
func TestSetupCov_GetStartupState_EnterpriseUserOnboarding(t *testing.T) {
	tmpDir := t.TempDir()

	// Create HMAC file for enterprise mode.
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.WriteFile(hmacPath, []byte("hmac-data"), 0600))

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigDir(tmpDir)
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})

	// PINService without manager -> GetPINStatus returns error,
	// so UserPINSet stays false -> "user_onboarding" mode.
	pinSvc := NewPINService()
	svc.SetPINService(pinSvc)

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
	assert.True(t, state.EnterpriseMode)
	assert.Equal(t, "user_onboarding", state.EnterpriseWizardMode)
}

// TestSetupCov_GetStartupState_SOProvisioning covers GetStartupState when
// configDir is set, no HMAC file exists, and setup is not complete.
func TestSetupCov_GetStartupState_SOProvisioning(t *testing.T) {
	tmpDir := t.TempDir()

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigDir(tmpDir) // No HMAC file -> not enterprise mode.
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
	assert.False(t, state.EnterpriseMode)
	assert.Equal(t, "so_provisioning", state.EnterpriseWizardMode)
}

// TestSetupCov_GetStartupState_Complete covers GetStartupState when
// setup is already complete.
func TestSetupCov_GetStartupState_Complete(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: true}
	})

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.SetupComplete)
	assert.Empty(t, state.EnterpriseWizardMode)
}

// TestSetupCov_GetStartupState_WithPINStatus covers GetStartupState with
// a working PINService that returns PIN status.
func TestSetupCov_GetStartupState_WithPINStatus(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: true}
	})

	pinMgr := &wizardMockPINBackend{
		strategy:   pin.StrategySoftware,
		soPINSet:   true,
		userPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	svc.SetPINService(pinSvc)

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.SOPINSet)
	assert.True(t, state.UserPINSet)
}

// TestSetupCov_GetStartupState_NilConfigFunc covers GetStartupState when
// configFunc is nil (L658 branch not taken).
func TestSetupCov_GetStartupState_NilConfigFunc(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
}

// TestSetupCov_ApplySetup_InitDataDirFails covers the initDataDirFunc
// error path in ApplySetup (L372-377).
func TestSetupCov_ApplySetup_InitDataDirFails(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetInitDataDirFunc(func() error {
		return errors.New("cannot create data dir")
	})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "testbarrier123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "data directory initialization failed"))
}

// fscSealer is a minimal types.Sealer for testing.
type fscSealer struct {
	canSeal bool
	sealErr error
}

func (s *fscSealer) CanSeal() bool { return s.canSeal }
func (s *fscSealer) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	if s.sealErr != nil {
		return nil, s.sealErr
	}
	return &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		Ciphertext: data,
	}, nil
}
func (s *fscSealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return sealed.Ciphertext, nil
}

// ---------------------------------------------------------------------------
// ProbeEnvironment regression tests — TPM device detection & backend listing
// ---------------------------------------------------------------------------

func TestProbeEnvironment_TPMDeviceExists_Available(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetTPMStatusFunc(func() (bool, bool, bool) {
		return true, true, false // deviceExists=true, available=true
	})

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.True(t, probe.TPMAvailable)
	assert.True(t, probe.TPMDeviceExists)
}

func TestProbeEnvironment_TPMDeviceExists_NotAvailable(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetTPMStatusFunc(func() (bool, bool, bool) {
		return true, false, false // deviceExists=true, available=false
	})

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.False(t, probe.TPMAvailable)
	assert.True(t, probe.TPMDeviceExists)
}

func TestProbeEnvironment_NoTPMDevice(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetTPMStatusFunc(func() (bool, bool, bool) {
		return false, false, false
	})

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.False(t, probe.TPMAvailable)
	assert.False(t, probe.TPMDeviceExists)
}

func TestProbeEnvironment_NilTPMStatusFunc(t *testing.T) {
	svc := NewSetupWizardService()
	// No tpmStatusFn set.
	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.False(t, probe.TPMAvailable)
	assert.False(t, probe.TPMDeviceExists)
}

func TestProbeEnvironment_TPMDevicePath_FromTPMService(t *testing.T) {
	svc := NewSetupWizardService()
	tpmSvc := NewTPMService()
	tpmSvc.SetDevicePath("/dev/tpm0")
	svc.SetTPMService(tpmSvc)

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.Equal(t, "/dev/tpm0", probe.TPMDevicePath)
}

func TestProbeEnvironment_AvailableBackends_WithAdminService(t *testing.T) {
	svc := NewSetupWizardService()

	// Create an admin service that returns a static backend list.
	adminSvc := NewAdminService()
	adminSvc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return []BackendInfo{
			{ID: "software", Type: "software", Enabled: true},
			{ID: "tpm2", Type: "tpm2", Enabled: true},
		}, nil
	})
	svc.SetAdminService(adminSvc)

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	require.Len(t, probe.AvailableBackends, 2)
	assert.Equal(t, "software", probe.AvailableBackends[0].ID)
	assert.Equal(t, "tpm2", probe.AvailableBackends[1].ID)
}

func TestProbeEnvironment_AvailableBackends_NilAdminService(t *testing.T) {
	svc := NewSetupWizardService()
	// No admin service set.
	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.Empty(t, probe.AvailableBackends)
}

func TestSetupWizardService_SetAdminService(t *testing.T) {
	svc := NewSetupWizardService()
	assert.Nil(t, svc.adminSvc)

	adminSvc := NewAdminService()
	svc.SetAdminService(adminSvc)
	assert.NotNil(t, svc.adminSvc)
}
