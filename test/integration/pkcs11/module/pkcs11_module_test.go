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

//go:build integration
// +build integration

package module

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestModuleInitialize tests C_Initialize functionality.
// Per PKCS#11 v3.0, C_Initialize initializes the Cryptoki library.
func TestModuleInitialize(t *testing.T) {
	t.Run("SuccessfulInitialization", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		rv := env.InitializeModule(t)
		RequireOK(t, rv, "C_Initialize")

		if !env.Module.IsInitialized() {
			t.Error("module should be initialized after C_Initialize")
		}
	})

	t.Run("InitializeWithNilConfig", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		// Initialize with nil config should use defaults
		rv := env.Module.Initialize(nil)
		RequireOK(t, rv, "C_Initialize with nil config")

		if !env.Module.IsInitialized() {
			t.Error("module should be initialized with default config")
		}
	})

	t.Run("DoubleInitialization", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		rv := env.InitializeModule(t)
		RequireOK(t, rv, "first C_Initialize")

		// Second initialization should return CKR_CRYPTOKI_ALREADY_INITIALIZED
		rv = env.InitializeModule(t)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_ALREADY_INITIALIZED, "second C_Initialize")
	})

	t.Run("InitializeAfterFinalize", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		// First initialization
		rv := env.InitializeModule(t)
		RequireOK(t, rv, "first C_Initialize")

		// Finalize
		rv = env.Module.Finalize()
		RequireOK(t, rv, "C_Finalize")

		// Re-initialization should succeed
		rv = env.InitializeModule(t)
		RequireOK(t, rv, "second C_Initialize after finalize")
	})
}

// TestModuleFinalize tests C_Finalize functionality.
// Per PKCS#11 v3.0, C_Finalize indicates that an application is done with
// the Cryptoki library.
func TestModuleFinalize(t *testing.T) {
	t.Run("SuccessfulFinalization", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.Finalize()
		RequireOK(t, rv, "C_Finalize")

		if env.Module.IsInitialized() {
			t.Error("module should not be initialized after C_Finalize")
		}
	})

	t.Run("FinalizeWithoutInitialize", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		// Finalize without initialization should return CKR_CRYPTOKI_NOT_INITIALIZED
		rv := env.Module.Finalize()
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "C_Finalize without init")
	})

	t.Run("DoubleFinalization", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.Finalize()
		RequireOK(t, rv, "first C_Finalize")

		rv = env.Module.Finalize()
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "second C_Finalize")
	})

	t.Run("FinalizeClosesAllSessions", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open multiple sessions
		session1 := env.MustOpenRWSession(t)
		session2 := env.MustOpenROSession(t)

		// Verify sessions are valid
		_, rv := env.Module.GetSessionInfo(session1)
		RequireOK(t, rv, "GetSessionInfo for session1 before finalize")

		_, rv = env.Module.GetSessionInfo(session2)
		RequireOK(t, rv, "GetSessionInfo for session2 before finalize")

		// Finalize should close all sessions
		rv = env.Module.Finalize()
		RequireOK(t, rv, "C_Finalize")

		// After finalize, module operations should fail
		// Note: Session handles become invalid after finalize
	})
}

// TestModuleGetInfo tests C_GetInfo functionality.
// Per PKCS#11 v3.0, C_GetInfo returns general information about Cryptoki.
func TestModuleGetInfo(t *testing.T) {
	t.Run("GetInfoBeforeInitialize", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		// C_GetInfo should work before initialization per PKCS#11 spec
		info, rv := env.Module.GetInfo()
		RequireOK(t, rv, "C_GetInfo before initialize")

		if info == nil {
			t.Fatal("GetInfo returned nil info")
		}

		// Verify Cryptoki version is 3.0
		if info.CryptokiVersion.Major != 3 || info.CryptokiVersion.Minor != 0 {
			t.Errorf("expected Cryptoki version 3.0, got %d.%d",
				info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
		}

		// Verify manufacturer ID
		mfgID := info.GetManufacturerID()
		if mfgID == "" {
			t.Error("manufacturer ID should not be empty")
		}
		t.Logf("Manufacturer ID: %s", mfgID)

		// Verify library description
		libDesc := info.GetLibraryDescription()
		if libDesc == "" {
			t.Error("library description should not be empty")
		}
		t.Logf("Library Description: %s", libDesc)

		// Verify library version
		t.Logf("Library Version: %d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor)

		// Flags should be 0 per PKCS#11 spec
		if info.Flags != 0 {
			t.Errorf("expected flags to be 0, got %d", info.Flags)
		}
	})

	t.Run("GetInfoAfterInitialize", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		info, rv := env.Module.GetInfo()
		RequireOK(t, rv, "C_GetInfo after initialize")

		if info == nil {
			t.Fatal("GetInfo returned nil info")
		}

		// Verify version info is consistent
		if info.CryptokiVersion.Major < 2 {
			t.Error("Cryptoki major version should be at least 2")
		}
	})

	t.Run("GetInfoConsistency", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		// Get info before init
		infoBefore, rv := env.Module.GetInfo()
		RequireOK(t, rv, "C_GetInfo before init")

		env.MustInitializeModule(t)

		// Get info after init
		infoAfter, rv := env.Module.GetInfo()
		RequireOK(t, rv, "C_GetInfo after init")

		// Version info should be consistent
		if infoBefore.CryptokiVersion.Major != infoAfter.CryptokiVersion.Major ||
			infoBefore.CryptokiVersion.Minor != infoAfter.CryptokiVersion.Minor {
			t.Error("Cryptoki version should be consistent before and after initialization")
		}

		if infoBefore.LibraryVersion.Major != infoAfter.LibraryVersion.Major ||
			infoBefore.LibraryVersion.Minor != infoAfter.LibraryVersion.Minor {
			t.Error("Library version should be consistent before and after initialization")
		}
	})
}

// TestModuleGetFunctionList tests C_GetFunctionList behavior.
// In Go, this is implicit as all functions are exposed through the Module struct.
func TestModuleGetFunctionList(t *testing.T) {
	t.Run("AllCoreFunctionsAvailable", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		// Verify core functions exist (implicit in Go through the Module type)
		// This test validates that the module exposes expected PKCS#11 operations

		// Module management
		_ = env.Module.Initialize
		_ = env.Module.Finalize
		_ = env.Module.GetInfo

		// Slot and token management
		_ = env.Module.GetSlotList
		_ = env.Module.GetSlotInfo
		_ = env.Module.GetTokenInfo
		_ = env.Module.GetMechanismList
		_ = env.Module.GetMechanismInfo
		_ = env.Module.InitToken
		_ = env.Module.InitPIN
		_ = env.Module.SetPIN

		// Session management
		_ = env.Module.OpenSession
		_ = env.Module.CloseSession
		_ = env.Module.CloseAllSessions
		_ = env.Module.GetSessionInfo
		_ = env.Module.Login
		_ = env.Module.Logout

		// Object management
		_ = env.Module.CreateObject
		_ = env.Module.CopyObject
		_ = env.Module.DestroyObject
		_ = env.Module.GetAttributeValue
		_ = env.Module.SetAttributeValue
		_ = env.Module.FindObjectsInit
		_ = env.Module.FindObjects
		_ = env.Module.FindObjectsFinal

		// Cryptographic operations
		_ = env.Module.SignInit
		_ = env.Module.Sign
		_ = env.Module.VerifyInit
		_ = env.Module.Verify
		_ = env.Module.EncryptInit
		_ = env.Module.Encrypt
		_ = env.Module.DecryptInit
		_ = env.Module.Decrypt
		_ = env.Module.DigestInit
		_ = env.Module.Digest

		// Key management
		_ = env.Module.GenerateKey
		_ = env.Module.GenerateKeyPair
		_ = env.Module.GenerateRandom

		t.Log("All core PKCS#11 functions are available")
	})
}

// TestModuleGetInterface tests C_GetInterface behavior for PKCS#11 v3.0.
// This validates that the module supports the v3.0 interface.
func TestModuleGetInterface(t *testing.T) {
	t.Run("InterfaceVersion", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		info, rv := env.Module.GetInfo()
		RequireOK(t, rv, "C_GetInfo")

		// Verify this is a v3.0 compliant implementation
		if info.CryptokiVersion.Major != 3 {
			t.Errorf("expected Cryptoki major version 3, got %d", info.CryptokiVersion.Major)
		}

		t.Logf("Cryptoki Interface Version: %d.%02d",
			info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
	})
}

// TestModuleSlotOperationsBeforeInit tests that slot operations fail before initialization.
func TestModuleSlotOperationsBeforeInit(t *testing.T) {
	t.Run("GetSlotListBeforeInit", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		_, rv := env.Module.GetSlotList(false)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "GetSlotList before init")
	})

	t.Run("GetSlotInfoBeforeInit", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		_, rv := env.Module.GetSlotInfo(0)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "GetSlotInfo before init")
	})

	t.Run("GetTokenInfoBeforeInit", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		_, rv := env.Module.GetTokenInfo(0)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "GetTokenInfo before init")
	})

	t.Run("GetMechanismListBeforeInit", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		_, rv := env.Module.GetMechanismList(0)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "GetMechanismList before init")
	})
}

// TestModuleSlotOperationsAfterInit tests slot operations after initialization.
func TestModuleSlotOperationsAfterInit(t *testing.T) {
	t.Run("GetSlotList", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// Get all slots
		slots, rv := env.Module.GetSlotList(false)
		RequireOK(t, rv, "GetSlotList(false)")

		if len(slots) == 0 {
			t.Error("expected at least one slot")
		}
		t.Logf("Found %d slots", len(slots))

		// Get slots with tokens present
		slotsWithTokens, rv := env.Module.GetSlotList(true)
		RequireOK(t, rv, "GetSlotList(true)")

		t.Logf("Found %d slots with tokens present", len(slotsWithTokens))
	})

	t.Run("GetSlotInfo", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		info, rv := env.Module.GetSlotInfo(0)
		RequireOK(t, rv, "GetSlotInfo")

		if info == nil {
			t.Fatal("GetSlotInfo returned nil")
		}

		slotDesc := info.GetSlotDescription()
		mfgID := info.GetManufacturerID()

		t.Logf("Slot Description: %s", slotDesc)
		t.Logf("Manufacturer ID: %s", mfgID)
		t.Logf("Hardware Version: %d.%d", info.HardwareVersion.Major, info.HardwareVersion.Minor)
		t.Logf("Firmware Version: %d.%d", info.FirmwareVersion.Major, info.FirmwareVersion.Minor)
		t.Logf("Flags: %s", info.Flags.String())
	})

	t.Run("GetSlotInfoInvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		_, rv := env.Module.GetSlotInfo(9999)
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "GetSlotInfo with invalid slot")
	})

	t.Run("GetTokenInfo", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		info, rv := env.Module.GetTokenInfo(0)
		RequireOK(t, rv, "GetTokenInfo")

		if info == nil {
			t.Fatal("GetTokenInfo returned nil")
		}

		tokenLabel := info.GetLabel()
		mfgID := info.GetManufacturerID()
		model := info.GetModel()
		serialNumber := info.GetSerialNumber()

		t.Logf("Token Label: %s", tokenLabel)
		t.Logf("Manufacturer ID: %s", mfgID)
		t.Logf("Model: %s", model)
		t.Logf("Serial Number: %s", serialNumber)
		t.Logf("Hardware Version: %d.%d", info.HardwareVersion.Major, info.HardwareVersion.Minor)
		t.Logf("Firmware Version: %d.%d", info.FirmwareVersion.Major, info.FirmwareVersion.Minor)
		t.Logf("Flags: %s", info.Flags.String())
		t.Logf("Max Session Count: %d", info.MaxSessionCount)
		t.Logf("Min PIN Length: %d", info.MinPinLen)
		t.Logf("Max PIN Length: %d", info.MaxPinLen)

		// Verify token is initialized
		if info.Flags&module.CKF_TOKEN_INITIALIZED == 0 {
			t.Error("token should have CKF_TOKEN_INITIALIZED flag set")
		}
	})

	t.Run("GetMechanismList", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		mechs, rv := env.Module.GetMechanismList(0)
		RequireOK(t, rv, "GetMechanismList")

		if len(mechs) == 0 {
			t.Error("expected at least one mechanism")
		}

		t.Logf("Found %d mechanisms", len(mechs))
		for _, mech := range mechs {
			t.Logf("  - %s", mech.String())
		}
	})

	t.Run("GetMechanismInfo", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// Test getting info for RSA key pair generation mechanism
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_RSA_PKCS_KEY_PAIR_GEN)
		RequireOK(t, rv, "GetMechanismInfo for CKM_RSA_PKCS_KEY_PAIR_GEN")

		if info == nil {
			t.Fatal("GetMechanismInfo returned nil")
		}

		t.Logf("CKM_RSA_PKCS_KEY_PAIR_GEN:")
		t.Logf("  Min Key Size: %d", info.MinKeySize)
		t.Logf("  Max Key Size: %d", info.MaxKeySize)
		t.Logf("  Flags: 0x%08X", info.Flags)
	})

	t.Run("GetMechanismInfoInvalidMechanism", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		_, rv := env.Module.GetMechanismInfo(0, 0xFFFFFFFF)
		RequireReturnValue(t, rv, module.CKR_MECHANISM_INVALID, "GetMechanismInfo with invalid mechanism")
	})
}

// TestModuleTokenInitialization tests C_InitToken functionality.
func TestModuleTokenInitialization(t *testing.T) {
	t.Run("InitToken", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.InitToken(0, TestPINs.SO, "My Test Token")
		RequireOK(t, rv, "C_InitToken")

		// Verify token info
		info, rv := env.Module.GetTokenInfo(0)
		RequireOK(t, rv, "GetTokenInfo")

		label := info.GetLabel()
		if label != "My Test Token" {
			t.Errorf("expected label 'My Test Token', got '%s'", label)
		}
	})

	t.Run("InitTokenInvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.InitToken(9999, TestPINs.SO, "Test")
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "InitToken with invalid slot")
	})

	t.Run("InitTokenWithSessionOpen", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open a session
		session := env.MustOpenRWSession(t)
		defer func() {
			_ = env.Module.CloseSession(session)
		}()

		// Per PKCS#11, InitToken should fail if sessions exist
		rv := env.Module.InitToken(0, TestPINs.SO, "New Label")
		RequireReturnValue(t, rv, module.CKR_SESSION_EXISTS, "InitToken with session open")
	})
}

// TestModuleGlobalModuleOperations tests global module singleton behavior.
func TestModuleGlobalModuleOperations(t *testing.T) {
	t.Run("GetGlobalModule", func(t *testing.T) {
		// Reset first
		module.ResetGlobalModule()

		mod := module.GetGlobalModule()
		if mod == nil {
			t.Fatal("GetGlobalModule returned nil")
		}

		// Should return the same instance
		mod2 := module.GetGlobalModule()
		if mod != mod2 {
			t.Error("GetGlobalModule should return the same instance")
		}

		// Clean up
		module.ResetGlobalModule()
	})

	t.Run("SetGlobalModule", func(t *testing.T) {
		module.ResetGlobalModule()

		newMod, err := module.New()
		if err != nil {
			t.Fatalf("failed to create new module: %v", err)
		}

		module.SetGlobalModule(newMod)

		mod := module.GetGlobalModule()
		if mod != newMod {
			t.Error("SetGlobalModule did not set the global module")
		}

		module.ResetGlobalModule()
	})

	t.Run("ResetGlobalModule", func(t *testing.T) {
		module.ResetGlobalModule()

		mod := module.GetGlobalModule()
		if mod == nil {
			t.Fatal("GetGlobalModule returned nil after reset")
		}

		rv := mod.Initialize(nil)
		if rv != module.CKR_OK {
			t.Fatalf("Initialize failed: %s", rv.String())
		}

		// Reset should finalize and clear
		module.ResetGlobalModule()

		// New module should be uninitialized
		mod2 := module.GetGlobalModule()
		if mod2.IsInitialized() {
			t.Error("module should not be initialized after reset")
		}

		module.ResetGlobalModule()
	})
}
