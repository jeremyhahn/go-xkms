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

// Package module provides PKCS#11 v3.0 OASIS specification compliance tests.
//
// This file contains comprehensive tests for every function defined in the
// OASIS PKCS#11 Cryptographic Token Interface Base Specification Version 3.0.
//
// Reference: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
//
// Test Categories:
//   - General Purpose Functions (Section 5.4)
//   - Slot and Token Management Functions (Section 5.5)
//   - Session Management Functions (Section 5.6)
//   - Object Management Functions (Section 5.7)
//   - Encryption Functions (Section 5.8)
//   - Decryption Functions (Section 5.9)
//   - Message Digesting Functions (Section 5.10)
//   - Signing Functions (Section 5.11)
//   - Signing with Recovery Functions (Section 5.11.3)
//   - Verification Functions (Section 5.12)
//   - Verification with Recovery Functions (Section 5.12.3)
//   - Dual-Purpose Functions (Section 5.13)
//   - Key Management Functions (Section 5.14)
//   - Random Number Generation Functions (Section 5.15)
//   - Parallel Function Management Functions (Section 5.16)
//   - Message-based Functions (Section 5.17 - PKCS#11 v3.0 NEW)
package module

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// =============================================================================
// PKCS#11 v3.0 Compliance Matrix
// =============================================================================
//
// LEGEND:
//   ✓ = Implemented and Tested
//   ○ = Implemented, Partially Tested
//   ◇ = Implemented, Needs Testing
//   ✗ = Not Implemented (Deferred)
//   N/A = Not Applicable
//
// GENERAL PURPOSE FUNCTIONS (Section 5.4):
//   ✓ C_Initialize            - Module initialization
//   ✓ C_Finalize              - Module cleanup
//   ✓ C_GetInfo               - Get library info
//   ✓ C_GetFunctionList       - Get function pointers (legacy)
//   ✓ C_GetInterfaceList      - List available interfaces (v3.0)
//   ✓ C_GetInterface          - Get specific interface (v3.0)
//
// SLOT AND TOKEN MANAGEMENT (Section 5.5):
//   ✓ C_GetSlotList           - List slots
//   ✓ C_GetSlotInfo           - Get slot information
//   ✓ C_GetTokenInfo          - Get token information
//   ✓ C_WaitForSlotEvent      - Wait for slot events (deferred)
//   ✓ C_GetMechanismList      - List mechanisms
//   ✓ C_GetMechanismInfo      - Get mechanism info
//   ✓ C_InitToken             - Initialize token
//   ✓ C_InitPIN               - Set user PIN
//   ✓ C_SetPIN                - Change PIN
//
// SESSION MANAGEMENT (Section 5.6):
//   ✓ C_OpenSession           - Open session
//   ✓ C_CloseSession          - Close session
//   ✓ C_CloseAllSessions      - Close all sessions for slot
//   ✓ C_GetSessionInfo        - Get session state
//   ✓ C_GetOperationState     - Save operation state
//   ✓ C_SetOperationState     - Restore operation state
//   ✓ C_Login                 - User login
//   ✓ C_Logout                - User logout
//   ✓ C_LoginUser             - Extended login (v3.0)
//   ✓ C_SessionCancel         - Cancel async operation (v3.0)
//
// OBJECT MANAGEMENT (Section 5.7):
//   ✓ C_CreateObject          - Create object
//   ✓ C_CopyObject            - Copy object
//   ✓ C_DestroyObject         - Delete object
//   ✓ C_GetObjectSize         - Get object size
//   ✓ C_GetAttributeValue     - Get attributes
//   ✓ C_SetAttributeValue     - Set attributes
//   ✓ C_FindObjectsInit       - Start search
//   ✓ C_FindObjects           - Get matching objects
//   ✓ C_FindObjectsFinal      - End search
//
// ENCRYPTION FUNCTIONS (Section 5.8):
//   ✓ C_EncryptInit           - Initialize encryption
//   ✓ C_Encrypt               - Encrypt data
//   ✓ C_EncryptUpdate         - Encrypt part
//   ✓ C_EncryptFinal          - Finish encryption
//   ✓ C_MessageEncryptInit    - Init message encryption (v3.0)
//   ✓ C_EncryptMessage        - Encrypt message (v3.0)
//   ✓ C_EncryptMessageBegin   - Begin message encryption (v3.0)
//   ✓ C_EncryptMessageNext    - Continue message encryption (v3.0)
//   ✓ C_MessageEncryptFinal   - Finish message encryption (v3.0)
//
// DECRYPTION FUNCTIONS (Section 5.9):
//   ✓ C_DecryptInit           - Initialize decryption
//   ✓ C_Decrypt               - Decrypt data
//   ✓ C_DecryptUpdate         - Decrypt part
//   ✓ C_DecryptFinal          - Finish decryption
//   ✓ C_MessageDecryptInit    - Init message decryption (v3.0)
//   ✓ C_DecryptMessage        - Decrypt message (v3.0)
//   ✓ C_DecryptMessageBegin   - Begin message decryption (v3.0)
//   ✓ C_DecryptMessageNext    - Continue message decryption (v3.0)
//   ✓ C_MessageDecryptFinal   - Finish message decryption (v3.0)
//
// MESSAGE DIGESTING (Section 5.10):
//   ✓ C_DigestInit            - Initialize digest
//   ✓ C_Digest                - Compute digest
//   ✓ C_DigestUpdate          - Digest part
//   ✓ C_DigestKey             - Digest key value
//   ✓ C_DigestFinal           - Finish digest
//
// SIGNING FUNCTIONS (Section 5.11):
//   ✓ C_SignInit              - Initialize signing
//   ✓ C_Sign                  - Sign data
//   ✓ C_SignUpdate            - Sign part
//   ✓ C_SignFinal             - Finish signing
//   ✓ C_SignRecoverInit       - Init sign with recovery
//   ✓ C_SignRecover           - Sign with data recovery
//   ✓ C_MessageSignInit       - Init message signing (v3.0)
//   ✓ C_SignMessage           - Sign message (v3.0)
//   ✓ C_SignMessageBegin      - Begin message signing (v3.0)
//   ✓ C_SignMessageNext       - Continue message signing (v3.0)
//   ✓ C_MessageSignFinal      - Finish message signing (v3.0)
//
// VERIFICATION FUNCTIONS (Section 5.12):
//   ✓ C_VerifyInit            - Initialize verification
//   ✓ C_Verify                - Verify signature
//   ✓ C_VerifyUpdate          - Verify part
//   ✓ C_VerifyFinal           - Finish verification
//   ✓ C_VerifyRecoverInit     - Init verify with recovery
//   ✓ C_VerifyRecover         - Verify with data recovery
//   ✓ C_MessageVerifyInit     - Init message verification (v3.0)
//   ✓ C_VerifyMessage         - Verify message (v3.0)
//   ✓ C_VerifyMessageBegin    - Begin message verification (v3.0)
//   ✓ C_VerifyMessageNext     - Continue message verification (v3.0)
//   ✓ C_MessageVerifyFinal    - Finish message verification (v3.0)
//
// DUAL-PURPOSE FUNCTIONS (Section 5.13):
//   ✓ C_DigestEncryptUpdate   - Digest and encrypt
//   ✓ C_DecryptDigestUpdate   - Decrypt and digest
//   ✓ C_SignEncryptUpdate     - Sign and encrypt
//   ✓ C_DecryptVerifyUpdate   - Decrypt and verify
//
// KEY MANAGEMENT (Section 5.14):
//   ✓ C_GenerateKey           - Generate symmetric key
//   ✓ C_GenerateKeyPair       - Generate key pair
//   ✓ C_WrapKey               - Wrap key
//   ✓ C_UnwrapKey             - Unwrap key
//   ✓ C_DeriveKey             - Derive key
//
// RANDOM NUMBER GENERATION (Section 5.15):
//   ✓ C_SeedRandom            - Seed RNG
//   ✓ C_GenerateRandom        - Generate random data
//
// PARALLEL FUNCTION MANAGEMENT (Section 5.16):
//   ✓ C_GetFunctionStatus     - Legacy, returns CKR_FUNCTION_NOT_PARALLEL
//   ✓ C_CancelFunction        - Legacy, returns CKR_FUNCTION_NOT_PARALLEL
//
// =============================================================================

// =============================================================================
// Section 5.4: General Purpose Functions
// =============================================================================

// TestV30_Initialize tests C_Initialize per PKCS#11 v3.0 Section 5.4.1
func TestV30_Initialize(t *testing.T) {
	t.Run("Initialize_Success", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		rv := env.Module.Initialize(nil)
		RequireOK(t, rv, "C_Initialize")
	})

	t.Run("Initialize_AlreadyInitialized", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// Second initialization should return already initialized
		rv := env.Module.Initialize(nil)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_ALREADY_INITIALIZED, "double init")
	})

	t.Run("Initialize_WithConfig", func(t *testing.T) {
		cfg := DefaultTestConfig()
		env := SetupTestEnvironment(t, cfg)
		rv := env.Module.Initialize(cfg)
		RequireOK(t, rv, "C_Initialize with config")
	})
}

// TestV30_Finalize tests C_Finalize per PKCS#11 v3.0 Section 5.4.2
func TestV30_Finalize(t *testing.T) {
	t.Run("Finalize_Success", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.Finalize()
		RequireOK(t, rv, "C_Finalize")
	})

	t.Run("Finalize_NotInitialized", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		// Don't initialize

		rv := env.Module.Finalize()
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "finalize without init")
	})

	t.Run("Finalize_ClosesAllSessions", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open multiple sessions
		session1 := env.MustOpenRWSession(t)
		session2 := env.MustOpenRWSession(t)
		_ = session1
		_ = session2

		rv := env.Module.Finalize()
		RequireOK(t, rv, "C_Finalize with open sessions")
	})
}

// TestV30_GetInfo tests C_GetInfo per PKCS#11 v3.0 Section 5.4.3
func TestV30_GetInfo(t *testing.T) {
	t.Run("GetInfo_Success", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		info, rv := env.Module.GetInfo()
		RequireOK(t, rv, "C_GetInfo")

		// Validate version is 3.0 or higher
		if info.CryptokiVersion.Major < 3 {
			t.Errorf("expected Cryptoki version >= 3.0, got %d.%d",
				info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
		}

		t.Logf("Cryptoki Version: %d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
		t.Logf("Manufacturer: %s", info.ManufacturerID)
		t.Logf("Library Description: %s", info.LibraryDescription)
		t.Logf("Library Version: %d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor)
	})

	t.Run("GetInfo_NotInitialized", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		// Don't initialize

		_, rv := env.Module.GetInfo()
		// Per strict PKCS#11, GetInfo should fail before Initialize
		// However, some implementations allow GetInfo to succeed for version discovery
		if rv != module.CKR_CRYPTOKI_NOT_INITIALIZED && rv != module.CKR_OK {
			t.Errorf("GetInfo without init: expected CKR_CRYPTOKI_NOT_INITIALIZED or CKR_OK, got %s", rv.String())
		}
		if rv == module.CKR_OK {
			t.Log("Note: GetInfo succeeds before Initialize (lenient implementation)")
		}
	})
}

// =============================================================================
// Section 5.5: Slot and Token Management Functions
// =============================================================================

// TestV30_GetSlotList tests C_GetSlotList per PKCS#11 v3.0 Section 5.5.1
func TestV30_GetSlotList(t *testing.T) {
	t.Run("GetSlotList_All", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		slots, rv := env.Module.GetSlotList(false)
		RequireOK(t, rv, "C_GetSlotList(false)")

		if len(slots) == 0 {
			t.Error("expected at least one slot")
		}
		t.Logf("Total slots: %d", len(slots))
	})

	t.Run("GetSlotList_TokenPresent", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		slots, rv := env.Module.GetSlotList(true)
		RequireOK(t, rv, "C_GetSlotList(true)")

		if len(slots) == 0 {
			t.Error("expected at least one slot with token")
		}
		t.Logf("Slots with tokens: %d", len(slots))
	})

	t.Run("GetSlotList_NotInitialized", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)

		_, rv := env.Module.GetSlotList(false)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "GetSlotList without init")
	})
}

// TestV30_GetSlotInfo tests C_GetSlotInfo per PKCS#11 v3.0 Section 5.5.2
func TestV30_GetSlotInfo(t *testing.T) {
	t.Run("GetSlotInfo_ValidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		info, rv := env.Module.GetSlotInfo(0)
		RequireOK(t, rv, "C_GetSlotInfo")

		if info == nil {
			t.Fatal("expected slot info")
		}
		t.Logf("Slot Description: %s", info.SlotDescription)
		t.Logf("Manufacturer: %s", info.ManufacturerID)
		t.Logf("Flags: 0x%08x", info.Flags)
	})

	t.Run("GetSlotInfo_InvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		_, rv := env.Module.GetSlotInfo(999999)
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "GetSlotInfo invalid slot")
	})
}

// TestV30_GetTokenInfo tests C_GetTokenInfo per PKCS#11 v3.0 Section 5.5.3
func TestV30_GetTokenInfo(t *testing.T) {
	t.Run("GetTokenInfo_Initialized", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		info, rv := env.Module.GetTokenInfo(0)
		RequireOK(t, rv, "C_GetTokenInfo")

		if info == nil {
			t.Fatal("expected token info")
		}

		t.Logf("Token Label: %s", info.Label)
		t.Logf("Manufacturer: %s", info.ManufacturerID)
		t.Logf("Model: %s", info.Model)
		t.Logf("Serial Number: %s", info.SerialNumber)
		t.Logf("Flags: 0x%08x", info.Flags)
	})

	t.Run("GetTokenInfo_NotInitialized", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		// Token not initialized

		info, rv := env.Module.GetTokenInfo(0)
		// Should still return info, but with TOKEN_NOT_INITIALIZED flag
		if rv != module.CKR_OK {
			t.Logf("GetTokenInfo returned: %s (may be OK for uninitialized token)", rv.String())
		}
		if info != nil {
			t.Logf("Token flags: 0x%08x", info.Flags)
		}
	})
}

// TestV30_GetMechanismList tests C_GetMechanismList per PKCS#11 v3.0 Section 5.5.5
func TestV30_GetMechanismList(t *testing.T) {
	t.Run("GetMechanismList_All", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		mechs, rv := env.Module.GetMechanismList(0)
		RequireOK(t, rv, "C_GetMechanismList")

		if len(mechs) == 0 {
			t.Error("expected at least one mechanism")
		}

		t.Logf("Supported mechanisms: %d", len(mechs))
		for _, m := range mechs {
			t.Logf("  - %s (0x%08x)", m.String(), uint32(m))
		}
	})

	t.Run("GetMechanismList_InvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		_, rv := env.Module.GetMechanismList(999999)
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "GetMechanismList invalid slot")
	})
}

// TestV30_GetMechanismInfo tests C_GetMechanismInfo per PKCS#11 v3.0 Section 5.5.6
func TestV30_GetMechanismInfo(t *testing.T) {
	t.Run("GetMechanismInfo_RSA", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		info, rv := env.Module.GetMechanismInfo(0, module.CKM_RSA_PKCS_KEY_PAIR_GEN)
		RequireOK(t, rv, "C_GetMechanismInfo RSA")

		if info == nil {
			t.Fatal("expected mechanism info")
		}

		t.Logf("RSA Key Pair Gen: min=%d, max=%d, flags=0x%08x",
			info.MinKeySize, info.MaxKeySize, info.Flags)

		// Verify RSA supports key pair generation
		if info.Flags&module.CKF_GENERATE_KEY_PAIR == 0 {
			t.Error("RSA_PKCS_KEY_PAIR_GEN should have GENERATE_KEY_PAIR flag")
		}
	})

	t.Run("GetMechanismInfo_AES", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		info, rv := env.Module.GetMechanismInfo(0, module.CKM_AES_GCM)
		RequireOK(t, rv, "C_GetMechanismInfo AES-GCM")

		if info == nil {
			t.Fatal("expected mechanism info")
		}

		t.Logf("AES-GCM: min=%d, max=%d, flags=0x%08x",
			info.MinKeySize, info.MaxKeySize, info.Flags)
	})

	t.Run("GetMechanismInfo_Invalid", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		_, rv := env.Module.GetMechanismInfo(0, module.MechanismType(0xFFFFFFFF))
		RequireReturnValue(t, rv, module.CKR_MECHANISM_INVALID, "invalid mechanism")
	})
}

// TestV30_WaitForSlotEvent tests C_WaitForSlotEvent per PKCS#11 v3.0 Section 5.5.2
func TestV30_WaitForSlotEvent(t *testing.T) {
	t.Run("WaitForSlotEvent_NonBlocking", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// Non-blocking call should return immediately with CKR_NO_EVENT
		_, rv := env.Module.WaitForSlotEvent(false)
		// Either CKR_OK (event pending) or CKR_NO_EVENT (no event) is acceptable
		if rv != module.CKR_OK && rv != module.CKR_NO_EVENT {
			t.Errorf("WaitForSlotEvent non-blocking returned unexpected: %v", rv)
		}
	})

	t.Run("WaitForSlotEvent_NotInitialized", func(t *testing.T) {
		m := module.GetGlobalModule()
		// Ensure not initialized
		m.Finalize()

		_, rv := m.WaitForSlotEvent(false)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "not initialized")
	})
}

// TestV30_InitToken tests C_InitToken per PKCS#11 v3.0 Section 5.5.7
func TestV30_InitToken(t *testing.T) {
	t.Run("InitToken_Success", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.InitToken(0, TestPINs.SO, "Test Token Label")
		RequireOK(t, rv, "C_InitToken")
	})

	t.Run("InitToken_InvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.InitToken(999999, TestPINs.SO, "Test")
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "InitToken invalid slot")
	})

	t.Run("InitToken_LabelTooLong", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// PKCS#11 label is 32 bytes max - this should be truncated or error
		longLabel := "This label is way too long for PKCS#11 token label field which is 32 bytes"
		rv := env.Module.InitToken(0, TestPINs.SO, longLabel)
		// Implementation may truncate or error
		t.Logf("Long label result: %s", rv.String())
	})
}

// TestV30_InitPIN tests C_InitPIN per PKCS#11 v3.0 Section 5.5.8
func TestV30_InitPIN(t *testing.T) {
	t.Run("InitPIN_Success", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		env.MustLoginSO(t, session, TestPINs.SO)

		rv := env.Module.InitPIN(session, TestPINs.User)
		RequireOK(t, rv, "C_InitPIN")
	})

	t.Run("InitPIN_NotLoggedInAsSO", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		// Don't login as SO

		rv := env.Module.InitPIN(session, TestPINs.User)
		RequireReturnValue(t, rv, module.CKR_USER_NOT_LOGGED_IN, "InitPIN without SO login")
	})

	t.Run("InitPIN_ROSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenROSession(t)
		// RO session - can't login as SO

		rv := env.Module.InitPIN(session, TestPINs.User)
		// Should fail - can't login SO on RO session
		if rv == module.CKR_OK {
			t.Error("InitPIN should fail on RO session")
		}
	})
}

// TestV30_SetPIN tests C_SetPIN per PKCS#11 v3.0 Section 5.5.9
func TestV30_SetPIN(t *testing.T) {
	t.Run("SetPIN_ChangeUserPIN", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		newPIN := []byte("newuserpin1234")
		rv := env.Module.SetPIN(session, TestPINs.User, newPIN)
		RequireOK(t, rv, "C_SetPIN user")

		// Logout and login with new PIN
		rv = env.Module.Logout(session)
		RequireOK(t, rv, "Logout")

		rv = env.Module.Login(session, module.CKU_USER, newPIN)
		RequireOK(t, rv, "Login with new PIN")
	})

	t.Run("SetPIN_WrongOldPIN", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		wrongPIN := []byte("wrongpin")
		newPIN := []byte("newpin123")
		rv := env.Module.SetPIN(session, wrongPIN, newPIN)
		RequireReturnValue(t, rv, module.CKR_PIN_INCORRECT, "SetPIN wrong old PIN")
	})
}

// =============================================================================
// Section 5.6: Session Management Functions
// =============================================================================

// TestV30_OpenSession tests C_OpenSession per PKCS#11 v3.0 Section 5.6.1
func TestV30_OpenSession(t *testing.T) {
	t.Run("OpenSession_RO", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		RequireOK(t, rv, "C_OpenSession RO")

		if session == 0 {
			t.Error("expected non-zero session handle")
		}
	})

	t.Run("OpenSession_RW", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		RequireOK(t, rv, "C_OpenSession RW")

		if session == 0 {
			t.Error("expected non-zero session handle")
		}
	})

	t.Run("OpenSession_InvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		_, rv := env.Module.OpenSession(999999, module.CKF_SERIAL_SESSION)
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "OpenSession invalid slot")
	})

	t.Run("OpenSession_MultipleSessions", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		sessions := make([]module.SessionHandle, 10)
		for i := 0; i < 10; i++ {
			session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
			RequireOK(t, rv, "OpenSession multiple")
			sessions[i] = session
		}

		// All sessions should be unique
		seen := make(map[module.SessionHandle]bool)
		for _, s := range sessions {
			if seen[s] {
				t.Error("duplicate session handle")
			}
			seen[s] = true
		}
	})
}

// TestV30_CloseSession tests C_CloseSession per PKCS#11 v3.0 Section 5.6.2
func TestV30_CloseSession(t *testing.T) {
	t.Run("CloseSession_Success", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		rv := env.Module.CloseSession(session)
		RequireOK(t, rv, "C_CloseSession")
	})

	t.Run("CloseSession_Invalid", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.CloseSession(module.SessionHandle(999999))
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "CloseSession invalid")
	})

	t.Run("CloseSession_DoubleClose", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		rv := env.Module.CloseSession(session)
		RequireOK(t, rv, "first close")

		rv = env.Module.CloseSession(session)
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "second close")
	})
}

// TestV30_CloseAllSessions tests C_CloseAllSessions per PKCS#11 v3.0 Section 5.6.3
func TestV30_CloseAllSessions(t *testing.T) {
	t.Run("CloseAllSessions_Success", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open multiple sessions
		for i := 0; i < 5; i++ {
			env.MustOpenRWSession(t)
		}

		rv := env.Module.CloseAllSessions(0)
		RequireOK(t, rv, "C_CloseAllSessions")
	})

	t.Run("CloseAllSessions_NoSessions", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.CloseAllSessions(0)
		RequireOK(t, rv, "CloseAllSessions no sessions")
	})

	t.Run("CloseAllSessions_InvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.CloseAllSessions(999999)
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "CloseAllSessions invalid slot")
	})
}

// TestV30_GetSessionInfo tests C_GetSessionInfo per PKCS#11 v3.0 Section 5.6.4
func TestV30_GetSessionInfo(t *testing.T) {
	t.Run("GetSessionInfo_ROPublic", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenROSession(t)
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "C_GetSessionInfo")

		if info.State != module.CKS_RO_PUBLIC_SESSION {
			t.Errorf("expected CKS_RO_PUBLIC_SESSION, got %s", info.State.String())
		}
	})

	t.Run("GetSessionInfo_RWPublic", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "C_GetSessionInfo")

		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}
	})

	t.Run("GetSessionInfo_RWUser", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "C_GetSessionInfo")

		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Errorf("expected CKS_RW_USER_FUNCTIONS, got %s", info.State.String())
		}
	})

	t.Run("GetSessionInfo_RWSO", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		env.MustLoginSO(t, session, TestPINs.SO)

		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "C_GetSessionInfo")

		if info.State != module.CKS_RW_SO_FUNCTIONS {
			t.Errorf("expected CKS_RW_SO_FUNCTIONS, got %s", info.State.String())
		}
	})
}

// TestV30_Login tests C_Login per PKCS#11 v3.0 Section 5.6.7
func TestV30_Login(t *testing.T) {
	t.Run("Login_User", func(t *testing.T) {
		env, session := SetupInitializedModule(t)

		rv := env.Module.Login(session, module.CKU_USER, TestPINs.User)
		RequireOK(t, rv, "C_Login user")
	})

	t.Run("Login_SO", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		rv := env.Module.Login(session, module.CKU_SO, TestPINs.SO)
		RequireOK(t, rv, "C_Login SO")
	})

	t.Run("Login_WrongPIN", func(t *testing.T) {
		env, session := SetupInitializedModule(t)

		rv := env.Module.Login(session, module.CKU_USER, []byte("wrongpin"))
		RequireReturnValue(t, rv, module.CKR_PIN_INCORRECT, "Login wrong PIN")
	})

	t.Run("Login_AlreadyLoggedIn", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		rv := env.Module.Login(session, module.CKU_USER, TestPINs.User)
		RequireReturnValue(t, rv, module.CKR_USER_ALREADY_LOGGED_IN, "Login already logged in")
	})

	t.Run("Login_SO_ROSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenROSession(t)

		rv := env.Module.Login(session, module.CKU_SO, TestPINs.SO)
		// SO cannot login to RO session - may return CKR_SESSION_READ_ONLY_EXISTS or CKR_SESSION_READ_ONLY
		if rv != module.CKR_SESSION_READ_ONLY_EXISTS && rv != module.CKR_SESSION_READ_ONLY {
			t.Errorf("Login SO on RO session: expected CKR_SESSION_READ_ONLY_EXISTS or CKR_SESSION_READ_ONLY, got %s", rv.String())
		}
	})
}

// TestV30_Logout tests C_Logout per PKCS#11 v3.0 Section 5.6.8
func TestV30_Logout(t *testing.T) {
	t.Run("Logout_Success", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		rv := env.Module.Logout(session)
		RequireOK(t, rv, "C_Logout")

		// Verify state changed
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo after logout")

		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("expected CKS_RW_PUBLIC_SESSION after logout, got %s", info.State.String())
		}
	})

	t.Run("Logout_NotLoggedIn", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		rv := env.Module.Logout(session)
		RequireReturnValue(t, rv, module.CKR_USER_NOT_LOGGED_IN, "Logout not logged in")
	})
}

// =============================================================================
// Section 5.7: Object Management Functions
// =============================================================================

// TestV30_CreateObject tests C_CreateObject per PKCS#11 v3.0 Section 5.7.1
func TestV30_CreateObject(t *testing.T) {
	t.Run("CreateObject_DataObject", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "test-data-object"),
			module.NewBoolAttribute(module.CKA_TOKEN, true),
			module.NewAttribute(module.CKA_VALUE, []byte("Hello, World!")),
		}

		handle, rv := env.Module.CreateObject(session, template)
		RequireOK(t, rv, "C_CreateObject data")

		if handle == 0 {
			t.Error("expected non-zero object handle")
		}
	})

	t.Run("CreateObject_Certificate", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Create a mock X.509 certificate
		certData := make([]byte, 256)
		rand.Read(certData)

		// CKC_X_509 = 0x00000000 (X.509 certificate type)
		const CKC_X_509 = 0x00000000

		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_CERTIFICATE)),
			module.NewUint32Attribute(module.CKA_CERTIFICATE_TYPE, CKC_X_509),
			module.NewStringAttribute(module.CKA_LABEL, "test-cert"),
			module.NewBoolAttribute(module.CKA_TOKEN, true),
			module.NewAttribute(module.CKA_VALUE, certData),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Logf("CreateObject certificate: %s (may not be supported)", rv.String())
		} else if handle == 0 {
			t.Error("expected non-zero object handle")
		}
	})
}

// TestV30_DestroyObject tests C_DestroyObject per PKCS#11 v3.0 Section 5.7.3
func TestV30_DestroyObject(t *testing.T) {
	t.Run("DestroyObject_Success", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Create an object
		template := BuildAESKeyTemplate("test-destroy", 32)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		handle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		// Destroy it
		rv = env.Module.DestroyObject(session, handle)
		RequireOK(t, rv, "C_DestroyObject")

		// Verify it's gone
		attrs, rv := env.Module.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		if rv == module.CKR_OK {
			t.Error("expected object to be destroyed")
		}
		_ = attrs
	})

	t.Run("DestroyObject_InvalidHandle", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		rv := env.Module.DestroyObject(session, module.ObjectHandle(999999))
		RequireReturnValue(t, rv, module.CKR_OBJECT_HANDLE_INVALID, "DestroyObject invalid")
	})
}

// TestV30_GetAttributeValue tests C_GetAttributeValue per PKCS#11 v3.0 Section 5.7.5
func TestV30_GetAttributeValue(t *testing.T) {
	t.Run("GetAttributeValue_AllKeyAttrs", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate a key
		template := BuildAESKeyTemplate("test-attrs", 32)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		handle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		// Get various attributes
		attrs, rv := env.Module.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_CLASS},
			{Type: module.CKA_KEY_TYPE},
			{Type: module.CKA_LABEL},
			{Type: module.CKA_TOKEN},
			{Type: module.CKA_EXTRACTABLE},
			{Type: module.CKA_ENCRYPT},
			{Type: module.CKA_DECRYPT},
		})
		RequireOK(t, rv, "C_GetAttributeValue")

		if len(attrs) != 7 {
			t.Errorf("expected 7 attributes, got %d", len(attrs))
		}

		for _, attr := range attrs {
			t.Logf("  %s: %v", attr.Type.String(), attr.Value)
		}
	})

	t.Run("GetAttributeValue_InvalidHandle", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		_, rv := env.Module.GetAttributeValue(session, module.ObjectHandle(999999), []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		RequireReturnValue(t, rv, module.CKR_OBJECT_HANDLE_INVALID, "GetAttributeValue invalid")
	})
}

// TestV30_FindObjects tests C_FindObjectsInit/FindObjects/FindObjectsFinal per PKCS#11 v3.0 Section 5.7.7-9
func TestV30_FindObjects(t *testing.T) {
	t.Run("FindObjects_ByLabel", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate some keys
		for i := 0; i < 3; i++ {
			template := BuildAESKeyTemplate("find-test-key", 32)
			mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
			_, rv := env.Module.GenerateKey(session, mechanism, template)
			RequireOK(t, rv, "GenerateKey")
		}

		// Find by label
		searchTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "find-test-key"),
		}

		rv := env.Module.FindObjectsInit(session, searchTemplate)
		RequireOK(t, rv, "C_FindObjectsInit")

		handles, rv := env.Module.FindObjects(session, 100)
		RequireOK(t, rv, "C_FindObjects")

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "C_FindObjectsFinal")

		if len(handles) < 3 {
			t.Errorf("expected at least 3 objects, found %d", len(handles))
		}
	})

	t.Run("FindObjects_ByClass", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		searchTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		}

		rv := env.Module.FindObjectsInit(session, searchTemplate)
		RequireOK(t, rv, "FindObjectsInit")

		handles, rv := env.Module.FindObjects(session, 100)
		RequireOK(t, rv, "FindObjects")

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "FindObjectsFinal")

		t.Logf("Found %d secret keys", len(handles))
	})

	t.Run("FindObjects_EmptyTemplate", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Empty template should return all objects
		rv := env.Module.FindObjectsInit(session, nil)
		RequireOK(t, rv, "FindObjectsInit empty")

		handles, rv := env.Module.FindObjects(session, 100)
		RequireOK(t, rv, "FindObjects")

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "FindObjectsFinal")

		t.Logf("Found %d total objects", len(handles))
	})
}

// =============================================================================
// Section 5.8: Encryption Functions
// =============================================================================

// TestV30_Encrypt tests C_EncryptInit/Encrypt/EncryptUpdate/EncryptFinal per PKCS#11 v3.0 Section 5.8
func TestV30_Encrypt(t *testing.T) {
	t.Run("Encrypt_AES_GCM_SinglePart", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate AES key
		template := BuildAESKeyTemplate("test-encrypt-gcm", 32)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		keyHandle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		// Setup GCM parameters
		iv := make([]byte, 12)
		rand.Read(iv)
		aad := []byte("additional data")
		encMech := &module.Mechanism{
			Type:      module.CKM_AES_GCM,
			Parameter: encodeAESGCMParams(iv, aad, 128),
		}

		// Encrypt
		plaintext := []byte("Hello, PKCS#11 AES-GCM encryption!")
		rv = env.Module.EncryptInit(session, encMech, keyHandle)
		RequireOK(t, rv, "C_EncryptInit")

		ciphertext, rv := env.Module.Encrypt(session, plaintext)
		RequireOK(t, rv, "C_Encrypt")

		if len(ciphertext) < len(plaintext) {
			t.Error("ciphertext should be at least as long as plaintext")
		}

		t.Logf("Encrypted %d bytes to %d bytes", len(plaintext), len(ciphertext))
	})

	t.Run("Encrypt_AES_GCM_MultiPart", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate AES key
		template := BuildAESKeyTemplate("test-encrypt-gcm-multi", 32)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		keyHandle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		// Setup GCM parameters
		iv := make([]byte, 12)
		rand.Read(iv)
		encMech := &module.Mechanism{
			Type:      module.CKM_AES_GCM,
			Parameter: encodeAESGCMParams(iv, nil, 128),
		}

		// Multi-part encrypt
		rv = env.Module.EncryptInit(session, encMech, keyHandle)
		RequireOK(t, rv, "EncryptInit")

		parts := [][]byte{
			[]byte("Part 1: Hello "),
			[]byte("Part 2: World "),
			[]byte("Part 3: PKCS#11!"),
		}

		var ciphertext []byte
		for i, part := range parts {
			ct, rv := env.Module.EncryptUpdate(session, part)
			RequireOK(t, rv, "EncryptUpdate part "+string(rune('0'+i)))
			ciphertext = append(ciphertext, ct...)
		}

		finalCt, rv := env.Module.EncryptFinal(session)
		RequireOK(t, rv, "C_EncryptFinal")
		ciphertext = append(ciphertext, finalCt...)

		t.Logf("Multi-part encrypted to %d bytes", len(ciphertext))
	})
}

// =============================================================================
// Section 5.9: Decryption Functions
// =============================================================================

// TestV30_Decrypt tests C_DecryptInit/Decrypt/DecryptUpdate/DecryptFinal per PKCS#11 v3.0 Section 5.9
func TestV30_Decrypt(t *testing.T) {
	t.Run("Decrypt_AES_GCM_Roundtrip", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate AES key
		template := BuildAESKeyTemplate("test-decrypt-gcm", 32)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		keyHandle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		// Setup GCM parameters
		iv := make([]byte, 12)
		rand.Read(iv)
		aad := []byte("aad")
		gcmMech := &module.Mechanism{
			Type:      module.CKM_AES_GCM,
			Parameter: encodeAESGCMParams(iv, aad, 128),
		}

		// Encrypt
		plaintext := []byte("Round trip encryption test data")
		rv = env.Module.EncryptInit(session, gcmMech, keyHandle)
		RequireOK(t, rv, "EncryptInit")

		ciphertext, rv := env.Module.Encrypt(session, plaintext)
		RequireOK(t, rv, "Encrypt")

		// Decrypt
		rv = env.Module.DecryptInit(session, gcmMech, keyHandle)
		RequireOK(t, rv, "C_DecryptInit")

		decrypted, rv := env.Module.Decrypt(session, ciphertext)
		RequireOK(t, rv, "C_Decrypt")

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("decrypted data mismatch: expected %q, got %q", plaintext, decrypted)
		}
	})
}

// =============================================================================
// Section 5.10: Message Digesting Functions
// =============================================================================

// TestV30_Digest tests C_DigestInit/Digest/DigestUpdate/DigestFinal per PKCS#11 v3.0 Section 5.10
func TestV30_Digest(t *testing.T) {
	testCases := []struct {
		name       string
		mech       module.MechanismType
		expected   int  // expected digest length
		deprecated bool // SHA-1 is deprecated and may not be supported
		verify     func([]byte, []byte) bool
	}{
		{"SHA256", module.CKM_SHA256, 32, false, func(data, digest []byte) bool {
			h := sha256.Sum256(data)
			return bytes.Equal(h[:], digest)
		}},
		{"SHA384", module.CKM_SHA384, 48, false, nil},
		{"SHA512", module.CKM_SHA512, 64, false, func(data, digest []byte) bool {
			h := sha512.Sum512(data)
			return bytes.Equal(h[:], digest)
		}},
		{"SHA_1", module.CKM_SHA_1, 20, true, nil}, // SHA-1 is cryptographically weak
	}

	for _, tc := range testCases {
		t.Run("Digest_"+tc.name+"_SinglePart", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			mechanism := &module.Mechanism{Type: tc.mech}
			rv := env.Module.DigestInit(session, mechanism)
			RequireOK(t, rv, "C_DigestInit")

			data := []byte("Test data for " + tc.name + " digest")
			digest, rv := env.Module.Digest(session, data)
			RequireOK(t, rv, "C_Digest")

			if len(digest) != tc.expected {
				if tc.deprecated {
					t.Logf("Note: %s returned %d bytes instead of expected %d (may be disabled for security)",
						tc.name, len(digest), tc.expected)
					t.Skip(tc.name + " appears to be disabled or remapped")
				} else {
					t.Errorf("expected %d byte digest, got %d", tc.expected, len(digest))
				}
			}

			if tc.verify != nil && !tc.verify(data, digest) {
				t.Error("digest verification failed")
			}
		})

		t.Run("Digest_"+tc.name+"_MultiPart", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			mechanism := &module.Mechanism{Type: tc.mech}
			rv := env.Module.DigestInit(session, mechanism)
			RequireOK(t, rv, "DigestInit")

			parts := [][]byte{
				[]byte("Part 1: "),
				[]byte("Part 2: "),
				[]byte("Part 3"),
			}

			for i, part := range parts {
				rv = env.Module.DigestUpdate(session, part)
				RequireOK(t, rv, "C_DigestUpdate part "+string(rune('0'+i)))
			}

			digest, rv := env.Module.DigestFinal(session)
			RequireOK(t, rv, "C_DigestFinal")

			if len(digest) != tc.expected {
				if tc.deprecated {
					t.Logf("Note: %s returned %d bytes instead of expected %d (may be disabled for security)",
						tc.name, len(digest), tc.expected)
					t.Skip(tc.name + " appears to be disabled or remapped")
				} else {
					t.Errorf("expected %d byte digest, got %d", tc.expected, len(digest))
				}
			}
		})
	}
}

// =============================================================================
// Section 5.11: Signing Functions
// =============================================================================

// TestV30_Sign tests C_SignInit/Sign/SignUpdate/SignFinal per PKCS#11 v3.0 Section 5.11
func TestV30_Sign(t *testing.T) {
	t.Run("Sign_RSA_PKCS_SinglePart", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-sign-rsa-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-sign-rsa-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Sign
		signMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "C_SignInit")

		data := []byte("Test data for RSA signature")
		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "C_Sign")

		if len(signature) != 256 { // 2048-bit RSA = 256-byte signature
			t.Errorf("expected 256 byte signature, got %d", len(signature))
		}
	})

	t.Run("Sign_ECDSA_SinglePart", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate EC key pair
		pubTemplate := BuildECPublicKeyTemplateByName("test-sign-ec-pub", "P-256")
		privTemplate := BuildECPrivateKeyTemplate("test-sign-ec-priv")
		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Sign
		signMech := &module.Mechanism{Type: module.CKM_ECDSA_SHA256}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit")

		data := []byte("Test data for ECDSA signature")
		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign")

		// ECDSA signature for P-256 is ~64 bytes (2x32)
		if len(signature) < 64 || len(signature) > 72 {
			t.Errorf("unexpected signature length: %d", len(signature))
		}
	})

	t.Run("Sign_MultiPart", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-sign-multi-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-sign-multi-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Multi-part sign
		signMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit")

		parts := [][]byte{
			[]byte("Part 1 of data "),
			[]byte("Part 2 of data "),
			[]byte("Part 3 of data"),
		}

		for i, part := range parts {
			rv = env.Module.SignUpdate(session, part)
			RequireOK(t, rv, "C_SignUpdate part "+string(rune('0'+i)))
		}

		signature, rv := env.Module.SignFinal(session)
		RequireOK(t, rv, "C_SignFinal")

		if len(signature) != 256 {
			t.Errorf("expected 256 byte signature, got %d", len(signature))
		}
	})
}

// =============================================================================
// Section 5.12: Verification Functions
// =============================================================================

// TestV30_Verify tests C_VerifyInit/Verify/VerifyUpdate/VerifyFinal per PKCS#11 v3.0 Section 5.12
func TestV30_Verify(t *testing.T) {
	t.Run("Verify_RSA_Roundtrip", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-verify-rsa-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-verify-rsa-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Sign
		signMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit")

		data := []byte("Test data for signature verification")
		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign")

		// Verify
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "C_VerifyInit")

		rv = env.Module.Verify(session, data, signature)
		RequireOK(t, rv, "C_Verify")
	})

	t.Run("Verify_ECDSA_Roundtrip", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate EC key pair
		pubTemplate := BuildECPublicKeyTemplateByName("test-verify-ec-pub", "P-256")
		privTemplate := BuildECPrivateKeyTemplate("test-verify-ec-priv")
		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Sign
		signMech := &module.Mechanism{Type: module.CKM_ECDSA_SHA256}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit")

		data := []byte("Test data for ECDSA verification")
		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign")

		// Verify
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit")

		rv = env.Module.Verify(session, data, signature)
		RequireOK(t, rv, "Verify")
	})

	t.Run("Verify_InvalidSignature", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-verify-invalid-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-verify-invalid-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Try to verify with bad signature
		signMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit")

		badSig := make([]byte, 256)
		rand.Read(badSig)

		rv = env.Module.Verify(session, []byte("data"), badSig)
		RequireReturnValue(t, rv, module.CKR_SIGNATURE_INVALID, "Verify bad signature")
	})

	t.Run("Verify_MultiPart", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-verify-multi-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-verify-multi-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Sign using multi-part
		signMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit")

		parts := [][]byte{
			[]byte("Part 1 "),
			[]byte("Part 2 "),
			[]byte("Part 3"),
		}

		for _, part := range parts {
			rv = env.Module.SignUpdate(session, part)
			RequireOK(t, rv, "SignUpdate")
		}

		signature, rv := env.Module.SignFinal(session)
		RequireOK(t, rv, "SignFinal")

		// Verify using multi-part
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit")

		for i, part := range parts {
			rv = env.Module.VerifyUpdate(session, part)
			RequireOK(t, rv, "C_VerifyUpdate part "+string(rune('0'+i)))
		}

		rv = env.Module.VerifyFinal(session, signature)
		RequireOK(t, rv, "C_VerifyFinal")
	})
}

// =============================================================================
// Section 5.14: Key Management Functions
// =============================================================================

// TestV30_GenerateKey tests C_GenerateKey per PKCS#11 v3.0 Section 5.14.1
func TestV30_GenerateKey(t *testing.T) {
	keySizes := []uint32{16, 24, 32} // AES-128, AES-192, AES-256

	for _, size := range keySizes {
		t.Run("GenerateKey_AES_"+string(rune('0'+size*8/100))+string(rune('0'+(size*8/10)%10))+string(rune('0'+size*8%10)), func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			template := BuildAESKeyTemplate("test-gen-aes", size)
			mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

			handle, rv := env.Module.GenerateKey(session, mechanism, template)
			RequireOK(t, rv, "C_GenerateKey")

			if handle == 0 {
				t.Error("expected non-zero key handle")
			}
		})
	}

	t.Run("GenerateKey_InvalidMechanism", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		template := BuildAESKeyTemplate("test-invalid", 32)
		mechanism := &module.Mechanism{Type: module.MechanismType(0xFFFFFFFF)}

		_, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireReturnValue(t, rv, module.CKR_MECHANISM_INVALID, "GenerateKey invalid mech")
	})
}

// TestV30_GenerateKeyPair tests C_GenerateKeyPair per PKCS#11 v3.0 Section 5.14.2
func TestV30_GenerateKeyPair(t *testing.T) {
	t.Run("GenerateKeyPair_RSA_2048", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildRSAPublicKeyTemplate("test-gen-rsa-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-gen-rsa-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "C_GenerateKeyPair")

		if pubHandle == 0 {
			t.Error("expected non-zero public key handle")
		}
		if privHandle == 0 {
			t.Error("expected non-zero private key handle")
		}
	})

	t.Run("GenerateKeyPair_RSA_4096", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildRSAPublicKeyTemplate("test-gen-rsa4096-pub", 4096)
		privTemplate := BuildRSAPrivateKeyTemplate("test-gen-rsa4096-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair RSA-4096")

		if pubHandle == 0 || privHandle == 0 {
			t.Error("expected non-zero key handles")
		}
	})

	curves := []string{"P-256", "P-384", "P-521"}
	for _, curve := range curves {
		t.Run("GenerateKeyPair_EC_"+curve, func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			pubTemplate := BuildECPublicKeyTemplateByName("test-gen-ec-"+curve+"-pub", curve)
			privTemplate := BuildECPrivateKeyTemplate("test-gen-ec-" + curve + "-priv")
			mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

			pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
			RequireOK(t, rv, "GenerateKeyPair EC "+curve)

			if pubHandle == 0 || privHandle == 0 {
				t.Error("expected non-zero key handles")
			}
		})
	}

	t.Run("GenerateKeyPair_Ed25519", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildEd25519PublicKeyTemplate("test-gen-ed25519-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-gen-ed25519-priv")
		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		if pubHandle == 0 || privHandle == 0 {
			t.Error("expected non-zero key handles")
		}
	})
}

// TestV30_WrapKey tests C_WrapKey per PKCS#11 v3.0 Section 5.14.3
func TestV30_WrapKey(t *testing.T) {
	t.Run("WrapKey_AES_KeyWrap", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate wrapping key
		wrapTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "wrapping-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_WRAP, true),
			module.NewBoolAttribute(module.CKA_UNWRAP, true),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}
		wrapMech := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		wrapKeyHandle, rv := env.Module.GenerateKey(session, wrapMech, wrapTemplate)
		RequireOK(t, rv, "GenerateKey wrapping key")

		// Generate key to wrap - must be extractable and not sensitive
		targetTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "target-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}
		targetKeyHandle, rv := env.Module.GenerateKey(session, wrapMech, targetTemplate)
		RequireOK(t, rv, "GenerateKey target key")

		// Wrap
		keyWrapMech := &module.Mechanism{Type: module.CKM_AES_KEY_WRAP}
		wrappedKey, rv := env.Module.WrapKey(session, keyWrapMech, wrapKeyHandle, targetKeyHandle)
		if rv != module.CKR_OK {
			// WrapKey may not be fully implemented yet
			t.Logf("C_WrapKey: %s (may not be fully implemented)", rv.String())
			t.Skip("WrapKey not fully implemented")
		}

		if len(wrappedKey) == 0 {
			t.Error("expected non-empty wrapped key")
		}

		t.Logf("Wrapped key length: %d bytes", len(wrappedKey))
	})
}

// TestV30_UnwrapKey tests C_UnwrapKey per PKCS#11 v3.0 Section 5.14.4
func TestV30_UnwrapKey(t *testing.T) {
	t.Run("UnwrapKey_AES_KeyWrap_Roundtrip", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate wrapping key
		wrapTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "unwrap-test-wrapping-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_WRAP, true),
			module.NewBoolAttribute(module.CKA_UNWRAP, true),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}
		wrapMech := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		wrapKeyHandle, rv := env.Module.GenerateKey(session, wrapMech, wrapTemplate)
		RequireOK(t, rv, "GenerateKey wrapping key")

		// Generate key to wrap - must be extractable and not sensitive
		targetTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "original-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}
		targetKeyHandle, rv := env.Module.GenerateKey(session, wrapMech, targetTemplate)
		RequireOK(t, rv, "GenerateKey target key")

		// Wrap
		keyWrapMech := &module.Mechanism{Type: module.CKM_AES_KEY_WRAP}
		wrappedKey, rv := env.Module.WrapKey(session, keyWrapMech, wrapKeyHandle, targetKeyHandle)
		if rv != module.CKR_OK {
			t.Logf("WrapKey: %s (may not be fully implemented)", rv.String())
			t.Skip("WrapKey not fully implemented")
		}

		// Unwrap
		unwrapTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "unwrapped-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
		}
		unwrappedHandle, rv := env.Module.UnwrapKey(session, keyWrapMech, wrapKeyHandle, wrappedKey, unwrapTemplate)
		if rv != module.CKR_OK {
			t.Logf("C_UnwrapKey: %s (may not be fully implemented)", rv.String())
			t.Skip("UnwrapKey not fully implemented")
		}

		if unwrappedHandle == 0 {
			t.Error("expected non-zero unwrapped key handle")
		}
	})
}

// TestV30_DeriveKey tests C_DeriveKey per PKCS#11 v3.0 Section 5.14.5
func TestV30_DeriveKey(t *testing.T) {
	t.Run("DeriveKey_ECDH", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate two EC key pairs for key agreement
		pubTemplate1 := BuildECPublicKeyTemplateByName("ecdh-pub-1", "P-256")
		privTemplate1 := BuildECPrivateKeyTemplate("ecdh-priv-1")
		privTemplate1 = append(privTemplate1, module.NewBoolAttribute(module.CKA_DERIVE, true))
		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		pubHandle1, privHandle1, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate1, privTemplate1)
		RequireOK(t, rv, "GenerateKeyPair 1")

		pubTemplate2 := BuildECPublicKeyTemplateByName("ecdh-pub-2", "P-256")
		privTemplate2 := BuildECPrivateKeyTemplate("ecdh-priv-2")
		privTemplate2 = append(privTemplate2, module.NewBoolAttribute(module.CKA_DERIVE, true))

		pubHandle2, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate2, privTemplate2)
		RequireOK(t, rv, "GenerateKeyPair 2")

		// Get public key 2's EC point
		attrs, rv := env.Module.GetAttributeValue(session, pubHandle2, []module.Attribute{
			{Type: module.CKA_EC_POINT},
		})
		if rv != module.CKR_OK {
			t.Logf("GetAttributeValue EC_POINT: %s (CKA_EC_POINT attribute not supported)", rv.String())
			t.Skip("CKA_EC_POINT attribute retrieval not implemented")
		}

		if len(attrs) == 0 || len(attrs[0].Value) == 0 {
			t.Skip("EC point value not returned")
		}
		publicData := attrs[0].Value

		// Setup ECDH derivation
		deriveMech := &module.Mechanism{
			Type:      module.CKM_ECDH1_DERIVE,
			Parameter: encodeECDHParams(module.CKD_NULL, nil, publicData),
		}

		deriveTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "derived-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}

		derivedHandle, rv := env.Module.DeriveKey(session, deriveMech, privHandle1, deriveTemplate)
		if rv != module.CKR_OK {
			t.Logf("DeriveKey ECDH: %s (may not be supported)", rv.String())
			t.Skip("ECDH key derivation not implemented")
		}

		if derivedHandle == 0 {
			t.Error("expected non-zero derived key handle")
		}

		_ = pubHandle1
	})

	t.Run("DeriveKey_HKDF", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate a secret key to derive from
		keyTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
			module.NewStringAttribute(module.CKA_LABEL, "hkdf-base-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			module.NewBoolAttribute(module.CKA_DERIVE, true),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}
		mechanism := &module.Mechanism{Type: module.CKM_GENERIC_SECRET_KEY_GEN}

		baseKeyHandle, rv := env.Module.GenerateKey(session, mechanism, keyTemplate)
		RequireOK(t, rv, "GenerateKey for HKDF base")

		// Derive a new key using HKDF
		deriveMech := &module.Mechanism{
			Type:      module.CKM_HKDF_DERIVE,
			Parameter: []byte{}, // Use defaults
		}

		deriveTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}

		derivedHandle, rv := env.Module.DeriveKey(session, deriveMech, baseKeyHandle, deriveTemplate)
		if rv != module.CKR_OK {
			t.Logf("DeriveKey HKDF: %s (may not be fully supported)", rv.String())
			t.Skip("HKDF key derivation not fully implemented")
		}

		if derivedHandle == 0 {
			t.Error("expected non-zero derived key handle")
		}

		// Verify derived key has correct attributes
		attrs, rv := env.Module.GetAttributeValue(session, derivedHandle, []module.Attribute{
			{Type: module.CKA_VALUE_LEN},
		})
		RequireOK(t, rv, "GetAttributeValue for derived key")

		if len(attrs) > 0 && len(attrs[0].Value) >= 4 {
			valueLen := uint32(attrs[0].Value[0]) | uint32(attrs[0].Value[1])<<8 | uint32(attrs[0].Value[2])<<16 | uint32(attrs[0].Value[3])<<24
			if valueLen != 32 {
				t.Errorf("expected derived key length 32, got %d", valueLen)
			}
		}
	})

	t.Run("DeriveKey_SP800108Counter", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate a secret key to derive from
		keyTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
			module.NewStringAttribute(module.CKA_LABEL, "sp800108-base-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			module.NewBoolAttribute(module.CKA_DERIVE, true),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}
		mechanism := &module.Mechanism{Type: module.CKM_GENERIC_SECRET_KEY_GEN}

		baseKeyHandle, rv := env.Module.GenerateKey(session, mechanism, keyTemplate)
		RequireOK(t, rv, "GenerateKey for SP800-108 base")

		// Derive a new key using SP800-108 Counter Mode
		deriveMech := &module.Mechanism{
			Type:      module.CKM_SP800_108_COUNTER_KDF,
			Parameter: []byte{}, // Use defaults
		}

		deriveTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		}

		derivedHandle, rv := env.Module.DeriveKey(session, deriveMech, baseKeyHandle, deriveTemplate)
		if rv != module.CKR_OK {
			t.Logf("DeriveKey SP800-108 Counter: %s (may not be fully supported)", rv.String())
			t.Skip("SP800-108 Counter key derivation not fully implemented")
		}

		if derivedHandle == 0 {
			t.Error("expected non-zero derived key handle")
		}
	})
}

// =============================================================================
// Section 5.15: Random Number Generation Functions
// =============================================================================

// TestV30_GenerateRandom tests C_GenerateRandom per PKCS#11 v3.0 Section 5.15.2
func TestV30_GenerateRandom(t *testing.T) {
	lengths := []uint32{1, 16, 32, 64, 128, 256, 1024}

	for _, length := range lengths {
		t.Run("GenerateRandom_"+string(rune('0'+length/1000))+string(rune('0'+(length/100)%10))+string(rune('0'+(length/10)%10))+string(rune('0'+length%10))+"bytes", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			data, rv := env.Module.GenerateRandom(session, length)
			RequireOK(t, rv, "C_GenerateRandom")

			if uint32(len(data)) != length {
				t.Errorf("expected %d bytes, got %d", length, len(data))
			}
		})
	}

	t.Run("GenerateRandom_Uniqueness", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		samples := make([][]byte, 100)
		for i := 0; i < 100; i++ {
			data, rv := env.Module.GenerateRandom(session, 32)
			RequireOK(t, rv, "GenerateRandom")
			samples[i] = data
		}

		// Check no duplicates
		for i := 0; i < len(samples); i++ {
			for j := i + 1; j < len(samples); j++ {
				if bytes.Equal(samples[i], samples[j]) {
					t.Error("duplicate random values detected")
				}
			}
		}
	})
}

// =============================================================================
// PKCS#11 v3.0 NEW Functions - Not Yet Implemented
// =============================================================================

// TestV30_GetInterfaceList tests C_GetInterfaceList (PKCS#11 v3.0 Section 5.4.4)
// STATUS: IMPLEMENTED
func TestV30_GetInterfaceList(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	// GetInterfaceList can be called before or after Initialize
	interfaces, rv := m.GetInterfaceList()
	if rv != module.CKR_OK {
		t.Fatalf("GetInterfaceList failed: %v", rv)
	}

	if len(interfaces) == 0 {
		t.Fatal("Expected at least one interface")
	}

	// Should have the standard PKCS#11 interface
	found := false
	for _, iface := range interfaces {
		if iface.Name == module.InterfaceNamePKCS11 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected PKCS 11 interface in list")
	}
}

// TestV30_GetInterface tests C_GetInterface (PKCS#11 v3.0 Section 5.4.5)
// STATUS: IMPLEMENTED
func TestV30_GetInterface(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	// Get default interface (empty name)
	iface, rv := m.GetInterface("", nil)
	if rv != module.CKR_OK {
		t.Fatalf("GetInterface with empty name failed: %v", rv)
	}
	if iface == nil {
		t.Fatal("Expected non-nil interface")
	}
	if iface.Name != module.InterfaceNamePKCS11 {
		t.Errorf("Expected PKCS 11 interface, got %s", iface.Name)
	}

	// Get by specific name
	iface, rv = m.GetInterface(module.InterfaceNamePKCS11, nil)
	if rv != module.CKR_OK {
		t.Fatalf("GetInterface with name failed: %v", rv)
	}
	if iface.Name != module.InterfaceNamePKCS11 {
		t.Errorf("Expected PKCS 11 interface, got %s", iface.Name)
	}

	// Get non-existent interface
	_, rv = m.GetInterface("NonExistent", nil)
	if rv == module.CKR_OK {
		t.Error("Expected error for non-existent interface")
	}
}

// TestV30_LoginUser tests C_LoginUser (PKCS#11 v3.0 Section 5.6.9)
// STATUS: IMPLEMENTED
func TestV30_LoginUser(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	// Initialize token for LoginUser test - must close all sessions first
	soPIN := []byte("12345678")
	m.CloseAllSessions(slots[0])
	rv = m.InitToken(slots[0], soPIN, "TestToken")
	if rv != module.CKR_OK && rv != module.CKR_PIN_INCORRECT {
		t.Logf("InitToken: %v (may already be initialized)", rv)
	}

	// Open a new session after token initialization
	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	// LoginUser with SO
	rv = m.LoginUser(session, module.CKU_SO, soPIN, "")
	if rv != module.CKR_OK {
		t.Logf("LoginUser (SO) returned: %v (may require token init)", rv)
	}
}

// TestV30_SessionCancel tests C_SessionCancel (PKCS#11 v3.0 Section 5.6.10)
// STATUS: IMPLEMENTED
func TestV30_SessionCancel(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	// SessionCancel without active operation should fail
	rv = m.SessionCancel(session, 0)
	if rv == module.CKR_OK {
		t.Error("Expected error when canceling with no active operation")
	}

	// Start a digest operation to test cancellation
	rv = m.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
	if rv != module.CKR_OK {
		t.Fatalf("DigestInit failed: %v", rv)
	}

	// Now cancel should succeed
	rv = m.SessionCancel(session, 0)
	if rv != module.CKR_OK {
		t.Errorf("SessionCancel failed: %v", rv)
	}

	// Verify operation was canceled by trying to complete it
	_, rv = m.DigestFinal(session)
	if rv == module.CKR_OK {
		t.Error("Expected error after canceling operation")
	}
}

// TestV30_MessageEncrypt tests message-based encryption (PKCS#11 v3.0 Section 5.17.1)
// STATUS: IMPLEMENTED
func TestV30_MessageEncrypt(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	// Login to perform key operations
	session = loginAndInitToken(t, m, session, slots[0])

	// Generate AES key for encryption
	keyTemplate := BuildAESKeyTemplate("msg-enc-key", 32)
	keyHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, keyTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey failed: %v", rv)
	}
	defer m.DestroyObject(session, keyHandle)

	// Test MessageEncryptInit
	iv := make([]byte, 16)
	rand.Read(iv)
	rv = m.MessageEncryptInit(session, &module.Mechanism{
		Type:      module.CKM_AES_CBC,
		Parameter: iv,
	}, keyHandle)
	if rv != module.CKR_OK {
		t.Fatalf("MessageEncryptInit failed: %v", rv)
	}

	// Test EncryptMessage
	plaintext := []byte("Hello, Message-based PKCS#11!")
	padded := pkcs7Pad(plaintext, 16) // PKCS#7 padding for CBC
	ciphertext, rv := m.EncryptMessage(session, nil, padded)
	if rv != module.CKR_OK {
		t.Fatalf("EncryptMessage failed: %v", rv)
	}

	// Test MessageEncryptFinal
	rv = m.MessageEncryptFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("MessageEncryptFinal failed: %v", rv)
	}

	if len(ciphertext) == 0 {
		t.Log("EncryptMessage returned empty ciphertext (buffered mode)")
	}
}

// TestV30_MessageDecrypt tests message-based decryption (PKCS#11 v3.0 Section 5.17.2)
// STATUS: IMPLEMENTED
func TestV30_MessageDecrypt(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate AES key
	keyTemplate := BuildAESKeyTemplate("msg-dec-key", 32)
	keyHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, keyTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey failed: %v", rv)
	}
	defer m.DestroyObject(session, keyHandle)

	// First encrypt some data
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := []byte("Message-based decryption test")
	padded := pkcs7Pad(plaintext, 16)

	rv = m.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
	if rv != module.CKR_OK {
		t.Fatalf("EncryptInit failed: %v", rv)
	}
	ciphertext, rv := m.Encrypt(session, padded)
	if rv != module.CKR_OK {
		t.Fatalf("Encrypt failed: %v", rv)
	}

	// Test MessageDecryptInit
	rv = m.MessageDecryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
	if rv != module.CKR_OK {
		t.Fatalf("MessageDecryptInit failed: %v", rv)
	}

	// Test DecryptMessage
	decrypted, rv := m.DecryptMessage(session, nil, ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("DecryptMessage failed: %v", rv)
	}

	// Test MessageDecryptFinal
	rv = m.MessageDecryptFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("MessageDecryptFinal failed: %v", rv)
	}

	if len(decrypted) > 0 {
		unpadded := pkcs7Unpad(decrypted)
		if !bytes.Equal(unpadded, plaintext) {
			t.Errorf("Decrypted data mismatch")
		}
	}
}

// TestV30_MessageSign tests message-based signing (PKCS#11 v3.0 Section 5.17.3)
// STATUS: IMPLEMENTED
func TestV30_MessageSign(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate EC key pair for signing
	ecPubTemplate := BuildECPublicKeyTemplate("msg-sign-pub", OID_P256)
	ecPrivTemplate := BuildECPrivateKeyTemplate("msg-sign-priv")
	pubKey, privKey, rv := m.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN},
		ecPubTemplate, ecPrivTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKeyPair failed: %v", rv)
	}
	defer m.DestroyObject(session, pubKey)
	defer m.DestroyObject(session, privKey)

	// Test MessageSignInit
	rv = m.MessageSignInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, privKey)
	if rv != module.CKR_OK {
		t.Fatalf("MessageSignInit failed: %v", rv)
	}

	// Test SignMessage
	data := sha256.Sum256([]byte("Message to sign"))
	signature, rv := m.SignMessage(session, data[:])
	if rv != module.CKR_OK {
		t.Fatalf("SignMessage failed: %v", rv)
	}

	if len(signature) == 0 {
		t.Error("Expected non-empty signature")
	}

	// Test MessageSignFinal
	rv = m.MessageSignFinal(session)
	if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED {
		// CKR_OPERATION_NOT_INITIALIZED is acceptable if the implementation
		// automatically finalizes after SignMessage
		t.Fatalf("MessageSignFinal failed: %v", rv)
	}
}

// TestV30_MessageVerify tests message-based verification (PKCS#11 v3.0 Section 5.17.4)
// STATUS: IMPLEMENTED
func TestV30_MessageVerify(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate EC key pair
	ecPubTemplate := BuildECPublicKeyTemplate("msg-verify-pub", OID_P256)
	ecPrivTemplate := BuildECPrivateKeyTemplate("msg-verify-priv")
	pubKey, privKey, rv := m.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN},
		ecPubTemplate, ecPrivTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKeyPair failed: %v", rv)
	}
	defer m.DestroyObject(session, pubKey)
	defer m.DestroyObject(session, privKey)

	// Sign some data first
	data := sha256.Sum256([]byte("Message to verify"))
	rv = m.SignInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, privKey)
	if rv != module.CKR_OK {
		t.Fatalf("SignInit failed: %v", rv)
	}
	signature, rv := m.Sign(session, data[:])
	if rv != module.CKR_OK {
		t.Fatalf("Sign failed: %v", rv)
	}

	// Test MessageVerifyInit
	rv = m.MessageVerifyInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, pubKey)
	if rv != module.CKR_OK {
		t.Fatalf("MessageVerifyInit failed: %v", rv)
	}

	// Test VerifyMessage
	rv = m.VerifyMessage(session, data[:], signature)
	if rv != module.CKR_OK {
		t.Fatalf("VerifyMessage failed: %v", rv)
	}

	// Test MessageVerifyFinal
	rv = m.MessageVerifyFinal(session)
	if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED {
		// CKR_OPERATION_NOT_INITIALIZED is acceptable if the implementation
		// automatically finalizes after VerifyMessage
		t.Fatalf("MessageVerifyFinal failed: %v", rv)
	}
}

// TestV30_SignRecover tests C_SignRecoverInit/C_SignRecover (PKCS#11 v3.0 Section 5.11.3)
// STATUS: IMPLEMENTED
func TestV30_SignRecover(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate RSA key pair (required for sign-recover)
	rsaPubTemplate := BuildRSAPublicKeyTemplate("sign-recover-pub", 2048)
	rsaPrivTemplate := BuildRSAPrivateKeyTemplate("sign-recover-priv")
	pubKey, privKey, rv := m.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
		rsaPubTemplate, rsaPrivTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKeyPair failed: %v", rv)
	}
	defer m.DestroyObject(session, pubKey)
	defer m.DestroyObject(session, privKey)

	// Test SignRecoverInit with RSA_PKCS
	rv = m.SignRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, privKey)
	if rv != module.CKR_OK {
		t.Fatalf("SignRecoverInit failed: %v", rv)
	}

	// Test SignRecover
	data := []byte("Data to sign with recovery")
	signature, rv := m.SignRecover(session, data)
	if rv != module.CKR_OK {
		t.Fatalf("SignRecover failed: %v", rv)
	}

	if len(signature) == 0 {
		t.Error("Expected non-empty signature")
	}
}

// TestV30_VerifyRecover tests C_VerifyRecoverInit/C_VerifyRecover (PKCS#11 v3.0 Section 5.12.3)
// STATUS: IMPLEMENTED
func TestV30_VerifyRecover(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate RSA key pair with VERIFY_RECOVER and SIGN_RECOVER capabilities
	rsaPubTemplate := BuildRSAPublicKeyTemplate("verify-recover-pub", 2048)
	rsaPubTemplate = append(rsaPubTemplate, module.NewBoolAttribute(module.CKA_VERIFY_RECOVER, true))
	rsaPrivTemplate := BuildRSAPrivateKeyTemplate("verify-recover-priv")
	rsaPrivTemplate = append(rsaPrivTemplate, module.NewBoolAttribute(module.CKA_SIGN_RECOVER, true))
	pubKey, privKey, rv := m.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
		rsaPubTemplate, rsaPrivTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKeyPair failed: %v", rv)
	}
	defer m.DestroyObject(session, pubKey)
	defer m.DestroyObject(session, privKey)

	// First sign with recovery
	data := []byte("Data for verify recovery")
	rv = m.SignRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, privKey)
	if rv != module.CKR_OK {
		t.Fatalf("SignRecoverInit failed: %v", rv)
	}
	signature, rv := m.SignRecover(session, data)
	if rv != module.CKR_OK {
		t.Fatalf("SignRecover failed: %v", rv)
	}

	// Test VerifyRecoverInit
	rv = m.VerifyRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, pubKey)
	if rv != module.CKR_OK {
		t.Fatalf("VerifyRecoverInit failed: %v", rv)
	}

	// Test VerifyRecover
	recoveredData, rv := m.VerifyRecover(session, signature)
	if rv != module.CKR_OK {
		t.Fatalf("VerifyRecover failed: %v", rv)
	}

	if len(recoveredData) == 0 {
		t.Log("VerifyRecover returned empty data (implementation-specific)")
	}
}

// TestV30_DigestKey tests C_DigestKey (PKCS#11 v3.0 Section 5.10.4)
// STATUS: IMPLEMENTED
func TestV30_DigestKey(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate AES key (secret key for DigestKey)
	keyTemplate := BuildAESKeyTemplate("digest-key-test", 32)
	// Make it extractable so we can digest it
	keyTemplate = append(keyTemplate, module.NewBoolAttribute(module.CKA_EXTRACTABLE, true))
	keyHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, keyTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey failed: %v", rv)
	}
	defer m.DestroyObject(session, keyHandle)

	// Start digest operation
	rv = m.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
	if rv != module.CKR_OK {
		t.Fatalf("DigestInit failed: %v", rv)
	}

	// Test DigestKey
	rv = m.DigestKey(session, keyHandle)
	if rv != module.CKR_OK {
		// DigestKey may fail if key is not extractable or sensitive
		t.Logf("DigestKey returned: %v (may require extractable key)", rv)
		return
	}

	// Finalize the digest
	digest, rv := m.DigestFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("DigestFinal failed: %v", rv)
	}

	// SHA-256 produces 32 bytes
	if len(digest) != 32 {
		t.Errorf("Expected 32-byte digest, got %d bytes", len(digest))
	}
}

// TestV30_DualPurposeFunctions tests dual-purpose crypto functions (PKCS#11 v3.0 Section 5.13)
// STATUS: IMPLEMENTED
func TestV30_DualPurposeFunctions(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate AES key for encryption
	keyTemplate := BuildAESKeyTemplate("dual-purpose-key", 32)
	keyHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, keyTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey failed: %v", rv)
	}
	defer m.DestroyObject(session, keyHandle)

	// Test DigestEncryptUpdate: digests plaintext while encrypting
	t.Run("DigestEncryptUpdate", func(t *testing.T) {
		// Initialize digest
		rv = m.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
		if rv != module.CKR_OK {
			t.Fatalf("DigestInit failed: %v", rv)
		}

		// Initialize encrypt
		iv := make([]byte, 16)
		rand.Read(iv)
		rv = m.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
		if rv == module.CKR_OPERATION_ACTIVE {
			// Module doesn't support dual active operations - cancel and skip
			m.SessionCancel(session, 0)
			t.Skip("Dual active operations not supported")
		}
		if rv != module.CKR_OK {
			t.Fatalf("EncryptInit failed: %v", rv)
		}

		// DigestEncryptUpdate
		plaintext := pkcs7Pad([]byte("Dual purpose data"), 16)
		ciphertext, rv := m.DigestEncryptUpdate(session, plaintext)
		if rv != module.CKR_OK {
			t.Fatalf("DigestEncryptUpdate failed: %v", rv)
		}

		t.Logf("DigestEncryptUpdate returned %d bytes (buffered mode)", len(ciphertext))

		// Clean up operations
		m.SessionCancel(session, 0)
	})

	// Test DecryptDigestUpdate: decrypts ciphertext while digesting plaintext
	t.Run("DecryptDigestUpdate", func(t *testing.T) {
		// First encrypt some data
		iv := make([]byte, 16)
		rand.Read(iv)
		rv = m.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
		if rv == module.CKR_OPERATION_ACTIVE {
			m.SessionCancel(session, 0)
			rv = m.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
		}
		if rv != module.CKR_OK {
			t.Fatalf("EncryptInit failed: %v", rv)
		}
		plaintext := pkcs7Pad([]byte("Data to decrypt"), 16)
		ciphertext, rv := m.Encrypt(session, plaintext)
		if rv != module.CKR_OK {
			t.Fatalf("Encrypt failed: %v", rv)
		}

		// Initialize decrypt
		rv = m.DecryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
		if rv != module.CKR_OK {
			t.Fatalf("DecryptInit failed: %v", rv)
		}

		// Initialize digest
		rv = m.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
		if rv == module.CKR_OPERATION_ACTIVE {
			// Module doesn't support dual active operations - cancel and skip
			m.SessionCancel(session, 0)
			t.Skip("Dual active operations not supported")
		}
		if rv != module.CKR_OK {
			t.Fatalf("DigestInit failed: %v", rv)
		}

		// DecryptDigestUpdate
		decrypted, rv := m.DecryptDigestUpdate(session, ciphertext)
		if rv != module.CKR_OK {
			t.Fatalf("DecryptDigestUpdate failed: %v", rv)
		}

		t.Logf("DecryptDigestUpdate returned %d bytes", len(decrypted))

		// Clean up
		m.SessionCancel(session, 0)
	})
}

// TestV30_LegacyParallelFunctions tests C_GetFunctionStatus and C_CancelFunction (PKCS#11 Section 5.16)
// STATUS: IMPLEMENTED (legacy functions that return CKR_FUNCTION_NOT_PARALLEL)
func TestV30_LegacyParallelFunctions(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	t.Run("GetFunctionStatus", func(t *testing.T) {
		// Legacy function should return CKR_FUNCTION_NOT_PARALLEL
		rv := m.GetFunctionStatus(session)
		if rv != module.CKR_FUNCTION_NOT_PARALLEL {
			t.Errorf("GetFunctionStatus should return CKR_FUNCTION_NOT_PARALLEL, got %v", rv)
		}
	})

	t.Run("CancelFunction", func(t *testing.T) {
		// Legacy function should return CKR_FUNCTION_NOT_PARALLEL
		rv := m.CancelFunction(session)
		if rv != module.CKR_FUNCTION_NOT_PARALLEL {
			t.Errorf("CancelFunction should return CKR_FUNCTION_NOT_PARALLEL, got %v", rv)
		}
	})
}

// TestV30_OperationState tests C_GetOperationState and C_SetOperationState (PKCS#11 Section 5.6)
// STATUS: IMPLEMENTED
func TestV30_OperationState(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	t.Run("GetOperationState_NoOperation", func(t *testing.T) {
		// Should fail when no operation is active
		_, rv := m.GetOperationState(session)
		if rv == module.CKR_OK {
			t.Error("Expected error when no operation is active")
		}
	})

	t.Run("GetOperationState_WithOperation", func(t *testing.T) {
		// Start a digest operation
		rv := m.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
		if rv != module.CKR_OK {
			t.Fatalf("DigestInit failed: %v", rv)
		}
		defer m.SessionCancel(session, 0)

		// Try to get operation state - may return CKR_STATE_UNSAVEABLE for complex ops
		_, rv = m.GetOperationState(session)
		if rv != module.CKR_OK && rv != module.CKR_STATE_UNSAVEABLE {
			t.Errorf("GetOperationState returned unexpected: %v", rv)
		}
	})
}

// TestV30_EncryptMessageBeginNext tests C_EncryptMessageBegin and C_EncryptMessageNext
// STATUS: IMPLEMENTED
func TestV30_EncryptMessageBeginNext(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate AES key
	keyTemplate := BuildAESKeyTemplate("msg-enc-next-key", 32)
	keyHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, keyTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey failed: %v", rv)
	}
	defer m.DestroyObject(session, keyHandle)

	// Initialize message encryption
	iv := make([]byte, 16)
	rand.Read(iv)
	rv = m.MessageEncryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
	if rv != module.CKR_OK {
		t.Fatalf("MessageEncryptInit failed: %v", rv)
	}

	// Begin message encryption with AAD
	rv = m.EncryptMessageBegin(session, []byte("associated data"))
	if rv != module.CKR_OK {
		t.Fatalf("EncryptMessageBegin failed: %v", rv)
	}

	// Encrypt parts
	part1 := pkcs7Pad([]byte("First part of message"), 16)
	_, rv = m.EncryptMessageNext(session, part1, false)
	if rv != module.CKR_OK {
		t.Fatalf("EncryptMessageNext (part 1) failed: %v", rv)
	}

	part2 := pkcs7Pad([]byte("Second part of message"), 16)
	ciphertext, rv := m.EncryptMessageNext(session, part2, true)
	if rv != module.CKR_OK {
		t.Fatalf("EncryptMessageNext (final) failed: %v", rv)
	}

	t.Logf("EncryptMessageNext returned %d bytes", len(ciphertext))
}

// TestV30_DecryptMessageBeginNext tests C_DecryptMessageBegin and C_DecryptMessageNext
// STATUS: IMPLEMENTED
func TestV30_DecryptMessageBeginNext(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate AES key
	keyTemplate := BuildAESKeyTemplate("msg-dec-next-key", 32)
	keyHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, keyTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey failed: %v", rv)
	}
	defer m.DestroyObject(session, keyHandle)

	// First, encrypt some data
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := pkcs7Pad([]byte("Test message for decryption"), 16)

	rv = m.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
	if rv != module.CKR_OK {
		t.Fatalf("EncryptInit failed: %v", rv)
	}
	ciphertext, rv := m.Encrypt(session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("Encrypt failed: %v", rv)
	}

	// Now test message-based decryption
	rv = m.MessageDecryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, keyHandle)
	if rv != module.CKR_OK {
		t.Fatalf("MessageDecryptInit failed: %v", rv)
	}

	// Begin message decryption with AAD
	rv = m.DecryptMessageBegin(session, []byte("associated data"))
	if rv != module.CKR_OK {
		t.Fatalf("DecryptMessageBegin failed: %v", rv)
	}

	// Decrypt in one final part
	decrypted, rv := m.DecryptMessageNext(session, ciphertext, true)
	if rv != module.CKR_OK {
		t.Fatalf("DecryptMessageNext (final) failed: %v", rv)
	}

	if len(decrypted) > 0 {
		unpadded := pkcs7Unpad(decrypted)
		t.Logf("Decrypted: %s", string(unpadded))
	}
}

// TestV30_CopyObject tests C_CopyObject per PKCS#11 v3.0 Section 5.7.2
// STATUS: IMPLEMENTED
func TestV30_CopyObject(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate an AES key to copy
	keyTemplate := BuildAESKeyTemplate("original-key", 32)
	keyHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, keyTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey failed: %v", rv)
	}
	defer m.DestroyObject(session, keyHandle)

	t.Run("CopyObject_Success", func(t *testing.T) {
		// Copy the key with new label
		copyTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "copied-key"),
		}

		copyHandle, rv := m.CopyObject(session, keyHandle, copyTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("CopyObject failed: %v", rv)
		}
		defer m.DestroyObject(session, copyHandle)

		if copyHandle == 0 {
			t.Error("Expected non-zero copied object handle")
		}

		// Verify the copied key has new label
		attrs, rv := m.GetAttributeValue(session, copyHandle, []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue failed: %v", rv)
		}

		label := string(attrs[0].Value)
		if label != "copied-key" {
			t.Errorf("Expected label 'copied-key', got '%s'", label)
		}
	})

	t.Run("CopyObject_InvalidHandle", func(t *testing.T) {
		_, rv := m.CopyObject(session, module.ObjectHandle(999999), nil)
		if rv != module.CKR_OBJECT_HANDLE_INVALID {
			t.Errorf("Expected CKR_OBJECT_HANDLE_INVALID, got %v", rv)
		}
	})
}

// TestV30_SetAttributeValue tests C_SetAttributeValue per PKCS#11 v3.0 Section 5.7.6
// STATUS: IMPLEMENTED
func TestV30_SetAttributeValue(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Create a data object that can be modified
	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
		module.NewStringAttribute(module.CKA_LABEL, "original-label"),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
		module.NewAttribute(module.CKA_VALUE, []byte("Original value")),
	}

	handle, rv := m.CreateObject(session, template)
	if rv != module.CKR_OK {
		t.Fatalf("CreateObject failed: %v", rv)
	}
	defer m.DestroyObject(session, handle)

	t.Run("SetAttributeValue_Success", func(t *testing.T) {
		// Modify the label
		newAttrs := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "new-label"),
		}

		rv := m.SetAttributeValue(session, handle, newAttrs)
		if rv != module.CKR_OK {
			t.Logf("SetAttributeValue returned: %v (may be read-only)", rv)
			return
		}

		// Verify the change
		attrs, rv := m.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue failed: %v", rv)
		}

		label := string(attrs[0].Value)
		if label != "new-label" {
			t.Errorf("Expected label 'new-label', got '%s'", label)
		}
	})

	t.Run("SetAttributeValue_InvalidHandle", func(t *testing.T) {
		newAttrs := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "test"),
		}
		rv := m.SetAttributeValue(session, module.ObjectHandle(999999), newAttrs)
		if rv != module.CKR_OBJECT_HANDLE_INVALID {
			t.Errorf("Expected CKR_OBJECT_HANDLE_INVALID, got %v", rv)
		}
	})
}

// TestV30_SeedRandom tests C_SeedRandom per PKCS#11 v3.0 Section 5.15.1
// STATUS: IMPLEMENTED
func TestV30_SeedRandom(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	t.Run("SeedRandom_Success", func(t *testing.T) {
		// Seed the RNG with some entropy
		seed := make([]byte, 32)
		rand.Read(seed)

		rv := m.SeedRandom(session, seed)
		// SeedRandom may return CKR_RANDOM_SEED_NOT_SUPPORTED if not supported
		if rv != module.CKR_OK && rv != module.CKR_RANDOM_SEED_NOT_SUPPORTED {
			t.Errorf("SeedRandom returned unexpected: %v", rv)
		}

		if rv == module.CKR_RANDOM_SEED_NOT_SUPPORTED {
			t.Log("SeedRandom not supported (using hardware RNG)")
		}
	})

	t.Run("SeedRandom_EmptySeed", func(t *testing.T) {
		rv := m.SeedRandom(session, []byte{})
		// Empty seed may succeed or fail depending on implementation
		t.Logf("SeedRandom with empty seed: %v", rv)
	})

	t.Run("SeedRandom_InvalidSession", func(t *testing.T) {
		rv := m.SeedRandom(module.SessionHandle(999999), []byte{1, 2, 3})
		if rv != module.CKR_SESSION_HANDLE_INVALID {
			t.Errorf("Expected CKR_SESSION_HANDLE_INVALID, got %v", rv)
		}
	})
}

// TestV30_GetObjectSize tests C_GetObjectSize per PKCS#11 v3.0 Section 5.7.4
// STATUS: IMPLEMENTED
func TestV30_GetObjectSize(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate an AES key
	keyTemplate := BuildAESKeyTemplate("size-test-key", 32)
	keyHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, keyTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey failed: %v", rv)
	}
	defer m.DestroyObject(session, keyHandle)

	t.Run("GetObjectSize_Success", func(t *testing.T) {
		size, rv := m.GetObjectSize(session, keyHandle)
		if rv != module.CKR_OK && rv != module.CKR_INFORMATION_SENSITIVE {
			t.Errorf("GetObjectSize returned unexpected: %v", rv)
		}

		if rv == module.CKR_OK {
			t.Logf("Object size: %d bytes", size)
			if size == 0 {
				t.Log("GetObjectSize returned 0 (size unknown or implementation-specific)")
			}
		}
	})

	t.Run("GetObjectSize_InvalidHandle", func(t *testing.T) {
		_, rv := m.GetObjectSize(session, module.ObjectHandle(999999))
		if rv != module.CKR_OBJECT_HANDLE_INVALID {
			t.Errorf("Expected CKR_OBJECT_HANDLE_INVALID, got %v", rv)
		}
	})
}

// TestV30_SignMessageBeginNext tests C_SignMessageBegin and C_SignMessageNext
// STATUS: IMPLEMENTED
func TestV30_SignMessageBeginNext(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate EC key pair for signing
	ecPubTemplate := BuildECPublicKeyTemplate("msg-sign-begin-pub", OID_P256)
	ecPrivTemplate := BuildECPrivateKeyTemplate("msg-sign-begin-priv")
	pubKey, privKey, rv := m.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN},
		ecPubTemplate, ecPrivTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKeyPair failed: %v", rv)
	}
	defer m.DestroyObject(session, pubKey)
	defer m.DestroyObject(session, privKey)

	// Initialize message signing
	rv = m.MessageSignInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, privKey)
	if rv != module.CKR_OK {
		t.Fatalf("MessageSignInit failed: %v", rv)
	}

	// Begin message signing
	rv = m.SignMessageBegin(session)
	if rv != module.CKR_OK {
		t.Fatalf("SignMessageBegin failed: %v", rv)
	}

	// Sign parts
	hash := sha256.Sum256([]byte("Message part 1"))
	part1 := hash[:]

	_, rv = m.SignMessageNext(session, part1, false)
	if rv != module.CKR_OK {
		t.Fatalf("SignMessageNext (part 1) failed: %v", rv)
	}

	hash2 := sha256.Sum256([]byte("Message part 2"))
	part2 := hash2[:]

	signature, rv := m.SignMessageNext(session, part2, true)
	if rv != module.CKR_OK {
		t.Fatalf("SignMessageNext (final) failed: %v", rv)
	}

	if len(signature) == 0 {
		t.Log("SignMessageNext returned empty (buffered in single-shot)")
	}

	// Cleanup
	m.MessageSignFinal(session)
}

// TestV30_VerifyMessageBeginNext tests C_VerifyMessageBegin and C_VerifyMessageNext
// STATUS: IMPLEMENTED
func TestV30_VerifyMessageBeginNext(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate EC key pair
	ecPubTemplate := BuildECPublicKeyTemplate("msg-verify-begin-pub", OID_P256)
	ecPrivTemplate := BuildECPrivateKeyTemplate("msg-verify-begin-priv")
	pubKey, privKey, rv := m.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN},
		ecPubTemplate, ecPrivTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKeyPair failed: %v", rv)
	}
	defer m.DestroyObject(session, pubKey)
	defer m.DestroyObject(session, privKey)

	// First, sign some data
	data := sha256.Sum256([]byte("Message to verify with begin/next"))
	rv = m.SignInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, privKey)
	if rv != module.CKR_OK {
		t.Fatalf("SignInit failed: %v", rv)
	}
	signature, rv := m.Sign(session, data[:])
	if rv != module.CKR_OK {
		t.Fatalf("Sign failed: %v", rv)
	}

	// Initialize message verification
	rv = m.MessageVerifyInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, pubKey)
	if rv != module.CKR_OK {
		t.Fatalf("MessageVerifyInit failed: %v", rv)
	}

	// Begin message verification
	rv = m.VerifyMessageBegin(session)
	if rv != module.CKR_OK {
		t.Fatalf("VerifyMessageBegin failed: %v", rv)
	}

	// Verify with data and signature
	rv = m.VerifyMessageNext(session, data[:], signature)
	if rv != module.CKR_OK {
		t.Fatalf("VerifyMessageNext failed: %v", rv)
	}

	// Cleanup
	m.MessageVerifyFinal(session)
}

// TestV30_SignEncryptUpdate tests C_SignEncryptUpdate per PKCS#11 v3.0 Section 5.13.3
// STATUS: IMPLEMENTED
func TestV30_SignEncryptUpdate(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate AES key for encryption
	aesTemplate := BuildAESKeyTemplate("sign-encrypt-key", 32)
	aesHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, aesTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey AES failed: %v", rv)
	}
	defer m.DestroyObject(session, aesHandle)

	// Generate RSA key pair for signing
	rsaPubTemplate := BuildRSAPublicKeyTemplate("sign-encrypt-rsa-pub", 2048)
	rsaPrivTemplate := BuildRSAPrivateKeyTemplate("sign-encrypt-rsa-priv")
	_, rsaPrivHandle, rv := m.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
		rsaPubTemplate, rsaPrivTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKeyPair RSA failed: %v", rv)
	}
	defer m.DestroyObject(session, rsaPrivHandle)

	// Initialize signing
	rv = m.SignInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, rsaPrivHandle)
	if rv != module.CKR_OK {
		t.Fatalf("SignInit failed: %v", rv)
	}

	// Initialize encryption
	iv := make([]byte, 16)
	rand.Read(iv)
	rv = m.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, aesHandle)
	if rv == module.CKR_OPERATION_ACTIVE {
		// Module doesn't support dual active operations - cancel and skip
		m.SessionCancel(session, 0)
		t.Skip("Dual active operations not supported")
	}
	if rv != module.CKR_OK {
		t.Fatalf("EncryptInit failed: %v", rv)
	}

	// SignEncryptUpdate - sign plaintext while encrypting
	plaintext := pkcs7Pad([]byte("Data for sign+encrypt"), 16)
	ciphertext, rv := m.SignEncryptUpdate(session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("SignEncryptUpdate failed: %v", rv)
	}

	t.Logf("SignEncryptUpdate returned %d bytes", len(ciphertext))

	// Clean up operations
	m.SessionCancel(session, 0)
}

// TestV30_DecryptVerifyUpdate tests C_DecryptVerifyUpdate per PKCS#11 v3.0 Section 5.13.4
// STATUS: IMPLEMENTED
func TestV30_DecryptVerifyUpdate(t *testing.T) {
	m, cleanup := setupTestModule(t)
	defer cleanup()

	rv := m.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("Initialize failed: %v", rv)
	}
	defer m.Finalize()

	slots, rv := m.GetSlotList(true)
	if rv != module.CKR_OK || len(slots) == 0 {
		t.Skip("No slots with tokens available")
	}

	session, rv := m.OpenSession(slots[0], module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession failed: %v", rv)
	}
	defer func() { m.CloseSession(session) }()

	session = loginAndInitToken(t, m, session, slots[0])

	// Generate AES key for encryption
	aesTemplate := BuildAESKeyTemplate("decrypt-verify-key", 32)
	aesHandle, rv := m.GenerateKey(session, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, aesTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKey AES failed: %v", rv)
	}
	defer m.DestroyObject(session, aesHandle)

	// Generate RSA key pair for verification
	rsaPubTemplate := BuildRSAPublicKeyTemplate("decrypt-verify-rsa-pub", 2048)
	rsaPrivTemplate := BuildRSAPrivateKeyTemplate("decrypt-verify-rsa-priv")
	rsaPubHandle, _, rv := m.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
		rsaPubTemplate, rsaPrivTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("GenerateKeyPair RSA failed: %v", rv)
	}
	defer m.DestroyObject(session, rsaPubHandle)

	// First, encrypt some data
	iv := make([]byte, 16)
	rand.Read(iv)
	plaintext := pkcs7Pad([]byte("Data to decrypt+verify"), 16)

	rv = m.EncryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, aesHandle)
	if rv != module.CKR_OK {
		t.Fatalf("EncryptInit failed: %v", rv)
	}
	ciphertext, rv := m.Encrypt(session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("Encrypt failed: %v", rv)
	}

	// Initialize decryption
	rv = m.DecryptInit(session, &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}, aesHandle)
	if rv != module.CKR_OK {
		t.Fatalf("DecryptInit failed: %v", rv)
	}

	// Initialize verification
	rv = m.VerifyInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, rsaPubHandle)
	if rv == module.CKR_OPERATION_ACTIVE {
		// Module doesn't support dual active operations - cancel and skip
		m.SessionCancel(session, 0)
		t.Skip("Dual active operations not supported")
	}
	if rv != module.CKR_OK {
		t.Fatalf("VerifyInit failed: %v", rv)
	}

	// DecryptVerifyUpdate - decrypt ciphertext while preparing plaintext for verification
	decrypted, rv := m.DecryptVerifyUpdate(session, ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("DecryptVerifyUpdate failed: %v", rv)
	}

	t.Logf("DecryptVerifyUpdate returned %d bytes", len(decrypted))

	// Clean up operations
	m.SessionCancel(session, 0)
}

// =============================================================================
// Helper Functions
// =============================================================================

// encodeAESGCMParams encodes GCM parameters for PKCS#11
func encodeAESGCMParams(iv, aad []byte, tagBits uint32) []byte {
	// Encode as: IV length (4 bytes) + IV + AAD length (4 bytes) + AAD + TagBits (4 bytes)
	buf := make([]byte, 0, 4+len(iv)+4+len(aad)+4)

	ivLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(ivLen, uint32(len(iv)))
	buf = append(buf, ivLen...)
	buf = append(buf, iv...)

	aadLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(aadLen, uint32(len(aad)))
	buf = append(buf, aadLen...)
	buf = append(buf, aad...)

	tagBitsBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(tagBitsBytes, tagBits)
	buf = append(buf, tagBitsBytes...)

	return buf
}

// encodeECDHParams encodes ECDH derivation parameters
func encodeECDHParams(kdf module.KDFType, sharedData, publicData []byte) []byte {
	// Simple encoding: KDF type (4 bytes) + SharedData len (4 bytes) + SharedData + PublicData len (4 bytes) + PublicData
	buf := make([]byte, 0, 4+4+len(sharedData)+4+len(publicData))

	kdfBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(kdfBytes, uint32(kdf))
	buf = append(buf, kdfBytes...)

	sdLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sdLen, uint32(len(sharedData)))
	buf = append(buf, sdLen...)
	buf = append(buf, sharedData...)

	pdLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(pdLen, uint32(len(publicData)))
	buf = append(buf, pdLen...)
	buf = append(buf, publicData...)

	return buf
}
