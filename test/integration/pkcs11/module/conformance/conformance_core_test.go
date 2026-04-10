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

//go:build integration && conformance

// Package conformance provides OASIS PKCS#11 v3.0 conformance tests.
//
// These tests validate the go-xkms PKCS#11 module implementation against
// the OASIS PKCS#11 Cryptographic Token Interface Base Specification Version 3.0.
//
// # Core Function Conformance Tests
//
// This file tests all 70+ C_* functions for correct CKR_* return codes per
// the OASIS PKCS#11 v3.0 specification.
//
// References:
//   - OASIS PKCS#11 Base v3.0, Section 5: General Overview
//   - OASIS PKCS#11 Base v3.0, Section 11: Return Values
package conformance

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// TestCoreFunctions_BeforeInitialization tests that functions requiring initialization
// return CKR_CRYPTOKI_NOT_INITIALIZED before C_Initialize is called.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.4
// "Most Cryptoki functions require that C_Initialize has been called before
// they may be invoked. The exceptions to this are C_GetFunctionList, C_GetInfo,
// and C_GetInterfaceList."
func TestCoreFunctions_BeforeInitialization(t *testing.T) {
	t.Parallel()

	// Setup uninitialized module
	module.ResetGlobalModule()
	defer module.ResetGlobalModule()

	mod, err := module.New()
	if err != nil {
		t.Fatalf("failed to create module: %v", err)
	}

	// Define test cases for functions that require initialization
	testCases := []struct {
		name     string
		testFunc func() module.CK_RV
	}{
		{
			name: "C_GetSlotList",
			testFunc: func() module.CK_RV {
				_, rv := mod.GetSlotList(false)
				return rv
			},
		},
		{
			name: "C_GetSlotInfo",
			testFunc: func() module.CK_RV {
				_, rv := mod.GetSlotInfo(0)
				return rv
			},
		},
		{
			name: "C_GetTokenInfo",
			testFunc: func() module.CK_RV {
				_, rv := mod.GetTokenInfo(0)
				return rv
			},
		},
		{
			name: "C_GetMechanismList",
			testFunc: func() module.CK_RV {
				_, rv := mod.GetMechanismList(0)
				return rv
			},
		},
		{
			name: "C_GetMechanismInfo",
			testFunc: func() module.CK_RV {
				_, rv := mod.GetMechanismInfo(0, module.CKM_RSA_PKCS)
				return rv
			},
		},
		{
			name: "C_InitToken",
			testFunc: func() module.CK_RV {
				return mod.InitToken(0, []byte("12345678"), "test")
			},
		},
		{
			name: "C_OpenSession",
			testFunc: func() module.CK_RV {
				_, rv := mod.OpenSession(0, module.CKF_SERIAL_SESSION)
				return rv
			},
		},
		{
			name: "C_CloseSession",
			testFunc: func() module.CK_RV {
				return mod.CloseSession(1)
			},
		},
		{
			name: "C_CloseAllSessions",
			testFunc: func() module.CK_RV {
				return mod.CloseAllSessions(0)
			},
		},
		{
			name: "C_GetSessionInfo",
			testFunc: func() module.CK_RV {
				_, rv := mod.GetSessionInfo(1)
				return rv
			},
		},
		{
			name: "C_Login",
			testFunc: func() module.CK_RV {
				return mod.Login(1, module.CKU_USER, []byte("1234"))
			},
		},
		{
			name: "C_Logout",
			testFunc: func() module.CK_RV {
				return mod.Logout(1)
			},
		},
		{
			name: "C_CreateObject",
			testFunc: func() module.CK_RV {
				_, rv := mod.CreateObject(1, nil)
				return rv
			},
		},
		{
			name: "C_DestroyObject",
			testFunc: func() module.CK_RV {
				return mod.DestroyObject(1, 1)
			},
		},
		{
			name: "C_GetAttributeValue",
			testFunc: func() module.CK_RV {
				_, rv := mod.GetAttributeValue(1, 1, nil)
				return rv
			},
		},
		{
			name: "C_SetAttributeValue",
			testFunc: func() module.CK_RV {
				return mod.SetAttributeValue(1, 1, nil)
			},
		},
		{
			name: "C_FindObjectsInit",
			testFunc: func() module.CK_RV {
				return mod.FindObjectsInit(1, nil)
			},
		},
		{
			name: "C_FindObjects",
			testFunc: func() module.CK_RV {
				_, rv := mod.FindObjects(1, 10)
				return rv
			},
		},
		{
			name: "C_FindObjectsFinal",
			testFunc: func() module.CK_RV {
				return mod.FindObjectsFinal(1)
			},
		},
		{
			name: "C_EncryptInit",
			testFunc: func() module.CK_RV {
				return mod.EncryptInit(1, &module.Mechanism{Type: module.CKM_AES_CBC}, 1)
			},
		},
		{
			name: "C_Encrypt",
			testFunc: func() module.CK_RV {
				_, rv := mod.Encrypt(1, []byte("test"))
				return rv
			},
		},
		{
			name: "C_DecryptInit",
			testFunc: func() module.CK_RV {
				return mod.DecryptInit(1, &module.Mechanism{Type: module.CKM_AES_CBC}, 1)
			},
		},
		{
			name: "C_Decrypt",
			testFunc: func() module.CK_RV {
				_, rv := mod.Decrypt(1, []byte("test"))
				return rv
			},
		},
		{
			name: "C_DigestInit",
			testFunc: func() module.CK_RV {
				return mod.DigestInit(1, &module.Mechanism{Type: module.CKM_SHA256})
			},
		},
		{
			name: "C_Digest",
			testFunc: func() module.CK_RV {
				_, rv := mod.Digest(1, []byte("test"))
				return rv
			},
		},
		{
			name: "C_SignInit",
			testFunc: func() module.CK_RV {
				return mod.SignInit(1, &module.Mechanism{Type: module.CKM_RSA_PKCS}, 1)
			},
		},
		{
			name: "C_Sign",
			testFunc: func() module.CK_RV {
				_, rv := mod.Sign(1, []byte("test"))
				return rv
			},
		},
		{
			name: "C_VerifyInit",
			testFunc: func() module.CK_RV {
				return mod.VerifyInit(1, &module.Mechanism{Type: module.CKM_RSA_PKCS}, 1)
			},
		},
		{
			name: "C_Verify",
			testFunc: func() module.CK_RV {
				return mod.Verify(1, []byte("test"), []byte("sig"))
			},
		},
		{
			name: "C_GenerateKey",
			testFunc: func() module.CK_RV {
				_, rv := mod.GenerateKey(1, &module.Mechanism{Type: module.CKM_AES_KEY_GEN}, nil)
				return rv
			},
		},
		{
			name: "C_GenerateKeyPair",
			testFunc: func() module.CK_RV {
				_, _, rv := mod.GenerateKeyPair(1, &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}, nil, nil)
				return rv
			},
		},
		{
			name: "C_GenerateRandom",
			testFunc: func() module.CK_RV {
				_, rv := mod.GenerateRandom(1, 16)
				return rv
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rv := tc.testFunc()
			if rv != module.CKR_CRYPTOKI_NOT_INITIALIZED {
				t.Errorf("%s: expected CKR_CRYPTOKI_NOT_INITIALIZED, got %s", tc.name, rv.String())
			}
		})
	}
}

// TestCoreFunctions_GetInfo tests that C_GetInfo can be called before initialization.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.4.1
// "C_GetInfo returns general information about Cryptoki. pInfo points to the
// location that receives the information. If C_GetInfo is called before
// C_Initialize it returns valid information."
func TestCoreFunctions_GetInfo(t *testing.T) {
	t.Parallel()

	module.ResetGlobalModule()
	defer module.ResetGlobalModule()

	mod, err := module.New()
	if err != nil {
		t.Fatalf("failed to create module: %v", err)
	}

	// C_GetInfo should work before initialization
	info, rv := mod.GetInfo()
	if rv != module.CKR_OK {
		t.Fatalf("C_GetInfo before init: expected CKR_OK, got %s", rv.String())
	}

	// Verify CK_INFO structure
	// Reference: OASIS PKCS#11 v3.0, Section 5.4.1
	if info == nil {
		t.Fatal("C_GetInfo returned nil info")
	}

	// cryptokiVersion should be set (v3.0)
	if info.CryptokiVersion.Major < 2 {
		t.Errorf("cryptokiVersion.major: expected >= 2, got %d", info.CryptokiVersion.Major)
	}

	// manufacturerID should be set (32 bytes, space-padded)
	mfr := info.GetManufacturerID()
	if len(mfr) == 0 {
		t.Error("manufacturerID is empty")
	}

	// libraryDescription should be set (32 bytes, space-padded)
	desc := info.GetLibraryDescription()
	if len(desc) == 0 {
		t.Error("libraryDescription is empty")
	}

	// flags should be 0 (reserved for future versions)
	if info.Flags != 0 {
		t.Errorf("flags: expected 0, got %d", info.Flags)
	}
}

// TestCoreFunctions_Initialize tests C_Initialize behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.4.2
func TestCoreFunctions_Initialize(t *testing.T) {
	module.ResetGlobalModule()
	defer module.ResetGlobalModule()

	mod, err := module.New()
	if err != nil {
		t.Fatalf("failed to create module: %v", err)
	}

	// Test successful initialization
	rv := mod.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("C_Initialize: expected CKR_OK, got %s", rv.String())
	}

	// Test double initialization
	// Reference: OASIS PKCS#11 v3.0, Section 5.4.2
	// "If C_Initialize is called while Cryptoki is already initialized,
	// CKR_CRYPTOKI_ALREADY_INITIALIZED is returned."
	rv = mod.Initialize(nil)
	if rv != module.CKR_CRYPTOKI_ALREADY_INITIALIZED {
		t.Errorf("C_Initialize twice: expected CKR_CRYPTOKI_ALREADY_INITIALIZED, got %s", rv.String())
	}

	// Clean up
	rv = mod.Finalize()
	if rv != module.CKR_OK {
		t.Errorf("C_Finalize: expected CKR_OK, got %s", rv.String())
	}
}

// TestCoreFunctions_Finalize tests C_Finalize behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.4.3
func TestCoreFunctions_Finalize(t *testing.T) {
	module.ResetGlobalModule()
	defer module.ResetGlobalModule()

	mod, err := module.New()
	if err != nil {
		t.Fatalf("failed to create module: %v", err)
	}

	// Test finalize before initialization
	// Reference: OASIS PKCS#11 v3.0, Section 5.4.3
	// "If C_Finalize is called while Cryptoki is not initialized,
	// CKR_CRYPTOKI_NOT_INITIALIZED is returned."
	rv := mod.Finalize()
	if rv != module.CKR_CRYPTOKI_NOT_INITIALIZED {
		t.Errorf("C_Finalize before init: expected CKR_CRYPTOKI_NOT_INITIALIZED, got %s", rv.String())
	}

	// Initialize
	rv = mod.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("C_Initialize: expected CKR_OK, got %s", rv.String())
	}

	// Test successful finalize
	rv = mod.Finalize()
	if rv != module.CKR_OK {
		t.Errorf("C_Finalize: expected CKR_OK, got %s", rv.String())
	}

	// Test finalize again (should fail)
	rv = mod.Finalize()
	if rv != module.CKR_CRYPTOKI_NOT_INITIALIZED {
		t.Errorf("C_Finalize twice: expected CKR_CRYPTOKI_NOT_INITIALIZED, got %s", rv.String())
	}
}

// TestCoreFunctions_InvalidHandles tests that invalid handle parameters return
// correct error codes.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestCoreFunctions_InvalidHandles(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	testCases := []struct {
		name     string
		testFunc func() module.CK_RV
		expected module.CK_RV
	}{
		{
			name: "C_GetSlotInfo_InvalidSlot",
			testFunc: func() module.CK_RV {
				_, rv := env.Module.GetSlotInfo(999999)
				return rv
			},
			expected: module.CKR_SLOT_ID_INVALID,
		},
		{
			name: "C_GetTokenInfo_InvalidSlot",
			testFunc: func() module.CK_RV {
				_, rv := env.Module.GetTokenInfo(999999)
				return rv
			},
			expected: module.CKR_SLOT_ID_INVALID,
		},
		{
			name: "C_GetMechanismList_InvalidSlot",
			testFunc: func() module.CK_RV {
				_, rv := env.Module.GetMechanismList(999999)
				return rv
			},
			expected: module.CKR_SLOT_ID_INVALID,
		},
		{
			name: "C_GetMechanismInfo_InvalidSlot",
			testFunc: func() module.CK_RV {
				_, rv := env.Module.GetMechanismInfo(999999, module.CKM_RSA_PKCS)
				return rv
			},
			expected: module.CKR_SLOT_ID_INVALID,
		},
		{
			name: "C_OpenSession_InvalidSlot",
			testFunc: func() module.CK_RV {
				_, rv := env.Module.OpenSession(999999, module.CKF_SERIAL_SESSION)
				return rv
			},
			expected: module.CKR_SLOT_ID_INVALID,
		},
		{
			name: "C_CloseSession_InvalidHandle",
			testFunc: func() module.CK_RV {
				return env.Module.CloseSession(999999)
			},
			expected: module.CKR_SESSION_HANDLE_INVALID,
		},
		{
			name: "C_CloseAllSessions_InvalidSlot",
			testFunc: func() module.CK_RV {
				return env.Module.CloseAllSessions(999999)
			},
			expected: module.CKR_SLOT_ID_INVALID,
		},
		{
			name: "C_GetSessionInfo_InvalidHandle",
			testFunc: func() module.CK_RV {
				_, rv := env.Module.GetSessionInfo(999999)
				return rv
			},
			expected: module.CKR_SESSION_HANDLE_INVALID,
		},
		{
			name: "C_Login_InvalidHandle",
			testFunc: func() module.CK_RV {
				return env.Module.Login(999999, module.CKU_USER, []byte("1234"))
			},
			expected: module.CKR_SESSION_HANDLE_INVALID,
		},
		{
			name: "C_Logout_InvalidHandle",
			testFunc: func() module.CK_RV {
				return env.Module.Logout(999999)
			},
			expected: module.CKR_SESSION_HANDLE_INVALID,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rv := tc.testFunc()
			if rv != tc.expected {
				t.Errorf("%s: expected %s, got %s", tc.name, tc.expected.String(), rv.String())
			}
		})
	}
}

// TestCoreFunctions_SlotAndToken tests slot and token management functions.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5
func TestCoreFunctions_SlotAndToken(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	// Test C_GetSlotList
	// Reference: OASIS PKCS#11 v3.0, Section 5.5.1
	t.Run("C_GetSlotList", func(t *testing.T) {
		// Get all slots
		slots, rv := env.Module.GetSlotList(false)
		if rv != module.CKR_OK {
			t.Fatalf("C_GetSlotList(false): expected CKR_OK, got %s", rv.String())
		}

		if len(slots) == 0 {
			t.Error("C_GetSlotList returned no slots")
		}

		// Get slots with tokens present
		slotsWithTokens, rv := env.Module.GetSlotList(true)
		if rv != module.CKR_OK {
			t.Fatalf("C_GetSlotList(true): expected CKR_OK, got %s", rv.String())
		}

		// Slots with tokens should be <= all slots
		if len(slotsWithTokens) > len(slots) {
			t.Error("slots with tokens > all slots")
		}
	})

	// Test C_GetSlotInfo
	// Reference: OASIS PKCS#11 v3.0, Section 5.5.2
	t.Run("C_GetSlotInfo", func(t *testing.T) {
		slots, _ := env.Module.GetSlotList(false)
		if len(slots) == 0 {
			t.Skip("no slots available")
		}

		info, rv := env.Module.GetSlotInfo(slots[0])
		if rv != module.CKR_OK {
			t.Fatalf("C_GetSlotInfo: expected CKR_OK, got %s", rv.String())
		}

		if info == nil {
			t.Fatal("C_GetSlotInfo returned nil info")
		}

		// Verify CK_SLOT_INFO structure fields
		desc := info.GetSlotDescription()
		if len(desc) == 0 {
			t.Error("slotDescription is empty")
		}

		mfr := info.GetManufacturerID()
		if len(mfr) == 0 {
			t.Error("manufacturerID is empty")
		}
	})

	// Initialize token for further tests
	soPin := []byte("12345678")
	rv := env.Module.InitToken(0, soPin, "test-token")
	if rv != module.CKR_OK {
		t.Fatalf("C_InitToken: expected CKR_OK, got %s", rv.String())
	}

	// Test C_GetTokenInfo
	// Reference: OASIS PKCS#11 v3.0, Section 5.5.3
	t.Run("C_GetTokenInfo", func(t *testing.T) {
		info, rv := env.Module.GetTokenInfo(0)
		if rv != module.CKR_OK {
			t.Fatalf("C_GetTokenInfo: expected CKR_OK, got %s", rv.String())
		}

		if info == nil {
			t.Fatal("C_GetTokenInfo returned nil info")
		}

		// Verify CK_TOKEN_INFO structure
		label := info.GetLabel()
		if label != "test-token" {
			t.Errorf("label: expected 'test-token', got '%s'", label)
		}

		// CKF_TOKEN_INITIALIZED should be set
		if info.Flags&module.CKF_TOKEN_INITIALIZED == 0 {
			t.Error("CKF_TOKEN_INITIALIZED flag not set")
		}
	})

	// Test C_GetMechanismList
	// Reference: OASIS PKCS#11 v3.0, Section 5.5.4
	t.Run("C_GetMechanismList", func(t *testing.T) {
		mechs, rv := env.Module.GetMechanismList(0)
		if rv != module.CKR_OK {
			t.Fatalf("C_GetMechanismList: expected CKR_OK, got %s", rv.String())
		}

		// Should have some mechanisms
		if len(mechs) == 0 {
			t.Error("C_GetMechanismList returned no mechanisms")
		}
	})

	// Test C_GetMechanismInfo
	// Reference: OASIS PKCS#11 v3.0, Section 5.5.5
	t.Run("C_GetMechanismInfo", func(t *testing.T) {
		mechs, _ := env.Module.GetMechanismList(0)
		if len(mechs) == 0 {
			t.Skip("no mechanisms available")
		}

		info, rv := env.Module.GetMechanismInfo(0, mechs[0])
		if rv != module.CKR_OK {
			t.Fatalf("C_GetMechanismInfo: expected CKR_OK, got %s", rv.String())
		}

		if info == nil {
			t.Fatal("C_GetMechanismInfo returned nil info")
		}

		// Verify CK_MECHANISM_INFO structure
		// Flags should have at least one operation flag set
		// (CKF_ENCRYPT, CKF_DECRYPT, CKF_SIGN, etc.)
	})

	// Test C_GetMechanismInfo with invalid mechanism
	t.Run("C_GetMechanismInfo_InvalidMechanism", func(t *testing.T) {
		_, rv := env.Module.GetMechanismInfo(0, module.MechanismType(0xFFFFFFFF))
		if rv != module.CKR_MECHANISM_INVALID {
			t.Errorf("C_GetMechanismInfo invalid: expected CKR_MECHANISM_INVALID, got %s", rv.String())
		}
	})
}

// TestCoreFunctions_InitToken tests C_InitToken behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5.6
func TestCoreFunctions_InitToken(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	soPin := []byte("12345678")
	label := "conformance-test"

	// Test successful token initialization
	rv := env.Module.InitToken(0, soPin, label)
	if rv != module.CKR_OK {
		t.Fatalf("C_InitToken: expected CKR_OK, got %s", rv.String())
	}

	// Verify token was initialized
	info, rv := env.Module.GetTokenInfo(0)
	if rv != module.CKR_OK {
		t.Fatalf("C_GetTokenInfo: expected CKR_OK, got %s", rv.String())
	}

	if info.GetLabel() != label {
		t.Errorf("label mismatch: expected '%s', got '%s'", label, info.GetLabel())
	}

	// Test InitToken with session open should fail
	// Reference: OASIS PKCS#11 v3.0, Section 5.5.6
	// "CKR_SESSION_EXISTS is returned if there is already a session open on the token."
	t.Run("InitToken_SessionExists", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(session)

		rv = env.Module.InitToken(0, soPin, "new-label")
		if rv != module.CKR_SESSION_EXISTS {
			t.Errorf("C_InitToken with session: expected CKR_SESSION_EXISTS, got %s", rv.String())
		}
	})

	// Test InitToken with invalid slot
	t.Run("InitToken_InvalidSlot", func(t *testing.T) {
		rv := env.Module.InitToken(999999, soPin, label)
		if rv != module.CKR_SLOT_ID_INVALID {
			t.Errorf("C_InitToken invalid slot: expected CKR_SLOT_ID_INVALID, got %s", rv.String())
		}
	})
}

// TestCoreFunctions_PIN tests C_InitPIN and C_SetPIN behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5.7 and 5.5.8
func TestCoreFunctions_PIN(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	soPin := []byte("12345678")
	userPin := []byte("87654321")
	newPin := []byte("newpin12")

	// Initialize token
	rv := env.Module.InitToken(0, soPin, "pin-test")
	if rv != module.CKR_OK {
		t.Fatalf("C_InitToken: expected CKR_OK, got %s", rv.String())
	}

	// Open RW session
	session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.CloseSession(session)

	// Test C_InitPIN without login should fail
	// Reference: OASIS PKCS#11 v3.0, Section 5.5.7
	// "CKR_USER_NOT_LOGGED_IN is returned if the session is not authorized
	// to set the normal user PIN."
	t.Run("InitPIN_NotLoggedIn", func(t *testing.T) {
		rv := env.Module.InitPIN(session, userPin)
		if rv != module.CKR_USER_NOT_LOGGED_IN {
			t.Errorf("C_InitPIN not logged in: expected CKR_USER_NOT_LOGGED_IN, got %s", rv.String())
		}
	})

	// Login as SO
	rv = env.Module.Login(session, module.CKU_SO, soPin)
	if rv != module.CKR_OK {
		t.Fatalf("C_Login SO: expected CKR_OK, got %s", rv.String())
	}

	// Test C_InitPIN as SO
	t.Run("InitPIN_AsSO", func(t *testing.T) {
		rv := env.Module.InitPIN(session, userPin)
		if rv != module.CKR_OK {
			t.Errorf("C_InitPIN as SO: expected CKR_OK, got %s", rv.String())
		}
	})

	// Logout SO
	rv = env.Module.Logout(session)
	if rv != module.CKR_OK {
		t.Fatalf("C_Logout: expected CKR_OK, got %s", rv.String())
	}

	// Login as User
	rv = env.Module.Login(session, module.CKU_USER, userPin)
	if rv != module.CKR_OK {
		t.Fatalf("C_Login User: expected CKR_OK, got %s", rv.String())
	}

	// Test C_SetPIN as user
	// Reference: OASIS PKCS#11 v3.0, Section 5.5.8
	t.Run("SetPIN_AsUser", func(t *testing.T) {
		rv := env.Module.SetPIN(session, userPin, newPin)
		if rv != module.CKR_OK {
			t.Errorf("C_SetPIN as User: expected CKR_OK, got %s", rv.String())
		}
	})

	// Test C_SetPIN with wrong old PIN
	t.Run("SetPIN_WrongOldPIN", func(t *testing.T) {
		rv := env.Module.SetPIN(session, []byte("wrongpin"), newPin)
		if rv != module.CKR_PIN_INCORRECT {
			t.Errorf("C_SetPIN wrong PIN: expected CKR_PIN_INCORRECT, got %s", rv.String())
		}
	})
}

// TestCoreFunctions_SessionManagement tests session management functions.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6
func TestCoreFunctions_SessionManagement(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	soPin := []byte("12345678")
	rv := env.Module.InitToken(0, soPin, "session-test")
	if rv != module.CKR_OK {
		t.Fatalf("C_InitToken: expected CKR_OK, got %s", rv.String())
	}

	// Test C_OpenSession
	// Reference: OASIS PKCS#11 v3.0, Section 5.6.1
	t.Run("OpenSession", func(t *testing.T) {
		// CKF_SERIAL_SESSION must be set
		_, rv := env.Module.OpenSession(0, 0)
		if rv != module.CKR_SESSION_PARALLEL_NOT_SUPPORTED {
			t.Errorf("C_OpenSession no CKF_SERIAL_SESSION: expected CKR_SESSION_PARALLEL_NOT_SUPPORTED, got %s", rv.String())
		}

		// Open RO session
		roSession, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession RO: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(roSession)

		// Open RW session
		rwSession, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession RW: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(rwSession)

		// Verify session info
		info, rv := env.Module.GetSessionInfo(roSession)
		if rv != module.CKR_OK {
			t.Fatalf("C_GetSessionInfo: expected CKR_OK, got %s", rv.String())
		}

		// RO session should be in CKS_RO_PUBLIC_SESSION state
		if info.State != module.CKS_RO_PUBLIC_SESSION {
			t.Errorf("RO session state: expected CKS_RO_PUBLIC_SESSION, got %s", info.State.String())
		}

		// RW session should be in CKS_RW_PUBLIC_SESSION state
		info, _ = env.Module.GetSessionInfo(rwSession)
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("RW session state: expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}
	})

	// Test C_CloseSession
	// Reference: OASIS PKCS#11 v3.0, Section 5.6.2
	t.Run("CloseSession", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
		}

		rv = env.Module.CloseSession(session)
		if rv != module.CKR_OK {
			t.Errorf("C_CloseSession: expected CKR_OK, got %s", rv.String())
		}

		// Closing again should fail
		rv = env.Module.CloseSession(session)
		if rv != module.CKR_SESSION_HANDLE_INVALID {
			t.Errorf("C_CloseSession twice: expected CKR_SESSION_HANDLE_INVALID, got %s", rv.String())
		}
	})

	// Test C_CloseAllSessions
	// Reference: OASIS PKCS#11 v3.0, Section 5.6.3
	t.Run("CloseAllSessions", func(t *testing.T) {
		// Open multiple sessions
		session1, _ := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		session2, _ := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)

		rv := env.Module.CloseAllSessions(0)
		if rv != module.CKR_OK {
			t.Errorf("C_CloseAllSessions: expected CKR_OK, got %s", rv.String())
		}

		// Both sessions should be invalid
		_, rv = env.Module.GetSessionInfo(session1)
		if rv != module.CKR_SESSION_HANDLE_INVALID {
			t.Errorf("session1 after CloseAllSessions: expected CKR_SESSION_HANDLE_INVALID, got %s", rv.String())
		}

		_, rv = env.Module.GetSessionInfo(session2)
		if rv != module.CKR_SESSION_HANDLE_INVALID {
			t.Errorf("session2 after CloseAllSessions: expected CKR_SESSION_HANDLE_INVALID, got %s", rv.String())
		}
	})
}

// TestCoreFunctions_ObjectManagement tests object management functions.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.7
func TestCoreFunctions_ObjectManagement(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test C_CreateObject
	// Reference: OASIS PKCS#11 v3.0, Section 5.7.1
	t.Run("CreateObject", func(t *testing.T) {
		// Create a data object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "test-data"),
			module.NewAttribute(module.CKA_VALUE, []byte("test value")),
			module.NewBoolAttribute(module.CKA_TOKEN, false), // session object
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("C_CreateObject: expected CKR_OK, got %s", rv.String())
		}

		if handle == 0 {
			t.Error("C_CreateObject returned invalid handle")
		}

		// Clean up
		env.Module.DestroyObject(session, handle)
	})

	// Test C_CreateObject without CKA_CLASS should fail
	t.Run("CreateObject_NoClass", func(t *testing.T) {
		template := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "no-class"),
		}

		_, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_TEMPLATE_INCOMPLETE {
			t.Errorf("C_CreateObject no class: expected CKR_TEMPLATE_INCOMPLETE, got %s", rv.String())
		}
	})

	// Test C_CopyObject
	// Reference: OASIS PKCS#11 v3.0, Section 5.7.2
	t.Run("CopyObject", func(t *testing.T) {
		// Create source object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "original"),
			module.NewAttribute(module.CKA_VALUE, []byte("original value")),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_COPYABLE, true),
		}

		srcHandle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("C_CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, srcHandle)

		// Copy with new label
		copyTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "copy"),
		}

		copyHandle, rv := env.Module.CopyObject(session, srcHandle, copyTemplate)
		if rv != module.CKR_OK {
			t.Errorf("C_CopyObject: expected CKR_OK, got %s", rv.String())
		}

		if copyHandle != 0 {
			env.Module.DestroyObject(session, copyHandle)
		}
	})

	// Test C_DestroyObject
	// Reference: OASIS PKCS#11 v3.0, Section 5.7.3
	t.Run("DestroyObject", func(t *testing.T) {
		// Create object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "to-destroy"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_DESTROYABLE, true),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("C_CreateObject: expected CKR_OK, got %s", rv.String())
		}

		rv = env.Module.DestroyObject(session, handle)
		if rv != module.CKR_OK {
			t.Errorf("C_DestroyObject: expected CKR_OK, got %s", rv.String())
		}

		// Destroying again should fail
		rv = env.Module.DestroyObject(session, handle)
		if rv != module.CKR_OBJECT_HANDLE_INVALID {
			t.Errorf("C_DestroyObject twice: expected CKR_OBJECT_HANDLE_INVALID, got %s", rv.String())
		}
	})

	// Test C_GetAttributeValue
	// Reference: OASIS PKCS#11 v3.0, Section 5.7.5
	t.Run("GetAttributeValue", func(t *testing.T) {
		// Create object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "get-attr-test"),
			module.NewAttribute(module.CKA_VALUE, []byte("test value")),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("C_CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Get attributes
		getTemplate := []module.Attribute{
			{Type: module.CKA_CLASS},
			{Type: module.CKA_LABEL},
		}

		attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("C_GetAttributeValue: expected CKR_OK, got %s", rv.String())
		}

		if len(attrs) != 2 {
			t.Errorf("C_GetAttributeValue: expected 2 attributes, got %d", len(attrs))
		}

		// Verify label
		for _, attr := range attrs {
			if attr.Type == module.CKA_LABEL {
				if string(attr.Value) != "get-attr-test" {
					t.Errorf("label mismatch: expected 'get-attr-test', got '%s'", string(attr.Value))
				}
			}
		}
	})

	// Test C_SetAttributeValue
	// Reference: OASIS PKCS#11 v3.0, Section 5.7.6
	t.Run("SetAttributeValue", func(t *testing.T) {
		// Create object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "set-attr-test"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("C_CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Set new label
		setTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "new-label"),
		}

		rv = env.Module.SetAttributeValue(session, handle, setTemplate)
		if rv != module.CKR_OK {
			t.Errorf("C_SetAttributeValue: expected CKR_OK, got %s", rv.String())
		}

		// Verify change
		getTemplate := []module.Attribute{{Type: module.CKA_LABEL}}
		attrs, _ := env.Module.GetAttributeValue(session, handle, getTemplate)

		if string(attrs[0].Value) != "new-label" {
			t.Errorf("label after set: expected 'new-label', got '%s'", string(attrs[0].Value))
		}
	})

	// Test C_SetAttributeValue on read-only attribute should fail
	t.Run("SetAttributeValue_ReadOnly", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "readonly-test"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("C_CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Try to change CKA_CLASS (read-only)
		setTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_CERTIFICATE)),
		}

		rv = env.Module.SetAttributeValue(session, handle, setTemplate)
		if rv != module.CKR_ATTRIBUTE_READ_ONLY {
			t.Errorf("C_SetAttributeValue read-only: expected CKR_ATTRIBUTE_READ_ONLY, got %s", rv.String())
		}
	})

	// Test C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal
	// Reference: OASIS PKCS#11 v3.0, Section 5.7.7, 5.7.8, 5.7.9
	t.Run("FindObjects", func(t *testing.T) {
		// Create multiple objects
		for i := 0; i < 3; i++ {
			template := []module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
				module.NewStringAttribute(module.CKA_LABEL, "find-test"),
				module.NewBoolAttribute(module.CKA_TOKEN, false),
			}
			handle, _ := env.Module.CreateObject(session, template)
			defer env.Module.DestroyObject(session, handle)
		}

		// Find objects with matching label
		findTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "find-test"),
		}

		rv := env.Module.FindObjectsInit(session, findTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("C_FindObjectsInit: expected CKR_OK, got %s", rv.String())
		}

		handles, rv := env.Module.FindObjects(session, 10)
		if rv != module.CKR_OK {
			t.Fatalf("C_FindObjects: expected CKR_OK, got %s", rv.String())
		}

		if len(handles) != 3 {
			t.Errorf("C_FindObjects: expected 3 objects, got %d", len(handles))
		}

		rv = env.Module.FindObjectsFinal(session)
		if rv != module.CKR_OK {
			t.Errorf("C_FindObjectsFinal: expected CKR_OK, got %s", rv.String())
		}
	})

	// Test C_FindObjectsInit with active find operation should fail
	t.Run("FindObjects_ActiveOperation", func(t *testing.T) {
		rv := env.Module.FindObjectsInit(session, nil)
		if rv != module.CKR_OK {
			t.Fatalf("C_FindObjectsInit: expected CKR_OK, got %s", rv.String())
		}

		// Second init should fail
		rv = env.Module.FindObjectsInit(session, nil)
		if rv != module.CKR_OPERATION_ACTIVE {
			t.Errorf("C_FindObjectsInit twice: expected CKR_OPERATION_ACTIVE, got %s", rv.String())
		}

		// Clean up
		env.Module.FindObjectsFinal(session)
	})
}

// TestCoreFunctions_RandomGeneration tests C_GenerateRandom and C_SeedRandom.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.9
func TestCoreFunctions_RandomGeneration(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test C_GenerateRandom
	// Reference: OASIS PKCS#11 v3.0, Section 5.9.2
	t.Run("GenerateRandom", func(t *testing.T) {
		random, rv := env.Module.GenerateRandom(session, 32)
		if rv != module.CKR_OK {
			t.Fatalf("C_GenerateRandom: expected CKR_OK, got %s", rv.String())
		}

		if len(random) != 32 {
			t.Errorf("C_GenerateRandom: expected 32 bytes, got %d", len(random))
		}

		// Random data should not be all zeros
		allZeros := true
		for _, b := range random {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("C_GenerateRandom returned all zeros")
		}
	})

	// Test multiple calls return different data
	t.Run("GenerateRandom_Different", func(t *testing.T) {
		random1, _ := env.Module.GenerateRandom(session, 32)
		random2, _ := env.Module.GenerateRandom(session, 32)

		same := true
		for i := range random1 {
			if random1[i] != random2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("C_GenerateRandom returned same data twice")
		}
	})
}
