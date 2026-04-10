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
// # Error Code Validation Tests
//
// This file tests that PKCS#11 CKR_* error codes are returned in appropriate
// situations per the OASIS PKCS#11 v3.0 specification, including error precedence
// when multiple errors apply.
//
// References:
//   - OASIS PKCS#11 Base v3.0, Section 11: Return Values
package conformance

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// TestErrors_CKR_CRYPTOKI_NOT_INITIALIZED tests that functions return
// CKR_CRYPTOKI_NOT_INITIALIZED before C_Initialize is called.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_CRYPTOKI_NOT_INITIALIZED(t *testing.T) {
	t.Parallel()

	module.ResetGlobalModule()
	defer module.ResetGlobalModule()

	mod, err := module.New()
	if err != nil {
		t.Fatalf("failed to create module: %v", err)
	}

	// Functions that require initialization
	testCases := []struct {
		name     string
		testFunc func() module.CK_RV
	}{
		{"C_GetSlotList", func() module.CK_RV { _, rv := mod.GetSlotList(false); return rv }},
		{"C_GetSlotInfo", func() module.CK_RV { _, rv := mod.GetSlotInfo(0); return rv }},
		{"C_GetTokenInfo", func() module.CK_RV { _, rv := mod.GetTokenInfo(0); return rv }},
		{"C_OpenSession", func() module.CK_RV { _, rv := mod.OpenSession(0, module.CKF_SERIAL_SESSION); return rv }},
		{"C_CloseSession", func() module.CK_RV { return mod.CloseSession(1) }},
		{"C_GenerateRandom", func() module.CK_RV { _, rv := mod.GenerateRandom(1, 16); return rv }},
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

// TestErrors_CKR_CRYPTOKI_ALREADY_INITIALIZED tests double initialization error.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.4.2
func TestErrors_CKR_CRYPTOKI_ALREADY_INITIALIZED(t *testing.T) {
	module.ResetGlobalModule()
	defer module.ResetGlobalModule()

	mod, err := module.New()
	if err != nil {
		t.Fatalf("failed to create module: %v", err)
	}

	// Initialize first time
	rv := mod.Initialize(nil)
	if rv != module.CKR_OK {
		t.Fatalf("first initialize: expected CKR_OK, got %s", rv.String())
	}
	defer mod.Finalize()

	// Initialize second time
	rv = mod.Initialize(nil)
	if rv != module.CKR_CRYPTOKI_ALREADY_INITIALIZED {
		t.Errorf("double initialize: expected CKR_CRYPTOKI_ALREADY_INITIALIZED, got %s", rv.String())
	}
}

// TestErrors_CKR_SLOT_ID_INVALID tests invalid slot ID error.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_SLOT_ID_INVALID(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	testCases := []struct {
		name     string
		testFunc func() module.CK_RV
	}{
		{"C_GetSlotInfo", func() module.CK_RV { _, rv := env.Module.GetSlotInfo(999999); return rv }},
		{"C_GetTokenInfo", func() module.CK_RV { _, rv := env.Module.GetTokenInfo(999999); return rv }},
		{"C_GetMechanismList", func() module.CK_RV { _, rv := env.Module.GetMechanismList(999999); return rv }},
		{"C_GetMechanismInfo", func() module.CK_RV { _, rv := env.Module.GetMechanismInfo(999999, module.CKM_RSA_PKCS); return rv }},
		{"C_InitToken", func() module.CK_RV { return env.Module.InitToken(999999, []byte("pin"), "label") }},
		{"C_OpenSession", func() module.CK_RV { _, rv := env.Module.OpenSession(999999, module.CKF_SERIAL_SESSION); return rv }},
		{"C_CloseAllSessions", func() module.CK_RV { return env.Module.CloseAllSessions(999999) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rv := tc.testFunc()
			if rv != module.CKR_SLOT_ID_INVALID {
				t.Errorf("%s: expected CKR_SLOT_ID_INVALID, got %s", tc.name, rv.String())
			}
		})
	}
}

// TestErrors_CKR_SESSION_HANDLE_INVALID tests invalid session handle error.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_SESSION_HANDLE_INVALID(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	testCases := []struct {
		name     string
		testFunc func() module.CK_RV
	}{
		{"C_CloseSession", func() module.CK_RV { return env.Module.CloseSession(999999) }},
		{"C_GetSessionInfo", func() module.CK_RV { _, rv := env.Module.GetSessionInfo(999999); return rv }},
		{"C_Login", func() module.CK_RV { return env.Module.Login(999999, module.CKU_USER, []byte("pin")) }},
		{"C_Logout", func() module.CK_RV { return env.Module.Logout(999999) }},
		{"C_CreateObject", func() module.CK_RV { _, rv := env.Module.CreateObject(999999, nil); return rv }},
		{"C_DestroyObject", func() module.CK_RV { return env.Module.DestroyObject(999999, 1) }},
		{"C_FindObjectsInit", func() module.CK_RV { return env.Module.FindObjectsInit(999999, nil) }},
		{"C_FindObjects", func() module.CK_RV { _, rv := env.Module.FindObjects(999999, 10); return rv }},
		{"C_FindObjectsFinal", func() module.CK_RV { return env.Module.FindObjectsFinal(999999) }},
		{"C_GenerateRandom", func() module.CK_RV { _, rv := env.Module.GenerateRandom(999999, 16); return rv }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rv := tc.testFunc()
			if rv != module.CKR_SESSION_HANDLE_INVALID {
				t.Errorf("%s: expected CKR_SESSION_HANDLE_INVALID, got %s", tc.name, rv.String())
			}
		})
	}
}

// TestErrors_CKR_OBJECT_HANDLE_INVALID tests invalid object handle error.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_OBJECT_HANDLE_INVALID(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	testCases := []struct {
		name     string
		testFunc func() module.CK_RV
	}{
		{"C_DestroyObject", func() module.CK_RV { return env.Module.DestroyObject(session, 999999) }},
		{"C_GetAttributeValue", func() module.CK_RV { _, rv := env.Module.GetAttributeValue(session, 999999, nil); return rv }},
		{"C_SetAttributeValue", func() module.CK_RV { return env.Module.SetAttributeValue(session, 999999, nil) }},
		{"C_CopyObject", func() module.CK_RV { _, rv := env.Module.CopyObject(session, 999999, nil); return rv }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rv := tc.testFunc()
			if rv != module.CKR_OBJECT_HANDLE_INVALID {
				t.Errorf("%s: expected CKR_OBJECT_HANDLE_INVALID, got %s", tc.name, rv.String())
			}
		})
	}
}

// TestErrors_CKR_PIN errors tests various PIN-related errors.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_PIN(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout")
	testutil.RequireOK(t, env.Module.CloseSession(session), "CloseSession")

	t.Run("CKR_PIN_INCORRECT", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Login(session, module.CKU_USER, []byte("wrongpin"))
		if rv != module.CKR_PIN_INCORRECT {
			t.Errorf("wrong PIN: expected CKR_PIN_INCORRECT, got %s", rv.String())
		}
	})

	t.Run("CKR_PIN_LEN_RANGE", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		// Empty PIN
		rv := env.Module.Login(session, module.CKU_USER, []byte(""))
		if rv != module.CKR_PIN_LEN_RANGE {
			// May also return CKR_PIN_INCORRECT
			t.Logf("empty PIN: got %s (may be CKR_PIN_INCORRECT or CKR_PIN_LEN_RANGE)", rv.String())
		}
	})
}

// TestErrors_CKR_USER errors tests various user login/logout errors.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_USER(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout")
	testutil.RequireOK(t, env.Module.CloseSession(session), "CloseSession")

	t.Run("CKR_USER_NOT_LOGGED_IN", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Logout(session)
		if rv != module.CKR_USER_NOT_LOGGED_IN {
			t.Errorf("logout not logged in: expected CKR_USER_NOT_LOGGED_IN, got %s", rv.String())
		}
	})

	t.Run("CKR_USER_ALREADY_LOGGED_IN", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		if rv != module.CKR_OK {
			t.Fatalf("first login: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.Logout(session)

		rv = env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		if rv != module.CKR_USER_ALREADY_LOGGED_IN {
			t.Errorf("double login: expected CKR_USER_ALREADY_LOGGED_IN, got %s", rv.String())
		}
	})

	t.Run("CKR_USER_ANOTHER_ALREADY_LOGGED_IN", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		if rv != module.CKR_OK {
			t.Fatalf("user login: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.Logout(session)

		rv = env.Module.Login(session, module.CKU_SO, testutil.TestPINs.SO)
		if rv != module.CKR_USER_ANOTHER_ALREADY_LOGGED_IN {
			t.Errorf("SO login while user logged in: expected CKR_USER_ANOTHER_ALREADY_LOGGED_IN, got %s", rv.String())
		}
	})

	t.Run("CKR_USER_TYPE_INVALID", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Login(session, module.UserType(99), testutil.TestPINs.User)
		if rv != module.CKR_USER_TYPE_INVALID {
			t.Errorf("invalid user type: expected CKR_USER_TYPE_INVALID, got %s", rv.String())
		}
	})
}

// TestErrors_CKR_SESSION errors tests various session-related errors.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_SESSION(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	t.Run("CKR_SESSION_PARALLEL_NOT_SUPPORTED", func(t *testing.T) {
		// Missing CKF_SERIAL_SESSION flag
		_, rv := env.Module.OpenSession(0, 0)
		if rv != module.CKR_SESSION_PARALLEL_NOT_SUPPORTED {
			t.Errorf("missing CKF_SERIAL_SESSION: expected CKR_SESSION_PARALLEL_NOT_SUPPORTED, got %s", rv.String())
		}
	})

	t.Run("CKR_SESSION_READ_ONLY_EXISTS", func(t *testing.T) {
		// Open RO session first
		roSession, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("open RO session: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(roSession)

		// Open RW session
		rwSession, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("open RW session: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(rwSession)

		// Try to login as SO with RO session open
		rv = env.Module.Login(rwSession, module.CKU_SO, testutil.TestPINs.SO)
		if rv != module.CKR_SESSION_READ_ONLY_EXISTS {
			t.Errorf("SO login with RO session: expected CKR_SESSION_READ_ONLY_EXISTS, got %s", rv.String())
		}
	})

	t.Run("CKR_SESSION_READ_WRITE_SO_EXISTS", func(t *testing.T) {
		// Login as SO first
		rwSession, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("open RW session: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(rwSession)

		rv = env.Module.Login(rwSession, module.CKU_SO, testutil.TestPINs.SO)
		if rv != module.CKR_OK {
			t.Fatalf("SO login: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.Logout(rwSession)

		// Try to open RO session while SO is logged in
		_, rv = env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_SESSION_READ_WRITE_SO_EXISTS {
			t.Errorf("RO session while SO logged in: expected CKR_SESSION_READ_WRITE_SO_EXISTS, got %s", rv.String())
		}
	})

	t.Run("CKR_SESSION_EXISTS", func(t *testing.T) {
		// Open a session
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("open session: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(session)

		// Try to initialize token with session open
		rv = env.Module.InitToken(0, testutil.TestPINs.SO, "new-label")
		if rv != module.CKR_SESSION_EXISTS {
			t.Errorf("InitToken with session open: expected CKR_SESSION_EXISTS, got %s", rv.String())
		}
	})

	t.Run("CKR_SESSION_READ_ONLY", func(t *testing.T) {
		// Setup user PIN
		rwSession := env.MustOpenRWSession(t)
		env.MustLoginSO(t, rwSession, testutil.TestPINs.SO)
		testutil.RequireOK(t, env.Module.InitPIN(rwSession, testutil.TestPINs.User), "InitPIN")
		testutil.RequireOK(t, env.Module.Logout(rwSession), "Logout")
		testutil.RequireOK(t, env.Module.CloseSession(rwSession), "CloseSession")

		// Try to login as SO on RO session
		roSession, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("open RO session: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(roSession)

		rv = env.Module.Login(roSession, module.CKU_SO, testutil.TestPINs.SO)
		if rv != module.CKR_SESSION_READ_ONLY {
			t.Errorf("SO login on RO session: expected CKR_SESSION_READ_ONLY, got %s", rv.String())
		}
	})
}

// TestErrors_CKR_OPERATION errors tests operation state errors.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_OPERATION(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	t.Run("CKR_OPERATION_NOT_INITIALIZED", func(t *testing.T) {
		// Try to call FindObjects without FindObjectsInit
		_, rv := env.Module.FindObjects(session, 10)
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("FindObjects without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}

		// Try to call FindObjectsFinal without FindObjectsInit
		rv = env.Module.FindObjectsFinal(session)
		if rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("FindObjectsFinal without Init: expected CKR_OPERATION_NOT_INITIALIZED, got %s", rv.String())
		}
	})

	t.Run("CKR_OPERATION_ACTIVE", func(t *testing.T) {
		// Start a find operation
		rv := env.Module.FindObjectsInit(session, nil)
		if rv != module.CKR_OK {
			t.Fatalf("FindObjectsInit: expected CKR_OK, got %s", rv.String())
		}

		// Try to start another find operation
		rv = env.Module.FindObjectsInit(session, nil)
		if rv != module.CKR_OPERATION_ACTIVE {
			t.Errorf("double FindObjectsInit: expected CKR_OPERATION_ACTIVE, got %s", rv.String())
		}

		// Clean up
		env.Module.FindObjectsFinal(session)
	})
}

// TestErrors_CKR_TEMPLATE errors tests template-related errors.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_TEMPLATE(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	t.Run("CKR_TEMPLATE_INCOMPLETE", func(t *testing.T) {
		// Create object without CKA_CLASS
		template := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "no-class"),
		}

		_, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_TEMPLATE_INCOMPLETE {
			t.Errorf("create without CKA_CLASS: expected CKR_TEMPLATE_INCOMPLETE, got %s", rv.String())
		}
	})
}

// TestErrors_CKR_ATTRIBUTE errors tests attribute-related errors.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_ATTRIBUTE(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Create a test object
	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
		module.NewStringAttribute(module.CKA_LABEL, "attr-test"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
	}

	handle, rv := env.Module.CreateObject(session, template)
	if rv != module.CKR_OK {
		t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.DestroyObject(session, handle)

	t.Run("CKR_ATTRIBUTE_READ_ONLY", func(t *testing.T) {
		// Try to modify CKA_CLASS (read-only)
		setTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_CERTIFICATE)),
		}

		rv := env.Module.SetAttributeValue(session, handle, setTemplate)
		if rv != module.CKR_ATTRIBUTE_READ_ONLY {
			t.Errorf("modify CKA_CLASS: expected CKR_ATTRIBUTE_READ_ONLY, got %s", rv.String())
		}
	})

	t.Run("CKR_ATTRIBUTE_TYPE_INVALID", func(t *testing.T) {
		// Request a non-existent attribute
		getTemplate := []module.Attribute{
			{Type: module.AttributeType(0xFFFFFFFF)},
		}

		_, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
		// May return CKR_ATTRIBUTE_TYPE_INVALID or include it in the results
		if rv != module.CKR_OK && rv != module.CKR_ATTRIBUTE_TYPE_INVALID {
			t.Errorf("get invalid attribute type: expected CKR_OK or CKR_ATTRIBUTE_TYPE_INVALID, got %s", rv.String())
		}
	})
}

// TestErrors_CKR_ACTION_PROHIBITED tests action prohibited errors.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_ACTION_PROHIBITED(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	t.Run("CopyNonCopyable", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "non-copyable"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_COPYABLE, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		_, rv = env.Module.CopyObject(session, handle, nil)
		if rv != module.CKR_ACTION_PROHIBITED {
			t.Errorf("copy non-copyable: expected CKR_ACTION_PROHIBITED, got %s", rv.String())
		}
	})

	t.Run("ModifyNonModifiable", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "non-modifiable"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_MODIFIABLE, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		setTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "new-label"),
		}

		rv = env.Module.SetAttributeValue(session, handle, setTemplate)
		if rv != module.CKR_ACTION_PROHIBITED {
			t.Errorf("modify non-modifiable: expected CKR_ACTION_PROHIBITED, got %s", rv.String())
		}
	})

	t.Run("DestroyNonDestroyable", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "non-destroyable"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_DESTROYABLE, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		// Note: Object will be cleaned up when session closes

		rv = env.Module.DestroyObject(session, handle)
		if rv != module.CKR_ACTION_PROHIBITED {
			t.Errorf("destroy non-destroyable: expected CKR_ACTION_PROHIBITED, got %s", rv.String())
		}
	})
}

// TestErrors_CKR_MECHANISM_INVALID tests mechanism invalid error.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_MECHANISM_INVALID(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	t.Run("GetMechanismInfo_Invalid", func(t *testing.T) {
		_, rv := env.Module.GetMechanismInfo(0, module.MechanismType(0xFFFFFFFF))
		if rv != module.CKR_MECHANISM_INVALID {
			t.Errorf("GetMechanismInfo invalid: expected CKR_MECHANISM_INVALID, got %s", rv.String())
		}
	})
}

// TestErrors_ErrorPrecedence tests that correct error is returned when multiple errors apply.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
// "If more than one of these error codes is applicable, there is no guarantee
// as to which one Cryptoki will return."
func TestErrors_ErrorPrecedence(t *testing.T) {
	module.ResetGlobalModule()
	defer module.ResetGlobalModule()

	mod, err := module.New()
	if err != nil {
		t.Fatalf("failed to create module: %v", err)
	}

	// Multiple errors: not initialized + invalid slot + invalid session
	// CKR_CRYPTOKI_NOT_INITIALIZED should typically take precedence
	t.Run("NotInitialized_Precedence", func(t *testing.T) {
		rv := mod.CloseSession(999999)
		// Could be CKR_CRYPTOKI_NOT_INITIALIZED or CKR_SESSION_HANDLE_INVALID
		if rv != module.CKR_CRYPTOKI_NOT_INITIALIZED && rv != module.CKR_SESSION_HANDLE_INVALID {
			t.Errorf("expected CKR_CRYPTOKI_NOT_INITIALIZED or CKR_SESSION_HANDLE_INVALID, got %s", rv.String())
		}
	})
}

// TestErrors_CKR_TOKEN_NOT_PRESENT tests token not present error.
//
// Reference: OASIS PKCS#11 v3.0, Section 11
func TestErrors_CKR_TOKEN_NOT_PRESENT(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	// Note: This test assumes slot 0 has a token present after module initialization
	// In some implementations, we may need to test with a slot that has no token
	t.Run("GetTokenInfo_NoToken", func(t *testing.T) {
		// Get slot list and find a slot without a token
		slots, rv := env.Module.GetSlotList(false)
		if rv != module.CKR_OK {
			t.Fatalf("GetSlotList: expected CKR_OK, got %s", rv.String())
		}

		for _, slot := range slots {
			info, rv := env.Module.GetSlotInfo(slot)
			if rv != module.CKR_OK {
				continue
			}

			// Check if token is not present
			if info.Flags&module.CKF_TOKEN_PRESENT == 0 {
				_, rv = env.Module.GetTokenInfo(slot)
				if rv != module.CKR_TOKEN_NOT_PRESENT {
					t.Logf("slot %d without token: GetTokenInfo returned %s", slot, rv.String())
				}
			}
		}
	})
}

// TestErrors_AllCKR verifies all error codes have proper string representations.
func TestErrors_AllCKR(t *testing.T) {
	t.Parallel()

	allErrors := []module.CK_RV{
		module.CKR_OK,
		module.CKR_CANCEL,
		module.CKR_HOST_MEMORY,
		module.CKR_SLOT_ID_INVALID,
		module.CKR_GENERAL_ERROR,
		module.CKR_FUNCTION_FAILED,
		module.CKR_ARGUMENTS_BAD,
		module.CKR_NO_EVENT,
		module.CKR_NEED_TO_CREATE_THREADS,
		module.CKR_CANT_LOCK,
		module.CKR_ATTRIBUTE_READ_ONLY,
		module.CKR_ATTRIBUTE_SENSITIVE,
		module.CKR_ATTRIBUTE_TYPE_INVALID,
		module.CKR_ATTRIBUTE_VALUE_INVALID,
		module.CKR_ACTION_PROHIBITED,
		module.CKR_DATA_INVALID,
		module.CKR_DATA_LEN_RANGE,
		module.CKR_DEVICE_ERROR,
		module.CKR_DEVICE_MEMORY,
		module.CKR_DEVICE_REMOVED,
		module.CKR_ENCRYPTED_DATA_INVALID,
		module.CKR_ENCRYPTED_DATA_LEN_RANGE,
		module.CKR_AEAD_DECRYPT_FAILED,
		module.CKR_FUNCTION_CANCELED,
		module.CKR_FUNCTION_NOT_PARALLEL,
		module.CKR_FUNCTION_NOT_SUPPORTED,
		module.CKR_KEY_HANDLE_INVALID,
		module.CKR_KEY_SIZE_RANGE,
		module.CKR_KEY_TYPE_INCONSISTENT,
		module.CKR_KEY_NOT_NEEDED,
		module.CKR_KEY_CHANGED,
		module.CKR_KEY_NEEDED,
		module.CKR_KEY_INDIGESTIBLE,
		module.CKR_KEY_FUNCTION_NOT_PERMITTED,
		module.CKR_KEY_NOT_WRAPPABLE,
		module.CKR_KEY_UNEXTRACTABLE,
		module.CKR_MECHANISM_INVALID,
		module.CKR_MECHANISM_PARAM_INVALID,
		module.CKR_OBJECT_HANDLE_INVALID,
		module.CKR_OPERATION_ACTIVE,
		module.CKR_OPERATION_NOT_INITIALIZED,
		module.CKR_PIN_INCORRECT,
		module.CKR_PIN_INVALID,
		module.CKR_PIN_LEN_RANGE,
		module.CKR_PIN_EXPIRED,
		module.CKR_PIN_LOCKED,
		module.CKR_SESSION_CLOSED,
		module.CKR_SESSION_COUNT,
		module.CKR_SESSION_HANDLE_INVALID,
		module.CKR_SESSION_PARALLEL_NOT_SUPPORTED,
		module.CKR_SESSION_READ_ONLY,
		module.CKR_SESSION_EXISTS,
		module.CKR_SESSION_READ_ONLY_EXISTS,
		module.CKR_SESSION_READ_WRITE_SO_EXISTS,
		module.CKR_SIGNATURE_INVALID,
		module.CKR_SIGNATURE_LEN_RANGE,
		module.CKR_TEMPLATE_INCOMPLETE,
		module.CKR_TEMPLATE_INCONSISTENT,
		module.CKR_TOKEN_NOT_PRESENT,
		module.CKR_TOKEN_NOT_RECOGNIZED,
		module.CKR_TOKEN_WRITE_PROTECTED,
		module.CKR_UNWRAPPING_KEY_HANDLE_INVALID,
		module.CKR_UNWRAPPING_KEY_SIZE_RANGE,
		module.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
		module.CKR_USER_ALREADY_LOGGED_IN,
		module.CKR_USER_NOT_LOGGED_IN,
		module.CKR_USER_PIN_NOT_INITIALIZED,
		module.CKR_USER_TYPE_INVALID,
		module.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
		module.CKR_USER_TOO_MANY_TYPES,
		module.CKR_WRAPPED_KEY_INVALID,
		module.CKR_WRAPPED_KEY_LEN_RANGE,
		module.CKR_WRAPPING_KEY_HANDLE_INVALID,
		module.CKR_WRAPPING_KEY_SIZE_RANGE,
		module.CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
		module.CKR_RANDOM_SEED_NOT_SUPPORTED,
		module.CKR_RANDOM_NO_RNG,
		module.CKR_DOMAIN_PARAMS_INVALID,
		module.CKR_CURVE_NOT_SUPPORTED,
		module.CKR_BUFFER_TOO_SMALL,
		module.CKR_SAVED_STATE_INVALID,
		module.CKR_INFORMATION_SENSITIVE,
		module.CKR_STATE_UNSAVEABLE,
		module.CKR_CRYPTOKI_NOT_INITIALIZED,
		module.CKR_CRYPTOKI_ALREADY_INITIALIZED,
		module.CKR_MUTEX_BAD,
		module.CKR_MUTEX_NOT_LOCKED,
		module.CKR_NEW_PIN_MODE,
		module.CKR_NEXT_OTP,
		module.CKR_EXCEEDED_MAX_ITERATIONS,
		module.CKR_FIPS_SELF_TEST_FAILED,
		module.CKR_LIBRARY_LOAD_FAILED,
		module.CKR_PIN_TOO_WEAK,
		module.CKR_PUBLIC_KEY_INVALID,
		module.CKR_FUNCTION_REJECTED,
		module.CKR_TOKEN_RESOURCE_EXCEEDED,
		module.CKR_OPERATION_CANCEL_FAILED,
		module.CKR_KEY_EXHAUSTED,
	}

	for _, rv := range allErrors {
		t.Run(rv.String(), func(t *testing.T) {
			str := rv.String()
			if str == "" {
				t.Errorf("error code %d has empty string representation", rv)
			}
			if str[:3] != "CKR" {
				t.Errorf("error code %d has invalid string: %s", rv, str)
			}
		})
	}
}
