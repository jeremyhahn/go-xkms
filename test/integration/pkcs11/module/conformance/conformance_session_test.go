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
// # Session State Machine Conformance Tests
//
// This file tests the PKCS#11 session state machine per the OASIS PKCS#11 v3.0
// specification, including all CK_STATE transitions, session flags, login state
// persistence, SO vs User login restrictions, and read-only restrictions.
//
// References:
//   - OASIS PKCS#11 Base v3.0, Section 5.6: Session Management
//   - OASIS PKCS#11 Base v3.0, Figure 1: Session States
package conformance

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// TestSessionState_InitialStates tests that sessions start in correct initial states.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6, Figure 1
// Read-only sessions start in CKS_RO_PUBLIC_SESSION.
// Read-write sessions start in CKS_RW_PUBLIC_SESSION.
func TestSessionState_InitialStates(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	t.Run("ROSession_InitialState", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession RO: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(session)

		info, rv := env.Module.GetSessionInfo(session)
		if rv != module.CKR_OK {
			t.Fatalf("C_GetSessionInfo: expected CKR_OK, got %s", rv.String())
		}

		// Reference: OASIS PKCS#11 v3.0, Section 5.6.4
		// "A read-only session is opened in the CKS_RO_PUBLIC_SESSION state."
		if info.State != module.CKS_RO_PUBLIC_SESSION {
			t.Errorf("RO session initial state: expected CKS_RO_PUBLIC_SESSION, got %s", info.State.String())
		}

		// Verify flags
		if info.Flags&module.CKF_SERIAL_SESSION == 0 {
			t.Error("CKF_SERIAL_SESSION not set")
		}
		if info.Flags&module.CKF_RW_SESSION != 0 {
			t.Error("CKF_RW_SESSION should not be set for RO session")
		}
	})

	t.Run("RWSession_InitialState", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession RW: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(session)

		info, rv := env.Module.GetSessionInfo(session)
		if rv != module.CKR_OK {
			t.Fatalf("C_GetSessionInfo: expected CKR_OK, got %s", rv.String())
		}

		// Reference: OASIS PKCS#11 v3.0, Section 5.6.4
		// "A read-write session is opened in the CKS_RW_PUBLIC_SESSION state."
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("RW session initial state: expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}

		// Verify flags
		if info.Flags&module.CKF_SERIAL_SESSION == 0 {
			t.Error("CKF_SERIAL_SESSION not set")
		}
		if info.Flags&module.CKF_RW_SESSION == 0 {
			t.Error("CKF_RW_SESSION should be set for RW session")
		}
	})
}

// TestSessionState_UserLoginTransitions tests state transitions when user logs in/out.
//
// Reference: OASIS PKCS#11 v3.0, Figure 1: Session States
// CKS_RO_PUBLIC_SESSION -> CKS_RO_USER_FUNCTIONS (on C_Login as CKU_USER)
// CKS_RW_PUBLIC_SESSION -> CKS_RW_USER_FUNCTIONS (on C_Login as CKU_USER)
func TestSessionState_UserLoginTransitions(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout SO")
	testutil.RequireOK(t, env.Module.CloseSession(session), "CloseSession")

	t.Run("ROSession_UserLogin", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(session)

		// Initial state
		info, _ := env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RO_PUBLIC_SESSION {
			t.Fatalf("initial state: expected CKS_RO_PUBLIC_SESSION, got %s", info.State.String())
		}

		// Login as user
		rv = env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		if rv != module.CKR_OK {
			t.Fatalf("C_Login: expected CKR_OK, got %s", rv.String())
		}

		// Should transition to CKS_RO_USER_FUNCTIONS
		info, _ = env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RO_USER_FUNCTIONS {
			t.Errorf("after login: expected CKS_RO_USER_FUNCTIONS, got %s", info.State.String())
		}

		// Logout
		rv = env.Module.Logout(session)
		if rv != module.CKR_OK {
			t.Fatalf("C_Logout: expected CKR_OK, got %s", rv.String())
		}

		// Should transition back to CKS_RO_PUBLIC_SESSION
		info, _ = env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RO_PUBLIC_SESSION {
			t.Errorf("after logout: expected CKS_RO_PUBLIC_SESSION, got %s", info.State.String())
		}
	})

	t.Run("RWSession_UserLogin", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(session)

		// Initial state
		info, _ := env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Fatalf("initial state: expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}

		// Login as user
		rv = env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		if rv != module.CKR_OK {
			t.Fatalf("C_Login: expected CKR_OK, got %s", rv.String())
		}

		// Should transition to CKS_RW_USER_FUNCTIONS
		info, _ = env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Errorf("after login: expected CKS_RW_USER_FUNCTIONS, got %s", info.State.String())
		}

		// Logout
		rv = env.Module.Logout(session)
		if rv != module.CKR_OK {
			t.Fatalf("C_Logout: expected CKR_OK, got %s", rv.String())
		}

		// Should transition back to CKS_RW_PUBLIC_SESSION
		info, _ = env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("after logout: expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}
	})
}

// TestSessionState_SOLoginTransitions tests state transitions when SO logs in/out.
//
// Reference: OASIS PKCS#11 v3.0, Figure 1: Session States
// CKS_RW_PUBLIC_SESSION -> CKS_RW_SO_FUNCTIONS (on C_Login as CKU_SO)
// Note: SO can only log into RW sessions
func TestSessionState_SOLoginTransitions(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	t.Run("RWSession_SOLogin", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(session)

		// Initial state
		info, _ := env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Fatalf("initial state: expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}

		// Login as SO
		rv = env.Module.Login(session, module.CKU_SO, testutil.TestPINs.SO)
		if rv != module.CKR_OK {
			t.Fatalf("C_Login SO: expected CKR_OK, got %s", rv.String())
		}

		// Should transition to CKS_RW_SO_FUNCTIONS
		info, _ = env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RW_SO_FUNCTIONS {
			t.Errorf("after SO login: expected CKS_RW_SO_FUNCTIONS, got %s", info.State.String())
		}

		// Logout
		rv = env.Module.Logout(session)
		if rv != module.CKR_OK {
			t.Fatalf("C_Logout: expected CKR_OK, got %s", rv.String())
		}

		// Should transition back to CKS_RW_PUBLIC_SESSION
		info, _ = env.Module.GetSessionInfo(session)
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("after logout: expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}
	})

	// SO login to RO session should fail
	// Reference: OASIS PKCS#11 v3.0, Section 5.6.6
	t.Run("ROSession_SOLogin_Fails", func(t *testing.T) {
		session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.CloseSession(session)

		rv = env.Module.Login(session, module.CKU_SO, testutil.TestPINs.SO)
		if rv != module.CKR_SESSION_READ_ONLY {
			t.Errorf("SO login to RO session: expected CKR_SESSION_READ_ONLY, got %s", rv.String())
		}
	})
}

// TestSessionState_LoginPersistence tests that login state persists across sessions.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6.6
// "C_Login logs a user into a token. [...] When the user is logged in to the
// token, all sessions have the same state."
func TestSessionState_LoginPersistence(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout SO")
	testutil.RequireOK(t, env.Module.CloseSession(session), "CloseSession")

	// Open first session and login
	session1, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.CloseSession(session1)

	rv = env.Module.Login(session1, module.CKU_USER, testutil.TestPINs.User)
	if rv != module.CKR_OK {
		t.Fatalf("C_Login: expected CKR_OK, got %s", rv.String())
	}

	// Open second session - should inherit logged-in state
	session2, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("C_OpenSession 2: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.CloseSession(session2)

	info2, _ := env.Module.GetSessionInfo(session2)
	if info2.State != module.CKS_RW_USER_FUNCTIONS {
		t.Errorf("session2 state: expected CKS_RW_USER_FUNCTIONS (inherited), got %s", info2.State.String())
	}

	// Logout from session1 should affect session2
	rv = env.Module.Logout(session1)
	if rv != module.CKR_OK {
		t.Fatalf("C_Logout: expected CKR_OK, got %s", rv.String())
	}

	info2, _ = env.Module.GetSessionInfo(session2)
	if info2.State != module.CKS_RW_PUBLIC_SESSION {
		t.Errorf("session2 after logout: expected CKS_RW_PUBLIC_SESSION, got %s", info2.State.String())
	}
}

// TestSessionState_SOSessionRestrictions tests restrictions on sessions when SO is logged in.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6.1
// "If SO is logged in, C_OpenSession with CKF_RW_SESSION clear (i.e., a RO session)
// fails with CKR_SESSION_READ_WRITE_SO_EXISTS."
func TestSessionState_SOSessionRestrictions(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Open RW session and login as SO
	session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("C_OpenSession: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.CloseSession(session)

	rv = env.Module.Login(session, module.CKU_SO, testutil.TestPINs.SO)
	if rv != module.CKR_OK {
		t.Fatalf("C_Login SO: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.Logout(session)

	// Cannot open RO session while SO is logged in
	_, rv = env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
	if rv != module.CKR_SESSION_READ_WRITE_SO_EXISTS {
		t.Errorf("open RO while SO logged in: expected CKR_SESSION_READ_WRITE_SO_EXISTS, got %s", rv.String())
	}

	// Can still open RW session
	session2, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Errorf("open RW while SO logged in: expected CKR_OK, got %s", rv.String())
	} else {
		// New session should also be in CKS_RW_SO_FUNCTIONS state
		info, _ := env.Module.GetSessionInfo(session2)
		if info.State != module.CKS_RW_SO_FUNCTIONS {
			t.Errorf("new RW session state: expected CKS_RW_SO_FUNCTIONS, got %s", info.State.String())
		}
		env.Module.CloseSession(session2)
	}
}

// TestSessionState_ROSessionRestrictions tests restrictions on SO login when RO sessions exist.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6.6
// "If the application has any read-only sessions open with the token, the SO
// cannot log in and CKR_SESSION_READ_ONLY_EXISTS is returned."
func TestSessionState_ROSessionRestrictions(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Open RO session first
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

	// SO login should fail because RO session exists
	rv = env.Module.Login(rwSession, module.CKU_SO, testutil.TestPINs.SO)
	if rv != module.CKR_SESSION_READ_ONLY_EXISTS {
		t.Errorf("SO login with RO session: expected CKR_SESSION_READ_ONLY_EXISTS, got %s", rv.String())
	}
}

// TestSessionState_ReadOnlySessionRestrictions tests that RO sessions cannot perform write operations.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.7
func TestSessionState_ReadOnlySessionRestrictions(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN via RW session
	rwSession := env.MustOpenRWSession(t)
	env.MustLoginSO(t, rwSession, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(rwSession, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(rwSession), "Logout")
	testutil.RequireOK(t, env.Module.CloseSession(rwSession), "CloseSession")

	// Create a token object via RW session for later tests
	rwSession = env.MustOpenRWSession(t)
	env.MustLoginUser(t, rwSession, testutil.TestPINs.User)

	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
		module.NewStringAttribute(module.CKA_LABEL, "ro-test-object"),
		module.NewAttribute(module.CKA_VALUE, []byte("test")),
		module.NewBoolAttribute(module.CKA_TOKEN, true), // token object
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
	}

	tokenObj, rv := env.Module.CreateObject(rwSession, template)
	if rv != module.CKR_OK {
		t.Fatalf("create token object: expected CKR_OK, got %s", rv.String())
	}
	defer func() {
		env.Module.DestroyObject(rwSession, tokenObj)
	}()

	testutil.RequireOK(t, env.Module.Logout(rwSession), "Logout")
	testutil.RequireOK(t, env.Module.CloseSession(rwSession), "CloseSession")

	// Open RO session and login
	roSession, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("C_OpenSession RO: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.CloseSession(roSession)

	rv = env.Module.Login(roSession, module.CKU_USER, testutil.TestPINs.User)
	if rv != module.CKR_OK {
		t.Fatalf("C_Login: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.Logout(roSession)

	// RO session cannot create token objects
	// Reference: OASIS PKCS#11 v3.0, Section 5.7.1
	t.Run("CreateTokenObject_Fails", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "ro-session-obj"),
			module.NewBoolAttribute(module.CKA_TOKEN, true), // token object
		}

		_, rv := env.Module.CreateObject(roSession, template)
		if rv != module.CKR_SESSION_READ_ONLY {
			t.Errorf("create token object in RO session: expected CKR_SESSION_READ_ONLY, got %s", rv.String())
		}
	})

	// RO session cannot modify token objects
	// Reference: OASIS PKCS#11 v3.0, Section 5.7.6
	t.Run("ModifyTokenObject_Fails", func(t *testing.T) {
		template := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "modified-label"),
		}

		rv := env.Module.SetAttributeValue(roSession, tokenObj, template)
		if rv != module.CKR_SESSION_READ_ONLY {
			t.Errorf("modify token object in RO session: expected CKR_SESSION_READ_ONLY, got %s", rv.String())
		}
	})

	// RO session CAN create session objects
	t.Run("CreateSessionObject_Succeeds", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "ro-session-obj"),
			module.NewBoolAttribute(module.CKA_TOKEN, false), // session object
		}

		handle, rv := env.Module.CreateObject(roSession, template)
		if rv != module.CKR_OK {
			t.Errorf("create session object in RO session: expected CKR_OK, got %s", rv.String())
		}

		if handle != 0 {
			env.Module.DestroyObject(roSession, handle)
		}
	})
}

// TestSessionState_LoginErrors tests various login error conditions.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6.6
func TestSessionState_LoginErrors(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout SO")
	testutil.RequireOK(t, env.Module.CloseSession(session), "CloseSession")

	t.Run("InvalidUserType", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Login(session, module.UserType(99), testutil.TestPINs.User)
		if rv != module.CKR_USER_TYPE_INVALID {
			t.Errorf("login invalid user type: expected CKR_USER_TYPE_INVALID, got %s", rv.String())
		}
	})

	t.Run("WrongPIN", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Login(session, module.CKU_USER, []byte("wrongpin"))
		if rv != module.CKR_PIN_INCORRECT {
			t.Errorf("login wrong PIN: expected CKR_PIN_INCORRECT, got %s", rv.String())
		}
	})

	t.Run("AlreadyLoggedIn", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		if rv != module.CKR_OK {
			t.Fatalf("first login: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.Logout(session)

		// Second login should fail
		rv = env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		if rv != module.CKR_USER_ALREADY_LOGGED_IN {
			t.Errorf("second login: expected CKR_USER_ALREADY_LOGGED_IN, got %s", rv.String())
		}
	})

	t.Run("AnotherUserLoggedIn", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		// Login as user
		rv := env.Module.Login(session, module.CKU_USER, testutil.TestPINs.User)
		if rv != module.CKR_OK {
			t.Fatalf("user login: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.Logout(session)

		// Try to login as SO (different user type)
		rv = env.Module.Login(session, module.CKU_SO, testutil.TestPINs.SO)
		if rv != module.CKR_USER_ANOTHER_ALREADY_LOGGED_IN {
			t.Errorf("SO login while user logged in: expected CKR_USER_ANOTHER_ALREADY_LOGGED_IN, got %s", rv.String())
		}
	})
}

// TestSessionState_LogoutErrors tests various logout error conditions.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6.7
func TestSessionState_LogoutErrors(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	t.Run("NotLoggedIn", func(t *testing.T) {
		session := env.MustOpenRWSession(t)
		defer env.Module.CloseSession(session)

		rv := env.Module.Logout(session)
		if rv != module.CKR_USER_NOT_LOGGED_IN {
			t.Errorf("logout not logged in: expected CKR_USER_NOT_LOGGED_IN, got %s", rv.String())
		}
	})

	t.Run("InvalidSession", func(t *testing.T) {
		rv := env.Module.Logout(999999)
		if rv != module.CKR_SESSION_HANDLE_INVALID {
			t.Errorf("logout invalid session: expected CKR_SESSION_HANDLE_INVALID, got %s", rv.String())
		}
	})
}

// TestSessionState_SessionFlags tests CKF_SERIAL_SESSION requirement.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6.1
// "For legacy reasons, the CKF_SERIAL_SESSION bit MUST always be set."
func TestSessionState_SessionFlags(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// CKF_SERIAL_SESSION must be set
	t.Run("SerialSessionRequired", func(t *testing.T) {
		// No flags (missing CKF_SERIAL_SESSION)
		_, rv := env.Module.OpenSession(0, 0)
		if rv != module.CKR_SESSION_PARALLEL_NOT_SUPPORTED {
			t.Errorf("open without CKF_SERIAL_SESSION: expected CKR_SESSION_PARALLEL_NOT_SUPPORTED, got %s", rv.String())
		}

		// Only CKF_RW_SESSION (missing CKF_SERIAL_SESSION)
		_, rv = env.Module.OpenSession(0, module.CKF_RW_SESSION)
		if rv != module.CKR_SESSION_PARALLEL_NOT_SUPPORTED {
			t.Errorf("open with only CKF_RW_SESSION: expected CKR_SESSION_PARALLEL_NOT_SUPPORTED, got %s", rv.String())
		}
	})

	// Valid flag combinations
	t.Run("ValidFlagCombinations", func(t *testing.T) {
		// CKF_SERIAL_SESSION only
		session1, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
		if rv != module.CKR_OK {
			t.Errorf("open with CKF_SERIAL_SESSION: expected CKR_OK, got %s", rv.String())
		} else {
			env.Module.CloseSession(session1)
		}

		// CKF_SERIAL_SESSION | CKF_RW_SESSION
		session2, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		if rv != module.CKR_OK {
			t.Errorf("open with CKF_SERIAL_SESSION|CKF_RW_SESSION: expected CKR_OK, got %s", rv.String())
		} else {
			env.Module.CloseSession(session2)
		}
	})
}

// TestSessionState_MixedSessions tests behavior with mixed RO/RW sessions.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.6
func TestSessionState_MixedSessions(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout")
	testutil.RequireOK(t, env.Module.CloseSession(session), "CloseSession")

	// Open mixed RO and RW sessions
	roSession1, _ := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
	defer env.Module.CloseSession(roSession1)

	rwSession, _ := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	defer env.Module.CloseSession(rwSession)

	roSession2, _ := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION)
	defer env.Module.CloseSession(roSession2)

	// Login as user via RW session
	rv := env.Module.Login(rwSession, module.CKU_USER, testutil.TestPINs.User)
	if rv != module.CKR_OK {
		t.Fatalf("C_Login: expected CKR_OK, got %s", rv.String())
	}

	// All sessions should now be in logged-in state
	info1, _ := env.Module.GetSessionInfo(roSession1)
	if info1.State != module.CKS_RO_USER_FUNCTIONS {
		t.Errorf("RO session 1: expected CKS_RO_USER_FUNCTIONS, got %s", info1.State.String())
	}

	infoRW, _ := env.Module.GetSessionInfo(rwSession)
	if infoRW.State != module.CKS_RW_USER_FUNCTIONS {
		t.Errorf("RW session: expected CKS_RW_USER_FUNCTIONS, got %s", infoRW.State.String())
	}

	info2, _ := env.Module.GetSessionInfo(roSession2)
	if info2.State != module.CKS_RO_USER_FUNCTIONS {
		t.Errorf("RO session 2: expected CKS_RO_USER_FUNCTIONS, got %s", info2.State.String())
	}

	// Logout from RO session should affect all sessions
	rv = env.Module.Logout(roSession1)
	if rv != module.CKR_OK {
		t.Fatalf("C_Logout: expected CKR_OK, got %s", rv.String())
	}

	// All sessions should be in public state
	info1, _ = env.Module.GetSessionInfo(roSession1)
	if info1.State != module.CKS_RO_PUBLIC_SESSION {
		t.Errorf("RO session 1 after logout: expected CKS_RO_PUBLIC_SESSION, got %s", info1.State.String())
	}

	infoRW, _ = env.Module.GetSessionInfo(rwSession)
	if infoRW.State != module.CKS_RW_PUBLIC_SESSION {
		t.Errorf("RW session after logout: expected CKS_RW_PUBLIC_SESSION, got %s", infoRW.State.String())
	}
}
