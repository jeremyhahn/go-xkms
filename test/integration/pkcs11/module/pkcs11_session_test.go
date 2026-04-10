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
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestOpenCloseSession tests basic session lifecycle.
func TestOpenCloseSession(t *testing.T) {
	t.Run("OpenReadOnlySession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session, rv := env.OpenROSession(t)
		RequireOK(t, rv, "OpenSession (RO)")

		if session == 0 || session == module.SessionHandle(module.InvalidHandle) {
			t.Error("expected valid session handle")
		}

		// Verify session info
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		if info.State != module.CKS_RO_PUBLIC_SESSION {
			t.Errorf("expected state CKS_RO_PUBLIC_SESSION, got %s", info.State.String())
		}

		if info.Flags&module.CKF_RW_SESSION != 0 {
			t.Error("RO session should not have CKF_RW_SESSION flag")
		}

		rv = env.Module.CloseSession(session)
		RequireOK(t, rv, "CloseSession")
	})

	t.Run("OpenReadWriteSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session, rv := env.OpenRWSession(t)
		RequireOK(t, rv, "OpenSession (RW)")

		// Verify session info
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("expected state CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}

		if info.Flags&module.CKF_RW_SESSION == 0 {
			t.Error("RW session should have CKF_RW_SESSION flag")
		}

		rv = env.Module.CloseSession(session)
		RequireOK(t, rv, "CloseSession")
	})

	t.Run("OpenSessionWithoutSerialFlag", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// CKF_SERIAL_SESSION must be set per PKCS#11 spec
		_, rv := env.Module.OpenSession(0, module.CKF_RW_SESSION)
		RequireReturnValue(t, rv, module.CKR_SESSION_PARALLEL_NOT_SUPPORTED,
			"OpenSession without CKF_SERIAL_SESSION")
	})

	t.Run("OpenSessionInvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		_, rv := env.Module.OpenSession(9999, module.CKF_SERIAL_SESSION)
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "OpenSession with invalid slot")
	})

	t.Run("CloseInvalidSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		rv := env.Module.CloseSession(module.SessionHandle(9999))
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "CloseSession with invalid handle")
	})

	t.Run("CloseAlreadyClosedSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		// First close should succeed
		rv := env.Module.CloseSession(session)
		RequireOK(t, rv, "first CloseSession")

		// Second close should fail
		rv = env.Module.CloseSession(session)
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "CloseSession already closed")
	})
}

// TestMultipleSessions tests handling of multiple concurrent sessions.
func TestMultipleSessions(t *testing.T) {
	t.Run("OpenMultipleSessions", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		const numSessions = 10
		sessions := make([]module.SessionHandle, numSessions)

		// Open multiple sessions
		for i := 0; i < numSessions; i++ {
			session, rv := env.OpenRWSession(t)
			RequireOK(t, rv, "OpenSession")
			sessions[i] = session
		}

		// Verify all sessions are valid and unique
		handleSet := make(map[module.SessionHandle]bool)
		for _, session := range sessions {
			if handleSet[session] {
				t.Error("duplicate session handle detected")
			}
			handleSet[session] = true

			info, rv := env.Module.GetSessionInfo(session)
			RequireOK(t, rv, "GetSessionInfo")
			if info.State != module.CKS_RW_PUBLIC_SESSION {
				t.Errorf("expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
			}
		}

		// Close all sessions
		for _, session := range sessions {
			rv := env.Module.CloseSession(session)
			RequireOK(t, rv, "CloseSession")
		}
	})

	t.Run("MixedReadOnlyAndReadWriteSessions", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open RW sessions
		rw1 := env.MustOpenRWSession(t)
		rw2 := env.MustOpenRWSession(t)

		// Open RO sessions
		ro1 := env.MustOpenROSession(t)
		ro2 := env.MustOpenROSession(t)

		// Verify session types
		info, rv := env.Module.GetSessionInfo(rw1)
		RequireOK(t, rv, "GetSessionInfo rw1")
		if info.Flags&module.CKF_RW_SESSION == 0 {
			t.Error("rw1 should be RW session")
		}

		info, rv = env.Module.GetSessionInfo(ro1)
		RequireOK(t, rv, "GetSessionInfo ro1")
		if info.Flags&module.CKF_RW_SESSION != 0 {
			t.Error("ro1 should be RO session")
		}

		// Close all
		env.Module.CloseSession(rw1)
		env.Module.CloseSession(rw2)
		env.Module.CloseSession(ro1)
		env.Module.CloseSession(ro2)
	})

	t.Run("ConcurrentSessionOperations", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		const numGoroutines = 5
		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				// Open session
				session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
				if rv != module.CKR_OK {
					errors <- module.NewPKCS11Error(rv)
					return
				}

				// Get session info
				_, rv = env.Module.GetSessionInfo(session)
				if rv != module.CKR_OK {
					errors <- module.NewPKCS11Error(rv)
					return
				}

				// Close session
				rv = env.Module.CloseSession(session)
				if rv != module.CKR_OK {
					errors <- module.NewPKCS11Error(rv)
					return
				}
			}()
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("concurrent session operation failed: %v", err)
		}
	})
}

// TestLoginLogout tests user authentication operations.
func TestLoginLogout(t *testing.T) {
	t.Run("LoginAsUser", func(t *testing.T) {
		env, session := SetupInitializedModule(t)

		// Login as user
		rv := env.LoginUser(t, session, TestPINs.User)
		RequireOK(t, rv, "Login as user")

		// Verify session state changed
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Errorf("expected CKS_RW_USER_FUNCTIONS, got %s", info.State.String())
		}
	})

	t.Run("LoginAsSO", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		// Login as SO
		rv := env.LoginSO(t, session, TestPINs.SO)
		RequireOK(t, rv, "Login as SO")

		// Verify session state
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		if info.State != module.CKS_RW_SO_FUNCTIONS {
			t.Errorf("expected CKS_RW_SO_FUNCTIONS, got %s", info.State.String())
		}
	})

	t.Run("LoginWithIncorrectPIN", func(t *testing.T) {
		env, session := SetupInitializedModule(t)

		rv := env.LoginUser(t, session, []byte("wrongpin"))
		RequireReturnValue(t, rv, module.CKR_PIN_INCORRECT, "Login with wrong PIN")
	})

	t.Run("LoginAlreadyLoggedIn", func(t *testing.T) {
		env, session := SetupInitializedModule(t)

		// First login
		env.MustLoginUser(t, session, TestPINs.User)

		// Second login should fail
		rv := env.LoginUser(t, session, TestPINs.User)
		RequireReturnValue(t, rv, module.CKR_USER_ALREADY_LOGGED_IN, "Login when already logged in")
	})

	t.Run("LoginDifferentUserType", func(t *testing.T) {
		env, session := SetupInitializedModule(t)

		// Login as user
		env.MustLoginUser(t, session, TestPINs.User)

		// Trying to login as SO while user is logged in should fail
		rv := env.LoginSO(t, session, TestPINs.SO)
		RequireReturnValue(t, rv, module.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
			"Login as SO while user logged in")
	})

	t.Run("Logout", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		// Logout
		rv := env.Module.Logout(session)
		RequireOK(t, rv, "Logout")

		// Verify session state changed back to public
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo after logout")

		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("expected CKS_RW_PUBLIC_SESSION after logout, got %s", info.State.String())
		}
	})

	t.Run("LogoutWhenNotLoggedIn", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		rv := env.Module.Logout(session)
		RequireReturnValue(t, rv, module.CKR_USER_NOT_LOGGED_IN, "Logout when not logged in")
	})

	t.Run("SOLoginRequiresRWSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open RO session
		session := env.MustOpenROSession(t)

		// SO login should fail on RO session
		rv := env.LoginSO(t, session, TestPINs.SO)
		RequireReturnValue(t, rv, module.CKR_SESSION_READ_ONLY, "SO login on RO session")
	})

	t.Run("SOLoginBlockedByROSessions", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open an RO session first
		_ = env.MustOpenROSession(t)

		// Open an RW session for SO login attempt
		rwSession := env.MustOpenRWSession(t)

		// SO login should fail because RO sessions exist
		rv := env.LoginSO(t, rwSession, TestPINs.SO)
		RequireReturnValue(t, rv, module.CKR_SESSION_READ_ONLY_EXISTS, "SO login with RO sessions")
	})

	t.Run("LoginInvalidUserType", func(t *testing.T) {
		env, session := SetupInitializedModule(t)

		// Use an invalid user type
		rv := env.Module.Login(session, module.UserType(99), TestPINs.User)
		RequireReturnValue(t, rv, module.CKR_USER_TYPE_INVALID, "Login with invalid user type")
	})
}

// TestSessionInfo tests C_GetSessionInfo functionality.
func TestSessionInfo(t *testing.T) {
	t.Run("GetSessionInfoValidSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		if info == nil {
			t.Fatal("GetSessionInfo returned nil")
		}

		// Verify info fields
		if info.SlotID != 0 {
			t.Errorf("expected slot ID 0, got %d", info.SlotID)
		}

		if info.Flags&module.CKF_SERIAL_SESSION == 0 {
			t.Error("session should have CKF_SERIAL_SESSION flag")
		}

		t.Logf("Session Info:")
		t.Logf("  Slot ID: %d", info.SlotID)
		t.Logf("  State: %s", info.State.String())
		t.Logf("  Flags: 0x%08X", info.Flags)
		t.Logf("  Device Error: %d", info.DeviceError)
	})

	t.Run("GetSessionInfoInvalidSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		_, rv := env.Module.GetSessionInfo(module.SessionHandle(9999))
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "GetSessionInfo invalid session")
	})

	t.Run("SessionStateTransitions", func(t *testing.T) {
		env, session := SetupInitializedModule(t)

		// Initial state: RW public session
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo initial")
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("expected CKS_RW_PUBLIC_SESSION initially, got %s", info.State.String())
		}

		// Login: state changes to RW user functions
		env.MustLoginUser(t, session, TestPINs.User)
		info, rv = env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo after login")
		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Errorf("expected CKS_RW_USER_FUNCTIONS after login, got %s", info.State.String())
		}

		// Logout: state returns to RW public session
		rv = env.Module.Logout(session)
		RequireOK(t, rv, "Logout")
		info, rv = env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo after logout")
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("expected CKS_RW_PUBLIC_SESSION after logout, got %s", info.State.String())
		}
	})
}

// TestCloseAllSessions tests C_CloseAllSessions functionality.
func TestCloseAllSessions(t *testing.T) {
	t.Run("CloseAllSessionsForSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open multiple sessions
		session1 := env.MustOpenRWSession(t)
		session2 := env.MustOpenROSession(t)
		session3 := env.MustOpenRWSession(t)

		// Close all sessions for slot 0
		rv := env.Module.CloseAllSessions(0)
		RequireOK(t, rv, "CloseAllSessions")

		// All sessions should now be invalid
		_, rv = env.Module.GetSessionInfo(session1)
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "session1 after CloseAllSessions")

		_, rv = env.Module.GetSessionInfo(session2)
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "session2 after CloseAllSessions")

		_, rv = env.Module.GetSessionInfo(session3)
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "session3 after CloseAllSessions")
	})

	t.Run("CloseAllSessionsInvalidSlot", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		rv := env.Module.CloseAllSessions(9999)
		RequireReturnValue(t, rv, module.CKR_SLOT_ID_INVALID, "CloseAllSessions invalid slot")
	})

	t.Run("CloseAllSessionsLogsOutUser", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		// Verify logged in
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo before close all")
		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Error("should be in CKS_RW_USER_FUNCTIONS state")
		}

		// Close all sessions
		rv = env.Module.CloseAllSessions(0)
		RequireOK(t, rv, "CloseAllSessions")

		// Open a new session - should be in public state
		newSession := env.MustOpenRWSession(t)
		info, rv = env.Module.GetSessionInfo(newSession)
		RequireOK(t, rv, "GetSessionInfo new session")
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("expected CKS_RW_PUBLIC_SESSION for new session, got %s", info.State.String())
		}
	})
}

// TestPINOperations tests C_InitPIN and C_SetPIN functionality.
func TestPINOperations(t *testing.T) {
	t.Run("InitPIN", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		env.MustLoginSO(t, session, TestPINs.SO)

		// Initialize user PIN
		rv := env.Module.InitPIN(session, TestPINs.User)
		RequireOK(t, rv, "InitPIN")

		// Logout and verify user can login with new PIN
		rv = env.Module.Logout(session)
		RequireOK(t, rv, "Logout SO")

		rv = env.LoginUser(t, session, TestPINs.User)
		RequireOK(t, rv, "Login with new user PIN")
	})

	t.Run("InitPINRequiresSOLogin", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		// Try to init PIN without SO login
		rv := env.Module.InitPIN(session, TestPINs.User)
		RequireReturnValue(t, rv, module.CKR_USER_NOT_LOGGED_IN, "InitPIN without SO login")
	})

	t.Run("InitPINRequiresRWSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// First login as SO in RW session to set things up
		rwSession := env.MustOpenRWSession(t)
		env.MustLoginSO(t, rwSession, TestPINs.SO)

		// Note: RO session cannot be opened while SO is logged in per PKCS#11
		// So this test validates the constraint is in place

		// With SO logged in, trying to open RO session should fail
		_, rv := env.OpenROSession(t)
		RequireReturnValue(t, rv, module.CKR_SESSION_READ_WRITE_SO_EXISTS, "RO session while SO logged in")
	})

	t.Run("SetPINAsUser", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		newPIN := []byte("newuserpin")

		// Change user PIN
		rv := env.Module.SetPIN(session, TestPINs.User, newPIN)
		RequireOK(t, rv, "SetPIN as user")

		// Logout and login with new PIN
		rv = env.Module.Logout(session)
		RequireOK(t, rv, "Logout")

		rv = env.LoginUser(t, session, newPIN)
		RequireOK(t, rv, "Login with new PIN")
	})

	t.Run("SetPINWithIncorrectOldPIN", func(t *testing.T) {
		env, session := SetupInitializedModule(t)
		env.MustLoginUser(t, session, TestPINs.User)

		rv := env.Module.SetPIN(session, []byte("wrongpin"), []byte("newpin"))
		RequireReturnValue(t, rv, module.CKR_PIN_INCORRECT, "SetPIN with wrong old PIN")
	})

	t.Run("SetPINWithoutLogin", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		rv := env.Module.SetPIN(session, TestPINs.User, []byte("newpin"))
		RequireReturnValue(t, rv, module.CKR_USER_NOT_LOGGED_IN, "SetPIN without login")
	})
}

// TestSessionObjectCleanup tests that session objects are cleaned up when session closes.
func TestSessionObjectCleanup(t *testing.T) {
	t.Run("SessionObjectsDestroyedOnClose", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Create a session object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "test-session-object"),
			module.NewBoolAttribute(module.CKA_TOKEN, false), // Session object
			module.NewAttribute(module.CKA_VALUE, []byte("test data")),
		}

		handle, rv := env.Module.CreateObject(session, template)
		RequireOK(t, rv, "CreateObject")

		// Verify object exists
		_, rv = env.Module.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		RequireOK(t, rv, "GetAttributeValue before close")

		// Close session
		rv = env.Module.CloseSession(session)
		RequireOK(t, rv, "CloseSession")

		// Open new session
		newSession := env.MustOpenRWSession(t)
		env.MustLoginUser(t, newSession, TestPINs.User)

		// Session object should no longer exist
		_, rv = env.Module.GetAttributeValue(newSession, handle, []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		RequireReturnValue(t, rv, module.CKR_OBJECT_HANDLE_INVALID, "GetAttributeValue after close")
	})
}
