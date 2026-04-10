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

package pkcs11test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// RunSessionTests runs PKCS#11 v3.0 Section 5.6 Session Management conformance tests.
//
// Tests cover:
//   - C_OpenSession: open RW/RO sessions, invalid slot, missing flags, uninitialized module
//   - C_CloseSession: close valid session, close invalid handle
//   - C_CloseAllSessions: close all sessions on a slot, verify closed handles are invalid
//   - C_GetSessionInfo: retrieve info for RW session, invalid handle
//   - C_Login / C_Logout: SO and user login state transitions, double login, logout without login
//   - C_LoginUser (v3.0): context-specific login
//   - C_SessionCancel (v3.0): cancel active operation
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.6
func (s *Suite) RunSessionTests(t *testing.T) {
	t.Run("C_OpenSession", s.testOpenSession)
	t.Run("C_CloseSession", s.testCloseSession)
	t.Run("C_CloseAllSessions", s.testCloseAllSessions)
	t.Run("C_GetSessionInfo", s.testGetSessionInfo)
	t.Run("C_Login_C_Logout", s.testLoginLogout)
	t.Run("C_LoginUser", s.testLoginUser)
	t.Run("C_SessionCancel", s.testSessionCancel)
}

// testOpenSession verifies C_OpenSession behavior per PKCS#11 Section 5.6.1.
func (s *Suite) testOpenSession(t *testing.T) {

	t.Run("RW_session_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		requireRV(t, module.CKR_OK, rv, "OpenSession RW should succeed")

		rv = m.CloseSession(handle)
		requireRV(t, module.CKR_OK, rv, "CloseSession should succeed")
	})

	t.Run("RO_session_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION)
		requireRV(t, module.CKR_OK, rv, "OpenSession RO should succeed")

		rv = m.CloseSession(handle)
		requireRV(t, module.CKR_OK, rv, "CloseSession should succeed")
	})

	t.Run("invalid_slot_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		_, rv := m.OpenSession(9999, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		requireRV(t, module.CKR_SLOT_ID_INVALID, rv,
			"OpenSession with invalid slot should return CKR_SLOT_ID_INVALID")
	})

	t.Run("missing_serial_session_flag_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		// CKF_SERIAL_SESSION (0x04) must always be set per PKCS#11 spec.
		// Passing only CKF_RW_SESSION (0x02) without CKF_SERIAL_SESSION
		// must return CKR_SESSION_PARALLEL_NOT_SUPPORTED.
		_, rv := m.OpenSession(0, module.CKF_RW_SESSION)
		requireRV(t, module.CKR_SESSION_PARALLEL_NOT_SUPPORTED, rv,
			"OpenSession without CKF_SERIAL_SESSION should return CKR_SESSION_PARALLEL_NOT_SUPPORTED")
	})

	t.Run("not_initialized_fails", func(t *testing.T) {
		m, cleanup := s.factory(t)
		defer cleanup()

		// Module is not initialized; all operations must fail.
		_, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		requireRV(t, module.CKR_CRYPTOKI_NOT_INITIALIZED, rv,
			"OpenSession on uninitialized module should return CKR_CRYPTOKI_NOT_INITIALIZED")
	})
}

// testCloseSession verifies C_CloseSession behavior per PKCS#11 Section 5.6.2.
func (s *Suite) testCloseSession(t *testing.T) {

	t.Run("close_valid_session_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)
		rv := m.CloseSession(handle)
		requireRV(t, module.CKR_OK, rv, "CloseSession on valid handle should succeed")
	})

	t.Run("close_invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.CloseSession(module.SessionHandle(0xDEADBEEF))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"CloseSession with invalid handle should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("double_close_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)
		rv := m.CloseSession(handle)
		requireRV(t, module.CKR_OK, rv, "first CloseSession should succeed")

		rv = m.CloseSession(handle)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"second CloseSession on same handle should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testCloseAllSessions verifies C_CloseAllSessions behavior per PKCS#11 Section 5.6.3.
func (s *Suite) testCloseAllSessions(t *testing.T) {

	t.Run("closes_all_sessions_on_slot", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		// Open multiple sessions
		h1 := openRWSession(t, m)
		h2 := openROSession(t, m)
		h3 := openRWSession(t, m)

		rv := m.CloseAllSessions(0)
		requireRV(t, module.CKR_OK, rv, "CloseAllSessions should succeed")

		// All previously opened session handles must now be invalid
		rv = m.CloseSession(h1)
		assertRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"session h1 should be invalid after CloseAllSessions")

		rv = m.CloseSession(h2)
		assertRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"session h2 should be invalid after CloseAllSessions")

		rv = m.CloseSession(h3)
		assertRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"session h3 should be invalid after CloseAllSessions")
	})

	t.Run("operations_on_closed_sessions_fail", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)

		rv := m.CloseAllSessions(0)
		requireRV(t, module.CKR_OK, rv, "CloseAllSessions should succeed")

		// GetSessionInfo on a closed handle must fail
		_, rv = m.GetSessionInfo(handle)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"GetSessionInfo on closed session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("invalid_slot_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.CloseAllSessions(9999)
		requireRV(t, module.CKR_SLOT_ID_INVALID, rv,
			"CloseAllSessions with invalid slot should return CKR_SLOT_ID_INVALID")
	})
}

// testGetSessionInfo verifies C_GetSessionInfo behavior per PKCS#11 Section 5.6.4.
func (s *Suite) testGetSessionInfo(t *testing.T) {

	t.Run("RW_public_session_info", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)
		defer func() { m.CloseSession(handle) }()

		info, rv := m.GetSessionInfo(handle)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo should succeed")

		if info == nil {
			t.Fatal("GetSessionInfo returned nil SessionInfo")
		}

		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Fatalf("expected state CKS_RW_PUBLIC_SESSION (%d), got %s (%d)",
				module.CKS_RW_PUBLIC_SESSION, info.State, info.State)
		}

		if info.Flags&module.CKF_RW_SESSION == 0 {
			t.Fatal("expected CKF_RW_SESSION flag to be set")
		}

		if info.Flags&module.CKF_SERIAL_SESSION == 0 {
			t.Fatal("expected CKF_SERIAL_SESSION flag to be set")
		}
	})

	t.Run("RO_public_session_info", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openROSession(t, m)
		defer func() { m.CloseSession(handle) }()

		info, rv := m.GetSessionInfo(handle)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo should succeed")

		if info == nil {
			t.Fatal("GetSessionInfo returned nil SessionInfo")
		}

		if info.State != module.CKS_RO_PUBLIC_SESSION {
			t.Fatalf("expected state CKS_RO_PUBLIC_SESSION (%d), got %s (%d)",
				module.CKS_RO_PUBLIC_SESSION, info.State, info.State)
		}

		if info.Flags&module.CKF_RW_SESSION != 0 {
			t.Fatal("expected CKF_RW_SESSION flag to be unset for RO session")
		}
	})

	t.Run("invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		_, rv := m.GetSessionInfo(module.SessionHandle(0xDEADBEEF))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"GetSessionInfo with invalid handle should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testLoginLogout verifies C_Login and C_Logout behavior per PKCS#11 Section 5.6.5-5.6.6.
func (s *Suite) testLoginLogout(t *testing.T) {

	t.Run("login_as_SO_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)
		defer func() { m.CloseSession(handle) }()

		rv := m.Login(handle, module.CKU_SO, []byte("12345678"))
		requireRV(t, module.CKR_OK, rv, "Login as SO should succeed")

		// Verify session state transitioned to CKS_RW_SO_FUNCTIONS
		info, rv := m.GetSessionInfo(handle)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo should succeed")

		if info.State != module.CKS_RW_SO_FUNCTIONS {
			t.Fatalf("expected state CKS_RW_SO_FUNCTIONS (%d), got %s (%d)",
				module.CKS_RW_SO_FUNCTIONS, info.State, info.State)
		}

		rv = m.Logout(handle)
		requireRV(t, module.CKR_OK, rv, "Logout should succeed")
	})

	t.Run("login_as_user_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)

		handle := openRWSession(t, m)
		defer func() { m.CloseSession(handle) }()

		loginAsUser(t, m, handle)

		// Verify session state transitioned to CKS_RW_USER_FUNCTIONS
		info, rv := m.GetSessionInfo(handle)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo should succeed")

		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Fatalf("expected state CKS_RW_USER_FUNCTIONS (%d), got %s (%d)",
				module.CKS_RW_USER_FUNCTIONS, info.State, info.State)
		}

		rv = m.Logout(handle)
		requireRV(t, module.CKR_OK, rv, "Logout should succeed")
	})

	t.Run("RO_user_login_state", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)

		handle := openROSession(t, m)
		defer func() { m.CloseSession(handle) }()

		loginAsUser(t, m, handle)

		// Verify RO session transitions to CKS_RO_USER_FUNCTIONS
		info, rv := m.GetSessionInfo(handle)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo should succeed")

		if info.State != module.CKS_RO_USER_FUNCTIONS {
			t.Fatalf("expected state CKS_RO_USER_FUNCTIONS (%d), got %s (%d)",
				module.CKS_RO_USER_FUNCTIONS, info.State, info.State)
		}

		rv = m.Logout(handle)
		requireRV(t, module.CKR_OK, rv, "Logout should succeed")
	})

	t.Run("double_login_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)

		handle := openRWSession(t, m)
		defer func() {
			m.Logout(handle)
			m.CloseSession(handle)
		}()

		loginAsUser(t, m, handle)

		// Second login as the same user type must fail
		rv := m.Login(handle, module.CKU_USER, []byte("userpin"))
		requireRV(t, module.CKR_USER_ALREADY_LOGGED_IN, rv,
			"double login should return CKR_USER_ALREADY_LOGGED_IN")
	})

	t.Run("logout_without_login_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)
		defer func() { m.CloseSession(handle) }()

		rv := m.Logout(handle)
		requireRV(t, module.CKR_USER_NOT_LOGGED_IN, rv,
			"Logout without login should return CKR_USER_NOT_LOGGED_IN")
	})

	t.Run("login_invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.Login(module.SessionHandle(0xDEADBEEF), module.CKU_USER, []byte("userpin"))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Login with invalid handle should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("logout_invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.Logout(module.SessionHandle(0xDEADBEEF))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"Logout with invalid handle should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("login_wrong_PIN_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)
		defer func() { m.CloseSession(handle) }()

		rv := m.Login(handle, module.CKU_SO, []byte("wrong-pin"))
		requireRV(t, module.CKR_PIN_INCORRECT, rv,
			"Login with wrong PIN should return CKR_PIN_INCORRECT")
	})

	t.Run("login_affects_all_sessions", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)

		// Open two RW sessions
		h1 := openRWSession(t, m)
		h2 := openRWSession(t, m)
		defer func() {
			m.Logout(h1)
			m.CloseSession(h1)
			m.CloseSession(h2)
		}()

		// Login via the first session
		loginAsUser(t, m, h1)

		// Per PKCS#11, login state applies to all sessions on the token.
		// The second session should also reflect the logged-in state.
		info, rv := m.GetSessionInfo(h2)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo on h2 should succeed")

		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Fatalf("expected h2 state CKS_RW_USER_FUNCTIONS (%d), got %s (%d)",
				module.CKS_RW_USER_FUNCTIONS, info.State, info.State)
		}
	})

	t.Run("logout_affects_all_sessions", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)

		h1 := openRWSession(t, m)
		h2 := openRWSession(t, m)
		defer func() {
			m.CloseSession(h1)
			m.CloseSession(h2)
		}()

		loginAsUser(t, m, h1)

		// Logout via the first session
		rv := m.Logout(h1)
		requireRV(t, module.CKR_OK, rv, "Logout should succeed")

		// Both sessions should return to public state
		info1, rv := m.GetSessionInfo(h1)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo on h1 should succeed")
		if info1.State != module.CKS_RW_PUBLIC_SESSION {
			t.Fatalf("expected h1 state CKS_RW_PUBLIC_SESSION, got %s", info1.State)
		}

		info2, rv := m.GetSessionInfo(h2)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo on h2 should succeed")
		if info2.State != module.CKS_RW_PUBLIC_SESSION {
			t.Fatalf("expected h2 state CKS_RW_PUBLIC_SESSION, got %s", info2.State)
		}
	})
}

// testLoginUser verifies C_LoginUser behavior per PKCS#11 v3.0 Section 5.6.7.
func (s *Suite) testLoginUser(t *testing.T) {

	t.Run("login_user_v3_supported", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)

		handle := openRWSession(t, m)
		defer func() {
			m.Logout(handle)
			m.CloseSession(handle)
		}()

		rv := m.LoginUser(handle, module.CKU_USER, []byte("userpin"), "testuser")
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "LoginUser as CKU_USER should succeed")

		// Verify the session transitioned to user functions state
		info, rv := m.GetSessionInfo(handle)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo should succeed after LoginUser")

		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Fatalf("expected state CKS_RW_USER_FUNCTIONS (%d), got %s (%d)",
				module.CKS_RW_USER_FUNCTIONS, info.State, info.State)
		}
	})

	t.Run("login_user_SO_v3_supported", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)
		defer func() {
			m.Logout(handle)
			m.CloseSession(handle)
		}()

		rv := m.LoginUser(handle, module.CKU_SO, []byte("12345678"), "admin")
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "LoginUser as CKU_SO should succeed")

		info, rv := m.GetSessionInfo(handle)
		requireRV(t, module.CKR_OK, rv, "GetSessionInfo should succeed after LoginUser SO")

		if info.State != module.CKS_RW_SO_FUNCTIONS {
			t.Fatalf("expected state CKS_RW_SO_FUNCTIONS (%d), got %s (%d)",
				module.CKS_RW_SO_FUNCTIONS, info.State, info.State)
		}
	})

	t.Run("login_user_invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.LoginUser(module.SessionHandle(0xDEADBEEF), module.CKU_USER, []byte("userpin"), "testuser")
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"LoginUser with invalid handle should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testSessionCancel verifies C_SessionCancel behavior per PKCS#11 v3.0 Section 5.16.1.
func (s *Suite) testSessionCancel(t *testing.T) {

	t.Run("cancel_no_active_operation", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		handle := openRWSession(t, m)
		defer func() { m.CloseSession(handle) }()

		rv := m.SessionCancel(handle, 0)
		if s.skipIfUnsupported(t, rv) {
			return
		}

		// With no active operation, the spec says CKR_OPERATION_NOT_INITIALIZED
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"SessionCancel with no active operation should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("cancel_invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.SessionCancel(module.SessionHandle(0xDEADBEEF), 0)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"SessionCancel with invalid handle should return CKR_SESSION_HANDLE_INVALID")
	})
}
