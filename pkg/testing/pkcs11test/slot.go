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

// RunSlotTests runs PKCS#11 v3.0 Section 5.5 Slot and Token Management conformance tests.
//
// Tests cover:
//   - C_GetSlotList: enumerate slots with and without token presence filter
//   - C_GetSlotInfo: retrieve slot information, invalid slot handling
//   - C_GetTokenInfo: retrieve token information after initialization, invalid slot handling
//   - C_GetMechanismList: enumerate supported mechanisms, invalid slot handling
//   - C_GetMechanismInfo: retrieve mechanism details, invalid mechanism/slot handling
//   - C_InitToken: initialize token with SO PIN, re-initialization
//   - C_InitPIN: set user PIN after SO login, error without SO login
//   - C_SetPIN: change current PIN, error with wrong old PIN
//   - C_WaitForSlotEvent: non-blocking slot event polling
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.5
func (s *Suite) RunSlotTests(t *testing.T) {
	t.Run("C_GetSlotList", s.testGetSlotList)
	t.Run("C_GetSlotInfo", s.testGetSlotInfo)
	t.Run("C_GetTokenInfo", s.testGetTokenInfo)
	t.Run("C_GetMechanismList", s.testGetMechanismList)
	t.Run("C_GetMechanismInfo", s.testGetMechanismInfo)
	t.Run("C_InitToken", s.testInitToken)
	t.Run("C_InitPIN", s.testInitPIN)
	t.Run("C_SetPIN", s.testSetPIN)
	t.Run("C_WaitForSlotEvent", s.testWaitForSlotEvent)
}

// testGetSlotList verifies C_GetSlotList behavior per PKCS#11 v3.0 Section 5.5.1.
func (s *Suite) testGetSlotList(t *testing.T) {

	t.Run("returns_at_least_one_slot", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		slots, rv := m.GetSlotList(false)
		requireRV(t, module.CKR_OK, rv, "GetSlotList(false) should return CKR_OK")

		if len(slots) == 0 {
			t.Fatal("GetSlotList(false) should return at least one slot")
		}
	})

	t.Run("token_present_true_returns_slots", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		slots, rv := m.GetSlotList(true)
		requireRV(t, module.CKR_OK, rv, "GetSlotList(true) should return CKR_OK")

		if len(slots) == 0 {
			t.Fatal("GetSlotList(true) should return at least one slot after token initialization")
		}
	})

	t.Run("token_present_false_returns_all_slots", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		allSlots, rv := m.GetSlotList(false)
		requireRV(t, module.CKR_OK, rv, "GetSlotList(false) should return CKR_OK")

		presentSlots, rv := m.GetSlotList(true)
		requireRV(t, module.CKR_OK, rv, "GetSlotList(true) should return CKR_OK")

		if len(allSlots) < len(presentSlots) {
			t.Fatalf("GetSlotList(false) returned %d slots, but GetSlotList(true) returned %d; "+
				"all-slots list must be >= token-present list",
				len(allSlots), len(presentSlots))
		}
	})
}

// testGetSlotInfo verifies C_GetSlotInfo behavior per PKCS#11 v3.0 Section 5.5.2.
func (s *Suite) testGetSlotInfo(t *testing.T) {

	t.Run("valid_slot_returns_info", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		info, rv := m.GetSlotInfo(0)
		requireRV(t, module.CKR_OK, rv, "GetSlotInfo(0) should return CKR_OK")

		if info == nil {
			t.Fatal("GetSlotInfo returned nil SlotInfo for slot 0")
		}

		if info.GetSlotDescription() == "" {
			t.Error("SlotInfo.SlotDescription should be non-empty")
		}

		if info.GetManufacturerID() == "" {
			t.Error("SlotInfo.ManufacturerID should be non-empty")
		}
	})

	t.Run("invalid_slot_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		_, rv := m.GetSlotInfo(9999)
		requireRV(t, module.CKR_SLOT_ID_INVALID, rv,
			"GetSlotInfo with invalid slot should return CKR_SLOT_ID_INVALID")
	})
}

// testGetTokenInfo verifies C_GetTokenInfo behavior per PKCS#11 v3.0 Section 5.5.3.
func (s *Suite) testGetTokenInfo(t *testing.T) {

	t.Run("returns_valid_info_after_init", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		info, rv := m.GetTokenInfo(0)
		requireRV(t, module.CKR_OK, rv, "GetTokenInfo(0) should return CKR_OK")

		if info == nil {
			t.Fatal("GetTokenInfo returned nil TokenInfo")
		}

		if info.GetLabel() == "" {
			t.Error("TokenInfo.Label should be non-empty after InitToken")
		}

		if info.GetManufacturerID() == "" {
			t.Error("TokenInfo.ManufacturerID should be non-empty")
		}

		if info.GetModel() == "" {
			t.Error("TokenInfo.Model should be non-empty")
		}

		if info.GetSerialNumber() == "" {
			t.Error("TokenInfo.SerialNumber should be non-empty")
		}
	})

	t.Run("invalid_slot_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		_, rv := m.GetTokenInfo(9999)
		requireRV(t, module.CKR_SLOT_ID_INVALID, rv,
			"GetTokenInfo with invalid slot should return CKR_SLOT_ID_INVALID")
	})
}

// testGetMechanismList verifies C_GetMechanismList behavior per PKCS#11 v3.0 Section 5.5.4.
func (s *Suite) testGetMechanismList(t *testing.T) {

	t.Run("returns_non_empty_list", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		mechs, rv := m.GetMechanismList(0)
		requireRV(t, module.CKR_OK, rv, "GetMechanismList(0) should return CKR_OK")

		if len(mechs) == 0 {
			t.Fatal("GetMechanismList should return at least one mechanism for slot 0")
		}
	})

	t.Run("invalid_slot_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		_, rv := m.GetMechanismList(9999)
		requireRV(t, module.CKR_SLOT_ID_INVALID, rv,
			"GetMechanismList with invalid slot should return CKR_SLOT_ID_INVALID")
	})
}

// testGetMechanismInfo verifies C_GetMechanismInfo behavior per PKCS#11 v3.0 Section 5.5.5.
func (s *Suite) testGetMechanismInfo(t *testing.T) {

	t.Run("returns_valid_info_for_known_mechanism", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		// Get the mechanism list so we can query info for a real mechanism.
		mechs, rv := m.GetMechanismList(0)
		requireRV(t, module.CKR_OK, rv, "GetMechanismList should return CKR_OK")

		if len(mechs) == 0 {
			t.Fatal("GetMechanismList returned no mechanisms; cannot test GetMechanismInfo")
		}

		info, rv := m.GetMechanismInfo(0, mechs[0])
		requireRV(t, module.CKR_OK, rv, "GetMechanismInfo for a supported mechanism should return CKR_OK")

		if info == nil {
			t.Fatal("GetMechanismInfo returned nil MechanismInfo")
		}

		// The flags field must have at least one capability bit set for a
		// mechanism that appears in the mechanism list.
		if info.Flags == 0 {
			t.Error("MechanismInfo.Flags should have at least one capability bit set")
		}
	})

	t.Run("invalid_mechanism_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		// Use an invalid mechanism type that is unlikely to be supported.
		_, rv := m.GetMechanismInfo(0, module.MechanismType(0xFFFFFFFF))
		requireRV(t, module.CKR_MECHANISM_INVALID, rv,
			"GetMechanismInfo with invalid mechanism should return CKR_MECHANISM_INVALID")
	})

	t.Run("invalid_slot_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		_, rv := m.GetMechanismInfo(9999, module.MechanismType(0))
		requireRV(t, module.CKR_SLOT_ID_INVALID, rv,
			"GetMechanismInfo with invalid slot should return CKR_SLOT_ID_INVALID")
	})
}

// testInitToken verifies C_InitToken behavior per PKCS#11 v3.0 Section 5.5.6.
func (s *Suite) testInitToken(t *testing.T) {

	t.Run("valid_SO_PIN_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.InitToken(0, []byte("12345678"), "test-token")
		requireRV(t, module.CKR_OK, rv, "InitToken with valid SO PIN should return CKR_OK")
	})

	t.Run("empty_label_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.InitToken(0, []byte("12345678"), "")
		requireRV(t, module.CKR_OK, rv, "InitToken with empty label should return CKR_OK")
	})

	t.Run("re_init_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.InitToken(0, []byte("12345678"), "first-init")
		requireRV(t, module.CKR_OK, rv, "first InitToken should return CKR_OK")

		rv = m.InitToken(0, []byte("12345678"), "second-init")
		requireRV(t, module.CKR_OK, rv, "re-init with same SO PIN should return CKR_OK")

		// Verify the token can still be queried after re-initialization.
		info, rv := m.GetTokenInfo(0)
		requireRV(t, module.CKR_OK, rv, "GetTokenInfo after re-init should return CKR_OK")

		if info == nil {
			t.Fatal("GetTokenInfo returned nil after re-init")
		}
	})

	t.Run("invalid_slot_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.InitToken(9999, []byte("12345678"), "test-token")
		requireRV(t, module.CKR_SLOT_ID_INVALID, rv,
			"InitToken with invalid slot should return CKR_SLOT_ID_INVALID")
	})
}

// testInitPIN verifies C_InitPIN behavior per PKCS#11 v3.0 Section 5.5.7.
func (s *Suite) testInitPIN(t *testing.T) {

	t.Run("SO_login_then_InitPIN_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		sh := openRWSession(t, m)
		defer func() {
			m.Logout(sh)
			m.CloseSession(sh)
		}()

		rv := m.Login(sh, module.CKU_SO, []byte("12345678"))
		requireRV(t, module.CKR_OK, rv, "Login as SO should succeed")

		rv = m.InitPIN(sh, []byte("userpin"))
		requireRV(t, module.CKR_OK, rv, "InitPIN after SO login should return CKR_OK")
	})

	t.Run("without_SO_login_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initToken(t, m)

		sh := openRWSession(t, m)
		defer func() { m.CloseSession(sh) }()

		// Attempt InitPIN without being logged in as SO.
		rv := m.InitPIN(sh, []byte("userpin"))
		requireRV(t, module.CKR_USER_NOT_LOGGED_IN, rv,
			"InitPIN without SO login should return CKR_USER_NOT_LOGGED_IN")
	})

	t.Run("invalid_session_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.InitPIN(module.SessionHandle(0xDEADBEEF), []byte("userpin"))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"InitPIN with invalid session handle should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testSetPIN verifies C_SetPIN behavior per PKCS#11 v3.0 Section 5.5.8.
func (s *Suite) testSetPIN(t *testing.T) {

	t.Run("valid_old_and_new_PIN_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)

		sh := openRWSession(t, m)
		defer func() {
			m.Logout(sh)
			m.CloseSession(sh)
		}()

		loginAsUser(t, m, sh)

		rv := m.SetPIN(sh, []byte("userpin"), []byte("newuserpin"))
		requireRV(t, module.CKR_OK, rv, "SetPIN with valid old and new PINs should return CKR_OK")

		// Verify the new PIN works: logout, close session, re-open, and login with new PIN.
		rv = m.Logout(sh)
		requireRV(t, module.CKR_OK, rv, "Logout after SetPIN should succeed")

		rv = m.CloseSession(sh)
		requireRV(t, module.CKR_OK, rv, "CloseSession after SetPIN should succeed")

		sh2 := openRWSession(t, m)
		defer func() {
			m.Logout(sh2)
			m.CloseSession(sh2)
		}()

		rv = m.Login(sh2, module.CKU_USER, []byte("newuserpin"))
		requireRV(t, module.CKR_OK, rv, "Login with new PIN should succeed after SetPIN")
	})

	t.Run("wrong_old_PIN_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		initTokenAndPIN(t, m)

		sh := openRWSession(t, m)
		defer func() {
			m.Logout(sh)
			m.CloseSession(sh)
		}()

		loginAsUser(t, m, sh)

		rv := m.SetPIN(sh, []byte("wrong-old-pin"), []byte("newuserpin"))
		requireRV(t, module.CKR_PIN_INCORRECT, rv,
			"SetPIN with wrong old PIN should return CKR_PIN_INCORRECT")
	})

	t.Run("invalid_session_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		rv := m.SetPIN(module.SessionHandle(0xDEADBEEF), []byte("old"), []byte("new"))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"SetPIN with invalid session handle should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testWaitForSlotEvent verifies C_WaitForSlotEvent behavior per PKCS#11 v3.0 Section 5.5.9.
func (s *Suite) testWaitForSlotEvent(t *testing.T) {

	t.Run("non_blocking_returns_no_event", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		_, rv := m.WaitForSlotEvent(false)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_NO_EVENT, rv,
			"WaitForSlotEvent(false) should return CKR_NO_EVENT when no slot event is pending")
	})
}
