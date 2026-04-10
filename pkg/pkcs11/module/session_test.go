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

package module

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// TestSessionState_String tests the String method for SessionState.
func TestSessionState_String(t *testing.T) {
	tests := []struct {
		state    SessionState
		expected string
	}{
		{CKS_RO_PUBLIC_SESSION, "CKS_RO_PUBLIC_SESSION"},
		{CKS_RO_USER_FUNCTIONS, "CKS_RO_USER_FUNCTIONS"},
		{CKS_RW_PUBLIC_SESSION, "CKS_RW_PUBLIC_SESSION"},
		{CKS_RW_USER_FUNCTIONS, "CKS_RW_USER_FUNCTIONS"},
		{CKS_RW_SO_FUNCTIONS, "CKS_RW_SO_FUNCTIONS"},
		{SessionState(99), "CKS_UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("SessionState.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestUserType_String tests the String method for UserType.
func TestUserType_String(t *testing.T) {
	tests := []struct {
		userType UserType
		expected string
	}{
		{CKU_SO, "CKU_SO"},
		{CKU_USER, "CKU_USER"},
		{CKU_CONTEXT_SPECIFIC, "CKU_CONTEXT_SPECIFIC"},
		{UserType(99), "CKU_UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.userType.String(); got != tt.expected {
				t.Errorf("UserType.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestOperationType_String tests the String method for OperationType.
func TestOperationType_String(t *testing.T) {
	tests := []struct {
		opType   OperationType
		expected string
	}{
		{OperationNone, "OperationNone"},
		{OperationSign, "OperationSign"},
		{OperationVerify, "OperationVerify"},
		{OperationEncrypt, "OperationEncrypt"},
		{OperationDecrypt, "OperationDecrypt"},
		{OperationDigest, "OperationDigest"},
		{OperationFindObjects, "OperationFindObjects"},
		{OperationType(99), "OperationUnknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.opType.String(); got != tt.expected {
				t.Errorf("OperationType.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestNewSession_ReadOnly tests creating a read-only session.
func TestNewSession_ReadOnly(t *testing.T) {
	session := NewSession(1, 0, CKF_SERIAL_SESSION)

	if session.Handle != 1 {
		t.Errorf("expected handle 1, got %d", session.Handle)
	}
	if session.SlotID != 0 {
		t.Errorf("expected slot ID 0, got %d", session.SlotID)
	}
	if session.State() != CKS_RO_PUBLIC_SESSION {
		t.Errorf("expected CKS_RO_PUBLIC_SESSION, got %s", session.State())
	}
	if session.IsReadWrite() {
		t.Error("expected read-only session")
	}
}

// TestNewSession_ReadWrite tests creating a read-write session.
func TestNewSession_ReadWrite(t *testing.T) {
	session := NewSession(2, 1, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	if session.Handle != 2 {
		t.Errorf("expected handle 2, got %d", session.Handle)
	}
	if session.SlotID != 1 {
		t.Errorf("expected slot ID 1, got %d", session.SlotID)
	}
	if session.State() != CKS_RW_PUBLIC_SESSION {
		t.Errorf("expected CKS_RW_PUBLIC_SESSION, got %s", session.State())
	}
	if !session.IsReadWrite() {
		t.Error("expected read-write session")
	}
}

// TestSession_IsLoggedIn tests login state checking.
func TestSession_IsLoggedIn(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Initially not logged in
	if session.IsLoggedIn() {
		t.Error("expected not logged in initially")
	}
	if session.IsUserLoggedIn() {
		t.Error("expected user not logged in initially")
	}
	if session.IsSOLoggedIn() {
		t.Error("expected SO not logged in initially")
	}

	// Set to user logged in state
	session.setState(CKS_RW_USER_FUNCTIONS)
	if !session.IsLoggedIn() {
		t.Error("expected logged in after setting user state")
	}
	if !session.IsUserLoggedIn() {
		t.Error("expected user logged in")
	}
	if session.IsSOLoggedIn() {
		t.Error("expected SO not logged in")
	}

	// Set to SO logged in state
	session.setState(CKS_RW_SO_FUNCTIONS)
	if !session.IsLoggedIn() {
		t.Error("expected logged in after setting SO state")
	}
	if session.IsUserLoggedIn() {
		t.Error("expected user not logged in")
	}
	if !session.IsSOLoggedIn() {
		t.Error("expected SO logged in")
	}
}

// TestSession_GetInfo tests getting session info.
func TestSession_GetInfo(t *testing.T) {
	session := NewSession(42, 5, CKF_RW_SESSION|CKF_SERIAL_SESSION)
	session.DeviceError = 123

	info := session.GetInfo()

	if info.SlotID != 5 {
		t.Errorf("expected slot ID 5, got %d", info.SlotID)
	}
	if info.State != CKS_RW_PUBLIC_SESSION {
		t.Errorf("expected CKS_RW_PUBLIC_SESSION, got %s", info.State)
	}
	if info.Flags != CKF_RW_SESSION|CKF_SERIAL_SESSION {
		t.Errorf("unexpected flags: %d", info.Flags)
	}
	if info.DeviceError != 123 {
		t.Errorf("expected device error 123, got %d", info.DeviceError)
	}
}

// TestSession_OperationState tests operation state management.
func TestSession_OperationState(t *testing.T) {
	session := NewSession(1, 0, CKF_SERIAL_SESSION)

	// Initially no active operation
	if session.HasActiveOperation() {
		t.Error("expected no active operation initially")
	}
	if session.GetActiveOperationType() != OperationNone {
		t.Errorf("expected OperationNone, got %s", session.GetActiveOperationType())
	}

	// Set operation state
	state := OperationState{
		Type:      OperationSign,
		Mechanism: CKM_RSA_PKCS,
		KeyHandle: 100,
		Data:      []byte("test data"),
	}
	session.SetOperationState(state)

	if !session.HasActiveOperation() {
		t.Error("expected active operation after setting state")
	}
	if session.GetActiveOperationType() != OperationSign {
		t.Errorf("expected OperationSign, got %s", session.GetActiveOperationType())
	}

	// Get operation state
	got := session.GetOperationState()
	if got.Type != OperationSign {
		t.Errorf("expected OperationSign, got %s", got.Type)
	}
	if got.Mechanism != CKM_RSA_PKCS {
		t.Errorf("unexpected mechanism: %d", got.Mechanism)
	}
	if got.KeyHandle != 100 {
		t.Errorf("expected key handle 100, got %d", got.KeyHandle)
	}
	if string(got.Data) != "test data" {
		t.Errorf("expected data 'test data', got %q", got.Data)
	}

	// Clear operation
	session.ClearOperation()
	if session.HasActiveOperation() {
		t.Error("expected no active operation after clear")
	}
}

// TestSession_OperationState_DataCopy tests that GetOperationState returns a copy.
func TestSession_OperationState_DataCopy(t *testing.T) {
	session := NewSession(1, 0, CKF_SERIAL_SESSION)

	originalData := []byte("original")
	session.SetOperationState(OperationState{
		Type: OperationDigest,
		Data: originalData,
	})

	// Get state and modify the data
	got := session.GetOperationState()
	got.Data[0] = 'X'

	// Original should be unchanged
	current := session.GetOperationState()
	if current.Data[0] != 'o' {
		t.Error("modification of returned data affected original")
	}
}

// TestNewSessionManager tests creating a session manager.
func TestNewSessionManager(t *testing.T) {
	manager := NewSessionManager(0, 100)

	if manager == nil {
		t.Fatal("NewSessionManager returned nil")
	}
	if manager.slotID != 0 {
		t.Errorf("expected slot ID 0, got %d", manager.slotID)
	}
	if manager.maxSessions != 100 {
		t.Errorf("expected max sessions 100, got %d", manager.maxSessions)
	}
	if manager.SessionCount() != 0 {
		t.Errorf("expected session count 0, got %d", manager.SessionCount())
	}
}

// TestSessionManager_OpenSession_Success tests successful session opening.
func TestSessionManager_OpenSession_Success(t *testing.T) {
	manager := NewSessionManager(0, 10)

	// Open RO session
	handle, err := manager.OpenSession(CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}
	if handle == SessionHandle(InvalidHandle) {
		t.Error("got invalid handle")
	}
	if manager.SessionCount() != 1 {
		t.Errorf("expected session count 1, got %d", manager.SessionCount())
	}
	if manager.ROSessionCount() != 1 {
		t.Errorf("expected RO session count 1, got %d", manager.ROSessionCount())
	}
	if manager.RWSessionCount() != 0 {
		t.Errorf("expected RW session count 0, got %d", manager.RWSessionCount())
	}

	// Open RW session
	handle2, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession (RW) failed: %v", err)
	}
	if handle2 == handle {
		t.Error("got duplicate handle")
	}
	if manager.SessionCount() != 2 {
		t.Errorf("expected session count 2, got %d", manager.SessionCount())
	}
	if manager.RWSessionCount() != 1 {
		t.Errorf("expected RW session count 1, got %d", manager.RWSessionCount())
	}
}

// TestSessionManager_OpenSession_MissingSerialFlag tests opening without CKF_SERIAL_SESSION.
func TestSessionManager_OpenSession_MissingSerialFlag(t *testing.T) {
	manager := NewSessionManager(0, 10)

	_, err := manager.OpenSession(CKF_RW_SESSION)
	if err == nil {
		t.Fatal("expected error for missing CKF_SERIAL_SESSION")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_PARALLEL_NOT_SUPPORTED {
		t.Errorf("expected CKR_SESSION_PARALLEL_NOT_SUPPORTED, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_OpenSession_MaxSessions tests session count limit.
func TestSessionManager_OpenSession_MaxSessions(t *testing.T) {
	manager := NewSessionManager(0, 3)

	// Open max sessions
	for i := 0; i < 3; i++ {
		_, err := manager.OpenSession(CKF_SERIAL_SESSION)
		if err != nil {
			t.Fatalf("OpenSession %d failed: %v", i, err)
		}
	}

	// Try to open one more
	_, err := manager.OpenSession(CKF_SERIAL_SESSION)
	if err == nil {
		t.Fatal("expected error for exceeding max sessions")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_COUNT {
		t.Errorf("expected CKR_SESSION_COUNT, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_OpenSession_UnlimitedSessions tests unlimited session mode.
func TestSessionManager_OpenSession_UnlimitedSessions(t *testing.T) {
	manager := NewSessionManager(0, 0) // 0 = unlimited

	// Open many sessions
	for i := 0; i < 100; i++ {
		_, err := manager.OpenSession(CKF_SERIAL_SESSION)
		if err != nil {
			t.Fatalf("OpenSession %d failed: %v", i, err)
		}
	}

	if manager.SessionCount() != 100 {
		t.Errorf("expected session count 100, got %d", manager.SessionCount())
	}
}

// TestSessionManager_CloseSession_Success tests successful session closing.
func TestSessionManager_CloseSession_Success(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.CloseSession(handle)
	if err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	if manager.SessionCount() != 0 {
		t.Errorf("expected session count 0, got %d", manager.SessionCount())
	}
}

// TestSessionManager_CloseSession_InvalidHandle tests closing invalid handle.
func TestSessionManager_CloseSession_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	err := manager.CloseSession(SessionHandle(999))
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_CloseAllSessions tests closing all sessions.
func TestSessionManager_CloseAllSessions(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetUserPIN(hashPin("userpin"))

	// Open several sessions
	handles := make([]SessionHandle, 5)
	for i := 0; i < 5; i++ {
		var err error
		handles[i], err = manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
		if err != nil {
			t.Fatalf("OpenSession %d failed: %v", i, err)
		}
	}

	// Login
	err := manager.Login(handles[0], CKU_USER, []byte("userpin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Close all
	manager.CloseAllSessions()

	if manager.SessionCount() != 0 {
		t.Errorf("expected session count 0, got %d", manager.SessionCount())
	}
	if manager.IsLoggedIn() {
		t.Error("expected not logged in after closing all sessions")
	}
}

// TestSessionManager_GetSession tests retrieving a session.
func TestSessionManager_GetSession(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	session, err := manager.GetSession(handle)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if session.Handle != handle {
		t.Errorf("expected handle %d, got %d", handle, session.Handle)
	}
	if !session.IsReadWrite() {
		t.Error("expected RW session")
	}
}

// TestSessionManager_GetSession_InvalidHandle tests getting invalid session.
func TestSessionManager_GetSession_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	_, err := manager.GetSession(SessionHandle(999))
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_GetSessionInfo tests getting session info.
func TestSessionManager_GetSessionInfo(t *testing.T) {
	manager := NewSessionManager(5, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	info, err := manager.GetSessionInfo(handle)
	if err != nil {
		t.Fatalf("GetSessionInfo failed: %v", err)
	}

	if info.SlotID != 5 {
		t.Errorf("expected slot ID 5, got %d", info.SlotID)
	}
	if info.State != CKS_RW_PUBLIC_SESSION {
		t.Errorf("expected CKS_RW_PUBLIC_SESSION, got %s", info.State)
	}
}

// TestSessionManager_Login_UserSuccess tests successful user login.
func TestSessionManager_Login_UserSuccess(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetUserPIN(hashPin("userpin"))

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_USER, []byte("userpin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if !manager.IsLoggedIn() {
		t.Error("expected logged in")
	}

	userType, ok := manager.GetLoggedInUserType()
	if !ok {
		t.Error("expected logged in user type")
	}
	if userType != CKU_USER {
		t.Errorf("expected CKU_USER, got %s", userType)
	}

	// Check session state updated
	session, _ := manager.GetSession(handle)
	if session.State() != CKS_RW_USER_FUNCTIONS {
		t.Errorf("expected CKS_RW_USER_FUNCTIONS, got %s", session.State())
	}
}

// TestSessionManager_Login_SOSuccess tests successful SO login.
func TestSessionManager_Login_SOSuccess(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetSOPIN(hashPin("sopin"))

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_SO, []byte("sopin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if !manager.IsLoggedIn() {
		t.Error("expected logged in")
	}

	userType, ok := manager.GetLoggedInUserType()
	if !ok {
		t.Error("expected logged in user type")
	}
	if userType != CKU_SO {
		t.Errorf("expected CKU_SO, got %s", userType)
	}

	// Check session state updated
	session, _ := manager.GetSession(handle)
	if session.State() != CKS_RW_SO_FUNCTIONS {
		t.Errorf("expected CKS_RW_SO_FUNCTIONS, got %s", session.State())
	}
}

// TestSessionManager_Login_InvalidUserType tests login with invalid user type.
func TestSessionManager_Login_InvalidUserType(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, UserType(99), []byte("pin"))
	if err == nil {
		t.Fatal("expected error for invalid user type")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_USER_TYPE_INVALID {
		t.Errorf("expected CKR_USER_TYPE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_AlreadyLoggedIn tests login when already logged in.
func TestSessionManager_Login_AlreadyLoggedIn(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetUserPIN(hashPin("userpin"))

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// First login
	err = manager.Login(handle, CKU_USER, []byte("userpin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Try to login again
	err = manager.Login(handle, CKU_USER, []byte("userpin"))
	if err == nil {
		t.Fatal("expected error for already logged in")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_USER_ALREADY_LOGGED_IN {
		t.Errorf("expected CKR_USER_ALREADY_LOGGED_IN, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_AnotherUserLoggedIn tests login when different user is logged in.
func TestSessionManager_Login_AnotherUserLoggedIn(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetUserPIN(hashPin("userpin"))
	manager.SetSOPIN(hashPin("sopin"))

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Login as user
	err = manager.Login(handle, CKU_USER, []byte("userpin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Try to login as SO
	err = manager.Login(handle, CKU_SO, []byte("sopin"))
	if err == nil {
		t.Fatal("expected error for another user logged in")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_USER_ANOTHER_ALREADY_LOGGED_IN {
		t.Errorf("expected CKR_USER_ANOTHER_ALREADY_LOGGED_IN, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_SORequiresRWSession tests SO login requires RW session.
func TestSessionManager_Login_SORequiresRWSession(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetSOPIN(hashPin("sopin"))

	handle, err := manager.OpenSession(CKF_SERIAL_SESSION) // RO session
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_SO, []byte("sopin"))
	if err == nil {
		t.Fatal("expected error for SO login on RO session")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_READ_ONLY {
		t.Errorf("expected CKR_SESSION_READ_ONLY, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_SOBlockedByROSession tests SO login blocked by existing RO session.
func TestSessionManager_Login_SOBlockedByROSession(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetSOPIN(hashPin("sopin"))

	// Open RO session first
	_, err := manager.OpenSession(CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession (RO) failed: %v", err)
	}

	// Open RW session
	rwHandle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession (RW) failed: %v", err)
	}

	// Try SO login
	err = manager.Login(rwHandle, CKU_SO, []byte("sopin"))
	if err == nil {
		t.Fatal("expected error for SO login with RO session existing")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_READ_ONLY_EXISTS {
		t.Errorf("expected CKR_SESSION_READ_ONLY_EXISTS, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_IncorrectPIN tests login with wrong PIN.
func TestSessionManager_Login_IncorrectPIN(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetUserPIN(hashPin("correctpin"))

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_USER, []byte("wrongpin"))
	if err == nil {
		t.Fatal("expected error for incorrect PIN")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_PIN_INCORRECT {
		t.Errorf("expected CKR_PIN_INCORRECT, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_EmptyPIN tests login with empty PIN.
func TestSessionManager_Login_EmptyPIN(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetUserPIN(hashPin("userpin"))

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_USER, []byte{})
	if err == nil {
		t.Fatal("expected error for empty PIN")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_PIN_LEN_RANGE {
		t.Errorf("expected CKR_PIN_LEN_RANGE, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_PINNotInitialized tests login when PIN not set.
func TestSessionManager_Login_PINNotInitialized(t *testing.T) {
	manager := NewSessionManager(0, 10)
	// Don't set PIN

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_USER, []byte("anypin"))
	if err == nil {
		t.Fatal("expected error for uninitialized PIN")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_USER_PIN_NOT_INITIALIZED {
		t.Errorf("expected CKR_USER_PIN_NOT_INITIALIZED, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_CustomValidator tests using custom PIN validator.
func TestSessionManager_Login_CustomValidator(t *testing.T) {
	manager := NewSessionManager(0, 10)

	// Set custom validator
	manager.SetPINValidator(func(userType UserType, pin []byte) bool {
		return string(pin) == "custom-valid-pin"
	})

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Wrong PIN
	err = manager.Login(handle, CKU_USER, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong PIN")
	}

	// Correct PIN
	err = manager.Login(handle, CKU_USER, []byte("custom-valid-pin"))
	if err != nil {
		t.Fatalf("Login with custom validator failed: %v", err)
	}
}

// TestSessionManager_Login_InvalidSessionHandle tests login with invalid session.
func TestSessionManager_Login_InvalidSessionHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	err := manager.Login(SessionHandle(999), CKU_USER, []byte("pin"))
	if err == nil {
		t.Fatal("expected error for invalid session handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Logout_Success tests successful logout.
func TestSessionManager_Logout_Success(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetUserPIN(hashPin("userpin"))

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_USER, []byte("userpin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	err = manager.Logout(handle)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	if manager.IsLoggedIn() {
		t.Error("expected not logged in after logout")
	}

	// Check session state updated
	session, _ := manager.GetSession(handle)
	if session.State() != CKS_RW_PUBLIC_SESSION {
		t.Errorf("expected CKS_RW_PUBLIC_SESSION, got %s", session.State())
	}
}

// TestSessionManager_Logout_NotLoggedIn tests logout when not logged in.
func TestSessionManager_Logout_NotLoggedIn(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Logout(handle)
	if err == nil {
		t.Fatal("expected error for logout when not logged in")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_USER_NOT_LOGGED_IN {
		t.Errorf("expected CKR_USER_NOT_LOGGED_IN, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Logout_InvalidSessionHandle tests logout with invalid session.
func TestSessionManager_Logout_InvalidSessionHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	err := manager.Logout(SessionHandle(999))
	if err == nil {
		t.Fatal("expected error for invalid session handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_OpenSession_SOLoggedInBlocksRO tests RO session blocked when SO logged in.
func TestSessionManager_OpenSession_SOLoggedInBlocksRO(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetSOPIN(hashPin("sopin"))

	// Open RW session and login as SO
	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_SO, []byte("sopin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Try to open RO session
	_, err = manager.OpenSession(CKF_SERIAL_SESSION)
	if err == nil {
		t.Fatal("expected error for RO session while SO logged in")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_READ_WRITE_SO_EXISTS {
		t.Errorf("expected CKR_SESSION_READ_WRITE_SO_EXISTS, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_LoginState_AffectsAllSessions tests login state affects all sessions.
func TestSessionManager_LoginState_AffectsAllSessions(t *testing.T) {
	manager := NewSessionManager(0, 10)
	manager.SetUserPIN(hashPin("userpin"))

	// Open multiple sessions
	handle1, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession 1 failed: %v", err)
	}
	handle2, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession 2 failed: %v", err)
	}
	handle3, err := manager.OpenSession(CKF_SERIAL_SESSION) // RO session
	if err != nil {
		t.Fatalf("OpenSession 3 failed: %v", err)
	}

	// Login on one session
	err = manager.Login(handle1, CKU_USER, []byte("userpin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// All sessions should be in logged-in state
	session1, _ := manager.GetSession(handle1)
	session2, _ := manager.GetSession(handle2)
	session3, _ := manager.GetSession(handle3)

	if session1.State() != CKS_RW_USER_FUNCTIONS {
		t.Errorf("session1: expected CKS_RW_USER_FUNCTIONS, got %s", session1.State())
	}
	if session2.State() != CKS_RW_USER_FUNCTIONS {
		t.Errorf("session2: expected CKS_RW_USER_FUNCTIONS, got %s", session2.State())
	}
	if session3.State() != CKS_RO_USER_FUNCTIONS {
		t.Errorf("session3: expected CKS_RO_USER_FUNCTIONS, got %s", session3.State())
	}
}

// TestSessionManager_InitializeOperation tests initializing operations.
func TestSessionManager_InitializeOperation(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.InitializeOperation(handle, OperationSign, CKM_RSA_PKCS, ObjectHandle(100))
	if err != nil {
		t.Fatalf("InitializeOperation failed: %v", err)
	}

	state, err := manager.GetOperationState(handle)
	if err != nil {
		t.Fatalf("GetOperationState failed: %v", err)
	}

	if state.Type != OperationSign {
		t.Errorf("expected OperationSign, got %s", state.Type)
	}
	if state.Mechanism != CKM_RSA_PKCS {
		t.Errorf("unexpected mechanism: %d", state.Mechanism)
	}
	if state.KeyHandle != 100 {
		t.Errorf("expected key handle 100, got %d", state.KeyHandle)
	}
}

// TestSessionManager_InitializeOperation_AlreadyActive tests error when same operation type is active.
func TestSessionManager_InitializeOperation_AlreadyActive(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// First operation
	err = manager.InitializeOperation(handle, OperationSign, CKM_RSA_PKCS, ObjectHandle(100))
	if err != nil {
		t.Fatalf("InitializeOperation failed: %v", err)
	}

	// Try to initialize the same operation type - should fail
	err = manager.InitializeOperation(handle, OperationSign, CKM_ECDSA, ObjectHandle(200))
	if err == nil {
		t.Fatal("expected error for same operation type already active")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_OPERATION_ACTIVE {
		t.Errorf("expected CKR_OPERATION_ACTIVE, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_InitializeOperation_DualOperation tests that different operation types can coexist.
func TestSessionManager_InitializeOperation_DualOperation(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Initialize sign operation
	err = manager.InitializeOperation(handle, OperationSign, CKM_RSA_PKCS, ObjectHandle(100))
	if err != nil {
		t.Fatalf("InitializeOperation (Sign) failed: %v", err)
	}

	// Initialize encrypt operation - should succeed (dual-operation support)
	err = manager.InitializeOperation(handle, OperationEncrypt, CKM_AES_CBC, ObjectHandle(200))
	if err != nil {
		t.Fatalf("InitializeOperation (Encrypt) failed: %v", err)
	}

	// Verify both operations are active
	session, _ := manager.GetSession(handle)
	if !session.HasOperationType(OperationSign) {
		t.Error("expected Sign operation to be active")
	}
	if !session.HasOperationType(OperationEncrypt) {
		t.Error("expected Encrypt operation to be active")
	}
}

// TestSessionManager_FinalizeOperation tests finalizing operations.
func TestSessionManager_FinalizeOperation(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Initialize operation
	err = manager.InitializeOperation(handle, OperationSign, CKM_RSA_PKCS, ObjectHandle(100))
	if err != nil {
		t.Fatalf("InitializeOperation failed: %v", err)
	}

	// Finalize
	err = manager.FinalizeOperation(handle)
	if err != nil {
		t.Fatalf("FinalizeOperation failed: %v", err)
	}

	// Should be no operation now
	session, _ := manager.GetSession(handle)
	if session.HasActiveOperation() {
		t.Error("expected no active operation after finalize")
	}
}

// TestSessionManager_FinalizeOperation_NotInitialized tests error when no operation.
func TestSessionManager_FinalizeOperation_NotInitialized(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.FinalizeOperation(handle)
	if err == nil {
		t.Fatal("expected error for finalizing without operation")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_SetOperationState tests setting operation state.
func TestSessionManager_SetOperationState(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	state := OperationState{
		Type:      OperationVerify,
		Mechanism: CKM_ECDSA,
		KeyHandle: ObjectHandle(200),
		Data:      []byte("verification data"),
	}

	err = manager.SetOperationState(handle, state)
	if err != nil {
		t.Fatalf("SetOperationState failed: %v", err)
	}

	got, err := manager.GetOperationState(handle)
	if err != nil {
		t.Fatalf("GetOperationState failed: %v", err)
	}

	if got.Type != OperationVerify {
		t.Errorf("expected OperationVerify, got %s", got.Type)
	}
}

// TestSessionManager_SetOperationState_WhileActive tests error when same operation type is active.
func TestSessionManager_SetOperationState_WhileActive(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Initialize operation
	err = manager.InitializeOperation(handle, OperationSign, CKM_RSA_PKCS, ObjectHandle(100))
	if err != nil {
		t.Fatalf("InitializeOperation failed: %v", err)
	}

	// Try to set state for the same operation type - should fail
	err = manager.SetOperationState(handle, OperationState{Type: OperationSign})
	if err == nil {
		t.Fatal("expected error for setting same operation type while active")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_OPERATION_ACTIVE {
		t.Errorf("expected CKR_OPERATION_ACTIVE, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_SetOperationState_DifferentType tests that different operation types can be set.
func TestSessionManager_SetOperationState_DifferentType(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Initialize operation
	err = manager.InitializeOperation(handle, OperationSign, CKM_RSA_PKCS, ObjectHandle(100))
	if err != nil {
		t.Fatalf("InitializeOperation failed: %v", err)
	}

	// Set state for a different operation type - should succeed
	err = manager.SetOperationState(handle, OperationState{Type: OperationVerify})
	if err != nil {
		t.Fatalf("SetOperationState for different type failed: %v", err)
	}

	// Verify both operations are active
	session, _ := manager.GetSession(handle)
	if !session.HasOperationType(OperationSign) {
		t.Error("expected Sign operation to be active")
	}
	if !session.HasOperationType(OperationVerify) {
		t.Error("expected Verify operation to be active")
	}
}

// TestSessionManager_GetOperationState_NotInitialized tests error when no operation.
func TestSessionManager_GetOperationState_NotInitialized(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	_, err = manager.GetOperationState(handle)
	if err == nil {
		t.Fatal("expected error for getting state without operation")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_ConcurrentSessions tests concurrent session operations.
func TestSessionManager_ConcurrentSessions(t *testing.T) {
	manager := NewSessionManager(0, 1000)
	manager.SetUserPIN(hashPin("userpin"))

	var wg sync.WaitGroup
	numGoroutines := 50
	sessionsPerGoroutine := 10

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			handles := make([]SessionHandle, sessionsPerGoroutine)

			// Open sessions
			for j := 0; j < sessionsPerGoroutine; j++ {
				h, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
				if err != nil {
					t.Errorf("OpenSession failed: %v", err)
					return
				}
				handles[j] = h
			}

			// Close sessions
			for _, h := range handles {
				if err := manager.CloseSession(h); err != nil {
					t.Errorf("CloseSession failed: %v", err)
				}
			}
		}()
	}

	wg.Wait()

	if manager.SessionCount() != 0 {
		t.Errorf("expected 0 sessions after concurrent test, got %d", manager.SessionCount())
	}
}

// TestComparePINs tests the constant-time PIN comparison.
func TestComparePINs(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"equal", []byte("password"), []byte("password"), true},
		{"different length", []byte("short"), []byte("longer"), false},
		{"different content", []byte("password1"), []byte("password2"), false},
		{"empty equal", []byte{}, []byte{}, true},
		{"one empty", []byte("pin"), []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := comparePINs(tt.a, tt.b); got != tt.expected {
				t.Errorf("comparePINs(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestSession_FindObjects_State tests FindObjects operation state.
func TestSession_FindObjects_State(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set FindObjects operation state
	state := OperationState{
		Type:        OperationFindObjects,
		FindResults: []ObjectHandle{100, 200, 300},
		FindIndex:   0,
	}
	session.SetOperationState(state)

	got := session.GetOperationState()
	if got.Type != OperationFindObjects {
		t.Errorf("expected OperationFindObjects, got %s", got.Type)
	}
	if len(got.FindResults) != 3 {
		t.Errorf("expected 3 find results, got %d", len(got.FindResults))
	}
	if got.FindResults[0] != 100 {
		t.Errorf("expected first result 100, got %d", got.FindResults[0])
	}
}

// TestGetLoggedInUserType_NotLoggedIn tests getting user type when not logged in.
func TestGetLoggedInUserType_NotLoggedIn(t *testing.T) {
	manager := NewSessionManager(0, 10)

	_, ok := manager.GetLoggedInUserType()
	if ok {
		t.Error("expected not logged in")
	}
}

// TestSessionCounts tests session count tracking.
func TestSessionCounts(t *testing.T) {
	manager := NewSessionManager(0, 10)

	// Open RO sessions
	ro1, _ := manager.OpenSession(CKF_SERIAL_SESSION)
	ro2, _ := manager.OpenSession(CKF_SERIAL_SESSION)

	// Open RW sessions
	rw1, _ := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	rw2, _ := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	rw3, _ := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)

	if manager.ROSessionCount() != 2 {
		t.Errorf("expected RO count 2, got %d", manager.ROSessionCount())
	}
	if manager.RWSessionCount() != 3 {
		t.Errorf("expected RW count 3, got %d", manager.RWSessionCount())
	}
	if manager.SessionCount() != 5 {
		t.Errorf("expected total count 5, got %d", manager.SessionCount())
	}

	// Close some
	_ = manager.CloseSession(ro1)
	_ = manager.CloseSession(rw1)

	if manager.ROSessionCount() != 1 {
		t.Errorf("expected RO count 1, got %d", manager.ROSessionCount())
	}
	if manager.RWSessionCount() != 2 {
		t.Errorf("expected RW count 2, got %d", manager.RWSessionCount())
	}
	if manager.SessionCount() != 3 {
		t.Errorf("expected total count 3, got %d", manager.SessionCount())
	}

	// Clean up
	_ = manager.CloseSession(ro2)
	_ = manager.CloseSession(rw2)
	_ = manager.CloseSession(rw3)
}

// TestSessionFlags tests session flag constants.
func TestSessionFlags(t *testing.T) {
	if CKF_RW_SESSION != 0x00000002 {
		t.Errorf("CKF_RW_SESSION = %#x, want %#x", CKF_RW_SESSION, 0x00000002)
	}
	if CKF_SERIAL_SESSION != 0x00000004 {
		t.Errorf("CKF_SERIAL_SESSION = %#x, want %#x", CKF_SERIAL_SESSION, 0x00000004)
	}
}

// TestSession_Flags tests the Flags method.
func TestSession_Flags(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)
	flags := session.Flags()

	if flags != CKF_RW_SESSION|CKF_SERIAL_SESSION {
		t.Errorf("expected flags %d, got %d", CKF_RW_SESSION|CKF_SERIAL_SESSION, flags)
	}
}

// TestSessionManager_GetSessionInfo_InvalidHandle tests getting info for invalid handle.
func TestSessionManager_GetSessionInfo_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	_, err := manager.GetSessionInfo(SessionHandle(999))
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_InitializeOperation_InvalidHandle tests initializing operation on invalid handle.
func TestSessionManager_InitializeOperation_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	err := manager.InitializeOperation(SessionHandle(999), OperationSign, CKM_RSA_PKCS, ObjectHandle(100))
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_FinalizeOperation_InvalidHandle tests finalizing operation on invalid handle.
func TestSessionManager_FinalizeOperation_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	err := manager.FinalizeOperation(SessionHandle(999))
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_GetOperationState_InvalidHandle tests getting operation state on invalid handle.
func TestSessionManager_GetOperationState_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	_, err := manager.GetOperationState(SessionHandle(999))
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_SetOperationState_InvalidHandle tests setting operation state on invalid handle.
func TestSessionManager_SetOperationState_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	err := manager.SetOperationState(SessionHandle(999), OperationState{Type: OperationSign})
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_Login_ContextSpecific tests context-specific login.
func TestSessionManager_Login_ContextSpecific(t *testing.T) {
	manager := NewSessionManager(0, 10)

	// Set custom validator that accepts context-specific
	manager.SetPINValidator(func(userType UserType, pin []byte) bool {
		return userType == CKU_CONTEXT_SPECIFIC && string(pin) == "context-pin"
	})

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	err = manager.Login(handle, CKU_CONTEXT_SPECIFIC, []byte("context-pin"))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if !manager.IsLoggedIn() {
		t.Error("expected logged in")
	}
}

// TestSession_ROUserFunctions tests RO session with user logged in.
func TestSession_ROUserFunctions(t *testing.T) {
	session := NewSession(1, 0, CKF_SERIAL_SESSION)

	// Set to RO user state
	session.setState(CKS_RO_USER_FUNCTIONS)

	if !session.IsLoggedIn() {
		t.Error("expected logged in")
	}
	if !session.IsUserLoggedIn() {
		t.Error("expected user logged in")
	}
	if session.IsSOLoggedIn() {
		t.Error("expected SO not logged in")
	}
}

// TestSessionManager_validatePIN_InvalidUserType tests validatePIN with invalid user type.
func TestSessionManager_validatePIN_InvalidUserType(t *testing.T) {
	manager := NewSessionManager(0, 10)
	// No custom validator, and no PINs set

	// Try to validate with an invalid user type directly
	// This tests the default path with an unsupported user type
	manager.SetUserPIN(hashPin("userpin"))
	manager.SetSOPIN(hashPin("sopin"))

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// CONTEXT_SPECIFIC login without custom validator will fail
	err = manager.Login(handle, CKU_CONTEXT_SPECIFIC, []byte("anypin"))
	if err == nil {
		t.Fatal("expected error for context-specific login without validator")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_USER_TYPE_INVALID {
		t.Errorf("expected CKR_USER_TYPE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSession_OperationState_FindResultsCopy tests that FindResults is copied.
func TestSession_OperationState_FindResultsCopy(t *testing.T) {
	session := NewSession(1, 0, CKF_SERIAL_SESSION)

	originalResults := []ObjectHandle{100, 200, 300}
	session.SetOperationState(OperationState{
		Type:        OperationFindObjects,
		FindResults: originalResults,
	})

	// Get state and modify the results
	got := session.GetOperationState()
	got.FindResults[0] = 999

	// Original should be unchanged
	current := session.GetOperationState()
	if current.FindResults[0] != 100 {
		t.Error("modification of returned FindResults affected original")
	}
}

// BenchmarkSessionManager_OpenSession benchmarks session opening.
func BenchmarkSessionManager_OpenSession(b *testing.B) {
	manager := NewSessionManager(0, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, _ := manager.OpenSession(CKF_SERIAL_SESSION)
		_ = manager.CloseSession(h)
	}
}

// BenchmarkSessionManager_GetSession benchmarks session lookup.
func BenchmarkSessionManager_GetSession(b *testing.B) {
	manager := NewSessionManager(0, 0)

	// Pre-allocate sessions
	handles := make([]SessionHandle, 100)
	for i := 0; i < 100; i++ {
		handles[i], _ = manager.OpenSession(CKF_SERIAL_SESSION)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.GetSession(handles[i%100])
	}
}

// BenchmarkSessionManager_ConcurrentOpenClose benchmarks concurrent open/close.
func BenchmarkSessionManager_ConcurrentOpenClose(b *testing.B) {
	manager := NewSessionManager(0, 0)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h, _ := manager.OpenSession(CKF_SERIAL_SESSION)
			_ = manager.CloseSession(h)
		}
	})
}

// TestSession_DualOperation_DigestEncrypt tests dual digest and encrypt operations.
func TestSession_DualOperation_DigestEncrypt(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set both operations
	session.SetOperationByType(OperationDigest, &OperationState{
		Type:      OperationDigest,
		Mechanism: CKM_SHA256,
	})
	session.SetOperationByType(OperationEncrypt, &OperationState{
		Type:      OperationEncrypt,
		Mechanism: CKM_AES_CBC,
		KeyHandle: ObjectHandle(100),
	})

	// Both should be active
	if !session.HasOperationType(OperationDigest) {
		t.Error("expected Digest operation to be active")
	}
	if !session.HasOperationType(OperationEncrypt) {
		t.Error("expected Encrypt operation to be active")
	}

	// Get each operation by type
	digestOp := session.GetOperationByType(OperationDigest)
	if digestOp == nil || digestOp.Mechanism != CKM_SHA256 {
		t.Error("failed to get Digest operation by type")
	}

	encryptOp := session.GetOperationByType(OperationEncrypt)
	if encryptOp == nil || encryptOp.Mechanism != CKM_AES_CBC {
		t.Error("failed to get Encrypt operation by type")
	}

	// Clear only digest
	session.ClearOperationType(OperationDigest)
	if session.HasOperationType(OperationDigest) {
		t.Error("Digest operation should be cleared")
	}
	if !session.HasOperationType(OperationEncrypt) {
		t.Error("Encrypt operation should still be active")
	}
}

// TestSession_DualOperation_SignEncrypt tests dual sign and encrypt operations.
func TestSession_DualOperation_SignEncrypt(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set both operations
	session.SetOperationByType(OperationSign, &OperationState{
		Type:      OperationSign,
		Mechanism: CKM_RSA_PKCS,
		KeyHandle: ObjectHandle(50),
	})
	session.SetOperationByType(OperationEncrypt, &OperationState{
		Type:      OperationEncrypt,
		Mechanism: CKM_AES_GCM,
		KeyHandle: ObjectHandle(100),
	})

	// Both should be active
	if !session.HasOperationType(OperationSign) {
		t.Error("expected Sign operation to be active")
	}
	if !session.HasOperationType(OperationEncrypt) {
		t.Error("expected Encrypt operation to be active")
	}

	// HasActiveOperation should return true
	if !session.HasActiveOperation() {
		t.Error("expected HasActiveOperation to return true")
	}

	// GetActiveOperationType should return Sign (first in priority order)
	activeType := session.GetActiveOperationType()
	if activeType != OperationSign {
		t.Errorf("expected Sign as active type, got %s", activeType)
	}
}

// TestSession_DualOperation_DecryptVerify tests dual decrypt and verify operations.
func TestSession_DualOperation_DecryptVerify(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set both operations
	session.SetOperationByType(OperationDecrypt, &OperationState{
		Type:      OperationDecrypt,
		Mechanism: CKM_AES_CBC,
		KeyHandle: ObjectHandle(100),
	})
	session.SetOperationByType(OperationVerify, &OperationState{
		Type:      OperationVerify,
		Mechanism: CKM_ECDSA,
		KeyHandle: ObjectHandle(200),
	})

	// Both should be active
	if !session.HasOperationType(OperationDecrypt) {
		t.Error("expected Decrypt operation to be active")
	}
	if !session.HasOperationType(OperationVerify) {
		t.Error("expected Verify operation to be active")
	}

	// ClearOperation should clear all
	session.ClearOperation()
	if session.HasActiveOperation() {
		t.Error("expected no active operations after ClearOperation")
	}
}

// TestSession_DualOperation_DecryptDigest tests dual decrypt and digest operations.
func TestSession_DualOperation_DecryptDigest(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set both operations
	session.SetOperationByType(OperationDecrypt, &OperationState{
		Type:      OperationDecrypt,
		Mechanism: CKM_AES_CBC,
		KeyHandle: ObjectHandle(100),
	})
	session.SetOperationByType(OperationDigest, &OperationState{
		Type:      OperationDigest,
		Mechanism: CKM_SHA512,
	})

	// Both should be active
	if !session.HasOperationType(OperationDecrypt) {
		t.Error("expected Decrypt operation to be active")
	}
	if !session.HasOperationType(OperationDigest) {
		t.Error("expected Digest operation to be active")
	}

	// Verify GetOperationState returns the first in priority order (Decrypt before Digest)
	opState := session.GetOperationState()
	if opState.Type != OperationDecrypt {
		t.Errorf("expected Decrypt from GetOperationState, got %s", opState.Type)
	}
}

// TestSessionManager_FinalizeOperationType tests finalizing specific operation types.
func TestSessionManager_FinalizeOperationType(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Initialize both operations
	err = manager.InitializeOperation(handle, OperationDigest, CKM_SHA256, ObjectHandle(0))
	if err != nil {
		t.Fatalf("InitializeOperation (Digest) failed: %v", err)
	}

	err = manager.InitializeOperation(handle, OperationEncrypt, CKM_AES_CBC, ObjectHandle(100))
	if err != nil {
		t.Fatalf("InitializeOperation (Encrypt) failed: %v", err)
	}

	// Finalize only Digest
	err = manager.FinalizeOperationType(handle, OperationDigest)
	if err != nil {
		t.Fatalf("FinalizeOperationType (Digest) failed: %v", err)
	}

	// Verify Digest is gone but Encrypt remains
	session, _ := manager.GetSession(handle)
	if session.HasOperationType(OperationDigest) {
		t.Error("Digest operation should be cleared")
	}
	if !session.HasOperationType(OperationEncrypt) {
		t.Error("Encrypt operation should still be active")
	}
}

// TestSessionManager_GetOperationStateByType tests getting specific operation types.
func TestSessionManager_GetOperationStateByType(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Initialize both operations
	err = manager.InitializeOperation(handle, OperationSign, CKM_RSA_PKCS, ObjectHandle(50))
	if err != nil {
		t.Fatalf("InitializeOperation (Sign) failed: %v", err)
	}

	err = manager.InitializeOperation(handle, OperationEncrypt, CKM_AES_GCM, ObjectHandle(100))
	if err != nil {
		t.Fatalf("InitializeOperation (Encrypt) failed: %v", err)
	}

	// Get Sign operation by type
	signOp, err := manager.GetOperationStateByType(handle, OperationSign)
	if err != nil {
		t.Fatalf("GetOperationStateByType (Sign) failed: %v", err)
	}
	if signOp.Type != OperationSign || signOp.Mechanism != CKM_RSA_PKCS {
		t.Error("incorrect Sign operation state")
	}

	// Get Encrypt operation by type
	encryptOp, err := manager.GetOperationStateByType(handle, OperationEncrypt)
	if err != nil {
		t.Fatalf("GetOperationStateByType (Encrypt) failed: %v", err)
	}
	if encryptOp.Type != OperationEncrypt || encryptOp.Mechanism != CKM_AES_GCM {
		t.Error("incorrect Encrypt operation state")
	}

	// Get non-existent operation should fail
	_, err = manager.GetOperationStateByType(handle, OperationDigest)
	if err == nil {
		t.Error("expected error for non-existent operation type")
	}
}

// TestSession_SetOperationState_OperationNone tests that setting OperationNone clears all operations.
func TestSession_SetOperationState_OperationNone(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set up multiple operations
	session.SetOperationByType(OperationSign, &OperationState{
		Type:      OperationSign,
		Mechanism: CKM_RSA_PKCS,
	})
	session.SetOperationByType(OperationEncrypt, &OperationState{
		Type:      OperationEncrypt,
		Mechanism: CKM_AES_CBC,
	})

	// Verify operations are active
	if !session.HasActiveOperation() {
		t.Error("expected operations to be active")
	}

	// Set OperationNone state should clear all
	session.SetOperationState(OperationState{Type: OperationNone})

	// Verify all operations are cleared
	if session.HasActiveOperation() {
		t.Error("expected no active operations after setting OperationNone")
	}
	if session.HasOperationType(OperationSign) {
		t.Error("Sign operation should be cleared")
	}
	if session.HasOperationType(OperationEncrypt) {
		t.Error("Encrypt operation should be cleared")
	}
}

// TestSession_SetOperationByType_NilClearsOperation tests that setting nil clears the operation.
func TestSession_SetOperationByType_NilClearsOperation(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set up an operation
	session.SetOperationByType(OperationSign, &OperationState{
		Type:      OperationSign,
		Mechanism: CKM_RSA_PKCS,
	})

	// Verify operation is active
	if !session.HasOperationType(OperationSign) {
		t.Error("expected Sign operation to be active")
	}

	// Set nil should clear the operation
	session.SetOperationByType(OperationSign, nil)

	// Verify operation is cleared
	if session.HasOperationType(OperationSign) {
		t.Error("Sign operation should be cleared after setting nil")
	}
}

// TestSession_SetOperationByType_SetsType tests that SetOperationByType sets the Type field.
func TestSession_SetOperationByType_SetsType(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Create state with incorrect type
	state := &OperationState{
		Type:      OperationVerify, // Different from what we're setting
		Mechanism: CKM_RSA_PKCS,
	}

	// Set as Sign operation
	session.SetOperationByType(OperationSign, state)

	// Verify the type was updated
	op := session.GetOperationByType(OperationSign)
	if op == nil {
		t.Fatal("expected Sign operation to exist")
	}
	if op.Type != OperationSign {
		t.Errorf("expected Type to be OperationSign, got %s", op.Type)
	}
}

// TestSessionManager_SetOperation tests SetOperation function.
func TestSessionManager_SetOperation(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	state := &OperationState{
		Type:      OperationSign,
		Mechanism: CKM_RSA_PKCS,
		KeyHandle: ObjectHandle(100),
	}

	err = manager.SetOperation(handle, state)
	if err != nil {
		t.Fatalf("SetOperation failed: %v", err)
	}

	// Verify operation was set
	session, _ := manager.GetSession(handle)
	if !session.HasOperationType(OperationSign) {
		t.Error("expected Sign operation to be active")
	}
}

// TestSessionManager_SetOperation_InvalidHandle tests SetOperation with invalid handle.
func TestSessionManager_SetOperation_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	state := &OperationState{
		Type:      OperationSign,
		Mechanism: CKM_RSA_PKCS,
	}

	err := manager.SetOperation(SessionHandle(999), state)
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_FinalizeOperationType_InvalidHandle tests FinalizeOperationType with invalid handle.
func TestSessionManager_FinalizeOperationType_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	err := manager.FinalizeOperationType(SessionHandle(999), OperationSign)
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_FinalizeOperationType_NotInitialized tests FinalizeOperationType when operation not active.
func TestSessionManager_FinalizeOperationType_NotInitialized(t *testing.T) {
	manager := NewSessionManager(0, 10)

	handle, err := manager.OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	// Try to finalize operation that doesn't exist
	err = manager.FinalizeOperationType(handle, OperationSign)
	if err == nil {
		t.Fatal("expected error for finalizing non-existent operation type")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcs11Err.Code)
	}
}

// TestSessionManager_GetOperationStateByType_InvalidHandle tests GetOperationStateByType with invalid handle.
func TestSessionManager_GetOperationStateByType_InvalidHandle(t *testing.T) {
	manager := NewSessionManager(0, 10)

	_, err := manager.GetOperationStateByType(SessionHandle(999), OperationSign)
	if err == nil {
		t.Fatal("expected error for invalid handle")
	}

	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcs11Err.Code != CKR_SESSION_HANDLE_INVALID {
		t.Errorf("expected CKR_SESSION_HANDLE_INVALID, got %s", pkcs11Err.Code)
	}
}

// TestSession_GetOperationByType_NoOperation tests GetOperationByType when no operation of that type exists.
func TestSession_GetOperationByType_NoOperation(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// No operations set
	op := session.GetOperationByType(OperationSign)
	if op != nil {
		t.Error("expected nil for non-existent operation")
	}
}

// TestSession_copyOperationState_WithNilData tests that copyOperationState handles nil Data correctly.
func TestSession_copyOperationState_WithNilData(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set operation with nil Data
	session.SetOperationByType(OperationSign, &OperationState{
		Type:      OperationSign,
		Mechanism: CKM_RSA_PKCS,
		Data:      nil,
	})

	// Get operation state
	op := session.GetOperationByType(OperationSign)
	if op == nil {
		t.Fatal("expected operation to exist")
	}
	if op.Data != nil {
		t.Error("expected nil Data")
	}
}

// TestSession_copyOperationState_WithNilFindResults tests that copyOperationState handles nil FindResults correctly.
func TestSession_copyOperationState_WithNilFindResults(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set operation with nil FindResults
	session.SetOperationByType(OperationFindObjects, &OperationState{
		Type:        OperationFindObjects,
		FindResults: nil,
	})

	// Get operation state
	op := session.GetOperationByType(OperationFindObjects)
	if op == nil {
		t.Fatal("expected operation to exist")
	}
	if op.FindResults != nil {
		t.Error("expected nil FindResults")
	}
}

// TestSession_WithOperation tests the WithOperation method for thread-safe
// in-place mutation of live operation state.
func TestSession_WithOperation(t *testing.T) {

	t.Run("mutates operation state in place", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		// Plant an operation
		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			Data:      []byte("original-sig"),
		})

		// Use WithOperation to mutate it in place
		err := session.WithOperation(OperationVerifySignature, func(op *OperationState) error {
			op.Data = append(op.Data, []byte("-appended")...)
			return nil
		})
		if err != nil {
			t.Fatalf("WithOperation failed: %v", err)
		}

		// Verify the mutation persisted
		op := session.GetOperationByType(OperationVerifySignature)
		if op == nil {
			t.Fatal("expected operation to exist")
		}
		expected := "original-sig-appended"
		if string(op.Data) != expected {
			t.Errorf("expected Data=%q, got %q", expected, string(op.Data))
		}
	})

	t.Run("returns CKR_OPERATION_NOT_INITIALIZED when no operation exists", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		err := session.WithOperation(OperationVerifySignature, func(op *OperationState) error {
			t.Fatal("callback should not be called")
			return nil
		})
		if err == nil {
			t.Fatal("expected error")
		}

		var pkcsErr *PKCS11Error
		if !errors.As(err, &pkcsErr) {
			t.Fatalf("expected PKCS11Error, got %T", err)
		}
		if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code)
		}
	})

	t.Run("propagates callback errors", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		session.SetOperationByType(OperationEncapsulate, &OperationState{
			Type: OperationEncapsulate,
		})

		callbackErr := NewPKCS11Error(CKR_FUNCTION_FAILED)
		err := session.WithOperation(OperationEncapsulate, func(op *OperationState) error {
			return callbackErr
		})
		if err != callbackErr {
			t.Errorf("expected callback error to propagate, got %v", err)
		}
	})

	t.Run("handles concurrent access safely", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		session.SetOperationByType(OperationDecapsulate, &OperationState{
			Type: OperationDecapsulate,
			Data: make([]byte, 0, 1000),
		})

		var wg sync.WaitGroup
		const goroutines = 10
		const iterations = 100

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < iterations; j++ {
					_ = session.WithOperation(OperationDecapsulate, func(op *OperationState) error {
						op.Data = append(op.Data, byte(j))
						return nil
					})
				}
			}()
		}

		wg.Wait()

		op := session.GetOperationByType(OperationDecapsulate)
		if op == nil {
			t.Fatal("expected operation to exist")
		}
		if len(op.Data) != goroutines*iterations {
			t.Errorf("expected %d bytes, got %d", goroutines*iterations, len(op.Data))
		}
	})
}

// TestSession_ConsumeOperation tests atomically extracting and removing operation state.
func TestSession_ConsumeOperation(t *testing.T) {

	t.Run("atomically extracts and removes operation", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Type:      OperationVerifySignature,
			Mechanism: CKM_ML_DSA,
			Data:      []byte("test-sig"),
		})

		op, err := session.ConsumeOperation(OperationVerifySignature)
		if err != nil {
			t.Fatalf("ConsumeOperation failed: %v", err)
		}
		if op == nil {
			t.Fatal("expected non-nil operation")
		}
		if string(op.Data) != "test-sig" {
			t.Errorf("expected Data=%q, got %q", "test-sig", string(op.Data))
		}

		// Verify the operation is removed
		if session.HasOperationType(OperationVerifySignature) {
			t.Error("expected operation to be removed after consume")
		}
	})

	t.Run("returns CKR_OPERATION_NOT_INITIALIZED when no operation exists", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		_, err := session.ConsumeOperation(OperationVerifySignature)
		if err == nil {
			t.Fatal("expected error")
		}

		var pkcsErr *PKCS11Error
		if !errors.As(err, &pkcsErr) {
			t.Fatalf("expected PKCS11Error, got %T", err)
		}
		if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code)
		}
	})

	t.Run("only one concurrent consumer succeeds", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		session.SetOperationByType(OperationEncapsulate, &OperationState{
			Type: OperationEncapsulate,
		})

		var wg sync.WaitGroup
		const goroutines = 10
		successCount := int32(0)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := session.ConsumeOperation(OperationEncapsulate)
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				}
			}()
		}

		wg.Wait()

		if successCount != 1 {
			t.Errorf("expected exactly 1 successful consumer, got %d", successCount)
		}
	})
}

// TestSession_OperationType_VerifySignature tests the v3.2 VerifySignature operation type.
func TestSession_OperationType_VerifySignature(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	// Set VerifySignature operation
	session.SetOperationByType(OperationVerifySignature, &OperationState{
		Type:      OperationVerifySignature,
		Mechanism: CKM_ML_DSA,
	})

	if !session.HasOperationType(OperationVerifySignature) {
		t.Error("expected HasOperationType to return true for OperationVerifySignature")
	}

	op := session.GetOperationByType(OperationVerifySignature)
	if op == nil {
		t.Fatal("expected operation to exist")
	}
	if op.Type != OperationVerifySignature {
		t.Errorf("expected OperationVerifySignature, got %v", op.Type)
	}

	// Clear it
	session.ClearOperationType(OperationVerifySignature)
	if session.HasOperationType(OperationVerifySignature) {
		t.Error("expected HasOperationType to return false after clear")
	}
}

// TestSession_OperationType_Encapsulate tests the v3.2 Encapsulate operation type.
func TestSession_OperationType_Encapsulate(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	session.SetOperationByType(OperationEncapsulate, &OperationState{
		Type:      OperationEncapsulate,
		Mechanism: CKM_ML_KEM,
	})

	if !session.HasOperationType(OperationEncapsulate) {
		t.Error("expected HasOperationType to return true for OperationEncapsulate")
	}

	session.ClearOperationType(OperationEncapsulate)
	if session.HasOperationType(OperationEncapsulate) {
		t.Error("expected HasOperationType to return false after clear")
	}
}

// TestSession_OperationType_Decapsulate tests the v3.2 Decapsulate operation type.
func TestSession_OperationType_Decapsulate(t *testing.T) {
	session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

	session.SetOperationByType(OperationDecapsulate, &OperationState{
		Type:      OperationDecapsulate,
		Mechanism: CKM_ML_KEM,
	})

	if !session.HasOperationType(OperationDecapsulate) {
		t.Error("expected HasOperationType to return true for OperationDecapsulate")
	}

	session.ClearOperationType(OperationDecapsulate)
	if session.HasOperationType(OperationDecapsulate) {
		t.Error("expected HasOperationType to return false after clear")
	}
}

// TestSession_SetOperationIfAbsent tests the atomic check-and-set method.
func TestSession_SetOperationIfAbsent(t *testing.T) {

	t.Run("sets operation when slot is empty", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		err := session.SetOperationIfAbsent(OperationVerifySignature, &OperationState{
			Mechanism: CKM_ML_DSA,
			KeyHandle: ObjectHandle(42),
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !session.HasOperationType(OperationVerifySignature) {
			t.Error("expected HasOperationType to return true after SetOperationIfAbsent")
		}
	})

	t.Run("returns CKR_OPERATION_ACTIVE when slot is taken", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		// Plant an existing operation
		session.SetOperationByType(OperationVerifySignature, &OperationState{
			Mechanism: CKM_ML_DSA,
		})

		// Attempt to set again — should fail
		err := session.SetOperationIfAbsent(OperationVerifySignature, &OperationState{
			Mechanism: CKM_ML_DSA,
			KeyHandle: ObjectHandle(99),
		})
		if err == nil {
			t.Fatal("expected CKR_OPERATION_ACTIVE error, got nil")
		}
		var pkcsErr *PKCS11Error
		if !errors.As(err, &pkcsErr) {
			t.Fatalf("expected *PKCS11Error, got %T", err)
		}
		if pkcsErr.Code != CKR_OPERATION_ACTIVE {
			t.Errorf("expected CKR_OPERATION_ACTIVE (%#x), got %#x", CKR_OPERATION_ACTIVE, pkcsErr.Code)
		}
	})

	t.Run("sets Type field on the state", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		state := &OperationState{Mechanism: CKM_ML_KEM}
		err := session.SetOperationIfAbsent(OperationEncapsulate, state)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if state.Type != OperationEncapsulate {
			t.Errorf("expected Type %d, got %d", OperationEncapsulate, state.Type)
		}
	})

	t.Run("allows different operation types concurrently", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)

		err1 := session.SetOperationIfAbsent(OperationVerifySignature, &OperationState{
			Mechanism: CKM_ML_DSA,
		})
		err2 := session.SetOperationIfAbsent(OperationEncapsulate, &OperationState{
			Mechanism: CKM_ML_KEM,
		})
		if err1 != nil {
			t.Fatalf("expected no error for VerifySignature, got %v", err1)
		}
		if err2 != nil {
			t.Fatalf("expected no error for Encapsulate, got %v", err2)
		}
		if !session.HasOperationType(OperationVerifySignature) {
			t.Error("expected VerifySignature operation to be active")
		}
		if !session.HasOperationType(OperationEncapsulate) {
			t.Error("expected Encapsulate operation to be active")
		}
	})

	t.Run("concurrent goroutines race exactly one wins", func(t *testing.T) {
		session := NewSession(1, 0, CKF_RW_SESSION|CKF_SERIAL_SESSION)
		const n = 100
		errs := make(chan error, n)

		for i := 0; i < n; i++ {
			go func() {
				errs <- session.SetOperationIfAbsent(OperationVerifySignature, &OperationState{
					Mechanism: CKM_ML_DSA,
				})
			}()
		}

		var successes, failures int
		for i := 0; i < n; i++ {
			if err := <-errs; err == nil {
				successes++
			} else {
				var pkcsErr *PKCS11Error
				if !errors.As(err, &pkcsErr) {
					t.Errorf("expected *PKCS11Error, got %T: %v", err, err)
				} else if pkcsErr.Code != CKR_OPERATION_ACTIVE {
					t.Errorf("expected CKR_OPERATION_ACTIVE, got %#x", pkcsErr.Code)
				}
				failures++
			}
		}
		if successes != 1 {
			t.Errorf("expected exactly 1 success, got %d", successes)
		}
		if failures != n-1 {
			t.Errorf("expected %d failures, got %d", n-1, failures)
		}
	})
}
