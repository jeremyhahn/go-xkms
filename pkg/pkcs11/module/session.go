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

// Package module provides PKCS#11 session management implementing the
// OASIS PKCS#11 v3.0 session state machine.
//
// Session States (CK_STATE):
//   - CKS_RO_PUBLIC_SESSION: Read-only session, no user logged in
//   - CKS_RO_USER_FUNCTIONS: Read-only session, user logged in
//   - CKS_RW_PUBLIC_SESSION: Read-write session, no user logged in
//   - CKS_RW_USER_FUNCTIONS: Read-write session, user logged in
//   - CKS_RW_SO_FUNCTIONS: Read-write session, SO logged in
//
// User Types (CK_USER_TYPE):
//   - CKU_SO: Security Officer
//   - CKU_USER: Normal User
//   - CKU_CONTEXT_SPECIFIC: Context-specific login
//
// References:
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package module

import (
	"sync"
	"sync/atomic"
)

// Session state constants (CK_STATE).
// These define the possible states of a PKCS#11 session.
type SessionState uint32

const (
	// CKS_RO_PUBLIC_SESSION is a read-only session without user login.
	CKS_RO_PUBLIC_SESSION SessionState = 0

	// CKS_RO_USER_FUNCTIONS is a read-only session with normal user logged in.
	CKS_RO_USER_FUNCTIONS SessionState = 1

	// CKS_RW_PUBLIC_SESSION is a read-write session without user login.
	CKS_RW_PUBLIC_SESSION SessionState = 2

	// CKS_RW_USER_FUNCTIONS is a read-write session with normal user logged in.
	CKS_RW_USER_FUNCTIONS SessionState = 3

	// CKS_RW_SO_FUNCTIONS is a read-write session with SO logged in.
	CKS_RW_SO_FUNCTIONS SessionState = 4
)

// sessionStateNames maps session states to their string names.
var sessionStateNames = map[SessionState]string{
	CKS_RO_PUBLIC_SESSION: "CKS_RO_PUBLIC_SESSION",
	CKS_RO_USER_FUNCTIONS: "CKS_RO_USER_FUNCTIONS",
	CKS_RW_PUBLIC_SESSION: "CKS_RW_PUBLIC_SESSION",
	CKS_RW_USER_FUNCTIONS: "CKS_RW_USER_FUNCTIONS",
	CKS_RW_SO_FUNCTIONS:   "CKS_RW_SO_FUNCTIONS",
}

// String returns the string representation of the session state.
func (s SessionState) String() string {
	if name, ok := sessionStateNames[s]; ok {
		return name
	}
	return "CKS_UNKNOWN"
}

// User type constants (CK_USER_TYPE).
type UserType uint32

const (
	// CKU_SO is the Security Officer user type.
	CKU_SO UserType = 0

	// CKU_USER is the normal user type.
	CKU_USER UserType = 1

	// CKU_CONTEXT_SPECIFIC is for context-specific login.
	CKU_CONTEXT_SPECIFIC UserType = 2
)

// userTypeNames maps user types to their string names.
var userTypeNames = map[UserType]string{
	CKU_SO:               "CKU_SO",
	CKU_USER:             "CKU_USER",
	CKU_CONTEXT_SPECIFIC: "CKU_CONTEXT_SPECIFIC",
}

// String returns the string representation of the user type.
func (u UserType) String() string {
	if name, ok := userTypeNames[u]; ok {
		return name
	}
	return "CKU_UNKNOWN"
}

// Session flag constants (CK_FLAGS for sessions).
type SessionFlag uint32

const (
	// CKF_RW_SESSION indicates a read-write session.
	CKF_RW_SESSION SessionFlag = 0x00000002

	// CKF_SERIAL_SESSION must always be set (required by PKCS#11).
	CKF_SERIAL_SESSION SessionFlag = 0x00000004
)

// Operation type constants for multi-part cryptographic operations.
type OperationType uint8

const (
	// OperationNone indicates no operation is active.
	OperationNone OperationType = iota

	// OperationSign indicates a signing operation is active.
	OperationSign

	// OperationVerify indicates a verification operation is active.
	OperationVerify

	// OperationEncrypt indicates an encryption operation is active.
	OperationEncrypt

	// OperationDecrypt indicates a decryption operation is active.
	OperationDecrypt

	// OperationDigest indicates a digest operation is active.
	OperationDigest

	// OperationFindObjects indicates a find objects operation is active.
	OperationFindObjects

	// OperationDerive indicates a key derivation operation is active.
	OperationDerive

	// OperationVerifySignature indicates a signature-first verification operation is active (v3.2).
	OperationVerifySignature

	// OperationEncapsulate indicates a KEM encapsulation operation is active (v3.2).
	OperationEncapsulate

	// OperationDecapsulate indicates a KEM decapsulation operation is active (v3.2).
	OperationDecapsulate
)

// operationTypeNames maps operation types to their string names.
var operationTypeNames = map[OperationType]string{
	OperationNone:            "OperationNone",
	OperationSign:            "OperationSign",
	OperationVerify:          "OperationVerify",
	OperationEncrypt:         "OperationEncrypt",
	OperationDecrypt:         "OperationDecrypt",
	OperationDigest:          "OperationDigest",
	OperationFindObjects:     "OperationFindObjects",
	OperationDerive:          "OperationDerive",
	OperationVerifySignature: "OperationVerifySignature",
	OperationEncapsulate:     "OperationEncapsulate",
	OperationDecapsulate:     "OperationDecapsulate",
}

// String returns the string representation of the operation type.
func (o OperationType) String() string {
	if name, ok := operationTypeNames[o]; ok {
		return name
	}
	return "OperationUnknown"
}

// OperationState holds state for multi-part cryptographic operations.
type OperationState struct {
	// Type is the type of operation currently active.
	Type OperationType

	// Mechanism is the mechanism used for the operation.
	Mechanism MechanismType

	// KeyHandle is the key handle used for the operation.
	KeyHandle ObjectHandle

	// Data accumulates data for multi-part operations.
	Data []byte

	// FindTemplate stores the template for FindObjects operations.
	FindTemplate []Attribute

	// FindResults stores the results of a FindObjects operation.
	FindResults []ObjectHandle

	// FindIndex tracks position in FindResults for FindObjectsFinal.
	FindIndex int

	// CryptoOp stores the cryptographic operation object.
	// This is an interface{} to avoid circular dependencies with crypto.go.
	CryptoOp interface{}
}

// Session represents a PKCS#11 session.
// Per OASIS PKCS#11 specification, a session is an open connection
// between an application and a token.
type Session struct {
	// Handle is the unique session handle.
	Handle SessionHandle

	// SlotID identifies the slot containing the token.
	SlotID uint64

	// state holds the current session state (atomic for lock-free reads).
	state atomic.Uint32

	// flags holds the session flags.
	flags SessionFlag

	// DeviceError holds the last device error code.
	DeviceError uint32

	// mu protects operation state changes.
	mu sync.RWMutex

	// operations holds the current operation states, indexed by operation type.
	// This allows multiple concurrent operations (e.g., digest + encrypt for
	// dual-operation functions like DigestEncryptUpdate).
	operations map[OperationType]*OperationState
}

// NewSession creates a new session with the given parameters.
func NewSession(handle SessionHandle, slotID uint64, flags SessionFlag) *Session {
	s := &Session{
		Handle:     handle,
		SlotID:     slotID,
		flags:      flags,
		operations: make(map[OperationType]*OperationState),
	}

	// Initialize to appropriate public session state based on flags
	if flags&CKF_RW_SESSION != 0 {
		s.state.Store(uint32(CKS_RW_PUBLIC_SESSION))
	} else {
		s.state.Store(uint32(CKS_RO_PUBLIC_SESSION))
	}

	return s
}

// State returns the current session state.
func (s *Session) State() SessionState {
	return SessionState(s.state.Load())
}

// setState atomically updates the session state.
func (s *Session) setState(state SessionState) {
	s.state.Store(uint32(state))
}

// Flags returns the session flags.
func (s *Session) Flags() SessionFlag {
	return s.flags
}

// IsReadWrite returns true if this is a read-write session.
func (s *Session) IsReadWrite() bool {
	return s.flags&CKF_RW_SESSION != 0
}

// IsLoggedIn returns true if a user or SO is logged in.
func (s *Session) IsLoggedIn() bool {
	state := s.State()
	return state == CKS_RO_USER_FUNCTIONS ||
		state == CKS_RW_USER_FUNCTIONS ||
		state == CKS_RW_SO_FUNCTIONS
}

// IsUserLoggedIn returns true if a normal user is logged in.
func (s *Session) IsUserLoggedIn() bool {
	state := s.State()
	return state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS
}

// IsSOLoggedIn returns true if the Security Officer is logged in.
func (s *Session) IsSOLoggedIn() bool {
	return s.State() == CKS_RW_SO_FUNCTIONS
}

// GetOperationState returns a copy of the current operation state.
// For backward compatibility, this returns the first active operation found,
// preferring operations in the order: Sign, Verify, Encrypt, Decrypt, Digest, FindObjects.
func (s *Session) GetOperationState() OperationState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return the first active operation found (for backward compatibility)
	operationOrder := []OperationType{
		OperationSign,
		OperationVerify,
		OperationEncrypt,
		OperationDecrypt,
		OperationDigest,
		OperationFindObjects,
		OperationDerive,
		OperationVerifySignature,
		OperationEncapsulate,
		OperationDecapsulate,
	}

	for _, opType := range operationOrder {
		if op, exists := s.operations[opType]; exists && op != nil {
			return s.copyOperationState(op)
		}
	}

	return OperationState{}
}

// GetOperationByType returns a copy of the operation state for a specific type.
// Returns nil if no operation of that type is active.
func (s *Session) GetOperationByType(opType OperationType) *OperationState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	op, exists := s.operations[opType]
	if !exists || op == nil {
		return nil
	}

	copied := s.copyOperationState(op)
	return &copied
}

// copyOperationState creates a deep copy of an operation state.
func (s *Session) copyOperationState(op *OperationState) OperationState {
	state := *op
	if op.Data != nil {
		state.Data = make([]byte, len(op.Data))
		copy(state.Data, op.Data)
	}
	if op.FindResults != nil {
		state.FindResults = make([]ObjectHandle, len(op.FindResults))
		copy(state.FindResults, op.FindResults)
	}
	return state
}

// SetOperationState sets the operation state.
// The operation is stored by its type for dual-operation support.
func (s *Session) SetOperationState(state OperationState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state.Type == OperationNone {
		// Clear all operations when setting to None
		s.operations = make(map[OperationType]*OperationState)
		return
	}

	s.operations[state.Type] = &state
}

// SetOperationByType sets the operation state for a specific type.
func (s *Session) SetOperationByType(opType OperationType, state *OperationState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state == nil {
		delete(s.operations, opType)
		return
	}

	state.Type = opType
	s.operations[opType] = state
}

// SetOperationIfAbsent atomically checks that no operation of the given type
// is active, then sets it. Returns CKR_OPERATION_ACTIVE if the slot is taken.
// This prevents TOCTOU races between HasOperationType and SetOperationByType.
func (s *Session) SetOperationIfAbsent(opType OperationType, state *OperationState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.operations[opType]; ok && existing != nil {
		return NewPKCS11Error(CKR_OPERATION_ACTIVE)
	}

	state.Type = opType
	s.operations[opType] = state
	return nil
}

// HasActiveOperation returns true if any operation is in progress,
// or if opType is specified (not OperationNone), checks for that specific operation type.
func (s *Session) HasActiveOperation() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.operations) > 0
}

// HasOperationType returns true if an operation of the specified type is active.
func (s *Session) HasOperationType(opType OperationType) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	op, exists := s.operations[opType]
	return exists && op != nil
}

// GetActiveOperationType returns the current operation type.
// For backward compatibility, returns the first active operation found.
func (s *Session) GetActiveOperationType() OperationType {
	s.mu.RLock()
	defer s.mu.RUnlock()

	operationOrder := []OperationType{
		OperationSign,
		OperationVerify,
		OperationEncrypt,
		OperationDecrypt,
		OperationDigest,
		OperationFindObjects,
		OperationDerive,
		OperationVerifySignature,
		OperationEncapsulate,
		OperationDecapsulate,
	}

	for _, opType := range operationOrder {
		if op, exists := s.operations[opType]; exists && op != nil {
			return opType
		}
	}

	return OperationNone
}

// ClearOperation resets all operation states.
func (s *Session) ClearOperation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operations = make(map[OperationType]*OperationState)
}

// ClearOperationType clears a specific operation type from the session.
func (s *Session) ClearOperationType(opType OperationType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.operations, opType)
}

// WithOperation provides thread-safe in-place mutation of a live operation.
// The callback receives a pointer to the actual operation state (not a copy),
// allowing callers to modify fields like CryptoOp and Data directly.
// Returns CKR_OPERATION_NOT_INITIALIZED if no operation of the given type exists.
func (s *Session) WithOperation(opType OperationType, fn func(op *OperationState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	op, exists := s.operations[opType]
	if !exists || op == nil {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	return fn(op)
}

// ConsumeOperation atomically extracts operation state and removes it from the
// session in a single lock hold. This prevents TOCTOU races where a concurrent
// VerifySignatureInit could set a new operation between the extract and the
// clear, causing the deferred clear to remove the wrong operation.
// Returns CKR_OPERATION_NOT_INITIALIZED if no operation of the given type exists.
func (s *Session) ConsumeOperation(opType OperationType) (*OperationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	op, exists := s.operations[opType]
	if !exists || op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	// Remove from the map atomically under the same lock
	delete(s.operations, opType)
	return op, nil
}

// SessionInfo represents information about a session (CK_SESSION_INFO).
type SessionInfo struct {
	// SlotID identifies the slot containing the token.
	SlotID uint64

	// State is the current session state.
	State SessionState

	// Flags contains the session flags.
	Flags SessionFlag

	// DeviceError holds the last device error code.
	DeviceError uint32
}

// GetInfo returns session information.
func (s *Session) GetInfo() SessionInfo {
	return SessionInfo{
		SlotID:      s.SlotID,
		State:       s.State(),
		Flags:       s.flags,
		DeviceError: s.DeviceError,
	}
}

// SessionManager manages PKCS#11 sessions for a slot.
// It handles session lifecycle, login state, and operation tracking.
type SessionManager struct {
	// mu protects the session manager state.
	mu sync.RWMutex

	// sessions maps session handles to sessions.
	sessions *HandleTable[*Session]

	// slotID is the slot this manager belongs to.
	slotID uint64

	// maxSessions is the maximum number of concurrent sessions (0 = unlimited).
	maxSessions uint32

	// loginState tracks the current login state across all sessions.
	// In PKCS#11, login state applies to all sessions of a token.
	loginState atomic.Uint32

	// loggedInUser tracks which user type is logged in.
	loggedInUser atomic.Uint32

	// roSessionCount tracks the number of read-only sessions.
	roSessionCount atomic.Uint32

	// rwSessionCount tracks the number of read-write sessions.
	rwSessionCount atomic.Uint32

	// userPIN is the hashed user PIN (for validation).
	userPIN []byte

	// soPIN is the hashed SO PIN (for validation).
	soPIN []byte

	// pinValidator is an optional function to validate PINs.
	pinValidator func(userType UserType, pin []byte) bool
}

// Login state constants for the session manager.
const (
	loginStateNone uint32 = iota
	loginStateUser
	loginStateSO
)

// NewSessionManager creates a new session manager for a slot.
func NewSessionManager(slotID uint64, maxSessions uint32) *SessionManager {
	return &SessionManager{
		sessions:    NewHandleTable[*Session](),
		slotID:      slotID,
		maxSessions: maxSessions,
	}
}

// SetPINValidator sets the PIN validation function.
func (m *SessionManager) SetPINValidator(validator func(userType UserType, pin []byte) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pinValidator = validator
}

// SetUserPIN sets the user PIN (should be hashed).
func (m *SessionManager) SetUserPIN(pin []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userPIN = make([]byte, len(pin))
	copy(m.userPIN, pin)
}

// SetSOPIN sets the SO PIN (should be hashed).
func (m *SessionManager) SetSOPIN(pin []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.soPIN = make([]byte, len(pin))
	copy(m.soPIN, pin)
}

// OpenSession opens a new session.
// Implements C_OpenSession behavior per PKCS#11 specification.
func (m *SessionManager) OpenSession(flags SessionFlag) (SessionHandle, error) {
	// CKF_SERIAL_SESSION must always be set
	if flags&CKF_SERIAL_SESSION == 0 {
		return SessionHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_PARALLEL_NOT_SUPPORTED)
	}

	// Check if SO is logged in and this is a RO session request
	// Per PKCS#11, RO sessions cannot be opened while SO is logged in
	if m.loginState.Load() == loginStateSO && flags&CKF_RW_SESSION == 0 {
		return SessionHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_READ_WRITE_SO_EXISTS)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check session count limit
	if m.maxSessions > 0 {
		totalSessions := m.roSessionCount.Load() + m.rwSessionCount.Load()
		if totalSessions >= m.maxSessions {
			return SessionHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_COUNT)
		}
	}

	// Create session with a temporary handle (will be updated after allocation)
	session := NewSession(SessionHandle(0), m.slotID, flags)

	// Allocate session handle and store session
	handle, err := m.sessions.Allocate(session)
	if err != nil {
		return SessionHandle(InvalidHandle), NewPKCS11ErrorWithCause(CKR_HOST_MEMORY, err)
	}

	// Update the session's handle to the allocated value
	session.Handle = SessionHandle(handle)

	// Update session state based on current login state
	m.updateSessionLoginState(session)

	// Update session counts
	if flags&CKF_RW_SESSION != 0 {
		m.rwSessionCount.Add(1)
	} else {
		m.roSessionCount.Add(1)
	}

	return SessionHandle(handle), nil
}

// updateSessionLoginState updates a session's state based on current login state.
func (m *SessionManager) updateSessionLoginState(session *Session) {
	loginState := m.loginState.Load()
	isRW := session.IsReadWrite()

	switch loginState {
	case loginStateUser:
		if isRW {
			session.setState(CKS_RW_USER_FUNCTIONS)
		} else {
			session.setState(CKS_RO_USER_FUNCTIONS)
		}
	case loginStateSO:
		// SO can only have RW sessions
		session.setState(CKS_RW_SO_FUNCTIONS)
	default:
		if isRW {
			session.setState(CKS_RW_PUBLIC_SESSION)
		} else {
			session.setState(CKS_RO_PUBLIC_SESSION)
		}
	}
}

// CloseSession closes a session.
// Implements C_CloseSession behavior per PKCS#11 specification.
func (m *SessionManager) CloseSession(handle SessionHandle) error {
	session, ok := m.sessions.Release(uint64(handle))
	if !ok {
		return NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Update session counts
	if session.IsReadWrite() {
		m.rwSessionCount.Add(^uint32(0)) // Decrement by 1
	} else {
		m.roSessionCount.Add(^uint32(0)) // Decrement by 1
	}

	// If this was the last session and user/SO was logged in, they remain logged in
	// per PKCS#11 spec - login state persists until explicit logout or all sessions close
	m.checkAndClearLoginState()

	return nil
}

// CloseAllSessions closes all sessions for the slot.
// Implements C_CloseAllSessions behavior per PKCS#11 specification.
func (m *SessionManager) CloseAllSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions.Clear()
	m.roSessionCount.Store(0)
	m.rwSessionCount.Store(0)

	// Clear login state when all sessions are closed
	m.loginState.Store(loginStateNone)
	m.loggedInUser.Store(0)
}

// checkAndClearLoginState clears login state if no sessions remain.
func (m *SessionManager) checkAndClearLoginState() {
	if m.sessions.Size() == 0 {
		m.loginState.Store(loginStateNone)
		m.loggedInUser.Store(0)
	}
}

// GetSession retrieves a session by handle.
func (m *SessionManager) GetSession(handle SessionHandle) (*Session, error) {
	session, ok := m.sessions.Lookup(uint64(handle))
	if !ok {
		return nil, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}
	return session, nil
}

// GetSessionInfo returns information about a session.
func (m *SessionManager) GetSessionInfo(handle SessionHandle) (SessionInfo, error) {
	session, err := m.GetSession(handle)
	if err != nil {
		return SessionInfo{}, err
	}
	return session.GetInfo(), nil
}

// Login logs a user into the token.
// Implements C_Login behavior per PKCS#11 specification.
func (m *SessionManager) Login(handle SessionHandle, userType UserType, pin []byte) error {
	session, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	// Validate user type
	if userType != CKU_SO && userType != CKU_USER && userType != CKU_CONTEXT_SPECIFIC {
		return NewPKCS11Error(CKR_USER_TYPE_INVALID)
	}

	// Check if already logged in
	currentLogin := m.loginState.Load()
	if currentLogin != loginStateNone {
		// Check if same user is trying to log in again
		if (currentLogin == loginStateUser && userType == CKU_USER) ||
			(currentLogin == loginStateSO && userType == CKU_SO) {
			return NewPKCS11Error(CKR_USER_ALREADY_LOGGED_IN)
		}
		// Different user trying to log in
		return NewPKCS11Error(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
	}

	// SO login requires RW session
	if userType == CKU_SO && !session.IsReadWrite() {
		return NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}

	// SO login cannot proceed if RO sessions exist
	if userType == CKU_SO && m.roSessionCount.Load() > 0 {
		return NewPKCS11Error(CKR_SESSION_READ_ONLY_EXISTS)
	}

	// Validate PIN
	if err := m.validatePIN(userType, pin); err != nil {
		return err
	}

	// Update login state
	m.mu.Lock()
	defer m.mu.Unlock()

	if userType == CKU_SO {
		m.loginState.Store(loginStateSO)
	} else {
		m.loginState.Store(loginStateUser)
	}
	m.loggedInUser.Store(uint32(userType))

	// Update all sessions to reflect login state
	m.sessions.ForEach(func(h uint64, s *Session) bool {
		m.updateSessionLoginState(s)
		return true
	})

	return nil
}

// validatePIN validates a PIN for the given user type.
// The stored PIN is expected to be a SHA-256 hash.
func (m *SessionManager) validatePIN(userType UserType, pin []byte) error {
	// Check PIN length
	if len(pin) == 0 {
		return NewPKCS11Error(CKR_PIN_LEN_RANGE)
	}

	// Use custom validator if provided
	if m.pinValidator != nil {
		if !m.pinValidator(userType, pin) {
			return NewPKCS11Error(CKR_PIN_INCORRECT)
		}
		return nil
	}

	// Default PIN validation using stored PINs
	m.mu.RLock()
	defer m.mu.RUnlock()

	var storedPINHash []byte
	switch userType {
	case CKU_SO:
		storedPINHash = m.soPIN
	case CKU_USER:
		storedPINHash = m.userPIN
	default:
		return NewPKCS11Error(CKR_USER_TYPE_INVALID)
	}

	// Check if PIN is initialized
	if storedPINHash == nil {
		return NewPKCS11Error(CKR_USER_PIN_NOT_INITIALIZED)
	}

	// Hash the provided PIN and compare with stored hash
	// Uses hashPin from token.go (same package)
	pinHash := hashPin(string(pin))
	if !comparePINs(pinHash, storedPINHash) {
		return NewPKCS11Error(CKR_PIN_INCORRECT)
	}

	return nil
}

// comparePINs compares two PINs in constant time.
func comparePINs(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// Logout logs out the current user.
// Implements C_Logout behavior per PKCS#11 specification.
func (m *SessionManager) Logout(handle SessionHandle) error {
	_, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	// Check if logged in
	if m.loginState.Load() == loginStateNone {
		return NewPKCS11Error(CKR_USER_NOT_LOGGED_IN)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear login state
	m.loginState.Store(loginStateNone)
	m.loggedInUser.Store(0)

	// Update all sessions to public state
	m.sessions.ForEach(func(h uint64, s *Session) bool {
		m.updateSessionLoginState(s)
		return true
	})

	return nil
}

// IsLoggedIn returns true if any user is logged in.
func (m *SessionManager) IsLoggedIn() bool {
	return m.loginState.Load() != loginStateNone
}

// GetLoggedInUserType returns the currently logged in user type.
// Returns false if no user is logged in.
func (m *SessionManager) GetLoggedInUserType() (UserType, bool) {
	if m.loginState.Load() == loginStateNone {
		return 0, false
	}
	return UserType(m.loggedInUser.Load()), true
}

// SessionCount returns the total number of open sessions.
func (m *SessionManager) SessionCount() uint32 {
	return m.roSessionCount.Load() + m.rwSessionCount.Load()
}

// ROSessionCount returns the number of read-only sessions.
func (m *SessionManager) ROSessionCount() uint32 {
	return m.roSessionCount.Load()
}

// RWSessionCount returns the number of read-write sessions.
func (m *SessionManager) RWSessionCount() uint32 {
	return m.rwSessionCount.Load()
}

// InitializeOperation initializes a cryptographic operation on a session.
// For dual-operation support, this only returns CKR_OPERATION_ACTIVE if
// the same operation type is already active.
func (m *SessionManager) InitializeOperation(handle SessionHandle, opType OperationType, mechanism MechanismType, keyHandle ObjectHandle) error {
	session, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	// Check if the same operation type is already active
	if session.HasOperationType(opType) {
		return NewPKCS11Error(CKR_OPERATION_ACTIVE)
	}

	// Set operation state
	session.SetOperationByType(opType, &OperationState{
		Type:      opType,
		Mechanism: mechanism,
		KeyHandle: keyHandle,
	})

	return nil
}

// FinalizeOperation clears the active operation on a session.
// For backward compatibility, this clears all operations.
func (m *SessionManager) FinalizeOperation(handle SessionHandle) error {
	session, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	// Check if any operation is active
	if !session.HasActiveOperation() {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	session.ClearOperation()
	return nil
}

// FinalizeOperationType clears a specific operation type on a session.
func (m *SessionManager) FinalizeOperationType(handle SessionHandle, opType OperationType) error {
	session, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	// Check if the specific operation type is active
	if !session.HasOperationType(opType) {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	session.ClearOperationType(opType)
	return nil
}

// GetOperationState returns the operation state for a session.
// For backward compatibility, this returns the first active operation found.
func (m *SessionManager) GetOperationState(handle SessionHandle) (OperationState, error) {
	session, err := m.GetSession(handle)
	if err != nil {
		return OperationState{}, err
	}

	if !session.HasActiveOperation() {
		return OperationState{}, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	return session.GetOperationState(), nil
}

// GetOperationStateByType returns the operation state for a specific type.
func (m *SessionManager) GetOperationStateByType(handle SessionHandle, opType OperationType) (*OperationState, error) {
	session, err := m.GetSession(handle)
	if err != nil {
		return nil, err
	}

	op := session.GetOperationByType(opType)
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	return op, nil
}

// SetOperationState sets the operation state for a session.
// Used for C_SetOperationState to restore saved state.
func (m *SessionManager) SetOperationState(handle SessionHandle, state OperationState) error {
	session, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	// Cannot set state while the same operation type is active
	if session.HasOperationType(state.Type) {
		return NewPKCS11Error(CKR_OPERATION_ACTIVE)
	}

	session.SetOperationState(state)
	return nil
}

// SetOperation sets the operation state directly for a session.
// This is used for operations like SignRecoverInit that need to initialize
// and set state in one step without first checking for an active operation.
func (m *SessionManager) SetOperation(handle SessionHandle, state *OperationState) error {
	session, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	session.SetOperationState(*state)
	return nil
}
