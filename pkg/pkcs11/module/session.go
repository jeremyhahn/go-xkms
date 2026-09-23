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
	"errors"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-enclave"
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

	// Result caches the output of a terminal operation such as C_Sign or
	// C_Encrypt. PKCS#11 v3.2 §5.2 lets an application call these functions
	// twice — once with a NULL buffer to learn the required length, then again
	// to collect the bytes — and neither the length query nor a
	// CKR_BUFFER_TOO_SMALL result may terminate the operation. Caching the
	// output makes the second call return the same bytes without running the
	// backend operation again, which matters for mechanisms whose every
	// invocation consumes a nonce or a counter.
	Result []byte

	// ResultReady reports whether Result holds the output of a completed
	// terminal operation, distinguishing a cached empty result from no result.
	ResultReady bool

	// MultiPart reports whether the operation has consumed at least one part
	// through its *Update function. PKCS#11 v3.2 requires that the single-part
	// function (C_Sign, C_Verify, C_Encrypt, C_Decrypt, C_Digest,
	// C_VerifySignature) follow its *Init with no intervening *Update, because
	// it cannot be used to terminate a multiple-part operation. Without this
	// flag the single-part call would silently discard everything buffered so
	// far and operate on its own argument alone, returning a well-formed but
	// wrong result.
	//
	// Data cannot serve this purpose: it holds AEAD associated data, which the
	// message-based functions set without starting a multiple-part operation.
	MultiPart bool

	// AuthRevoked reports that C_Logout has revoked the authentication this
	// operation was initialized under. PKCS#11 v3.2 §5.6.10 says logging out
	// destroys the application's private session objects and invalidates its
	// handles to private objects, so an operation bound to a private key
	// cannot be completed afterwards.
	//
	// The reason has to be recorded at the moment of the logout, because that
	// is the only moment it is knowable: by the time the next C_Sign or
	// C_Decrypt looks the key up, an unresolvable handle is indistinguishable
	// from one the application destroyed itself, and the two call for
	// different answers -- CKR_USER_NOT_LOGGED_IN for this one, the
	// undiagnosable CKR_FUNCTION_FAILED for the other.
	AuthRevoked bool
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

	// contextAuth records, per operation category, the key for which the
	// application has re-authenticated with C_Login(CKU_CONTEXT_SPECIFIC). An
	// entry authorizes exactly one use of that key and is consumed when the use
	// occurs.
	//
	// The key is half of the entry because PKCS#11 v3.2 §4.10 authenticates
	// "the active key": re-authentication follows an operation that was
	// initiated with a particular key, and it is that key it puts "in an
	// authenticated state". Recording only the category let a grant obtained
	// while one key's operation was active be spent on a different key.
	contextAuth map[OperationType]ObjectHandle
}

// NewSession creates a new session with the given parameters.
func NewSession(handle SessionHandle, slotID uint64, flags SessionFlag) *Session {
	s := &Session{
		Handle:      handle,
		SlotID:      slotID,
		flags:       flags,
		operations:  make(map[OperationType]*OperationState),
		contextAuth: make(map[OperationType]ObjectHandle),
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
	if op.Result != nil {
		state.Result = make([]byte, len(op.Result))
		copy(state.Result, op.Result)
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

// ClearOperation resets all operation states. It is only correct where every
// operation on the session must end at once, such as C_CloseSession or
// C_SessionCancel with all categories selected. Terminating a single operation
// must use ClearOperationType, otherwise a concurrently active operation of a
// different category — the other half of a dual-function flow — is destroyed
// along with it.
func (s *Session) ClearOperation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, op := range s.operations {
		zeroizeOperation(op)
	}
	s.operations = make(map[OperationType]*OperationState)
	s.contextAuth = make(map[OperationType]ObjectHandle)
}

// GrantContextAuthentication records that the application re-authenticated with
// C_Login(CKU_CONTEXT_SPECIFIC) for one use of keyHandle in the given operation
// category.
func (s *Session) GrantContextAuthentication(opType OperationType, keyHandle ObjectHandle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contextAuth[opType] = keyHandle
}

// ConsumeContextAuthentication reports whether the application re-authenticated
// for a use of keyHandle in the given operation category, consuming the
// authorization so it covers a single use.
//
// A grant made for one key does not answer for another. PKCS#11 v3.2 §4.10 puts
// "the active key" into an authenticated state, so an authorization the
// application obtained while an operation on some other key was active is not
// the authorization this key's CKA_ALWAYS_AUTHENTICATE asks for.
func (s *Session) ConsumeContextAuthentication(opType OperationType, keyHandle ObjectHandle) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	granted, ok := s.contextAuth[opType]
	if !ok || granted != keyHandle {
		return false
	}
	delete(s.contextAuth, opType)
	return true
}

// ActiveOperationKey returns the key handle of the active operation of the given
// type, reporting false when no operation of that type is active.
func (s *Session) ActiveOperationKey(opType OperationType) (ObjectHandle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	op, exists := s.operations[opType]
	if !exists || op == nil {
		return ObjectHandle(InvalidHandle), false
	}
	return op.KeyHandle, true
}

// ClearOperationType clears a specific operation type from the session, leaving
// any concurrently active operation of another category untouched.
func (s *Session) ClearOperationType(opType OperationType) {
	s.mu.Lock()
	defer s.mu.Unlock()

	zeroizeOperation(s.operations[opType])
	delete(s.operations, opType)

	// A context-specific authorization is scoped to the operation that was
	// active when it was granted, so it must not outlive that operation.
	delete(s.contextAuth, opType)
}

// RevokeOperationAuthorization marks every active operation for which revoked
// reports true as no longer authorized, so the next call that would continue it
// refuses instead. C_Logout is the only caller: it has just withdrawn the
// authentication the session held, and PKCS#11 v3.2 §5.6.10 forbids the
// operations that depended on it from completing.
//
// The predicate is evaluated under the session lock against the live operation
// state, so an operation cannot be started, finished or re-bound midway through
// the decision. It must not call back into this session.
func (s *Session) RevokeOperationAuthorization(revoked func(op *OperationState) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, op := range s.operations {
		if op == nil || op.AuthRevoked {
			continue
		}
		if revoked(op) {
			op.AuthRevoked = true
		}
	}
}

// zeroizeOperation overwrites the cached output an operation holds before it is
// discarded. Result caches the output of a terminal call — for a decryption
// that is recovered plaintext — so it must not be left for the garbage
// collector to release at some arbitrary later point. Only Result is wiped:
// cacheResult stores a private copy, whereas Data may alias buffers the caller
// still owns.
func zeroizeOperation(op *OperationState) {
	if op == nil {
		return
	}
	enclave.Wipe(op.Result)
	op.Result = nil
	op.ResultReady = false
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

	// failedUserPIN and failedSOPIN count consecutive failed authentication
	// attempts. Without a lockout an attacker with session access can brute
	// force a short PIN online at full speed. Counters are atomic so a failed
	// attempt can be recorded from a read-locked validation path.
	failedUserPIN atomic.Uint32
	failedSOPIN   atomic.Uint32

	// incrementAttempt and resetAttempt, when set, reconcile a failed-attempt
	// counter with durable storage so the lockout reaches the token before the
	// next call can be made. A lockout a restart clears is not a lockout: the
	// atomics above are an optimistic in-memory cache, but the authoritative
	// counter lives in the store.
	//
	// incrementAttempt atomically bumps the durable counter and returns
	// (authoritative value, persisted). persisted is false when no durable
	// backend is configured, so the caller advances its own atomic instead — and
	// so that several remote-mode clients sharing one token accumulate failures
	// against one true counter rather than each losing the others' increments.
	// resetAttempt clears the durable counter after a success or PIN change.
	//
	// A shared token's local atomic can trail the durable counter between a
	// concurrent client's increment and this client's next reconcile, so the
	// cheap pre-check in preparePINVerificationLocked may admit one extra
	// derivation per lagging client; the increment on that attempt still reads
	// the durable value and locks, so the budget is never actually exceeded.
	incrementAttempt func(userType UserType) (uint32, bool)
	resetAttempt     func(userType UserType)
}

// Login state constants for the session manager.
const (
	loginStateNone uint32 = iota
	loginStateUser
	loginStateSO
)

// NewSessionManager creates a new session manager for a slot.
func NewSessionManager(slotID uint64, maxSessions uint32) *SessionManager {
	return NewSessionManagerWithTable(slotID, maxSessions, NewHandleTable[*Session]())
}

// NewSessionManagerWithTable creates a session manager for a slot that draws its
// handles from a table shared with every other slot of the same module.
//
// CK_SESSION_HANDLE is ONE flat namespace across the library (v3.2 §3.3), so a
// manager with a private counter hands out handle 1 for its slot while another
// manager hands out handle 1 for its own. Module.findSession and
// Module.CloseSession both resolve a handle by ranging over the managers and
// taking the first hit, and Go randomizes map iteration -- so with two slots,
// C_CloseSession(1) would close whichever the range reached first, and
// C_Login(1) would authenticate against an arbitrary token.
//
// SlotManager provisions only slot 0 today, which is the sole reason this has
// never been observable. Sharing the table removes the ambiguity structurally
// rather than relying on that staying true.
func NewSessionManagerWithTable(slotID uint64, maxSessions uint32, sessions *HandleTable[*Session]) *SessionManager {
	return &SessionManager{
		sessions:    sessions,
		slotID:      slotID,
		maxSessions: maxSessions,
	}
}

// ownsSession reports whether a session in the shared table belongs to this
// manager's slot. Every walker filters on it: the table now holds every slot's
// sessions, so an unfiltered range would reach another token's.
func (m *SessionManager) ownsSession(s *Session) bool {
	return s != nil && s.SlotID == m.slotID
}

// SetUserPIN sets the user PIN verifier (already hashed).
//
// An empty verifier is stored as nil so that "no PIN has been established"
// stays distinguishable from "a PIN that nothing matches". make([]byte, 0) is
// non-nil, and storing that made C_InitToken's reset of the user PIN look like
// a provisioned token whose every login failed: three attempts then locked it,
// where the answer should have been CKR_USER_PIN_NOT_INITIALIZED.
func (m *SessionManager) SetUserPIN(pin []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(pin) == 0 {
		m.userPIN = nil
		return
	}
	m.userPIN = make([]byte, len(pin))
	copy(m.userPIN, pin)
}

// SetSOPIN sets the SO PIN verifier (already hashed). An empty verifier is
// stored as nil, for the reason SetUserPIN gives.
func (m *SessionManager) SetSOPIN(pin []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(pin) == 0 {
		m.soPIN = nil
		return
	}
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

	// An asynchronous session must be refused rather than downgraded. PKCS#11
	// v3.2 §5.6.1 says a token that does not support asynchronous operations
	// should return CKR_SESSION_ASYNC_NOT_SUPPORTED, and this token does not
	// advertise CKF_ASYNC_SESSION_SUPPORTED. Handing back a synchronous session
	// under CKR_OK would leave the application believing it may collect results
	// with C_AsyncGetID, so the mismatch would surface far from its cause.
	if flags&SessionFlag(CKF_ASYNC_SESSION) != 0 {
		return SessionHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_ASYNC_NOT_SUPPORTED)
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
	// Ownership is checked BEFORE the release, or this manager would close a
	// session belonging to another slot and then report it could not find it.
	if existing, ok := m.sessions.Lookup(uint64(handle)); !ok || !m.ownsSession(existing) {
		return NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	session, ok := m.sessions.Release(uint64(handle))
	if !ok {
		return NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Closing a session ends every operation on it, so the outputs those
	// operations cached are wiped here rather than left for the collector.
	// OperationState.Result holds the result of a terminal call -- for
	// C_Decrypt, recovered plaintext -- which the two-call convention requires
	// the module to keep between the length query and the copying call. Every
	// other termination path zeroizes it; this one must too, or a short-lived
	// process leaves it readable in a core dump.
	session.ClearOperation()

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

	// Only this slot's sessions. The table is shared across every slot of the
	// module, so Clear() would close another token's sessions as a side effect
	// of closing this one's.
	//
	// Handles are collected under the table's read lock and released afterwards,
	// because Release takes the write lock and ForEach holds the read lock for
	// the whole walk. Each session's cached operation output is wiped first, for
	// the reason CloseSession gives.
	var owned []uint64
	m.sessions.ForEach(func(handle uint64, session *Session) bool {
		if m.ownsSession(session) {
			session.ClearOperation()
			owned = append(owned, handle)
		}
		return true
	})
	for _, handle := range owned {
		m.sessions.Release(handle)
	}
	m.roSessionCount.Store(0)
	m.rwSessionCount.Store(0)

	// Clear login state when all sessions are closed
	m.loginState.Store(loginStateNone)
	m.loggedInUser.Store(0)
}

// SessionHandles returns the handles of every session currently open on this
// slot.
//
// It exists so the module can destroy each session's objects before the manager
// forgets the sessions that owned them: a session object lives no longer than
// its session (v3.2 §4.1.3), and after CloseAllSessions nothing can name those
// sessions to clean up after them.
func (m *SessionManager) SessionHandles() []SessionHandle {
	var handles []SessionHandle
	m.sessions.ForEach(func(handle uint64, session *Session) bool {
		if m.ownsSession(session) {
			handles = append(handles, SessionHandle(handle))
		}
		return true
	})
	return handles
}

// checkAndClearLoginState clears login state if no sessions remain.
func (m *SessionManager) checkAndClearLoginState() {
	// Only this slot's sessions decide this slot's login state; the table also
	// holds other slots'.
	remaining := 0
	m.sessions.ForEach(func(_ uint64, session *Session) bool {
		if m.ownsSession(session) {
			remaining++
		}
		return true
	})
	if remaining == 0 {
		m.loginState.Store(loginStateNone)
		m.loggedInUser.Store(0)
	}
}

// GetSession retrieves a session by handle.
func (m *SessionManager) GetSession(handle SessionHandle) (*Session, error) {
	session, ok := m.sessions.Lookup(uint64(handle))
	// A handle naming another slot's session is not this manager's to return.
	// The table is shared across the module, so the lookup alone no longer
	// establishes ownership -- and Module.findSession resolves a handle by
	// asking each manager in turn, so a manager that answered for a foreign
	// session would make the search order decide which token replied.
	if !ok || !m.ownsSession(session) {
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
	// The handle has to name a session even though nothing below reads the
	// session itself; C_Login answers CKR_SESSION_HANDLE_INVALID for a handle
	// that names none (v3.2 §5.6.8).
	if _, err := m.GetSession(handle); err != nil {
		return err
	}

	// Validate user type
	if userType != CKU_SO && userType != CKU_USER && userType != CKU_CONTEXT_SPECIFIC {
		return NewPKCS11Error(CKR_USER_TYPE_INVALID)
	}

	// The invariant checks below and the state they commit must be evaluated
	// atomically. Reading the login and session counters before taking the lock
	// would let a concurrent OpenSession and Login both pass their checks and
	// produce an SO login coexisting with an open read-only session — exactly
	// what CKR_SESSION_READ_ONLY_EXISTS forbids.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Re-authentication for CKA_ALWAYS_AUTHENTICATE keys is expressly allowed
	// while the normal user is already logged in (v3.2 §5.6.8); it validates the
	// user PIN without altering the token's login state.
	//
	// Validating the PIN is all this layer does. The authorization a successful
	// re-authentication produces is bound to the key of the operation it
	// follows (v3.2 §4.10), and a session manager holds sessions, not objects:
	// it cannot resolve an operation's key handle to the object whose
	// CKA_ALWAYS_AUTHENTICATE the grant answers. Module.loginContextSpecific
	// owns that decision and makes the grant, which is also what keeps C_Login
	// and C_LoginUser answering alike.
	if userType == CKU_CONTEXT_SPECIFIC {
		if m.loginState.Load() != loginStateUser {
			return NewPKCS11Error(CKR_USER_NOT_LOGGED_IN)
		}
		plan, decided := m.preparePINVerificationLocked(CKU_USER, pin)
		if decided != nil {
			return decided
		}
		// The lock is released only for the derivation and re-taken before
		// returning, so the deferred Unlock above stays balanced on every path.
		m.mu.Unlock()
		err := m.finishPINVerification(plan, pin)
		m.mu.Lock()
		return err
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

	// The Security Officer may not log in while any read-only session is open on
	// the token. C_Login's return table (v3.2 §5.6.8) expresses this with
	// CKR_SESSION_READ_ONLY_EXISTS and does not list CKR_SESSION_READ_ONLY at
	// all, so that is the only code this refusal may carry.
	//
	// One check covers both shapes of the refusal. A read-only session used to
	// be rejected separately for not being read-write, but a session cannot be
	// read-only without having incremented roSessionCount, so this test already
	// catches it — and the separate test answered a code outside the function's
	// contract. SoftHSM 2.6 agrees: C_Login(CKU_SO) on a read-only session
	// returns CKR_SESSION_READ_ONLY_EXISTS (0x000000B7).
	if userType == CKU_SO && m.roSessionCount.Load() > 0 {
		return NewPKCS11Error(CKR_SESSION_READ_ONLY_EXISTS)
	}

	// The verifier is snapshotted here and the derivation runs with the lock
	// RELEASED; see preparePINVerificationLocked for why. The invariants checked
	// above are re-checked after re-acquiring, because a concurrent Login or
	// OpenSession can commit in the window.
	plan, decided := m.preparePINVerificationLocked(userType, pin)
	if decided != nil {
		return decided
	}

	// Released only for the derivation, and re-taken before anything else is
	// read or written, so the deferred Unlock stays balanced.
	m.mu.Unlock()
	verifyErr := m.finishPINVerification(plan, pin)
	m.mu.Lock()

	if verifyErr != nil {
		return verifyErr
	}

	// Re-check what the released lock allowed to change. Without this, two
	// concurrent Logins could both pass their checks and both commit, and an
	// OpenSession could open a read-only session while an SO login was mid-flight
	// -- the exact state CKR_SESSION_READ_ONLY_EXISTS exists to prevent.
	if m.loginState.Load() != loginStateNone {
		return NewPKCS11Error(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
	}
	if userType == CKU_SO && m.roSessionCount.Load() > 0 {
		return NewPKCS11Error(CKR_SESSION_READ_ONLY_EXISTS)
	}

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

// finishPINVerification runs the Argon2id derivation and records the outcome.
// It must be called WITHOUT m.mu held: that is the entire point of the split.
//
// The attempt counters are atomics and saveAttempts writes through the storage
// callback, neither of which needs the session lock.
func (m *SessionManager) finishPINVerification(plan *pinVerificationPlan, pin []byte) error {
	if !verifyPin(plan.verifier, string(pin)) {
		return m.recordFailedAttempt(plan.userType, plan.attempts)
	}
	if plan.attempts != nil {
		plan.attempts.Store(0)
		m.reconcileReset(plan.userType)
	}
	return nil
}

// MaxPINAttempts is the number of consecutive failed authentication attempts
// after which a PIN locks. PKCS#11 PINs are short, so an online guessing attack
// must be bounded rather than merely slowed.
const MaxPINAttempts = 3

// contextAuthOperations lists the operation categories that can require
// re-authentication for a key carrying CKA_ALWAYS_AUTHENTICATE.
var contextAuthOperations = map[OperationType]bool{
	OperationSign:    true,
	OperationDecrypt: true,
}

// pinVerificationPlan carries what the expensive half of PIN validation needs,
// snapshotted while the lock is held.
type pinVerificationPlan struct {
	// verifier is a COPY of the stored Argon2id verifier, so the derivation can
	// run after the lock is released without racing a concurrent C_SetPIN.
	verifier []byte

	// attempts is the failed-attempt counter for this user type. It is an
	// atomic, so it is safe to touch from either side of the lock.
	attempts *atomic.Uint32

	// userType names the counter attempts refers to, so the durable-storage
	// reconcile (increment on failure, reset on success) can address the right
	// per-token counter key.
	userType UserType
}

// preparePINVerificationLocked does the cheap part of PIN validation and returns
// what the expensive part needs. The caller must hold m.mu.
//
// A non-nil second return means the answer is already settled and no derivation
// should run.
//
// The split exists because verifyPin is deliberately expensive: it queues on a
// bounded admission gate and then runs a 64 MiB Argon2id derivation. Doing that
// under the session write lock meant one caller's WRONG PIN stalled every
// C_OpenSession, C_CloseSession and C_Login on the token for the duration --
// and an attacker needs no valid PIN to trigger it, since a wrong guess costs
// exactly the same derivation.
func (m *SessionManager) preparePINVerificationLocked(userType UserType, pin []byte) (*pinVerificationPlan, error) {
	attempts := m.attemptCounter(userType)
	if attempts != nil && attempts.Load() >= MaxPINAttempts {
		return nil, NewPKCS11Error(CKR_PIN_LOCKED)
	}

	var storedPINHash []byte
	switch userType {
	case CKU_SO:
		storedPINHash = m.soPIN
	case CKU_USER:
		storedPINHash = m.userPIN
	default:
		return nil, NewPKCS11Error(CKR_USER_TYPE_INVALID)
	}

	// Whether a PIN exists at all is decided before any attempt is counted. A
	// token with no verifier cannot be authenticated to by any PIN, so charging
	// the attempt would let three logins lock a PIN that was never established
	// -- and C_InitPIN, the call meant to establish it, does not clear the
	// counter. The answer is the one v3.2 §5.6.8 names for this state, which
	// OpenSC branches on to prompt the SO.
	//
	// The test is on length rather than on nil so that a zero-length verifier
	// reaching this point from any source is treated the same way.
	if len(storedPINHash) == 0 {
		return nil, NewPKCS11Error(CKR_USER_PIN_NOT_INITIALIZED)
	}

	// An empty PIN supplied against a token that does have a verifier is a
	// genuine wrong guess, so it is counted as one. This is not the NULL pPin
	// case: C_Login rejects that at the ABI boundary with CKR_ARGUMENTS_BAD,
	// because v3.2 §5.6.8 gives NULL a meaning only for a token with a protected
	// authentication path, which this token does not advertise.
	if len(pin) == 0 {
		return nil, m.recordFailedAttempt(userType, attempts)
	}

	// The verifier is copied out. It carries its own salt, so it cannot be
	// checked by re-hashing and comparing bytes -- the derivation has to run,
	// and it runs against this copy after the lock is released.
	verifier := make([]byte, len(storedPINHash))
	copy(verifier, storedPINHash)

	return &pinVerificationPlan{verifier: verifier, attempts: attempts, userType: userType}, nil
}

// attemptCounter returns the failed-attempt counter for a user type, or nil for
// a user type that has none.
func (m *SessionManager) attemptCounter(userType UserType) *atomic.Uint32 {
	switch userType {
	case CKU_SO:
		return &m.failedSOPIN
	case CKU_USER:
		return &m.failedUserPIN
	default:
		return nil
	}
}

// recordFailedAttempt increments the failure counter and reports whether the
// PIN has now locked. The increment is reconciled with durable storage before
// returning, so the attempt is spent even if the process does not survive to
// answer — and, for a shared remote token, so a concurrent client's failures are
// counted against the same budget rather than lost.
func (m *SessionManager) recordFailedAttempt(userType UserType, attempts *atomic.Uint32) error {
	if attempts == nil {
		return NewPKCS11Error(CKR_PIN_INCORRECT)
	}

	// The durable counter is authoritative: its post-increment value, not the
	// local guess, decides the lockout. When there is no durable backend (or the
	// reconcile fails) the local atomic is advanced instead, preserving the
	// in-memory-only behavior a store-less module has always had.
	var count uint32
	if m.incrementAttempt != nil {
		if authoritative, persisted := m.incrementAttempt(userType); persisted {
			attempts.Store(authoritative)
			count = authoritative
		} else {
			count = attempts.Add(1)
		}
	} else {
		count = attempts.Add(1)
	}

	if count >= MaxPINAttempts {
		return NewPKCS11Error(CKR_PIN_LOCKED)
	}
	return NewPKCS11Error(CKR_PIN_INCORRECT)
}

// ResetPINAttempts clears the failed-attempt counter for a user type. It is
// called when a PIN is set or reset by an authorized party.
func (m *SessionManager) ResetPINAttempts(userType UserType) {
	if attempts := m.attemptCounter(userType); attempts != nil {
		attempts.Store(0)
		m.reconcileReset(userType)
	}
}

// VerifyPINForChange checks an old PIN offered to C_SetPIN against the same
// lockout accounting C_Login uses, and reports the CK_RV to return.
//
// It exists because proving the old PIN is an authentication, whatever function
// it happens under. C_SetPIN verified it directly against the token, outside the
// counter, which left an unbounded oracle: an attacker repeats
// C_SetPIN(wrongOld, anything) forever and gets CKR_PIN_INCORRECT each time,
// while three C_Login attempts would have locked the token. v3.2 §5.5.9 lists
// CKR_PIN_LOCKED among C_SetPIN's own return values, so the spec expects this
// path to be able to lock.
//
// A successful check clears the counter, exactly as a successful login does.
//
// The result is translated into C_SetPIN's own vocabulary. validatePINLocked
// answers in C_Login's, and the two return tables differ:
// CKR_USER_PIN_NOT_INITIALIZED is listed for C_Login (§5.6.8) and not for
// C_SetPIN (§5.5.9), where an old PIN that matches a verifier which does not
// exist is simply incorrect. That case is also not charged to the lockout --
// there is nothing to guess, so an attempt reveals nothing and must not be able
// to lock a token before its PIN has been provisioned.
func (m *SessionManager) VerifyPINForChange(userType UserType, oldPin []byte) error {
	// Snapshot the verifier under the lock, then run the Argon2id derivation
	// with it released — the same split the login path uses. C_SetPIN is
	// authenticated and infrequent, so this is not the DoS the login fix
	// addressed, but there is no reason to hold the read lock across a
	// deliberately slow KDF and stall every other reader of this token.
	m.mu.RLock()
	plan, decided := m.preparePINVerificationLocked(userType, oldPin)
	m.mu.RUnlock()

	err := decided
	if err == nil {
		err = m.finishPINVerification(plan, oldPin)
	}

	var pkcsErr *PKCS11Error
	if errors.As(err, &pkcsErr) && pkcsErr.Code == CKR_USER_PIN_NOT_INITIALIZED {
		return NewPKCS11Error(CKR_PIN_INCORRECT)
	}
	return err
}

// SetAttemptPersistence installs the callbacks that reconcile the failed-attempt
// counters with durable storage: increment on a failure, reset on a success or
// PIN change. increment returns the authoritative post-increment value and
// whether it was persisted; reset best-effort clears the durable counter. Both
// are addressed by user type so they reach the right per-token counter key.
func (m *SessionManager) SetAttemptPersistence(increment func(userType UserType) (uint32, bool), reset func(userType UserType)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incrementAttempt = increment
	m.resetAttempt = reset
}

// PINAttempts returns the current failed-attempt counters, for persistence.
func (m *SessionManager) PINAttempts() (user, so uint32) {
	return m.failedUserPIN.Load(), m.failedSOPIN.Load()
}

// RestorePINAttempts reinstates counters loaded from durable storage, so a
// token that was locked before a restart is still locked after it.
func (m *SessionManager) RestorePINAttempts(user, so uint32) {
	m.failedUserPIN.Store(user)
	m.failedSOPIN.Store(so)
}

// reconcileReset invokes the reset callback, if one is installed.
//
// The callback is read without taking m.mu: recordFailedAttempt and the success
// path run on the authentication path, which already holds the lock for reading,
// and taking it again here would deadlock. Installation happens once during
// Initialize, before any session exists to authenticate.
func (m *SessionManager) reconcileReset(userType UserType) {
	if m.resetAttempt != nil {
		m.resetAttempt(userType)
	}
}

// PINAttemptStatus reports the failed-attempt count and lock state for a user
// type, so the token can publish the CKF_*_PIN_COUNT_LOW, CKF_*_PIN_FINAL_TRY
// and CKF_*_PIN_LOCKED flags in CK_TOKEN_INFO.
func (m *SessionManager) PINAttemptStatus(userType UserType) (failed uint32, locked bool) {
	attempts := m.attemptCounter(userType)
	if attempts == nil {
		return 0, false
	}
	failed = attempts.Load()
	return failed, failed >= MaxPINAttempts
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
// ForEachSession invokes fn for the handle of every open session managed by
// this slot.
func (m *SessionManager) ForEachSession(fn func(handle SessionHandle)) {
	m.sessions.ForEach(func(handle uint64, session *Session) bool {
		if m.ownsSession(session) {
			fn(SessionHandle(handle))
		}
		return true
	})
}

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
