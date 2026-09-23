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

// Package module provides the core PKCS#11 (Cryptoki) v3.2 module implementation.
//
// This file implements the main Module struct that orchestrates all PKCS#11 operations
// by coordinating the SlotManager, SessionManager, ObjectManager, and CryptoManager
// components. It connects to the go-xkms backend via the SDK transport client.
//
// Per PKCS#11 specification, there is a single global module instance that must be
// initialized before use and finalized when done.
//
// v3.2 additions include KEM operations, authenticated wrapping, signature-first
// verification, async operations, and standardized PQC mechanisms (ML-DSA, ML-KEM,
// SLH-DSA, HSS, XMSS).
//
// References:
//   - OASIS PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package module

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/grpc"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/quic"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/unix"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	"github.com/jeremyhahn/go-enclave"
)

// CK_INFO represents the PKCS#11 library information structure.
// Returned by C_GetInfo to provide information about the Cryptoki library.
type CK_INFO struct {
	// CryptokiVersion is the Cryptoki interface version number.
	CryptokiVersion Version

	// ManufacturerID identifies the manufacturer of the library.
	// Padded with spaces to 32 characters per PKCS#11 spec.
	ManufacturerID [32]byte

	// Flags is reserved for future use (must be zero).
	Flags uint64

	// LibraryDescription describes the library.
	// Padded with spaces to 32 characters per PKCS#11 spec.
	LibraryDescription [32]byte

	// LibraryVersion is the library version number.
	LibraryVersion Version
}

// GetManufacturerID returns the manufacturer ID as a trimmed string.
func (i *CK_INFO) GetManufacturerID() string {
	return infoTrimPaddedString(i.ManufacturerID[:])
}

// SetManufacturerID sets the manufacturer ID, padding with spaces.
func (i *CK_INFO) SetManufacturerID(id string) {
	infoSetPaddedString(i.ManufacturerID[:], id)
}

// GetLibraryDescription returns the library description as a trimmed string.
func (i *CK_INFO) GetLibraryDescription() string {
	return infoTrimPaddedString(i.LibraryDescription[:])
}

// SetLibraryDescription sets the library description, padding with spaces.
func (i *CK_INFO) SetLibraryDescription(desc string) {
	infoSetPaddedString(i.LibraryDescription[:], desc)
}

// CK_INTERFACE represents a PKCS#11 v3.0 interface.
// An interface is a named collection of functions that a library provides.
type CK_INTERFACE struct {
	// Name is the name of the interface (e.g., "PKCS 11")
	Name string

	// FunctionList is a pointer to the function list for this interface.
	// For v3.0, this points to CK_FUNCTION_LIST_3_0.
	//
	// It is always nil in this package. The function list is a table of C
	// function pointers into the shared library, which only exists once the
	// module is built with buildmode=c-shared; this package is pure Go and has
	// nothing to point at. cmd/pkcs11-module builds the real tables and its
	// C_GetInterface / C_GetInterfaceList exports are authoritative — they
	// return three interfaces (v2.40, v3.0 and v3.2), each with a non-NULL
	// pFunctionList as the spec requires. Anything asserting the spec's
	// non-NULL rule must go through the shared library, not through here.
	FunctionList interface{}

	// Flags contains interface flags.
	Flags uint64
}

// Interface flag constants for PKCS#11 v3.0.
const (
	// CKF_INTERFACE_FORK_SAFE indicates the interface is fork-safe.
	CKF_INTERFACE_FORK_SAFE uint64 = 0x00000001
)

// Standard interface names.
const (
	// InterfaceNamePKCS11 is the standard PKCS#11 interface name.
	InterfaceNamePKCS11 = "PKCS 11"
)

// Cryptoki version constants.
// This module implements PKCS#11 v3.0.
const (
	// CryptokiVersionMajor is the major version of the Cryptoki interface.
	CryptokiVersionMajor = 3
	// CryptokiVersionMinor is the minor version of the Cryptoki interface.
	CryptokiVersionMinor = 2
)

// Module represents the PKCS#11 Cryptoki module.
// It manages the lifecycle of all PKCS#11 operations and coordinates
// between slots, sessions, objects, and cryptographic operations.
type Module struct {
	// initialized indicates whether the module has been initialized.
	// Uses atomic operations for lock-free access.
	initialized atomic.Bool

	// config holds the module configuration.
	config *Config

	// client is the transport client for backend communication.
	// Uses the minimal PKCS11Transport interface (15 methods) rather than
	// the full transport.Client (116 methods).
	client PKCS11Transport

	// slotManager manages slots and tokens.
	slotManager *SlotManager

	// sessionManagers maps slot IDs to their session managers.
	// Each slot has its own session manager per PKCS#11 spec.
	sessionManagers map[SlotID]*SessionManager

	// sessionHandles is the single flat CK_SESSION_HANDLE namespace shared by
	// every slot's session manager (v3.2 §3.3). It is held here so that any
	// manager created after Initialize — e.g. the OpenSession fallback — draws
	// from the same table rather than a private counter that would restart at 1
	// and hand out colliding handles across slots.
	sessionHandles *HandleTable[*Session]

	// sealController, when injected via WithSealController, is the at-rest
	// barrier for the token's private key material. The module unseals it with
	// the user PIN at C_Login(CKU_USER) and reseals at C_Logout / C_Finalize.
	// Nil means no module-driven sealing (see SealController).
	sealController SealController

	// objectManager manages PKCS#11 objects (keys, certificates, data).
	objectManager *ObjectManager

	// cryptoManager handles cryptographic operations.
	cryptoManager *CryptoManager

	// storage provides persistent storage for token and object state.
	storage *ModuleStorage

	// info contains the library information returned by GetInfo.
	info CK_INFO

	// interfaces contains the list of supported PKCS#11 interfaces.
	// For v3.0 compliance, we support the standard "PKCS 11" interface.
	interfaces []CK_INTERFACE

	// quantumCrypto holds the QuantumCryptoManager when built with "quantum" tag.
	// Stored as any to avoid build-tag type mismatch; type-assert to
	// *QuantumCryptoManager in quantum-gated code paths.
	quantumCrypto any

	// mu protects complex state modifications.
	mu sync.RWMutex

	// keyCounter is used to generate unique key IDs for symmetric keys.
	keyCounter atomic.Uint64

	// lastStorageError records the most recent persistence failure. Persistence
	// is best-effort on paths that must complete regardless — C_InitToken must
	// still initialize the token if the store is unavailable — but the failure
	// is recorded rather than discarded so operators can see it.
	lastStorageError atomic.Value
}

// storageFailure describes a persistence error and the operation that hit it.
type storageFailure struct {
	Operation string
	Err       error
}

// Error implements the error interface.
func (f storageFailure) Error() string {
	return f.Operation + ": " + f.Err.Error()
}

// Unwrap exposes the underlying error for errors.Is and errors.As.
func (f storageFailure) Unwrap() error {
	return f.Err
}

// logStorageError records a best-effort persistence failure.
func (m *Module) logStorageError(operation string, err error) {
	if err == nil {
		return
	}
	m.lastStorageError.Store(storageFailure{Operation: operation, Err: err})
}

// recordStorageError records a persistence failure the way logStorageError does
// and also returns it, for the callers that must fail the Cryptoki call they are
// serving rather than continue past the failure.
//
// A nil error is not a failure and is returned unchanged, so a call that may
// have succeeded can be wrapped directly.
func (m *Module) recordStorageError(operation string, err error) error {
	if err == nil {
		return nil
	}
	m.logStorageError(operation, err)
	return storageFailure{Operation: operation, Err: err}
}

// LastStorageError returns the most recent best-effort persistence failure, or
// nil if every persistence attempt has succeeded.
func (m *Module) LastStorageError() error {
	if failure, ok := m.lastStorageError.Load().(storageFailure); ok {
		return failure
	}
	return nil
}

// Global module instance and initialization synchronization.
var (
	globalModule   *Module
	globalModuleMu sync.Mutex
)

// ModuleOption is a function that configures the module.
type ModuleOption func(*Module) error

// WithConfig sets the module configuration.
func WithConfig(cfg *Config) ModuleOption {
	return func(m *Module) error {
		m.config = cfg
		return nil
	}
}

// WithClient sets a custom transport client.
// Accepts any PKCS11Transport implementation, including transport.Client.
func WithClient(client PKCS11Transport) ModuleOption {
	return func(m *Module) error {
		m.client = client
		return nil
	}
}

// WithStorage sets a custom storage backend.
func WithStorage(backend storage.Backend) ModuleOption {
	return func(m *Module) error {
		m.storage = NewModuleStorage(backend)
		return nil
	}
}

// New creates a new Module instance.
// This does not initialize the module; call Initialize for that.
func New(opts ...ModuleOption) (*Module, error) {
	m := &Module{
		sessionManagers: make(map[SlotID]*SessionManager),
		info: CK_INFO{
			CryptokiVersion: Version{Major: CryptokiVersionMajor, Minor: CryptokiVersionMinor},
			Flags:           0,
			LibraryVersion:  Version{Major: 1, Minor: 0},
		},
	}

	m.info.SetManufacturerID("go-xkms")
	m.info.SetLibraryDescription(moduleLibraryDescription())

	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// GetGlobalModule returns the global module instance.
// Creates a new uninitialized module if none exists.
func GetGlobalModule() *Module {
	globalModuleMu.Lock()
	defer globalModuleMu.Unlock()

	if globalModule == nil {
		globalModule = &Module{
			sessionManagers: make(map[SlotID]*SessionManager),
			info: CK_INFO{
				CryptokiVersion: Version{Major: CryptokiVersionMajor, Minor: CryptokiVersionMinor},
				Flags:           0,
				LibraryVersion:  Version{Major: 1, Minor: 0},
			},
		}
		globalModule.info.SetManufacturerID("go-xkms")
		globalModule.info.SetLibraryDescription(moduleLibraryDescription())
	}

	return globalModule
}

// HasGlobalModule reports whether a global module has been installed, without
// creating one. Unlike GetGlobalModule it never lazily constructs the default
// module, so a composition root can decide whether to install a custom module
// (e.g. an offline embedded one) before the default path runs.
func HasGlobalModule() bool {
	globalModuleMu.Lock()
	defer globalModuleMu.Unlock()
	return globalModule != nil
}

// SetGlobalModule sets the global module instance.
// Used for testing or custom module configurations.
func SetGlobalModule(m *Module) {
	globalModuleMu.Lock()
	defer globalModuleMu.Unlock()
	globalModule = m
}

// ResetGlobalModule resets the global module instance.
// Used primarily for testing.
func ResetGlobalModule() {
	globalModuleMu.Lock()
	defer globalModuleMu.Unlock()
	if globalModule != nil {
		globalModule.Finalize()
	}
	globalModule = nil
}

// Initialize initializes the PKCS#11 module.
// Must be called before any other PKCS#11 operations.
// Implements C_Initialize behavior per PKCS#11 specification.
func (m *Module) Initialize(config *Config) CK_RV {
	// Check if already initialized
	if m.initialized.Load() {
		return CKR_CRYPTOKI_ALREADY_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring lock
	if m.initialized.Load() {
		return CKR_CRYPTOKI_ALREADY_INITIALIZED
	}

	// Use provided config or load default. A configuration that cannot be
	// loaded or does not validate is fatal: silently falling back to defaults
	// would replace an operator's intended endpoint and transport security with
	// something weaker, which is exactly the failure a misconfigured deployment
	// must not have hidden from it.
	if config != nil {
		m.config = config
	} else if m.config == nil {
		loaded, err := Load()
		if err != nil {
			return CKR_GENERAL_ERROR
		}
		m.config = loaded
	}

	// Validate() is specified to run against a fully-defaulted configuration, so
	// a caller that constructed a Config directly gets its zero-valued fields
	// filled in first rather than failing validation on fields it never set.
	m.config.SetDefaults()
	if err := m.config.Validate(); err != nil {
		return CKR_GENERAL_ERROR
	}

	// Initialize transport client if not already set
	if m.client == nil {
		if err := m.initializeClient(); err != nil {
			return CKR_DEVICE_ERROR
		}
	}

	// Connect to the backend
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	if err := m.client.Connect(ctx); err != nil {
		return CKR_DEVICE_ERROR
	}

	// Determine the default backend from config
	defaultBackend := m.config.DefaultBackend
	if defaultBackend == "" {
		defaultBackend = DefaultBackend
	}

	// Initialize storage if not already set
	if m.storage == nil {
		if err := m.initializeStorage(); err != nil {
			return CKR_DEVICE_ERROR
		}
	}

	// Initialize managers
	m.slotManager = NewSlotManager()
	m.objectManager = NewObjectManager()
	m.cryptoManager = NewCryptoManager(m.client, &CryptoManagerConfig{
		DefaultBackend: defaultBackend,
	})

	// One handle table for every slot. CK_SESSION_HANDLE is a single flat
	// namespace across the library, so per-slot counters would each start at 1
	// and hand out colliding handles; see NewSessionManagerWithTable.
	slotIDs := m.slotManager.GetSlotList(false)
	sessionHandles := NewHandleTable[*Session]()
	m.sessionHandles = sessionHandles
	for _, slotID := range slotIDs {
		sm := NewSessionManagerWithTable(uint64(slotID), 0, sessionHandles)
		// Every change to a lockout counter is reconciled with the store, so the
		// budget an attacker has spent survives C_Finalize and a restart — and so
		// that several remote-mode clients sharing one token count their failures
		// against one authoritative counter. The slot is captured per iteration
		// because the callbacks outlive it.
		slot := slotID
		sm.SetAttemptPersistence(
			func(userType UserType) (uint32, bool) {
				value, persisted, err := m.storage.IncrementFailedAttempt(slot, userType)
				if err != nil {
					m.logStorageError("persist PIN lockout increment", err)
					return 0, false
				}
				return value, persisted
			},
			func(userType UserType) {
				if err := m.storage.ResetFailedAttempt(slot, userType); err != nil {
					m.logStorageError("persist PIN lockout reset", err)
				}
			},
		)
		m.sessionManagers[slotID] = sm
	}

	// Load persisted state
	if rv := m.loadPersistedState(); rv != CKR_OK {
		// Log warning but continue - persistence failure shouldn't prevent operation
		_ = rv
	}

	// Initialize v3.0 interfaces
	m.interfaces = []CK_INTERFACE{
		{
			Name:         InterfaceNamePKCS11,
			FunctionList: nil, // Function list is provided via C_GetFunctionList
			Flags:        0,
		},
	}

	// Initialize quantum crypto manager (non-nil only with "quantum" build tag)
	m.quantumCrypto = getQuantumCryptoManager()

	m.initialized.Store(true)

	// Perform auto-initialization if configured
	if m.config.AutoInitToken && m.config.SOPIN != "" {
		if rv := m.autoInitializeToken(); rv != CKR_OK {
			// Log warning but don't fail initialization
			// Token can still be initialized manually
			_ = rv // auto-init is best effort
		}
	}

	// Load PIV objects for configured backends.
	// This creates PKCS#11 certificate, public key, and private key objects
	// for each occupied PIV slot in the configured backends.
	if len(m.config.PIVBackends) > 0 {
		pivCtx, pivCancel := context.WithTimeout(context.Background(), m.config.Timeout)
		defer pivCancel()
		for _, backend := range m.config.PIVBackends {
			_ = m.LoadPIVObjects(pivCtx, backend) // best effort
		}
	}

	return CKR_OK
}

// autoInitializeToken initializes the token with SO PIN and user PIN from config.
// This is useful for testing and development environments where manual token
// initialization is impractical (e.g., when pkcs11-tool restarts the library).
// NOTE: This only initializes if the token is not already initialized.
// It will NOT overwrite PINs that were set via C_InitPIN or C_SetPIN.
func (m *Module) autoInitializeToken() CK_RV {
	// Get default slot
	slotIDs := m.slotManager.GetSlotList(true)
	if len(slotIDs) == 0 {
		return CKR_SLOT_ID_INVALID
	}
	slotID := slotIDs[0]

	// Initialize the token directly (we already hold the lock from Initialize)
	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return CKR_SLOT_ID_INVALID
	}

	if slot.Token == nil {
		return CKR_TOKEN_NOT_PRESENT
	}

	// Skip if token is already initialized (e.g., from persistence)
	// This prevents overwriting PINs that were changed via C_SetPIN
	if slot.Token.Initialized {
		return CKR_OK
	}

	// Initialize token with SO PIN
	label := m.config.TokenLabel
	if label == "" {
		label = "XKMSToken"
	}

	// Initialize the token
	if err := slot.Token.SetSOPin(m.config.SOPIN); err != nil {
		m.logStorageError("hash SO PIN during auto-init", err)
		return CKR_DEVICE_ERROR
	}
	slot.Token.Info.SetLabel(label)
	// A token identifies itself by serial in every PKCS#11 URI, so auto-init
	// mints one exactly as C_InitToken does. Setting only the label left the
	// serial as sixteen NUL bytes for the token's whole life, and every
	// integration target that sets XKMS_PKCS11_AUTO_INIT_TOKEN=true runs against
	// that token -- so nothing in the suite ever observed a real one.
	if slot.Token.Info.GetSerialNumber() == "" {
		serial, err := generateSerialNumber()
		if err != nil {
			m.logStorageError("mint token serial during auto-init", err)
			return CKR_DEVICE_ERROR
		}
		slot.Token.Info.SetSerialNumber(serial)
	}
	slot.Token.Info.Flags |= CKF_TOKEN_INITIALIZED
	slot.Token.Initialized = true

	// Set SO PIN hash in session manager
	if sm, ok := m.sessionManagers[slotID]; ok {
		soHash, err := hashPin(m.config.SOPIN)
		if err != nil {
			m.logStorageError("hash SO PIN during auto-init", err)
			return CKR_DEVICE_ERROR
		}
		sm.SetSOPIN(soHash)
	}

	// If user PIN is provided, initialize it too
	if m.config.UserPIN != "" {
		// Set user PIN directly on token
		if err := slot.Token.SetUserPin(m.config.UserPIN); err != nil {
			m.logStorageError("hash user PIN during auto-init", err)
			return CKR_DEVICE_ERROR
		}
		slot.Token.Info.Flags |= CKF_USER_PIN_INITIALIZED

		// Set user PIN hash in session manager
		if sm, ok := m.sessionManagers[slotID]; ok {
			userHash, err := hashPin(m.config.UserPIN)
			if err != nil {
				m.logStorageError("hash user PIN during auto-init", err)
				return CKR_DEVICE_ERROR
			}
			sm.SetUserPIN(userHash)
		}
	}

	// Persist the token state this function just established.
	//
	// Unlike C_InitToken, a failure here is recorded rather than returned.
	// Auto-initialization is driven by the module configuration, which is read
	// again on every C_Initialize, so a token whose state did not reach the
	// store is rebuilt from the same source next time; refusing to initialize
	// would deny service for a condition that repairs itself.
	//
	// It is still not nothing. Discarding the error left no trace of a store
	// that had stopped accepting writes, and the counters that drive
	// CKR_PIN_LOCKED travel this same path once the token is in use -- a silent
	// failure there is a lockout that does not survive a restart. Recording it
	// puts the failure behind LastStorageError, where every other best-effort
	// persistence failure in this module reports.
	m.logStorageError("persist token state during auto-initialization", m.saveTokenState(slotID))

	return CKR_OK
}

// initializeStorage creates the storage backend based on configuration.
func (m *Module) initializeStorage() error {
	var backend storage.Backend
	var err error

	switch m.config.StorageType {
	case StorageTypeFile:
		backend, err = file.New(m.config.StoragePath)
		if err != nil {
			return &errs.Detail{Err: ErrStorageInit, Detail: fmt.Sprintf("%v", err)}
		}
	case StorageTypeMemory, "":
		backend = storage.NewMemory()
	case StorageTypeRemote:
		// Remote mode keeps no local on-disk state: the module's token and
		// object records live in xkmsd over the active transport. m.client was
		// built by initializeClient (which runs first) and must carry the
		// PKCS#11-state RPCs — gRPC and Unix do.
		stateClient, ok := m.client.(PKCS11StateClient)
		if !ok {
			return &errs.Detail{Err: ErrRemoteClientUnsupported, Detail: m.config.Target}
		}
		backend, err = newRemoteBackend(stateClient, m.config.TenantID, m.config.TokenLabel)
		if err != nil {
			return &errs.Detail{Err: ErrStorageInit, Detail: fmt.Sprintf("%v", err)}
		}
	default:
		return &errs.Detail{Err: ErrInvalidStorageType, Detail: m.config.StorageType}
	}

	m.storage = NewModuleStorage(backend)
	return nil
}

// loadPersistedState loads token and object state from storage.
func (m *Module) loadPersistedState() CK_RV {
	if m.storage == nil {
		return CKR_OK
	}

	// Load token state for each slot
	for _, slotID := range m.slotManager.GetSlotList(false) {
		state, err := m.storage.LoadTokenState(slotID)
		if err != nil {
			// A genuinely-absent record is (nil, nil); an error here means the
			// record exists but is unreadable or corrupt. That record holds the
			// PIN hashes and the failed-attempt budget, so silently skipping it
			// would bring the token up with no PIN and a reset lockout counter —
			// exactly what an attacker who could corrupt the file would want.
			// Fail closed with CKR_DEVICE_ERROR (§5.1.6) instead.
			m.logStorageError("load persisted token state", err)
			return CKR_DEVICE_ERROR
		}
		if state == nil {
			continue // No persisted state for this slot
		}

		slot, err := m.slotManager.GetSlot(slotID)
		if err != nil || slot.Token == nil {
			continue
		}

		// Restore token state
		RestoreTokenState(slot.Token, state)

		// Update session manager with PIN hashes
		if sm, ok := m.sessionManagers[slotID]; ok {
			if len(state.SOPinHash) > 0 {
				sm.SetSOPIN(state.SOPinHash)
			}
			if len(state.UserPinHash) > 0 {
				sm.SetUserPIN(state.UserPinHash)
			}
			// The verifier and the budget for guessing it are restored together.
			// Reloading one without the other is what let C_Finalize followed by
			// C_Initialize hand an attacker three fresh attempts, indefinitely.
			//
			// The authoritative counters live in dedicated storage keys, so several
			// remote-mode clients can increment them atomically; the record's
			// embedded fields are a snapshot for operators inspecting the record,
			// not a source LoadFailedAttempts reads from.
			failedUser, failedSO, err := m.storage.LoadFailedAttempts(slotID)
			if err != nil {
				m.logStorageError("load persisted lockout counters", err)
				return CKR_DEVICE_ERROR
			}
			sm.RestorePINAttempts(failedUser, failedSO)
		}

		// Load objects for this slot. An error means the object store could not
		// be enumerated or a record would not read back — the token would come
		// up silently missing keys it is supposed to hold, so refuse rather
		// than present an incomplete token as if it were whole.
		objects, err := m.storage.LoadObjects(slotID)
		if err != nil {
			m.logStorageError("load persisted objects", err)
			return CKR_DEVICE_ERROR
		}

		// Find the maximum handle to set the next handle counter
		var maxHandle ObjectHandle
		for _, po := range objects {
			obj := RestoreObject(po)
			// RestoreObject carries the slot the object was persisted under,
			// but pin it to the slot actually being restored so a corrupted or
			// mislabelled record cannot graft an object onto another token.
			obj.SlotID = slotID
			if err := m.objectManager.AddObject(obj); err != nil {
				m.logStorageError("restore persisted object", err)
				continue
			}
			if obj.Handle > maxHandle {
				maxHandle = obj.Handle
			}
		}

		// Update handle counter to avoid conflicts
		if maxHandle > 0 {
			m.objectManager.SetNextHandle(maxHandle + 1)
		}
	}

	return CKR_OK
}

// saveTokenState persists the token state to storage.
func (m *Module) saveTokenState(slotID SlotID) error {
	if m.storage == nil {
		return nil
	}

	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil || slot.Token == nil {
		return nil
	}

	// The lockout counters are written with the rest of the token's state, so a
	// PIN that has run out of attempts is still out of attempts after a restart.
	var failedUser, failedSO uint32
	if sm, ok := m.sessionManagers[slotID]; ok {
		failedUser, failedSO = sm.PINAttempts()
	}

	return m.storage.SaveTokenState(slotID, slot.Token, failedUser, failedSO)
}

// persistObjectIfToken writes a token object through to the module's store and
// reports a write that did not happen.
//
// PKCS#11 v3.2 §4.4 defines a token object as one that "remains on the token
// until specifically destroyed", so an object whose CKA_TOKEN is CK_TRUE is not
// really on the token until the store holds it. Two outcomes are not failures
// and return nil: a module configured without a store, and a session object.
// Neither is supposed to reach storage.
//
// Every other outcome is returned. Discarding the write error instead — which
// this function used to do — let every caller answer CKR_OK for an object the
// next process start would not find, which is indistinguishable to the
// application from a token that kept it. The failure is recorded through
// LastStorageError as well, so an operator whose store has gone away sees the
// cause and not only the CK_RV the application saw.
func (m *Module) persistObjectIfToken(handle ObjectHandle, sessionHandle SessionHandle) error {
	if m.storage == nil {
		return nil
	}

	obj, err := m.objectManager.getObjectUnchecked(handle)
	if err != nil {
		return m.recordStorageError("look up object to persist", err)
	}
	if !obj.IsToken {
		return nil
	}

	// Find the slot ID from the session
	slotID, err := m.getSlotIDFromSession(sessionHandle)
	if err != nil {
		return m.recordStorageError("resolve slot of object to persist", err)
	}

	// Persist the object
	return m.recordStorageError("persist token object", m.storage.SaveObject(slotID, obj))
}

// persistNewObject persists a newly created token object and, when the store
// refuses it, destroys the object again.
//
// A creation function either places an object on the token or does not. An
// application that receives an error code is given no handle and so has nothing
// to clean up with, and an object left behind in the module's memory would be
// findable through C_FindObjects for the life of the process and absent from
// the next one — the same divergence between what the token reports and what it
// holds that failing the call exists to prevent. The rollback is the one these
// paths already perform when a later step fails.
//
// A rollback that cannot itself complete — CKA_DESTROYABLE is CK_FALSE, say — is
// recorded rather than returned, because the storage failure is the one the
// caller has to act on.
func (m *Module) persistNewObject(access AccessContext, handle ObjectHandle, sessionHandle SessionHandle) error {
	err := m.persistObjectIfToken(handle, sessionHandle)
	if err == nil {
		return nil
	}

	if destroyErr := m.objectManager.DestroyObject(access, handle); destroyErr != nil {
		m.logStorageError("destroy object left behind by a failed persist", destroyErr)
	}

	return err
}

// getSlotIDFromSession returns the slot ID for a given session.
func (m *Module) getSlotIDFromSession(sessionHandle SessionHandle) (SlotID, error) {
	for slotID, sm := range m.sessionManagers {
		if session, _ := sm.GetSession(sessionHandle); session != nil {
			return slotID, nil
		}
	}
	return 0, &errs.Message{Msg: "session not found"}
}

// initializeClient creates and configures the transport client based on the target format.
// Supported formats:
//   - unix:///path/to/socket: Unix domain socket (uses unix transport)
//   - dns:///host:port: DNS-based TCP connection (uses gRPC transport)
//   - host:port: Direct TCP connection (uses gRPC transport)
func (m *Module) initializeClient() error {
	target := m.config.Target

	// Unix socket format: unix:///path/to/socket
	if strings.HasPrefix(target, "unix://") {
		socketPath := strings.TrimPrefix(target, "unix://")
		client, err := unix.New(transport.WithAddress(socketPath))
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create unix transport", Err: err}
		}
		m.client = client
		return nil
	}

	// DNS format: dns:///host:port - use gRPC transport
	if strings.HasPrefix(target, "dns://") {
		addr := strings.TrimPrefix(target, "dns://")
		addr = strings.TrimPrefix(addr, "/")
		client, err := m.createGRPCClient(addr)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create gRPC transport for dns target", Err: err}
		}
		m.client = client
		return nil
	}

	// REST format: rest://host:port. The module cannot construct a REST client
	// itself: pkg/api/transport/rest is imported (transitively via pkg/auth,
	// which this module backs for PKCS#11 TLS) by pkg/api/rest, whose tests
	// import back into transport/rest, so a module→transport/rest edge would
	// close an import cycle. A REST client is therefore built by the composition
	// root (cmd/pkcs11-module or xkey, which import transport/rest freely) and
	// injected via module.WithClient — which skips this path entirely. Reaching
	// here means a rest:// target was set without injecting a client.
	if strings.HasPrefix(target, "rest://") {
		return &errs.Detail{Err: ErrRESTClientMustBeInjected, Detail: target}
	}

	// QUIC format: quic://host:port
	if strings.HasPrefix(target, "quic://") {
		addr := strings.TrimPrefix(target, "quic://")
		client, err := m.createQUICClient(addr)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create QUIC transport", Err: err}
		}
		m.client = client
		return nil
	}

	// MCP is an AI/LLM-oriented transport, not a crypto data plane, so the
	// module refuses to construct an MCP client at all rather than dial one.
	// validateTarget rejects it earlier; this is defense in depth so an
	// mcp:// target can never fall through to the unix-path default below.
	if strings.HasPrefix(target, "mcp://") {
		return &errs.Detail{Err: ErrMCPTargetNotSupported, Detail: target}
	}

	// Direct host:port format - use gRPC transport
	if strings.Contains(target, ":") && !strings.Contains(target, "://") {
		client, err := m.createGRPCClient(target)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create gRPC transport for tcp target", Err: err}
		}
		m.client = client
		return nil
	}

	// Default: treat as Unix socket path for backward compatibility
	client, err := unix.New(transport.WithAddress(target))
	if err != nil {
		return &errs.Wrapped{Msg: "failed to create unix transport for default target", Err: err}
	}
	m.client = client
	return nil
}

// buildTransportOptions assembles the dial options shared by every network
// transport (gRPC, REST, QUIC): the address plus the module's TLS configuration.
// TLS modes:
//   - mTLS: Both CertFile and KeyFile configured (mutual TLS authentication)
//   - TLS: Only CAFile configured (server certificate verification)
//   - Insecure: TLS enabled but no certificates (skip verification - testing only)
//
// Factored out so REST and QUIC clients are configured identically to gRPC
// rather than each duplicating the same TLS branch.
func (m *Module) buildTransportOptions(address string) []transport.Option {
	opts := []transport.Option{
		transport.WithAddress(address),
	}

	if m.config.TLS.Enabled {
		switch {
		case m.config.TLS.CertFile != "" && m.config.TLS.KeyFile != "":
			opts = append(opts, transport.WithMTLS(
				m.config.TLS.CertFile,
				m.config.TLS.KeyFile,
				m.config.TLS.CAFile,
			))
		case m.config.TLS.CAFile != "":
			opts = append(opts, transport.WithTLS(m.config.TLS.CAFile))
		default:
			// TLS enabled but no certificates - insecure mode (for testing).
			opts = append(opts, transport.WithTLS(""))
		}
	}

	return opts
}

// createGRPCClient creates a gRPC transport client with the shared TLS options.
func (m *Module) createGRPCClient(address string) (PKCS11Transport, error) {
	return grpc.New(m.buildTransportOptions(address)...)
}

// createQUICClient creates a QUIC transport client with the shared TLS options.
func (m *Module) createQUICClient(address string) (PKCS11Transport, error) {
	return quic.New(m.buildTransportOptions(address)...)
}

// Finalize cleans up the PKCS#11 module.
// Implements C_Finalize behavior per PKCS#11 specification.
func (m *Module) Finalize() CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Close all sessions, destroying each one's session objects first: they live
	// no longer than the session that created them (v3.2 §4.1.3), and once
	// CloseAllSessions has run nothing can name those sessions to clean up after.
	for _, sm := range m.sessionManagers {
		for _, handle := range sm.SessionHandles() {
			m.objectManager.DestroySessionObjects(handle)
		}
		sm.CloseAllSessions()
	}

	// Wipe whatever key material remains -- token objects, and anything a
	// session object left behind -- rather than releasing it to the collector.
	if m.objectManager != nil {
		m.objectManager.Zeroize()
	}

	// Reseal the private key barrier before tearing the rest down, so no
	// unsealed key survives finalization in memory.
	m.sealPrivateStore()

	// Close the transport client
	if m.client != nil {
		if err := m.client.Close(); err != nil {
			m.logStorageError("close the transport client during finalization", err)
		}
	}

	// Close storage
	if m.storage != nil {
		if err := m.storage.Close(); err != nil {
			m.logStorageError("close the object store during finalization", err)
		}
	}

	// Clear state
	m.sessionManagers = make(map[SlotID]*SessionManager)
	m.slotManager = nil
	m.objectManager = nil
	m.cryptoManager = nil
	m.storage = nil
	m.client = nil

	m.initialized.Store(false)
	return CKR_OK
}

// IsInitialized returns whether the module is initialized.
func (m *Module) IsInitialized() bool {
	return m.initialized.Load()
}

// GetInfo returns information about the Cryptoki library.
// Implements C_GetInfo behavior per PKCS#11 specification.
func (m *Module) GetInfo() (*CK_INFO, CK_RV) {
	// GetInfo can be called before Initialize per PKCS#11 spec
	info := m.info
	return &info, CKR_OK
}

// ----------------------------------------------------------------
// PKCS#11 v3.0 Interface Functions
// ----------------------------------------------------------------

// GetInterfaceList obtains a list of interfaces supported by the module.
// Implements C_GetInterfaceList behavior per PKCS#11 v3.0 specification.
// This is a v3.0 function that allows applications to discover available interfaces.
func (m *Module) GetInterfaceList() ([]CK_INTERFACE, CK_RV) {
	// GetInterfaceList can be called before Initialize per PKCS#11 v3.0 spec
	// Return a copy to prevent modification
	interfaces := make([]CK_INTERFACE, len(m.interfaces))
	copy(interfaces, m.interfaces)

	// If interfaces haven't been initialized, return the default interface
	if len(interfaces) == 0 {
		interfaces = []CK_INTERFACE{
			{
				Name:         InterfaceNamePKCS11,
				FunctionList: nil,
				Flags:        0,
			},
		}
	}

	return interfaces, CKR_OK
}

// GetInterface obtains a specific interface by name and version.
// Implements C_GetInterface behavior per PKCS#11 v3.0 specification.
// If name is nil or empty, returns the default interface.
// If version is nil, returns the interface with the highest version.
// If version is specified, it represents the minimum version required.
func (m *Module) GetInterface(name string, version *Version) (*CK_INTERFACE, CK_RV) {
	// GetInterface can be called before Initialize per PKCS#11 v3.0 spec

	// If name is empty, return the default PKCS#11 interface
	if name == "" {
		name = InterfaceNamePKCS11
	}

	// Exact version matching per PKCS#11 v3.2 spec:
	// If version is specified, only return an interface for that exact version.
	// Supported versions: 2.x (any minor), 3.0, and 3.2.
	if version != nil {
		switch {
		case version.Major == 2:
			// Any v2.x request is valid (CK_FUNCTION_LIST)
		case version.Major == 3 && version.Minor == 0:
			// v3.0 request is valid (CK_FUNCTION_LIST_3_0)
		case version.Major == 3 && version.Minor == 2:
			// v3.2 request is valid (CK_FUNCTION_LIST_3_2)
		default:
			return nil, CKR_ARGUMENTS_BAD
		}
	}

	// Get the list of interfaces
	interfaces := m.interfaces
	if len(interfaces) == 0 {
		interfaces = []CK_INTERFACE{
			{
				Name:         InterfaceNamePKCS11,
				FunctionList: nil,
				Flags:        0,
			},
		}
	}

	// Find the matching interface
	for i := range interfaces {
		if interfaces[i].Name == name {
			return &interfaces[i], CKR_OK
		}
	}

	// Interface not found
	return nil, CKR_ARGUMENTS_BAD
}

// ----------------------------------------------------------------
// Slot and Token Operations
// ----------------------------------------------------------------

// slotsLive reports whether the slot manager is still present.
//
// C_Finalize nils the managers out under the write lock, so an entry point that
// passed the m.initialized check before C_Finalize ran and then blocked on
// m.mu.RLock() resumes against a torn-down module. PKCS#11 v3.2 permits
// C_Finalize at any time, so a call that loses this race must return
// CKR_CRYPTOKI_NOT_INITIALIZED rather than dereference nil — through the C ABI
// the panic was caught by recoverCKRV and surfaced as CKR_FUNCTION_FAILED,
// which tells the application nothing about what happened.
//
// The functions that call findSession first are already safe: it fails with
// CKR_SESSION_HANDLE_INVALID off the emptied session map. Only the informational
// entry points that reach straight for the slot manager need this.
//
// The caller must hold at least the read lock.
func (m *Module) slotsLive() bool {
	return m.slotManager != nil
}

// GetSlotList obtains a list of slots in the system.
// Implements C_GetSlotList behavior per PKCS#11 specification.
func (m *Module) GetSlotList(tokenPresent bool) ([]SlotID, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.slotsLive() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	return m.slotManager.GetSlotList(tokenPresent), CKR_OK
}

// GetSlotInfo obtains information about a particular slot.
// Implements C_GetSlotInfo behavior per PKCS#11 specification.
func (m *Module) GetSlotInfo(slotID SlotID) (*SlotInfo, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.slotsLive() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return nil, CKR_SLOT_ID_INVALID
	}

	info := slot.Info
	return &info, CKR_OK
}

// GetTokenInfo obtains information about a particular token.
// Implements C_GetTokenInfo behavior per PKCS#11 specification.
func (m *Module) GetTokenInfo(slotID SlotID) (*TokenInfo, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.slotsLive() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return nil, CKR_SLOT_ID_INVALID
	}

	if slot.Token == nil {
		return nil, CKR_TOKEN_NOT_PRESENT
	}

	// CK_TOKEN_INFO reports live state, so the session counters and the PIN
	// status flags are computed at call time rather than read from a snapshot
	// that nothing updates.
	info := slot.Token.Info
	if sm, ok := m.sessionManagers[slotID]; ok {
		info.SessionCount = uint64(sm.SessionCount())
		info.RwSessionCount = uint64(sm.RWSessionCount())
		info.Flags = applyPINStatusFlags(info.Flags, sm)
	}

	return &info, CKR_OK
}

// applyPINStatusFlags refreshes the CK_TOKEN_INFO PIN status bits from the
// live failed-attempt counters, so an application can see that a PIN is running
// out of tries or has locked (PKCS#11 v3.2 §3.2).
func applyPINStatusFlags(flags TokenFlag, sm *SessionManager) TokenFlag {
	flags &^= CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED
	flags &^= CKF_SO_PIN_COUNT_LOW | CKF_SO_PIN_FINAL_TRY | CKF_SO_PIN_LOCKED

	userFailed, userLocked := sm.PINAttemptStatus(CKU_USER)
	switch {
	case userLocked:
		flags |= CKF_USER_PIN_LOCKED
	case userFailed == MaxPINAttempts-1:
		flags |= CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY
	case userFailed > 0:
		flags |= CKF_USER_PIN_COUNT_LOW
	}

	soFailed, soLocked := sm.PINAttemptStatus(CKU_SO)
	switch {
	case soLocked:
		flags |= CKF_SO_PIN_LOCKED
	case soFailed == MaxPINAttempts-1:
		flags |= CKF_SO_PIN_COUNT_LOW | CKF_SO_PIN_FINAL_TRY
	case soFailed > 0:
		flags |= CKF_SO_PIN_COUNT_LOW
	}

	return flags
}

// GetMechanismList obtains a list of mechanism types supported by a token.
// Implements C_GetMechanismList behavior per PKCS#11 specification.
func (m *Module) GetMechanismList(slotID SlotID) ([]MechanismType, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.slotsLive() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	_, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return nil, CKR_SLOT_ID_INVALID
	}

	mechs, err := m.slotManager.GetMechanismList(slotID)
	if err != nil {
		return nil, CKR_SLOT_ID_INVALID
	}

	return mechs, CKR_OK
}

// GetMechanismInfo obtains information about a mechanism.
// Implements C_GetMechanismInfo behavior per PKCS#11 specification.
func (m *Module) GetMechanismInfo(slotID SlotID, mechType MechanismType) (*MechanismInfo, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.slotsLive() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	_, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return nil, CKR_SLOT_ID_INVALID
	}

	info, err := m.slotManager.GetMechanismInfo(slotID, mechType)
	if err != nil {
		return nil, CKR_MECHANISM_INVALID
	}

	return info, CKR_OK
}

// WaitForSlotEvent waits for a slot event (token insertion/removal).
// Implements C_WaitForSlotEvent behavior per PKCS#11 specification.
// If blocking is false, returns immediately with CKR_NO_EVENT if no event is pending.
// If blocking is true, blocks until a slot event occurs.
func (m *Module) WaitForSlotEvent(blocking bool) (SlotID, CK_RV) {
	if !m.initialized.Load() {
		return 0, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// For virtual tokens that don't have physical slot events,
	// we can either block indefinitely or return no event.
	if !blocking {
		// Non-blocking mode: return immediately with no event
		return 0, CKR_NO_EVENT
	}

	// Blocking mode: For a software token implementation,
	// slot events don't naturally occur. We could:
	// 1. Block forever (until Finalize is called)
	// 2. Return after a timeout
	// 3. Monitor for programmatic token changes
	//
	// For now, we implement a simple version that returns no event
	// after checking slot state. Real implementations would use
	// channels or condition variables to wait for events.
	return 0, CKR_NO_EVENT
}

// InitToken initializes a token.
// Implements C_InitToken behavior per PKCS#11 specification.
func (m *Module) InitToken(slotID SlotID, soPin []byte, label string) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return CKR_SLOT_ID_INVALID
	}

	if slot.Token == nil {
		return CKR_TOKEN_NOT_PRESENT
	}

	// Check if sessions exist on this token
	if sm, ok := m.sessionManagers[slotID]; ok && sm.SessionCount() > 0 {
		return CKR_SESSION_EXISTS
	}

	// Re-initializing an already-initialized token requires the existing SO PIN
	// (v3.2 §5.5.7). Without this check any local caller could seize a
	// provisioned token by simply choosing a new PIN.
	if slot.Token.Initialized {
		if !slot.Token.VerifySOPin(string(soPin)) {
			return CKR_PIN_INCORRECT
		}
	}

	// Initialize the token
	if err := slot.Token.SetSOPin(string(soPin)); err != nil {
		return CKR_DEVICE_ERROR
	}
	slot.Token.Info.SetLabel(label)

	// Generate a serial number if not set
	if slot.Token.Info.GetSerialNumber() == "" {
		serial, err := generateSerialNumber()
		if err != nil {
			return CKR_DEVICE_ERROR
		}
		slot.Token.Info.SetSerialNumber(serial)
	}
	slot.Token.Info.Flags |= CKF_TOKEN_INITIALIZED
	slot.Token.Initialized = true

	// Initialization destroys every destroyable object on the token and
	// disables the normal user until the SO sets a new user PIN (v3.2 §5.5.7).
	// A destroyable object whose persistent delete fails would survive on disk
	// and reappear at the next C_Initialize, so a failure here is a device
	// error for the same reason the token-state write below is.
	if err := m.destroyTokenObjects(slotID); err != nil {
		return CKR_DEVICE_ERROR
	}
	slot.Token.ClearUserPin()
	slot.Token.Info.Flags &^= CKF_USER_PIN_INITIALIZED

	// Ensure SessionManager has the SO PIN hash for authentication
	if sm, ok := m.sessionManagers[slotID]; ok {
		soHash, err := hashPin(string(soPin))
		if err != nil {
			return CKR_DEVICE_ERROR
		}
		sm.SetSOPIN(soHash)
		sm.SetUserPIN(nil)
		sm.ResetPINAttempts(CKU_SO)
		sm.ResetPINAttempts(CKU_USER)
	}

	// C_InitToken fails if its result did not reach the store.
	//
	// This is the one persistence failure in this file that must not be
	// best-effort. Initialization is a one-shot administrative act with no
	// external source to rebuild it from: it has just destroyed every
	// destroyable object on the token, disabled the normal user, and installed
	// a new SO PIN. Reporting CKR_OK on a write that did not land tells the
	// administrator the token now has the SO PIN they chose, when a restart
	// will present the one it had before -- and §5.5.7 notes that a token whose
	// SO PIN is lost has to be reinitialized, so that is not a mistake the
	// caller can discover cheaply or repair in place.
	//
	// CKR_DEVICE_ERROR is in C_InitToken's return list (§5.5.7) and §5.1.6
	// defines it as "some problem has occurred with the token and/or slot",
	// which a token store that will not accept a write is.
	if err := m.saveTokenState(slotID); err != nil {
		m.logStorageError("persist token state after C_InitToken", err)
		return CKR_DEVICE_ERROR
	}

	return CKR_OK
}

// InitPIN initializes the user PIN.
// Implements C_InitPIN behavior per PKCS#11 specification.
func (m *Module) InitPIN(sessionHandle SessionHandle, pin []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the session and its slot
	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// Must be SO logged in
	if !session.IsSOLoggedIn() {
		return CKR_USER_NOT_LOGGED_IN
	}

	// Must be R/W session
	if !session.IsReadWrite() {
		return CKR_SESSION_READ_ONLY
	}

	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return CKR_SLOT_ID_INVALID
	}

	if slot.Token == nil {
		return CKR_TOKEN_NOT_PRESENT
	}

	// Validate PIN length
	if uint64(len(pin)) < slot.Token.Info.MinPinLen || uint64(len(pin)) > slot.Token.Info.MaxPinLen {
		return CKR_PIN_LEN_RANGE
	}

	if err := slot.Token.SetUserPin(string(pin)); err != nil {
		return CKR_DEVICE_ERROR
	}

	// Ensure SessionManager has the user PIN hash for authentication
	if sm, ok := m.sessionManagers[slotID]; ok {
		userHash, err := hashPin(string(pin))
		if err != nil {
			return CKR_DEVICE_ERROR
		}
		sm.SetUserPIN(userHash)
		// Establishing a PIN clears the failed-attempt budget, exactly as
		// C_InitToken and C_SetPIN do. A counter carried over from before the
		// PIN existed would apply to a secret no one has yet had the chance to
		// get wrong, and the SO has no other call to clear it with.
		sm.ResetPINAttempts(CKU_USER)
	}

	// Persist token state. A PIN that is live in memory but was never written
	// does not survive a restart, so a caller told C_InitPIN succeeded would
	// find the PIN gone after the next C_Initialize. §5.5.7 lists
	// CKR_DEVICE_ERROR for exactly this failure; report it rather than claim a
	// success the token cannot keep.
	if err := m.saveTokenState(slotID); err != nil {
		m.logStorageError("persist token state after C_InitPIN", err)
		return CKR_DEVICE_ERROR
	}

	return CKR_OK
}

// SetPIN modifies the PIN of the logged-in user.
// Implements C_SetPIN behavior per PKCS#11 specification.
func (m *Module) SetPIN(sessionHandle SessionHandle, oldPin, newPin []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return CKR_SLOT_ID_INVALID
	}

	if slot.Token == nil {
		return CKR_TOKEN_NOT_PRESENT
	}

	// Validate new PIN length
	if uint64(len(newPin)) < slot.Token.Info.MinPinLen || uint64(len(newPin)) > slot.Token.Info.MaxPinLen {
		return CKR_PIN_LEN_RANGE
	}

	// Get the session manager for this slot
	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// C_SetPIN is valid only from R/W Public, R/W User or R/W SO Functions
	// (v3.2 §5.5.9); any read-only session must be rejected outright.
	if !session.IsReadWrite() {
		return CKR_SESSION_READ_ONLY
	}

	// Verify old PIN and set new PIN based on the session's login state. A R/W
	// public session modifies the normal user's PIN, which is how an
	// unauthenticated user changes their own PIN by proving the old one.
	//
	// The old PIN is checked through the session manager rather than against the
	// token directly, so the attempt is counted and can lock. Proving the old
	// PIN is an authentication whichever function it happens under; verifying it
	// outside the lockout left an unbounded guessing oracle that C_Login does
	// not have, and v3.2 §5.5.9 lists CKR_PIN_LOCKED among this function's own
	// return values. A successful change clears the counter.
	switch {
	case session.IsSOLoggedIn():
		if err := sm.VerifyPINForChange(CKU_SO, oldPin); err != nil {
			return FromError(err)
		}
		if err := slot.Token.SetSOPin(string(newPin)); err != nil {
			return CKR_DEVICE_ERROR
		}
		// Also update the session manager's PIN hash for future login validation
		soHash, err := hashPin(string(newPin))
		if err != nil {
			return CKR_DEVICE_ERROR
		}
		sm.SetSOPIN(soHash)
		sm.ResetPINAttempts(CKU_SO)
	default:
		if err := sm.VerifyPINForChange(CKU_USER, oldPin); err != nil {
			return FromError(err)
		}
		// Re-protect the private key material under the new user PIN before
		// updating the module's PIN state, so a rekey failure leaves the token's
		// PIN unchanged and consistent with the barrier. The SO branch above has
		// no such step: the SO PIN never keys the private barrier. Only the user
		// PIN does, so only a user-PIN change rekeys.
		if err := m.rekeyPrivateStore(oldPin, newPin); err != nil {
			m.logStorageError("rekey private key store at C_SetPIN", err)
			return CKR_DEVICE_ERROR
		}
		if err := slot.Token.SetUserPin(string(newPin)); err != nil {
			return CKR_DEVICE_ERROR
		}
		// Also update the session manager's PIN hash for future login validation
		userHash, err := hashPin(string(newPin))
		if err != nil {
			return CKR_DEVICE_ERROR
		}
		sm.SetUserPIN(userHash)
		sm.ResetPINAttempts(CKU_USER)
	}

	// Persist token state. As with C_InitPIN, a PIN change that was applied in
	// memory but never written would be silently undone by the next
	// C_Initialize, so a persist failure is CKR_DEVICE_ERROR (§5.5.8) rather
	// than a claimed success.
	if err := m.saveTokenState(slotID); err != nil {
		m.logStorageError("persist token state after C_SetPIN", err)
		return CKR_DEVICE_ERROR
	}

	return CKR_OK
}

// ----------------------------------------------------------------
// Session Operations
// ----------------------------------------------------------------

// OpenSession opens a session between an application and a token.
// Implements C_OpenSession behavior per PKCS#11 specification.
func (m *Module) OpenSession(slotID SlotID, flags SessionFlag) (SessionHandle, CK_RV) {
	if !m.initialized.Load() {
		return SessionHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Verify slot exists
	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return SessionHandle(InvalidHandle), CKR_SLOT_ID_INVALID
	}

	if slot.Token == nil {
		return SessionHandle(InvalidHandle), CKR_TOKEN_NOT_PRESENT
	}

	// Get or create session manager for this slot. A manager created here must
	// share the library-wide handle table (m.sessionHandles), not a private
	// one: CK_SESSION_HANDLE is a single flat namespace across all slots (v3.2
	// §3.3), so a per-slot table restarting at 1 would hand out handles that
	// collide with another slot's. Initialize pre-populates every slot, so this
	// branch is defensive; wiring the shared table keeps it correct if slots
	// ever become dynamic.
	sm, ok := m.sessionManagers[slotID]
	if !ok {
		sm = NewSessionManagerWithTable(uint64(slotID), 0, m.sessionHandles)
		m.sessionManagers[slotID] = sm
	}

	// Open the session
	handle, sessErr := sm.OpenSession(flags)
	if sessErr != nil {
		return SessionHandle(InvalidHandle), FromError(sessErr)
	}

	return handle, CKR_OK
}

// CloseSession closes a session between an application and a token.
// Implements C_CloseSession behavior per PKCS#11 specification.
func (m *Module) CloseSession(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the session manager that owns this session
	for _, sm := range m.sessionManagers {
		if err := sm.CloseSession(sessionHandle); err == nil {
			// Clean up session objects
			m.objectManager.DestroySessionObjects(sessionHandle)
			return CKR_OK
		}
	}

	return CKR_SESSION_HANDLE_INVALID
}

// CloseAllSessions closes all sessions for a token.
// Implements C_CloseAllSessions behavior per PKCS#11 specification.
func (m *Module) CloseAllSessions(slotID SlotID) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return CKR_SLOT_ID_INVALID
	}

	sm, ok := m.sessionManagers[slotID]
	if ok {
		// Each session's objects are destroyed before the manager forgets the
		// sessions. C_CloseSession does this one session at a time (v3.2
		// §4.1.3); closing them in bulk must not be the way an application ends
		// up with session objects that outlive every session, still visible to
		// the next session opened on the slot because object visibility is
		// scoped to the token rather than to the session that created them.
		for _, handle := range sm.SessionHandles() {
			m.objectManager.DestroySessionObjects(handle)
		}
		sm.CloseAllSessions()
	}

	return CKR_OK
}

// GetSessionInfo obtains information about a session.
// Implements C_GetSessionInfo behavior per PKCS#11 specification.
func (m *Module) GetSessionInfo(sessionHandle SessionHandle) (*SessionInfo, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Find the session
	for _, sm := range m.sessionManagers {
		info, err := sm.GetSessionInfo(sessionHandle)
		if err == nil {
			return &info, CKR_OK
		}
	}

	return nil, CKR_SESSION_HANDLE_INVALID
}

// Login logs a user into a token.
// Implements C_Login behavior per PKCS#11 specification.
func (m *Module) Login(sessionHandle SessionHandle, userType UserType, pin []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// C_Login is the function PKCS#11 v3.2 §4.10 names for re-authentication, so
	// it takes the same path C_LoginUser does; loginContextSpecific says why the
	// two must not differ.
	if userType == CKU_CONTEXT_SPECIFIC {
		return m.loginContextSpecific(sm, sessionHandle, session, pin)
	}

	if err := sm.Login(sessionHandle, userType, pin); err != nil {
		return FromError(err)
	}

	// The user login is the point PKCS#11 grants access to private objects, so
	// it is where the barrier protecting private key material is unsealed. The
	// PIN has just been verified above, so a failure here is an at-rest fault:
	// the key material cannot be made available. Roll the login back rather than
	// present an authenticated session that cannot use its keys.
	if userType == CKU_USER {
		if err := m.unsealPrivateStore(pin); err != nil {
			_ = sm.Logout(sessionHandle)
			m.logStorageError("unseal private key store at login", err)
			return CKR_DEVICE_ERROR
		}
	}

	return CKR_OK
}

// Logout logs a user out from a token.
// Implements C_Logout behavior per PKCS#11 specification.
func (m *Module) Logout(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	if err := sm.Logout(sessionHandle); err != nil {
		return FromError(err)
	}

	// Operations already under way are recorded as unauthorized first, while
	// their keys can still be examined. Once the objects below are gone, an
	// operation caught by this logout is indistinguishable from one whose key
	// the application destroyed itself.
	sm.ForEachSession(func(handle SessionHandle) {
		m.revokeLoginBoundOperations(sm, handle)
	})

	// Logging out destroys every private session object belonging to the
	// application and invalidates handles to private objects (v3.2 §5.6.10),
	// so a handle obtained while authenticated cannot be replayed afterwards.
	// Private token objects survive, but the access context now denies them.
	sm.ForEachSession(func(handle SessionHandle) {
		m.objectManager.DestroyPrivateSessionObjects(handle)
	})

	// Access to private objects is gone, so the barrier protecting the private
	// key material is resealed, dropping the key from memory until the next
	// user login.
	m.sealPrivateStore()

	return CKR_OK
}

// revokeLoginBoundOperations marks the session's active operations that depend
// on the authentication C_Logout has just withdrawn. An operation depends on it
// exactly when its key is a private object, since that is the class of object
// PKCS#11 v3.2 §4.2 makes reachable only to an authenticated normal user.
//
// It runs before the private session objects are destroyed, because the test is
// a property of the key object and the object is about to cease to exist.
// Operations that carry no key -- C_DigestInit, C_FindObjectsInit -- name a
// handle that resolves to nothing and are correctly left alone.
func (m *Module) revokeLoginBoundOperations(sm *SessionManager, handle SessionHandle) {
	session, err := sm.GetSession(handle)
	if err != nil {
		// The session was closed concurrently; it has no operations left to
		// revoke, and C_Logout does not report another session's disappearance.
		return
	}

	session.RevokeOperationAuthorization(func(op *OperationState) bool {
		key, keyErr := m.objectManager.getObjectUnchecked(op.KeyHandle)
		return keyErr == nil && key.IsPrivate
	})
}

// LoginUser performs a context-specific login to a token.
// Implements C_LoginUser behavior per PKCS#11 v3.0 specification.
// This v3.0 function supports additional user types and context data.
func (m *Module) LoginUser(sessionHandle SessionHandle, userType UserType, pin []byte, username string) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// CKU_CONTEXT_SPECIFIC re-authenticates the key of an operation already
	// under way (v3.2 §4.10), so it goes through the same helper C_Login uses;
	// loginContextSpecific says why the two must not differ. The requirement
	// used to be stated here as "some operation is active", which admitted a
	// login that authenticated nothing: an active C_DigestInit has no key, and
	// an active operation on a key without CKA_ALWAYS_AUTHENTICATE has nothing
	// to re-authenticate for.
	if userType == CKU_CONTEXT_SPECIFIC {
		return m.loginContextSpecific(sm, sessionHandle, session, pin)
	}

	// For standard user types (CKU_SO, CKU_USER), delegate to session manager
	// The username is used for multi-user token scenarios (future enhancement)
	if err := sm.Login(sessionHandle, userType, pin); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// SessionCancel cancels an active cryptographic operation in a session.
// Implements C_SessionCancel behavior per PKCS#11 v3.0 specification.
// This v3.0 function allows canceling operations without completing them.
// Per OASIS PKCS#11 v3.0 Section 5.16.1:
// Returns CKR_OPERATION_NOT_INITIALIZED if no operation is active.
func (m *Module) SessionCancel(sessionHandle SessionHandle, flags uint64) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// PKCS#11 v3.2: "If no flags are set, the session state will not be
	// modified and CKR_OK will be returned." A zero flags argument selects no
	// operation, so it is not a request to cancel everything — reading it that
	// way would silently destroy operations the application never named.
	if flags == 0 {
		return CKR_OK
	}

	// "If a flag is set for an operation that has not been initialized in the
	// session, the operation flag will be ignored and C_SessionCancel will
	// behave as if the operation flag was not set." Cancelling something that
	// is not running is therefore success, not CKR_OPERATION_NOT_INITIALIZED:
	// the caller's postcondition — that the operation is not active — holds
	// either way.
	//
	// The flags also select which categories to cancel, so cancelling every
	// category regardless would destroy the other half of a dual-function flow
	// that the application asked to keep.
	for opType, flag := range sessionCancelFlags {
		if flags&flag == 0 || !session.HasOperationType(opType) {
			continue
		}
		// "If any of the operations indicated by the flags parameter cannot be
		// cancelled, CKR_OPERATION_CANCEL_FAILED must be returned."
		if err := sm.FinalizeOperationType(sessionHandle, opType); err != nil {
			return CKR_OPERATION_CANCEL_FAILED
		}
	}

	return CKR_OK
}

// sessionCancelFlags maps the operation categories C_SessionCancel can cancel
// to the CK_FLAGS bit that selects each one.
var sessionCancelFlags = map[OperationType]uint64{
	OperationEncrypt: uint64(CKF_ENCRYPT),
	OperationDecrypt: uint64(CKF_DECRYPT),
	OperationDigest:  uint64(CKF_DIGEST),
	OperationSign:    uint64(CKF_SIGN),
	OperationVerify:  uint64(CKF_VERIFY),
}

// ----------------------------------------------------------------
// Object Operations
// ----------------------------------------------------------------

// CreateObject creates a new object.
// Implements C_CreateObject behavior per PKCS#11 specification.
//
// A secret key whose material the template supplies in CKA_VALUE is imported
// into the configured backend and given a backend key id, which is what a real
// token does with C_CreateObject: the key becomes part of the token rather than
// an attribute map in this process. Without that id the service cannot name the
// key, so C_WrapKey and C_UnwrapKey refused it outright — a key imported this
// way could not be a key-encryption key — and C_Encrypt, C_Decrypt and C_Sign
// failed their own key lookups for the same reason. Importing fixes all of them
// at once, and needs no capability the wire did not already have: it is the
// same GetImportParameters/ImportKey ceremony the SDK uses, with the material
// wrapped in this process (see CryptoManager.ImportKeyMaterial).
//
// Three kinds of object are deliberately NOT imported.
//
// Public keys, certificates and data objects hold no secret. There is nothing
// for a backend to protect and nothing a backend copy would make possible, so
// they stay local, exactly as before.
//
// Private keys are not imported either. CKA_VALUE on a private key may be a
// PKCS#8 blob or a bare seed depending on the key type, and the import path
// accepts only one of those shapes, so a single rule cannot serve both. The
// post-quantum private keys this module generates in process are local by
// design (see module_keygen_quantum.go), and importing the C_CreateObject case
// alone would leave two kinds of private key with different residency for no
// benefit any verb collects.
//
// A key the application explicitly marks CKA_EXTRACTABLE=CK_FALSE is not
// imported. The import ceremony carries no exportability field, so the backend
// copy would be created extractable — the module would have quietly widened the
// very protection the caller asked for. Keeping such a key local honours the
// request; the cost is that it cannot serve as a KEK, which is what it could
// not do before this change either. CKA_SENSITIVE is not treated the same way:
// §4.9 Table 30 makes it a rule about disclosing the value, not about wrapping,
// and a backend-resident sensitive key is precisely what C_GenerateKey already
// produces.
//
// When the backend cannot import at all — several implement no import/export
// path — the object is kept local rather than the call refused. Refusing would
// withdraw a capability those backends have today, and §5.7.1's return table
// offers no code meaning "this token cannot hold this kind of key", only codes
// that would claim a failure that did not happen. The cost of the fallback is
// stated plainly: on such a backend an imported key still lives only in
// CKA_VALUE, so it still cannot be a wrapping key, and
// unimportedKeyPersistenceError still governs whether it may be a token object.
func (m *Module) CreateObject(sessionHandle SessionHandle, template []Attribute) (ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	access := NewAccessContext(sessionHandle, session)
	handle, err := m.objectManager.CreateObject(access, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	obj, getErr := m.objectManager.getObjectUnchecked(handle)
	if getErr != nil {
		return ObjectHandle(InvalidHandle), FromError(getErr)
	}

	// The import is attempted before the persistence rule is applied, because
	// the rule's question — is CKA_VALUE the only copy of this key? — is
	// answered by whether the import succeeded, and that is only knowable by
	// asking the backend.
	if importRV := m.importCreatedKey(obj); importRV != CKR_OK {
		if destroyErr := m.objectManager.DestroyObject(access, handle); destroyErr != nil {
			m.logStorageError("destroy object left behind by a failed key import", destroyErr)
		}
		return ObjectHandle(InvalidHandle), importRV
	}

	// A key this token can neither hold nor give back is refused rather than
	// stored as a shell. C_CreateObject was the one creation verb without this
	// rule, so a CKA_TOKEN key marked CKA_SENSITIVE returned CKR_OK and came
	// back after a restart with no CKA_VALUE at all.
	if persistErr := unimportedKeyPersistenceError(obj); persistErr != nil {
		if destroyErr := m.objectManager.DestroyObject(access, handle); destroyErr != nil {
			m.logStorageError("destroy object refused by the persistence rule", destroyErr)
		}
		return ObjectHandle(InvalidHandle), FromError(persistErr)
	}

	// Persist token objects to storage. A CKA_TOKEN object the store would not
	// take was not created, so C_CreateObject reports the token failure rather
	// than hand back a handle that lives only until C_Finalize (v3.2 §5.7.1).
	if persistErr := m.persistNewObject(access, handle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	return handle, CKR_OK
}

// importCreatedKey imports a newly created secret key's material into the
// backend and records the key id on the object.
//
// It returns CKR_OK both when the key was imported and when this token does not
// import keys of that kind at all; CreateObject's doc comment sets out which
// objects are candidates and why. Only a candidate the backend accepted comes
// back with a KeyID, so that field is the single signal for everything
// downstream — unimportedKeyPersistenceError, unstorableProtectionError,
// secretKeyValue and WrapKey all key off it.
//
// A backend that cannot import answers CKR_FUNCTION_NOT_SUPPORTED and the
// object is kept local. Every other failure is real and is reported as
// CKR_DEVICE_ERROR, which C_CreateObject's return table lists (v3.2 §5.7.1) and
// which this function's caller already returns when the object store refuses a
// write; a backend that was asked to take a key and could not is the same kind
// of failure. Reporting it is what keeps the call honest: the alternative —
// falling back to a local object — would answer CKR_OK for a key that is not on
// the token and cannot be used as one.
func (m *Module) importCreatedKey(obj *Object) CK_RV {
	if obj.Class != CKO_SECRET_KEY {
		return CKR_OK
	}

	// CKA_EXTRACTABLE defaults to CK_TRUE for a secret key (v3.2 §4.9
	// Table 30), which is the same default C_GenerateKey applies. Only an
	// explicit CK_FALSE keeps the key out of the backend.
	if !obj.IsExtractable {
		return CKR_OK
	}

	keyMaterial := obj.GetAttribute(CKA_VALUE)
	if len(keyMaterial) == 0 {
		// C_CreateObject on a secret key without CKA_VALUE creates no material
		// to import. The object layer decides whether that template is legal.
		return CKR_OK
	}

	label := obj.GetLabel()
	if label == "" {
		label = "imported-key"
	}
	keyID := fmt.Sprintf("%s-%d-%d", label, time.Now().UnixNano(), m.keyCounter.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// keyMaterial is GetAttribute's own copy (see GetAttribute), so sealing
	// it here -- which wipes the source slice -- cannot corrupt the object's
	// stored CKA_VALUE.
	keyMaterialBuf, err := secure.NewBufferFromBytes(keyMaterial)
	if err != nil {
		return CKR_DEVICE_ERROR
	}
	defer keyMaterialBuf.Destroy()

	importedID, err := m.cryptoManager.ImportKeyMaterial(ctx, &ImportKeyMaterialRequest{
		KeyID:       keyID,
		Backend:     m.cryptoManager.config.DefaultBackend,
		KeyMaterial: keyMaterialBuf,
	})
	if err != nil {
		if FromError(err) == CKR_FUNCTION_NOT_SUPPORTED {
			return CKR_OK
		}
		return CKR_DEVICE_ERROR
	}

	obj.KeyID = importedID
	obj.BackendName = m.cryptoManager.config.DefaultBackend

	return CKR_OK
}

// unimportedKeyPersistenceError refuses a C_CreateObject key this token could
// not give back after a restart.
//
// The rule is the one every other creation verb already applies —
// derivedKeyPersistenceError for C_DeriveKey, sharedSecretPersistenceError for
// the KEM verbs, unwrappedKeyPersistenceError for C_UnwrapKeyAuthenticated and
// quantumPrivateKeyPersistenceError for a post-quantum key pair. C_CreateObject
// was the one verb without it, and it is the verb whose material always arrives
// in CKA_VALUE, so it was the most exposed: a CKA_TOKEN secret key marked
// CKA_SENSITIVE was accepted with CKR_OK and came back from the next
// C_Initialize with a zero-length CKA_VALUE. Every use of that handle then
// failed, on an object the application had every reason to believe was a key,
// and nothing at creation time had warned.
//
// ModuleStorage.SaveObject withholds every attribute IsSensitiveAttribute names
// — CKA_VALUE among them — from a key object that protects its material,
// because the token store is a plaintext file and writing the key there would
// place in the clear exactly the bytes CKA_SENSITIVE and
// CKA_EXTRACTABLE=CK_FALSE promise never leave the token.
//
// An imported key is exempt, and that exemption is the point of importing.
// Once the object carries a KeyID the material is in the backend and the object
// is metadata, so dropping CKA_VALUE on the way to the store costs the key
// nothing — which is the state a C_GenerateKey key has always been in. The
// refusal therefore applies only to the objects that stayed local: a key the
// caller marked CKA_EXTRACTABLE=CK_FALSE, and any key on a backend that cannot
// import.
//
// CKR_TEMPLATE_INCONSISTENT is in C_CreateObject's return table (v3.2 §5.7.1),
// and §5.1 defines it as a template carrying conflicting attributes, which
// asking this token both to keep a key and to protect its only copy of that key
// is.
func unimportedKeyPersistenceError(obj *Object) error {
	// CKA_SENSITIVE and CKA_EXTRACTABLE carry protection semantics only for the
	// key classes (v3.2 §4.9). A certificate's or data object's CKA_VALUE is
	// public object content that the store always writes out.
	switch obj.Class {
	case CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKO_OTP_KEY:
	default:
		return nil
	}

	// A session object is never written to the store at all, so a protected one
	// keeps its CKA_VALUE for as long as it exists and loses nothing.
	if !obj.IsToken {
		return nil
	}

	// A key whose material the backend holds loses nothing by having its
	// CKA_VALUE withheld, and a key that has no material in CKA_VALUE has
	// nothing to lose in the first place.
	if obj.KeyID != "" || len(obj.GetAttribute(CKA_VALUE)) == 0 {
		return nil
	}

	if !obj.protectsSensitiveAttributes() {
		return nil
	}

	return NewPKCS11ErrorWithMessage(CKR_TEMPLATE_INCONSISTENT,
		"a CKA_TOKEN key whose only copy is its own CKA_VALUE must be CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE: this token cannot persist protected key material it could not import")
}

// CopyObject copies an object.
// Implements C_CopyObject behavior per PKCS#11 specification.
func (m *Module) CopyObject(sessionHandle SessionHandle, objectHandle ObjectHandle, template []Attribute) (ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	access := NewAccessContext(sessionHandle, session)
	newHandle, err := m.objectManager.CopyObject(access, objectHandle, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// Persist token objects to storage. The copy is a new object (v3.2 §5.7.2),
	// so it is subject to the same rule as C_CreateObject's: a CKA_TOKEN copy
	// the store would not take was not made.
	if persistErr := m.persistNewObject(access, newHandle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	return newHandle, CKR_OK
}

// DestroyObject destroys an object.
// Implements C_DestroyObject behavior per PKCS#11 specification.
func (m *Module) DestroyObject(sessionHandle SessionHandle, objectHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	if err := m.objectManager.DestroyObject(NewAccessContext(sessionHandle, session), objectHandle); err != nil {
		return FromError(err)
	}

	// A token object is on the token until the store stops holding it (v3.2
	// §4.4), so a delete the store refused is a destruction that did not happen:
	// the next C_Initialize restores the object from the record still on disk,
	// and a key an operator revoked is live again. The in-memory object is
	// already gone and cannot be put back, so the honest answer is the device
	// error -- this process no longer has the object, the next one will, and the
	// caller now knows.
	if m.storage != nil {
		if err := m.storage.DeleteObject(objectHandle); err != nil {
			m.logStorageError("delete destroyed object from the store", err)
			return CKR_DEVICE_ERROR
		}
	}

	return CKR_OK
}

// GetAttributeValue obtains the value of one or more attributes of an object.
// Implements C_GetAttributeValue behavior per PKCS#11 specification.
func (m *Module) GetAttributeValue(sessionHandle SessionHandle, objectHandle ObjectHandle, template []Attribute) ([]Attribute, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	// The result is returned even when err is non-nil: PKCS#11 v3.2 §5.7.5
	// requires every attribute in the template to be processed, so the caller
	// must still receive the values it is entitled to alongside the error.
	access := NewAccessContext(sessionHandle, session)
	attrs, err := m.objectManager.GetAttributeValue(access, objectHandle, template)

	// A secret key the object manager judged revealable still has no CKA_VALUE
	// in its attribute map, because C_GenerateKey creates the material inside
	// the backend. Fetch it now rather than report the attribute missing: a key
	// the caller created as neither sensitive nor unextractable is one PKCS#11
	// v3.2 §4.9 footnote 7 says its value may be revealed, so answering
	// CKR_ATTRIBUTE_TYPE_INVALID would contradict the object's own attributes.
	filled, rv := m.fillBackendKeyValue(access, objectHandle, attrs)
	if rv != CKR_OK {
		return attrs, rv
	}

	if err == nil {
		return attrs, CKR_OK
	}

	// The object manager reported CKA_VALUE missing before it was fetched, so
	// that error may now describe a state that no longer exists -- returning it
	// would contradict the values in hand, handing the caller a full key
	// alongside CKR_ATTRIBUTE_TYPE_INVALID. It is reconsidered only when the
	// fetch actually supplied something; every other failure, including an
	// invalid object handle, is left exactly as reported.
	if filled && !anyAttributeUnavailable(attrs) {
		return attrs, CKR_OK
	}

	return attrs, FromError(err)
}

// anyAttributeUnavailable reports whether any attribute in the result is still
// missing or withheld.
func anyAttributeUnavailable(attrs []Attribute) bool {
	for _, attr := range attrs {
		if attr.Unavailable {
			return true
		}
	}
	return false
}

// secretKeyValue resolves a secret key's material, fetching it from the backend
// when the object itself does not carry it.
//
// C_GenerateKey creates the material inside the backend and keeps only a key
// identifier on the object, so the attribute map holds no CKA_VALUE. Reading
// that map alone cannot tell "this key has no value" apart from "this key's
// value lives elsewhere", and every caller that assumed the former reported a
// perfectly readable key as unavailable.
//
// Whether the value may be revealed at all is settled first by the object's own
// attributes: PKCS#11 v3.2 §4.9 footnote 7 withholds it whenever CKA_SENSITIVE
// is CK_TRUE or CKA_EXTRACTABLE is CK_FALSE. The backend applies the same rule
// again on its side, so a key it refuses to release stays unreadable here.
//
// A nil value with CKR_OK means the object simply has no backend material to
// fetch; CKR_ATTRIBUTE_SENSITIVE means the fetch was attempted and refused.
//
// The backend fetch itself returns the material sealed in a *secure.Buffer
// (ExportKeyMaterialResponse.KeyMaterial); this is the C boundary where that
// protection necessarily ends -- the caller is filling a CK_ATTRIBUTE.Value
// a C_GetAttributeValue caller reads directly, and PKCS#11's C ABI has no
// enclaved equivalent. Only the copy made here, for that one crossing, is
// unbounded Go-heap memory; the export path up to this point stays enclaved.
func (m *Module) secretKeyValue(obj *Object) ([]byte, CK_RV) {
	// Footnote 7 is settled before the material is read, not after: a sensitive
	// or unextractable key withholds its value even when that value still sits
	// in the attribute map after a C_CreateObject or C_UnwrapKey that supplied
	// it. The object manager already withholds the copy it returns, but this
	// path re-reads the object directly, so reading the map before this guard
	// would hand the caller the very material CKA_SENSITIVE forbids.
	if obj.protectsSensitiveAttributes() {
		return nil, CKR_OK
	}

	if value := obj.GetAttribute(CKA_VALUE); len(value) > 0 {
		return value, CKR_OK
	}

	if obj.Class != CKO_SECRET_KEY || obj.KeyID == "" {
		return nil, CKR_OK
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	resp, err := m.cryptoManager.ExportKeyMaterial(ctx, &ExportKeyMaterialRequest{
		KeyID:   obj.KeyID,
		Backend: obj.BackendName,
	})
	if err != nil {
		return nil, CKR_ATTRIBUTE_SENSITIVE
	}
	defer resp.KeyMaterial.Destroy()

	var value []byte
	if err := resp.KeyMaterial.WithBytes(func(b []byte) error {
		value = make([]byte, len(b))
		copy(value, b)
		return nil
	}); err != nil {
		return nil, CKR_ATTRIBUTE_SENSITIVE
	}

	return value, CKR_OK
}

// fillBackendKeyValue populates a revealable secret key's CKA_VALUE from its
// backend.
//
// It is a no-op unless CKA_VALUE was asked for, came back unavailable, and the
// object is a secret key that protects nothing -- so a sensitive or
// unextractable key is never fetched, and the object manager's
// CKR_ATTRIBUTE_SENSITIVE stands. The backend applies the same rule again on
// its own side, refusing anything asymmetric or not marked exportable.
func (m *Module) fillBackendKeyValue(ctx AccessContext, objectHandle ObjectHandle, attrs []Attribute) (filled bool, rv CK_RV) {
	index := -1
	for i, attr := range attrs {
		if attr.Type == CKA_VALUE && len(attr.Value) == 0 {
			index = i
			break
		}
	}
	if index < 0 {
		return false, CKR_OK
	}

	obj, err := m.objectManager.GetObjectFor(ctx, objectHandle)
	if err != nil {
		return false, CKR_OK // the object manager already reported the real problem
	}

	value, valueRV := m.secretKeyValue(obj)
	if valueRV != CKR_OK {
		// The object says the value may be revealed but the backend will not
		// release it. Reporting it as sensitive is the honest answer and keeps
		// the two consistent from the caller's point of view.
		attrs[index].Unavailable = true
		return false, valueRV
	}
	if len(value) == 0 {
		return false, CKR_OK
	}

	attrs[index].Value = value
	attrs[index].Unavailable = false
	return true, CKR_OK
}

// SetAttributeValue modifies the value of one or more attributes of an object.
// Implements C_SetAttributeValue behavior per PKCS#11 specification.
func (m *Module) SetAttributeValue(sessionHandle SessionHandle, objectHandle ObjectHandle, template []Attribute) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// A tightening this token could only carry out by destroying the key it
	// protects is refused before any of the template is applied.
	//
	// The lookup goes through the access context, not getObjectUnchecked. An
	// unchecked lookup answered for objects the session may not see, and the
	// refusal below is derived entirely from such an object's attributes, so
	// the code it returned was itself the disclosure: a caller who was not
	// logged in could set CKA_SENSITIVE against a handle and read
	// CKR_TEMPLATE_INCONSISTENT where an unknown handle gave
	// CKR_OBJECT_HANDLE_INVALID. Sweeping the handle space that way revealed,
	// per handle, that an object existed, that it was a private, secret or OTP
	// key, that it was a token object still holding its material in CKA_VALUE,
	// and that it was currently unprotected — none of which a session that
	// cannot see the object is entitled to learn. The write was refused
	// throughout; what leaked was the answer.
	//
	// Resolving through the access context makes the pre-check see exactly the
	// objects the modification itself would see, so a handle the object layer
	// would reject keeps the code the object layer gives it — which is what the
	// lenient lookup was there to achieve and did not.
	if obj, lookupErr := m.objectManager.GetObjectFor(
		NewAccessContext(sessionHandle, session), objectHandle); lookupErr == nil {
		if protectionErr := unstorableProtectionError(obj, template); protectionErr != nil {
			return FromError(protectionErr)
		}
	}

	// The read-only-session rule applies to token objects only: a read-only
	// session may still modify its own session objects (v3.2 §5.7.4). The
	// object layer applies the distinction, which it can because it knows
	// whether the target is a token object.
	if err := m.objectManager.SetAttributeValue(NewAccessContext(sessionHandle, session), objectHandle, template); err != nil {
		return FromError(err)
	}

	// A modified token object has to be written back, for the same reason
	// C_CreateObject writes a new one: PKCS#11 v3.2 §4.4 keeps a token object on
	// the token "until specifically destroyed", and its attributes are part of
	// it. Modification was the one mutation that never reached the store, so an
	// administrator who tightened a stored key — CKA_ALWAYS_AUTHENTICATE,
	// CKA_TRUSTED, CKA_SENSITIVE, or the one-way CKA_EXTRACTABLE=CK_FALSE — was
	// told it took effect and got the key back at its former, wider permissions
	// at the next process start. Because §4.9 makes those transitions one-way,
	// an application that did not know the change was lost could not even
	// re-apply it.
	//
	// The object is not rolled back on a store failure and cannot be: the
	// one-way transitions that make this worth reporting are exactly the ones
	// C_SetAttributeValue would refuse to undo. What the caller gets instead is
	// the truth — CKR_DEVICE_ERROR, listed for C_SetAttributeValue in v3.2
	// §5.7.6 — leaving the in-memory object at the tighter setting the call
	// asked for and the stored copy unchanged, which fails closed for this
	// process and reverts at the next start the caller now knows about.
	if persistErr := m.persistObjectIfToken(objectHandle, sessionHandle); persistErr != nil {
		return CKR_DEVICE_ERROR
	}

	return CKR_OK
}

// unstorableProtectionError refuses a modification that would leave a token
// object's only copy of its key material unstorable.
//
// A key that holds its material in CKA_VALUE and nowhere else names no backend
// key, so ModuleStorage.SaveObject's rule — withhold every attribute
// IsSensitiveAttribute names from a key object that protects its material,
// because the token store is a plaintext file — has nothing to fall back on.
// Writing such an object back after CKA_SENSITIVE or CKA_EXTRACTABLE was
// tightened would replace the stored key with a key-shaped shell, so the
// protection the administrator asked for would take effect by destroying what it
// protects.
//
// Which objects those are narrowed when C_CreateObject began importing a secret
// key's material into the backend. An imported key now carries a KeyID, so its
// material is where C_GenerateKey's has always been and a tightening costs it
// nothing; the check is on the KeyID rather than on how the object was created,
// so the two rules cannot drift apart. What is left under this refusal is the
// set C_CreateObject could not import: a key the caller marked
// CKA_EXTRACTABLE=CK_FALSE, whose backend copy would have silently widened that
// very protection, and any key on a backend with no import support. Both are
// exactly the objects unimportedKeyPersistenceError refuses to create as
// CKA_TOKEN objects when they are protected from the start, so an object can
// reach this function only by having been created unprotected and tightened
// afterwards.
//
// Refusing is the only honest answer available. Persisting the tightening loses
// the key; persisting the key ignores the tightening, which is the silent
// downgrade this call was fixed to stop; and writing the material out anyway
// would break the promise CKA_SENSITIVE makes. The same tightening stays
// available on every object that loses nothing by it: a key whose material the
// backend holds, an object already protected — whose stored copy has no
// CKA_VALUE to lose — and any session object, which is never written out at all.
//
// CKR_TEMPLATE_INCONSISTENT is in C_SetAttributeValue's return table (v3.2
// §5.7.6), and §5.1 defines it as a template carrying conflicting attributes,
// which asking this token both to keep a key and to protect its only copy of
// that key is. It is the code quantumPrivateKeyPersistenceError and
// sharedSecretPersistenceError refuse the same conflict with at creation time.
func unstorableProtectionError(obj *Object, template []Attribute) error {
	// CKA_SENSITIVE and CKA_EXTRACTABLE are defined only for these classes
	// (v3.2 §4.9); elsewhere they carry no protection semantics, and the
	// object's CKA_VALUE is public content that always persists.
	switch obj.Class {
	case CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKO_OTP_KEY:
	default:
		return nil
	}

	// Nothing is at risk unless the object is written out at all, is still
	// having its CKA_VALUE persisted, and keeps its material there — which is
	// where a key this token could not import holds it, and where a key
	// generated, unwrapped or imported in the backend never does.
	if !obj.IsToken || obj.protectsSensitiveAttributes() {
		return nil
	}
	if obj.KeyID != "" || len(obj.GetAttribute(CKA_VALUE)) == 0 {
		return nil
	}

	// The object's current values are the fallbacks: an attribute the template
	// does not mention is left as it is, so the test is what the object would
	// become and not what the template alone says.
	sensitive := templateBoolIsTrue(template, CKA_SENSITIVE, obj.IsSensitive)
	extractable := templateBoolIsTrue(template, CKA_EXTRACTABLE, obj.IsExtractable)
	if !sensitive && extractable {
		return nil
	}

	return NewPKCS11ErrorWithMessage(CKR_TEMPLATE_INCONSISTENT,
		"this token cannot protect a stored key whose only copy is its own CKA_VALUE: CKA_SENSITIVE=CK_TRUE or CKA_EXTRACTABLE=CK_FALSE would leave it with no key material after a restart")
}

// FindObjectsInit initializes a search for objects that match a template.
// Implements C_FindObjectsInit behavior per PKCS#11 specification.
func (m *Module) FindObjectsInit(sessionHandle SessionHandle, template []Attribute) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	if err := m.objectManager.FindObjectsInit(NewAccessContext(sessionHandle, session), template); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// FindObjects continues a search for objects.
// Implements C_FindObjects behavior per PKCS#11 specification.
func (m *Module) FindObjects(sessionHandle SessionHandle, maxCount uint32) ([]ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	handles, err := m.objectManager.FindObjects(sessionHandle, int(maxCount))
	if err != nil {
		return nil, FromError(err)
	}

	return handles, CKR_OK
}

// FindObjectsFinal terminates a search for objects.
// Implements C_FindObjectsFinal behavior per PKCS#11 specification.
func (m *Module) FindObjectsFinal(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	if err := m.objectManager.FindObjectsFinal(sessionHandle); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// ----------------------------------------------------------------
// Cryptographic Operations
// ----------------------------------------------------------------

// resolveOperationKey resolves the key for a cryptographic operation and
// applies every access rule PKCS#11 places on it before the operation may be
// initialized: the token's login requirement must be satisfied, the session
// must be permitted to see the object, the key's usage attribute for this
// operation category must be CK_TRUE, and the mechanism must be one the key's
// CKA_ALLOWED_MECHANISMS permits (PKCS#11 v3.2 §4.8.2).
//
// The mechanism argument is the one the initializer was handed. Every caller
// reaches this method only after dispatching a NULL pMechanism to
// terminateInitOperation, so it is never nil here; a nil mechanism would name
// no mechanism to test and is refused as CKR_ARGUMENTS_BAD rather than allowed
// through unchecked.
//
// Every C_*Init entry point must resolve its key through this method. Resolving
// a handle directly bypasses the token's access-control model.
func (m *Module) resolveOperationKey(slotID SlotID, sessionHandle SessionHandle, session *Session, keyHandle ObjectHandle, usage AttributeType, mechanism *Mechanism) (*Object, CK_RV) {
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return nil, rv
	}

	obj, err := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), keyHandle)
	if err != nil {
		return nil, CKR_KEY_HANDLE_INVALID
	}

	// An absent usage attribute is not permission. A key is usable for an
	// operation only when it was explicitly marked for it.
	if usage != 0 && !boolAttributeIsTrue(obj.GetAttribute(usage)) {
		return nil, CKR_KEY_FUNCTION_NOT_PERMITTED
	}

	// CKA_ALLOWED_MECHANISMS restricts this key to a named set of mechanisms.
	// It is a per-key rule and therefore belongs here, not in
	// validateInitMechanism, which only decides what the token as a whole
	// offers.
	if mechanism == nil {
		return nil, CKR_ARGUMENTS_BAD
	}
	if mechErr := obj.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return nil, FromError(mechErr)
	}

	if !mechanismAcceptsKeyType(mechanism.Type, obj.KeyType, obj.HasAttribute(CKA_KEY_TYPE)) {
		return nil, CKR_KEY_TYPE_INCONSISTENT
	}

	return obj, CKR_OK
}

// mechanismKeyTypes names the key types each operational mechanism accepts.
//
// A mechanism absent from this table has no opinion and admits any key type.
// That is deliberate rather than lax: the table's job is to refuse pairings the
// module knows are wrong, and inventing a rule for a mechanism whose key
// requirements have not been established here would refuse work the token can
// actually do. Every mechanism this module advertises for an operation is
// present, so the gap applies only to unadvertised ones.
var mechanismKeyTypes = map[MechanismType][]KeyType{
	// RSA. Every RSA mechanism takes a CKK_RSA key, whether the digest is
	// applied by the token (the CKM_SHA*_RSA_* families) or by the caller.
	CKM_RSA_PKCS:            {CKK_RSA},
	CKM_RSA_PKCS_OAEP:       {CKK_RSA},
	CKM_RSA_PKCS_PSS:        {CKK_RSA},
	CKM_RSA_X_509:           {CKK_RSA},
	CKM_SHA1_RSA_PKCS:       {CKK_RSA},
	CKM_SHA256_RSA_PKCS:     {CKK_RSA},
	CKM_SHA384_RSA_PKCS:     {CKK_RSA},
	CKM_SHA512_RSA_PKCS:     {CKK_RSA},
	CKM_SHA256_RSA_PKCS_PSS: {CKK_RSA},
	CKM_SHA384_RSA_PKCS_PSS: {CKK_RSA},
	CKM_SHA512_RSA_PKCS_PSS: {CKK_RSA},

	// ECDSA. CKK_EC is the v3.2 name; CKK_ECDSA is the deprecated alias for the
	// same value, so both are listed for readers rather than for the lookup.
	CKM_ECDSA:        {CKK_EC},
	CKM_ECDSA_SHA1:   {CKK_EC},
	CKM_ECDSA_SHA224: {CKK_EC},
	CKM_ECDSA_SHA256: {CKK_EC},
	CKM_ECDSA_SHA384: {CKK_EC},
	CKM_ECDSA_SHA512: {CKK_EC},

	// EdDSA keys are CKK_EC_EDWARDS, a distinct type from CKK_EC: the curve is
	// Edwards-form and the signature scheme is not ECDSA, so a P-256 key here
	// is exactly the confusion CKR_KEY_TYPE_INCONSISTENT names.
	CKM_EDDSA: {CKK_EC_EDWARDS},

	// ML-DSA (FIPS 204). The parameter-set-specific vendor mechanisms sign with
	// the same CKK_ML_DSA key type as the standard one; the parameter set is a
	// property of the key, carried in CKA_PARAMETER_SET, not of its type. They
	// are listed here rather than in v32KeyTypeMap because that map is keyed by
	// standard v3.2 mechanisms and quantumVendorToStandard already translates
	// these into them for every other purpose.
	CKM_ML_DSA:           {CKK_ML_DSA},
	CKM_VENDOR_ML_DSA_44: {CKK_ML_DSA},
	CKM_VENDOR_ML_DSA_65: {CKK_ML_DSA},
	CKM_VENDOR_ML_DSA_87: {CKK_ML_DSA},

	// AES modes.
	CKM_AES_ECB:     {CKK_AES},
	CKM_AES_CBC:     {CKK_AES},
	CKM_AES_CBC_PAD: {CKK_AES},
	CKM_AES_GCM:     {CKK_AES},

	// HMAC. PKCS#11 v3.2 states the requirement per family in the same words
	// each time -- for SHA-256, "the keys it uses are generic secret keys and
	// CKK_SHA256_HMAC" -- so each mechanism takes CKK_GENERIC_SECRET or the
	// digest's own HMAC key type, and nothing else. An asymmetric key here is
	// the mistake this table exists to name.
	//
	// These are present even though the module does not advertise them. An
	// unadvertised mechanism is still usable: GetMechanismDescriptor resolves
	// anything in the registry and filters only on FIPS, which is what lets
	// CKM_RSA_X_509 serve C_VerifyRecover without being offered. Leaving them
	// out would have exempted every HMAC mechanism from the check.
	CKM_SHA_1_HMAC:              {CKK_GENERIC_SECRET, CKK_SHA_1_HMAC},
	CKM_SHA_1_HMAC_GENERAL:      {CKK_GENERIC_SECRET, CKK_SHA_1_HMAC},
	CKM_SHA224_HMAC:             {CKK_GENERIC_SECRET, CKK_SHA224_HMAC},
	CKM_SHA224_HMAC_GENERAL:     {CKK_GENERIC_SECRET, CKK_SHA224_HMAC},
	CKM_SHA256_HMAC:             {CKK_GENERIC_SECRET, CKK_SHA256_HMAC},
	CKM_SHA256_HMAC_GENERAL:     {CKK_GENERIC_SECRET, CKK_SHA256_HMAC},
	CKM_SHA384_HMAC:             {CKK_GENERIC_SECRET, CKK_SHA384_HMAC},
	CKM_SHA384_HMAC_GENERAL:     {CKK_GENERIC_SECRET, CKK_SHA384_HMAC},
	CKM_SHA512_HMAC:             {CKK_GENERIC_SECRET, CKK_SHA512_HMAC},
	CKM_SHA512_HMAC_GENERAL:     {CKK_GENERIC_SECRET, CKK_SHA512_HMAC},
	CKM_SHA512_224_HMAC:         {CKK_GENERIC_SECRET, CKK_SHA512_224_HMAC},
	CKM_SHA512_224_HMAC_GENERAL: {CKK_GENERIC_SECRET, CKK_SHA512_224_HMAC},
	CKM_SHA512_256_HMAC:         {CKK_GENERIC_SECRET, CKK_SHA512_256_HMAC},
	CKM_SHA512_256_HMAC_GENERAL: {CKK_GENERIC_SECRET, CKK_SHA512_256_HMAC},
	CKM_SHA3_224_HMAC:           {CKK_GENERIC_SECRET, CKK_SHA3_224_HMAC},
	CKM_SHA3_224_HMAC_GENERAL:   {CKK_GENERIC_SECRET, CKK_SHA3_224_HMAC},
	CKM_SHA3_256_HMAC:           {CKK_GENERIC_SECRET, CKK_SHA3_256_HMAC},
	CKM_SHA3_256_HMAC_GENERAL:   {CKK_GENERIC_SECRET, CKK_SHA3_256_HMAC},
	CKM_SHA3_384_HMAC:           {CKK_GENERIC_SECRET, CKK_SHA3_384_HMAC},
	CKM_SHA3_384_HMAC_GENERAL:   {CKK_GENERIC_SECRET, CKK_SHA3_384_HMAC},
	CKM_SHA3_512_HMAC:           {CKK_GENERIC_SECRET, CKK_SHA3_512_HMAC},
	CKM_SHA3_512_HMAC_GENERAL:   {CKK_GENERIC_SECRET, CKK_SHA3_512_HMAC},
}

// acceptedKeyTypes resolves the key types a mechanism accepts, and reports
// whether any rule is known for it at all.
//
// There are two sources and they are not duplicated. mechanismKeyTypes covers
// the classic mechanisms, where one mechanism can accept more than one key type
// -- every HMAC mechanism takes CKK_GENERIC_SECRET as well as its own digest's
// HMAC key type. The v3.2 post-quantum families each use exactly one key type
// and already record it in v32KeyTypeMap, which exists to answer "what key type
// does this mechanism use" for C_GenerateKeyPair; consulting it here keeps the
// pre-hash ML-DSA and SLH-DSA families -- some thirty mechanisms -- from having
// to be listed a second time, where the two copies could disagree.
func acceptedKeyTypes(mechType MechanismType) ([]KeyType, bool) {
	if accepted, ok := mechanismKeyTypes[mechType]; ok {
		return accepted, true
	}
	if keyType, ok := v32KeyTypeMap[mechType]; ok {
		return []KeyType{keyType}, true
	}
	return nil, false
}

// mechanismAcceptsKeyType reports whether a key of the given type may be used
// with the given mechanism.
//
// PKCS#11 v3.2 §5.1.6 defines CKR_KEY_TYPE_INCONSISTENT as "the specified key
// is not the correct type of key to use with the specified mechanism", and the
// code appears in the return table of every C_*Init function. Without this
// check the module accepted, for instance, C_EncryptInit(CKM_AES_GCM) against
// an RSA key and failed somewhere further down -- at the backend, or with a
// code that described the symptom rather than the caller's mistake.
//
// An object with no CKA_KEY_TYPE is admitted, since refusing on a missing field
// would reject valid keys on the strength of an absent attribute rather than a
// wrong one. Whether the attribute is present has to be asked of the object,
// not inferred from the value: CKK_RSA is 0x00000000, so treating a zero key
// type as "unset" would exempt every RSA key in the token from this check --
// which is exactly what the first version of this function did.
func mechanismAcceptsKeyType(mechType MechanismType, keyType KeyType, keyTypeKnown bool) bool {
	accepted, ok := acceptedKeyTypes(mechType)
	if !ok || !keyTypeKnown {
		return true
	}
	for _, candidate := range accepted {
		if keyType == candidate {
			return true
		}
	}
	return false
}

// validateInitMechanism decides whether an operation initializer may proceed
// with the mechanism it was handed, and is the module's only such decision.
//
// Resolution goes through GetMechanismDescriptor because that function carries
// the FIPS filter: a mechanism the module holds but must not offer in FIPS mode
// returns a nil descriptor there. Any initializer that dispatches on
// mechanism.Type without asking here would be a second, unfiltered opinion on
// what the token performs, so every one of them calls this.
//
// A mechanism the module does not implement is CKR_MECHANISM_INVALID —
// "specified mechanism is invalid for this operation" (PKCS#11 v3.2 §5.1) — and
// a missing mechanism is CKR_ARGUMENTS_BAD. Both codes appear in the return
// table of every function that calls this. Note that a caller wishing to
// terminate an operation with a NULL mechanism must have been dispatched to
// terminateInitOperation before reaching here; only the initializers that have
// no such contract (C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey,
// C_DeriveKey) let a nil mechanism arrive at this function.
//
// # Ordering
//
// Callers validate the KEY before the mechanism.
//
// PKCS#11 v3.2 §5.1.6 is explicit that this is a free choice: "there are in
// general no particular priorities among the errors listed below" — so no
// ordering is more conformant than another, and the only defect an
// implementation can commit here is being inconsistent about it. Key-first is
// chosen for two reasons. It is what SoftHSM does (it answers
// CKR_OBJECT_HANDLE_INVALID when both a bad handle and a bad mechanism are
// present), and SoftHSM is the reference applications are in practice written
// and debugged against. And it matches the progression resolveOperationKey
// already fixes for its own callers — login, then key handle, then key usage —
// so the whole check reads coarsest-to-finest with the mechanism, the most
// specific property of the request, last.
//
// The competing argument, that mechanism-first avoids confirming to a caller
// that a handle exists, does not survive resolveOperationKey: CKF_LOGIN_REQUIRED
// is enforced before any handle is looked up, so an unauthenticated session
// still learns nothing, and a logged-in session can probe handles with
// C_GetAttributeValue regardless.
func validateInitMechanism(mechanism *Mechanism) CK_RV {
	if mechanism == nil {
		return CKR_ARGUMENTS_BAD
	}
	if GetMechanismDescriptor(mechanism.Type) == nil {
		return CKR_MECHANISM_INVALID
	}
	return CKR_OK
}

// primarySlotID returns the slot that owns objects created outside any session,
// such as the PIV objects that mirror a card's slot contents. The lowest slot
// ID is the module's default token (SlotManager always provisions slot 0), and
// scoping these objects to it keeps them reachable from ordinary sessions while
// still giving every object a definite owning token.
func (m *Module) primarySlotID() SlotID {
	slots := m.slotManager.GetSlotList(false)
	if len(slots) == 0 {
		return 0
	}

	lowest := slots[0]
	for _, slotID := range slots[1:] {
		if slotID < lowest {
			lowest = slotID
		}
	}
	return lowest
}

// destroyTokenObjects destroys every destroyable object belonging to the given
// token and removes it from persistent storage, as C_InitToken requires.
// Objects on other slots are untouched.
// destroyTokenObjects removes every destroyable token object from memory and
// from the store. It returns the first persistent-delete error encountered, so
// C_InitToken can refuse rather than leave an object on disk that the next
// C_Initialize would resurrect under a token the administrator believes empty.
func (m *Module) destroyTokenObjects(slotID SlotID) error {
	var firstErr error
	for _, handle := range m.objectManager.DestroyAllDestroyableObjects(slotID) {
		if m.storage != nil {
			if err := m.storage.DeleteObject(handle); err != nil {
				m.logStorageError("delete object during token initialization", err)
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}

// requireLogin enforces the token's CKF_LOGIN_REQUIRED policy. A token that
// advertises the flag must not perform key-bearing operations for a session
// that has not authenticated.
func (m *Module) requireLogin(slotID SlotID, session *Session) CK_RV {
	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil || slot.Token == nil {
		// Not CKR_TOKEN_NOT_PRESENT. PKCS#11 v3.2 §5.1.7 is explicit:
		// "functions that use a session handle (i.e., most functions!) never
		// return the error code CKR_TOKEN_NOT_PRESENT (they return
		// CKR_SESSION_HANDLE_INVALID instead)." Every caller of this helper
		// reached it through a session handle, and §5.1.2 describes exactly
		// this case — removing a token closes all sessions with it, so a
		// session whose token has gone is a stale handle rather than an absent
		// slot. The code is also absent from these functions' return tables.
		return CKR_SESSION_HANDLE_INVALID
	}
	if slot.Token.Info.Flags&CKF_LOGIN_REQUIRED == 0 {
		return CKR_OK
	}
	if session == nil || (!session.IsUserLoggedIn() && !session.IsSOLoggedIn()) {
		return CKR_USER_NOT_LOGGED_IN
	}
	return CKR_OK
}

// cachedResult returns the cached output of a terminal operation when the
// application has already run it, so a repeated call after a length query or a
// CKR_BUFFER_TOO_SMALL does not execute the backend operation twice.
// The replay MUST come after requireOperationAuthorization, never before it.
// PKCS#11 v3.2 §5.2's two-call convention means a terminal operation computes
// its output on the length query and hands it to the application only on the
// second call, so a C_Logout in between withdraws the authorization while the
// output is still held here. A replay placed first returned that output under
// CKR_OK with the guard never reached — C_Login, C_DecryptInit on a private
// key, C_Decrypt(NULL_PTR), C_Logout, C_Decrypt(buf) recovered plaintext the
// session was no longer entitled to. The legitimate sequence is unaffected: no
// logout means no revocation, and the same bytes are still returned without
// re-running the operation.
func cachedResult(session *Session, opType OperationType) ([]byte, bool) {
	op := session.GetOperationByType(opType)
	if op == nil || !op.ResultReady {
		return nil, false
	}
	return op.Result, true
}

// cacheResult stores the output of a terminal operation without terminating it.
// The operation stays active until the caller confirms it received the output
// by calling FinishOperation.
func cacheResult(session *Session, opType OperationType, result []byte) {
	if op := session.GetOperationByType(opType); op != nil {
		// Cache a copy: the same bytes are returned to the caller, and the
		// cache is zeroized when the operation ends. Sharing one backing array
		// would let that zeroization wipe the buffer the caller is still
		// holding.
		op.Result = copyBytes(result)
		op.ResultReady = true
		session.SetOperationByType(opType, op)
	}
}

// releaseResult discards a cached terminal result and rearms the underlying
// crypto operation, so the next call processes its own input instead of
// replaying the previous output.
//
// Resetting the CryptoOp rather than tearing it down and rebuilding it is what
// keeps the mechanism parameters intact. CryptoOperation.Reset clears the
// buffered data and the finalized flag while leaving baseOperation.mechanism in
// place, so an RSA-PSS message process keeps its CK_RSA_PKCS_PSS_PARAMS across
// messages. Re-initializing from OperationState instead would lose them:
// OperationState records only the mechanism TYPE, which is the same gap that
// once made C_Sign discard C_SignInit's PSS parameters.
func releaseResult(session *Session, opType OperationType) {
	op := session.GetOperationByType(opType)
	if op == nil {
		return
	}
	enclave.Wipe(op.Result)
	op.Result = nil
	op.ResultReady = false
	if cryptoOp, ok := op.CryptoOp.(CryptoOperation); ok && cryptoOp != nil {
		cryptoOp.Reset()
	}
	session.SetOperationByType(opType, op)
}

// ReleaseOperationResult discards the cached output of a terminal operation
// while leaving the operation itself initialized.
//
// The message-based functions need this where the single-shot functions need
// FinishOperation. C_SignMessage and C_EncryptMessage run under a
// C_MessageSignInit or C_MessageEncryptInit that stays live across many
// messages until its C_Message*Final (v3.0 §5.20), so terminating the operation
// after one message would break the next one. But the cached result must still
// be dropped: the cache exists only to make the §5.2 two-call sequence return
// the same bytes twice, and carrying it into the following message would return
// the previous message's output under CKR_OK.
//
// The caller at the C boundary invokes this exactly once, after it has copied
// the output out — the same contract as FinishOperation, and for the same
// reason: only it knows whether this call was a length query, a
// CKR_BUFFER_TOO_SMALL, or the real collection.
func (m *Module) ReleaseOperationResult(sessionHandle SessionHandle, opType OperationType) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	releaseResult(session, opType)

	return CKR_OK
}

// FinishOperation terminates a cryptographic operation once the caller has
// successfully received its output.
//
// PKCS#11 v3.2 §5.2 requires the operation to survive a length query
// (pBuf == NULL_PTR) and a CKR_BUFFER_TOO_SMALL result so the application can
// retry with a correctly sized buffer. Only the caller sitting at the C
// boundary knows which of those happened, so terminating the operation is its
// responsibility: it must call this exactly once, after it has copied the
// output out.
func (m *Module) FinishOperation(sessionHandle SessionHandle, opType OperationType) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	if err := sm.FinalizeOperationType(sessionHandle, opType); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// terminateInitOperation applies the NULL-mechanism contract that PKCS#11 v3.2
// gives every operation initializer.
//
// PKCS#11 v3.2 §5.13.1 states it for C_SignInit: "C_SignInit can be called with
// pMechanism set to NULL_PTR to terminate an active signature operation. If an
// operation has been initialized and it cannot be cancelled,
// CKR_OPERATION_CANCEL_FAILED must be returned." The same sentence, with the
// operation renamed, appears for C_EncryptInit (§5.8.1), C_MessageEncryptInit
// (§5.9.1), C_DecryptInit (§5.10.1), C_DigestInit (§5.12.1), C_SignRecoverInit
// (§5.13.5), C_VerifyInit (§5.15.1), C_VerifyRecoverInit (§5.15.5) and
// C_VerifySignatureInit (§5.15.7), which is why CKR_OPERATION_CANCEL_FAILED
// appears in each of their return tables. C_MessageDecryptInit (§5.11.1) lists
// CKR_OPERATION_CANCEL_FAILED in its return table without restating the
// sentence, and C_MessageSignInit (§5.14.1) and C_MessageVerifyInit (§5.16.1)
// state neither. All four message-based initializers are otherwise defined in
// parallel, so treating the two omissions as editorial keeps a single rule for
// the whole family.
//
// The rule lives here rather than at the C boundary because this is the API an
// application-facing caller reaches: a Go consumer of Module and the cgo shim
// must answer a NULL mechanism identically, and one implementation is the only
// way to guarantee that.
//
// The caller must not hold m.mu: termination runs through FinishOperation,
// which takes the lock itself. Routing through FinishOperation is deliberate —
// it is already the module's one way to end a single operation category, and it
// is the primitive C_SessionCancel uses, so a second cancellation path would be
// free to drift from the one C_SessionCancel is tested against.
func (m *Module) terminateInitOperation(sessionHandle SessionHandle, opType OperationType) CK_RV {
	switch rv := m.FinishOperation(sessionHandle, opType); rv {
	case CKR_OK, CKR_OPERATION_NOT_INITIALIZED:
		// Cancelling when nothing is active is CKR_OK, not
		// CKR_OPERATION_NOT_INITIALIZED. The spec makes only the *failure* to
		// cancel an error, and C_SessionCancel — the function written expressly
		// to cancel operations — says in §5.6.5 that a flag naming an
		// uninitialized operation "will be ignored and C_SessionCancel will
		// behave as if the operation flag was not set". The caller's
		// postcondition, that no operation of this category is active, holds
		// either way, so reporting an error would describe a state the caller
		// asked for.
		return CKR_OK

	case CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED:
		// The library or the session, not the operation, is what could not be
		// resolved. Each of these codes is listed in the initializers' return
		// tables, whereas answering CKR_OPERATION_CANCEL_FAILED here would tell
		// the application its token refused a cancellation that was never
		// attempted.
		return rv

	default:
		// "If an operation has been initialized and it cannot be cancelled,
		// CKR_OPERATION_CANCEL_FAILED must be returned." Anything else reported
		// is a refusal to end the operation, which is exactly what that code
		// names. C_SessionCancel treats the same class of failure the same way.
		return CKR_OPERATION_CANCEL_FAILED
	}
}

// terminalKeyGoneRV is the CK_RV a terminal cryptographic function returns when
// the key its C_*Init bound can no longer be resolved — destroyed, or no longer
// visible to the session — between initialization and this call.
//
// CKR_KEY_HANDLE_INVALID is the obvious description and is what these functions
// used to return, but it is absent from the return table of every one of them:
// PKCS#11 v3.2 lists it for the initializers, which are the functions that take
// a key handle as an argument, and C_Sign, C_SignRecover, C_Verify, C_Encrypt
// and C_Decrypt take none. §5.1 requires a function to return a value from its
// own table, so the code had to come from what these tables do offer, which is
// CKR_OPERATION_NOT_INITIALIZED or CKR_FUNCTION_FAILED.
//
// CKR_FUNCTION_FAILED is the honest of the two. §5.1 defines it as "the
// requested function could not be performed, but detailed information about why
// is not available", which is exactly this case. Answering
// CKR_OPERATION_NOT_INITIALIZED would assert that the application never called
// the matching C_*Init, which is false — it did, and the module accepted it.
// Each of these sites terminates the operation before returning, so the
// application's recovery is the same either way: initialize again.
const terminalKeyGoneRV = CKR_FUNCTION_FAILED

// requireOperationAuthorization enforces that the authentication an active
// operation was initialized under is still in force, and is the guard every
// function that continues an operation applies before it touches the key.
//
// C_Logout withdraws that authentication and invalidates the handles to the
// private objects it covered (PKCS#11 v3.2 §5.6.10), so an operation caught in
// that window must not complete — not even if the application has logged in
// again in the meantime, because the new session is a different authentication
// than the one the caller's C_*Init was accepted under. Completing it would
// produce a signature or a plaintext with a key the application is no longer
// entitled to use, which is the failure that stays silent: the call returns
// CKR_OK and the result is indistinguishable from an authorized one.
//
// CKR_USER_NOT_LOGGED_IN names the condition and appears in the return table of
// every function guarded here: C_Sign and C_SignUpdate/C_SignFinal (§5.13),
// C_SignRecover (§5.13.6), C_Verify and its update/final (§5.14),
// C_VerifyRecover (§5.15.6), C_Encrypt and its update/final (§5.9), C_Decrypt
// and its update/final (§5.10). Reporting terminalKeyGoneRV instead would
// flatten a diagnosable authentication failure into CKR_FUNCTION_FAILED — the
// same value the C ABI substitutes for an escaped panic — leaving the
// application unable to tell "log in again" from "the token malfunctioned".
//
// The revoked operation is terminated, so recovery is to log in and initialize
// again.
func requireOperationAuthorization(session *Session, opType OperationType, op *OperationState) CK_RV {
	if op == nil || !op.AuthRevoked {
		return CKR_OK
	}
	session.ClearOperationType(opType)
	return CKR_USER_NOT_LOGGED_IN
}

// requireContextAuthentication enforces CKA_ALWAYS_AUTHENTICATE for a use of a
// key by an operation that was initiated with it.
//
// PKCS#11 v3.2 §4.10 forces re-authentication "for each use of a private key",
// where "'Use' in this case means a cryptographic operation such as sign or
// decrypt", and prescribes one way to give it: "calling C_Login with userType
// set to CKU_CONTEXT_SPECIFIC immediately after a cryptographic operation using
// the key has been initiated (e.g. after C_SignInit)", which "sets the active
// key in an authenticated state". The authorization is therefore a property of
// one key and one initiated operation. It is consumed here so it covers exactly
// one use, and it must have been granted for this key: a grant minted while
// another key's operation was active does not answer for this one.
//
// The gate applies only where §4.10's protocol can be run, which is why the
// active operation is checked as well as the attribute. It gates C_Sign,
// C_SignFinal, C_SignRecover, C_Decrypt and C_DecryptFinal, where the operation
// the spec anchors on exists, and it is not called at all from C_UnwrapKey,
// C_UnwrapKeyAuthenticated or C_DecapsulateKey.
//
// The two *Final verbs are as much a part of that list as the single-part ones,
// and §4.10 names C_SignFinal itself when it describes how long the
// authenticated state lasts. They were once absent from it, which left the
// attribute inert on the ordinary multi-part path — C_SignInit / C_SignUpdate /
// C_SignFinal completed with no re-authentication requested or required — while
// this comment claimed otherwise. The list above and the call sites have to be
// read together, so a divergence between them is a defect in both.
//
// Those three have no Init phase, so an application can never issue the login
// §4.10 prescribes for them: C_Login(CKU_CONTEXT_SPECIFIC) answers
// CKR_OPERATION_NOT_INITIALIZED while only such a call is pending. They are
// also key-management functions rather than the sign or decrypt §4.10 defines a
// "use" as, and gating them would refuse a legal operation on every correctly
// configured key — one marked CKA_UNWRAP without CKA_DECRYPT can never have a
// decryption operation active.
//
// Calling it from them was worse than useless. Nothing stops an application
// from unwrapping with a key while a decryption it initiated with that same key
// is still active, and in that one reachable case the gate found a grant minted
// for the decryption and spent it on the unwrap: the application's own
// C_Decrypt then failed CKR_USER_NOT_LOGGED_IN, indistinguishable from a wrong
// PIN. §4.10 forbids that directly — a successful re-authentication "sets the
// active key in an authenticated state that lasts until the cryptographic
// operation has successfully or unsuccessfully been completed (e.g. by C_Sign,
// C_SignFinal,..)" — so the grant is the property of the operation it was
// granted for, and no other call may end it. That is the cross-operation theft
// the key binding above exists to prevent, one verb further out, and it is why
// those call sites are gone rather than merely unreachable.
func requireContextAuthentication(session *Session, opType OperationType, key *Object) CK_RV {
	if key == nil || !boolAttributeIsTrue(key.GetAttribute(CKA_ALWAYS_AUTHENTICATE)) {
		return CKR_OK
	}
	activeKey, active := session.ActiveOperationKey(opType)
	if !active || activeKey != key.Handle {
		return CKR_OK
	}
	if !session.ConsumeContextAuthentication(opType, key.Handle) {
		return CKR_USER_NOT_LOGGED_IN
	}
	return CKR_OK
}

// contextAuthTarget names an initiated operation whose key requires
// re-authentication: the operation category, and the key a
// C_Login(CKU_CONTEXT_SPECIFIC) authenticates within it.
type contextAuthTarget struct {
	opType    OperationType
	keyHandle ObjectHandle
}

// contextAuthenticationTargets collects the operations a
// C_Login(CKU_CONTEXT_SPECIFIC) on this session would authenticate, and refuses
// the login when there are none.
//
// PKCS#11 v3.2 §4.10 places re-authentication "immediately after a
// cryptographic operation using the key has been initiated" and says that in
// that call "the actual user type is implicitly given by the usage requirements
// of the active key", so the login means something only when an operation is
// active and its key carries CKA_ALWAYS_AUTHENTICATE. The same section fixes the
// answer when it does not: "C_Login will return CKR_OPERATION_NOT_INITIALIZED
// ... if an attempt is made to re-authenticate when CKA_ALWAYS_AUTHENTICATE is
// set to CK_FALSE."
//
// The key handle travels with the category because the grant is bound to it.
// Granting for a category alone let one key's re-authentication satisfy
// another's requirement: a C_DecryptInit on a key with no
// CKA_ALWAYS_AUTHENTICATE minted a decryption grant that a key carrying the
// attribute then spent.
func (m *Module) contextAuthenticationTargets(session *Session) ([]contextAuthTarget, CK_RV) {
	targets := make([]contextAuthTarget, 0, len(contextAuthOperations))

	for opType := range contextAuthOperations {
		keyHandle, active := session.ActiveOperationKey(opType)
		if !active {
			continue
		}

		// A handle the object store no longer resolves names no active key, so
		// there is nothing this login could authenticate for it. The operation
		// itself fails on its own terms when it next runs.
		key, err := m.objectManager.getObjectUnchecked(keyHandle)
		if err != nil {
			continue
		}
		if !boolAttributeIsTrue(key.GetAttribute(CKA_ALWAYS_AUTHENTICATE)) {
			continue
		}

		targets = append(targets, contextAuthTarget{opType: opType, keyHandle: keyHandle})
	}

	if len(targets) == 0 {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	return targets, CKR_OK
}

// loginContextSpecific performs the CKU_CONTEXT_SPECIFIC half of C_Login and
// C_LoginUser.
//
// Both functions name the same user type and must answer alike. They used to
// disagree: C_LoginUser demanded an active operation and answered
// CKR_OPERATION_NOT_INITIALIZED without one, while C_Login required nothing,
// granted nothing and returned CKR_OK. C_Login is the function PKCS#11 v3.2
// §4.10 names, so an application following the specification was told its
// re-authentication had succeeded and then failed the key's own use with
// CKR_USER_NOT_LOGGED_IN, with nothing to distinguish that from a wrong PIN.
//
// C_Login's own description settles it: "If the user type is
// CKU_CONTEXT_SPECIFIC, the behavior of C_Login depends on the context in which
// it is called. Improper use of this user type will result in a return value
// CKR_OPERATION_NOT_INITIALIZED" (§5.6.8), and the same section allows the
// repeated login "if (and only if) a key with the CKA_ALWAYS_AUTHENTICATE
// attribute set to CK_TRUE exists, and the user needs to do cryptographic
// operation on this key". CKR_OPERATION_NOT_INITIALIZED is in that function's
// return table.
func (m *Module) loginContextSpecific(sm *SessionManager, sessionHandle SessionHandle, session *Session, pin []byte) CK_RV {
	// The operation precondition is settled before the PIN is offered, so a
	// login that could not have authenticated anything does not spend an attempt
	// from the lockout budget.
	targets, rv := m.contextAuthenticationTargets(session)
	if rv != CKR_OK {
		return rv
	}

	// The session manager owns the token's login state and the PIN verifier, and
	// validates the user PIN without disturbing either.
	if err := sm.Login(sessionHandle, CKU_CONTEXT_SPECIFIC, pin); err != nil {
		return FromError(err)
	}

	for _, target := range targets {
		session.GrantContextAuthentication(target.opType, target.keyHandle)
	}

	return CKR_OK
}

// SignInit initializes a signing operation.
// Implements C_SignInit behavior per PKCS#11 specification.
func (m *Module) SignInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// PKCS#11 v3.2 §5.13.1: "C_SignInit can be called with pMechanism set to
	// NULL_PTR to terminate an active signature operation."
	if mechanism == nil {
		return m.terminateInitOperation(sessionHandle, OperationSign)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Get the key object, enforcing visibility, login and CKA_SIGN
	obj, rv := m.resolveOperationKey(slotID, sessionHandle, session, keyHandle, CKA_SIGN, mechanism)
	if rv != CKR_OK {
		return rv
	}

	// Key first, then mechanism; validateInitMechanism documents why.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return rv
	}

	// Initialize the operation in the session manager
	if err := sm.InitializeOperation(sessionHandle, OperationSign, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	// An ML-DSA key that this token generated holds its own material and names
	// no backend key, so it is signed in process rather than over the
	// transport. See holdsOwnQuantumSignatureMaterial for why.
	if handled, rv := m.quantumSignInit(session, mechanism, keyHandle, obj); handled {
		if rv != CKR_OK {
			_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		}
		return rv
	}

	// Create crypto operation and store in session state
	signOp, cryptoErr := m.cryptoManager.SignInit(mechanism, keyHandle, obj.KeyID, obj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return FromError(cryptoErr)
	}
	// The raw ECDSA signature is sized from the key's curve, not from the
	// numbers in the signature (v3.2 §6.3.1).
	signOp.SetECFieldLen(ecFieldLenForParams(obj.GetAttribute(CKA_EC_PARAMS)))

	// Store the crypto operation in session state for multi-part ops
	opState := session.GetOperationByType(OperationSign)
	if opState != nil {
		opState.CryptoOp = signOp
		session.SetOperationByType(OperationSign, opState)
	}

	return CKR_OK
}

// Sign signs data in a single operation.
// Implements C_Sign behavior per PKCS#11 specification.
func (m *Module) Sign(sessionHandle SessionHandle, data []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState := session.GetOperationByType(OperationSign)
	if opState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationSign, opState); rv != CKR_OK {
		return nil, rv
	}

	// A repeated call after a length query returns the same signature without
	// re-running the backend operation. It follows the authorization check
	// rather than preceding it; see cachedResult.
	if signature, ok := cachedResult(session, OperationSign); ok {
		return signature, CKR_OK
	}

	// C_Sign must follow C_SignInit with no intervening C_SignUpdate: it
	// cannot terminate a multi-part operation (v3.2 §5.14.3).
	// Data holds AEAD associated data, not buffered parts, so MultiPart is
	// the only reliable marker that an *Update call has occurred.
	if opState.MultiPart {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return nil, CKR_OPERATION_ACTIVE
	}

	// Get key for signing
	obj, objErr := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), opState.KeyHandle)
	if objErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return nil, terminalKeyGoneRV
	}

	if rv := requireContextAuthentication(session, OperationSign, obj); rv != CKR_OK {
		return nil, rv
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// An in-process ML-DSA operation is claimed by the type of the operation
	// C_SignInit stored, and produces its signature without a transport call.
	if signature, handled, rv := m.quantumSign(session, opState, data); handled {
		if rv != CKR_OK {
			_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
			return nil, rv
		}
		return signature, CKR_OK
	}

	// Reuse the operation C_SignInit built. Rebuilding it here from
	// opState.Mechanism alone discarded every mechanism parameter, because
	// OperationState carries only the mechanism TYPE -- the CK_MECHANISM's
	// pParameter lives on the crypto operation that C_SignInit stored. RSA-PSS
	// showed it plainly: C_SignInit validated the caller's
	// CK_RSA_PKCS_PSS_PARAMS and then C_Sign re-initialized without them and
	// failed with CKR_MECHANISM_PARAM_INVALID. Any mechanism whose behaviour
	// depends on its parameters was affected; PSS merely had validation strict
	// enough to notice rather than silently signing under the wrong salt.
	signOp, ok := opState.CryptoOp.(*SignOperation)
	if !ok || signOp == nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	signature, signErr := m.cryptoManager.Sign(ctx, signOp, data)
	if signErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return nil, FromError(signErr)
	}

	// The operation stays active until the caller confirms it received the
	// signature with FinishOperation.
	cacheResult(session, OperationSign, signature)

	return signature, CKR_OK
}

// SignUpdate continues a multiple-part signing operation.
// Implements C_SignUpdate behavior per PKCS#11 specification.
func (m *Module) SignUpdate(sessionHandle SessionHandle, data []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationSign)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationSign {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationSign, opState); rv != CKR_OK {
		return rv
	}

	// An in-process ML-DSA operation accumulates the part here and signs
	// everything at C_SignFinal, because ML-DSA signs the message itself.
	if handled, rv := m.quantumSignUpdate(session, opState, data); handled {
		if rv != CKR_OK {
			_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		}
		return rv
	}

	// Get the stored sign operation
	signOp, ok := opState.CryptoOp.(*SignOperation)
	if !ok || signOp == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// Update with data
	if err := m.cryptoManager.SignUpdate(signOp, data); err != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return FromError(err)
	}

	// Update session state with the modified operation
	opState.MultiPart = true
	opState.CryptoOp = signOp
	session.SetOperationState(*opState)

	return CKR_OK
}

// SignFinal finishes a multiple-part signing operation.
// Implements C_SignFinal behavior per PKCS#11 specification.
func (m *Module) SignFinal(sessionHandle SessionHandle) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationSign)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationSign {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationSign, opState); rv != CKR_OK {
		return nil, rv
	}

	// A repeated call after a length query returns the cached output without
	// re-running the backend operation. It follows the authorization check
	// rather than preceding it; see cachedResult.
	if out, done := cachedResult(session, OperationSign); done {
		return out, CKR_OK
	}

	// CKA_ALWAYS_AUTHENTICATE gates the terminal call of a multi-part signature
	// exactly as it gates C_Sign. §4.10 anchors the requirement on the
	// operation, and names this verb explicitly: the authenticated state "lasts
	// until the cryptographic operation has successfully or unsuccessfully been
	// completed (e.g. by C_Sign, C_SignFinal,..)". Leaving it out made the
	// attribute inert for every signature larger than one buffer, because
	// C_SignInit / C_SignUpdate / C_SignFinal reached the backend without the
	// application even being asked to re-authenticate — the same sidestep the
	// gate on C_SignRecover exists to close, through the more obvious door.
	//
	// It sits after the cached-result check on purpose. A length query followed
	// by the real call is one use of the key, and §4.10 grants the state for
	// one operation, so letting the replay consume the grant a second time
	// would fail the caller's second call with CKR_USER_NOT_LOGGED_IN for a
	// re-authentication it performed correctly.
	if obj, objErr := m.objectManager.GetObjectFor(
		NewAccessContext(sessionHandle, session), opState.KeyHandle); objErr == nil {
		if rv := requireContextAuthentication(session, OperationSign, obj); rv != CKR_OK {
			return nil, rv
		}
	}

	// An in-process ML-DSA operation signs everything C_SignUpdate accumulated.
	if signature, handled, rv := m.quantumSignFinal(session, opState); handled {
		if rv != CKR_OK {
			_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
			return nil, rv
		}
		return signature, CKR_OK
	}

	signOp, ok := opState.CryptoOp.(*SignOperation)
	if !ok || signOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	signature, signErr := m.cryptoManager.SignFinal(ctx, signOp)
	if signErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return nil, FromError(signErr)
	}

	// The operation stays active until the caller confirms it received the
	// output with FinishOperation, per the two-call convention (v3.2 §5.2).
	cacheResult(session, OperationSign, signature)

	return signature, CKR_OK
}

// SignRecoverInit initializes a signing operation where the data can be
// recovered from the signature.
// Implements C_SignRecoverInit behavior per PKCS#11 specification.
func (m *Module) SignRecoverInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// PKCS#11 v3.2 §5.13.5: "C_SignRecoverInit can be called with pMechanism
	// set to NULL_PTR to terminate an active signature with data recovery
	// operation."
	if mechanism == nil {
		return m.terminateInitOperation(sessionHandle, OperationSign)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// The gating attribute is CKA_SIGN_RECOVER, not CKA_SIGN: a key that can
	// sign normally need not support the recover variant (v3.2 §5.14.5).
	keyObj, rv := m.resolveOperationKey(slotID, sessionHandle, session, keyHandle, CKA_SIGN_RECOVER, mechanism)
	if rv != CKR_OK {
		return rv
	}

	// Key first, then mechanism; validateInitMechanism documents why. The
	// module-wide check runs before the recover-specific one so a mechanism
	// withheld in FIPS mode is refused here rather than by a table that knows
	// nothing about the policy.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return rv
	}

	// Check if mechanism supports sign recover
	if !m.mechanismSupportsSignRecover(mechanism.Type) {
		return CKR_MECHANISM_INVALID
	}

	sm := m.sessionManagers[slotID]
	if sm == nil {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Reserve the operation slot before doing any work, so an already-active
	// signing operation is reported as CKR_OPERATION_ACTIVE instead of being
	// silently replaced.
	if err := sm.InitializeOperation(sessionHandle, OperationSign, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	signOp, cryptoErr := m.cryptoManager.SignInit(mechanism, keyHandle, keyObj.KeyID, keyObj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return FromError(cryptoErr)
	}
	signOp.SetECFieldLen(ecFieldLenForParams(keyObj.GetAttribute(CKA_EC_PARAMS)))

	// Mark this as a sign-recover operation
	signOp.IsRecover = true

	if opState := session.GetOperationByType(OperationSign); opState != nil {
		opState.CryptoOp = signOp
		session.SetOperationByType(OperationSign, opState)
	}

	return CKR_OK
}

// SignRecover signs data where the data can be recovered from the signature.
// Implements C_SignRecover behavior per PKCS#11 specification.
func (m *Module) SignRecover(sessionHandle SessionHandle, data []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationSign)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationSign {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationSign, opState); rv != CKR_OK {
		return nil, rv
	}

	// A repeated call after a length query returns the cached output without
	// re-running the backend operation. It follows the authorization check
	// rather than preceding it; see cachedResult.
	if out, done := cachedResult(session, OperationSign); done {
		return out, CKR_OK
	}

	signOp, ok := opState.CryptoOp.(*SignOperation)
	if !ok || signOp == nil || !signOp.IsRecover {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// CKA_ALWAYS_AUTHENTICATE applies to every use of the key, so recovering a
	// signature must consume a re-authentication just as C_Sign does. Without
	// this the requirement could be sidestepped by driving the private key
	// through C_SignRecover instead.
	keyObj, keyErr := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), opState.KeyHandle)
	if keyErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return nil, terminalKeyGoneRV
	}
	if rv := requireContextAuthentication(session, OperationSign, keyObj); rv != CKR_OK {
		return nil, rv
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// For RSA, sign-recover uses raw RSA (no padding) so data can be recovered
	// The signature contains the original data that can be decrypted with public key
	signature, signErr := m.cryptoManager.Sign(ctx, signOp, data)
	if signErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationSign)
		return nil, FromError(signErr)
	}

	// The operation stays active until the caller confirms it received the
	// output with FinishOperation, per the two-call convention (v3.2 §5.2).
	cacheResult(session, OperationSign, signature)

	return signature, CKR_OK
}

// VerifyInit initializes a verification operation.
// Implements C_VerifyInit behavior per PKCS#11 specification.
func (m *Module) VerifyInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// PKCS#11 v3.2 §5.15.1: "C_VerifyInit can be called with pMechanism set to
	// NULL_PTR to terminate an active verification operation."
	if mechanism == nil {
		return m.terminateInitOperation(sessionHandle, OperationVerify)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	obj, rv := m.resolveOperationKey(slotID, sessionHandle, session, keyHandle, CKA_VERIFY, mechanism)
	if rv != CKR_OK {
		return rv
	}

	// Key first, then mechanism; validateInitMechanism documents why.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return rv
	}

	if err := sm.InitializeOperation(sessionHandle, OperationVerify, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	// The exact counterpart of the C_SignInit hook: an ML-DSA public key this
	// token generated carries its own material and is verified in process.
	if handled, rv := m.quantumVerifyInit(session, mechanism, keyHandle, obj); handled {
		if rv != CKR_OK {
			_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		}
		return rv
	}

	// C_VerifyInit needs the plain-verify capability specifically. The crypto
	// layer's constructor also serves C_VerifyRecoverInit and so admits either
	// flag; without this check a verify-recover-only mechanism such as
	// CKM_RSA_X_509 would be accepted here and then verified under the wrong
	// scheme (v3.2 §5.15.1).
	if desc := GetMechanismDescriptor(mechanism.Type); desc == nil || desc.Flags&CKF_VERIFY == 0 {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return CKR_MECHANISM_INVALID
	}

	verifyOp, cryptoErr := m.cryptoManager.VerifyInit(mechanism, keyHandle, obj.KeyID, obj.BackendName)
	verifyOp.SetECFieldLen(ecFieldLenForParams(obj.GetAttribute(CKA_EC_PARAMS)))
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return FromError(cryptoErr)
	}

	// Store the crypto operation in session state for multi-part ops
	opState := session.GetOperationByType(OperationVerify)
	if opState != nil {
		opState.CryptoOp = verifyOp
		session.SetOperationByType(OperationVerify, opState)
	}

	return CKR_OK
}

// Verify verifies a signature in a single operation.
// Implements C_Verify behavior per PKCS#11 specification.
func (m *Module) Verify(sessionHandle SessionHandle, data, signature []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationVerify)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationVerify {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// C_Verify cannot terminate a multiple-part operation (v3.2 §5.14.6): it
	// starts a fresh verification below, so buffered parts would be dropped and
	// a signature over the whole message would be reported invalid.
	if opState.MultiPart {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return CKR_OPERATION_ACTIVE
	}

	if rv := requireOperationAuthorization(session, OperationVerify, opState); rv != CKR_OK {
		return rv
	}

	// The key is resolved through the session's access context so a session
	// that may no longer see the key cannot complete a verification it started.
	if _, objErr := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), opState.KeyHandle); objErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return terminalKeyGoneRV
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// An in-process ML-DSA operation terminates here exactly as the transport
	// path does: C_Verify's whole answer is its return value.
	if handled, rv := m.quantumVerify(opState, data, signature); handled {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return rv
	}

	// Reuse the operation C_VerifyInit built, for the same reason C_Sign does:
	// OperationState holds only the mechanism type, so re-initializing here
	// would drop the CK_MECHANISM parameters the caller supplied and verify
	// under a different scheme than the one it named.
	verifyOp, ok := opState.CryptoOp.(*VerifyOperation)
	if !ok || verifyOp == nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return CKR_OPERATION_NOT_INITIALIZED
	}

	verifyErr := m.cryptoManager.Verify(ctx, verifyOp, data, signature)
	_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)

	if verifyErr != nil {
		return FromError(verifyErr)
	}

	return CKR_OK
}

// VerifyUpdate continues a multiple-part verification operation.
// Implements C_VerifyUpdate behavior per PKCS#11 specification.
func (m *Module) VerifyUpdate(sessionHandle SessionHandle, data []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationVerify)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationVerify {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationVerify, opState); rv != CKR_OK {
		return rv
	}

	// An in-process ML-DSA operation accumulates the part here and verifies
	// everything at C_VerifyFinal.
	if handled, rv := m.quantumVerifyUpdate(session, opState, data); handled {
		if rv != CKR_OK {
			_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		}
		return rv
	}

	verifyOp, ok := opState.CryptoOp.(*VerifyOperation)
	if !ok || verifyOp == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if err := m.cryptoManager.VerifyUpdate(verifyOp, data); err != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return FromError(err)
	}

	opState.MultiPart = true
	opState.CryptoOp = verifyOp
	session.SetOperationState(*opState)

	return CKR_OK
}

// VerifyFinal finishes a multiple-part verification operation.
// Implements C_VerifyFinal behavior per PKCS#11 specification.
func (m *Module) VerifyFinal(sessionHandle SessionHandle, signature []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationVerify)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationVerify {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationVerify, opState); rv != CKR_OK {
		return rv
	}

	// An in-process ML-DSA operation verifies the signature against everything
	// C_VerifyUpdate accumulated, and terminates as the transport path does.
	if handled, rv := m.quantumVerifyFinal(opState, signature); handled {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return rv
	}

	verifyOp, ok := opState.CryptoOp.(*VerifyOperation)
	if !ok || verifyOp == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	verifyErr := m.cryptoManager.VerifyFinal(ctx, verifyOp, signature)
	_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)

	if verifyErr != nil {
		return FromError(verifyErr)
	}

	return CKR_OK
}

// VerifyRecoverInit initializes a verification operation where the data can be
// recovered from the signature.
// Implements C_VerifyRecoverInit behavior per PKCS#11 specification.
func (m *Module) VerifyRecoverInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// PKCS#11 v3.2 §5.15.5: "C_VerifyRecoverInit can be called with pMechanism
	// set to NULL_PTR to terminate an active verification with data recovery
	// operation."
	if mechanism == nil {
		return m.terminateInitOperation(sessionHandle, OperationVerify)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	keyObj, rv2 := m.resolveOperationKey(slotID, sessionHandle, session, keyHandle, CKA_VERIFY_RECOVER, mechanism)
	if rv2 != CKR_OK {
		return rv2
	}

	// Key first, then mechanism; validateInitMechanism documents why. The
	// module-wide check runs before the recover-specific one so a mechanism
	// withheld in FIPS mode is refused here rather than by a table that knows
	// nothing about the policy.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return rv
	}

	// Check if mechanism supports verify recover
	if !m.mechanismSupportsVerifyRecover(mechanism.Type) {
		return CKR_MECHANISM_INVALID
	}

	sm := m.sessionManagers[slotID]
	if sm == nil {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Reserve the operation slot first so an already-active verify operation is
	// reported as CKR_OPERATION_ACTIVE rather than silently replaced.
	if err := sm.InitializeOperation(sessionHandle, OperationVerify, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	// C_VerifyRecoverInit needs the recover capability specifically (v3.2
	// §5.15.5), for the reason C_VerifyInit gives about the shared constructor.
	if desc := GetMechanismDescriptor(mechanism.Type); desc == nil || desc.Flags&CKF_VERIFY_RECOVER == 0 {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return CKR_MECHANISM_INVALID
	}

	verifyOp, cryptoErr := m.cryptoManager.VerifyInit(mechanism, keyHandle, keyObj.KeyID, keyObj.BackendName)
	verifyOp.SetECFieldLen(ecFieldLenForParams(keyObj.GetAttribute(CKA_EC_PARAMS)))
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return FromError(cryptoErr)
	}

	// Mark this as a verify-recover operation
	verifyOp.IsRecover = true

	// For RSA verify-recover, extract the public key components from the key object
	modulus := keyObj.GetAttribute(CKA_MODULUS)
	pubExponent := keyObj.GetAttribute(CKA_PUBLIC_EXPONENT)
	if len(modulus) > 0 && len(pubExponent) > 0 {
		verifyOp.SetRSAPublicKey(modulus, pubExponent)
	}

	// Update session state
	opState := session.GetOperationByType(OperationVerify)
	if opState != nil {
		opState.Type = OperationVerify
		opState.CryptoOp = verifyOp
		session.SetOperationByType(OperationVerify, opState)
	}

	return CKR_OK
}

// VerifyRecover verifies a signature and recovers the signed data.
// Implements C_VerifyRecover behavior per PKCS#11 specification.
func (m *Module) VerifyRecover(sessionHandle SessionHandle, signature []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationVerify)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationVerify {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationVerify, opState); rv != CKR_OK {
		return nil, rv
	}

	// A repeated call after a length query returns the cached output without
	// re-running the backend operation. It follows the authorization check
	// rather than preceding it; see cachedResult.
	if out, done := cachedResult(session, OperationVerify); done {
		return out, CKR_OK
	}

	verifyOp, ok := opState.CryptoOp.(*VerifyOperation)
	if !ok || verifyOp == nil || !verifyOp.IsRecover {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// For RSA verify-recover, we decrypt the signature with the public key
	// to recover the original data that was signed
	recoveredData, verifyErr := m.cryptoManager.VerifyRecover(ctx, verifyOp, signature)
	if verifyErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationVerify)
		return nil, FromError(verifyErr)
	}

	// The operation stays active until the caller confirms it received the
	// output with FinishOperation, per the two-call convention (v3.2 §5.2).
	cacheResult(session, OperationVerify, recoveredData)

	return recoveredData, CKR_OK
}

// EncryptInit initializes an encryption operation.
// Implements C_EncryptInit behavior per PKCS#11 specification.
func (m *Module) EncryptInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// PKCS#11 v3.2 §5.8.1: "C_EncryptInit can be called with pMechanism set to
	// NULL_PTR to terminate an active encryption operation." The same call is
	// C_MessageEncryptInit's termination (§5.9.1), which delegates here.
	if mechanism == nil {
		return m.terminateInitOperation(sessionHandle, OperationEncrypt)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	obj, rv := m.resolveOperationKey(slotID, sessionHandle, session, keyHandle, CKA_ENCRYPT, mechanism)
	if rv != CKR_OK {
		return rv
	}

	// Key first, then mechanism; validateInitMechanism documents why.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return rv
	}

	if err := sm.InitializeOperation(sessionHandle, OperationEncrypt, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	encOp, cryptoErr := m.cryptoManager.EncryptInit(mechanism, keyHandle, obj.KeyID, obj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return FromError(cryptoErr)
	}

	// Store the crypto operation in session state for multi-part ops
	opState := session.GetOperationByType(OperationEncrypt)
	if opState != nil {
		opState.CryptoOp = encOp
		session.SetOperationByType(OperationEncrypt, opState)
	}

	return CKR_OK
}

// Encrypt encrypts data in a single operation.
// Implements C_Encrypt behavior per PKCS#11 specification.
func (m *Module) Encrypt(sessionHandle SessionHandle, plaintext []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState := session.GetOperationByType(OperationEncrypt)
	if opState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationEncrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	// A repeated call after a length query returns the cached ciphertext. This
	// matters beyond efficiency: re-running an AEAD encryption would consume a
	// second nonce for the same plaintext. It follows the authorization check
	// rather than preceding it; see cachedResult.
	if ciphertext, ok := cachedResult(session, OperationEncrypt); ok {
		return ciphertext, CKR_OK
	}

	// C_Encrypt cannot terminate a multi-part operation (v3.2 §5.9.2).
	// Data holds AEAD associated data, not buffered parts, so MultiPart is
	// the only reliable marker that an *Update call has occurred.
	if opState.MultiPart {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return nil, CKR_OPERATION_ACTIVE
	}

	if _, objErr := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), opState.KeyHandle); objErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return nil, terminalKeyGoneRV
	}

	// Reuse the operation C_EncryptInit built. Rebuilding one from the bare
	// mechanism type would discard the mechanism parameters the caller
	// supplied — the GCM IV and tag length, the CBC IV — and silently encrypt
	// under different ones.
	encOp, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || encOp == nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	ciphertext, encErr := m.cryptoManager.Encrypt(ctx, encOp, plaintext)
	if encErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return nil, FromError(encErr)
	}

	cacheResult(session, OperationEncrypt, ciphertext)

	return ciphertext, CKR_OK
}

// EncryptUpdate continues a multiple-part encryption operation.
// Implements C_EncryptUpdate behavior per PKCS#11 specification.
func (m *Module) EncryptUpdate(sessionHandle SessionHandle, plaintext []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationEncrypt)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationEncrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	encOp, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if err := m.cryptoManager.EncryptUpdate(encOp, plaintext); err != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return nil, FromError(err)
	}

	opState.MultiPart = true
	opState.CryptoOp = encOp
	session.SetOperationState(*opState)

	// For multi-part encryption with buffering, we return empty data
	// The actual ciphertext is returned in EncryptFinal
	return nil, CKR_OK
}

// EncryptFinal finishes a multiple-part encryption operation.
// Implements C_EncryptFinal behavior per PKCS#11 specification.
func (m *Module) EncryptFinal(sessionHandle SessionHandle) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationEncrypt)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationEncrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	// A repeated call after a length query returns the cached output without
	// re-running the backend operation. It follows the authorization check
	// rather than preceding it; see cachedResult.
	if out, done := cachedResult(session, OperationEncrypt); done {
		return out, CKR_OK
	}

	encOp, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	ciphertext, encErr := m.cryptoManager.EncryptFinal(ctx, encOp)
	if encErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return nil, FromError(encErr)
	}

	// The operation stays active until the caller confirms it received the
	// output with FinishOperation, per the two-call convention (v3.2 §5.2).
	cacheResult(session, OperationEncrypt, ciphertext)

	return ciphertext, CKR_OK
}

// ----------------------------------------------------------------
// PKCS#11 v3.0 Message-Based Operations
// ----------------------------------------------------------------

// MessageEncryptInit initializes a message-based encryption operation.
// Implements C_MessageEncryptInit behavior per PKCS#11 v3.0 specification.
// Used for AEAD-style encryption where each message has associated data.
func (m *Module) MessageEncryptInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// Message-based encryption uses the same initialization as regular encryption
	return m.EncryptInit(sessionHandle, mechanism, keyHandle)
}

// EncryptMessage encrypts a single message with associated data.
// Implements C_EncryptMessage behavior per PKCS#11 v3.0 specification.
// The associatedData provides authentication but is not encrypted.
func (m *Module) EncryptMessage(sessionHandle SessionHandle, params *AESGCMMessageParams, associatedData, plaintext []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category. The untyped accessor returns
	// whichever operation ranks first in a fixed priority order, which is
	// the wrong one whenever a dual-function flow has two categories active.
	opState := session.GetOperationByType(OperationEncrypt)
	if opState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}
	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// C_Logout withdraws the authorization every operation bound to a private
	// key was started under (v3.2 §5.6.10), and requireOperationAuthorization
	// is what refuses to continue such an operation afterwards. Without it
	// here, a logged-out session could still drive the key.
	if rv := requireOperationAuthorization(session, OperationEncrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	encOp, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// Set AAD for AEAD modes (e.g., AES-GCM)
	if len(associatedData) > 0 {
		encOp.SetAAD(associatedData)
	}

	// CK_GCM_MESSAGE_PARAMS.ivGenerator decides who produces the IV. Leaving
	// the operation's IV empty is how the backend is asked to generate one.
	if params != nil {
		// The token can preserve no caller-fixed prefix, so a fixed-bits or
		// counter request is refused rather than silently downgraded to a random
		// IV (§6.13.5). Shared with the message-based paths so all agree.
		if rv := validateGCMMessageIVGeneration(params); rv != CKR_OK {
			return nil, rv
		}
		if params.IVGenerator == CKG_NO_GENERATE {
			encOp.SetIV(params.IV)
		} else {
			// Leaving the operation's IV empty asks the backend to generate one.
			encOp.SetIV(nil)
		}

		// CK_GCM_MESSAGE_PARAMS.ulTagBits is a PER-MESSAGE parameter (v3.2
		// §6.13.5): a message-based operation binds only the mechanism and the
		// key, so the tag length arrives with each message rather than at Init.
		// Resolving it here is what lets a caller ask for a 96-bit tag and get
		// one; without it every message was sealed at the full 128 bits.
		if params.TagBits != 0 {
			if err := encOp.SetTagSize(params.TagBits); err != nil {
				return nil, FromError(err)
			}
		}
	}

	ciphertext, encErr := m.cryptoManager.Encrypt(ctx, encOp, plaintext)
	if encErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return nil, FromError(encErr)
	}

	if params == nil {
		return ciphertext, CKR_OK
	}

	// Both pIv and pTag are outputs here (v3.2 §6.13.5). An application that
	// asked the token to generate the IV has no other way to learn it, and
	// without the tag it can never decrypt what it just encrypted -- so
	// dropping these writes makes the whole message-based AEAD round trip
	// impossible, however well-formed the ciphertext looks.
	if params.IVGenerator != CKG_NO_GENERATE {
		params.IV = copyBytes(encOp.IV())
	}

	ciphertext, tag, rv := splitAEADTag(ciphertext, params.TagBits)
	if rv != CKR_OK {
		return nil, rv
	}
	params.Tag = tag

	return ciphertext, CKR_OK
}

// AES-GCM authentication tag bounds, per PKCS#11 v3.2 §6.13.5: ulTagBits may
// be any value from 0 to 128.
const (
	// defaultGCMTagBits is the tag length assumed when the caller leaves
	// ulTagBits at zero. A full-length tag is the only safe default; a shorter
	// one weakens the authentication the caller did not ask to weaken.
	defaultGCMTagBits = 128

	// maxGCMTagBits is the largest tag GCM produces.
	maxGCMTagBits = 128
)

// splitAEADTag separates the trailing authentication tag from an AES-GCM
// ciphertext.
//
// The crypto layer returns ciphertext || tag, which is the framing PKCS#11
// v3.2 §6.13.7 defines for C_Encrypt. The message-based functions instead
// return the tag out of band in CK_GCM_MESSAGE_PARAMS.pTag, so it is split off
// here rather than handed to the caller twice.
func splitAEADTag(ciphertext []byte, tagBits uint32) (body, tag []byte, rv CK_RV) {
	if tagBits == 0 {
		tagBits = defaultGCMTagBits
	}
	if tagBits > maxGCMTagBits || tagBits%8 != 0 {
		return nil, nil, CKR_MECHANISM_PARAM_INVALID
	}

	tagBytes := int(tagBits / 8)
	if len(ciphertext) < tagBytes {
		return nil, nil, CKR_DEVICE_ERROR
	}

	split := len(ciphertext) - tagBytes
	return copyBytes(ciphertext[:split]), copyBytes(ciphertext[split:]), CKR_OK
}

// MessageEncryptFinal finishes a message-based encryption operation.
// Implements C_MessageEncryptFinal behavior per PKCS#11 v3.0 specification.
func (m *Module) MessageEncryptFinal(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Finalize the operation
	if err := sm.FinalizeOperationType(sessionHandle, OperationEncrypt); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// validateGCMMessageIVGeneration enforces the IV-generation rules the token can
// honour for the message-based AES-GCM path, shared by the single-part
// EncryptMessage, the multi-part EncryptMessageNext, and the *Begin entry
// points so all three agree. A CKG_NO_GENERATE request must carry the IV it
// names; every other generator has the token produce a fully random IV, which
// cannot preserve a caller-fixed prefix (ulIvFixedBits) or a counter
// construction (§6.13.5), so a request that depends on either is refused rather
// than silently downgraded.
func validateGCMMessageIVGeneration(params *AESGCMMessageParams) CK_RV {
	if params == nil {
		return CKR_OK
	}
	if params.IVGenerator == CKG_NO_GENERATE {
		if len(params.IV) == 0 {
			return CKR_MECHANISM_PARAM_INVALID
		}
		return CKR_OK
	}
	if params.IVGenerator == CKG_GENERATE_COUNTER ||
		params.IVGenerator == CKG_GENERATE_COUNTER_XOR {
		return CKR_MECHANISM_PARAM_INVALID
	}
	if params.IVFixedBits != 0 {
		return CKR_MECHANISM_PARAM_INVALID
	}
	return CKR_OK
}

// EncryptMessageBegin begins a multiple-part message encryption operation.
// Implements C_EncryptMessageBegin behavior per PKCS#11 v3.0 specification.
func (m *Module) EncryptMessageBegin(sessionHandle SessionHandle, params *AESGCMMessageParams, associatedData []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// Look the operation up by category. The untyped accessor returns
	// whichever operation ranks first in a fixed priority order, which is
	// the wrong one whenever a dual-function flow has two categories active.
	opState := session.GetOperationByType(OperationEncrypt)
	if opState == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}
	if opState.Type != OperationEncrypt {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// The message parameter reaches Begin as well as every Next (v3.2 §5.9.3):
	// validate it here so a request the token cannot honour is refused at the
	// start of the message rather than at the first part, and apply a
	// caller-supplied IV now so the same value governs every part.
	if rv := validateGCMMessageIVGeneration(params); rv != CKR_OK {
		return rv
	}

	// The associated data has to reach the cipher, which means the crypto
	// operation's own AAD. Appending it to OperationState.Data instead left it
	// somewhere nothing reads for AEAD purposes, so a multi-part message was
	// authenticated with no AAD at all -- silently on encrypt, and as an
	// authentication failure on decrypt.
	op, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || op == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}
	if params != nil && params.IVGenerator == CKG_NO_GENERATE {
		op.SetIV(params.IV)
	}
	if len(associatedData) > 0 {
		op.SetAAD(associatedData)
	}
	opState.CryptoOp = op
	session.SetOperationState(*opState)

	return CKR_OK
}

// EncryptMessageNext continues a multiple-part message encryption operation.
// Implements C_EncryptMessageNext behavior per PKCS#11 v3.0 specification.
// If final is true, this is the last part and returns the final ciphertext.
func (m *Module) EncryptMessageNext(sessionHandle SessionHandle, params *AESGCMMessageParams, plaintext []byte, final bool) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category. The untyped accessor returns
	// whichever operation ranks first in a fixed priority order, which is
	// the wrong one whenever a dual-function flow has two categories active.
	opState := session.GetOperationByType(OperationEncrypt)
	if opState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}
	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// C_Logout withdraws the authorization every operation bound to a private
	// key was started under (v3.2 §5.6.10), and requireOperationAuthorization
	// is what refuses to continue such an operation afterwards. Without it
	// here, a logged-out session could still drive the key.
	// It also precedes the cached-result replay below, so a C_Logout between the
	// length query and the collection cannot be stepped over by the replay.
	if rv := requireOperationAuthorization(session, OperationEncrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	encOp, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// A repeated final call after a length query or a CKR_BUFFER_TOO_SMALL must
	// replay the cached ciphertext rather than encrypt again (v3.2 §5.2). The
	// check has to come before EncryptUpdate: feeding the same plaintext in a
	// second time would corrupt the stream, and re-running EncryptFinal would
	// consume a second IV.
	if final {
		if cached, hit := cachedResult(session, OperationEncrypt); hit {
			return finishGCMMessage(cached, params, encOp)
		}
	}

	// The IV is settled once for the whole message, so it is applied on the
	// first part and the generated value is handed back with the tag when the
	// last part completes (v3.2 §6.13.5). The same fixed-bits/counter refusal
	// the single-part path uses applies here.
	if rv := validateGCMMessageIVGeneration(params); rv != CKR_OK {
		return nil, rv
	}
	if params != nil && params.IVGenerator == CKG_NO_GENERATE {
		encOp.SetIV(params.IV)
	}
	if params != nil && params.TagBits != 0 {
		// Per-message tag length; see EncryptMessage.
		if err := encOp.SetTagSize(params.TagBits); err != nil {
			return nil, FromError(err)
		}
	}

	// Update with plaintext
	if err := m.cryptoManager.EncryptUpdate(encOp, plaintext); err != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
		return nil, FromError(err)
	}

	if final {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
		defer cancel()

		ciphertext, encErr := m.cryptoManager.EncryptFinal(ctx, encOp)
		if encErr != nil {
			_ = sm.FinalizeOperationType(sessionHandle, OperationEncrypt)
			return nil, FromError(encErr)
		}

		// The operation stays active and the result is cached, so the caller
		// can run the §5.2 two-call sequence. Terminating here made the retry
		// fail with CKR_OPERATION_NOT_INITIALIZED, which meant a correctly
		// written application could never collect the ciphertext at all. The C
		// shim drops the cache with ReleaseOperationResult once it has copied
		// the bytes out; the message operation itself lives until
		// C_MessageEncryptFinal.
		cacheResult(session, OperationEncrypt, ciphertext)

		return finishGCMMessage(ciphertext, params, encOp)
	}

	return nil, CKR_OK
}

// finishGCMMessage splits a completed AEAD message into its body and
// authentication tag and reports the IV that was used, leaving both in the
// caller's CK_GCM_MESSAGE_PARAMS.
//
// It is shared by the fresh and the replayed paths so a repeated call after a
// length query hands back exactly the same IV, tag and body as the first.
func finishGCMMessage(ciphertext []byte, params *AESGCMMessageParams, encOp *EncryptOperation) ([]byte, CK_RV) {
	if params == nil {
		return ciphertext, CKR_OK
	}

	if params.IVGenerator != CKG_NO_GENERATE {
		params.IV = copyBytes(encOp.IV())
	}

	body, tag, rv := splitAEADTag(ciphertext, params.TagBits)
	if rv != CKR_OK {
		return nil, rv
	}
	params.Tag = tag

	return body, CKR_OK
}

// MessageDecryptInit initializes a message-based decryption operation.
// Implements C_MessageDecryptInit behavior per PKCS#11 v3.0 specification.
func (m *Module) MessageDecryptInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// A message-based operation binds only the mechanism and the key. The IV
	// and authentication tag are per-message and arrive in
	// CK_GCM_MESSAGE_PARAMS on each C_DecryptMessage (v3.2 §5.11.1, §6.13.5),
	// so unlike C_DecryptInit this must not insist on an IV up front.
	// Delegating to DecryptInit did insist, which is why every CKM_AES_GCM
	// caller was rejected with CKR_MECHANISM_PARAM_INVALID here while the
	// matching C_MessageEncryptInit accepted them.
	return m.decryptInitInternal(sessionHandle, mechanism, keyHandle, true)
}

// DecryptMessage decrypts a single message with associated data.
// Implements C_DecryptMessage behavior per PKCS#11 v3.0 specification.
func (m *Module) DecryptMessage(sessionHandle SessionHandle, params *AESGCMMessageParams, associatedData, ciphertext []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category. The untyped accessor returns
	// whichever operation ranks first in a fixed priority order, which is
	// the wrong one whenever a dual-function flow has two categories active.
	opState := session.GetOperationByType(OperationDecrypt)
	if opState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}
	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// C_Logout withdraws the authorization every operation bound to a private
	// key was started under (v3.2 §5.6.10), and requireOperationAuthorization
	// is what refuses to continue such an operation afterwards. Without it
	// here, a logged-out session could still drive the key.
	if rv := requireOperationAuthorization(session, OperationDecrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	decOp, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// Set AAD for AEAD modes (e.g., AES-GCM)
	if len(associatedData) > 0 {
		decOp.SetAAD(associatedData)
	}

	// The IV and the tag are inputs here, carried per message rather than on
	// the Init (v3.2 §6.13.5). The crypto layer expects the spec's
	// ciphertext || tag framing, so the out-of-band tag is reattached.
	if params != nil {
		if len(params.IV) == 0 {
			return nil, CKR_MECHANISM_PARAM_INVALID
		}
		decOp.SetIV(params.IV)

		// The per-message tag length, for the reason the encrypt side gives.
		// It decides where Decrypt splits ciphertext||tag, so a mismatch hands
		// the backend ciphertext bytes as tag material and the message fails as
		// though it had been tampered with.
		if params.TagBits != 0 {
			if err := decOp.SetTagSize(params.TagBits); err != nil {
				return nil, FromError(err)
			}
		}

		if len(params.Tag) > 0 {
			framed := make([]byte, 0, len(ciphertext)+len(params.Tag))
			framed = append(framed, ciphertext...)
			framed = append(framed, params.Tag...)
			ciphertext = framed
		}
	}

	plaintext, decErr := m.cryptoManager.Decrypt(ctx, decOp, ciphertext)
	if decErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return nil, FromError(decErr)
	}

	return plaintext, CKR_OK
}

// MessageDecryptFinal finishes a message-based decryption operation.
// Implements C_MessageDecryptFinal behavior per PKCS#11 v3.0 specification.
func (m *Module) MessageDecryptFinal(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	if err := sm.FinalizeOperationType(sessionHandle, OperationDecrypt); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// DecryptMessageBegin begins a multiple-part message decryption operation.
// Implements C_DecryptMessageBegin behavior per PKCS#11 v3.0 specification.
func (m *Module) DecryptMessageBegin(sessionHandle SessionHandle, params *AESGCMMessageParams, associatedData []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// Look the operation up by category. The untyped accessor returns
	// whichever operation ranks first in a fixed priority order, which is
	// the wrong one whenever a dual-function flow has two categories active.
	opState := session.GetOperationByType(OperationDecrypt)
	if opState == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}
	if opState.Type != OperationDecrypt {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	op, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || op == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// For decryption the message parameter is always an input (v3.2 §5.11.3):
	// the caller must present the exact IV the message was sealed under, so an
	// absent IV is refused here rather than surfacing as an authentication
	// failure at the first part.
	if params != nil {
		if len(params.IV) == 0 {
			return CKR_MECHANISM_PARAM_INVALID
		}
		op.SetIV(params.IV)
		if params.TagBits != 0 {
			if err := op.SetTagSize(params.TagBits); err != nil {
				return FromError(err)
			}
		}
	}

	// The associated data has to reach the cipher, which means the crypto
	// operation's own AAD. Appending it to OperationState.Data instead left it
	// somewhere nothing reads for AEAD purposes, so a multi-part message was
	// authenticated with no AAD at all -- silently on encrypt, and as an
	// authentication failure on decrypt.
	if len(associatedData) > 0 {
		op.SetAAD(associatedData)
	}
	opState.CryptoOp = op
	session.SetOperationState(*opState)

	return CKR_OK
}

// DecryptMessageNext continues a multiple-part message decryption operation.
// Implements C_DecryptMessageNext behavior per PKCS#11 v3.0 specification.
// If final is true, this is the last part and returns the final plaintext.
func (m *Module) DecryptMessageNext(sessionHandle SessionHandle, params *AESGCMMessageParams, ciphertext []byte, final bool) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category. The untyped accessor returns
	// whichever operation ranks first in a fixed priority order, which is
	// the wrong one whenever a dual-function flow has two categories active.
	opState := session.GetOperationByType(OperationDecrypt)
	if opState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}
	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// C_Logout withdraws the authorization every operation bound to a private
	// key was started under (v3.2 §5.6.10), and requireOperationAuthorization
	// is what refuses to continue such an operation afterwards. Without it
	// here, a logged-out session could still drive the key.
	// It also precedes the cached-result replay below, so a C_Logout between the
	// length query and the collection cannot be stepped over by the replay.
	if rv := requireOperationAuthorization(session, OperationDecrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	decOp, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// A repeated final call after a length query or a CKR_BUFFER_TOO_SMALL must
	// replay the cached plaintext rather than decrypt again (v3.2 §5.2). The
	// check precedes DecryptUpdate because feeding the same ciphertext in twice
	// would corrupt the stream and fail tag verification.
	if final {
		if cached, hit := cachedResult(session, OperationDecrypt); hit {
			return cached, CKR_OK
		}
	}

	// The IV and tag arrive per message, not on the Init, so they are applied
	// here just as C_DecryptMessage applies them (v3.2 §6.13.5). On the final
	// part the out-of-band tag is reattached, because the crypto layer expects
	// the spec's ciphertext || tag framing.
	if params != nil {
		if len(params.IV) == 0 {
			return nil, CKR_MECHANISM_PARAM_INVALID
		}
		decOp.SetIV(params.IV)

		if params.TagBits != 0 {
			// Per-message tag length; see DecryptMessage.
			if err := decOp.SetTagSize(params.TagBits); err != nil {
				return nil, FromError(err)
			}
		}

		if final && len(params.Tag) > 0 {
			framed := make([]byte, 0, len(ciphertext)+len(params.Tag))
			framed = append(framed, ciphertext...)
			framed = append(framed, params.Tag...)
			ciphertext = framed
		}
	}

	// Update with ciphertext
	if err := m.cryptoManager.DecryptUpdate(decOp, ciphertext); err != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return nil, FromError(err)
	}

	if final {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
		defer cancel()

		plaintext, decErr := m.cryptoManager.DecryptFinal(ctx, decOp)
		if decErr != nil {
			_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
			return nil, FromError(decErr)
		}

		// Cached, not finalized, for the same reason as the encrypt side: the
		// caller must be able to retry the §5.2 two-call sequence, and
		// C_MessageDecryptInit lives until C_MessageDecryptFinal.
		cacheResult(session, OperationDecrypt, plaintext)

		return plaintext, CKR_OK
	}

	return nil, CKR_OK
}

// MessageSignInit initializes a message-based signing operation.
// Implements C_MessageSignInit behavior per PKCS#11 v3.0 specification.
func (m *Module) MessageSignInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	return m.SignInit(sessionHandle, mechanism, keyHandle)
}

// SignMessage signs a single message.
// Implements C_SignMessage behavior per PKCS#11 v3.0 specification.
func (m *Module) SignMessage(sessionHandle SessionHandle, data []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// SignMessage is equivalent to calling Sign for a single-part operation
	return m.Sign(sessionHandle, data)
}

// SignMessageBegin begins a multiple-part message signing operation.
// Implements C_SignMessageBegin behavior per PKCS#11 v3.0 specification.
func (m *Module) SignMessageBegin(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// The operation should already be initialized via MessageSignInit
	// This just validates the state is correct
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// Look the operation up by category. The untyped accessor returns
	// whichever operation ranks first in a fixed priority order, which is
	// the wrong one whenever a dual-function flow has two categories active.
	opState := session.GetOperationByType(OperationSign)
	if opState == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}
	if opState.Type != OperationSign {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	return CKR_OK
}

// SignMessageNext continues a multiple-part message signing operation.
// Implements C_SignMessageNext behavior per PKCS#11 v3.0 specification.
func (m *Module) SignMessageNext(sessionHandle SessionHandle, data []byte, final bool) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// Update the sign operation with data
	rv := m.SignUpdate(sessionHandle, data)
	if rv != CKR_OK {
		return nil, rv
	}

	if final {
		// Return the final signature
		return m.SignFinal(sessionHandle)
	}

	return nil, CKR_OK
}

// MessageSignFinal finishes a message-based signing operation.
// Implements C_MessageSignFinal behavior per PKCS#11 v3.0 specification.
func (m *Module) MessageSignFinal(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	if err := sm.FinalizeOperationType(sessionHandle, OperationSign); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// MessageVerifyInit initializes a message-based verification operation.
// Implements C_MessageVerifyInit behavior per PKCS#11 v3.0 specification.
func (m *Module) MessageVerifyInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	return m.VerifyInit(sessionHandle, mechanism, keyHandle)
}

// VerifyMessage verifies a signature on a single message.
// Implements C_VerifyMessage behavior per PKCS#11 v3.0 specification.
func (m *Module) VerifyMessage(sessionHandle SessionHandle, data, signature []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// PKCS#11 v3.2 §5.16.2 is explicit: "A call to C_VerifyMessage starts and
	// terminates a message verification operation. C_VerifyMessage does not
	// finish the message-based verification process." The distinction is that
	// C_MessageVerifyInit establishes a mechanism and key that outlive any one
	// message — an application may verify several messages against them and
	// only C_MessageVerifyFinal tears the process down.
	//
	// Verify below is the single-part function and necessarily terminates its
	// own operation, so the operation is captured first and re-established
	// afterwards. Without this the second C_VerifyMessage, and
	// C_MessageVerifyFinal itself, fail with CKR_OPERATION_NOT_INITIALIZED.
	opState, rv := m.messageOperationBinding(sessionHandle, OperationVerify)
	if rv != CKR_OK {
		return rv
	}

	verifyRV := m.Verify(sessionHandle, data, signature)

	// A verification that merely reports a bad signature leaves the process
	// usable, so it is re-established regardless of the verdict. Only a failure
	// to re-establish it is reported in place of that verdict.
	if rv := m.restoreMessageOperation(sessionHandle, opState); rv != CKR_OK && verifyRV == CKR_OK {
		return rv
	}

	return verifyRV
}

// messageOperationBinding returns the operation a message-based process was
// initialized with.
//
// The message-based functions delegate to their single-part equivalents, which
// consume the operation state. Capturing it first is what lets the process be
// re-established afterwards, as PKCS#11 v3.2 §5.16 requires.
//
// The whole OperationState is captured, not the mechanism type and key handle
// it records. OperationState.Mechanism is only a CK_MECHANISM_TYPE: the
// CK_MECHANISM's pParameter lives on the crypto operation in
// OperationState.CryptoOp, so a binding described by the type alone loses every
// mechanism parameter C_MessageVerifyInit validated and stored. That is the
// same gap that once made C_Sign discard C_SignInit's PSS parameters, and it
// was fatal here rather than merely wrong: re-initializing an RSA-PSS process
// from the bare type failed validateRSAPSSParams with
// CKR_MECHANISM_PARAM_INVALID, and C_VerifyMessage returned that in place of
// the CKR_OK it had just computed for a valid signature.
func (m *Module) messageOperationBinding(sessionHandle SessionHandle, opType OperationType) (*OperationState, CK_RV) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	opState := session.GetOperationByType(opType)
	if opState == nil || opState.Type != opType {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	return opState, CKR_OK
}

// restoreMessageOperation re-establishes the message-based process that
// messageOperationBinding captured, after the single-part function it delegated
// to has consumed the operation.
//
// The captured state is put back rather than rebuilt through C_VerifyInit,
// which is what preserves the CK_MECHANISM parameters: GetOperationByType
// returns a copy whose CryptoOp is the very operation C_MessageVerifyInit
// built, and CryptoOperation.Reset clears the buffered data and the finalized
// flag while leaving baseOperation.mechanism in place. This is exactly how
// releaseResult rearms an operation between messages, and for the same reason.
//
// The cached terminal result is dropped, not carried across: it belongs to the
// message just verified, and PKCS#11 v3.2 §5.16.2 starts each C_VerifyMessage
// as its own message.
func (m *Module) restoreMessageOperation(sessionHandle SessionHandle, opState *OperationState) CK_RV {
	if opState == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	if cryptoOp, ok := opState.CryptoOp.(CryptoOperation); ok && cryptoOp != nil {
		cryptoOp.Reset()
	}
	enclave.Wipe(opState.Result)
	opState.Result = nil
	opState.ResultReady = false
	opState.MultiPart = false

	session.SetOperationByType(opState.Type, opState)

	return CKR_OK
}

// VerifyMessageBegin begins a multiple-part message verification operation.
// Implements C_VerifyMessageBegin behavior per PKCS#11 v3.0 specification.
func (m *Module) VerifyMessageBegin(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// Look the operation up by category. The untyped accessor returns
	// whichever operation ranks first in a fixed priority order, which is
	// the wrong one whenever a dual-function flow has two categories active.
	opState := session.GetOperationByType(OperationVerify)
	if opState == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}
	if opState.Type != OperationVerify {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	return CKR_OK
}

// VerifyMessageNext continues a multiple-part message verification operation.
// Implements C_VerifyMessageNext behavior per PKCS#11 v3.0 specification.
func (m *Module) VerifyMessageNext(sessionHandle SessionHandle, data []byte, signature []byte, final bool) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// Update the verify operation with data
	rv := m.VerifyUpdate(sessionHandle, data)
	if rv != CKR_OK {
		return rv
	}

	// Finality is signalled by a non-NULL pSignature at the C ABI, not by a
	// non-zero length (v3.2 §5.16.2 / the C_VerifyMessageNext contract). A
	// caller presenting a zero-length final signature is still making the final
	// call: VerifyFinal must run and answer with a signature or length error
	// rather than the operation silently staying open as if more messages were
	// coming.
	if final {
		return m.VerifyFinal(sessionHandle, signature)
	}

	return CKR_OK
}

// MessageVerifyFinal finishes a message-based verification operation.
// Implements C_MessageVerifyFinal behavior per PKCS#11 v3.0 specification.
func (m *Module) MessageVerifyFinal(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	if err := sm.FinalizeOperationType(sessionHandle, OperationVerify); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// DecryptInit initializes a decryption operation.
// Implements C_DecryptInit behavior per PKCS#11 specification.
func (m *Module) DecryptInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	return m.decryptInitInternal(sessionHandle, mechanism, keyHandle, false)
}

// decryptInitInternal is the body shared by C_DecryptInit and
// C_MessageDecryptInit.
//
// messageBased selects which of the two contracts applies. C_DecryptInit takes
// the IV from the mechanism and cannot proceed without it; a message-based
// operation binds only the mechanism and key, and each C_DecryptMessage
// supplies its own IV and tag.
func (m *Module) decryptInitInternal(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle, messageBased bool) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// PKCS#11 v3.2 §5.10.1: "C_DecryptInit can be called with pMechanism set to
	// NULL_PTR to terminate an active decryption operation." C_MessageDecryptInit
	// (§5.11.1) lists CKR_OPERATION_CANCEL_FAILED in its return table and reaches
	// the same code through messageBased.
	if mechanism == nil {
		return m.terminateInitOperation(sessionHandle, OperationDecrypt)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	obj, rv := m.resolveOperationKey(slotID, sessionHandle, session, keyHandle, CKA_DECRYPT, mechanism)
	if rv != CKR_OK {
		return rv
	}

	// Key first, then mechanism; validateInitMechanism documents why.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return rv
	}

	if err := sm.InitializeOperation(sessionHandle, OperationDecrypt, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	decryptInit := m.cryptoManager.DecryptInit
	if messageBased {
		decryptInit = m.cryptoManager.MessageDecryptInit
	}

	decOp, cryptoErr := decryptInit(mechanism, keyHandle, obj.KeyID, obj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return FromError(cryptoErr)
	}

	// Store the crypto operation in session state for multi-part ops
	opState := session.GetOperationByType(OperationDecrypt)
	if opState != nil {
		opState.CryptoOp = decOp
		session.SetOperationByType(OperationDecrypt, opState)
	}

	return CKR_OK
}

// Decrypt decrypts data in a single operation.
// Implements C_Decrypt behavior per PKCS#11 specification.
func (m *Module) Decrypt(sessionHandle SessionHandle, ciphertext []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState := session.GetOperationByType(OperationDecrypt)
	if opState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationDecrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	// A repeated call after a length query returns the cached plaintext. It
	// follows the authorization check rather than preceding it; see
	// cachedResult -- a replay placed first handed back plaintext computed
	// before a C_Logout that had already withdrawn the entitlement to it.
	if plaintext, ok := cachedResult(session, OperationDecrypt); ok {
		return plaintext, CKR_OK
	}

	// C_Decrypt cannot terminate a multi-part operation (v3.2 §5.10.2).
	// Data holds AEAD associated data, not buffered parts, so MultiPart is
	// the only reliable marker that an *Update call has occurred.
	if opState.MultiPart {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return nil, CKR_OPERATION_ACTIVE
	}

	obj, objErr := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), opState.KeyHandle)
	if objErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return nil, terminalKeyGoneRV
	}

	if rv := requireContextAuthentication(session, OperationDecrypt, obj); rv != CKR_OK {
		return nil, rv
	}

	// Reuse the operation C_DecryptInit built, so the mechanism parameters the
	// caller supplied (GCM tag length, CBC IV) are not discarded.
	decOp, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || decOp == nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	plaintext, decErr := m.cryptoManager.Decrypt(ctx, decOp, ciphertext)
	if decErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return nil, FromError(decErr)
	}

	cacheResult(session, OperationDecrypt, plaintext)

	return plaintext, CKR_OK
}

// DecryptUpdate continues a multiple-part decryption operation.
// Implements C_DecryptUpdate behavior per PKCS#11 specification.
func (m *Module) DecryptUpdate(sessionHandle SessionHandle, ciphertext []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationDecrypt)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationDecrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	decOp, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if err := m.cryptoManager.DecryptUpdate(decOp, ciphertext); err != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return nil, FromError(err)
	}

	opState.MultiPart = true
	opState.CryptoOp = decOp
	session.SetOperationState(*opState)

	// For multi-part decryption with buffering, we return empty data
	// The actual plaintext is returned in DecryptFinal
	return nil, CKR_OK
}

// DecryptFinal finishes a multiple-part decryption operation.
// Implements C_DecryptFinal behavior per PKCS#11 specification.
func (m *Module) DecryptFinal(sessionHandle SessionHandle) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationDecrypt)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if rv := requireOperationAuthorization(session, OperationDecrypt, opState); rv != CKR_OK {
		return nil, rv
	}

	// A repeated call after a length query returns the cached output without
	// re-running the backend operation. It follows the authorization check
	// rather than preceding it; see cachedResult.
	if out, done := cachedResult(session, OperationDecrypt); done {
		return out, CKR_OK
	}

	// CKA_ALWAYS_AUTHENTICATE gates the terminal call of a multi-part
	// decryption exactly as it gates C_Decrypt; see the matching gate in
	// SignFinal for why it belongs here and why it follows the cached-result
	// check rather than preceding it.
	if obj, objErr := m.objectManager.GetObjectFor(
		NewAccessContext(sessionHandle, session), opState.KeyHandle); objErr == nil {
		if rv := requireContextAuthentication(session, OperationDecrypt, obj); rv != CKR_OK {
			return nil, rv
		}
	}

	decOp, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	plaintext, decErr := m.cryptoManager.DecryptFinal(ctx, decOp)
	if decErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDecrypt)
		return nil, FromError(decErr)
	}

	// The operation stays active until the caller confirms it received the
	// output with FinishOperation, per the two-call convention (v3.2 §5.2).
	cacheResult(session, OperationDecrypt, plaintext)

	return plaintext, CKR_OK
}

// DigestEncryptUpdate continues a multiple-part combined digest and encryption operation.
// Implements C_DigestEncryptUpdate behavior per PKCS#11 specification.
// The data is digested and encrypted in a single operation.
// Note: This implementation buffers data for final processing. The returned byte slice
// may be empty if the cipher requires more data for a complete block.
func (m *Module) DigestEncryptUpdate(sessionHandle SessionHandle, data []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	_, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Get digest operation by type
	digestOpState := session.GetOperationByType(OperationDigest)
	if digestOpState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	digestOp, hasDigest := digestOpState.CryptoOp.(*DigestOperation)
	if !hasDigest || digestOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Get encryption operation by type
	encOpState := session.GetOperationByType(OperationEncrypt)
	if encOpState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	encOp, hasEncrypt := encOpState.CryptoOp.(*EncryptOperation)
	if !hasEncrypt || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Both halves of a dual-function flow are gated, not just the one that
	// holds a key. C_Logout revokes each operation it bound (v3.2 §5.6.10),
	// and a flow that continued on either half after that would keep using
	// state the session is no longer entitled to. The digest half carries no
	// key and so is never revoked today; it is checked anyway so all eight
	// dual-function and message verbs read the same way and a future
	// revocation rule cannot silently miss one.
	if rv := requireOperationAuthorization(session, OperationDigest, digestOpState); rv != CKR_OK {
		return nil, rv
	}
	if rv := requireOperationAuthorization(session, OperationEncrypt, encOpState); rv != CKR_OK {
		return nil, rv
	}

	// First, update the digest with the plaintext
	if digestErr := m.cryptoManager.DigestUpdate(digestOp, data); digestErr != nil {
		return nil, FromError(digestErr)
	}

	// Then, buffer the data for encryption (processed during Final)
	if encErr := m.cryptoManager.EncryptUpdate(encOp, data); encErr != nil {
		return nil, FromError(encErr)
	}

	// Return empty slice - data is buffered for final processing
	return []byte{}, CKR_OK
}

// DecryptDigestUpdate continues a multiple-part combined decrypt and digest operation.
// Implements C_DecryptDigestUpdate behavior per PKCS#11 specification.
// The data is decrypted and then digested in a single operation.
// Note: This implementation buffers data for final processing. The returned byte slice
// may be empty if the cipher requires more data for a complete block.
func (m *Module) DecryptDigestUpdate(sessionHandle SessionHandle, encryptedData []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	_, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Get decrypt operation by type
	decOpState := session.GetOperationByType(OperationDecrypt)
	if decOpState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	decOp, hasDecrypt := decOpState.CryptoOp.(*DecryptOperation)
	if !hasDecrypt || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Get digest operation by type
	digestOpState := session.GetOperationByType(OperationDigest)
	if digestOpState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	digestOp, hasDigest := digestOpState.CryptoOp.(*DigestOperation)
	if !hasDigest || digestOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Both halves of a dual-function flow are gated, not just the one that
	// holds a key. C_Logout revokes each operation it bound (v3.2 §5.6.10),
	// and a flow that continued on either half after that would keep using
	// state the session is no longer entitled to. The digest half carries no
	// key and so is never revoked today; it is checked anyway so all eight
	// dual-function and message verbs read the same way and a future
	// revocation rule cannot silently miss one.
	if rv := requireOperationAuthorization(session, OperationDecrypt, decOpState); rv != CKR_OK {
		return nil, rv
	}
	if rv := requireOperationAuthorization(session, OperationDigest, digestOpState); rv != CKR_OK {
		return nil, rv
	}

	// Buffer the encrypted data for decryption (processed during Final)
	if decErr := m.cryptoManager.DecryptUpdate(decOp, encryptedData); decErr != nil {
		return nil, FromError(decErr)
	}

	// The digest is NOT fed here, and DecryptFinal does not feed it either --
	// an earlier comment claimed it did, which was false for every input.
	//
	// This is still conformant. PKCS#11 v3.2 §5.17.2 conditions the rule on the
	// update producing output: it digests "the part of the plaintext that this
	// call produced", and an AEAD update produces none because the cipher
	// buffers everything until DecryptFinal can verify the tag. Releasing
	// plaintext before authentication is exactly what an AEAD must not do.
	//
	// The application completes the digest the way §5.17.2's own example does,
	// by passing DecryptFinal's remainder to C_DigestUpdate. Anyone changing
	// this to feed the digest directly must first make the decrypt side emit
	// plaintext from an update, which for AES-GCM it cannot.
	return []byte{}, CKR_OK
}

// SignEncryptUpdate continues a multiple-part combined sign and encrypt operation.
// Implements C_SignEncryptUpdate behavior per PKCS#11 specification.
// The data is signed and encrypted in a single operation.
// Note: This implementation buffers data for final processing. The returned byte slice
// may be empty if the cipher requires more data for a complete block.
func (m *Module) SignEncryptUpdate(sessionHandle SessionHandle, data []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	_, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Get sign operation by type
	signOpState := session.GetOperationByType(OperationSign)
	if signOpState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	signOp, hasSign := signOpState.CryptoOp.(*SignOperation)
	if !hasSign || signOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Get encryption operation by type
	encOpState := session.GetOperationByType(OperationEncrypt)
	if encOpState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	encOp, hasEncrypt := encOpState.CryptoOp.(*EncryptOperation)
	if !hasEncrypt || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Both halves of a dual-function flow are gated, not just the one that
	// holds a key. C_Logout revokes each operation it bound (v3.2 §5.6.10),
	// and a flow that continued on either half after that would keep using
	// state the session is no longer entitled to. The digest half carries no
	// key and so is never revoked today; it is checked anyway so all eight
	// dual-function and message verbs read the same way and a future
	// revocation rule cannot silently miss one.
	if rv := requireOperationAuthorization(session, OperationSign, signOpState); rv != CKR_OK {
		return nil, rv
	}
	if rv := requireOperationAuthorization(session, OperationEncrypt, encOpState); rv != CKR_OK {
		return nil, rv
	}

	// First, update the signature with the plaintext
	if signErr := m.cryptoManager.SignUpdate(signOp, data); signErr != nil {
		return nil, FromError(signErr)
	}

	// Then, buffer the data for encryption (processed during Final)
	if encErr := m.cryptoManager.EncryptUpdate(encOp, data); encErr != nil {
		return nil, FromError(encErr)
	}

	// Return empty slice - data is buffered for final processing
	return []byte{}, CKR_OK
}

// DecryptVerifyUpdate continues a multiple-part combined decrypt and verify operation.
// Implements C_DecryptVerifyUpdate behavior per PKCS#11 specification.
// The data is decrypted and the plaintext is used to update a verification.
// Note: This implementation buffers data for final processing. The returned byte slice
// may be empty if the cipher requires more data for a complete block.
func (m *Module) DecryptVerifyUpdate(sessionHandle SessionHandle, encryptedData []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	_, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// Get decrypt operation by type
	decOpState := session.GetOperationByType(OperationDecrypt)
	if decOpState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	decOp, hasDecrypt := decOpState.CryptoOp.(*DecryptOperation)
	if !hasDecrypt || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Get verify operation by type
	verifyOpState := session.GetOperationByType(OperationVerify)
	if verifyOpState == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	verifyOp, hasVerify := verifyOpState.CryptoOp.(*VerifyOperation)
	if !hasVerify || verifyOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Both halves of a dual-function flow are gated, not just the one that
	// holds a key. C_Logout revokes each operation it bound (v3.2 §5.6.10),
	// and a flow that continued on either half after that would keep using
	// state the session is no longer entitled to. The digest half carries no
	// key and so is never revoked today; it is checked anyway so all eight
	// dual-function and message verbs read the same way and a future
	// revocation rule cannot silently miss one.
	if rv := requireOperationAuthorization(session, OperationDecrypt, decOpState); rv != CKR_OK {
		return nil, rv
	}
	if rv := requireOperationAuthorization(session, OperationVerify, verifyOpState); rv != CKR_OK {
		return nil, rv
	}

	// Buffer the encrypted data for decryption (processed during Final)
	if decErr := m.cryptoManager.DecryptUpdate(decOp, encryptedData); decErr != nil {
		return nil, FromError(decErr)
	}

	// The verification is NOT fed here, and DecryptFinal does not feed it
	// either -- see DecryptDigestUpdate for the full reasoning. §5.17.4
	// conditions the rule on the update producing plaintext, and an AEAD update
	// produces none until the tag has been checked. The application passes
	// DecryptFinal's remainder to C_VerifyUpdate to complete the verification.
	return []byte{}, CKR_OK
}

// DigestInit initializes a message-digesting operation.
// Implements C_DigestInit behavior per PKCS#11 specification.
func (m *Module) DigestInit(sessionHandle SessionHandle, mechanism *Mechanism) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// PKCS#11 v3.2 §5.12.1: "C_DigestInit can be called with pMechanism set to
	// NULL_PTR to terminate an active message digesting operation."
	if mechanism == nil {
		return m.terminateInitOperation(sessionHandle, OperationDigest)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// C_DigestInit takes no key, so the mechanism is the only thing left to
	// validate; validateInitMechanism is still the one place that decides.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return rv
	}

	if err := sm.InitializeOperation(sessionHandle, OperationDigest, mechanism.Type, ObjectHandle(0)); err != nil {
		return FromError(err)
	}

	digestOp, cryptoErr := m.cryptoManager.DigestInit(mechanism)
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDigest)
		return FromError(cryptoErr)
	}

	// Store the crypto operation in session state for multi-part ops
	opState := session.GetOperationByType(OperationDigest)
	if opState != nil {
		opState.CryptoOp = digestOp
		session.SetOperationByType(OperationDigest, opState)
	}

	return CKR_OK
}

// Digest digests data in a single operation.
// Implements C_Digest behavior per PKCS#11 specification.
func (m *Module) Digest(sessionHandle SessionHandle, data []byte) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// A repeated call after a length query returns the cached output without
	// re-running the backend operation.
	if out, done := cachedResult(session, OperationDigest); done {
		return out, CKR_OK
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationDigest)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDigest {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// C_Digest must follow C_DigestInit with no intervening C_DigestUpdate or
	// C_DigestKey: it cannot terminate a multiple-part operation (v3.2
	// §5.12.2). It starts a fresh digest below, so without this guard the
	// buffered parts would be discarded and the caller would receive a
	// well-formed digest of the wrong message.
	if opState.MultiPart {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDigest)
		return nil, CKR_OPERATION_ACTIVE
	}

	mech := &Mechanism{Type: opState.Mechanism}
	digestOp, digestErr := m.cryptoManager.DigestInit(mech)
	if digestErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDigest)
		return nil, FromError(digestErr)
	}

	hash, digestErr := m.cryptoManager.Digest(digestOp, data)
	if digestErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDigest)
		return nil, FromError(digestErr)
	}

	// The operation stays active until the caller confirms it received the
	// output with FinishOperation, per the two-call convention (v3.2 §5.2).
	cacheResult(session, OperationDigest, hash)

	return hash, CKR_OK
}

// DigestUpdate continues a multiple-part message-digesting operation.
// Implements C_DigestUpdate behavior per PKCS#11 specification.
func (m *Module) DigestUpdate(sessionHandle SessionHandle, data []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationDigest)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDigest {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	digestOp, ok := opState.CryptoOp.(*DigestOperation)
	if !ok || digestOp == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if err := m.cryptoManager.DigestUpdate(digestOp, data); err != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDigest)
		return FromError(err)
	}

	opState.MultiPart = true
	opState.CryptoOp = digestOp
	session.SetOperationState(*opState)

	return CKR_OK
}

// DigestFinal finishes a multiple-part message-digesting operation.
// Implements C_DigestFinal behavior per PKCS#11 specification.
func (m *Module) DigestFinal(sessionHandle SessionHandle) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	// A repeated call after a length query returns the cached output without
	// re-running the backend operation.
	if out, done := cachedResult(session, OperationDigest); done {
		return out, CKR_OK
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationDigest)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDigest {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	digestOp, ok := opState.CryptoOp.(*DigestOperation)
	if !ok || digestOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	hash, digestErr := m.cryptoManager.DigestFinal(digestOp)
	if digestErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDigest)
		return nil, FromError(digestErr)
	}

	// The operation stays active until the caller confirms it received the
	// output with FinishOperation, per the two-call convention (v3.2 §5.2).
	cacheResult(session, OperationDigest, hash)

	return hash, CKR_OK
}

// DigestKey continues a multiple-part message-digesting operation by digesting
// the value of a secret key.
// Implements C_DigestKey behavior per PKCS#11 specification.
func (m *Module) DigestKey(sessionHandle SessionHandle, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	_, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	// Look the operation up by category: several operations of different
	// categories can be active at once, and a terminal call now leaves its
	// own operation active until FinishOperation.
	opState := session.GetOperationByType(OperationDigest)
	var err error
	if opState == nil {
		err = NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDigest {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	digestOp, ok := opState.CryptoOp.(*DigestOperation)
	if !ok || digestOp == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// Resolve through the session's access context: digesting a key reads its
	// material, so the session must be entitled to see it.
	keyObj, objErr := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), keyHandle)
	if objErr != nil {
		return CKR_KEY_HANDLE_INVALID
	}

	// Check that key is a secret key
	classAttr := keyObj.GetAttribute(CKA_CLASS)
	if len(classAttr) < 4 {
		return CKR_KEY_HANDLE_INVALID
	}
	class := ObjectClass(classAttr[0]) | ObjectClass(classAttr[1])<<8 |
		ObjectClass(classAttr[2])<<16 | ObjectClass(classAttr[3])<<24
	if class != CKO_SECRET_KEY {
		return CKR_KEY_INDIGESTIBLE
	}

	// C_DigestKey digests "the value of a secret key" (v3.2 §5.12.4), so it
	// needs the same material C_GetAttributeValue would hand back -- including
	// when that material lives in the backend rather than on the object. Reading
	// the attribute map alone made every backend-generated key indigestible,
	// however plainly its own attributes said the value could be revealed.
	//
	// A key the token may not reveal genuinely cannot be digested, and
	// CKR_KEY_INDIGESTIBLE is the code the spec lists for that.
	keyValue, valueRV := m.secretKeyValue(keyObj)
	if valueRV != CKR_OK || len(keyValue) == 0 {
		return CKR_KEY_INDIGESTIBLE
	}

	// Digest the key value
	if digestErr := m.cryptoManager.DigestUpdate(digestOp, keyValue); digestErr != nil {
		return FromError(digestErr)
	}

	// C_DigestKey feeds a part into the digest exactly as C_DigestUpdate does
	// (v3.2 §5.12.3 lets the two be interspersed), so it likewise makes the
	// operation multiple-part and rules out terminating it with C_Digest.
	opState.MultiPart = true
	session.SetOperationState(*opState)

	return CKR_OK
}

// ----------------------------------------------------------------
// Key Generation Operations
// ----------------------------------------------------------------

// GenerateKey generates a secret (symmetric) key.
// Implements C_GenerateKey behavior per PKCS#11 specification.
func (m *Module) GenerateKey(sessionHandle SessionHandle, mechanism *Mechanism, template []Attribute) (ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	// No unconditional read-only gate here. PKCS#11 v3.2 §5.7.1 says only that
	// "Only session objects can be created during a read-only session", so a
	// CKA_TOKEN=FALSE key is legal in a R/O session. The rule belongs to object
	// creation and is already enforced there by createPolicyChecked, which
	// gates on obj.IsToken && !ctx.ReadWrite. Rejecting every generation up
	// front refused a request the spec permits, and SoftHSM accepts it:
	// C_GenerateKey for a session key in a R/O session returns CKR_OK, and only
	// a token key returns CKR_SESSION_READ_ONLY. C_UnwrapKey in this file never
	// had the redundant gate, which is what made the inconsistency visible.
	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates
	// the crypto operations; which verb the caller uses must not change the
	// policy.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	// C_GenerateKey names no key, so there is nothing to order the mechanism
	// against; validateInitMechanism is still the one place that decides, so a
	// mechanism the module withholds cannot be reached through key generation.
	// C_GenerateKey has no NULL-pMechanism termination contract — §5.18.1 states
	// none — so a nil mechanism stays CKR_ARGUMENTS_BAD here.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	// Extract key parameters from template
	var label string
	var keySize int
	var valueLenBytes uint32
	var ckaID []byte
	for _, attr := range template {
		switch attr.Type {
		case CKA_LABEL:
			label = attr.GetString()
		case CKA_VALUE_LEN:
			if v, err := attr.GetUint32(); err == nil {
				valueLenBytes = v
				keySize = int(v) * 8 // Convert bytes to bits
			}
		case CKA_ID:
			ckaID = attr.Value
		}
	}

	// CKA_VALUE_LEN must lie inside the range C_GetMechanismInfo advertises for
	// the mechanism. Without this the requested size went straight to the
	// backend, which enforced no ceiling, so one call could make the daemon
	// allocate and generate an arbitrarily large key.
	//
	// The value checked is the BYTE count, not keySize. The two differ:
	// CKA_VALUE_LEN is "a particular length in bytes" (v3.2 §6.10.3 for
	// CKM_AES_KEY_GEN, whose ulMinKeySize/ulMaxKeySize "specify the supported
	// range of AES key sizes, in bytes"), whereas keySize above is converted to
	// bits because that is what the backend's generation request expects.
	// Passing the bit count here would compare 256 against an inclusive range of
	// 16..32 and reject every legal AES key.
	//
	// A zero means the template did not specify a length, which leaves the size
	// to the mechanism's own default and is not the application's assertion of
	// anything to validate.
	//
	// The code is CKR_ATTRIBUTE_VALUE_INVALID: it is in C_GenerateKey's return
	// table (§5.18.1) and CKR_KEY_SIZE_RANGE is not — that one belongs to the
	// operations that use an existing key.
	if valueLenBytes > 0 && !IsValidKeySize(mechanism.Type, valueLenBytes) {
		return ObjectHandle(InvalidHandle), CKR_ATTRIBUTE_VALUE_INVALID
	}

	// Generate CKA_ID if not provided - use incrementing counter as bytes
	if len(ckaID) == 0 {
		idCounter := m.keyCounter.Add(1)
		ckaID = make([]byte, 4)
		ckaID[0] = byte(idCounter)
		ckaID[1] = byte(idCounter >> 8)
		ckaID[2] = byte(idCounter >> 16)
		ckaID[3] = byte(idCounter >> 24)
	}

	if label == "" {
		label = "generated-key"
	}

	// Generate a unique key ID by appending a timestamp-based suffix
	// This ensures uniqueness while keeping the label as a prefix for identification
	keyID := fmt.Sprintf("%s-%d-%d", label, time.Now().UnixNano(), m.keyCounter.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// Whatever the template did not say about protection, the token decides --
	// and it has to decide before the request is built, so that the backend's
	// key record and this token's object describe the same key.
	//
	// These were previously derived from two different templates. The request
	// read CKA_EXTRACTABLE with a CK_TRUE fallback while the object read it
	// from secretKeyProtectionDefaults, whose fallback is CK_FALSE, so a
	// template naming neither attribute produced a key the backend recorded as
	// exportable and this token recorded as unextractable.
	//
	// The CK_TRUE fallback came from reading Table 30's "CK_TRUE if key is
	// extractable and can be wrapped" as a default. That column states the
	// attribute's meaning; the table gives CKA_EXTRACTABLE no default, and its
	// footnote 9 -- "default value is token-specific, and may depend on the
	// values of other attributes" -- hands the choice to the token.
	// secretKeyProtectionDefaults is where this token makes it, and it chooses
	// the protective value, which is also what SoftHSM2 produces: pkcs11-tool
	// --keygen --key-type aes:32 with no protection attributes yields a key
	// reporting "never extractable", and C_GetAttributeValue(CKA_VALUE) on it
	// answers CKR_ATTRIBUTE_SENSITIVE.
	//
	// Footnotes 11 and 12 are why the protective value is the only safe default
	// to pick unasked: CKA_SENSITIVE cannot be changed once CK_TRUE and
	// CKA_EXTRACTABLE cannot be changed once CK_FALSE, so both move one way
	// only. A token that defaults to the weaker setting has silently spent a
	// ratchet the application still had; one that defaults to the stronger
	// leaves the application free to ask for the weaker in its template.
	template = secretKeyProtectionDefaults(template)

	req := &GenerateKeyRequest{
		KeyID:     keyID,
		Backend:   "", // Empty to use CryptoManager's DefaultBackend
		Mechanism: mechanism,
		KeySize:   keySize,
		// Both attributes are present in the template by now, so these
		// fallbacks never decide anything; they only keep the lookups total.
		Exportable: templateBoolIsTrue(template, CKA_EXTRACTABLE, false),
		Sensitive:  templateBoolIsTrue(template, CKA_SENSITIVE, true),
	}

	resp, err := m.cryptoManager.GenerateKey(ctx, req)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// Store the object
	access := NewAccessContext(sessionHandle, session)
	handle, storeErr := m.objectManager.CreateGeneratedObject(
		access, CKO_SECRET_KEY, mechanismToKeyTypeFromMech(mechanism.Type), template)
	if storeErr != nil {
		return ObjectHandle(InvalidHandle), FromError(storeErr)
	}

	// Set the backend-specific key information on the object
	obj, getErr := m.objectManager.getObjectUnchecked(handle)
	if getErr != nil {
		_ = m.objectManager.DestroyObject(access, handle)
		return ObjectHandle(InvalidHandle), FromError(getErr)
	}
	obj.KeyID = resp.KeyID
	obj.BackendName = m.cryptoManager.config.DefaultBackend

	// Set CKA_ID on the key object
	obj.SetAttribute(CKA_ID, ckaID)

	// Persist token objects to storage. A CKA_TOKEN key the store would not take
	// is not a key on the token, and reporting CKR_OK for one left the
	// application holding a handle to a key that vanished at C_Finalize.
	if persistErr := m.persistNewObject(access, handle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	return handle, CKR_OK
}

// GenerateKeyPair generates a public-key/private-key pair.
// Implements C_GenerateKeyPair behavior per PKCS#11 specification.
func (m *Module) GenerateKeyPair(sessionHandle SessionHandle, mechanism *Mechanism, publicKeyTemplate, privateKeyTemplate []Attribute) (ObjectHandle, ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), rv
	}

	// No unconditional read-only gate here. PKCS#11 v3.2 §5.7.1 says only that
	// "Only session objects can be created during a read-only session", so a
	// CKA_TOKEN=FALSE key is legal in a R/O session. The rule belongs to object
	// creation and is already enforced there by createPolicyChecked, which
	// gates on obj.IsToken && !ctx.ReadWrite. Rejecting every generation up
	// front refused a request the spec permits, and SoftHSM accepts it:
	// C_GenerateKey for a session key in a R/O session returns CKR_OK, and only
	// a token key returns CKR_SESSION_READ_ONLY. C_UnwrapKey in this file never
	// had the redundant gate, which is what made the inconsistency visible.
	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates
	// the crypto operations; which verb the caller uses must not change the
	// policy.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), rv
	}

	// C_GenerateKeyPair names no key, so there is nothing to order the mechanism
	// against; validateInitMechanism is still the one place that decides, so a
	// mechanism the module withholds cannot be reached through key-pair
	// generation. C_GenerateKeyPair has no NULL-pMechanism termination contract
	// — §5.18.2 states none — so a nil mechanism stays CKR_ARGUMENTS_BAD here.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), rv
	}

	// Extract key parameters from templates
	var label string
	var keySize int
	var curve string
	var ecParams []byte
	var ckaID []byte

	for _, attr := range publicKeyTemplate {
		switch attr.Type {
		case CKA_LABEL:
			label = attr.GetString()
		case CKA_MODULUS_BITS:
			if v, err := attr.GetUint32(); err == nil {
				keySize = int(v)
			}
		case CKA_EC_PARAMS:
			var recognized bool
			if curve, recognized = extractCurveFromParams(attr.Value); !recognized {
				// Naming a curve the module does not implement must fail
				// rather than quietly produce a key on a different one.
				return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle),
					CKR_CURVE_NOT_SUPPORTED
			}
			// An ECDSA key pair can only be generated on a curve an ECDSA key
			// can live on. The Edwards and Montgomery OIDs are recognised so
			// they can name their OWN key types, so this is gated on the
			// mechanism rather than applied to every CKA_EC_PARAMS -- gating on
			// the curve alone would refuse CKM_EC_EDWARDS_KEY_PAIR_GEN, which
			// is exactly the curve it is supposed to name. Shares
			// curveUsableForECDSA with C_UnwrapKey so the two verbs agree by
			// construction (#161).
			if mechanismToKeyTypeMap[mechanism.Type] == "ECDSA" && !curveUsableForECDSA(curve) {
				return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle),
					CKR_CURVE_NOT_SUPPORTED
			}
			ecParams = copyBytes(attr.Value)
		case CKA_ID:
			ckaID = attr.Value
		}
	}

	// CKA_MODULUS_BITS must lie inside the range C_GetMechanismInfo advertises
	// for the mechanism. Without this the requested modulus went straight to the
	// backend, which enforced a floor and no ceiling, so a single call asking
	// for a 16384-bit modulus made the daemon generate it and exhausted its
	// memory.
	//
	// CKA_MODULUS_BITS is a bit count and the RSA key-pair-generation range is
	// in bits (v3.2 §6.1.2), so keySize is compared directly — no conversion,
	// unlike C_GenerateKey's byte-valued CKA_VALUE_LEN.
	//
	// The zero test is required rather than cosmetic: elliptic-curve key-pair
	// generation carries no CKA_MODULUS_BITS and takes its size from
	// CKA_EC_PARAMS, so keySize stays zero and validating it would refuse every
	// EC key pair.
	//
	// The code is CKR_ATTRIBUTE_VALUE_INVALID: it is in C_GenerateKeyPair's
	// return table (§5.18.2) and CKR_KEY_SIZE_RANGE is not.
	if keySize > 0 && !IsValidKeySize(mechanism.Type, uint32(keySize)) {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), CKR_ATTRIBUTE_VALUE_INVALID
	}

	// Also check private key template for CKA_ID if not found in public
	if len(ckaID) == 0 {
		for _, attr := range privateKeyTemplate {
			if attr.Type == CKA_ID {
				ckaID = attr.Value
				break
			}
		}
	}

	// Generate CKA_ID if not provided - use incrementing counter as bytes
	if len(ckaID) == 0 {
		idCounter := m.keyCounter.Add(1)
		ckaID = make([]byte, 4)
		ckaID[0] = byte(idCounter)
		ckaID[1] = byte(idCounter >> 8)
		ckaID[2] = byte(idCounter >> 16)
		ckaID[3] = byte(idCounter >> 24)
	}

	if label == "" {
		label = "generated-keypair"
	}

	// A post-quantum key pair is generated by this module rather than by the
	// backend, and both of its addressing forms -- the v3.2 standard mechanism
	// with CKA_PARAMETER_SET, and the per-level vendor mechanism -- are resolved
	// to one answer here. See module_keygen_quantum.go for why the token
	// generates it in process.
	if spec, isQuantum, specErr := resolveQuantumKeyGenSpec(mechanism.Type, publicKeyTemplate, privateKeyTemplate); isQuantum {
		if specErr != nil {
			return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(specErr)
		}
		return m.generateQuantumKeyPair(sessionHandle, session, spec, publicKeyTemplate, privateKeyTemplate, ckaID)
	}

	// Generate a unique key ID by appending a timestamp-based suffix
	// This ensures uniqueness while keeping the label as a prefix for identification
	keyID := fmt.Sprintf("%s-%d-%d", label, time.Now().UnixNano(), m.keyCounter.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	req := &GenerateKeyPairRequest{
		KeyID:     keyID,
		Backend:   "", // Empty to use CryptoManager's DefaultBackend
		Mechanism: mechanism,
		KeySize:   keySize,
		Curve:     curve,
	}

	resp, err := m.cryptoManager.GenerateKeyPair(ctx, req)
	if err != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(err)
	}

	// Create public key object
	access := NewAccessContext(sessionHandle, session)
	keyType := mechanismToKeyTypeFromMech(mechanism.Type)
	pubHandle, pubErr := m.objectManager.CreateGeneratedObject(
		access, CKO_PUBLIC_KEY, keyType, publicKeyTemplate)
	if pubErr != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(pubErr)
	}

	// Set the backend-specific key information on the public key
	pubObj, pubGetErr := m.objectManager.getObjectUnchecked(pubHandle)
	if pubGetErr != nil {
		_ = m.objectManager.DestroyObject(access, pubHandle)
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(pubGetErr)
	}
	pubObj.KeyID = resp.KeyID
	pubObj.BackendName = m.cryptoManager.config.DefaultBackend

	// Set CKA_ID on public key (ensures consistent ID for key pair)
	pubObj.SetAttribute(CKA_ID, ckaID)

	// A key pair whose public half the backend did not return is one no consumer
	// can verify with or export: ssh-keygen -D lists nothing for it and
	// pkcs11-provider reports "could not obtain a key", both long after
	// C_GenerateKeyPair answered CKR_OK. extractPublicKeyComponentsFromPEM's own
	// doc argues this case must not be silent; the guard below reintroduced the
	// silence one level up by treating an empty PEM as a skip rather than a
	// failure.
	if resp.PublicKeyPEM == "" {
		if destroyErr := m.objectManager.DestroyObject(access, pubHandle); destroyErr != nil {
			m.logStorageError("destroy public key of a key pair with no public material", destroyErr)
		}
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	// Extract and store public key components from PEM for use in verify-recover, etc.
	if resp.PublicKeyPEM != "" {
		modulus, pubExponent, ecPoint, componentErr := extractPublicKeyComponentsFromPEM(resp.PublicKeyPEM)
		if componentErr != nil {
			_ = m.objectManager.DestroyObject(access, pubHandle)
			return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(componentErr)
		}
		if len(modulus) > 0 {
			pubObj.SetAttribute(CKA_MODULUS, modulus)
		}
		if len(pubExponent) > 0 {
			pubObj.SetAttribute(CKA_PUBLIC_EXPONENT, pubExponent)
		}
		if len(ecPoint) > 0 {
			pubObj.SetAttribute(CKA_EC_POINT, ecPoint)
		}
	}

	// Create private key object
	privHandle, privErr := m.objectManager.CreateGeneratedObject(
		access, CKO_PRIVATE_KEY, keyType, privateKeyTemplate)
	if privErr != nil {
		_ = m.objectManager.DestroyObject(access, pubHandle)
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(privErr)
	}

	// Set the backend-specific key information on the private key
	privObj, privGetErr := m.objectManager.getObjectUnchecked(privHandle)
	if privGetErr != nil {
		_ = m.objectManager.DestroyObject(access, pubHandle)
		_ = m.objectManager.DestroyObject(access, privHandle)
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(privGetErr)
	}
	privObj.KeyID = resp.KeyID
	privObj.BackendName = m.cryptoManager.config.DefaultBackend

	// Set CKA_ID on private key (same ID as public key for the pair)
	privObj.SetAttribute(CKA_ID, ckaID)

	// The curve is republished in the module's canonical encoding rather than
	// echoed back as supplied. PKCS#11 v3.2 §6.3.5 accepts both an OID and a
	// curveName PrintableString for an Edwards curve, but warns the RFC 8032
	// and RFC 8410 flavours are incompatible; OpenSSL implements RFC 8410, so a
	// key described only by curveName is one it cannot build a public key from.
	if len(ecParams) > 0 {
		if canonical, ok := canonicalECParams(ecParams); ok {
			pubObj.SetAttribute(CKA_EC_PARAMS, canonical)
		}
	}

	// An RSA private key object carries the public components too (v3.2 §4.9,
	// RSA private key attribute table). They are not secret, and a client needs
	// them to build the public key from the private object alone — OpenSSL's
	// engine reads CKA_MODULUS off the private key and refuses to load it at
	// all when the attribute is missing. An EC private key likewise carries
	// CKA_EC_PARAMS.
	for _, attr := range []AttributeType{CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_EC_PARAMS, CKA_EC_POINT} {
		if value := pubObj.GetAttribute(attr); len(value) > 0 {
			privObj.SetAttribute(attr, value)
		}
	}

	// Persist token objects to storage. C_GenerateKeyPair creates both objects
	// or neither (v3.2 §5.18.2), so a store that refuses either half takes the
	// other half down with it: the public key is removed from the store it
	// already reached, both objects are destroyed, and the caller is told the
	// token failed rather than handed a pair only one of which survives a
	// restart.
	if persistErr := m.persistNewObject(access, pubHandle, sessionHandle); persistErr != nil {
		if destroyErr := m.objectManager.DestroyObject(access, privHandle); destroyErr != nil {
			m.logStorageError("destroy private key of an unpersisted key pair", destroyErr)
		}
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}
	if persistErr := m.persistNewObject(access, privHandle, sessionHandle); persistErr != nil {
		if deleteErr := m.storage.DeleteObject(pubHandle); deleteErr != nil {
			m.logStorageError("delete public key of an unpersisted key pair", deleteErr)
		}
		if destroyErr := m.objectManager.DestroyObject(access, pubHandle); destroyErr != nil {
			m.logStorageError("destroy public key of an unpersisted key pair", destroyErr)
		}
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	return pubHandle, privHandle, CKR_OK
}

// GenerateRandom generates random data.
// Implements C_GenerateRandom behavior per PKCS#11 specification.
func (m *Module) GenerateRandom(sessionHandle SessionHandle, length uint32) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	randomData := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, randomData); err != nil {
		return nil, CKR_RANDOM_NO_RNG
	}

	return randomData, CKR_OK
}

// SeedRandom mixes seed material into the random number generator.
// Implements C_SeedRandom behavior per PKCS#11 specification.
func (m *Module) SeedRandom(sessionHandle SessionHandle, seed []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// The Go crypto/rand package uses the operating system's CSPRNG,
	// which typically doesn't support external seeding. We accept the
	// seed but don't actually use it (common for HSM implementations).
	// This is compliant with PKCS#11 which allows implementations to
	// ignore seed material if the RNG is already sufficiently random.
	if len(seed) == 0 {
		return CKR_ARGUMENTS_BAD
	}

	return CKR_OK
}

// ----------------------------------------------------------------
// Object Size Operations
// ----------------------------------------------------------------

// GetObjectSize obtains the size of an object in bytes.
// Implements C_GetObjectSize behavior per PKCS#11 specification.
func (m *Module) GetObjectSize(sessionHandle SessionHandle, objectHandle ObjectHandle) (uint64, CK_RV) {
	if !m.initialized.Load() {
		return 0, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return 0, rv
	}

	// Resolve through the session's access context so a size query cannot be
	// used as an existence oracle for objects the session may not see.
	obj, err := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), objectHandle)
	if err != nil {
		return 0, CKR_OBJECT_HANDLE_INVALID
	}

	// Calculate approximate object size based on object attributes
	// Use GetAttributeValue to retrieve attribute sizes
	var size uint64 = 64 // Base object overhead

	// Common attributes that contribute to size
	attrTypes := []AttributeType{CKA_VALUE, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_EC_POINT, CKA_LABEL, CKA_ID}
	for _, attrType := range attrTypes {
		attrVal := obj.GetAttribute(attrType)
		if len(attrVal) > 0 {
			size += uint64(len(attrVal))
			size += 8 // Overhead for attribute type and length
		}
	}

	return size, CKR_OK
}

// ----------------------------------------------------------------
// Key Wrapping Operations
// ----------------------------------------------------------------

// WrapKey wraps (encrypts) a key.
// Implements C_WrapKey behavior per PKCS#11 specification.
func (m *Module) WrapKey(sessionHandle SessionHandle, mechanism *Mechanism, wrappingKey, key ObjectHandle) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates
	// the crypto operations; which verb the caller uses must not change the
	// policy.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return nil, rv
	}

	access := NewAccessContext(sessionHandle, session)

	// Get the wrapping key
	wrapKeyObj, err := m.objectManager.GetObjectFor(access, wrappingKey)
	if err != nil {
		return nil, CKR_WRAPPING_KEY_HANDLE_INVALID
	}

	// CKA_WRAP MUST be CK_TRUE on the wrapping key (v3.2 §5.18.3). An absent
	// attribute is not permission.
	//
	// The code is CKR_WRAPPING_KEY_TYPE_INCONSISTENT, not
	// CKR_KEY_FUNCTION_NOT_PERMITTED: C_WrapKey's return table lists the former
	// and does not list the latter, and §5.1 defines it as "the type of the
	// wrapping key does not match the type required by the mechanism", which is
	// what a key not marked for wrapping is.
	if !boolAttributeIsTrue(wrapKeyObj.GetAttribute(CKA_WRAP)) {
		return nil, CKR_WRAPPING_KEY_TYPE_INCONSISTENT
	}

	// Get the key to be wrapped
	targetKeyObj, err := m.objectManager.GetObjectFor(access, key)
	if err != nil {
		return nil, CKR_KEY_HANDLE_INVALID
	}

	// CKA_EXTRACTABLE MUST be CK_TRUE on the key being wrapped. Wrapping is an
	// export path, so a key that was never marked extractable must not leave.
	if !boolAttributeIsTrue(targetKeyObj.GetAttribute(CKA_EXTRACTABLE)) {
		return nil, CKR_KEY_UNEXTRACTABLE
	}

	// A key marked CKA_WRAP_WITH_TRUSTED may only be wrapped by a key the
	// token itself has marked CKA_TRUSTED (v3.2 §4.9).
	if boolAttributeIsTrue(targetKeyObj.GetAttribute(CKA_WRAP_WITH_TRUSTED)) &&
		!boolAttributeIsTrue(wrapKeyObj.GetAttribute(CKA_TRUSTED)) {
		return nil, CKR_KEY_NOT_WRAPPABLE
	}

	// CKA_WRAP_TEMPLATE partitions a wrapping key so it may wrap only the
	// subset of keys whose attributes match (v3.2 §5.14.3).
	if err := wrapKeyObj.CheckWrapTemplate(targetKeyObj); err != nil {
		return nil, FromError(err)
	}

	// Keys first, then mechanism; validateInitMechanism documents why. Routing
	// through it is what puts C_WrapKey behind the FIPS filter: the wrapping
	// mechanism otherwise reached mechanismToAlgorithm and the backend without
	// the module ever deciding whether it offers the mechanism at all.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return nil, rv
	}

	// The mechanism must be one this token offers for wrapping specifically.
	// validateInitMechanism only asks whether the module offers the mechanism
	// at all, so without this a caller could name a signing or digesting
	// mechanism and reach mechanismToAlgorithm, which answers for any mechanism
	// by falling back to its plain name -- turning "this token does not wrap
	// with CKM_SHA256" into a request the service rejects for an unrelated
	// reason, or, for a mechanism the service happens to know, into a wrap the
	// token never advertised. CKF_WRAP is exactly the bit C_GetMechanismInfo
	// publishes for this question (v3.2 §5.5, Table 44), so the flag and the
	// routing table must agree; every mechanism in wrapAlgorithmNames, and
	// CKM_RSA_PKCS_OAEP which oaepWrapAlgorithm resolves, carries it.
	if !CanWrap(mechanism.Type) {
		return nil, CKR_MECHANISM_INVALID
	}

	// CKA_ALLOWED_MECHANISMS on the wrapping key names the mechanisms that key
	// may be used with, wrapping included (v3.2 §4.8.2).
	if err := wrapKeyObj.CheckAllowedMechanism(mechanism.Type); err != nil {
		return nil, FromError(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	params, rv := wrapMechanismParameters(mechanism)
	if rv != CKR_OK {
		return nil, rv
	}

	req := &WrapKeyByIDRequest{
		WrappingKeyID:      wrapKeyObj.KeyID,
		WrappingKeyBackend: wrapKeyObj.BackendName,
		Algorithm:          mechanismToAlgorithm(mechanism),
		Params:             params,
	}

	// A target key that lives in a backend is named by its id, so its
	// plaintext is never assembled in this process. A key this module holds
	// itself -- one imported with C_CreateObject and CKA_VALUE, which never
	// receives a backend key id -- travels as material instead.
	//
	// Both forms are wrapped by the same service-side implementation, which is
	// what makes C_WrapKey and C_UnwrapKey agree on framing for every
	// mechanism. Encrypting the local value here instead did not: the AES-GCM
	// nonce the token generated stayed on the discarded EncryptOperation and
	// the blob was emitted as ciphertext||tag, where C_UnwrapKey parses
	// nonce||ciphertext||tag; AES-CBC emitted no IV where C_UnwrapKey expects
	// one; and the AES key-wrap mechanisms could not be reached at all,
	// because C_EncryptInit rejects a mechanism that does not carry
	// CKF_ENCRYPT. Every one of those wraps returned CKR_OK and a blob nothing
	// could unwrap.
	if targetKeyObj.KeyID != "" {
		req.TargetKeyID = targetKeyObj.KeyID
		req.TargetKeyBackend = targetKeyObj.BackendName
	} else {
		keyValue := targetKeyObj.GetAttribute(CKA_VALUE)
		if len(keyValue) == 0 {
			return nil, CKR_KEY_NOT_WRAPPABLE
		}
		req.TargetKeyMaterial = keyValue
	}

	wrappedKey, wrapErr := m.cryptoManager.WrapKeyByID(ctx, req)
	if wrapErr != nil {
		return nil, FromError(wrapErr)
	}

	return wrappedKey, CKR_OK
}

// UnwrapKey unwraps (decrypts) a key.
// Implements C_UnwrapKey behavior per PKCS#11 specification.
func (m *Module) UnwrapKey(sessionHandle SessionHandle, mechanism *Mechanism, unwrappingKey ObjectHandle, wrappedKey []byte, template []Attribute) (ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates
	// the crypto operations; which verb the caller uses must not change the
	// policy.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	access := NewAccessContext(sessionHandle, session)

	// Get the unwrapping key. Resolving through the access context keeps a
	// public session from unwrapping with a private key it must not see.
	unwrapKeyObj, err := m.objectManager.GetObjectFor(access, unwrappingKey)
	if err != nil {
		return ObjectHandle(InvalidHandle), CKR_UNWRAPPING_KEY_HANDLE_INVALID
	}

	// CKA_UNWRAP MUST be CK_TRUE on the unwrapping key (v3.2 §5.18.6). An
	// absent attribute is not permission: it means the key was never marked
	// usable for unwrapping.
	//
	// The code is CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, not
	// CKR_KEY_FUNCTION_NOT_PERMITTED: C_UnwrapKey's return table lists the
	// former and does not list the latter, and §5.1 defines it as "the type of
	// the unwrapping key does not match the type required by the mechanism",
	// which is what a key not marked for unwrapping is.
	if !boolAttributeIsTrue(unwrapKeyObj.GetAttribute(CKA_UNWRAP)) {
		return ObjectHandle(InvalidHandle), CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
	}

	// CKA_ALWAYS_AUTHENTICATE deliberately does not gate this call; see
	// requireContextAuthentication for the reasoning, which C_UnwrapKey,
	// C_UnwrapKeyAuthenticated and C_DecapsulateKey share.

	// Key first, then mechanism; validateInitMechanism documents why. Routing
	// through it is what puts C_UnwrapKey behind the FIPS filter, which
	// mechanismToAlgorithm alone never applied.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	// The mechanism must be one this token offers for unwrapping specifically;
	// see the matching CanWrap gate in WrapKey for why the flag rather than
	// mere registration is the question. CKF_UNWRAP is the bit
	// C_GetMechanismInfo publishes for it (v3.2 §5.5, Table 44).
	if !CanUnwrap(mechanism.Type) {
		return ObjectHandle(InvalidHandle), CKR_MECHANISM_INVALID
	}

	// CKA_ALLOWED_MECHANISMS on the unwrapping key names the mechanisms that
	// key may be used with, unwrapping included (v3.2 §4.8.2).
	if mechErr := unwrapKeyObj.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return ObjectHandle(InvalidHandle), FromError(mechErr)
	}

	// CKA_UNWRAP_TEMPLATE adds the unwrapping key's attribute set to the
	// caller's template for the key about to be unwrapped (v3.2 §5.14.4). It is
	// merged before the backend call, not merely before object creation,
	// because the merged template is what decides the size and exportability
	// the unwrapped key is created with in the backend.
	template, err = unwrapKeyObj.ApplyAttributeTemplate(CKA_UNWRAP_TEMPLATE, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// Unwrap inside the backend. The plaintext key must never enter the
	// module's attribute map: an unwrapped key marked sensitive or
	// unextractable would otherwise sit in process memory and, for a token
	// object, be serialized to storage in the clear.
	keyType, targetType := unwrapTargetKeyType(template)
	targetKeyID := fmt.Sprintf("unwrapped-%d-%d", time.Now().UnixNano(), m.keyCounter.Add(1))

	// The same CK_MECHANISM parameters C_WrapKey carries, resolved by the same
	// helper. AAD and the OAEP label are not recoverable from the blob -- one
	// is authenticated rather than encrypted, the other is bound into the OAEP
	// encoding -- so an unwrap that dropped them could not reverse a wrap that
	// honoured them.
	params, rv := wrapMechanismParameters(mechanism)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	// The curve the template names, for an EC target. Without it the service
	// substitutes P-256 for an empty curve (applyAsymmetricAlgorithm), so a
	// P-384 or P-521 key reached the backend described as P-256 -- stored under
	// attributes that misstate the key and reported as ECC_NIST_P256 by
	// determineKeySpec. UnwrapKeyByIDRequest has always carried TargetCurve and
	// CryptoManager has always mapped it onto the transport request; this call
	// site simply never filled it in.
	//
	// Only for an ECDSA target: the service consumes a curve for ECDSA and for
	// nothing else, and backendKeyTypeName maps every key type it does not name
	// to "symmetric", so looking one up elsewhere would refuse a request over an
	// attribute that cannot affect its result.
	var targetCurve string
	if targetType == "ecdsa" {
		name, present, curveRV := templateCurveName(template)
		if curveRV != CKR_OK {
			return ObjectHandle(InvalidHandle), curveRV
		}
		// Gate on the presence flag, never on the name alone. An absent
		// CKA_EC_PARAMS is the case Table 13 footnote 6 requires for an
		// unwrapped EC private key, so it must reach the backend and take the
		// service's default -- refusing it here would break the spec's own
		// shape of the call (#161).
		if present && !curveUsableForECDSA(name) {
			// Recognised, but not a curve an ECDSA key can live on. Refusing
			// here gives the caller CKR_CURVE_NOT_SUPPORTED, which PKCS#11
			// defines for exactly this, instead of the generic "invalid curve"
			// the service returns several layers down.
			return ObjectHandle(InvalidHandle), CKR_CURVE_NOT_SUPPORTED
		}
		targetCurve = name
	}

	newKeyID, unwrapErr := m.cryptoManager.UnwrapKeyByID(ctx, &UnwrapKeyByIDRequest{
		WrappedKey:           wrappedKey,
		UnwrappingKeyID:      unwrapKeyObj.KeyID,
		UnwrappingKeyBackend: unwrapKeyObj.BackendName,
		Algorithm:            mechanismToAlgorithm(mechanism),
		Params:               params,
		TargetKeyID:          targetKeyID,
		TargetKeyBackend:     unwrapKeyObj.BackendName,
		TargetKeyType:        targetType,
		TargetKeySize:        templateValueLenBits(template),
		TargetCurve:          targetCurve,
		TargetExportable:     templateBoolIsTrue(template, CKA_EXTRACTABLE, true),
	})
	if unwrapErr != nil {
		return ObjectHandle(InvalidHandle), FromError(unwrapErr)
	}

	// PKCS#11 v3.2 §5.18.4 fixes this default for C_UnwrapKey specifically:
	// "The CKA_EXTRACTABLE attribute is by default set to CK_TRUE." Unlike
	// C_GenerateKey's protection defaults, which §4.9 footnote 9 leaves to the
	// token, this one is the spec's. Letting it fall through to Go's zero value
	// made every unwrapped key non-extractable, so its value could never be
	// read back and it could never be re-wrapped.
	if _, ok := attributeByType(template, CKA_EXTRACTABLE); !ok {
		template = append(template, NewBoolAttribute(CKA_EXTRACTABLE, true))
	}

	handle, createErr := m.objectManager.CreateDerivedObject(
		access, unwrapKeyObj, unwrapTargetClass(template), keyType, template)
	if createErr != nil {
		return ObjectHandle(InvalidHandle), FromError(createErr)
	}

	obj, getErr := m.objectManager.getObjectUnchecked(handle)
	if getErr != nil {
		_ = m.objectManager.DestroyObject(access, handle)
		return ObjectHandle(InvalidHandle), FromError(getErr)
	}
	obj.KeyID = newKeyID
	obj.BackendName = unwrapKeyObj.BackendName

	// A CKA_TOKEN unwrapped key the store would not take was not imported, so
	// C_UnwrapKey reports the token failure rather than a handle whose object
	// disappears at the next start (v3.2 §5.18.4). The key material itself is in
	// the backend under newKeyID; what is lost with the object is the token's
	// only record of which key that is.
	if persistErr := m.persistNewObject(access, handle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	return handle, CKR_OK
}

// DeriveKey derives a key from a base key.
// Implements C_DeriveKey behavior per PKCS#11 specification.
func (m *Module) DeriveKey(sessionHandle SessionHandle, mechanism *Mechanism, baseKey ObjectHandle, template []Attribute) (ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	// No unconditional read-only gate here. PKCS#11 v3.2 §5.7.1 says only that
	// "Only session objects can be created during a read-only session", so a
	// CKA_TOKEN=FALSE key is legal in a R/O session. The rule belongs to object
	// creation and is already enforced there by createPolicyChecked, which
	// gates on obj.IsToken && !ctx.ReadWrite. Rejecting every generation up
	// front refused a request the spec permits, and SoftHSM accepts it:
	// C_GenerateKey for a session key in a R/O session returns CKR_OK, and only
	// a token key returns CKR_SESSION_READ_ONLY. C_UnwrapKey in this file never
	// had the redundant gate, which is what made the inconsistency visible.
	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates the
	// crypto operations; which verb the caller uses must not change the policy.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return ObjectHandle(InvalidHandle), CKR_SESSION_HANDLE_INVALID
	}

	// Get the base key
	baseKeyObj, err := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), baseKey)
	if err != nil {
		return ObjectHandle(InvalidHandle), CKR_KEY_HANDLE_INVALID
	}

	// CKA_DERIVE MUST be CK_TRUE on the base key (v3.2 §5.18.5). An absent
	// attribute means the key was never marked usable for derivation.
	//
	// The code is CKR_KEY_FUNCTION_NOT_PERMITTED. §5.1.6 defines it as "an
	// attempt has been made to use a key for a cryptographic purpose that the
	// key's attributes are not set to allow it to do", which is this condition
	// exactly, and defines CKR_KEY_TYPE_INCONSISTENT as "the specified key is
	// not the correct type of key to use with the specified mechanism", which
	// is a different fault: here the key is an EC key and the mechanism is
	// CKM_ECDH1_DERIVE, so the type is right and only the attribute is wrong.
	//
	// C_DeriveKey's enumerated return values in §5.18.5 list
	// CKR_KEY_TYPE_INCONSISTENT and omit CKR_KEY_FUNCTION_NOT_PERMITTED, which
	// is why this function used to return the former. That list is an
	// enumeration of what the function may return, not a mapping of conditions
	// to codes -- §5.1.7 says that where more than one code applies any of them
	// may be returned -- and it cannot make a code apply whose own definition
	// excludes the condition. SoftHSM2 answers this case with
	// CKR_KEY_FUNCTION_NOT_PERMITTED
	// (TestReferenceDeriveKeyRefusesABaseKeyWithoutCKADerive in the C ABI
	// suite records the probe), so returning the other code also disagreed with
	// what applications see from a conforming token.
	if !boolAttributeIsTrue(baseKeyObj.GetAttribute(CKA_DERIVE)) {
		return ObjectHandle(InvalidHandle), CKR_KEY_FUNCTION_NOT_PERMITTED
	}

	// Key first, then mechanism; validateInitMechanism documents why. Routing
	// through it is what puts C_DeriveKey behind the FIPS filter: the switch
	// below decides only which derivation this module implements, and knows
	// nothing about whether the module is permitted to offer it.
	if rv := validateInitMechanism(mechanism); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	// CKA_ALLOWED_MECHANISMS on the base key names the mechanisms that key may
	// be used with, derivation included (v3.2 §4.8.2).
	if mechErr := baseKeyObj.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return ObjectHandle(InvalidHandle), FromError(mechErr)
	}

	// CKA_DERIVE_TEMPLATE adds the base key's attribute set to the caller's
	// template for the key about to be derived (v3.2 §5.15.1). Merging here,
	// ahead of the mechanism switch, is what makes the constraint apply to both
	// derivation paths: the ECDH case returns from inside the switch with its
	// own CreateDerivedObject, and a merge placed after the switch would reach
	// only the KDF path. It also precedes the CKA_VALUE_LEN lookups, so a
	// length the constraint fixes is the length actually derived.
	template, err = baseKeyObj.ApplyAttributeTemplate(CKA_DERIVE_TEMPLATE, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// A derived key whose only copy of its material this token could not give
	// back is refused before anything is derived; derivedKeyPersistenceError
	// gives the reason. The check sits ahead of the mechanism switch for the
	// same reason the CKA_DERIVE_TEMPLATE merge does: the ECDH case returns from
	// inside the switch with its own CreateDerivedObject, so a check placed
	// after the switch would cover only the KDF path. It follows the merge so
	// that a CKA_TOKEN or CKA_SENSITIVE the base key's constraint contributes is
	// part of what is judged.
	if persistErr := derivedKeyPersistenceError(template); persistErr != nil {
		return ObjectHandle(InvalidHandle), FromError(persistErr)
	}

	// Check supported mechanisms
	switch mechanism.Type {
	case CKM_HKDF_DERIVE, CKM_HKDF_DATA, CKM_HKDF_KEY_GEN,
		CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF, CKM_SP800_108_DOUBLE_PIPELINE_KDF:
		// Supported derivation mechanisms - continue
	case CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE:
		// ECDH key derivation
		return m.deriveKeyECDH(sessionHandle, mechanism, baseKeyObj, template, sm)
	default:
		return ObjectHandle(InvalidHandle), CKR_MECHANISM_INVALID
	}

	// Initialize the operation in the session manager
	if err := sm.InitializeOperation(sessionHandle, OperationDerive, mechanism.Type, baseKey); err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// Create derive operation via CryptoManager
	deriveOp, cryptoErr := m.cryptoManager.DeriveKeyInit(mechanism, baseKey, baseKeyObj.KeyID, baseKeyObj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDerive)
		return ObjectHandle(InvalidHandle), FromError(cryptoErr)
	}

	// The base key supplies the input keying material, and only the base key
	// does. PKCS#11 v3.2 §5.18.5 derives "a key from a base key", and §6.62.3
	// names that key as HKDF's input key; nothing in either reading permits a
	// substitute.
	//
	// Exactly one of two forms is sent to the backend:
	//
	//	CKA_VALUE present  the application supplied this key's bytes itself
	//	                   through C_CreateObject, so the module holds them and
	//	                   sends them.
	//	CKA_VALUE absent   the token created the material inside the backend and
	//	                   kept only an identifier, so the IDENTITY travels and
	//	                   the backend runs the KDF over the key it holds. A
	//	                   hardware-backed key's bytes never leave the token,
	//	                   and this is what lets such a key be derived from at
	//	                   all.
	//
	// A base key that is neither — no CKA_VALUE and no backend key identifier —
	// names no key material anywhere and cannot be derived from. The code is
	// CKR_KEY_HANDLE_INVALID, which C_DeriveKey's return table lists and which
	// §5.1 defines to cover exactly this: "it may be the case that the
	// specified handle is a valid handle for an object which is not a key".
	// CKR_KEY_TYPE_INCONSISTENT is deliberately not reused here; it already
	// means "this key is not marked for derivation" a few lines above, and one
	// code for two conditions makes both undiagnosable.
	//
	// There is deliberately no fallback here. The code this replaced
	// substituted []byte(baseKeyObj.KeyID) — the "label-<unixnano>-<counter>"
	// string C_GenerateKey assigns — whenever CKA_VALUE was absent, which is
	// every key the token ever generated. Every such derivation ran the KDF
	// over the key's NAME, so anyone who knew the label could reproduce the
	// derived key. A base key that cannot be resolved to real key material is
	// an error, never a fallback.
	ikm := baseKeyObj.GetAttribute(CKA_VALUE)
	if len(ikm) == 0 && baseKeyObj.KeyID == "" {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDerive)
		return ObjectHandle(InvalidHandle), CKR_KEY_HANDLE_INVALID
	}

	// Get desired key length from template
	keyLength := 32 // Default
	for _, attr := range template {
		if attr.Type == CKA_VALUE_LEN {
			if len(attr.Value) >= 4 {
				keyLength = int(attr.Value[0]) | int(attr.Value[1])<<8 | int(attr.Value[2])<<16 | int(attr.Value[3])<<24
			}
		}
	}

	// Perform key derivation via transport layer
	// Every backend round-trip runs under a deadline. Without one a stalled
	// connection blocks this call forever inside the host application.
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()
	derivedKeyMaterial, cryptoErr := m.cryptoManager.DeriveKey(ctx, deriveOp, ikm, keyLength)
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDerive)
		return ObjectHandle(InvalidHandle), FromError(cryptoErr)
	}

	// Finalize the operation
	_ = sm.FinalizeOperationType(sessionHandle, OperationDerive)

	// Build the derived key template
	derivedKeyTemplate := derivedKeyAttributes(template, derivedKeyMaterial)

	access := NewAccessContext(sessionHandle, session)
	handle, err := m.objectManager.CreateDerivedObject(
		access, baseKeyObj, CKO_SECRET_KEY, CKK_GENERIC_SECRET, derivedKeyTemplate)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// A CKA_TOKEN derived key the store would not take was not derived, for the
	// reason C_CreateObject gives (v3.2 §5.18.5).
	if persistErr := m.persistNewObject(access, handle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	return handle, CKR_OK
}

// derivedKeyAttributes builds the attributes describing freshly derived key
// material. The material is carried in CKA_VALUE because key derivation
// produces the key locally; the key therefore defaults to sensitive and
// non-extractable so C_GetAttributeValue will not hand it back and the
// persistence layer will not write it out. A caller may relax either default
// explicitly in its own template.
func derivedKeyAttributes(template []Attribute, material []byte) []Attribute {
	valueLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueLen, uint32(len(material)))

	// The token supplies the derived material itself, so CKA_VALUE and
	// CKA_VALUE_LEN always describe what was actually derived and override
	// whatever the caller asked for. Everything else the caller set is kept.
	attrs := overrideAttributes(template,
		Attribute{Type: CKA_VALUE, Value: material},
		Attribute{Type: CKA_VALUE_LEN, Value: valueLen},
	)

	if _, ok := templateAttribute(attrs, CKA_SENSITIVE); !ok {
		attrs = append(attrs, NewBoolAttribute(CKA_SENSITIVE, true))
	}
	if _, ok := templateAttribute(attrs, CKA_EXTRACTABLE); !ok {
		attrs = append(attrs, NewBoolAttribute(CKA_EXTRACTABLE, false))
	}

	return attrs
}

// derivedKeyPersistenceError refuses a C_DeriveKey template that asks this token
// both to keep the derived key and to protect the only copy of it.
//
// A derived key is not like a C_UnwrapKey result. C_UnwrapKey unwraps inside the
// backend and gives its object a KeyID, so the object is metadata and the
// material stays where the backend holds it; dropping the object's sensitive
// attributes on the way to the store costs that key nothing. A derived key is
// built by derivedKeyAttributes, which carries the material in CKA_VALUE, and
// ObjectManager.CreateDerivedObject gives it no KeyID and no backend name, so
// CKA_VALUE is the only copy there is. ModuleStorage.SaveObject withholds every
// attribute IsSensitiveAttribute names — CKA_VALUE among them — from a key
// object that protects its material, because the token store is a plaintext file
// and writing the secret there would place in the clear exactly the bytes
// CKA_SENSITIVE and CKA_EXTRACTABLE=CK_FALSE promise never leave the token.
//
// The two rules meet on a CKA_TOKEN=CK_TRUE derived key the caller also asks to
// be protected: what persists is a key-shaped shell with no key in it, and every
// use of it after the restart fails on a handle the application had every reason
// to believe was a key. That is the defect sharedSecretPersistenceError refuses
// for a KEM shared secret and quantumPrivateKeyPersistenceError for a
// post-quantum private key, and it is refused here for the same reason rather
// than persisted, because persisting it is what produces the shell.
//
// CKR_TEMPLATE_INCONSISTENT is in C_DeriveKey's return table (v3.2 §5.18.5), and
// §5.1 defines it as a template carrying conflicting attributes — which asking
// this token both to keep a key and to protect its only copy of that key is. The
// same section requires the refusal to come before the derivation: "If a call to
// C_DeriveKey cannot support the precise template supplied to it, it will fail
// and return without creating any key object."
//
// Unlike the KEM path, the storable combination is not the default here.
// buildSecretKeyTemplate leaves a shared secret CKA_SENSITIVE=CK_FALSE and
// CKA_EXTRACTABLE=CK_TRUE, so a KEM template that states neither is storable;
// derivedKeyAttributes injects CKA_SENSITIVE=CK_TRUE and
// CKA_EXTRACTABLE=CK_FALSE, so a derive template that states neither is not.
// Those injected values, and not the class defaults applyClassDefaults would
// supply, are therefore the fallbacks tested here — testing the class defaults
// would admit exactly the template that produces the shell.
func derivedKeyPersistenceError(template []Attribute) error {
	// CKA_SENSITIVE and CKA_EXTRACTABLE carry protection semantics only for the
	// key classes (v3.2 §4.9), and Object.protectsSensitiveAttributes withholds
	// attributes from those alone. C_DeriveKey creates a CKO_SECRET_KEY unless
	// the template names another class, which is not hypothetical here:
	// CKM_HKDF_DATA is one of the mechanisms this module derives with, and
	// §6.62.4 makes its output "a CKO_DATA object whose value is the result of
	// the derive operation". A data object's CKA_VALUE is public object content
	// that the store always writes out, so nothing is lost by keeping it.
	class, ok, err := templateClass(template)
	if err != nil || !ok {
		class = CKO_SECRET_KEY
	}
	switch class {
	case CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKO_OTP_KEY:
	default:
		return nil
	}

	// A session object is never written to the store at all, so a protected one
	// keeps its CKA_VALUE for as long as it exists and loses nothing.
	if !templateBoolIsTrue(template, CKA_TOKEN, false) {
		return nil
	}

	sensitive := templateBoolIsTrue(template, CKA_SENSITIVE, true)
	extractable := templateBoolIsTrue(template, CKA_EXTRACTABLE, false)
	if !sensitive && extractable {
		return nil
	}

	return NewPKCS11ErrorWithMessage(CKR_TEMPLATE_INCONSISTENT,
		"a CKA_TOKEN derived key must be CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE: this token cannot persist protected key material")
}

// overrideAttributes returns template with each override replacing any existing
// attribute of the same type, appending the ones that were absent. A template
// must never carry the same attribute twice — that is CKR_TEMPLATE_INCONSISTENT.
func overrideAttributes(template []Attribute, overrides ...Attribute) []Attribute {
	result := make([]Attribute, 0, len(template)+len(overrides))
	replaced := make(map[AttributeType]bool, len(overrides))

	for _, attr := range template {
		if override, ok := attributeByType(overrides, attr.Type); ok {
			if !replaced[attr.Type] {
				result = append(result, override)
				replaced[attr.Type] = true
			}
			continue
		}
		result = append(result, attr)
	}

	for _, override := range overrides {
		if !replaced[override.Type] {
			result = append(result, override)
		}
	}

	return result
}

// IsAttributeArrayType reports whether an attribute's value is a nested
// template — an array of CK_ATTRIBUTE in the C API — rather than a scalar or an
// opaque byte string. The five such attributes are named in PKCS#11 v3.2 §4.8.2
// and §4.9: CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE,
// CKA_ENCAPSULATE_TEMPLATE and CKA_DECAPSULATE_TEMPLATE.
//
// It exists so the cgo boundary can tell which caller-supplied values must be
// flattened with EncodeAttributeArray on the way in and expanded back into a
// real CK_ATTRIBUTE array on the way out. It reads object.go's
// attributeArrayTypes rather than restating the list, so the boundary and the
// attribute policy table can never disagree about which attributes are
// templates.
func IsAttributeArrayType(attrType AttributeType) bool {
	return attributeArrayTypes[attrType]
}

// attributeByType looks up an attribute by type.
func attributeByType(attrs []Attribute, attrType AttributeType) (Attribute, bool) {
	for _, attr := range attrs {
		if attr.Type == attrType {
			return attr, true
		}
	}
	return Attribute{}, false
}

// deriveKeyECDH performs ECDH key derivation using the existing backend implementation.
func (m *Module) deriveKeyECDH(sessionHandle SessionHandle, mechanism *Mechanism, baseKeyObj *Object, template []Attribute, sm *SessionManager) (ObjectHandle, CK_RV) {
	// Extract ECDH parameters from mechanism
	ecdhParams, ok := mechanism.TypedParameter.(*ECDHParams)
	if !ok || ecdhParams == nil {
		// Try to parse from raw parameter bytes
		if len(mechanism.Parameter) < 8 {
			return ObjectHandle(InvalidHandle), CKR_MECHANISM_PARAM_INVALID
		}
		// Parse CK_ECDH1_DERIVE_PARAMS structure:
		// - KDF (CK_EC_KDF_TYPE, 4 bytes)
		// - SharedDataLen (CK_ULONG, 4/8 bytes depending on platform)
		// - SharedData (pointer, variable)
		// - PublicDataLen (CK_ULONG)
		// - PublicData (pointer)
		// For simplicity, require TypedParameter to be set by the CGO layer
		return ObjectHandle(InvalidHandle), CKR_MECHANISM_PARAM_INVALID
	}

	// The peer's point is validated before it reaches any backend: an
	// unvalidated point on a low-order twist turns each derivation into a leak
	// of the static private scalar (SP 800-56A Rev. 3 §5.6.2.3.2).
	if err := ValidateECDHPeerPoint(ecdhParams.PublicData); err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// Resolve the CK_EC_KDF_TYPE through the mechanism table. A KDF type this
	// module does not implement is refused: deriving with a substitute KDF
	// would hand back key material the caller never requested under CKR_OK.
	kdfAlgorithm, kdfHash, kdfOK := ECDHKDF(ecdhParams.KDF)
	if !kdfOK {
		return ObjectHandle(InvalidHandle), CKR_MECHANISM_PARAM_INVALID
	}

	// Get desired key length from template
	keyLength := 32 // Default 256-bit
	for _, attr := range template {
		if attr.Type == CKA_VALUE_LEN {
			if len(attr.Value) >= 4 {
				keyLength = int(attr.Value[0]) | int(attr.Value[1])<<8 | int(attr.Value[2])<<16 | int(attr.Value[3])<<24
			}
		}
	}

	// Build ECDH request for crypto manager
	req := &DeriveKeyECDHRequest{
		BaseKeyID:     baseKeyObj.KeyID,
		Backend:       baseKeyObj.BackendName,
		PeerPublicKey: ecdhParams.PublicData,
		KDFAlgorithm:  kdfAlgorithm,
		KDFHash:       kdfHash,
		Salt:          nil,
		Info:          ecdhParams.SharedData,
		KeyLength:     keyLength,
	}

	// Perform ECDH derivation via transport layer
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	derivedKeyMaterial, err := m.cryptoManager.DeriveKeyECDH(ctx, req)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// Build the derived key template. derivedKeyAttributes already carries the
	// caller's template forward, so it must not be appended a second time.
	derivedKeyTemplate := derivedKeyAttributes(template, derivedKeyMaterial)

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	access := NewAccessContext(sessionHandle, session)
	handle, createErr := m.objectManager.CreateDerivedObject(
		access, baseKeyObj, CKO_SECRET_KEY, CKK_GENERIC_SECRET, derivedKeyTemplate)
	if createErr != nil {
		return ObjectHandle(InvalidHandle), FromError(createErr)
	}

	// A CKA_TOKEN derived key the store would not take was not derived, for the
	// reason C_CreateObject gives (v3.2 §5.18.5).
	if persistErr := m.persistNewObject(access, handle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	return handle, CKR_OK
}

// ----------------------------------------------------------------
// Operation State Functions
// ----------------------------------------------------------------

// GetOperationStateBytes returns the cryptographic operation state as bytes.
// Implements C_GetOperationState behavior per PKCS#11 specification.
func (m *Module) GetOperationStateBytes(sessionHandle SessionHandle) ([]byte, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	opState := session.GetOperationState()
	if opState.Type == OperationNone {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// The running state of every operation this module supports lives in the
	// crypto manager or in the backend, not in the session, so it cannot leave
	// the token. PKCS#11 v3.2 §5.6.6 provides for exactly that: a token answers
	// CKR_STATE_UNSAVEABLE when "certain necessary state information and/or key
	// information can't leave the token".
	//
	// This is unconditional rather than gated on CryptoOp being non-nil. Every
	// savable operation sets CryptoOp in its *Init, so the gate was always true
	// in practice and the serializer below it was unreachable through the public
	// API — its only possible input was a blob this module had itself produced,
	// which it never could. Returning the refusal here says plainly what the
	// token does instead of leaving dead code that suggests otherwise.
	return nil, CKR_STATE_UNSAVEABLE
}

// SetOperationStateBytes restores the cryptographic operation state from bytes.
//
// PKCS#11 v3.2 §5.6.7 defines this as the exact inverse of C_GetOperationState:
// it restores state "obtained with C_GetOperationState". This module's
// C_GetOperationState never produces such state — every operation's running
// state lives in the crypto manager or in the backend and cannot leave the
// token, so it answers CKR_STATE_UNSAVEABLE for every savable operation
// (§5.6.6). No byte string this function can be handed is therefore valid saved
// state, and §5.6.7 names the answer for that: "If C_SetOperationState is
// supplied with alleged saved cryptographic operations state which it can
// determine is not valid saved state ... it fails with the error
// CKR_SAVED_STATE_INVALID."
//
// The previous implementation parsed the blob and reported CKR_OK, which was
// wrong in five separate ways and worse than refusing: accumulated data was
// stored and then silently ignored, so a restored digest returned the hash of
// only the bytes supplied afterwards; the encryption and authentication key
// handles were accepted and never examined, so none of §5.6.7's CKR_KEY_NEEDED,
// CKR_KEY_NOT_NEEDED or CKR_KEY_CHANGED could ever be returned; an
// out-of-range operation type wiped the session's entire operation map while
// still reporting success; it refused with CKR_OPERATION_ACTIVE where §5.6.7
// explicitly permits restoring over an active operation; and the restored
// operation was a zombie that reported itself both active and uninitialized
// depending on which function was asked.
func (m *Module) SetOperationStateBytes(sessionHandle SessionHandle, state []byte, encryptionKey, authenticationKey ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, _, rv := m.findSession(sessionHandle); rv != CKR_OK {
		return rv
	}

	return CKR_SAVED_STATE_INVALID
}

// GetOperationState returns the cryptographic operation state.
// This is an alias for GetOperationStateBytes for PKCS#11 C_GetOperationState compliance.
func (m *Module) GetOperationState(sessionHandle SessionHandle) ([]byte, CK_RV) {
	return m.GetOperationStateBytes(sessionHandle)
}

// SetOperationState restores the cryptographic operation state.
// This is an alias for SetOperationStateBytes for PKCS#11 C_SetOperationState compliance.
func (m *Module) SetOperationState(sessionHandle SessionHandle, state []byte, encryptionKey, authenticationKey ObjectHandle) CK_RV {
	return m.SetOperationStateBytes(sessionHandle, state, encryptionKey, authenticationKey)
}

// ----------------------------------------------------------------
// Legacy Parallel Function Management (Section 5.16)
// These functions are deprecated in PKCS#11 v3.0 and return CKR_FUNCTION_NOT_PARALLEL.
// ----------------------------------------------------------------

// GetFunctionStatus implements C_GetFunctionStatus and always returns
// CKR_FUNCTION_NOT_PARALLEL.
//
// PKCS#11 v3.0 §5.16 retired the parallel-function API but keeps the entry
// point in the function list, so a conformant module must still export it and
// answer exactly this way. It is a legacy surface, not a discouraged one: no
// replacement exists to move callers to, so it carries no Go deprecation
// marker.
func (m *Module) GetFunctionStatus(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// Validate session exists
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// Per PKCS#11 v3.0, this legacy function should return CKR_FUNCTION_NOT_PARALLEL
	return CKR_FUNCTION_NOT_PARALLEL
}

// CancelFunction implements C_CancelFunction and always returns
// CKR_FUNCTION_NOT_PARALLEL. See GetFunctionStatus above: PKCS#11 v3.0 §5.16
// retired the parallel-function API but a conformant module must still export
// this entry point and answer exactly this way.
func (m *Module) CancelFunction(sessionHandle SessionHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// Validate session exists
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// Per PKCS#11 v3.0, this legacy function should return CKR_FUNCTION_NOT_PARALLEL
	return CKR_FUNCTION_NOT_PARALLEL
}

// ----------------------------------------------------------------
// Helper Methods
// ----------------------------------------------------------------

// findSession finds a session by handle and returns its slot ID and session.
func (m *Module) findSession(handle SessionHandle) (SlotID, *Session, CK_RV) {
	for slotID, sm := range m.sessionManagers {
		session, err := sm.GetSession(handle)
		if err == nil {
			return slotID, session, CKR_OK
		}
	}
	return 0, nil, CKR_SESSION_HANDLE_INVALID
}

// getSessionManager returns the session manager for a given session handle.
func (m *Module) getSessionManager(handle SessionHandle) (*SessionManager, CK_RV) {
	slotID, _, rv := m.findSession(handle)
	if rv != CKR_OK {
		return nil, rv
	}
	return m.sessionManagers[slotID], CKR_OK
}

// mechanismSupportsSignRecover checks if a mechanism supports sign-recover.
// Per PKCS#11 spec, only certain RSA mechanisms support sign-recover.
func (m *Module) mechanismSupportsSignRecover(mechType MechanismType) bool {
	switch mechType {
	case CKM_RSA_PKCS, CKM_RSA_X_509:
		// RSA raw mechanisms support sign-recover
		return true
	default:
		return false
	}
}

// mechanismSupportsVerifyRecover checks if a mechanism supports verify-recover.
// Per PKCS#11 spec, only certain RSA mechanisms support verify-recover.
func (m *Module) mechanismSupportsVerifyRecover(mechType MechanismType) bool {
	switch mechType {
	case CKM_RSA_PKCS, CKM_RSA_X_509:
		// RSA raw mechanisms support verify-recover
		return true
	default:
		return false
	}
}

// mechanismToKeyTypeFromMech converts a mechanism type to a PKCS#11 key type.
func mechanismToKeyTypeFromMech(mech MechanismType) KeyType {
	switch mech {
	case CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS:
		return CKK_RSA
	case CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512:
		return CKK_EC
	case CKM_AES_KEY_GEN, CKM_AES_CBC, CKM_AES_GCM:
		return CKK_AES
	case CKM_DES3_KEY_GEN, CKM_DES3_CBC:
		return CKK_DES3
	case CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA:
		return CKK_EC_EDWARDS
	default:
		return CKK_GENERIC_SECRET
	}
}

// templateAttribute returns the first value for the given attribute type in a
// template, and whether it was present.
func templateAttribute(template []Attribute, attrType AttributeType) ([]byte, bool) {
	for _, attr := range template {
		if attr.Type == attrType {
			return attr.Value, true
		}
	}
	return nil, false
}

// templateBoolIsTrue reads a CK_BBOOL attribute from a template, returning
// fallback when the template does not carry it.
func templateBoolIsTrue(template []Attribute, attrType AttributeType, fallback bool) bool {
	value, ok := templateAttribute(template, attrType)
	if !ok || len(value) == 0 {
		return fallback
	}
	return value[0] != 0
}

// templateCurveName returns the canonical name of the curve the template's
// CKA_EC_PARAMS names, whether the attribute was present at all, and CKR_OK.
//
// A template naming no curve returns present=false rather than an error.
// PKCS#11 v3.2 Table 13 footnote 6 says CKA_EC_PARAMS must NOT be specified
// when an EC private key is unwrapped -- the wrapped PKCS#8 blob carries the
// curve -- so the attribute is legitimately absent, and the service's own
// default stands for those callers. Reading it when it IS present is what lets
// a caller that names a curve have the key stored describing that curve.
//
// A curve the module does not recognise is REFUSED rather than reported as
// absent. Returning "" there would let the service substitute P-256 for it,
// which is the silent substitution this function exists to close, and it
// matches what C_GenerateKeyPair already does with an unrecognised
// CKA_EC_PARAMS.
//
// The present flag exists because "" is the honest answer to two different
// questions -- the attribute was omitted, and the attribute named something
// unusable -- and a caller that gates on the name alone refuses the omitted
// case too. That is not hypothetical: it is the defect this signature closes
// (#161). The CK_RV separates error from success; present separates the two
// successes.
func templateCurveName(template []Attribute) (name string, present bool, rv CK_RV) {
	params, ok := templateAttribute(template, CKA_EC_PARAMS)
	if !ok {
		return "", false, CKR_OK
	}
	name, recognized := extractCurveFromParams(params)
	if !recognized {
		return "", true, CKR_CURVE_NOT_SUPPORTED
	}
	return name, true, CKR_OK
}

// curveUsableForECDSA reports whether an ECDSA key can be produced on the named
// curve. It is the one predicate C_UnwrapKey and C_GenerateKeyPair share, so
// the two verbs cannot drift into answering the same question differently --
// which is what #161 reports.
//
// The name must already have come from extractCurveFromParams: an unrecognised
// CKA_EC_PARAMS is refused before this is reached, and an unknown name here is
// not usable either.
func curveUsableForECDSA(name string) bool {
	for _, curve := range ecCurves {
		if curve.name == name {
			return curve.ecdsa
		}
	}
	return false
}

// templateValueLenBits reads CKA_VALUE_LEN, which PKCS#11 expresses in bytes,
// and returns the equivalent key size in bits. It returns 0 when the template
// does not specify a length.
func templateValueLenBits(template []Attribute) int {
	value, ok := templateAttribute(template, CKA_VALUE_LEN)
	if !ok {
		return 0
	}

	// CKA_VALUE_LEN is a CK_ULONG. Accept any width the caller marshalled and
	// read it little-endian, which is the CK_ULONG layout on every platform
	// this module supports.
	var length uint64
	for i := len(value) - 1; i >= 0; i-- {
		length = length<<8 | uint64(value[i])
	}
	if length == 0 || length > (1<<24) {
		return 0
	}
	return int(length) * 8
}

// unwrapTargetClass reports the object class an unwrap template asks for,
// defaulting to CKO_SECRET_KEY as the most common unwrap target.
func unwrapTargetClass(template []Attribute) ObjectClass {
	if class, ok, err := templateClass(template); err == nil && ok {
		return class
	}
	return CKO_SECRET_KEY
}

// unwrapTargetKeyType reports the key type an unwrap template asks for, along
// with the backend key-type name used by the transport layer.
func unwrapTargetKeyType(template []Attribute) (KeyType, string) {
	keyType := CKK_GENERIC_SECRET
	if value, ok := templateAttribute(template, CKA_KEY_TYPE); ok && len(value) >= 4 {
		keyType = KeyType(binary.LittleEndian.Uint32(value))
	}
	return keyType, backendKeyTypeName(keyType)
}

// backendKeyTypeName maps a PKCS#11 key type to the key-type name the transport
// layer expects.
func backendKeyTypeName(keyType KeyType) string {
	switch keyType {
	case CKK_RSA:
		return "rsa"
	case CKK_EC:
		return "ecdsa"
	case CKK_EC_EDWARDS:
		return "ed25519"
	default:
		return "symmetric"
	}
}

// mechanismToAlgorithm maps a wrapping mechanism to the canonical algorithm
// name the transport layer expects for wrap and unwrap operations.
//
// It takes the whole Mechanism, not just its type, because CKM_RSA_PKCS_OAEP
// alone does not say which digest the caller chose -- that lives in
// CK_RSA_PKCS_OAEP_PARAMS.hashAlg. Naming only the mechanism is what forced a
// separate lowercase vocabulary ("rsa-oaep") that carried no digest and that
// no other transport spoke; encoding the digest into the canonical name lets
// every transport share one vocabulary and lets a caller select SHA-384 or
// SHA-512 OAEP without a new request field.
func mechanismToAlgorithm(mech *Mechanism) string {
	if mech == nil {
		return ""
	}
	if mech.Type == CKM_RSA_PKCS_OAEP {
		return oaepWrapAlgorithm(mech)
	}
	if alg, ok := wrapAlgorithmNames[mech.Type]; ok {
		return string(alg)
	}
	return GetMechanismName(mech.Type)
}

// wrapAlgorithmNames maps the key-wrapping mechanisms this module supports to
// their canonical algorithm names. The values are types.KeyWrapAlgorithm
// constants rather than literals so this module and the service layer cannot
// drift apart: a renamed constant is a compile error here, not a request the
// service silently rejects at runtime.
//
// CKM_RSA_PKCS_OAEP is absent on purpose -- its name depends on the digest in
// the mechanism parameters, so it is resolved by oaepWrapAlgorithm.
var wrapAlgorithmNames = map[MechanismType]types.KeyWrapAlgorithm{
	CKM_AES_KEY_WRAP: types.WrapAESKW,

	// CKM_AES_KEY_WRAP_KWP is the current RFC 5649 identifier and
	// CKM_AES_KEY_WRAP_PAD its deprecated alias; both name the same
	// construction, so both must route to the same canonical algorithm.
	// Routing only the deprecated spelling left every caller using the
	// current one with an algorithm the service refuses.
	CKM_AES_KEY_WRAP_KWP: types.WrapAESKWP,
	CKM_AES_KEY_WRAP_PAD: types.WrapAESKWP,
	CKM_AES_GCM:          types.WrapAESGCM,
	CKM_AES_CBC:          types.WrapAESCBC,
	CKM_AES_CBC_PAD:      types.WrapAESCBCPad,
	CKM_RSA_PKCS:         types.WrapRSAPKCS1v15,
}

// oaepWrapAlgorithms maps the OAEP digest a caller selected in
// CK_RSA_PKCS_OAEP_PARAMS.hashAlg onto the canonical algorithm that names it.
var oaepWrapAlgorithms = map[MechanismType]types.KeyWrapAlgorithm{
	CKM_SHA_1:  types.WrapRSAOAEPSHA1,
	CKM_SHA256: types.WrapRSAOAEPSHA256,
	CKM_SHA384: types.WrapRSAOAEPSHA384,
	CKM_SHA512: types.WrapRSAOAEPSHA512,
}

// oaepWrapAlgorithm resolves CKM_RSA_PKCS_OAEP to the canonical algorithm
// naming both the mechanism and the caller's digest.
//
// A mechanism carrying no parameters keeps the project-wide SHA-256 default
// this service has always applied to a digest-less OAEP wrap. That is a
// deliberate deviation from PKCS#11, whose own default for an absent
// CK_RSA_PKCS_OAEP_PARAMS is SHA-1: SHA-1 OAEP is refused project-wide, so
// emitting it here would turn every parameterless wrap into a rejection.
//
// An unrecognized digest returns the mechanism's plain name, which the service
// refuses as an unsupported algorithm. That is deliberate: substituting
// SHA-256 for a digest the caller actually asked for would return a blob they
// cannot unwrap while reporting success.
func oaepWrapAlgorithm(mech *Mechanism) string {
	params, ok := mech.TypedParameter.(*RSAOAEPParams)
	if !ok || params == nil {
		return string(types.WrapRSAOAEPSHA256)
	}
	if alg, ok := oaepWrapAlgorithms[params.HashAlg]; ok {
		return string(alg)
	}
	return GetMechanismName(mech.Type)
}

// wrapMechanismParameters extracts the CK_MECHANISM parameters that C_WrapKey
// and C_UnwrapKey must carry to the service alongside the algorithm name.
//
// mechanismToAlgorithm reduces a whole CK_MECHANISM to a string, which names
// the construction and, for OAEP, the digest. Everything else in pParameter
// used to stop at that boundary, so a request that named an IV, AAD, a
// truncated tag or an OAEP label was answered as though it had named none of
// them. Only one of those failed loudly; the rest produced a blob under
// different parameters than the caller asked for and reported CKR_OK.
//
// Both directions resolve through this one function so they cannot disagree:
// wrap and unwrap must present identical AAD, tag length and OAEP label, or
// the unwrap fails as though the ciphertext were corrupt.
//
// A mechanism with no parameters is not an error here. PKCS#11 v3.2 §6.13.3
// lets the token generate an AES-GCM IV, and §6.1.8 gives OAEP a defaulted
// parameter set; the wrapped blob carries whatever the token chose.
func wrapMechanismParameters(mech *Mechanism) (WrapMechanismParams, CK_RV) {
	if mech == nil {
		return WrapMechanismParams{}, CKR_MECHANISM_INVALID
	}

	switch mech.Type {
	case CKM_AES_GCM:
		params, ok := mech.GetAESGCMParams()
		if !ok || params == nil {
			return WrapMechanismParams{}, CKR_OK
		}
		if len(params.IV) > 0 && len(params.IV) != GCMNonceSize {
			return WrapMechanismParams{}, CKR_MECHANISM_PARAM_INVALID
		}
		// resolveGCMTagSize is the same validator C_EncryptInit applies to
		// CK_GCM_PARAMS.ulTagBits, so a tag length this token refuses for
		// encryption is refused for wrapping too.
		if _, err := resolveGCMTagSize(params.TagBits); err != nil {
			return WrapMechanismParams{}, FromError(err)
		}
		// #nosec G115 - resolveGCMTagSize accepted it, so it is 96..128.
		return WrapMechanismParams{
			IV:      params.IV,
			AAD:     params.AAD,
			TagBits: int(params.TagBits),
		}, CKR_OK

	case CKM_AES_CBC, CKM_AES_CBC_PAD:
		// PKCS#11 v3.2 §6.10 defines the CBC mechanism parameter as the IV,
		// and resolveCBCIV is the same accessor C_EncryptInit uses. An absent
		// or wrong-length IV is CKR_MECHANISM_PARAM_INVALID rather than a
		// token-chosen IV, because the caller named a parameter the token
		// would otherwise be inventing on its behalf.
		iv, err := resolveCBCIV(mech)
		if err != nil {
			return WrapMechanismParams{}, FromError(err)
		}
		return WrapMechanismParams{IV: iv}, CKR_OK

	case CKM_RSA_PKCS_OAEP:
		return oaepWrapParameters(mech)
	}

	return WrapMechanismParams{}, CKR_OK
}

// oaepWrapParameters resolves CK_RSA_PKCS_OAEP_PARAMS for a wrap or unwrap.
//
// Only the label travels: the digest is already encoded in the algorithm name
// by oaepWrapAlgorithm. The other two fields are validated rather than
// forwarded, because the service performs RSA-OAEP with MGF1 over the same
// digest and no other source of the encoding parameter, so a caller naming
// something else must be refused rather than quietly given the scheme the
// token happens to implement.
//
// PKCS#11 v3.2 §6.1.8 defines source as CKZ_DATA_SPECIFIED with pSourceData
// the encoding parameter — RFC 8017 §7.1's label L. Dropping it was the
// silent failure this function exists to end: the wrap encrypted under the
// empty label and returned CKR_OK, and because C_UnwrapKey dropped it too, a
// round trip through this module still succeeded. Only a peer that honoured
// the label could observe that the blob was unreadable.
func oaepWrapParameters(mech *Mechanism) (WrapMechanismParams, CK_RV) {
	params, ok := mech.TypedParameter.(*RSAOAEPParams)
	if !ok || params == nil {
		return WrapMechanismParams{}, CKR_OK
	}

	// mgf and source are validated through the same helper C_Encrypt and
	// C_Decrypt use, so all four OAEP verbs agree about which parameter
	// combinations this token can serve.
	if err := ValidateRSAOAEPParams(params); err != nil {
		return WrapMechanismParams{}, FromError(err)
	}

	return WrapMechanismParams{OAEPLabel: params.SourceData}, CKR_OK
}

// ecCurve describes one elliptic curve the module recognises, with every
// CKA_EC_PARAMS encoding that may name it and the one it publishes.
//
// PKCS#11 v3.2 §6.3.5 gives CKA_EC_PARAMS four choices, two of which apply to
// Edwards and Montgomery curves: an OID, or a curveName PrintableString. A
// caller may use either — pkcs11-tool sends the curveName form — so both are
// accepted on input.
//
// Only one is published. The spec warns that "keys defined by [RFC 8032] and
// [RFC 8410] are incompatible", and OpenSSL's Ed25519 is the RFC 8410 flavour,
// so a key described by curveName alone is one OpenSSL cannot build an
// EVP_PKEY from: exporting the public key of an Edwards key fails outright.
// Publishing the OID form is equally spec-legal and is the one consumers can
// actually use.
type ecCurve struct {
	// name is the canonical curve name used throughout the module.
	name string

	// canonical is the CKA_EC_PARAMS encoding the module publishes.
	canonical []byte

	// aliases are the other encodings a caller may supply for this curve.
	aliases [][]byte

	// ecdsa reports whether this curve can carry an ECDSA key. The module
	// recognises the Edwards and Montgomery OIDs so that CKA_EC_PARAMS
	// identifies their own key types, but an ECDSA key cannot be generated or
	// unwrapped on them: types.ParseCurve, which every backend resolves an
	// ECDSA curve through, names only the NIST prime curves. Recognising a
	// curve and being able to produce an ECDSA key on it are two different
	// questions, and this field is the second one.
	ecdsa bool

	// fieldLen is the byte width of one field element -- ceil(bits(n)/8) for
	// the curve's order n. PKCS#11 v3.2 §6.3.1 defines the ECDSA signature as
	// raw r || s with each half exactly this wide, so it is the one number that
	// decides the signature's length. Zero for the Edwards and Montgomery
	// curves, whose signatures are not encoded that way.
	fieldLen int
}

// ecCurves lists the curves the module recognises.
//
// The Edwards and Montgomery OIDs are RFC 8410's: id-Ed25519 is 1.3.101.112,
// id-Ed448 1.3.101.113, id-X25519 1.3.101.110 and id-X448 1.3.101.111.
var ecCurves = []ecCurve{
	{
		name:      "P-256",
		fieldLen:  32,
		ecdsa:     true,
		canonical: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	},
	{
		name:      "P-384",
		fieldLen:  48,
		ecdsa:     true,
		canonical: []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22},
	},
	{
		name:      "P-521",
		fieldLen:  66,
		ecdsa:     true,
		canonical: []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23},
	},
	{
		name:      "Ed25519",
		canonical: []byte{0x06, 0x03, 0x2b, 0x65, 0x70},
		aliases:   [][]byte{printableString("edwards25519"), printableString("Ed25519")},
	},
	{
		name:      "Ed448",
		canonical: []byte{0x06, 0x03, 0x2b, 0x65, 0x71},
		aliases:   [][]byte{printableString("edwards448"), printableString("Ed448")},
	},
	{
		name:      "X25519",
		canonical: []byte{0x06, 0x03, 0x2b, 0x65, 0x6e},
		aliases:   [][]byte{printableString("curve25519"), printableString("X25519")},
	},
	{
		name:      "X448",
		canonical: []byte{0x06, 0x03, 0x2b, 0x65, 0x6f},
		aliases:   [][]byte{printableString("curve448"), printableString("X448")},
	},
}

// printableString DER-encodes s as an ASN.1 PrintableString, the encoding
// PKCS#11 v3.2 §6.3.5 gives for the curveName choice of CKA_EC_PARAMS.
func printableString(s string) []byte {
	out := make([]byte, 0, len(s)+2)
	out = append(out, 0x13, byte(len(s)))
	return append(out, s...)
}

// curveForParams resolves a CKA_EC_PARAMS value to a curve.
//
// It reports whether the value was recognised rather than guessing. The
// previous implementation returned P-256 for anything it did not know, so a
// caller naming an unsupported curve — or an Edwards curve, which it could not
// parse at all — silently received a completely different key from the one it
// asked for.
func curveForParams(params []byte) (ecCurve, bool) {
	for _, curve := range ecCurves {
		if bytesEqual(params, curve.canonical) {
			return curve, true
		}
		for _, alias := range curve.aliases {
			if bytesEqual(params, alias) {
				return curve, true
			}
		}
	}
	return ecCurve{}, false
}

// ecFieldLenForParams resolves a CKA_EC_PARAMS value to the byte width of one
// field element, or 0 when the value names no curve with a raw r || s
// signature encoding.
//
// It exists so the ECDSA signature width comes from the signing key rather than
// from the magnitudes of the numbers in the signature. Inferring it from the
// components picks the narrowest advertised curve that happens to hold them,
// which is wrong for any curve outside that set -- a P-224 PIV key produced a
// 64-byte signature where §6.3.1 requires 56 -- and wrong by chance for a P-521
// key whose r and s both fall below 2^384.
func ecFieldLenForParams(params []byte) int {
	curve, ok := curveForParams(params)
	if !ok {
		return 0
	}
	return curve.fieldLen
}

// canonicalECParams returns the CKA_EC_PARAMS encoding the module publishes for
// the curve the supplied value names, and whether it was recognised.
func canonicalECParams(params []byte) ([]byte, bool) {
	curve, ok := curveForParams(params)
	if !ok {
		return nil, false
	}
	return copyBytes(curve.canonical), true
}

// extractCurveFromParams returns the canonical name of the curve a
// CKA_EC_PARAMS value names, and whether it was recognised.
func extractCurveFromParams(params []byte) (string, bool) {
	curve, ok := curveForParams(params)
	if !ok {
		return "", false
	}
	return curve.name, true
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// infoTrimPaddedString removes trailing spaces from a PKCS#11 padded string field.
// Note: This is distinct from the token.go version to avoid redeclaration.
func infoTrimPaddedString(b []byte) string {
	// Find the first null byte or use full length
	end := len(b)
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}

	// Trim trailing spaces
	result := string(b[:end])
	return strings.TrimRight(result, " ")
}

// infoSetPaddedString sets a PKCS#11 padded string field.
// Fills the field with the string, padding with spaces if shorter.
// Note: This is distinct from the token.go version to avoid redeclaration.
func infoSetPaddedString(field []byte, s string) {
	// Clear the field with spaces
	for i := range field {
		field[i] = ' '
	}

	// Copy the string (truncate if too long)
	copy(field, s)
}

// extractPublicKeyComponentsFromPEM pulls the PKCS#11 public-key attributes out
// of a PEM-encoded SubjectPublicKeyInfo.
//
// Which attributes apply depends on the key type: RSA publishes CKA_MODULUS and
// CKA_PUBLIC_EXPONENT, every elliptic curve publishes CKA_EC_POINT. The point's
// encoding differs by curve family, and the difference matters — PKCS#11 v3.2
// §6.3.3 Table 64 defines a short-Weierstrass CKA_EC_POINT as the "DER-encoding
// of ANSI X9.62 ECPoint value Q", while §6.3.5 Table 66 and §6.3.7 Table 68
// define the Edwards and Montgomery ones as the raw "public key bytes in little
// endian order" of RFC 8032 and RFC 7748. Wrapping the latter in an OCTET
// STRING, or omitting them, leaves a key nothing can verify with.
//
// An unrecognised key type is an error rather than three nil slices: a public
// key with no CKA_EC_POINT can be signed with but never verified or exported,
// and silence made that indistinguishable from a key that simply had no
// components to publish.
func extractPublicKeyComponentsFromPEM(pemData string) (modulus, publicExponent, ecPoint []byte, err error) {
	if pemData == "" {
		return nil, nil, nil, nil
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, nil, nil, NewPKCS11ErrorWithMessage(CKR_GENERAL_ERROR,
			"public key is not valid PEM")
	}

	pubKey, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
	if parseErr != nil {
		return nil, nil, nil, NewPKCS11ErrorFull(CKR_GENERAL_ERROR,
			"failed to parse public key", parseErr)
	}

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		modulus = key.N.Bytes()
		publicExponent = big.NewInt(int64(key.E)).Bytes()
		if len(publicExponent) == 0 {
			publicExponent = []byte{0}
		}
		return modulus, publicExponent, nil, nil

	case *ecdsa.PublicKey:
		// Uncompressed point 0x04 || X || Y, DER-wrapped in an OCTET STRING as
		// §6.3.3 Table 64 requires.
		ecdhKey, ecdhErr := key.ECDH()
		if ecdhErr != nil {
			return nil, nil, nil, NewPKCS11ErrorFull(CKR_GENERAL_ERROR,
				"failed to encode EC public point", ecdhErr)
		}
		wrapped, marshalErr := asn1.Marshal(ecdhKey.Bytes())
		if marshalErr != nil {
			return nil, nil, nil, NewPKCS11ErrorFull(CKR_GENERAL_ERROR,
				"failed to DER-encode EC public point", marshalErr)
		}
		return nil, nil, wrapped, nil

	case ed25519.PublicKey:
		// PKCS#11 v3.2 §6.3.5 Table 66 describes the Edwards CKA_EC_POINT as
		// the "public key bytes in little endian order" of RFC 8032, which
		// reads as the bare 32 bytes. Every implementation in practice wraps
		// them in an ASN.1 OCTET STRING as the Weierstrass point is, and
		// OpenSSL's pkcs11-provider requires that: SoftHSM, the reference
		// token, publishes 0x04 0x20 followed by the 32 bytes, and a signature
		// made against its key verifies end to end. Publishing the bare bytes
		// instead leaves a key the provider cannot load at all -- it fails to
		// convert the object and abandons the whole slot.
		wrapped, marshalErr := asn1.Marshal([]byte(key))
		if marshalErr != nil {
			return nil, nil, nil, NewPKCS11ErrorFull(CKR_GENERAL_ERROR,
				"failed to DER-encode Edwards public point", marshalErr)
		}
		return nil, nil, wrapped, nil

	case *ecdh.PublicKey:
		// X25519 / X448 take the same treatment, for the same reason
		// (§6.3.7 Table 68).
		wrapped, marshalErr := asn1.Marshal(key.Bytes())
		if marshalErr != nil {
			return nil, nil, nil, NewPKCS11ErrorFull(CKR_GENERAL_ERROR,
				"failed to DER-encode Montgomery public point", marshalErr)
		}
		return nil, nil, wrapped, nil

	default:
		return nil, nil, nil, NewPKCS11ErrorWithMessage(CKR_GENERAL_ERROR,
			fmt.Sprintf("unsupported public key type %T", pubKey))
	}
}

// secretKeyProtectionDefaults fills in the protection attributes a generated
// secret key's template left unspecified.
//
// PKCS#11 v3.2 §4.9 footnote 9 makes these defaults token-specific, so this
// token chooses the protective ones: material generated inside a backend is
// sensitive and stays there unless the caller says otherwise.
//
// An explicit request is honoured rather than refused. Footnote 7 defines when
// a value may be revealed -- "Cannot be revealed if object has its
// CKA_SENSITIVE attribute set to CK_TRUE or its CKA_EXTRACTABLE attribute set
// to CK_FALSE" -- so CKA_SENSITIVE=CK_FALSE alone does not oblige the token to
// hand anything over, and refusing such a template was wrong. It also broke
// every standard tool: pkcs11-tool --keygen sends CKA_SENSITIVE=CK_FALSE by
// default, so no secret key could be generated without --sensitive.
func secretKeyProtectionDefaults(template []Attribute) []Attribute {
	defaults := make([]Attribute, 0, 2)
	if _, ok := attributeByType(template, CKA_SENSITIVE); !ok {
		defaults = append(defaults, NewBoolAttribute(CKA_SENSITIVE, true))
	}
	if _, ok := attributeByType(template, CKA_EXTRACTABLE); !ok {
		defaults = append(defaults, NewBoolAttribute(CKA_EXTRACTABLE, false))
	}
	if len(defaults) == 0 {
		return template
	}
	return append(append(make([]Attribute, 0, len(template)+len(defaults)), template...), defaults...)
}
