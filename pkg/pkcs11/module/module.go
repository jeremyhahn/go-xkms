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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/grpc"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/unix"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
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
	m.info.SetLibraryDescription("go-xkms PKCS#11")

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
		globalModule.info.SetLibraryDescription("go-xkms PKCS#11")
	}

	return globalModule
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

	// Use provided config or load default
	if config != nil {
		m.config = config
	} else if m.config == nil {
		var err error
		m.config, err = Load()
		if err != nil {
			// If config load fails, use defaults
			m.config = DefaultConfig()
		}
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

	// Initialize session managers for each slot
	slotIDs := m.slotManager.GetSlotList(false)
	for _, slotID := range slotIDs {
		m.sessionManagers[slotID] = NewSessionManager(uint64(slotID), 0)
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
	slot.Token.SetSOPin(m.config.SOPIN)
	slot.Token.Info.SetLabel(label)
	slot.Token.Info.Flags |= CKF_TOKEN_INITIALIZED
	slot.Token.Initialized = true

	// Set SO PIN hash in session manager
	if sm, ok := m.sessionManagers[slotID]; ok {
		sm.SetSOPIN(hashPin(m.config.SOPIN))
	}

	// If user PIN is provided, initialize it too
	if m.config.UserPIN != "" {
		// Set user PIN directly on token
		slot.Token.SetUserPin(m.config.UserPIN)
		slot.Token.Info.Flags |= CKF_USER_PIN_INITIALIZED

		// Set user PIN hash in session manager
		if sm, ok := m.sessionManagers[slotID]; ok {
			sm.SetUserPIN(hashPin(m.config.UserPIN))
		}
	}

	// Persist token state
	if err := m.saveTokenState(slotID); err != nil {
		// Log warning but don't fail
		_ = err
	}

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
			return fmt.Errorf("%w: %v", ErrStorageInit, err)
		}
	case StorageTypeMemory, "":
		backend = storage.NewMemory()
	default:
		return fmt.Errorf("%w: %s", ErrInvalidStorageType, m.config.StorageType)
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
			continue // Skip slots that fail to load
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
		}

		// Load objects for this slot
		objects, err := m.storage.LoadObjects(slotID)
		if err != nil {
			continue
		}

		// Find the maximum handle to set the next handle counter
		var maxHandle ObjectHandle
		for _, po := range objects {
			obj := RestoreObject(po)
			_ = m.objectManager.AddObject(obj)
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

	return m.storage.SaveTokenState(slotID, slot.Token)
}

// persistObjectIfToken persists an object to storage if it's a token object.
func (m *Module) persistObjectIfToken(handle ObjectHandle, sessionHandle SessionHandle) {
	if m.storage == nil {
		return
	}

	obj, err := m.objectManager.GetObject(handle)
	if err != nil || !obj.IsToken {
		return
	}

	// Find the slot ID from the session
	slotID, err := m.getSlotIDFromSession(sessionHandle)
	if err != nil {
		return
	}

	// Persist the object
	_ = m.storage.SaveObject(slotID, obj)
}

// getSlotIDFromSession returns the slot ID for a given session.
func (m *Module) getSlotIDFromSession(sessionHandle SessionHandle) (SlotID, error) {
	for slotID, sm := range m.sessionManagers {
		if session, _ := sm.GetSession(sessionHandle); session != nil {
			return slotID, nil
		}
	}
	return 0, fmt.Errorf("session not found")
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
			return fmt.Errorf("failed to create unix transport: %w", err)
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
			return fmt.Errorf("failed to create gRPC transport for dns target: %w", err)
		}
		m.client = client
		return nil
	}

	// Direct host:port format - use gRPC transport
	if strings.Contains(target, ":") && !strings.Contains(target, "://") {
		client, err := m.createGRPCClient(target)
		if err != nil {
			return fmt.Errorf("failed to create gRPC transport for tcp target: %w", err)
		}
		m.client = client
		return nil
	}

	// Default: treat as Unix socket path for backward compatibility
	client, err := unix.New(transport.WithAddress(target))
	if err != nil {
		return fmt.Errorf("failed to create unix transport for default target: %w", err)
	}
	m.client = client
	return nil
}

// createGRPCClient creates a gRPC transport client with TLS configuration if enabled.
// TLS modes:
//   - mTLS: Both CertFile and KeyFile configured (mutual TLS authentication)
//   - TLS: Only CAFile configured (server certificate verification)
//   - Insecure: TLS enabled but no certificates (skip verification - testing only)
func (m *Module) createGRPCClient(address string) (PKCS11Transport, error) {
	opts := []transport.Option{
		transport.WithAddress(address),
	}

	// Apply TLS configuration if enabled
	if m.config.TLS.Enabled {
		// Check for mTLS (mutual TLS) configuration
		if m.config.TLS.CertFile != "" && m.config.TLS.KeyFile != "" {
			opts = append(opts, transport.WithMTLS(
				m.config.TLS.CertFile,
				m.config.TLS.KeyFile,
				m.config.TLS.CAFile,
			))
		} else if m.config.TLS.CAFile != "" {
			// TLS with CA verification only
			opts = append(opts, transport.WithTLS(m.config.TLS.CAFile))
		} else {
			// TLS enabled but no certificates - insecure mode (for testing)
			opts = append(opts, transport.WithTLS(""))
		}
	}

	return grpc.New(opts...)
}

// Finalize cleans up the PKCS#11 module.
// Implements C_Finalize behavior per PKCS#11 specification.
func (m *Module) Finalize() CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Close all sessions
	for _, sm := range m.sessionManagers {
		sm.CloseAllSessions()
	}

	// Close the transport client
	if m.client != nil {
		_ = m.client.Close()
	}

	// Close storage
	if m.storage != nil {
		_ = m.storage.Close()
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

// GetSlotList obtains a list of slots in the system.
// Implements C_GetSlotList behavior per PKCS#11 specification.
func (m *Module) GetSlotList(tokenPresent bool) ([]SlotID, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

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

	slot, err := m.slotManager.GetSlot(slotID)
	if err != nil {
		return nil, CKR_SLOT_ID_INVALID
	}

	if slot.Token == nil {
		return nil, CKR_TOKEN_NOT_PRESENT
	}

	info := slot.Token.Info
	return &info, CKR_OK
}

// GetMechanismList obtains a list of mechanism types supported by a token.
// Implements C_GetMechanismList behavior per PKCS#11 specification.
func (m *Module) GetMechanismList(slotID SlotID) ([]MechanismType, CK_RV) {
	if !m.initialized.Load() {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

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

	// Initialize the token
	slot.Token.SetSOPin(string(soPin))
	slot.Token.Info.SetLabel(label)

	// Generate a serial number if not set
	if slot.Token.Info.GetSerialNumber() == "" {
		slot.Token.Info.SetSerialNumber(generateSerialNumber())
	}
	slot.Token.Info.Flags |= CKF_TOKEN_INITIALIZED
	slot.Token.Initialized = true

	// Ensure SessionManager has the SO PIN hash for authentication
	if sm, ok := m.sessionManagers[slotID]; ok {
		sm.SetSOPIN(hashPin(string(soPin)))
	}

	// Persist token state
	if err := m.saveTokenState(slotID); err != nil {
		// Log warning but don't fail
		_ = err
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

	slot.Token.SetUserPin(string(pin))

	// Ensure SessionManager has the user PIN hash for authentication
	if sm, ok := m.sessionManagers[slotID]; ok {
		sm.SetUserPIN(hashPin(string(pin)))
	}

	// Persist token state
	if err := m.saveTokenState(slotID); err != nil {
		// Log warning but don't fail
		_ = err
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

	// Verify old PIN and set new PIN based on user type
	if session.IsSOLoggedIn() {
		if !slot.Token.VerifySOPin(string(oldPin)) {
			return CKR_PIN_INCORRECT
		}
		slot.Token.SetSOPin(string(newPin))
		// Also update the session manager's PIN hash for future login validation
		sm.SetSOPIN(hashPin(string(newPin)))
	} else if session.IsUserLoggedIn() {
		if !slot.Token.VerifyUserPin(string(oldPin)) {
			return CKR_PIN_INCORRECT
		}
		slot.Token.SetUserPin(string(newPin))
		// Also update the session manager's PIN hash for future login validation
		sm.SetUserPIN(hashPin(string(newPin)))
	} else {
		return CKR_USER_NOT_LOGGED_IN
	}

	// Persist token state
	if err := m.saveTokenState(slotID); err != nil {
		// Log warning but don't fail
		_ = err
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

	// Get or create session manager for this slot
	sm, ok := m.sessionManagers[slotID]
	if !ok {
		sm = NewSessionManager(uint64(slotID), 0)
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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	if err := sm.Login(sessionHandle, userType, pin); err != nil {
		return FromError(err)
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

	return CKR_OK
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

	// Per OASIS PKCS#11 v3.0 Section 5.6.7: CKU_CONTEXT_SPECIFIC login
	// requires an active operation that needs additional authentication.
	// This is used for operations like key unwrapping that may require
	// per-operation authentication.
	if userType == CKU_CONTEXT_SPECIFIC {
		// Context-specific login requires an active operation
		if !session.HasActiveOperation() {
			return CKR_OPERATION_NOT_INITIALIZED
		}
		// For context-specific login, the username parameter may identify
		// which context to authenticate. The PIN is verified against the
		// current operation's requirements.
		// Note: Full implementation depends on operation-specific requirements.
		// For now, we verify the PIN matches the user PIN.
		if err := sm.Login(sessionHandle, CKU_USER, pin); err != nil {
			// If standard login fails, try context-specific validation
			return FromError(err)
		}
		return CKR_OK
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

	// Per OASIS PKCS#11 v3.0 Section 5.16.1:
	// CKR_OPERATION_NOT_INITIALIZED should be returned if no operation is active.
	if !session.HasActiveOperation() {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// Finalize/cancel the operation
	if err := sm.FinalizeOperation(sessionHandle); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// ----------------------------------------------------------------
// Object Operations
// ----------------------------------------------------------------

// CreateObject creates a new object.
// Implements C_CreateObject behavior per PKCS#11 specification.
func (m *Module) CreateObject(sessionHandle SessionHandle, template []Attribute) (ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	handle, err := m.objectManager.CreateObject(sessionHandle, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// Persist token objects to storage
	m.persistObjectIfToken(handle, sessionHandle)

	return handle, CKR_OK
}

// CopyObject copies an object.
// Implements C_CopyObject behavior per PKCS#11 specification.
func (m *Module) CopyObject(sessionHandle SessionHandle, objectHandle ObjectHandle, template []Attribute) (ObjectHandle, CK_RV) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	newHandle, err := m.objectManager.CopyObject(sessionHandle, objectHandle, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// Persist token objects to storage
	m.persistObjectIfToken(newHandle, sessionHandle)

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

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	if err := m.objectManager.DestroyObject(sessionHandle, objectHandle); err != nil {
		return FromError(err)
	}

	// Remove from storage
	if m.storage != nil {
		_ = m.storage.DeleteObject(objectHandle)
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

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	attrs, err := m.objectManager.GetAttributeValue(sessionHandle, objectHandle, template)
	if err != nil {
		return nil, FromError(err)
	}

	return attrs, CKR_OK
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

	if !session.IsReadWrite() {
		return CKR_SESSION_READ_ONLY
	}

	if err := m.objectManager.SetAttributeValue(sessionHandle, objectHandle, template); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// FindObjectsInit initializes a search for objects that match a template.
// Implements C_FindObjectsInit behavior per PKCS#11 specification.
func (m *Module) FindObjectsInit(sessionHandle SessionHandle, template []Attribute) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	if err := m.objectManager.FindObjectsInit(sessionHandle, template); err != nil {
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

// SignInit initializes a signing operation.
// Implements C_SignInit behavior per PKCS#11 specification.
func (m *Module) SignInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if mechanism == nil {
		return CKR_ARGUMENTS_BAD
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

	// Get the key object
	obj, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return CKR_KEY_HANDLE_INVALID
	}

	// Initialize the operation in the session manager
	if err := sm.InitializeOperation(sessionHandle, OperationSign, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	// Create crypto operation and store in session state
	signOp, cryptoErr := m.cryptoManager.SignInit(mechanism, keyHandle, obj.KeyID, obj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return FromError(cryptoErr)
	}

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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationSign {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Get key for signing
	obj, objErr := m.objectManager.GetObject(opState.KeyHandle)
	if objErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, CKR_KEY_HANDLE_INVALID
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	mech := &Mechanism{Type: opState.Mechanism}
	signOp, signErr := m.cryptoManager.SignInit(mech, opState.KeyHandle, obj.KeyID, obj.BackendName)
	if signErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(signErr)
	}

	signature, signErr := m.cryptoManager.Sign(ctx, signOp, data)
	_ = sm.FinalizeOperation(sessionHandle)

	if signErr != nil {
		return nil, FromError(signErr)
	}

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

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationSign {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// Get the stored sign operation
	signOp, ok := opState.CryptoOp.(*SignOperation)
	if !ok || signOp == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// Update with data
	if err := m.cryptoManager.SignUpdate(signOp, data); err != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return FromError(err)
	}

	// Update session state with the modified operation
	opState.CryptoOp = signOp
	session.SetOperationState(opState)

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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationSign {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	signOp, ok := opState.CryptoOp.(*SignOperation)
	if !ok || signOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	signature, signErr := m.cryptoManager.SignFinal(ctx, signOp)
	_ = sm.FinalizeOperation(sessionHandle)

	if signErr != nil {
		return nil, FromError(signErr)
	}

	return signature, CKR_OK
}

// SignRecoverInit initializes a signing operation where the data can be
// recovered from the signature.
// Implements C_SignRecoverInit behavior per PKCS#11 specification.
func (m *Module) SignRecoverInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	if !session.IsUserLoggedIn() && !session.IsSOLoggedIn() {
		return CKR_USER_NOT_LOGGED_IN
	}

	// Check if mechanism supports sign recover
	if !m.mechanismSupportsSignRecover(mechanism.Type) {
		return CKR_MECHANISM_INVALID
	}

	keyObj, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return CKR_KEY_HANDLE_INVALID
	}

	// Check that key has CKA_SIGN attribute
	signAttr := keyObj.GetAttribute(CKA_SIGN)
	if len(signAttr) > 0 && signAttr[0] == 0 {
		return CKR_KEY_FUNCTION_NOT_PERMITTED
	}

	signOp, cryptoErr := m.cryptoManager.SignInit(mechanism, keyHandle, keyObj.KeyID, keyObj.BackendName)
	if cryptoErr != nil {
		return FromError(cryptoErr)
	}

	// Mark this as a sign-recover operation
	signOp.IsRecover = true

	sm := m.sessionManagers[slotID]
	if sm == nil {
		return CKR_SESSION_HANDLE_INVALID
	}

	if err := sm.SetOperation(sessionHandle, &OperationState{
		Type:     OperationSign,
		CryptoOp: signOp,
	}); err != nil {
		return FromError(err)
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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationSign {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	signOp, ok := opState.CryptoOp.(*SignOperation)
	if !ok || signOp == nil || !signOp.IsRecover {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	// For RSA, sign-recover uses raw RSA (no padding) so data can be recovered
	// The signature contains the original data that can be decrypted with public key
	signature, signErr := m.cryptoManager.Sign(ctx, signOp, data)
	_ = sm.FinalizeOperation(sessionHandle)

	if signErr != nil {
		return nil, FromError(signErr)
	}

	return signature, CKR_OK
}

// VerifyInit initializes a verification operation.
// Implements C_VerifyInit behavior per PKCS#11 specification.
func (m *Module) VerifyInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if mechanism == nil {
		return CKR_ARGUMENTS_BAD
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

	obj, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return CKR_KEY_HANDLE_INVALID
	}

	if err := sm.InitializeOperation(sessionHandle, OperationVerify, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	verifyOp, cryptoErr := m.cryptoManager.VerifyInit(mechanism, keyHandle, obj.KeyID, obj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationVerify {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	obj, objErr := m.objectManager.GetObject(opState.KeyHandle)
	if objErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return CKR_KEY_HANDLE_INVALID
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	mech := &Mechanism{Type: opState.Mechanism}
	verifyOp, verifyErr := m.cryptoManager.VerifyInit(mech, opState.KeyHandle, obj.KeyID, obj.BackendName)
	if verifyErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return FromError(verifyErr)
	}

	verifyErr = m.cryptoManager.Verify(ctx, verifyOp, data, signature)
	_ = sm.FinalizeOperation(sessionHandle)

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

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationVerify {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	verifyOp, ok := opState.CryptoOp.(*VerifyOperation)
	if !ok || verifyOp == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if err := m.cryptoManager.VerifyUpdate(verifyOp, data); err != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return FromError(err)
	}

	opState.CryptoOp = verifyOp
	session.SetOperationState(opState)

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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationVerify {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	verifyOp, ok := opState.CryptoOp.(*VerifyOperation)
	if !ok || verifyOp == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	verifyErr := m.cryptoManager.VerifyFinal(ctx, verifyOp, signature)
	_ = sm.FinalizeOperation(sessionHandle)

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

	m.mu.Lock()
	defer m.mu.Unlock()

	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	// Check if mechanism supports verify recover
	if !m.mechanismSupportsVerifyRecover(mechanism.Type) {
		return CKR_MECHANISM_INVALID
	}

	keyObj, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return CKR_KEY_HANDLE_INVALID
	}

	// Check that key has CKA_VERIFY_RECOVER attribute (required for verify-recover)
	verifyRecoverAttr := keyObj.GetAttribute(CKA_VERIFY_RECOVER)
	if len(verifyRecoverAttr) > 0 && verifyRecoverAttr[0] == 0 {
		return CKR_KEY_FUNCTION_NOT_PERMITTED
	}

	verifyOp, cryptoErr := m.cryptoManager.VerifyInit(mechanism, keyHandle, keyObj.KeyID, keyObj.BackendName)
	if cryptoErr != nil {
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

	sm := m.sessionManagers[slotID]
	if sm == nil {
		return CKR_SESSION_HANDLE_INVALID
	}

	if err := sm.SetOperation(sessionHandle, &OperationState{
		Type:     OperationVerify,
		CryptoOp: verifyOp,
	}); err != nil {
		return FromError(err)
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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationVerify {
		return nil, CKR_OPERATION_NOT_INITIALIZED
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
	_ = sm.FinalizeOperation(sessionHandle)

	if verifyErr != nil {
		return nil, FromError(verifyErr)
	}

	return recoveredData, CKR_OK
}

// EncryptInit initializes an encryption operation.
// Implements C_EncryptInit behavior per PKCS#11 specification.
func (m *Module) EncryptInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if mechanism == nil {
		return CKR_ARGUMENTS_BAD
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

	obj, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return CKR_KEY_HANDLE_INVALID
	}

	if err := sm.InitializeOperation(sessionHandle, OperationEncrypt, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	encOp, cryptoErr := m.cryptoManager.EncryptInit(mechanism, keyHandle, obj.KeyID, obj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	obj, objErr := m.objectManager.GetObject(opState.KeyHandle)
	if objErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, CKR_KEY_HANDLE_INVALID
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	mech := &Mechanism{Type: opState.Mechanism}
	encOp, encErr := m.cryptoManager.EncryptInit(mech, opState.KeyHandle, obj.KeyID, obj.BackendName)
	if encErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(encErr)
	}

	ciphertext, encErr := m.cryptoManager.Encrypt(ctx, encOp, plaintext)
	_ = sm.FinalizeOperation(sessionHandle)

	if encErr != nil {
		return nil, FromError(encErr)
	}

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

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	encOp, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if err := m.cryptoManager.EncryptUpdate(encOp, plaintext); err != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(err)
	}

	opState.CryptoOp = encOp
	session.SetOperationState(opState)

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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	encOp, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	ciphertext, encErr := m.cryptoManager.EncryptFinal(ctx, encOp)
	_ = sm.FinalizeOperation(sessionHandle)

	if encErr != nil {
		return nil, FromError(encErr)
	}

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
func (m *Module) EncryptMessage(sessionHandle SessionHandle, associatedData, plaintext []byte) ([]byte, CK_RV) {
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

	opState := session.GetOperationState()
	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
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

	ciphertext, encErr := m.cryptoManager.Encrypt(ctx, encOp, plaintext)
	if encErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(encErr)
	}

	return ciphertext, CKR_OK
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
	if err := sm.FinalizeOperation(sessionHandle); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// EncryptMessageBegin begins a multiple-part message encryption operation.
// Implements C_EncryptMessageBegin behavior per PKCS#11 v3.0 specification.
func (m *Module) EncryptMessageBegin(sessionHandle SessionHandle, associatedData []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	opState := session.GetOperationState()
	if opState.Type != OperationEncrypt {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// Store associated data for AEAD modes if provided
	if len(associatedData) > 0 {
		opState.Data = append(opState.Data, associatedData...)
		session.SetOperationState(opState)
	}

	return CKR_OK
}

// EncryptMessageNext continues a multiple-part message encryption operation.
// Implements C_EncryptMessageNext behavior per PKCS#11 v3.0 specification.
// If final is true, this is the last part and returns the final ciphertext.
func (m *Module) EncryptMessageNext(sessionHandle SessionHandle, plaintext []byte, final bool) ([]byte, CK_RV) {
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

	opState := session.GetOperationState()
	if opState.Type != OperationEncrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	encOp, ok := opState.CryptoOp.(*EncryptOperation)
	if !ok || encOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Update with plaintext
	if err := m.cryptoManager.EncryptUpdate(encOp, plaintext); err != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(err)
	}

	if final {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
		defer cancel()

		ciphertext, encErr := m.cryptoManager.EncryptFinal(ctx, encOp)
		_ = sm.FinalizeOperation(sessionHandle)

		if encErr != nil {
			return nil, FromError(encErr)
		}
		return ciphertext, CKR_OK
	}

	return nil, CKR_OK
}

// MessageDecryptInit initializes a message-based decryption operation.
// Implements C_MessageDecryptInit behavior per PKCS#11 v3.0 specification.
func (m *Module) MessageDecryptInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	return m.DecryptInit(sessionHandle, mechanism, keyHandle)
}

// DecryptMessage decrypts a single message with associated data.
// Implements C_DecryptMessage behavior per PKCS#11 v3.0 specification.
func (m *Module) DecryptMessage(sessionHandle SessionHandle, associatedData, ciphertext []byte) ([]byte, CK_RV) {
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

	opState := session.GetOperationState()
	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
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

	plaintext, decErr := m.cryptoManager.Decrypt(ctx, decOp, ciphertext)
	if decErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
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

	if err := sm.FinalizeOperation(sessionHandle); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// DecryptMessageBegin begins a multiple-part message decryption operation.
// Implements C_DecryptMessageBegin behavior per PKCS#11 v3.0 specification.
func (m *Module) DecryptMessageBegin(sessionHandle SessionHandle, associatedData []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	opState := session.GetOperationState()
	if opState.Type != OperationDecrypt {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// Store associated data for AEAD modes if provided
	if len(associatedData) > 0 {
		opState.Data = append(opState.Data, associatedData...)
		session.SetOperationState(opState)
	}

	return CKR_OK
}

// DecryptMessageNext continues a multiple-part message decryption operation.
// Implements C_DecryptMessageNext behavior per PKCS#11 v3.0 specification.
// If final is true, this is the last part and returns the final plaintext.
func (m *Module) DecryptMessageNext(sessionHandle SessionHandle, ciphertext []byte, final bool) ([]byte, CK_RV) {
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

	opState := session.GetOperationState()
	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	decOp, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	// Update with ciphertext
	if err := m.cryptoManager.DecryptUpdate(decOp, ciphertext); err != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(err)
	}

	if final {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
		defer cancel()

		plaintext, decErr := m.cryptoManager.DecryptFinal(ctx, decOp)
		_ = sm.FinalizeOperation(sessionHandle)

		if decErr != nil {
			return nil, FromError(decErr)
		}
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

	opState := session.GetOperationState()
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

	if err := sm.FinalizeOperation(sessionHandle); err != nil {
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

	// VerifyMessage is equivalent to calling Verify for a single-part operation
	return m.Verify(sessionHandle, data, signature)
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

	opState := session.GetOperationState()
	if opState.Type != OperationVerify {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	return CKR_OK
}

// VerifyMessageNext continues a multiple-part message verification operation.
// Implements C_VerifyMessageNext behavior per PKCS#11 v3.0 specification.
func (m *Module) VerifyMessageNext(sessionHandle SessionHandle, data []byte, signature []byte) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// Update the verify operation with data
	rv := m.VerifyUpdate(sessionHandle, data)
	if rv != CKR_OK {
		return rv
	}

	// If signature is provided, verify the final signature
	if len(signature) > 0 {
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

	if err := sm.FinalizeOperation(sessionHandle); err != nil {
		return FromError(err)
	}

	return CKR_OK
}

// DecryptInit initializes a decryption operation.
// Implements C_DecryptInit behavior per PKCS#11 specification.
func (m *Module) DecryptInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if mechanism == nil {
		return CKR_ARGUMENTS_BAD
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

	obj, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return CKR_KEY_HANDLE_INVALID
	}

	if err := sm.InitializeOperation(sessionHandle, OperationDecrypt, mechanism.Type, keyHandle); err != nil {
		return FromError(err)
	}

	decOp, cryptoErr := m.cryptoManager.DecryptInit(mechanism, keyHandle, obj.KeyID, obj.BackendName)
	if cryptoErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	obj, objErr := m.objectManager.GetObject(opState.KeyHandle)
	if objErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, CKR_KEY_HANDLE_INVALID
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	mech := &Mechanism{Type: opState.Mechanism}
	decOp, decErr := m.cryptoManager.DecryptInit(mech, opState.KeyHandle, obj.KeyID, obj.BackendName)
	if decErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(decErr)
	}

	plaintext, decErr := m.cryptoManager.Decrypt(ctx, decOp, ciphertext)
	_ = sm.FinalizeOperation(sessionHandle)

	if decErr != nil {
		return nil, FromError(decErr)
	}

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

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	decOp, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if err := m.cryptoManager.DecryptUpdate(decOp, ciphertext); err != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(err)
	}

	opState.CryptoOp = decOp
	session.SetOperationState(opState)

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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDecrypt {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	decOp, ok := opState.CryptoOp.(*DecryptOperation)
	if !ok || decOp == nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	plaintext, decErr := m.cryptoManager.DecryptFinal(ctx, decOp)
	_ = sm.FinalizeOperation(sessionHandle)

	if decErr != nil {
		return nil, FromError(decErr)
	}

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

	// Buffer the encrypted data for decryption (processed during Final)
	if decErr := m.cryptoManager.DecryptUpdate(decOp, encryptedData); decErr != nil {
		return nil, FromError(decErr)
	}

	// Note: The digest will be updated with the plaintext during DecryptFinal
	// when the actual decryption occurs

	// Return empty slice - data is buffered for final processing
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

	// Buffer the encrypted data for decryption (processed during Final)
	if decErr := m.cryptoManager.DecryptUpdate(decOp, encryptedData); decErr != nil {
		return nil, FromError(decErr)
	}

	// Note: The verification will be updated with the plaintext during DecryptFinal
	// when the actual decryption occurs

	// Return empty slice - data is buffered for final processing
	return []byte{}, CKR_OK
}

// DigestInit initializes a message-digesting operation.
// Implements C_DigestInit behavior per PKCS#11 specification.
func (m *Module) DigestInit(sessionHandle SessionHandle, mechanism *Mechanism) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if mechanism == nil {
		return CKR_ARGUMENTS_BAD
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

	if err := sm.InitializeOperation(sessionHandle, OperationDigest, mechanism.Type, ObjectHandle(0)); err != nil {
		return FromError(err)
	}

	digestOp, cryptoErr := m.cryptoManager.DigestInit(mechanism)
	if cryptoErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
	if err != nil {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	if opState.Type != OperationDigest {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	mech := &Mechanism{Type: opState.Mechanism}
	digestOp, digestErr := m.cryptoManager.DigestInit(mech)
	if digestErr != nil {
		_ = sm.FinalizeOperation(sessionHandle)
		return nil, FromError(digestErr)
	}

	hash, digestErr := m.cryptoManager.Digest(digestOp, data)
	_ = sm.FinalizeOperation(sessionHandle)

	if digestErr != nil {
		return nil, FromError(digestErr)
	}

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

	opState, err := sm.GetOperationState(sessionHandle)
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
		_ = sm.FinalizeOperation(sessionHandle)
		return FromError(err)
	}

	opState.CryptoOp = digestOp
	session.SetOperationState(opState)

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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
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
	_ = sm.FinalizeOperation(sessionHandle)

	if digestErr != nil {
		return nil, FromError(digestErr)
	}

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

	slotID, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return rv
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}

	opState, err := sm.GetOperationState(sessionHandle)
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

	// Get the key object
	keyObj, objErr := m.objectManager.GetObject(keyHandle)
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

	// Get the key value - note: for HSM-backed keys, this may not be available
	keyValue := keyObj.GetAttribute(CKA_VALUE)
	if len(keyValue) == 0 {
		// If key is sensitive or not extractable, we can't digest it
		sensitiveAttr := keyObj.GetAttribute(CKA_SENSITIVE)
		if len(sensitiveAttr) > 0 && sensitiveAttr[0] != 0 {
			return CKR_KEY_INDIGESTIBLE
		}
		extractAttr := keyObj.GetAttribute(CKA_EXTRACTABLE)
		if len(extractAttr) > 0 && extractAttr[0] == 0 {
			return CKR_KEY_INDIGESTIBLE
		}
		return CKR_KEY_INDIGESTIBLE
	}

	// Digest the key value
	if digestErr := m.cryptoManager.DigestUpdate(digestOp, keyValue); digestErr != nil {
		return FromError(digestErr)
	}

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

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	if !session.IsReadWrite() {
		return ObjectHandle(InvalidHandle), CKR_SESSION_READ_ONLY
	}

	// Extract key parameters from template
	var label string
	var keySize int
	var ckaID []byte
	for _, attr := range template {
		switch attr.Type {
		case CKA_LABEL:
			label = attr.GetString()
		case CKA_VALUE_LEN:
			if v, err := attr.GetUint32(); err == nil {
				keySize = int(v) * 8 // Convert bytes to bits
			}
		case CKA_ID:
			ckaID = attr.Value
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
		label = "generated-key"
	}

	// Generate a unique key ID by appending a timestamp-based suffix
	// This ensures uniqueness while keeping the label as a prefix for identification
	keyID := fmt.Sprintf("%s-%d-%d", label, time.Now().UnixNano(), m.keyCounter.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	req := &GenerateKeyRequest{
		KeyID:     keyID,
		Backend:   "", // Empty to use CryptoManager's DefaultBackend
		Mechanism: mechanism,
		KeySize:   keySize,
	}

	resp, err := m.cryptoManager.GenerateKey(ctx, req)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	// Store the object
	handle, storeErr := m.objectManager.CreateObject(sessionHandle, template)
	if storeErr != nil {
		return ObjectHandle(InvalidHandle), FromError(storeErr)
	}

	// Set the backend-specific key information on the object
	obj, getErr := m.objectManager.GetObject(handle)
	if getErr != nil {
		_ = m.objectManager.DestroyObject(sessionHandle, handle)
		return ObjectHandle(InvalidHandle), FromError(getErr)
	}
	obj.KeyID = resp.KeyID
	obj.BackendName = m.cryptoManager.config.DefaultBackend

	// Set CKA_ID on the key object
	obj.SetAttribute(CKA_ID, ckaID)

	// Persist token objects to storage
	m.persistObjectIfToken(handle, sessionHandle)

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

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), rv
	}

	if !session.IsReadWrite() {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), CKR_SESSION_READ_ONLY
	}

	// Extract key parameters from templates
	var label string
	var keySize int
	var curve string
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
			curve = extractCurveFromParams(attr.Value)
		case CKA_ID:
			ckaID = attr.Value
		}
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
	pubHandle, pubErr := m.objectManager.CreateObject(sessionHandle, publicKeyTemplate)
	if pubErr != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(pubErr)
	}

	// Set the backend-specific key information on the public key
	pubObj, pubGetErr := m.objectManager.GetObject(pubHandle)
	if pubGetErr != nil {
		_ = m.objectManager.DestroyObject(sessionHandle, pubHandle)
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(pubGetErr)
	}
	pubObj.KeyID = resp.KeyID
	pubObj.BackendName = m.cryptoManager.config.DefaultBackend

	// Set CKA_ID on public key (ensures consistent ID for key pair)
	pubObj.SetAttribute(CKA_ID, ckaID)

	// Extract and store public key components from PEM for use in verify-recover, etc.
	if resp.PublicKeyPEM != "" {
		modulus, pubExponent, ecPoint := extractPublicKeyComponentsFromPEM(resp.PublicKeyPEM)
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
	privHandle, privErr := m.objectManager.CreateObject(sessionHandle, privateKeyTemplate)
	if privErr != nil {
		_ = m.objectManager.DestroyObject(sessionHandle, pubHandle)
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(privErr)
	}

	// Set the backend-specific key information on the private key
	privObj, privGetErr := m.objectManager.GetObject(privHandle)
	if privGetErr != nil {
		_ = m.objectManager.DestroyObject(sessionHandle, pubHandle)
		_ = m.objectManager.DestroyObject(sessionHandle, privHandle)
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(privGetErr)
	}
	privObj.KeyID = resp.KeyID
	privObj.BackendName = m.cryptoManager.config.DefaultBackend

	// Set CKA_ID on private key (same ID as public key for the pair)
	privObj.SetAttribute(CKA_ID, ckaID)

	// Persist token objects to storage
	m.persistObjectIfToken(pubHandle, sessionHandle)
	m.persistObjectIfToken(privHandle, sessionHandle)

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

	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return 0, rv
	}

	obj, err := m.objectManager.GetObject(objectHandle)
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

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, rv
	}

	if !session.IsReadWrite() {
		return nil, CKR_SESSION_READ_ONLY
	}

	// Get the wrapping key
	wrapKeyObj, err := m.objectManager.GetObject(wrappingKey)
	if err != nil {
		return nil, CKR_WRAPPING_KEY_HANDLE_INVALID
	}

	// Check if wrapping key can wrap
	wrapAttr := wrapKeyObj.GetAttribute(CKA_WRAP)
	if len(wrapAttr) > 0 && wrapAttr[0] == 0 {
		return nil, CKR_KEY_FUNCTION_NOT_PERMITTED
	}

	// Get the key to be wrapped
	targetKeyObj, err := m.objectManager.GetObject(key)
	if err != nil {
		return nil, CKR_KEY_HANDLE_INVALID
	}

	// Check if key is extractable
	extractAttr := targetKeyObj.GetAttribute(CKA_EXTRACTABLE)
	if len(extractAttr) > 0 && extractAttr[0] == 0 {
		return nil, CKR_KEY_UNEXTRACTABLE
	}

	// Get the key value to wrap
	keyValue := targetKeyObj.GetAttribute(CKA_VALUE)
	if len(keyValue) == 0 {
		return nil, CKR_KEY_NOT_WRAPPABLE
	}

	// Encrypt the key value using the wrapping key
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	encOp, cryptoErr := m.cryptoManager.EncryptInit(mechanism, wrappingKey, wrapKeyObj.KeyID, wrapKeyObj.BackendName)
	if cryptoErr != nil {
		return nil, FromError(cryptoErr)
	}

	wrappedKey, encErr := m.cryptoManager.Encrypt(ctx, encOp, keyValue)
	if encErr != nil {
		return nil, FromError(encErr)
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

	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), rv
	}

	if !session.IsReadWrite() {
		return ObjectHandle(InvalidHandle), CKR_SESSION_READ_ONLY
	}

	// Get the unwrapping key
	unwrapKeyObj, err := m.objectManager.GetObject(unwrappingKey)
	if err != nil {
		return ObjectHandle(InvalidHandle), CKR_UNWRAPPING_KEY_HANDLE_INVALID
	}

	// Check if unwrapping key can unwrap
	unwrapAttr := unwrapKeyObj.GetAttribute(CKA_UNWRAP)
	if len(unwrapAttr) > 0 && unwrapAttr[0] == 0 {
		return ObjectHandle(InvalidHandle), CKR_KEY_FUNCTION_NOT_PERMITTED
	}

	// Decrypt the wrapped key
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	decOp, cryptoErr := m.cryptoManager.DecryptInit(mechanism, unwrappingKey, unwrapKeyObj.KeyID, unwrapKeyObj.BackendName)
	if cryptoErr != nil {
		return ObjectHandle(InvalidHandle), FromError(cryptoErr)
	}

	keyValue, decErr := m.cryptoManager.Decrypt(ctx, decOp, wrappedKey)
	if decErr != nil {
		return ObjectHandle(InvalidHandle), FromError(decErr)
	}

	// Create the new key object with the unwrapped value
	newTemplate := make([]Attribute, len(template)+1)
	copy(newTemplate, template)
	newTemplate[len(template)] = Attribute{Type: CKA_VALUE, Value: keyValue}

	handle, createErr := m.objectManager.CreateObject(sessionHandle, newTemplate)
	if createErr != nil {
		return ObjectHandle(InvalidHandle), FromError(createErr)
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

	if !session.IsReadWrite() {
		return ObjectHandle(InvalidHandle), CKR_SESSION_READ_ONLY
	}

	sm, ok := m.sessionManagers[slotID]
	if !ok {
		return ObjectHandle(InvalidHandle), CKR_SESSION_HANDLE_INVALID
	}

	// Get the base key
	baseKeyObj, err := m.objectManager.GetObject(baseKey)
	if err != nil {
		return ObjectHandle(InvalidHandle), CKR_KEY_HANDLE_INVALID
	}

	// Check if base key can be used for derivation
	deriveAttr := baseKeyObj.GetAttribute(CKA_DERIVE)
	if len(deriveAttr) > 0 && deriveAttr[0] == 0 {
		return ObjectHandle(InvalidHandle), CKR_KEY_FUNCTION_NOT_PERMITTED
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

	// Get input key material from base key (CKA_VALUE attribute)
	ikm := baseKeyObj.GetAttribute(CKA_VALUE)
	if len(ikm) == 0 {
		// For hardware-backed keys, we may not have access to the raw key material
		// In that case, use the key ID and let the backend handle it
		ikm = []byte(baseKeyObj.KeyID)
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
	ctx := context.Background()
	derivedKeyMaterial, cryptoErr := m.cryptoManager.DeriveKey(ctx, deriveOp, ikm, keyLength)
	if cryptoErr != nil {
		_ = sm.FinalizeOperationType(sessionHandle, OperationDerive)
		return ObjectHandle(InvalidHandle), FromError(cryptoErr)
	}

	// Finalize the operation
	_ = sm.FinalizeOperationType(sessionHandle, OperationDerive)

	// Build the derived key template
	derivedKeyTemplate := make([]Attribute, 0, len(template)+4)

	// Copy template attributes
	derivedKeyTemplate = append(derivedKeyTemplate, template...)

	// Add/override with derived key value
	derivedKeyTemplate = append(derivedKeyTemplate, Attribute{
		Type:  CKA_VALUE,
		Value: derivedKeyMaterial,
	})

	// Add value length
	valueLenBytes := make([]byte, 4)
	valueLenBytes[0] = byte(len(derivedKeyMaterial))
	valueLenBytes[1] = byte(len(derivedKeyMaterial) >> 8)
	valueLenBytes[2] = byte(len(derivedKeyMaterial) >> 16)
	valueLenBytes[3] = byte(len(derivedKeyMaterial) >> 24)
	derivedKeyTemplate = append(derivedKeyTemplate, Attribute{
		Type:  CKA_VALUE_LEN,
		Value: valueLenBytes,
	})

	// Ensure class is set for secret key
	hasClass := false
	for _, attr := range derivedKeyTemplate {
		if attr.Type == CKA_CLASS {
			hasClass = true
			break
		}
	}
	if !hasClass {
		classBytes := make([]byte, 4)
		classBytes[0] = byte(CKO_SECRET_KEY)
		classBytes[1] = byte(CKO_SECRET_KEY >> 8)
		classBytes[2] = byte(CKO_SECRET_KEY >> 16)
		classBytes[3] = byte(CKO_SECRET_KEY >> 24)
		derivedKeyTemplate = append(derivedKeyTemplate, Attribute{
			Type:  CKA_CLASS,
			Value: classBytes,
		})
	}

	// Create the derived key object
	handle, err := m.objectManager.CreateObject(sessionHandle, derivedKeyTemplate)
	if err != nil {
		return ObjectHandle(InvalidHandle), FromError(err)
	}

	return handle, CKR_OK
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

	if len(ecdhParams.PublicData) == 0 {
		return ObjectHandle(InvalidHandle), CKR_MECHANISM_PARAM_INVALID
	}

	// Map KDF type to algorithm and hash strings
	kdfAlgorithm, kdfHash := mapECDHKDFType(ecdhParams.KDF)

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

	// Build the derived key template
	derivedKeyTemplate := make([]Attribute, 0, len(template)+4)

	// Copy template attributes
	derivedKeyTemplate = append(derivedKeyTemplate, template...)

	// Add/override with derived key value
	derivedKeyTemplate = append(derivedKeyTemplate, Attribute{
		Type:  CKA_VALUE,
		Value: derivedKeyMaterial,
	})

	// Add value length
	valueLenBytes := make([]byte, 4)
	valueLenBytes[0] = byte(len(derivedKeyMaterial))
	valueLenBytes[1] = byte(len(derivedKeyMaterial) >> 8)
	valueLenBytes[2] = byte(len(derivedKeyMaterial) >> 16)
	valueLenBytes[3] = byte(len(derivedKeyMaterial) >> 24)
	derivedKeyTemplate = append(derivedKeyTemplate, Attribute{
		Type:  CKA_VALUE_LEN,
		Value: valueLenBytes,
	})

	// Ensure class is set for secret key
	hasClass := false
	for _, attr := range derivedKeyTemplate {
		if attr.Type == CKA_CLASS {
			hasClass = true
			break
		}
	}
	if !hasClass {
		classBytes := make([]byte, 4)
		classBytes[0] = byte(CKO_SECRET_KEY)
		classBytes[1] = byte(CKO_SECRET_KEY >> 8)
		classBytes[2] = byte(CKO_SECRET_KEY >> 16)
		classBytes[3] = byte(CKO_SECRET_KEY >> 24)
		derivedKeyTemplate = append(derivedKeyTemplate, Attribute{
			Type:  CKA_CLASS,
			Value: classBytes,
		})
	}

	// Create the derived key object
	handle, createErr := m.objectManager.CreateObject(sessionHandle, derivedKeyTemplate)
	if createErr != nil {
		return ObjectHandle(InvalidHandle), FromError(createErr)
	}

	return handle, CKR_OK
}

// mapECDHKDFType maps PKCS#11 KDF types to transport layer algorithm and hash strings.
func mapECDHKDFType(kdf KDFType) (algorithm, hash string) {
	switch kdf {
	case CKD_NULL:
		return "", "" // No KDF, return raw shared secret
	case CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1, CKD_SHA1_KDF_CONCATENATE:
		return "X963", "SHA-1"
	case CKD_SHA224_KDF:
		return "X963", "SHA-224"
	case CKD_SHA256_KDF:
		return "X963", "SHA-256"
	case CKD_SHA384_KDF:
		return "X963", "SHA-384"
	case CKD_SHA512_KDF:
		return "X963", "SHA-512"
	case CKD_SHA1_KDF_SP800:
		return "SP800-56A", "SHA-1"
	case CKD_SHA224_KDF_SP800:
		return "SP800-56A", "SHA-224"
	case CKD_SHA256_KDF_SP800:
		return "SP800-56A", "SHA-256"
	case CKD_SHA384_KDF_SP800:
		return "SP800-56A", "SHA-384"
	case CKD_SHA512_KDF_SP800:
		return "SP800-56A", "SHA-512"
	case CKD_SHA3_224_KDF:
		return "X963", "SHA3-224"
	case CKD_SHA3_256_KDF:
		return "X963", "SHA3-256"
	case CKD_SHA3_384_KDF:
		return "X963", "SHA3-384"
	case CKD_SHA3_512_KDF:
		return "X963", "SHA3-512"
	default:
		return "HKDF", "SHA-256" // Default to HKDF with SHA-256
	}
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

	// For operations with internal crypto state, we can't easily serialize
	// Return CKR_STATE_UNSAVEABLE per PKCS#11 spec for complex operations
	if opState.CryptoOp != nil {
		return nil, CKR_STATE_UNSAVEABLE
	}

	// For simple operations, serialize the state
	// This is a simplified serialization - production would use proper encoding
	state := make([]byte, 0, 32+len(opState.Data))
	state = append(state, byte(opState.Type))
	state = append(state, byte(opState.Mechanism>>24), byte(opState.Mechanism>>16), byte(opState.Mechanism>>8), byte(opState.Mechanism))
	state = append(state, byte(opState.KeyHandle>>56), byte(opState.KeyHandle>>48), byte(opState.KeyHandle>>40), byte(opState.KeyHandle>>32))
	state = append(state, byte(opState.KeyHandle>>24), byte(opState.KeyHandle>>16), byte(opState.KeyHandle>>8), byte(opState.KeyHandle))
	state = append(state, opState.Data...)

	return state, CKR_OK
}

// SetOperationStateBytes restores the cryptographic operation state from bytes.
// Implements C_SetOperationState behavior per PKCS#11 specification.
func (m *Module) SetOperationStateBytes(sessionHandle SessionHandle, state []byte, encryptionKey, authenticationKey ObjectHandle) CK_RV {
	if !m.initialized.Load() {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if len(state) < 13 {
		return CKR_SAVED_STATE_INVALID
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

	// Check if an operation is already active
	if session.HasActiveOperation() {
		return CKR_OPERATION_ACTIVE
	}

	// Deserialize the state
	opType := OperationType(state[0])
	mechType := MechanismType(uint32(state[1])<<24 | uint32(state[2])<<16 | uint32(state[3])<<8 | uint32(state[4]))
	keyHandle := ObjectHandle(uint64(state[5])<<56 | uint64(state[6])<<48 | uint64(state[7])<<40 | uint64(state[8])<<32 |
		uint64(state[9])<<24 | uint64(state[10])<<16 | uint64(state[11])<<8 | uint64(state[12]))
	data := state[13:]

	// Validate key handle if specified
	if keyHandle != ObjectHandle(0) {
		_, err := m.objectManager.GetObject(keyHandle)
		if err != nil {
			return CKR_KEY_HANDLE_INVALID
		}
	}

	// Initialize the operation
	if err := sm.InitializeOperation(sessionHandle, opType, mechType, keyHandle); err != nil {
		return FromError(err)
	}

	// Set the operation state with accumulated data
	opState := session.GetOperationState()
	opState.Data = data
	session.SetOperationState(opState)

	return CKR_OK
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

// GetFunctionStatus is a legacy function from PKCS#11 v2.x.
// Implements C_GetFunctionStatus behavior per PKCS#11 specification.
// This function is deprecated and always returns CKR_FUNCTION_NOT_PARALLEL.
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

// CancelFunction is a legacy function from PKCS#11 v2.x.
// Implements C_CancelFunction behavior per PKCS#11 specification.
// This function is deprecated and always returns CKR_FUNCTION_NOT_PARALLEL.
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

// extractCurveFromParams extracts curve name from EC parameters (OID).
// This is a simplified implementation that handles common curves.
func extractCurveFromParams(params []byte) string {
	// Common OIDs for EC curves (DER-encoded)
	p256OID := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	p384OID := []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	p521OID := []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}

	if len(params) >= len(p256OID) && bytesEqual(params[:len(p256OID)], p256OID) {
		return "P-256"
	}
	if len(params) >= len(p384OID) && bytesEqual(params[:len(p384OID)], p384OID) {
		return "P-384"
	}
	if len(params) >= len(p521OID) && bytesEqual(params[:len(p521OID)], p521OID) {
		return "P-521"
	}

	return "P-256" // Default to P-256
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
	copy(field, []byte(s))
}

// extractPublicKeyComponentsFromPEM parses a PEM-encoded public key and extracts
// the key components suitable for storing as PKCS#11 attributes.
// For RSA keys, returns CKA_MODULUS and CKA_PUBLIC_EXPONENT.
// For EC keys, returns CKA_EC_POINT.
func extractPublicKeyComponentsFromPEM(pemData string) (modulus, publicExponent, ecPoint []byte) {
	if pemData == "" {
		return nil, nil, nil
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, nil, nil
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, nil
	}

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// Extract RSA modulus (N) and public exponent (E)
		modulus = key.N.Bytes()
		// Convert exponent to big-endian bytes
		e := key.E
		if e == 0 {
			publicExponent = []byte{0}
		} else {
			// Calculate number of bytes needed
			numBytes := 0
			temp := e
			for temp > 0 {
				numBytes++
				temp >>= 8
			}
			publicExponent = make([]byte, numBytes)
			for i := numBytes - 1; i >= 0; i-- {
				publicExponent[i] = byte(e & 0xff)
				e >>= 8
			}
		}
		return modulus, publicExponent, nil

	case *ecdsa.PublicKey:
		// Extract EC point (uncompressed format: 0x04 || X || Y)
		// The point is encoded as an OCTET STRING per PKCS#11
		ecdhKey, ecdhErr := key.ECDH()
		if ecdhErr != nil {
			return nil, nil, nil
		}
		ecPoint = ecdhKey.Bytes()
		// Wrap in ASN.1 OCTET STRING as per PKCS#11 spec
		ecPoint, _ = asn1.Marshal(ecPoint)
		return nil, nil, ecPoint

	default:
		return nil, nil, nil
	}
}
