//go:build pkcs11

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

package manager

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"

	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/miekg/pkcs11"
)

// loadedModule holds the runtime state for a single PKCS#11 module.
type loadedModule struct {
	info   ModuleInfo
	p11ctx *pkcs11.Ctx
}

// memoryManager is the production implementation of Manager.
type memoryManager struct {
	mu          sync.RWMutex
	modules     map[string]*loadedModule
	connections map[string]*Connection // key: moduleID:slotID
	closed      bool
	log         *slog.Logger
}

// Compile-time interface check.
var _ Manager = (*memoryManager)(nil)

// New creates a new PKCS#11 module manager.
func New(opts ...Option) Manager {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}

	return &memoryManager{
		modules:     make(map[string]*loadedModule),
		connections: make(map[string]*Connection),
		log:         logger,
	}
}

// IsAvailable returns true because PKCS#11 support is compiled in.
func (m *memoryManager) IsAvailable() bool {
	return true
}

// RegisterModule loads a PKCS#11 library, calls C_Initialize, and enumerates slots.
func (m *memoryManager) RegisterModule(libraryPath, displayName string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return "", ErrManagerClosed
	}

	if err := validateLibraryPath(libraryPath); err != nil {
		return "", err
	}

	moduleID := DeriveModuleID(libraryPath)

	if _, exists := m.modules[moduleID]; exists {
		return "", ErrModuleAlreadyLoaded
	}

	p11ctx := pkcs11.New(libraryPath)
	if p11ctx == nil {
		return "", ErrModuleLoadFailed
	}

	if err := p11ctx.Initialize(); err != nil {
		p11ctx.Destroy()
		return "", ErrModuleInitFailed
	}

	slots, err := m.enumerateSlots(p11ctx)
	if err != nil {
		_ = p11ctx.Finalize()
		p11ctx.Destroy()
		return "", err
	}

	mod := &loadedModule{
		info: ModuleInfo{
			ID:          moduleID,
			DisplayName: displayName,
			LibraryPath: libraryPath,
			State:       ModuleStateLoaded,
			Slots:       slots,
		},
		p11ctx: p11ctx,
	}

	m.modules[moduleID] = mod

	m.log.Info("pkcs11 manager: module registered",
		"module_id", moduleID,
		"library", libraryPath,
		"slots", len(slots))

	return moduleID, nil
}

// UnregisterModule finalizes and unloads a PKCS#11 module.
func (m *memoryManager) UnregisterModule(moduleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrManagerClosed
	}

	mod, exists := m.modules[moduleID]
	if !exists {
		return ErrModuleNotFound
	}

	// Close all connections for this module first
	for connID, conn := range m.connections {
		if conn.ModuleID == moduleID {
			if err := m.disconnectLocked(conn); err != nil {
				m.log.Warn("pkcs11 manager: failed to disconnect during unregister",
					"connection_id", connID,
					"error", err)
			}
			delete(m.connections, connID)
		}
	}

	if err := mod.p11ctx.Finalize(); err != nil {
		mod.info.State = ModuleStateError
		mod.info.ErrorMsg = err.Error()
		return ErrModuleFinalizeFailed
	}

	mod.p11ctx.Destroy()
	delete(m.modules, moduleID)

	m.log.Info("pkcs11 manager: module unregistered", "module_id", moduleID)

	return nil
}

// RefreshSlots re-enumerates slots for a loaded module.
func (m *memoryManager) RefreshSlots(moduleID string) ([]SlotInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrManagerClosed
	}

	mod, exists := m.modules[moduleID]
	if !exists {
		return nil, ErrModuleNotFound
	}

	slots, err := m.enumerateSlots(mod.p11ctx)
	if err != nil {
		return nil, err
	}

	mod.info.Slots = slots

	m.log.Info("pkcs11 manager: slots refreshed",
		"module_id", moduleID,
		"slots", len(slots))

	return slots, nil
}

// GetModule returns info about a registered module.
func (m *memoryManager) GetModule(moduleID string) (*ModuleInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrManagerClosed
	}

	mod, exists := m.modules[moduleID]
	if !exists {
		return nil, ErrModuleNotFound
	}

	// Return a copy to prevent external mutation.
	info := mod.info
	info.Slots = make([]SlotInfo, len(mod.info.Slots))
	copy(info.Slots, mod.info.Slots)

	return &info, nil
}

// ListModules returns all registered modules sorted by ID.
func (m *memoryManager) ListModules() []ModuleInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]ModuleInfo, 0, len(m.modules))
	for _, mod := range m.modules {
		info := mod.info
		info.Slots = make([]SlotInfo, len(mod.info.Slots))
		copy(info.Slots, mod.info.Slots)
		result = append(result, info)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// ListTokens returns all detected tokens across all modules.
func (m *memoryManager) ListTokens() []TokenInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tokens []TokenInfo

	for _, mod := range m.modules {
		for _, slot := range mod.info.Slots {
			if !slot.TokenPresent {
				continue
			}

			connID := connectionID(mod.info.ID, slot.SlotID)
			_, connected := m.connections[connID]

			tokens = append(tokens, TokenInfo{
				ModuleID:     mod.info.ID,
				ModuleName:   mod.info.DisplayName,
				SlotID:       slot.SlotID,
				Label:        slot.Label,
				Manufacturer: slot.Manufacturer,
				Model:        slot.Model,
				Serial:       slot.Serial,
				Initialized:  slot.Initialized,
				Connected:    connected,
			})
		}
	}

	return tokens
}

// InitializeToken initializes a new token with SO PIN and User PIN.
func (m *memoryManager) InitializeToken(moduleID string, slotID uint, label, soPin, userPin string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrManagerClosed
	}

	mod, exists := m.modules[moduleID]
	if !exists {
		return ErrModuleNotFound
	}

	// Validate slot exists
	var slotInfo *SlotInfo
	for i := range mod.info.Slots {
		if mod.info.Slots[i].SlotID == slotID {
			slotInfo = &mod.info.Slots[i]
			break
		}
	}
	if slotInfo == nil {
		return ErrSlotNotFound
	}
	if !slotInfo.TokenPresent {
		return ErrTokenNotPresent
	}

	// Validate PINs
	if len(soPin) < 4 || len(soPin) > 32 {
		return ErrInvalidPIN
	}
	if len(userPin) < 4 || len(userPin) > 32 {
		return ErrInvalidPIN
	}

	// Initialize the token
	if err := mod.p11ctx.InitToken(slotID, soPin, label); err != nil {
		return fmt.Errorf("%w: %v", ErrTokenInitFailed, err)
	}

	// Open a session as SO to initialize the user PIN
	session, err := mod.p11ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSessionOpenFailed, err)
	}
	defer func() { _ = mod.p11ctx.CloseSession(session) }()

	// Login as SO
	if err := mod.p11ctx.Login(session, pkcs11.CKU_SO, soPin); err != nil {
		return fmt.Errorf("%w: %v", ErrLoginFailed, err)
	}
	defer func() { _ = mod.p11ctx.Logout(session) }()

	// Initialize user PIN
	if err := mod.p11ctx.InitPIN(session, userPin); err != nil {
		return fmt.Errorf("%w: %v", ErrPINInitFailed, err)
	}

	// Refresh slots to update token info
	slots, err := m.enumerateSlots(mod.p11ctx)
	if err == nil {
		mod.info.Slots = slots
	}

	m.log.Info("pkcs11 manager: token initialized",
		"module_id", moduleID,
		"slot_id", slotID,
		"label", label)

	return nil
}

// TestLogin verifies that login to a token works without creating a full backend.
// This is useful for connection testing in UI flows where we just need to verify
// the PIN is correct without setting up the full backend infrastructure.
func (m *memoryManager) TestLogin(moduleID string, slotID uint, userPin string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrManagerClosed
	}

	mod, exists := m.modules[moduleID]
	if !exists {
		return ErrModuleNotFound
	}

	// Find slot info
	var slotInfo *SlotInfo
	for i := range mod.info.Slots {
		if mod.info.Slots[i].SlotID == slotID {
			slotInfo = &mod.info.Slots[i]
			break
		}
	}
	if slotInfo == nil {
		return ErrSlotNotFound
	}
	if !slotInfo.TokenPresent {
		return ErrTokenNotPresent
	}
	if !slotInfo.Initialized {
		return ErrTokenNotInitialized
	}

	// Open session
	session, err := mod.p11ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSessionOpenFailed, err)
	}
	defer func() { _ = mod.p11ctx.CloseSession(session) }()

	// Login as user
	if userPin != "" {
		if loginErr := mod.p11ctx.Login(session, pkcs11.CKU_USER, userPin); loginErr != nil {
			if !isAlreadyLoggedIn(loginErr) {
				return fmt.Errorf("%w: %v", ErrLoginFailed, loginErr)
			}
		}
		// Logout after successful login test
		_ = mod.p11ctx.Logout(session)
	}

	m.log.Info("pkcs11 manager: login test successful",
		"module_id", moduleID,
		"slot_id", slotID,
		"token_label", slotInfo.Label)

	return nil
}

// Connect opens a session to a token and creates a Backend.
func (m *memoryManager) Connect(moduleID string, slotID uint, userPin, soPin string) (Backend, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrManagerClosed
	}

	connID := connectionID(moduleID, slotID)
	if _, exists := m.connections[connID]; exists {
		return nil, ErrConnectionAlreadyExists
	}

	mod, exists := m.modules[moduleID]
	if !exists {
		return nil, ErrModuleNotFound
	}

	// Find slot info
	var slotInfo *SlotInfo
	for i := range mod.info.Slots {
		if mod.info.Slots[i].SlotID == slotID {
			slotInfo = &mod.info.Slots[i]
			break
		}
	}
	if slotInfo == nil {
		return nil, ErrSlotNotFound
	}
	if !slotInfo.TokenPresent {
		return nil, ErrTokenNotPresent
	}
	if !slotInfo.Initialized {
		return nil, ErrTokenNotInitialized
	}

	// Open session
	session, err := mod.p11ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionOpenFailed, err)
	}

	// Login as user
	if userPin != "" {
		if loginErr := mod.p11ctx.Login(session, pkcs11.CKU_USER, userPin); loginErr != nil {
			if !isAlreadyLoggedIn(loginErr) {
				_ = mod.p11ctx.CloseSession(session)
				return nil, fmt.Errorf("%w: %v", ErrLoginFailed, loginErr)
			}
		}
	}

	// Create memory storage for key and cert metadata
	keyStorage, err := storage.NewMemoryBackend()
	if err != nil {
		_ = mod.p11ctx.CloseSession(session)
		return nil, fmt.Errorf("failed to create key storage: %w", err)
	}
	certStorage, err := storage.NewMemoryBackend()
	if err != nil {
		_ = mod.p11ctx.CloseSession(session)
		return nil, fmt.Errorf("failed to create cert storage: %w", err)
	}

	// Create PKCS#11 backend
	slotIDPtr := int(slotID)
	config := &pkcs11backend.Config{
		Library:     mod.info.LibraryPath,
		Slot:        &slotIDPtr,
		PIN:         userPin,
		SOPIN:       soPin,
		TokenLabel:  slotInfo.Label,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}

	backend, err := pkcs11backend.NewBackend(config)
	if err != nil {
		_ = mod.p11ctx.CloseSession(session)
		return nil, err
	}

	conn := &Connection{
		ModuleID:      moduleID,
		SlotID:        slotID,
		TokenLabel:    slotInfo.Label,
		Backend:       backend,
		SessionHandle: uint(session),
		P11Ctx:        mod.p11ctx,
	}

	m.connections[connID] = conn

	m.log.Info("pkcs11 manager: connected to token",
		"module_id", moduleID,
		"slot_id", slotID,
		"token_label", slotInfo.Label)

	return backend, nil
}

// Disconnect closes the connection to a token.
func (m *memoryManager) Disconnect(moduleID string, slotID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrManagerClosed
	}

	connID := connectionID(moduleID, slotID)
	conn, exists := m.connections[connID]
	if !exists {
		return ErrConnectionNotFound
	}

	if err := m.disconnectLocked(conn); err != nil {
		return err
	}

	delete(m.connections, connID)

	m.log.Info("pkcs11 manager: disconnected from token",
		"module_id", moduleID,
		"slot_id", slotID)

	return nil
}

// disconnectLocked closes a connection (caller must hold lock).
func (m *memoryManager) disconnectLocked(conn *Connection) error {
	// Close the backend
	if conn.Backend != nil {
		if err := conn.Backend.Close(); err != nil {
			return err
		}
	}
	return nil
}

// GetConnection returns an existing connection if one exists.
func (m *memoryManager) GetConnection(moduleID string, slotID uint) (*Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrManagerClosed
	}

	connID := connectionID(moduleID, slotID)
	conn, exists := m.connections[connID]
	if !exists {
		return nil, ErrConnectionNotFound
	}

	return conn, nil
}

// ListConnections returns all active connections.
func (m *memoryManager) ListConnections() []*Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Connection, 0, len(m.connections))
	for _, conn := range m.connections {
		result = append(result, conn)
	}

	return result
}

// Close finalizes all modules and releases resources.
func (m *memoryManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	// Close all connections
	for _, conn := range m.connections {
		if err := m.disconnectLocked(conn); err != nil {
			m.log.Warn("pkcs11 manager: failed to disconnect during close",
				"module_id", conn.ModuleID,
				"slot_id", conn.SlotID,
				"error", err)
		}
	}
	m.connections = make(map[string]*Connection)

	// Finalize all modules
	for id, mod := range m.modules {
		if err := mod.p11ctx.Finalize(); err != nil {
			m.log.Warn("pkcs11 manager: finalize failed during close",
				"module_id", id,
				"error", err)
		}
		mod.p11ctx.Destroy()
	}
	m.modules = make(map[string]*loadedModule)

	m.log.Info("pkcs11 manager: closed")

	return nil
}

// enumerateSlots queries the module for all slots and gathers token info.
func (m *memoryManager) enumerateSlots(ctx *pkcs11.Ctx) ([]SlotInfo, error) {
	slotIDs, err := ctx.GetSlotList(false)
	if err != nil {
		return nil, ErrModuleLoadFailed
	}

	result := make([]SlotInfo, 0, len(slotIDs))

	for _, sid := range slotIDs {
		si := SlotInfo{
			SlotID: sid,
		}

		tokenInfo, tokenErr := ctx.GetTokenInfo(sid)
		if tokenErr != nil {
			// Token not present or not accessible
			si.TokenPresent = false
			result = append(result, si)
			continue
		}

		si.TokenPresent = true
		si.Label = strings.TrimSpace(tokenInfo.Label)
		si.Serial = strings.TrimSpace(tokenInfo.SerialNumber)
		si.Manufacturer = strings.TrimSpace(tokenInfo.ManufacturerID)
		si.Model = strings.TrimSpace(tokenInfo.Model)
		si.Initialized = (tokenInfo.Flags & pkcs11.CKF_TOKEN_INITIALIZED) != 0
		si.HardwareVersion = fmt.Sprintf("%d.%d",
			tokenInfo.HardwareVersion.Major,
			tokenInfo.HardwareVersion.Minor)
		si.FirmwareVersion = fmt.Sprintf("%d.%d",
			tokenInfo.FirmwareVersion.Major,
			tokenInfo.FirmwareVersion.Minor)

		result = append(result, si)
	}

	return result, nil
}

// validateLibraryPath checks that the library path is valid.
func validateLibraryPath(path string) error {
	if path == "" {
		return ErrInvalidLibraryPath
	}
	info, err := os.Stat(path)
	if err != nil {
		return ErrInvalidLibraryPath
	}
	if info.IsDir() {
		return ErrInvalidLibraryPath
	}
	return nil
}

// isAlreadyLoggedIn checks if the error indicates CKR_USER_ALREADY_LOGGED_IN.
func isAlreadyLoggedIn(err error) bool {
	var p11err pkcs11.Error
	if isP11Error(err, &p11err) {
		return uint(p11err) == pkcs11.CKR_USER_ALREADY_LOGGED_IN
	}
	return false
}

// isP11Error attempts to extract a pkcs11.Error from an error.
func isP11Error(err error, target *pkcs11.Error) bool {
	if p11e, ok := err.(pkcs11.Error); ok {
		*target = p11e
		return true
	}
	return false
}
