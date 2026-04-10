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

package pkcs11mgr

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/miekg/pkcs11"
)

// loadedModule holds the runtime state for a single PKCS#11 module.
type loadedModule struct {
	info   ModuleInfo
	p11ctx *pkcs11.Ctx
}

// MemoryManager is the production implementation of Manager. It uses
// miekg/pkcs11 to load and manage PKCS#11 libraries.
type MemoryManager struct {
	mu       sync.RWMutex
	modules  map[string]*loadedModule
	closed   bool
	log      *slog.Logger
	registry backendregistry.Registry
}

// Compile-time interface check.
var _ Manager = (*MemoryManager)(nil)

// NewManager creates a new PKCS#11 module manager with the given options.
func NewManager(opts ...Option) Manager {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}

	return &MemoryManager{
		modules:  make(map[string]*loadedModule),
		log:      logger,
		registry: o.registry,
	}
}

// RegisterModule loads a PKCS#11 library, calls C_Initialize, enumerates
// slots, and optionally registers each slot in the backend registry.
func (m *MemoryManager) RegisterModule(libraryPath, displayName string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return "", ErrManagerClosed
	}

	if err := validateLibraryPath(libraryPath); err != nil {
		return "", err
	}

	moduleID := deriveModuleID(libraryPath)

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
		// Best-effort finalize on failure.
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

	m.log.Info("pkcs11mgr: module registered",
		"module_id", moduleID,
		"library", libraryPath,
		"slots", len(slots))

	if m.registry != nil {
		m.registerSlotBackends(mod)
	}

	return moduleID, nil
}

// UnregisterModule finalizes the module, destroys the context, and removes
// it from the manager. If a registry is configured, slot backends are
// unregistered.
func (m *MemoryManager) UnregisterModule(moduleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrManagerClosed
	}

	mod, exists := m.modules[moduleID]
	if !exists {
		return ErrModuleNotFound
	}

	if m.registry != nil {
		m.unregisterSlotBackends(mod)
	}

	if err := mod.p11ctx.Finalize(); err != nil {
		mod.info.State = ModuleStateError
		mod.info.ErrorMsg = err.Error()
		return ErrModuleFinalizeFailed
	}

	mod.p11ctx.Destroy()
	delete(m.modules, moduleID)

	m.log.Info("pkcs11mgr: module unregistered", "module_id", moduleID)

	return nil
}

// RefreshSlots re-enumerates slots for a loaded module. This supports
// hot-plug scenarios where tokens may be inserted or removed.
func (m *MemoryManager) RefreshSlots(moduleID string) ([]SlotInfo, error) {
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

	// Unregister old slot backends before updating.
	if m.registry != nil {
		m.unregisterSlotBackends(mod)
	}

	mod.info.Slots = slots

	// Register new slot backends.
	if m.registry != nil {
		m.registerSlotBackends(mod)
	}

	m.log.Info("pkcs11mgr: slots refreshed",
		"module_id", moduleID,
		"slots", len(slots))

	return slots, nil
}

// GetModule returns info about a registered module.
func (m *MemoryManager) GetModule(moduleID string) (*ModuleInfo, error) {
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
func (m *MemoryManager) ListModules() []ModuleInfo {
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

// OpenSession opens a PKCS#11 session on the given slot. If pin is non-empty,
// performs C_Login with CKU_USER. CKR_USER_ALREADY_LOGGED_IN is treated as
// success since PKCS#11 login is per-token, not per-session.
func (m *MemoryManager) OpenSession(moduleID string, slotID uint, pin string) (*SessionHandle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrManagerClosed
	}

	mod, exists := m.modules[moduleID]
	if !exists {
		return nil, ErrModuleNotFound
	}

	slotFound := false
	for _, s := range mod.info.Slots {
		if s.SlotID == slotID {
			if !s.TokenPresent {
				return nil, ErrTokenNotPresent
			}
			slotFound = true
			break
		}
	}
	if !slotFound {
		return nil, ErrSlotNotFound
	}

	session, err := mod.p11ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, ErrSessionOpenFailed
	}

	if pin != "" {
		if loginErr := mod.p11ctx.Login(session, pkcs11.CKU_USER, pin); loginErr != nil {
			// CKR_USER_ALREADY_LOGGED_IN is not an error in our model.
			if !isAlreadyLoggedIn(loginErr) {
				// Best-effort close on login failure.
				_ = mod.p11ctx.CloseSession(session)
				return nil, ErrLoginFailed
			}
		}
	}

	return &SessionHandle{
		ModuleID: moduleID,
		SlotID:   slotID,
		Handle:   uint(session),
	}, nil
}

// CloseSession closes an open PKCS#11 session. It does NOT call C_Logout
// because logout affects all sessions on the token, not just this one.
func (m *MemoryManager) CloseSession(handle *SessionHandle) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return ErrManagerClosed
	}

	if handle == nil {
		return ErrSessionCloseFailed
	}

	mod, exists := m.modules[handle.ModuleID]
	if !exists {
		return ErrModuleNotFound
	}

	if err := mod.p11ctx.CloseSession(pkcs11.SessionHandle(handle.Handle)); err != nil {
		return ErrSessionCloseFailed
	}

	return nil
}

// Close finalizes all modules and releases all resources.
func (m *MemoryManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	for id, mod := range m.modules {
		if m.registry != nil {
			m.unregisterSlotBackends(mod)
		}

		if err := mod.p11ctx.Finalize(); err != nil {
			m.log.Warn("pkcs11mgr: finalize failed during close",
				"module_id", id,
				"error", err)
		}
		mod.p11ctx.Destroy()
	}

	m.modules = make(map[string]*loadedModule)

	m.log.Info("pkcs11mgr: manager closed")

	return nil
}

// enumerateSlots queries the module for all slots with tokens and gathers
// token info for each. Slots where the token is not present are included
// with TokenPresent set to false.
func (m *MemoryManager) enumerateSlots(ctx *pkcs11.Ctx) ([]SlotInfo, error) {
	// First get all slots (including those without tokens).
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
			// Token not present or not accessible — include the slot
			// but mark it accordingly.
			si.TokenPresent = false
			result = append(result, si)
			continue
		}

		si.TokenPresent = true
		si.Label = strings.TrimSpace(tokenInfo.Label)
		si.Serial = strings.TrimSpace(tokenInfo.SerialNumber)
		si.HardwareVersion = fmt.Sprintf("%d.%d",
			tokenInfo.HardwareVersion.Major,
			tokenInfo.HardwareVersion.Minor)
		si.FirmwareVersion = fmt.Sprintf("%d.%d",
			tokenInfo.FirmwareVersion.Major,
			tokenInfo.FirmwareVersion.Minor)
		// CKF_TOKEN_INITIALIZED = 0x00000400 (PKCS#11 v2.40, pkcs11t.h).
		si.Initialized = tokenInfo.Flags&0x00000400 != 0

		result = append(result, si)
	}

	return result, nil
}

// registerSlotBackends registers each slot that has a token present as a
// RegisteredBackend in the registry.
func (m *MemoryManager) registerSlotBackends(mod *loadedModule) {
	for _, slot := range mod.info.Slots {
		if !slot.TokenPresent {
			continue
		}

		backendID := slotBackendID(mod.info.ID, slot.SlotID)
		displayName := slot.Label
		if displayName == "" {
			displayName = fmt.Sprintf("%s slot %d", mod.info.DisplayName, slot.SlotID)
		}

		// PKCS#11 slot backends never advertise CapFIDO2. YubiKey's FIDO2 applet
		// is a separate HID USB interface that browsers talk to directly; the PIV
		// applet (libykcs11) cannot proxy FIDO2 credentials. Generic HSMs don't
		// implement FIDO2 either. FIDO2 capability for YubiKey is therefore
		// always false here, regardless of the underlying library.
		_ = strings.Contains(mod.info.LibraryPath, "libykcs11") // documents intent
		backend := &backendregistry.RegisteredBackend{
			ID:          backendID,
			Location:    backendregistry.LocationLocal,
			Category:    backendregistry.CategoryPKCS11,
			DisplayName: displayName,
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapSigning:    true,
				backendregistry.CapEncryption: true,
				backendregistry.CapPIV:        true,
				// CapFIDO2: intentionally omitted (false) — see comment above.
			},
			Metadata: map[string]string{
				"module_id":        mod.info.ID,
				"slot_id":          fmt.Sprintf("%d", slot.SlotID),
				"library_path":     mod.info.LibraryPath,
				"token_label":      slot.Label,
				"token_serial":     slot.Serial,
				"hardware_version": slot.HardwareVersion,
				"firmware_version": slot.FirmwareVersion,
			},
		}
		backend.SetState(backendregistry.StateReady)

		if err := m.registry.Register(backend); err != nil {
			m.log.Warn("pkcs11mgr: failed to register slot backend",
				"backend_id", backendID,
				"error", err)
		}
	}
}

// unregisterSlotBackends removes all slot backends for a module from the
// registry.
func (m *MemoryManager) unregisterSlotBackends(mod *loadedModule) {
	for _, slot := range mod.info.Slots {
		backendID := slotBackendID(mod.info.ID, slot.SlotID)
		if err := m.registry.Unregister(backendID); err != nil {
			m.log.Debug("pkcs11mgr: slot backend not in registry",
				"backend_id", backendID,
				"error", err)
		}
	}
}

// slotBackendID generates a deterministic backend ID for a slot.
func slotBackendID(moduleID string, slotID uint) string {
	return fmt.Sprintf("%s-slot-%d", moduleID, slotID)
}

// deriveModuleID generates a module ID from the library path basename.
// For example, "/usr/lib/libykcs11.so" becomes "pkcs11-libykcs11".
func deriveModuleID(libraryPath string) string {
	base := filepath.Base(libraryPath)
	// Strip common library extensions.
	for _, ext := range []string{".so", ".dylib", ".dll"} {
		if idx := strings.Index(base, ext); idx > 0 {
			base = base[:idx]
			break
		}
	}
	return "pkcs11-" + base
}

// validateLibraryPath checks that the library path is non-empty and points
// to an existing file.
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
	// miekg/pkcs11 wraps CKR codes as pkcs11.Error values.
	var p11err pkcs11.Error
	if ok := isP11Error(err, &p11err); ok {
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
