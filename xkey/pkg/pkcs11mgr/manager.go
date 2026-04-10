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

// Manager handles the lifecycle of PKCS#11 modules and their slots.
type Manager interface {
	// RegisterModule loads a PKCS#11 library and enumerates its slots.
	// Returns the generated module ID on success.
	RegisterModule(libraryPath, displayName string) (string, error)

	// UnregisterModule finalizes and unloads a PKCS#11 module.
	UnregisterModule(moduleID string) error

	// RefreshSlots re-enumerates slots for a loaded module (hot-plug support).
	RefreshSlots(moduleID string) ([]SlotInfo, error)

	// GetModule returns info about a registered module.
	GetModule(moduleID string) (*ModuleInfo, error)

	// ListModules returns all registered modules.
	ListModules() []ModuleInfo

	// OpenSession opens a session to a specific slot.
	// If pin is non-empty, performs C_Login with CKU_USER.
	OpenSession(moduleID string, slotID uint, pin string) (*SessionHandle, error)

	// CloseSession closes an open session.
	// Does NOT call C_Logout (which would affect all sessions on the token).
	CloseSession(handle *SessionHandle) error

	// Close finalizes all modules and releases resources.
	Close() error
}
