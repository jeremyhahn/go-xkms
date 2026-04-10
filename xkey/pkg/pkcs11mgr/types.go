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

// Package pkcs11mgr manages the lifecycle of PKCS#11 library modules,
// slot enumeration, and session management. Each module's slots can be
// registered as backends in the backend registry.
package pkcs11mgr

// ModuleState represents the lifecycle state of a PKCS#11 module.
type ModuleState int32

const (
	// ModuleStateUnloaded indicates the module has not been loaded.
	ModuleStateUnloaded ModuleState = iota

	// ModuleStateLoaded indicates the module is loaded and initialized.
	ModuleStateLoaded

	// ModuleStateError indicates the module encountered an error.
	ModuleStateError
)

// String returns the human-readable name for a ModuleState.
func (s ModuleState) String() string {
	if name, ok := moduleStateNames[s]; ok {
		return name
	}
	return "unknown"
}

var moduleStateNames = map[ModuleState]string{
	ModuleStateUnloaded: "unloaded",
	ModuleStateLoaded:   "loaded",
	ModuleStateError:    "error",
}

// SlotInfo describes a single slot in a PKCS#11 module.
type SlotInfo struct {
	// SlotID is the PKCS#11 slot identifier.
	SlotID uint `json:"slot_id"`

	// Label is the token label from CK_TOKEN_INFO.
	Label string `json:"label"`

	// Serial is the token serial number from CK_TOKEN_INFO.
	Serial string `json:"serial"`

	// TokenPresent indicates whether a token is inserted in this slot.
	TokenPresent bool `json:"token_present"`

	// Initialized indicates whether the token in this slot has been initialized.
	Initialized bool `json:"initialized"`

	// HardwareVersion is the hardware version string from CK_TOKEN_INFO.
	HardwareVersion string `json:"hardware_version"`

	// FirmwareVersion is the firmware version string from CK_TOKEN_INFO.
	FirmwareVersion string `json:"firmware_version"`
}

// ModuleInfo describes a loaded PKCS#11 module.
type ModuleInfo struct {
	// ID is the unique identifier for this module (derived from the library basename).
	ID string `json:"id"`

	// DisplayName is a human-readable name for this module.
	DisplayName string `json:"display_name"`

	// LibraryPath is the filesystem path to the PKCS#11 shared library.
	LibraryPath string `json:"library_path"`

	// State is the current lifecycle state of this module.
	State ModuleState `json:"state"`

	// Slots contains information about each slot in the module.
	Slots []SlotInfo `json:"slots"`

	// ErrorMsg is populated when State == ModuleStateError.
	ErrorMsg string `json:"error_msg,omitempty"`
}

// SessionHandle is an opaque reference to an open PKCS#11 session.
type SessionHandle struct {
	// ModuleID identifies which module owns this session.
	ModuleID string `json:"module_id"`

	// SlotID identifies which slot this session is on.
	SlotID uint `json:"slot_id"`

	// Handle is the underlying PKCS#11 session handle.
	Handle uint `json:"handle"`
}
