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
	"crypto"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Backend represents a cryptographic backend that can be returned by Connect.
// This interface matches the common operations available on all backends.
type Backend interface {
	// Type returns the backend type.
	Type() types.BackendType

	// Capabilities returns the backend capabilities.
	Capabilities() types.Capabilities

	// GenerateKey generates a new key with the given attributes.
	GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error)

	// Get retrieves key material.
	Get(attrs *types.KeyAttributes, extension types.FSExtension) ([]byte, error)

	// Delete removes a key.
	Delete(attrs *types.KeyAttributes) error

	// Signer returns a crypto.Signer for the given key.
	Signer(attrs *types.KeyAttributes) (crypto.Signer, error)

	// Close releases backend resources.
	Close() error
}

// Manager handles the lifecycle of PKCS#11 modules and their tokens.
// It provides multi-module/multi-token management for both CLI and GUI applications.
type Manager interface {
	// IsAvailable returns true if PKCS#11 support is compiled in.
	// When built without the pkcs11 tag, this returns false.
	IsAvailable() bool

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

	// ListTokens returns all detected PKCS#11 tokens across all modules.
	ListTokens() []TokenInfo

	// InitializeToken initializes a new token with SO PIN and User PIN.
	// This calls C_InitToken and C_InitPIN on the token.
	InitializeToken(moduleID string, slotID uint, label, soPin, userPin string) error

	// TestLogin verifies that login to a token works without creating a full backend.
	// This is useful for connection testing in UI flows.
	TestLogin(moduleID string, slotID uint, userPin string) error

	// Connect opens a session to a token and creates a Backend.
	// The backend can be used for cryptographic operations.
	Connect(moduleID string, slotID uint, userPin, soPin string) (Backend, error)

	// Disconnect closes the connection to a token and cleans up resources.
	Disconnect(moduleID string, slotID uint) error

	// GetConnection returns an existing connection if one exists.
	GetConnection(moduleID string, slotID uint) (*Connection, error)

	// ListConnections returns all active connections.
	ListConnections() []*Connection

	// Close finalizes all modules and releases resources.
	Close() error
}

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
	switch s {
	case ModuleStateUnloaded:
		return "unloaded"
	case ModuleStateLoaded:
		return "loaded"
	case ModuleStateError:
		return "error"
	default:
		return "unknown"
	}
}

// SlotInfo describes a single slot in a PKCS#11 module.
type SlotInfo struct {
	// SlotID is the PKCS#11 slot identifier.
	SlotID uint `json:"slot_id"`

	// Label is the token label from CK_TOKEN_INFO.
	Label string `json:"label"`

	// Serial is the token serial number from CK_TOKEN_INFO.
	Serial string `json:"serial"`

	// Manufacturer is the manufacturer from CK_TOKEN_INFO.
	Manufacturer string `json:"manufacturer"`

	// Model is the model from CK_TOKEN_INFO.
	Model string `json:"model"`

	// TokenPresent indicates whether a token is inserted in this slot.
	TokenPresent bool `json:"token_present"`

	// Initialized indicates whether the token has been initialized.
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

// TokenInfo describes a PKCS#11 token for display purposes.
type TokenInfo struct {
	// ModuleID is the ID of the module containing this token.
	ModuleID string `json:"module_id"`

	// ModuleName is the display name of the module.
	ModuleName string `json:"module_name"`

	// SlotID is the PKCS#11 slot identifier.
	SlotID uint `json:"slot_id"`

	// Label is the token label from CK_TOKEN_INFO.
	Label string `json:"label"`

	// Manufacturer is the manufacturer from CK_TOKEN_INFO.
	Manufacturer string `json:"manufacturer"`

	// Model is the model from CK_TOKEN_INFO.
	Model string `json:"model"`

	// Serial is the token serial number from CK_TOKEN_INFO.
	Serial string `json:"serial"`

	// Initialized indicates whether the token has been initialized.
	Initialized bool `json:"initialized"`

	// Connected indicates whether there is an active connection to this token.
	Connected bool `json:"connected"`
}

// Connection represents an active connection to a PKCS#11 token.
type Connection struct {
	// ModuleID identifies which module owns this connection.
	ModuleID string `json:"module_id"`

	// SlotID identifies which slot this connection is on.
	SlotID uint `json:"slot_id"`

	// TokenLabel is the label of the connected token.
	TokenLabel string `json:"token_label"`

	// Backend is the PKCS#11 backend for cryptographic operations.
	Backend Backend `json:"-"`

	// SessionHandle is the underlying PKCS#11 session handle.
	SessionHandle uint `json:"-"`

	// P11Ctx is the raw PKCS#11 context for the module.
	// Exposed so callers (e.g., PIV cert storage) can reuse the
	// already-initialized library context instead of re-initializing.
	P11Ctx interface{} `json:"-"`
}

// ConnectionID returns a unique identifier for this connection.
func (c *Connection) ConnectionID() string {
	return connectionID(c.ModuleID, c.SlotID)
}

// connectionID generates a unique connection ID from module ID and slot ID.
func connectionID(moduleID string, slotID uint) string {
	return moduleID + ":" + uintToString(slotID)
}

// uintToString converts a uint to string without importing strconv.
func uintToString(n uint) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf) - 1
	for n > 0 {
		buf[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	return string(buf[i+1:])
}

// Option configures the Manager.
type Option func(*options)

type options struct {
	logger *slog.Logger
}

// WithLogger sets the logger for the manager.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		o.logger = logger
	}
}
