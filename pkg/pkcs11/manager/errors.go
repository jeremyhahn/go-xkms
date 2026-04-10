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

import "errors"

// Error sentinels for PKCS#11 manager operations.
var (
	// ErrPKCS11Disabled is returned when PKCS#11 support is not compiled in.
	// Build with -tags pkcs11 to enable PKCS#11 functionality.
	ErrPKCS11Disabled = errors.New("pkcs11 support is disabled (build with -tags pkcs11)")

	// ErrManagerClosed is returned when operations are attempted on a closed manager.
	ErrManagerClosed = errors.New("manager is closed")

	// ErrModuleNotFound is returned when a module ID does not exist.
	ErrModuleNotFound = errors.New("module not found")

	// ErrModuleAlreadyLoaded is returned when attempting to register a module that is already loaded.
	ErrModuleAlreadyLoaded = errors.New("module already loaded")

	// ErrModuleLoadFailed is returned when the PKCS#11 library fails to load.
	ErrModuleLoadFailed = errors.New("failed to load PKCS#11 module")

	// ErrModuleInitFailed is returned when C_Initialize fails.
	ErrModuleInitFailed = errors.New("failed to initialize PKCS#11 module")

	// ErrModuleFinalizeFailed is returned when C_Finalize fails.
	ErrModuleFinalizeFailed = errors.New("failed to finalize PKCS#11 module")

	// ErrInvalidLibraryPath is returned when the library path is invalid.
	ErrInvalidLibraryPath = errors.New("invalid library path")

	// ErrSlotNotFound is returned when a slot ID does not exist.
	ErrSlotNotFound = errors.New("slot not found")

	// ErrTokenNotPresent is returned when no token is present in the slot.
	ErrTokenNotPresent = errors.New("token not present in slot")

	// ErrTokenNotInitialized is returned when attempting to connect to an uninitialized token.
	ErrTokenNotInitialized = errors.New("token not initialized")

	// ErrSessionOpenFailed is returned when C_OpenSession fails.
	ErrSessionOpenFailed = errors.New("failed to open session")

	// ErrSessionCloseFailed is returned when C_CloseSession fails.
	ErrSessionCloseFailed = errors.New("failed to close session")

	// ErrLoginFailed is returned when C_Login fails.
	ErrLoginFailed = errors.New("login failed")

	// ErrLogoutFailed is returned when C_Logout fails.
	ErrLogoutFailed = errors.New("logout failed")

	// ErrTokenInitFailed is returned when C_InitToken fails.
	ErrTokenInitFailed = errors.New("failed to initialize token")

	// ErrPINInitFailed is returned when C_InitPIN fails.
	ErrPINInitFailed = errors.New("failed to initialize PIN")

	// ErrConnectionNotFound is returned when a connection is not found.
	ErrConnectionNotFound = errors.New("connection not found")

	// ErrConnectionAlreadyExists is returned when a connection already exists for the slot.
	ErrConnectionAlreadyExists = errors.New("connection already exists for this slot")

	// ErrInvalidPIN is returned when the PIN format is invalid.
	ErrInvalidPIN = errors.New("invalid PIN format")
)
