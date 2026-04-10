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

import "errors"

var (
	// ErrModuleNotFound is returned when a module with the given ID is not registered.
	ErrModuleNotFound = errors.New("pkcs11mgr: module not found")

	// ErrModuleAlreadyLoaded is returned when attempting to register a module
	// that is already loaded.
	ErrModuleAlreadyLoaded = errors.New("pkcs11mgr: module already loaded")

	// ErrModuleLoadFailed is returned when the PKCS#11 shared library cannot
	// be loaded.
	ErrModuleLoadFailed = errors.New("pkcs11mgr: module load failed")

	// ErrModuleInitFailed is returned when C_Initialize fails on the module.
	ErrModuleInitFailed = errors.New("pkcs11mgr: module initialization failed")

	// ErrModuleFinalizeFailed is returned when C_Finalize fails on the module.
	ErrModuleFinalizeFailed = errors.New("pkcs11mgr: module finalization failed")

	// ErrSlotNotFound is returned when the requested slot does not exist
	// in the module.
	ErrSlotNotFound = errors.New("pkcs11mgr: slot not found")

	// ErrTokenNotPresent is returned when a slot does not have a token inserted.
	ErrTokenNotPresent = errors.New("pkcs11mgr: token not present in slot")

	// ErrSessionOpenFailed is returned when C_OpenSession fails.
	ErrSessionOpenFailed = errors.New("pkcs11mgr: session open failed")

	// ErrSessionCloseFailed is returned when C_CloseSession fails.
	ErrSessionCloseFailed = errors.New("pkcs11mgr: session close failed")

	// ErrLoginFailed is returned when C_Login fails.
	ErrLoginFailed = errors.New("pkcs11mgr: login failed")

	// ErrInvalidLibraryPath is returned when the library path is empty or
	// does not point to an existing file.
	ErrInvalidLibraryPath = errors.New("pkcs11mgr: invalid library path")

	// ErrManagerClosed is returned when an operation is attempted on a
	// closed manager.
	ErrManagerClosed = errors.New("pkcs11mgr: manager is closed")
)
