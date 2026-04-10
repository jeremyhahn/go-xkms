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

// Package module provides PKCS#11 (Cryptoki) v3.2 asynchronous operation support.
//
// This file implements the PKCS#11 v3.2 asynchronous operation functions that allow
// non-blocking cryptographic operations. Async operations are identified by function
// name (string), enabling applications to initiate long-running cryptographic
// computations and poll for or await their completion without blocking the calling thread.
//
// Functions:
//   - AsyncComplete: C_AsyncComplete — retrieve the result of a completed async operation
//   - AsyncGetID: C_AsyncGetID — retrieve the operation ID for an async function
//   - AsyncJoin: C_AsyncJoin — join/await an async operation with data
//
// References:
//   - OASIS PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
package module

// AsyncData represents the CK_ASYNC_DATA structure from the PKCS#11 v3.2 specification.
// It holds the result of a completed asynchronous operation.
type AsyncData struct {
	// Version is the structure version (currently 1).
	Version uint64

	// Value is the result data from the completed operation (e.g., ciphertext, signature).
	Value []byte

	// Object is the primary result object handle, or InvalidHandle if not applicable.
	Object ObjectHandle

	// AdditionalObject is a secondary result object handle, or InvalidHandle if not applicable.
	AdditionalObject ObjectHandle
}

// AsyncComplete retrieves the result of a completed asynchronous operation
// identified by function name. Returns the result as an AsyncData structure
// matching the CK_ASYNC_DATA specification.
//
// This implements C_AsyncComplete per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle
//   - functionName: the name of the async function to complete (e.g., "C_Sign")
//
// Returns:
//   - *AsyncData: the result data structure, or nil on error
//   - error: nil if the operation is complete, or a PKCS11Error
func (m *Module) AsyncComplete(sessionHandle SessionHandle, functionName string) (*AsyncData, error) {
	if !m.initialized.Load() {
		return nil, NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Validate function name is provided
	if functionName == "" {
		return nil, NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Async operations require hardware backend support that is not yet available.
	return nil, NewPKCS11Error(CKR_FUNCTION_NOT_SUPPORTED)
}

// AsyncGetID retrieves the operation ID for the asynchronous operation
// identified by function name on the given session. The operation ID can be
// used with AsyncJoin to manage the async operation lifecycle.
//
// This implements C_AsyncGetID per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle
//   - functionName: the name of the async function to query (e.g., "C_Sign")
//
// Returns:
//   - uint64: the operation ID
//   - error: nil on success, or a PKCS11Error
func (m *Module) AsyncGetID(sessionHandle SessionHandle, functionName string) (uint64, error) {
	if !m.initialized.Load() {
		return 0, NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return 0, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Validate function name is provided
	if functionName == "" {
		return 0, NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Async operations require hardware backend support that is not yet available.
	return 0, NewPKCS11Error(CKR_FUNCTION_NOT_SUPPORTED)
}

// AsyncJoin reconnects to the specified asynchronous operation and awaits
// its completion. The function name identifies which async operation to join,
// and the ID and data parameters provide context for the join operation.
//
// This implements C_AsyncJoin per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle
//   - functionName: the name of the async function to join (e.g., "C_Sign")
//   - id: the operation identifier obtained from AsyncGetID
//   - data: optional data to pass to the join operation; may be nil
//
// Returns:
//   - error: nil on success, or a PKCS11Error
func (m *Module) AsyncJoin(sessionHandle SessionHandle, functionName string, id uint64, data []byte) error {
	if !m.initialized.Load() {
		return NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Validate function name is provided
	if functionName == "" {
		return NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Async operations require hardware backend support that is not yet available.
	return NewPKCS11Error(CKR_FUNCTION_NOT_SUPPORTED)
}
