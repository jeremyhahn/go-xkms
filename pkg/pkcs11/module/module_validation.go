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

// Package module provides PKCS#11 (Cryptoki) v3.2 validation framework support.
//
// This file implements the PKCS#11 v3.2 validation framework that allows applications
// to query the validation state of a module and its sessions. The validation framework
// supports FIPS 140-3 and Common Criteria certification requirements by exposing
// whether the module is operating in a validated (protected) configuration.
//
// Constants:
//   - CKS_LAST_VALIDATION_OK: validation flags type for querying last operation validation status
//
// Functions:
//   - GetSessionValidationFlags: C_GetSessionValidationFlags — query validation status by flags type
//
// References:
//   - OASIS PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
package module

// Validation flags types for GetSessionValidationFlags (CK_SESSION_VALIDATION_FLAGS_TYPE).
const (
	// CKS_LAST_VALIDATION_OK is the flags type for querying whether the
	// last operation completed in a validated state per FIPS 140-3 or
	// equivalent certification requirements.
	CKS_LAST_VALIDATION_OK uint64 = 0x00000001
)

// Validation flag bits returned by GetSessionValidationFlags.
const (
	// CKF_VALIDATION_PROTECTED indicates the module is operating
	// in a validated (FIPS 140-3 / Common Criteria) configuration.
	CKF_VALIDATION_PROTECTED uint64 = 0x00000001
)

// GetSessionValidationFlags returns the validation status flags for a session.
// The flagsType parameter selects which category of validation flags to query,
// using a CK_SESSION_VALIDATION_FLAGS_TYPE value.
//
// This implements C_GetSessionValidationFlags per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle used to identify the context
//   - flagsType: the category of validation flags to query (CK_SESSION_VALIDATION_FLAGS_TYPE)
//
// Returns:
//   - uint64: bitmask of validation flags
//   - error: nil on success, or a PKCS11Error
func (m *Module) GetSessionValidationFlags(sessionHandle SessionHandle, flagsType uint64) (uint64, error) {
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

	// Validate flagsType is a known CK_SESSION_VALIDATION_FLAGS_TYPE value.
	// Per the spec, only CKS_LAST_VALIDATION_OK is defined.
	if flagsType != CKS_LAST_VALIDATION_OK {
		return 0, NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Return default flags: no special validation status.
	// When FIPS 140-3 or Common Criteria certification is achieved,
	// this should return appropriate flags when operating
	// in a validated configuration.
	return 0, nil
}
