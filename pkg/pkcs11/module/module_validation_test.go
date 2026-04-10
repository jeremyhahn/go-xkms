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

package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCKSLastValidationOKConstant verifies the constant value per PKCS#11 v3.2 spec.
func TestCKSLastValidationOKConstant(t *testing.T) {

	t.Run("CKS_LAST_VALIDATION_OK has correct value", func(t *testing.T) {
		assert.Equal(t, uint64(0x00000001), CKS_LAST_VALIDATION_OK)
	})

	t.Run("CKS_LAST_VALIDATION_OK is a single bit flag", func(t *testing.T) {
		// Verify it is exactly one bit set (power of 2)
		assert.Equal(t, uint64(1), CKS_LAST_VALIDATION_OK&(CKS_LAST_VALIDATION_OK-1)+1,
			"CKS_LAST_VALIDATION_OK should have exactly one bit set")
	})
}

// TestCKFValidationProtectedConstant verifies the flag bit value per PKCS#11 v3.2 spec.
func TestCKFValidationProtectedConstant(t *testing.T) {

	t.Run("CKF_VALIDATION_PROTECTED has correct value", func(t *testing.T) {
		assert.Equal(t, uint64(0x00000001), CKF_VALIDATION_PROTECTED)
	})
}

// TestGetSessionValidationFlags tests the validation flags query with a valid session.
func TestGetSessionValidationFlags(t *testing.T) {

	t.Run("returns zero flags with CKS_LAST_VALIDATION_OK flagsType", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		flags, err := m.GetSessionValidationFlags(sessionHandle, CKS_LAST_VALIDATION_OK)
		require.NoError(t, err)
		assert.Equal(t, uint64(0), flags)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with invalid flagsType", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		flags, err := m.GetSessionValidationFlags(sessionHandle, 0)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Equal(t, uint64(0), flags)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with unknown flagsType", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		flags, err := m.GetSessionValidationFlags(sessionHandle, 0xDEADBEEF)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Equal(t, uint64(0), flags)
	})
}

// TestGetSessionValidationFlagsNotInitialized tests that GetSessionValidationFlags
// rejects calls when the module has not been initialized.
func TestGetSessionValidationFlagsNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		flags, err := m.GetSessionValidationFlags(SessionHandle(1), 0)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
		assert.Equal(t, uint64(0), flags)
	})
}

// TestGetSessionValidationFlagsInvalidSession tests that GetSessionValidationFlags
// rejects calls with an invalid session handle.
func TestGetSessionValidationFlagsInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		flags, err := m.GetSessionValidationFlags(SessionHandle(99999), 0)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, uint64(0), flags)
	})
}
