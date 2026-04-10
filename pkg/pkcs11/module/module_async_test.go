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

// ----------------------------------------------------------------------------
// AsyncComplete
// ----------------------------------------------------------------------------

func TestAsyncComplete(t *testing.T) {

	t.Run("returns CKR_FUNCTION_NOT_SUPPORTED with valid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		result, err := m.AsyncComplete(sessionHandle, "C_Sign")
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_FUNCTION_NOT_SUPPORTED, pkcsErr.Code)
		assert.Nil(t, result)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with empty function name", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		result, err := m.AsyncComplete(sessionHandle, "")
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Nil(t, result)
	})
}

func TestAsyncCompleteNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		result, err := m.AsyncComplete(SessionHandle(1), "C_Sign")
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
		assert.Nil(t, result)
	})
}

func TestAsyncCompleteInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		result, err := m.AsyncComplete(SessionHandle(99999), "C_Sign")
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
		assert.Nil(t, result)
	})
}

// ----------------------------------------------------------------------------
// AsyncGetID
// ----------------------------------------------------------------------------

func TestAsyncGetID(t *testing.T) {

	t.Run("returns CKR_FUNCTION_NOT_SUPPORTED with valid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		operationID, err := m.AsyncGetID(sessionHandle, "C_Sign")
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_FUNCTION_NOT_SUPPORTED, pkcsErr.Code)
		assert.Equal(t, uint64(0), operationID)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with empty function name", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		operationID, err := m.AsyncGetID(sessionHandle, "")
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
		assert.Equal(t, uint64(0), operationID)
	})
}

func TestAsyncGetIDNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		operationID, err := m.AsyncGetID(SessionHandle(1), "C_Sign")
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
		assert.Equal(t, uint64(0), operationID)
	})
}

func TestAsyncGetIDInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		operationID, err := m.AsyncGetID(SessionHandle(99999), "C_Sign")
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
		assert.Equal(t, uint64(0), operationID)
	})
}

// ----------------------------------------------------------------------------
// AsyncJoin
// ----------------------------------------------------------------------------

func TestAsyncJoin(t *testing.T) {

	t.Run("returns CKR_FUNCTION_NOT_SUPPORTED with valid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		err := m.AsyncJoin(sessionHandle, "C_Sign", 42, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_FUNCTION_NOT_SUPPORTED, pkcsErr.Code)
	})

	t.Run("returns CKR_FUNCTION_NOT_SUPPORTED with data provided", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		err := m.AsyncJoin(sessionHandle, "C_Sign", 42, []byte("join-data"))
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_FUNCTION_NOT_SUPPORTED, pkcsErr.Code)
	})

	t.Run("returns CKR_ARGUMENTS_BAD with empty function name", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		err := m.AsyncJoin(sessionHandle, "", 42, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_ARGUMENTS_BAD, pkcsErr.Code)
	})
}

func TestAsyncJoinNotInitialized(t *testing.T) {

	t.Run("returns CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		m := createTestModule(t)

		err := m.AsyncJoin(SessionHandle(1), "C_Sign", 42, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
	})
}

func TestAsyncJoinInvalidSession(t *testing.T) {

	t.Run("returns CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		err := m.AsyncJoin(SessionHandle(99999), "C_Sign", 42, nil)
		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
	})
}

// ----------------------------------------------------------------------------
// AsyncData
// ----------------------------------------------------------------------------

func TestAsyncDataStruct(t *testing.T) {

	t.Run("zero value has correct defaults", func(t *testing.T) {
		var ad AsyncData
		assert.Equal(t, uint64(0), ad.Version)
		assert.Nil(t, ad.Value)
		assert.Equal(t, ObjectHandle(0), ad.Object)
		assert.Equal(t, ObjectHandle(0), ad.AdditionalObject)
	})

	t.Run("fields can be populated", func(t *testing.T) {
		ad := AsyncData{
			Version:          1,
			Value:            []byte{0x01, 0x02, 0x03},
			Object:           ObjectHandle(42),
			AdditionalObject: ObjectHandle(99),
		}
		assert.Equal(t, uint64(1), ad.Version)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, ad.Value)
		assert.Equal(t, ObjectHandle(42), ad.Object)
		assert.Equal(t, ObjectHandle(99), ad.AdditionalObject)
	})
}
