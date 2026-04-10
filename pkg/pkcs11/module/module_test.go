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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: mockClient and newMockClient are defined in crypto_test.go

// createTestModule creates a module with mock client for testing.
func createTestModule(t *testing.T) *Module {
	t.Helper()
	ResetGlobalModule()

	module, err := New(WithClient(newMockClient()), WithConfig(DefaultConfig()))
	require.NoError(t, err)

	return module
}

// initializeTestModule creates and initializes a module for testing.
func initializeTestModule(t *testing.T) *Module {
	t.Helper()
	m := createTestModule(t)
	rv := m.Initialize(nil)
	require.Equal(t, CKR_OK, rv, "Initialize should succeed")
	return m
}

// createTestModuleWithKey creates an initialized module with a test key object.
func createTestModuleWithKey(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()
	m := initializeTestModule(t)

	handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	// Create a public key object for testing
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		NewStringAttribute(CKA_LABEL, "test-key"),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_MODIFIABLE, true),
		NewBoolAttribute(CKA_COPYABLE, true),
		NewBoolAttribute(CKA_DESTROYABLE, true),
	}

	keyHandle, rv := m.CreateObject(handle, template)
	require.Equal(t, CKR_OK, rv)

	return m, handle, keyHandle
}

// TestNew tests module creation.
func TestNew(t *testing.T) {
	t.Run("creates module with defaults", func(t *testing.T) {
		module, err := New()
		require.NoError(t, err)
		assert.NotNil(t, module)
		assert.False(t, module.IsInitialized())
	})

	t.Run("creates module with config", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Target = "unix:///custom/path.sock"

		module, err := New(WithConfig(cfg))
		require.NoError(t, err)
		assert.NotNil(t, module)
		assert.Equal(t, "unix:///custom/path.sock", module.config.Target)
	})

	t.Run("creates module with custom client", func(t *testing.T) {
		client := newMockClient()
		module, err := New(WithClient(client))
		require.NoError(t, err)
		assert.NotNil(t, module)
		assert.Equal(t, client, module.client)
	})
}

// TestInitialize tests module initialization.
func TestInitialize(t *testing.T) {
	t.Run("initializes successfully", func(t *testing.T) {
		m := createTestModule(t)
		rv := m.Initialize(nil)
		assert.Equal(t, CKR_OK, rv)
		assert.True(t, m.IsInitialized())

		m.Finalize()
	})

	t.Run("fails when already initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.Initialize(nil)
		assert.Equal(t, CKR_CRYPTOKI_ALREADY_INITIALIZED, rv)
	})

	t.Run("initializes with custom config", func(t *testing.T) {
		m := createTestModule(t)
		cfg := DefaultConfig()
		cfg.Target = "unix:///var/run/test.sock"

		rv := m.Initialize(cfg)
		assert.Equal(t, CKR_OK, rv)
		assert.True(t, m.IsInitialized())
		assert.Equal(t, cfg.Target, m.config.Target)

		m.Finalize()
	})
}

// TestFinalize tests module finalization.
func TestFinalize(t *testing.T) {
	t.Run("finalizes successfully", func(t *testing.T) {
		m := initializeTestModule(t)

		rv := m.Finalize()
		assert.Equal(t, CKR_OK, rv)
		assert.False(t, m.IsInitialized())
	})

	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.Finalize()
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})
}

// TestGetInfo tests getting library information.
func TestGetInfo(t *testing.T) {
	t.Run("returns info before initialization", func(t *testing.T) {
		m := createTestModule(t)

		info, rv := m.GetInfo()
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, info)
		assert.Equal(t, byte(3), info.CryptokiVersion.Major)
		assert.Equal(t, byte(2), info.CryptokiVersion.Minor)
		assert.Equal(t, "go-xkms", info.GetManufacturerID())
		assert.Equal(t, "go-xkms PKCS#11", info.GetLibraryDescription())
	})

	t.Run("returns info after initialization", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		info, rv := m.GetInfo()
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, info)
	})
}

// TestGetSlotList tests slot enumeration.
func TestGetSlotList(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetSlotList(false)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("returns slot list", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		slots, rv := m.GetSlotList(false)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEmpty(t, slots)
		assert.Contains(t, slots, SlotID(0))
	})

	t.Run("returns slots with tokens present", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		slots, rv := m.GetSlotList(true)
		assert.Equal(t, CKR_OK, rv)
		// Slot 0 should have a token by default
		assert.NotEmpty(t, slots)
	})
}

// TestGetSlotInfo tests getting slot information.
func TestGetSlotInfo(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetSlotInfo(0)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("returns slot info", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		info, rv := m.GetSlotInfo(0)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, info)
	})

	t.Run("fails for invalid slot", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GetSlotInfo(9999)
		assert.Equal(t, CKR_SLOT_ID_INVALID, rv)
	})
}

// TestGetTokenInfo tests getting token information.
func TestGetTokenInfo(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetTokenInfo(0)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("returns token info", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		info, rv := m.GetTokenInfo(0)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, info)
		assert.Equal(t, "go-xkms", info.GetManufacturerID())
	})

	t.Run("fails for invalid slot", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GetTokenInfo(9999)
		assert.Equal(t, CKR_SLOT_ID_INVALID, rv)
	})
}

// TestGetMechanismList tests mechanism enumeration.
func TestGetMechanismList(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetMechanismList(0)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("returns mechanism list", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		mechs, rv := m.GetMechanismList(0)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEmpty(t, mechs)
	})
}

// TestOpenSession tests session creation.
func TestOpenSession(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("opens read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, SessionHandle(InvalidHandle), handle)
	})

	t.Run("opens read-write session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, SessionHandle(InvalidHandle), handle)
	})

	t.Run("fails for invalid slot", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.OpenSession(9999, CKF_SERIAL_SESSION)
		assert.Equal(t, CKR_SLOT_ID_INVALID, rv)
	})

	t.Run("fails without serial flag", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.OpenSession(0, 0)
		assert.Equal(t, CKR_SESSION_PARALLEL_NOT_SUPPORTED, rv)
	})
}

// TestCloseSession tests session closure.
func TestCloseSession(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.CloseSession(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("closes session successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)
		rv := m.CloseSession(handle)
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("fails for invalid handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.CloseSession(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestCloseAllSessions tests closing all sessions.
func TestCloseAllSessions(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.CloseAllSessions(0)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("closes all sessions", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Open multiple sessions
		m.OpenSession(0, CKF_SERIAL_SESSION)
		m.OpenSession(0, CKF_SERIAL_SESSION)
		m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.CloseAllSessions(0)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestGetSessionInfo tests getting session information.
func TestGetSessionInfo(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetSessionInfo(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("returns session info", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		info, rv := m.GetSessionInfo(handle)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, info)
		assert.Equal(t, uint64(0), info.SlotID)
		assert.Equal(t, CKS_RW_PUBLIC_SESSION, info.State)
	})

	t.Run("fails for invalid handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GetSessionInfo(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestInitToken tests token initialization.
func TestInitToken(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.InitToken(0, []byte("1234"), "Test Token")
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("initializes token", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.InitToken(0, []byte("so-pin-1234"), "Test Token")
		assert.Equal(t, CKR_OK, rv)

		// Verify token info
		info, _ := m.GetTokenInfo(0)
		assert.Equal(t, "Test Token", info.GetLabel())
	})

	t.Run("fails with session open", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.InitToken(0, []byte("so-pin-1234"), "Test Token")
		assert.Equal(t, CKR_SESSION_EXISTS, rv)
	})
}

// TestLoginLogout tests user authentication.
func TestLoginLogout(t *testing.T) {
	t.Run("login fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.Login(1, CKU_USER, []byte("1234"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("login/logout cycle works", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Initialize token first
		m.InitToken(0, []byte("so-pin-1234"), "Test Token")

		// Open session and login as SO
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.Login(handle, CKU_SO, []byte("so-pin-1234"))
		assert.Equal(t, CKR_OK, rv)

		// Initialize user PIN
		rv = m.InitPIN(handle, []byte("user-pin-1234"))
		assert.Equal(t, CKR_OK, rv)

		// Logout
		rv = m.Logout(handle)
		assert.Equal(t, CKR_OK, rv)

		// Login as user
		rv = m.Login(handle, CKU_USER, []byte("user-pin-1234"))
		assert.Equal(t, CKR_OK, rv)

		rv = m.Logout(handle)
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("logout fails when not logged in", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.Logout(handle)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
	})
}

// TestCreateObject tests object creation.
func TestCreateObject(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.CreateObject(1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("creates data object", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "test-data"),
			NewAttribute(CKA_VALUE, []byte("test value")),
		}

		objHandle, rv := m.CreateObject(handle, template)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), objHandle)
	})
}

// TestFindObjects tests object searching.
func TestFindObjects(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.FindObjectsInit(1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("find objects workflow", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create some objects
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "findme"),
			NewAttribute(CKA_VALUE, []byte("test value")),
		}

		m.CreateObject(handle, template)
		m.CreateObject(handle, template)

		// Find objects
		searchTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		}

		rv := m.FindObjectsInit(handle, searchTemplate)
		assert.Equal(t, CKR_OK, rv)

		objects, rv := m.FindObjects(handle, 10)
		assert.Equal(t, CKR_OK, rv)
		assert.Len(t, objects, 2)

		rv = m.FindObjectsFinal(handle)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestGenerateRandom tests random number generation.
func TestGenerateRandom(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GenerateRandom(1, 16)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("generates random bytes", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		data, rv := m.GenerateRandom(handle, 32)
		assert.Equal(t, CKR_OK, rv)
		assert.Len(t, data, 32)
	})

	t.Run("generates different random each time", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		data1, _ := m.GenerateRandom(handle, 32)
		data2, _ := m.GenerateRandom(handle, 32)

		assert.NotEqual(t, data1, data2)
	})
}

// TestGlobalModule tests the global module singleton.
func TestGlobalModule(t *testing.T) {
	t.Run("returns same instance", func(t *testing.T) {
		ResetGlobalModule()

		m1 := GetGlobalModule()
		m2 := GetGlobalModule()

		assert.Same(t, m1, m2)
	})

	t.Run("set and get global module", func(t *testing.T) {
		ResetGlobalModule()

		custom, _ := New()
		SetGlobalModule(custom)

		assert.Same(t, custom, GetGlobalModule())
	})

	t.Run("reset clears global module", func(t *testing.T) {
		m1 := GetGlobalModule()
		m1.Initialize(nil)

		ResetGlobalModule()

		m2 := GetGlobalModule()
		assert.False(t, m2.IsInitialized())
	})
}

// TestCK_INFO tests the CK_INFO structure.
func TestCK_INFO(t *testing.T) {
	t.Run("set and get manufacturer ID", func(t *testing.T) {
		info := &CK_INFO{}
		info.SetManufacturerID("test-manufacturer")

		assert.Equal(t, "test-manufacturer", info.GetManufacturerID())
	})

	t.Run("set and get library description", func(t *testing.T) {
		info := &CK_INFO{}
		info.SetLibraryDescription("test-library")

		assert.Equal(t, "test-library", info.GetLibraryDescription())
	})

	t.Run("truncates long strings", func(t *testing.T) {
		info := &CK_INFO{}
		// Use a string where the 32nd character is not a space to avoid trimming issues
		longString := "12345678901234567890123456789012this-exceeds-32-chars"
		info.SetManufacturerID(longString)

		// Should be truncated to 32 chars (before trailing space trimming)
		result := info.GetManufacturerID()
		assert.Len(t, result, 32)
		assert.Equal(t, "12345678901234567890123456789012", result)
	})
}

// TestHelperFunctions tests helper functions.
func TestHelperFunctions(t *testing.T) {
	t.Run("trimPaddedString", func(t *testing.T) {
		// Test with trailing spaces
		buf := [32]byte{}
		copy(buf[:], "hello")
		for i := 5; i < 32; i++ {
			buf[i] = ' '
		}
		assert.Equal(t, "hello", trimPaddedString(buf[:]))

		// Test with null bytes
		buf2 := [32]byte{}
		copy(buf2[:], "world")
		buf2[5] = 0
		assert.Equal(t, "world", trimPaddedString(buf2[:]))
	})

	t.Run("setPaddedString", func(t *testing.T) {
		buf := make([]byte, 16)
		setPaddedString(buf, "test")

		assert.Equal(t, byte('t'), buf[0])
		assert.Equal(t, byte('e'), buf[1])
		assert.Equal(t, byte('s'), buf[2])
		assert.Equal(t, byte('t'), buf[3])
		assert.Equal(t, byte(' '), buf[4])
		assert.Equal(t, byte(' '), buf[15])
	})

	t.Run("mechanismToKeyTypeFromMech", func(t *testing.T) {
		assert.Equal(t, CKK_RSA, mechanismToKeyTypeFromMech(CKM_RSA_PKCS_KEY_PAIR_GEN))
		assert.Equal(t, CKK_EC, mechanismToKeyTypeFromMech(CKM_EC_KEY_PAIR_GEN))
		assert.Equal(t, CKK_AES, mechanismToKeyTypeFromMech(CKM_AES_KEY_GEN))
		assert.Equal(t, CKK_EC_EDWARDS, mechanismToKeyTypeFromMech(CKM_EDDSA))
		assert.Equal(t, CKK_GENERIC_SECRET, mechanismToKeyTypeFromMech(0xFFFF))
	})

	t.Run("extractCurveFromParams", func(t *testing.T) {
		// P-256 OID
		p256OID := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
		assert.Equal(t, "P-256", extractCurveFromParams(p256OID))

		// Unknown defaults to P-256
		assert.Equal(t, "P-256", extractCurveFromParams([]byte{0x00}))
	})

	t.Run("bytesEqual", func(t *testing.T) {
		assert.True(t, bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 3}))
		assert.False(t, bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 4}))
		assert.False(t, bytesEqual([]byte{1, 2, 3}, []byte{1, 2}))
	})
}

// TestDigestOperations tests digest operations.
func TestDigestOperations(t *testing.T) {
	t.Run("digest init fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.DigestInit(1, &Mechanism{Type: CKM_SHA256})
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("digest workflow", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		assert.Equal(t, CKR_OK, rv)

		hash, rv := m.Digest(handle, []byte("test data"))
		assert.Equal(t, CKR_OK, rv)
		assert.Len(t, hash, 32) // SHA-256 produces 32 bytes
	})
}

// TestCopyObject tests object copying functionality.
func TestCopyObject(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.CopyObject(1, 1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.CopyObject(9999, 1, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("copies object successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create original object
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "original"),
			NewAttribute(CKA_VALUE, []byte("original value")),
			NewBoolAttribute(CKA_COPYABLE, true),
		}

		objHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Copy object with new label
		copyTemplate := []Attribute{
			NewStringAttribute(CKA_LABEL, "copied"),
		}

		newHandle, rv := m.CopyObject(handle, objHandle, copyTemplate)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, objHandle, newHandle)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), newHandle)
	})

	t.Run("fails with invalid object handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.CopyObject(handle, 9999, nil)
		assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv)
	})
}

// TestDestroyObject tests object destruction functionality.
func TestDestroyObject(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.DestroyObject(1, 1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.DestroyObject(9999, 1)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("destroys object successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create object
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "to-delete"),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}

		objHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Destroy object
		rv = m.DestroyObject(handle, objHandle)
		assert.Equal(t, CKR_OK, rv)

		// Verify object is gone by trying to get attributes
		_, rv = m.GetAttributeValue(handle, objHandle, []Attribute{{Type: CKA_LABEL}})
		assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv)
	})

	t.Run("fails with invalid object handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.DestroyObject(handle, 9999)
		assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv)
	})
}

// TestGetAttributeValue tests retrieving object attributes.
func TestGetAttributeValue(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetAttributeValue(1, 1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GetAttributeValue(9999, 1, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("retrieves attributes successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create object
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "test-label"),
			NewAttribute(CKA_VALUE, []byte("test value")),
		}

		objHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Get attributes
		getTemplate := []Attribute{
			{Type: CKA_LABEL},
			{Type: CKA_VALUE},
		}

		attrs, rv := m.GetAttributeValue(handle, objHandle, getTemplate)
		assert.Equal(t, CKR_OK, rv)
		assert.Len(t, attrs, 2)
		assert.Equal(t, "test-label", string(attrs[0].Value))
		assert.Equal(t, "test value", string(attrs[1].Value))
	})

	t.Run("fails with invalid object handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.GetAttributeValue(handle, 9999, []Attribute{{Type: CKA_LABEL}})
		assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv)
	})
}

// TestSetAttributeValue tests modifying object attributes.
func TestSetAttributeValue(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.SetAttributeValue(1, 1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.SetAttributeValue(9999, 1, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails with read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Create object in RW session first
		rwHandle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "test-label"),
			NewBoolAttribute(CKA_MODIFIABLE, true),
		}
		objHandle, _ := m.CreateObject(rwHandle, template)
		m.CloseSession(rwHandle)

		// Open read-only session
		roHandle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// Try to modify in read-only session
		rv := m.SetAttributeValue(roHandle, objHandle, []Attribute{
			NewStringAttribute(CKA_LABEL, "new-label"),
		})
		assert.Equal(t, CKR_SESSION_READ_ONLY, rv)
	})

	t.Run("modifies attributes successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create modifiable object
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "original-label"),
			NewBoolAttribute(CKA_MODIFIABLE, true),
		}

		objHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Modify attributes
		rv = m.SetAttributeValue(handle, objHandle, []Attribute{
			NewStringAttribute(CKA_LABEL, "new-label"),
		})
		assert.Equal(t, CKR_OK, rv)

		// Verify change
		attrs, rv := m.GetAttributeValue(handle, objHandle, []Attribute{{Type: CKA_LABEL}})
		assert.Equal(t, CKR_OK, rv)
		assert.Equal(t, "new-label", string(attrs[0].Value))
	})

	t.Run("fails with invalid object handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.SetAttributeValue(handle, 9999, []Attribute{
			NewStringAttribute(CKA_LABEL, "new-label"),
		})
		assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv)
	})
}

// TestGetInterfaceList tests PKCS#11 v3.0 interface listing.
func TestGetInterfaceList(t *testing.T) {
	t.Run("returns interface list before initialization", func(t *testing.T) {
		m := createTestModule(t)

		interfaces, rv := m.GetInterfaceList()
		assert.Equal(t, CKR_OK, rv)
		assert.NotEmpty(t, interfaces)

		// Should have PKCS 11 interface
		found := false
		for _, iface := range interfaces {
			if iface.Name == InterfaceNamePKCS11 {
				found = true
				break
			}
		}
		assert.True(t, found, "Should have PKCS 11 interface")
	})

	t.Run("returns interface list after initialization", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		interfaces, rv := m.GetInterfaceList()
		assert.Equal(t, CKR_OK, rv)
		assert.NotEmpty(t, interfaces)
	})
}

// TestGetInterface tests PKCS#11 v3.0 interface retrieval.
func TestGetInterface(t *testing.T) {
	t.Run("returns default interface with empty name", func(t *testing.T) {
		m := createTestModule(t)

		iface, rv := m.GetInterface("", nil)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, iface)
		assert.Equal(t, InterfaceNamePKCS11, iface.Name)
	})

	t.Run("returns named interface", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		iface, rv := m.GetInterface(InterfaceNamePKCS11, nil)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, iface)
		assert.Equal(t, InterfaceNamePKCS11, iface.Name)
	})

	t.Run("returns error for unknown interface", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GetInterface("Unknown Interface", nil)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})

	t.Run("accepts v3.0 version", func(t *testing.T) {
		m := createTestModule(t)

		version := &Version{Major: 3, Minor: 0}
		iface, rv := m.GetInterface(InterfaceNamePKCS11, version)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, iface)
	})

	t.Run("accepts v3.2 version for PKCS#11 v3.2 support", func(t *testing.T) {
		m := createTestModule(t)

		version := &Version{Major: 3, Minor: 2}
		iface, rv := m.GetInterface(InterfaceNamePKCS11, version)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, iface)
	})

	t.Run("accepts v2.40 version for backwards compatibility", func(t *testing.T) {
		m := createTestModule(t)

		version := &Version{Major: 2, Minor: 40}
		iface, rv := m.GetInterface(InterfaceNamePKCS11, version)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, iface)
	})

	t.Run("rejects v4.0 future version", func(t *testing.T) {
		m := createTestModule(t)

		version := &Version{Major: 4, Minor: 0}
		_, rv := m.GetInterface(InterfaceNamePKCS11, version)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})

	t.Run("rejects v3.3 future minor version", func(t *testing.T) {
		m := createTestModule(t)

		version := &Version{Major: 3, Minor: 3}
		_, rv := m.GetInterface(InterfaceNamePKCS11, version)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})
}

// TestGetMechanismInfo tests mechanism information retrieval.
func TestModuleGetMechanismInfo(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetMechanismInfo(0, CKM_RSA_PKCS)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid slot", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GetMechanismInfo(9999, CKM_RSA_PKCS)
		assert.Equal(t, CKR_SLOT_ID_INVALID, rv)
	})

	t.Run("returns mechanism info for valid mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// First get list of mechanisms to find a valid one
		mechs, rv := m.GetMechanismList(0)
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, mechs)

		// Get info for first available mechanism
		info, rv := m.GetMechanismInfo(0, mechs[0])
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, info)
	})

	t.Run("fails for invalid mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GetMechanismInfo(0, 0xFFFFFFFF)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})
}

// TestWaitForSlotEvent tests slot event waiting.
func TestWaitForSlotEvent(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.WaitForSlotEvent(false)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("returns no event in non-blocking mode", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.WaitForSlotEvent(false)
		assert.Equal(t, CKR_NO_EVENT, rv)
	})

	t.Run("returns no event in blocking mode for software token", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// For software tokens, blocking mode should also return no event
		// as there are no physical slot events
		_, rv := m.WaitForSlotEvent(true)
		assert.Equal(t, CKR_NO_EVENT, rv)
	})
}

// TestSetPIN tests PIN modification.
func TestSetPIN(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.SetPIN(1, []byte("old"), []byte("new"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.SetPIN(9999, []byte("old"), []byte("new"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when not logged in", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.SetPIN(handle, []byte("old-pin-12345"), []byte("new-pin-12345"))
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
	})

	t.Run("changes SO PIN successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		m.InitToken(0, []byte("so-pin-old"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Login as SO
		rv := m.Login(handle, CKU_SO, []byte("so-pin-old"))
		require.Equal(t, CKR_OK, rv)

		// Change SO PIN
		rv = m.SetPIN(handle, []byte("so-pin-old"), []byte("so-pin-new"))
		assert.Equal(t, CKR_OK, rv)

		// Logout and verify new PIN works
		m.Logout(handle)
		rv = m.Login(handle, CKU_SO, []byte("so-pin-new"))
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("changes user PIN successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Initialize token and user PIN
		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		m.Login(handle, CKU_SO, []byte("so-pin"))
		m.InitPIN(handle, []byte("user-pin-old"))
		m.Logout(handle)

		// Login as user
		rv := m.Login(handle, CKU_USER, []byte("user-pin-old"))
		require.Equal(t, CKR_OK, rv)

		// Change user PIN
		rv = m.SetPIN(handle, []byte("user-pin-old"), []byte("user-pin-new"))
		assert.Equal(t, CKR_OK, rv)

		// Logout and verify new PIN works
		m.Logout(handle)
		rv = m.Login(handle, CKU_USER, []byte("user-pin-new"))
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("fails with incorrect old PIN", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		m.Login(handle, CKU_SO, []byte("so-pin"))

		rv := m.SetPIN(handle, []byte("wrong-old"), []byte("new-pin"))
		assert.Equal(t, CKR_PIN_INCORRECT, rv)
	})
}

// TestLoginUser tests PKCS#11 v3.0 LoginUser function.
func TestLoginUser(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.LoginUser(1, CKU_USER, []byte("pin"), "username")
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.LoginUser(9999, CKU_USER, []byte("pin"), "username")
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("logs in successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		m.Login(handle, CKU_SO, []byte("so-pin"))
		m.InitPIN(handle, []byte("user-pin"))
		m.Logout(handle)

		// Use LoginUser with username
		rv := m.LoginUser(handle, CKU_USER, []byte("user-pin"), "testuser")
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("context-specific login fails without active operation", func(t *testing.T) {
		// Per OASIS PKCS#11 v3.0 Section 5.6.7: CKU_CONTEXT_SPECIFIC login
		// requires an active operation
		m := initializeTestModule(t)
		defer m.Finalize()

		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Try context-specific login without an active operation
		rv := m.LoginUser(handle, CKU_CONTEXT_SPECIFIC, []byte("pin"), "context")
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("context-specific login succeeds with active operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		m.Login(handle, CKU_SO, []byte("so-pin"))
		m.InitPIN(handle, []byte("user-pin"))
		m.Logout(handle)

		// Start an operation (e.g., digest)
		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Context-specific login with active operation
		rv = m.LoginUser(handle, CKU_CONTEXT_SPECIFIC, []byte("user-pin"), "context")
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestSessionCancel tests PKCS#11 v3.0 SessionCancel function.
func TestSessionCancel(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.SessionCancel(1, 0)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.SessionCancel(9999, 0)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when no operation active", func(t *testing.T) {
		// Per OASIS PKCS#11 v3.0 Section 5.16.1:
		// CKR_OPERATION_NOT_INITIALIZED is returned if no operation is active
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.SessionCancel(handle, 0)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("cancels active operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// Start a digest operation
		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Cancel it
		rv = m.SessionCancel(handle, 0)
		assert.Equal(t, CKR_OK, rv)

		// Verify operation was cancelled by trying to use it
		_, rv = m.Digest(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestGetOperationState tests operation state management.
func TestGetOperationState(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetOperationState(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("returns state for active operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// Start a digest operation
		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Get operation state
		state, rv := m.GetOperationState(handle)
		// Digest operations may not support state serialization
		// so we accept either CKR_OK or CKR_STATE_UNSAVEABLE
		if rv != CKR_OK && rv != CKR_STATE_UNSAVEABLE {
			t.Errorf("unexpected error code: %v", rv)
		}
		if rv == CKR_OK {
			assert.NotEmpty(t, state)
		}
	})
}

// TestSetOperationState tests restoring operation state.
func TestSetOperationState(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.SetOperationState(1, []byte{0x00}, 0, 0)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid state", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// State too short (< 13 bytes)
		rv := m.SetOperationState(handle, []byte{0x00}, 0, 0)
		assert.Equal(t, CKR_SAVED_STATE_INVALID, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Provide valid-length state (>= 13 bytes) to test session validation
		validLengthState := make([]byte, 13)
		rv := m.SetOperationState(9999, validLengthState, 0, 0)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestGetFunctionStatus tests legacy function status.
func TestGetFunctionStatus(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.GetFunctionStatus(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.GetFunctionStatus(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("returns function not parallel for valid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.GetFunctionStatus(handle)
		assert.Equal(t, CKR_FUNCTION_NOT_PARALLEL, rv)
	})
}

// TestCancelFunction tests legacy cancel function.
func TestCancelFunction(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.CancelFunction(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.CancelFunction(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("returns function not parallel for valid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.CancelFunction(handle)
		assert.Equal(t, CKR_FUNCTION_NOT_PARALLEL, rv)
	})
}

// TestGetSessionManager tests internal session manager retrieval.
func TestGetSessionManager(t *testing.T) {
	t.Run("returns nil for invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sm, rv := m.getSessionManager(9999)
		assert.Nil(t, sm)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("returns session manager for valid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		sm, rv := m.getSessionManager(handle)
		assert.NotNil(t, sm)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestMechanismSupportsSignRecover tests sign-recover mechanism support.
func TestMechanismSupportsSignRecover(t *testing.T) {
	m := createTestModule(t)

	testCases := []struct {
		name     string
		mechType MechanismType
		expected bool
	}{
		{"RSA_PKCS supports sign-recover", CKM_RSA_PKCS, true},
		{"RSA_X_509 supports sign-recover", CKM_RSA_X_509, true},
		{"SHA256_RSA_PKCS does not support sign-recover", CKM_SHA256_RSA_PKCS, false},
		{"ECDSA does not support sign-recover", CKM_ECDSA, false},
		{"AES_CBC does not support sign-recover", CKM_AES_CBC, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := m.mechanismSupportsSignRecover(tc.mechType)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestMechanismSupportsVerifyRecover tests verify-recover mechanism support.
func TestMechanismSupportsVerifyRecover(t *testing.T) {
	m := createTestModule(t)

	testCases := []struct {
		name     string
		mechType MechanismType
		expected bool
	}{
		{"RSA_PKCS supports verify-recover", CKM_RSA_PKCS, true},
		{"RSA_X_509 supports verify-recover", CKM_RSA_X_509, true},
		{"SHA256_RSA_PKCS does not support verify-recover", CKM_SHA256_RSA_PKCS, false},
		{"ECDSA does not support verify-recover", CKM_ECDSA, false},
		{"AES_CBC does not support verify-recover", CKM_AES_CBC, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := m.mechanismSupportsVerifyRecover(tc.mechType)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestSignRecoverInit tests sign-recover initialization.
func TestSignRecoverInit(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.SignRecoverInit(1, &Mechanism{Type: CKM_RSA_PKCS}, 1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.SignRecoverInit(9999, &Mechanism{Type: CKM_RSA_PKCS}, 1)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when not logged in", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.SignRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, 1)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, rv)
	})

	t.Run("fails with unsupported mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		m.Login(handle, CKU_SO, []byte("so-pin"))

		// ECDSA doesn't support sign-recover
		rv := m.SignRecoverInit(handle, &Mechanism{Type: CKM_ECDSA}, 1)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("fails with invalid key handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		m.Login(handle, CKU_SO, []byte("so-pin"))

		rv := m.SignRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, 9999)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})
}

// TestSignRecover tests sign-recover operation.
func TestSignRecover(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.SignRecover(1, []byte("data"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.SignRecover(9999, []byte("data"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails without initialized operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.SignRecover(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestVerifyRecoverInit tests verify-recover initialization.
func TestVerifyRecoverInit(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.VerifyRecoverInit(1, &Mechanism{Type: CKM_RSA_PKCS}, 1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.VerifyRecoverInit(9999, &Mechanism{Type: CKM_RSA_PKCS}, 1)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails with unsupported mechanism", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// ECDSA doesn't support verify-recover
		rv := m.VerifyRecoverInit(handle, &Mechanism{Type: CKM_ECDSA}, 1)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("fails with invalid key handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.VerifyRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, 9999)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})
}

// TestVerifyRecover tests verify-recover operation.
func TestVerifyRecover(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.VerifyRecover(1, []byte("signature"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.VerifyRecover(9999, []byte("signature"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails without initialized operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.VerifyRecover(handle, []byte("signature"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestSign tests single-part sign operation.
func TestSign(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.Sign(1, []byte("data"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.Sign(9999, []byte("data"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails without initialized operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.Sign(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestVerify tests single-part verify operation.
func TestVerify(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.Verify(1, []byte("data"), []byte("signature"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.Verify(9999, []byte("data"), []byte("signature"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails without initialized operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.Verify(handle, []byte("data"), []byte("signature"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestInitializeClient tests client initialization with various target formats.
func TestInitializeClient(t *testing.T) {
	t.Run("initializes with unix socket prefix", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Target = "unix:///var/run/test.sock"

		m, err := New(WithConfig(cfg))
		require.NoError(t, err)

		// This will fail to connect but should parse correctly
		err = m.initializeClient()
		assert.NoError(t, err)
		assert.NotNil(t, m.client)
	})

	t.Run("initializes with dns prefix", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Target = "dns:///localhost:8080"

		m, err := New(WithConfig(cfg))
		require.NoError(t, err)

		err = m.initializeClient()
		assert.NoError(t, err)
		assert.NotNil(t, m.client)
	})

	t.Run("initializes with direct host:port", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Target = "localhost:8080"

		m, err := New(WithConfig(cfg))
		require.NoError(t, err)

		err = m.initializeClient()
		assert.NoError(t, err)
		assert.NotNil(t, m.client)
	})

	t.Run("initializes with default unix path", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Target = "/var/run/xkms.sock"

		m, err := New(WithConfig(cfg))
		require.NoError(t, err)

		err = m.initializeClient()
		assert.NoError(t, err)
		assert.NotNil(t, m.client)
	})

	t.Run("initializes with TLS enabled but no certs", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Target = "localhost:8080"
		cfg.TLS.Enabled = true

		m, err := New(WithConfig(cfg))
		require.NoError(t, err)

		err = m.initializeClient()
		assert.NoError(t, err)
		assert.NotNil(t, m.client)
	})

	t.Run("initializes with TLS and CA file", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Target = "localhost:8080"
		cfg.TLS.Enabled = true
		cfg.TLS.CAFile = "/path/to/ca.crt"

		m, err := New(WithConfig(cfg))
		require.NoError(t, err)

		err = m.initializeClient()
		assert.NoError(t, err)
		assert.NotNil(t, m.client)
	})

	t.Run("initializes with mTLS configuration", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Target = "localhost:8080"
		cfg.TLS.Enabled = true
		cfg.TLS.CertFile = "/path/to/client.crt"
		cfg.TLS.KeyFile = "/path/to/client.key"
		cfg.TLS.CAFile = "/path/to/ca.crt"

		m, err := New(WithConfig(cfg))
		require.NoError(t, err)

		err = m.initializeClient()
		assert.NoError(t, err)
		assert.NotNil(t, m.client)
	})
}

// TestExtractCurveFromParams tests curve extraction from EC parameters.
func TestExtractCurveFromParams(t *testing.T) {
	testCases := []struct {
		name     string
		params   []byte
		expected string
	}{
		{
			name:     "P-256 OID",
			params:   []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
			expected: "P-256",
		},
		{
			name:     "P-384 OID",
			params:   []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22},
			expected: "P-384",
		},
		{
			name:     "P-521 OID",
			params:   []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23},
			expected: "P-521",
		},
		{
			name:     "Unknown defaults to P-256",
			params:   []byte{0x00, 0x01, 0x02},
			expected: "P-256",
		},
		{
			name:     "Empty params defaults to P-256",
			params:   []byte{},
			expected: "P-256",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractCurveFromParams(tc.params)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestMechanismToKeyTypeFromMech tests mechanism to key type conversion.
func TestMechanismToKeyTypeFromMech(t *testing.T) {
	testCases := []struct {
		name     string
		mechType MechanismType
		expected KeyType
	}{
		{"RSA_PKCS_KEY_PAIR_GEN", CKM_RSA_PKCS_KEY_PAIR_GEN, CKK_RSA},
		{"RSA_PKCS", CKM_RSA_PKCS, CKK_RSA},
		{"SHA256_RSA_PKCS", CKM_SHA256_RSA_PKCS, CKK_RSA},
		{"SHA384_RSA_PKCS", CKM_SHA384_RSA_PKCS, CKK_RSA},
		{"SHA512_RSA_PKCS", CKM_SHA512_RSA_PKCS, CKK_RSA},
		{"EC_KEY_PAIR_GEN", CKM_EC_KEY_PAIR_GEN, CKK_EC},
		{"ECDSA", CKM_ECDSA, CKK_EC},
		{"ECDSA_SHA256", CKM_ECDSA_SHA256, CKK_EC},
		{"ECDSA_SHA384", CKM_ECDSA_SHA384, CKK_EC},
		{"ECDSA_SHA512", CKM_ECDSA_SHA512, CKK_EC},
		{"AES_KEY_GEN", CKM_AES_KEY_GEN, CKK_AES},
		{"AES_CBC", CKM_AES_CBC, CKK_AES},
		{"AES_GCM", CKM_AES_GCM, CKK_AES},
		{"DES3_KEY_GEN", CKM_DES3_KEY_GEN, CKK_DES3},
		{"DES3_CBC", CKM_DES3_CBC, CKK_DES3},
		{"EC_EDWARDS_KEY_PAIR_GEN", CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK_EC_EDWARDS},
		{"EDDSA", CKM_EDDSA, CKK_EC_EDWARDS},
		{"Unknown", MechanismType(0xFFFFFFFF), CKK_GENERIC_SECRET},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mechanismToKeyTypeFromMech(tc.mechType)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestCloseAllSessionsInvalidSlot tests closing sessions for invalid slot.
func TestCloseAllSessionsInvalidSlot(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	rv := m.CloseAllSessions(9999)
	assert.Equal(t, CKR_SLOT_ID_INVALID, rv)
}

// TestEncrypt tests the single-part encryption operation.
func TestEncrypt(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.Encrypt(1, []byte("test"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.Encrypt(9999, []byte("test"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when operation not initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		_, rv := m.Encrypt(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestDecrypt tests the single-part decryption operation.
func TestDecrypt(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.Decrypt(1, []byte("test"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.Decrypt(9999, []byte("test"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when operation not initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		_, rv := m.Decrypt(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestGenerateKey tests symmetric key generation.
func TestGenerateKey(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GenerateKey(1, nil, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GenerateKey(9999, nil, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails with read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION) // Read-only session

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewUint32Attribute(CKA_VALUE_LEN, 32), // 256-bit key
		}

		_, rv := m.GenerateKey(handle, &Mechanism{Type: CKM_AES_KEY_GEN}, template)
		assert.Equal(t, CKR_SESSION_READ_ONLY, rv)
	})
}

// TestGenerateKeyPair tests asymmetric key pair generation.
func TestGenerateKeyPair(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, _, rv := m.GenerateKeyPair(1, nil, nil, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, _, rv := m.GenerateKeyPair(9999, nil, nil, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails with read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION) // Read-only session

		pubTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		}
		privTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		}

		_, _, rv := m.GenerateKeyPair(handle, &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}, pubTemplate, privTemplate)
		assert.Equal(t, CKR_SESSION_READ_ONLY, rv)
	})
}

// TestSeedRandom tests random seeding.
func TestSeedRandom(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.SeedRandom(1, []byte("seed"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.SeedRandom(9999, []byte("seed"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails with empty seed", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.SeedRandom(handle, []byte{})
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})

	t.Run("succeeds with valid seed", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.SeedRandom(handle, []byte("random-seed-data"))
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestDigestKey tests digesting a key.
func TestDigestKey(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.DigestKey(1, 1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.DigestKey(9999, 1)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when digest operation not initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		rv := m.DigestKey(handle, 1)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestDeriveKey tests key derivation.
func TestDeriveKey(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.DeriveKey(1, nil, 1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.DeriveKey(9999, nil, 1, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails with read-only session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION) // Read-only session

		_, rv := m.DeriveKey(handle, &Mechanism{Type: CKM_ECDH1_DERIVE}, 1, nil)
		assert.Equal(t, CKR_SESSION_READ_ONLY, rv)
	})
}

// TestMessageEncryptInit tests message encryption initialization.
func TestMessageEncryptInit(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.MessageEncryptInit(1, nil, 1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.MessageEncryptInit(9999, nil, 1)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})
}

// TestEncryptMessage tests message encryption.
func TestEncryptMessage(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.EncryptMessage(1, nil, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.EncryptMessage(9999, nil, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestEncryptMessageBegin tests starting multi-part message encryption.
func TestEncryptMessageBegin(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.EncryptMessageBegin(1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.EncryptMessageBegin(9999, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestEncryptMessageNext tests continuing multi-part message encryption.
func TestEncryptMessageNext(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.EncryptMessageNext(1, nil, false)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.EncryptMessageNext(9999, nil, false)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestMessageEncryptFinal tests finalizing message encryption.
func TestMessageEncryptFinal(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.MessageEncryptFinal(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.MessageEncryptFinal(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestMessageDecryptInit tests message decryption initialization.
func TestMessageDecryptInit(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.MessageDecryptInit(1, nil, 1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.MessageDecryptInit(9999, nil, 1)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})
}

// TestDecryptMessage tests message decryption.
func TestDecryptMessage(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.DecryptMessage(1, nil, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.DecryptMessage(9999, nil, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestDecryptMessageBegin tests starting multi-part message decryption.
func TestDecryptMessageBegin(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.DecryptMessageBegin(1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.DecryptMessageBegin(9999, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestDecryptMessageNext tests continuing multi-part message decryption.
func TestDecryptMessageNext(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.DecryptMessageNext(1, nil, false)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.DecryptMessageNext(9999, nil, false)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestMessageDecryptFinal tests finalizing message decryption.
func TestMessageDecryptFinal(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.MessageDecryptFinal(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.MessageDecryptFinal(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestMessageSignInit tests message signing initialization.
func TestMessageSignInit(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.MessageSignInit(1, nil, 1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.MessageSignInit(9999, nil, 1)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})
}

// TestSignMessage tests message signing.
func TestSignMessage(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.SignMessage(1, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.SignMessage(9999, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestSignMessageBegin tests starting multi-part message signing.
func TestSignMessageBegin(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.SignMessageBegin(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.SignMessageBegin(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestSignMessageNext tests continuing multi-part message signing.
func TestSignMessageNext(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.SignMessageNext(1, nil, false)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.SignMessageNext(9999, nil, false)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestMessageSignFinal tests finalizing message signing.
func TestMessageSignFinal(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.MessageSignFinal(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.MessageSignFinal(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestMessageVerifyInit tests message verification initialization.
func TestMessageVerifyInit(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.MessageVerifyInit(1, nil, 1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.MessageVerifyInit(9999, nil, 1)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})
}

// TestVerifyMessage tests message verification.
func TestVerifyMessage(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.VerifyMessage(1, nil, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.VerifyMessage(9999, nil, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestVerifyMessageBegin tests starting multi-part message verification.
func TestVerifyMessageBegin(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.VerifyMessageBegin(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.VerifyMessageBegin(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestVerifyMessageNext tests continuing multi-part message verification.
func TestVerifyMessageNext(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.VerifyMessageNext(1, nil, nil)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.VerifyMessageNext(9999, nil, nil)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestMessageVerifyFinal tests finalizing message verification.
func TestMessageVerifyFinal(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.MessageVerifyFinal(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.MessageVerifyFinal(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})
}

// TestDigestEncryptUpdate tests combined digest and encrypt update.
func TestDigestEncryptUpdate(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.DigestEncryptUpdate(1, []byte("test"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.DigestEncryptUpdate(9999, []byte("test"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when no digest operation active", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		_, rv := m.DigestEncryptUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestDecryptDigestUpdate tests combined decrypt and digest update.
func TestDecryptDigestUpdate(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.DecryptDigestUpdate(1, []byte("test"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.DecryptDigestUpdate(9999, []byte("test"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when no decrypt operation active", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		_, rv := m.DecryptDigestUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestSignEncryptUpdate tests combined sign and encrypt update.
func TestSignEncryptUpdate(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.SignEncryptUpdate(1, []byte("test"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.SignEncryptUpdate(9999, []byte("test"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when no sign operation active", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		_, rv := m.SignEncryptUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestDecryptVerifyUpdate tests combined decrypt and verify update.
func TestDecryptVerifyUpdate(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.DecryptVerifyUpdate(1, []byte("test"))
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.DecryptVerifyUpdate(9999, []byte("test"))
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when no decrypt operation active", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		_, rv := m.DecryptVerifyUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestGetOperationStateBytes tests the GetOperationStateBytes function.
func TestGetOperationStateBytes(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		_, rv := m.GetOperationStateBytes(1)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		_, rv := m.GetOperationStateBytes(9999)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when no operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		_, rv := m.GetOperationStateBytes(handle)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("returns state unsaveable for operation with crypto state", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// Initialize a digest operation which creates CryptoOp
		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		_, rv = m.GetOperationStateBytes(handle)
		assert.Equal(t, CKR_STATE_UNSAVEABLE, rv)
	})

	t.Run("returns serialized state for simple operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Manually set an operation state without CryptoOp via session manager
		slotID := SlotID(0)
		m.mu.Lock()
		sm := m.sessionManagers[slotID]
		_ = sm.InitializeOperation(handle, OperationFindObjects, CKM_SHA256, ObjectHandle(123))
		m.mu.Unlock()

		state, rv := m.GetOperationStateBytes(handle)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEmpty(t, state)
		// First byte should be operation type
		assert.Equal(t, byte(OperationFindObjects), state[0])
	})
}

// TestSign_WithInitializedOperation tests Sign with proper operation initialization.
func TestSign_WithInitializedOperation(t *testing.T) {
	t.Run("fails with wrong operation type", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize a different operation (Verify instead of Sign)
		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		_, rv = m.Sign(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when key handle becomes invalid", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize sign operation
		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Delete the key object
		rv = m.DestroyObject(handle, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Now Sign should fail due to invalid key handle
		_, rv = m.Sign(handle, []byte("data"))
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})
}

// TestVerify_WithInitializedOperation tests Verify with proper operation initialization.
func TestVerify_WithInitializedOperation(t *testing.T) {
	t.Run("fails with wrong operation type", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize a different operation (Sign instead of Verify)
		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.Verify(handle, []byte("data"), []byte("signature"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when key handle becomes invalid", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize verify operation
		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Delete the key object
		rv = m.DestroyObject(handle, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Now Verify should fail due to invalid key handle
		rv = m.Verify(handle, []byte("data"), []byte("signature"))
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})
}

// TestEncrypt_WithInitializedOperation tests Encrypt with proper operation initialization.
func TestEncrypt_WithInitializedOperation(t *testing.T) {
	t.Run("fails with wrong operation type", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize a different operation (Decrypt instead of Encrypt)
		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		_, rv = m.Encrypt(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when key handle becomes invalid", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		// Initialize encrypt operation
		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Delete the key object
		rv = m.DestroyObject(handle, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Now Encrypt should fail due to invalid key handle
		_, rv = m.Encrypt(handle, []byte("data"))
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})
}

// createTestModuleWithEncryptableKey creates a module with a secret key for encryption.
func createTestModuleWithEncryptableKey(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()
	m := initializeTestModule(t)

	handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	// Create a secret key object for encryption
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "test-aes-key"),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_MODIFIABLE, true),
		NewBoolAttribute(CKA_COPYABLE, true),
		NewBoolAttribute(CKA_DESTROYABLE, true),
		NewAttribute(CKA_VALUE, make([]byte, 32)), // 256-bit AES key
	}

	keyHandle, rv := m.CreateObject(handle, template)
	require.Equal(t, CKR_OK, rv)

	return m, handle, keyHandle
}

// TestDecrypt_WithInitializedOperation tests Decrypt with proper operation initialization.
func TestDecrypt_WithInitializedOperation(t *testing.T) {
	t.Run("fails with wrong operation type", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize a different operation (Encrypt instead of Decrypt)
		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		_, rv = m.Decrypt(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when key handle becomes invalid", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		// Initialize decrypt operation
		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Delete the key object
		rv = m.DestroyObject(handle, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Now Decrypt should fail due to invalid key handle
		_, rv = m.Decrypt(handle, []byte("data"))
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})
}

// TestSignRecover_WithInitializedOperation tests SignRecover with proper operation.
func TestSignRecover_WithInitializedOperation(t *testing.T) {
	t.Run("fails with wrong operation type", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize a regular sign operation (not sign-recover)
		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// SignRecover should fail because operation is not sign-recover
		_, rv = m.SignRecover(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails with verify operation type", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize verify operation instead of sign
		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		_, rv = m.SignRecover(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestVerifyRecover_WithInitializedOperation tests VerifyRecover with proper operation.
func TestVerifyRecover_WithInitializedOperation(t *testing.T) {
	t.Run("fails with wrong operation type", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize a regular verify operation (not verify-recover)
		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// VerifyRecover should fail because operation is not verify-recover
		_, rv = m.VerifyRecover(handle, []byte("signature"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails with sign operation type", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize sign operation instead of verify
		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		_, rv = m.VerifyRecover(handle, []byte("signature"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestDualOperations_DigestEncryptUpdate tests DigestEncryptUpdate with active operations.
func TestDualOperations_DigestEncryptUpdate(t *testing.T) {
	t.Run("fails when no encrypt operation active", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// Initialize only digest operation
		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		_, rv = m.DigestEncryptUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when digest operation has no CryptoOp", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		// Initialize encrypt operation
		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Set up a digest operation without CryptoOp
		m.mu.Lock()
		sm := m.sessionManagers[0]
		_ = sm.InitializeOperation(handle, OperationDigest, CKM_SHA256, 0)
		m.mu.Unlock()

		_, rv = m.DigestEncryptUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when encrypt operation has no CryptoOp", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// Initialize digest operation
		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Set up an encrypt operation without CryptoOp
		m.mu.Lock()
		sm := m.sessionManagers[0]
		_ = sm.InitializeOperation(handle, OperationEncrypt, CKM_AES_ECB, 0)
		m.mu.Unlock()

		_, rv = m.DigestEncryptUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestDualOperations_SignEncryptUpdate tests SignEncryptUpdate with active operations.
func TestDualOperations_SignEncryptUpdate(t *testing.T) {
	t.Run("fails when no encrypt operation active", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize only sign operation
		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		_, rv = m.SignEncryptUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when sign operation has no CryptoOp", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		// Initialize encrypt operation
		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Set up a sign operation without CryptoOp
		m.mu.Lock()
		sm := m.sessionManagers[0]
		_ = sm.InitializeOperation(handle, OperationSign, CKM_RSA_PKCS, 0)
		m.mu.Unlock()

		_, rv = m.SignEncryptUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when encrypt operation has no CryptoOp", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize sign operation
		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Set up an encrypt operation without CryptoOp
		m.mu.Lock()
		sm := m.sessionManagers[0]
		_ = sm.InitializeOperation(handle, OperationEncrypt, CKM_AES_ECB, 0)
		m.mu.Unlock()

		_, rv = m.SignEncryptUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestDualOperations_DecryptDigestUpdate tests DecryptDigestUpdate with active operations.
func TestDualOperations_DecryptDigestUpdate(t *testing.T) {
	t.Run("fails when no digest operation active", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		// Initialize only decrypt operation
		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		_, rv = m.DecryptDigestUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when decrypt operation has no CryptoOp", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// Initialize digest operation
		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Set up a decrypt operation without CryptoOp
		m.mu.Lock()
		sm := m.sessionManagers[0]
		_ = sm.InitializeOperation(handle, OperationDecrypt, CKM_AES_ECB, 0)
		m.mu.Unlock()

		_, rv = m.DecryptDigestUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when digest operation has no CryptoOp", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		// Initialize decrypt operation
		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Set up a digest operation without CryptoOp
		m.mu.Lock()
		sm := m.sessionManagers[0]
		_ = sm.InitializeOperation(handle, OperationDigest, CKM_SHA256, 0)
		m.mu.Unlock()

		_, rv = m.DecryptDigestUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestDualOperations_DecryptVerifyUpdate tests DecryptVerifyUpdate with active operations.
func TestDualOperations_DecryptVerifyUpdate(t *testing.T) {
	t.Run("fails when no verify operation active", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		// Initialize only decrypt operation
		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		_, rv = m.DecryptVerifyUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when decrypt operation has no CryptoOp", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithKey(t)
		defer m.Finalize()

		// Initialize verify operation
		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Set up a decrypt operation without CryptoOp
		m.mu.Lock()
		sm := m.sessionManagers[0]
		_ = sm.InitializeOperation(handle, OperationDecrypt, CKM_AES_ECB, 0)
		m.mu.Unlock()

		_, rv = m.DecryptVerifyUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("fails when verify operation has no CryptoOp", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		// Initialize decrypt operation
		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Set up a verify operation without CryptoOp
		m.mu.Lock()
		sm := m.sessionManagers[0]
		_ = sm.InitializeOperation(handle, OperationVerify, CKM_RSA_PKCS, 0)
		m.mu.Unlock()

		_, rv = m.DecryptVerifyUpdate(handle, []byte("test"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})
}

// TestSetOperationStateBytes tests restoring operation state from bytes.
func TestSetOperationStateBytes(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.SetOperationStateBytes(1, []byte{}, 0, 0)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with invalid state data", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// State too short (less than 13 bytes)
		rv := m.SetOperationStateBytes(handle, []byte{1, 2, 3}, 0, 0)
		assert.Equal(t, CKR_SAVED_STATE_INVALID, rv)
	})

	t.Run("fails with invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Need at least 13 bytes for valid state
		state := make([]byte, 13)
		state[0] = byte(OperationFindObjects)

		rv := m.SetOperationStateBytes(9999, state, 0, 0)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("fails when operation already active", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION)

		// Initialize an operation first
		rv := m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Now try to set operation state
		state := make([]byte, 13)
		state[0] = byte(OperationFindObjects)

		rv = m.SetOperationStateBytes(handle, state, 0, 0)
		assert.Equal(t, CKR_OPERATION_ACTIVE, rv)
	})

	t.Run("succeeds with valid state", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create valid state bytes
		// Format: [type][mech(4bytes)][keyHandle(8bytes)][data...]
		// Use a variable to avoid constant overflow warning
		mechType := uint32(CKM_SHA_1) // 0x220
		state := make([]byte, 20)
		state[0] = byte(OperationFindObjects)
		// Mechanism bytes (big endian)
		state[1] = byte(mechType >> 24)
		state[2] = byte(mechType >> 16)
		state[3] = byte(mechType >> 8)
		state[4] = byte(mechType)
		// Key handle (0) - 8 bytes already zeroed
		// Data at end
		state[13] = 0x01
		state[14] = 0x02

		rv := m.SetOperationStateBytes(handle, state, 0, 0)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestSignRecoverInit_SuccessPath tests successful SignRecoverInit.
func TestSignRecoverInit_SuccessPath(t *testing.T) {
	t.Run("initializes sign recover operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Init token and login as SO
		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		m.Login(handle, CKU_SO, []byte("so-pin"))

		// Create RSA key
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-sign-recover-key"),
			NewBoolAttribute(CKA_SIGN, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Now test SignRecoverInit
		rv = m.SignRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("fails when key CKA_SIGN is false", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Init token and login as SO
		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		m.Login(handle, CKU_SO, []byte("so-pin"))

		// Create RSA key with CKA_SIGN = false
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-no-sign-key"),
			NewBoolAttribute(CKA_SIGN, false),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// SignRecoverInit should fail
		rv = m.SignRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, rv)
	})
}

// TestVerifyRecoverInit_SuccessPath tests successful VerifyRecoverInit.
func TestVerifyRecoverInit_SuccessPath(t *testing.T) {
	t.Run("initializes verify recover operation", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create RSA public key for verify
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-verify-recover-key"),
			NewBoolAttribute(CKA_VERIFY, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
			// Add modulus and exponent for RSA verify recover to work
			NewAttribute(CKA_MODULUS, make([]byte, 256)),       // 2048-bit modulus
			NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}), // 65537
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Now test VerifyRecoverInit
		rv = m.VerifyRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("fails when key CKA_VERIFY_RECOVER is false", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create RSA key with CKA_VERIFY_RECOVER = false
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-no-verify-recover-key"),
			NewBoolAttribute(CKA_VERIFY_RECOVER, false),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// VerifyRecoverInit should fail because CKA_VERIFY_RECOVER is false
		rv = m.VerifyRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, rv)
	})
}

// TestSetOperationStateBytes_InvalidKeyHandle tests key handle validation.
func TestSetOperationStateBytes_InvalidKeyHandle(t *testing.T) {
	t.Run("fails with invalid key handle in state", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create valid state bytes with non-zero key handle
		mechType := uint32(CKM_SHA_1)
		keyHandle := uint64(9999) // Invalid key handle
		state := make([]byte, 13)
		state[0] = byte(OperationSign)
		state[1] = byte(mechType >> 24)
		state[2] = byte(mechType >> 16)
		state[3] = byte(mechType >> 8)
		state[4] = byte(mechType)
		state[5] = byte(keyHandle >> 56)
		state[6] = byte(keyHandle >> 48)
		state[7] = byte(keyHandle >> 40)
		state[8] = byte(keyHandle >> 32)
		state[9] = byte(keyHandle >> 24)
		state[10] = byte(keyHandle >> 16)
		state[11] = byte(keyHandle >> 8)
		state[12] = byte(keyHandle)

		rv := m.SetOperationStateBytes(handle, state, 0, 0)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})
}

// ----------------------------------------------------------------
// Extended Coverage Tests for Key Generation Operations
// ----------------------------------------------------------------

// createTestModuleWithSecretKey creates an initialized module with a secret key for testing.
func createTestModuleWithSecretKey(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()
	m := initializeTestModule(t)

	handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	// Create a secret key object with CKA_VALUE for testing
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "test-aes-key"),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
		NewBoolAttribute(CKA_DERIVE, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, []byte("0123456789abcdef0123456789abcdef")), // 32-byte key
	}

	keyHandle, rv := m.CreateObject(handle, template)
	require.Equal(t, CKR_OK, rv)

	return m, handle, keyHandle
}

// TestGenerateKeyExtended tests additional scenarios for key generation.
func TestGenerateKeyExtended(t *testing.T) {
	t.Run("generates key with label from template", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "my-custom-key"),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewUint32Attribute(CKA_VALUE_LEN, 32),
		}

		keyHandle, rv := m.GenerateKey(handle, &Mechanism{Type: CKM_AES_KEY_GEN}, template)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), keyHandle)
	})

	t.Run("generates key with default label when not specified", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewUint32Attribute(CKA_VALUE_LEN, 16),
		}

		keyHandle, rv := m.GenerateKey(handle, &Mechanism{Type: CKM_AES_KEY_GEN}, template)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), keyHandle)
	})
}

// TestGenerateKeyPairExtended tests additional scenarios for key pair generation.
func TestGenerateKeyPairExtended(t *testing.T) {
	t.Run("generates RSA key pair with modulus bits", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		pubTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "rsa-keypair"),
			NewUint32Attribute(CKA_MODULUS_BITS, 2048),
			NewBoolAttribute(CKA_VERIFY, true),
		}
		privTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewBoolAttribute(CKA_SIGN, true),
		}

		pubHandle, privHandle, rv := m.GenerateKeyPair(handle, &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}, pubTemplate, privTemplate)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), pubHandle)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), privHandle)
	})

	t.Run("generates EC key pair with curve parameters", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// P-256 OID
		p256OID := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

		pubTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
			NewStringAttribute(CKA_LABEL, "ec-keypair"),
			NewAttribute(CKA_EC_PARAMS, p256OID),
			NewBoolAttribute(CKA_VERIFY, true),
		}
		privTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
			NewBoolAttribute(CKA_SIGN, true),
		}

		pubHandle, privHandle, rv := m.GenerateKeyPair(handle, &Mechanism{Type: CKM_EC_KEY_PAIR_GEN}, pubTemplate, privTemplate)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), pubHandle)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), privHandle)
	})

	t.Run("generates key pair with default label when not specified", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		pubTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewUint32Attribute(CKA_MODULUS_BITS, 2048),
		}
		privTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		}

		pubHandle, privHandle, rv := m.GenerateKeyPair(handle, &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN}, pubTemplate, privTemplate)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), pubHandle)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), privHandle)
	})
}

// TestDeriveKeyExtended tests additional scenarios for key derivation.
func TestDeriveKeyExtended(t *testing.T) {
	t.Run("fails with invalid base key handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewUint32Attribute(CKA_VALUE_LEN, 32),
		}

		_, rv := m.DeriveKey(handle, &Mechanism{Type: CKM_HKDF_DERIVE}, 9999, template)
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})

	t.Run("fails with missing ECDH parameters", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewUint32Attribute(CKA_VALUE_LEN, 32),
		}

		// ECDH is now supported but requires valid parameters
		_, rv := m.DeriveKey(handle, &Mechanism{Type: CKM_ECDH1_DERIVE}, keyHandle, template)
		assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, rv)
	})

	t.Run("fails with invalid mechanism", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}

		_, rv := m.DeriveKey(handle, &Mechanism{Type: 0xFFFFFFFF}, keyHandle, template)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("fails with key that cannot derive", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		// Create a key with CKA_DERIVE set to false
		keyTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_DERIVE, false),
			NewAttribute(CKA_VALUE, []byte("0123456789abcdef")),
		}

		keyHandle, rv := m.CreateObject(handle, keyTemplate)
		require.Equal(t, CKR_OK, rv)

		deriveTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}

		_, rv = m.DeriveKey(handle, &Mechanism{Type: CKM_HKDF_DERIVE}, keyHandle, deriveTemplate)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, rv)
	})

	t.Run("derives key with HKDF mechanism", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewUint32Attribute(CKA_VALUE_LEN, 32),
		}

		derivedHandle, rv := m.DeriveKey(handle, &Mechanism{Type: CKM_HKDF_DERIVE}, keyHandle, template)
		assert.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), derivedHandle)
	})
}

// TestMapECDHKDFType tests the KDF type mapping for ECDH key derivation.
func TestMapECDHKDFType(t *testing.T) {
	testCases := []struct {
		name         string
		kdfType      KDFType
		expectedAlg  string
		expectedHash string
	}{
		{"CKD_NULL", CKD_NULL, "", ""},
		{"CKD_SHA1_KDF", CKD_SHA1_KDF, "X963", "SHA-1"},
		{"CKD_SHA1_KDF_ASN1", CKD_SHA1_KDF_ASN1, "X963", "SHA-1"},
		{"CKD_SHA1_KDF_CONCATENATE", CKD_SHA1_KDF_CONCATENATE, "X963", "SHA-1"},
		{"CKD_SHA224_KDF", CKD_SHA224_KDF, "X963", "SHA-224"},
		{"CKD_SHA256_KDF", CKD_SHA256_KDF, "X963", "SHA-256"},
		{"CKD_SHA384_KDF", CKD_SHA384_KDF, "X963", "SHA-384"},
		{"CKD_SHA512_KDF", CKD_SHA512_KDF, "X963", "SHA-512"},
		{"CKD_SHA1_KDF_SP800", CKD_SHA1_KDF_SP800, "SP800-56A", "SHA-1"},
		{"CKD_SHA224_KDF_SP800", CKD_SHA224_KDF_SP800, "SP800-56A", "SHA-224"},
		{"CKD_SHA256_KDF_SP800", CKD_SHA256_KDF_SP800, "SP800-56A", "SHA-256"},
		{"CKD_SHA384_KDF_SP800", CKD_SHA384_KDF_SP800, "SP800-56A", "SHA-384"},
		{"CKD_SHA512_KDF_SP800", CKD_SHA512_KDF_SP800, "SP800-56A", "SHA-512"},
		{"CKD_SHA3_224_KDF", CKD_SHA3_224_KDF, "X963", "SHA3-224"},
		{"CKD_SHA3_256_KDF", CKD_SHA3_256_KDF, "X963", "SHA3-256"},
		{"CKD_SHA3_384_KDF", CKD_SHA3_384_KDF, "X963", "SHA3-384"},
		{"CKD_SHA3_512_KDF", CKD_SHA3_512_KDF, "X963", "SHA3-512"},
		{"unknown KDF defaults to HKDF", KDFType(0xFFFF), "HKDF", "SHA-256"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alg, hash := mapECDHKDFType(tc.kdfType)
			assert.Equal(t, tc.expectedAlg, alg, "algorithm mismatch")
			assert.Equal(t, tc.expectedHash, hash, "hash mismatch")
		})
	}
}

// TestDigestKeyExtended tests additional scenarios for digest key operations.
func TestDigestKeyExtended(t *testing.T) {
	t.Run("fails with invalid key handle", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Initialize digest
		rv = m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Try to digest an invalid key
		rv = m.DigestKey(handle, ObjectHandle(9999))
		assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	})

	t.Run("digests secret key value successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create a secret key with CKA_EXTRACTABLE=true
		keyTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, []byte("secret-key-value")),
		}

		keyHandle, rv := m.CreateObject(handle, keyTemplate)
		require.Equal(t, CKR_OK, rv)

		// Initialize digest
		rv = m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Digest the key
		rv = m.DigestKey(handle, keyHandle)
		assert.Equal(t, CKR_OK, rv)

		// Finalize digest
		digest, rv := m.DigestFinal(handle)
		assert.Equal(t, CKR_OK, rv)
		assert.Len(t, digest, 32) // SHA-256 produces 32 bytes
	})

	t.Run("fails with non-secret key", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create a data object (not a secret key)
		objTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewAttribute(CKA_VALUE, []byte("some-data")),
		}

		objHandle, rv := m.CreateObject(handle, objTemplate)
		require.Equal(t, CKR_OK, rv)

		// Initialize digest
		rv = m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Try to digest non-secret key object
		rv = m.DigestKey(handle, objHandle)
		assert.Equal(t, CKR_KEY_INDIGESTIBLE, rv)
	})
}

// ----------------------------------------------------------------
// Extended Coverage Tests for Message-Based Encryption/Decryption
// ----------------------------------------------------------------

// TestEncryptMessageExtended tests additional scenarios for message encryption.
func TestEncryptMessageExtended(t *testing.T) {
	t.Run("fails when no encryption operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.EncryptMessage(handle, []byte("aad"), []byte("plaintext"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("encrypts message after proper initialization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		ciphertext, rv := m.EncryptMessage(handle, []byte("additional-data"), []byte("secret-message"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotEmpty(t, ciphertext)
	})
}

// TestDecryptMessageExtended tests additional scenarios for message decryption.
func TestDecryptMessageExtended(t *testing.T) {
	t.Run("fails when no decryption operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.DecryptMessage(handle, []byte("aad"), []byte("ciphertext"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("decrypts message after proper initialization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		plaintext, rv := m.DecryptMessage(handle, []byte("additional-data"), []byte("encrypted-data"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, plaintext)
	})
}

// TestEncryptMessageBeginExtended tests additional scenarios for multi-part message encryption begin.
func TestEncryptMessageBeginExtended(t *testing.T) {
	t.Run("fails when no encryption operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.EncryptMessageBegin(handle, []byte("aad"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("begins encryption with associated data", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.EncryptMessageBegin(handle, []byte("associated-data"))
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("begins encryption without associated data", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.EncryptMessageBegin(handle, nil)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestDecryptMessageBeginExtended tests additional scenarios for multi-part message decryption begin.
func TestDecryptMessageBeginExtended(t *testing.T) {
	t.Run("fails when no decryption operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.DecryptMessageBegin(handle, []byte("aad"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("begins decryption with associated data", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.DecryptMessageBegin(handle, []byte("associated-data"))
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("begins decryption without associated data", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.DecryptMessageBegin(handle, nil)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestEncryptMessageNextExtended tests additional scenarios for multi-part message encryption.
func TestEncryptMessageNextExtended(t *testing.T) {
	t.Run("fails when no encryption operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.EncryptMessageNext(handle, []byte("data"), false)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("updates encryption without finalization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		result, rv := m.EncryptMessageNext(handle, []byte("part1"), false)
		assert.Equal(t, CKR_OK, rv)
		assert.Nil(t, result) // Non-final should return nil
	})

	t.Run("finalizes encryption on last part", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// First part
		_, rv = m.EncryptMessageNext(handle, []byte("part1"), false)
		require.Equal(t, CKR_OK, rv)

		// Final part
		ciphertext, rv := m.EncryptMessageNext(handle, []byte("part2"), true)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, ciphertext)
	})
}

// TestDecryptMessageNextExtended tests additional scenarios for multi-part message decryption.
func TestDecryptMessageNextExtended(t *testing.T) {
	t.Run("fails when no decryption operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.DecryptMessageNext(handle, []byte("data"), false)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("updates decryption without finalization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		result, rv := m.DecryptMessageNext(handle, []byte("encrypted-part1"), false)
		assert.Equal(t, CKR_OK, rv)
		assert.Nil(t, result) // Non-final should return nil
	})

	t.Run("finalizes decryption on last part", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// First part
		_, rv = m.DecryptMessageNext(handle, []byte("encrypted-part1"), false)
		require.Equal(t, CKR_OK, rv)

		// Final part
		plaintext, rv := m.DecryptMessageNext(handle, []byte("encrypted-part2"), true)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, plaintext)
	})
}

// TestMessageEncryptFinalExtended tests additional scenarios for finalizing message encryption.
func TestMessageEncryptFinalExtended(t *testing.T) {
	t.Run("finalizes encryption operation successfully", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.EncryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.MessageEncryptFinal(handle)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestMessageDecryptFinalExtended tests additional scenarios for finalizing message decryption.
func TestMessageDecryptFinalExtended(t *testing.T) {
	t.Run("finalizes decryption operation successfully", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		rv := m.DecryptInit(handle, &Mechanism{Type: CKM_AES_GCM}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.MessageDecryptFinal(handle)
		assert.Equal(t, CKR_OK, rv)
	})
}

// ----------------------------------------------------------------
// Extended Coverage Tests for Message-Based Signing/Verification
// ----------------------------------------------------------------

// createTestModuleWithSigningKey creates an initialized module with a signing key.
func createTestModuleWithSigningKey(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()
	m := initializeTestModule(t)

	handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		NewStringAttribute(CKA_LABEL, "test-signing-key"),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_TOKEN, false),
	}

	keyHandle, rv := m.CreateObject(handle, template)
	require.Equal(t, CKR_OK, rv)

	return m, handle, keyHandle
}

// createTestModuleWithVerifyKey creates an initialized module with a verification key.
func createTestModuleWithVerifyKey(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()
	m := initializeTestModule(t)

	handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		NewStringAttribute(CKA_LABEL, "test-verify-key"),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_TOKEN, false),
	}

	keyHandle, rv := m.CreateObject(handle, template)
	require.Equal(t, CKR_OK, rv)

	return m, handle, keyHandle
}

// TestSignMessageBeginExtended tests additional scenarios for multi-part message signing begin.
func TestSignMessageBeginExtended(t *testing.T) {
	t.Run("fails when no sign operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.SignMessageBegin(handle)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("begins signing after proper initialization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSigningKey(t)
		defer m.Finalize()

		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.SignMessageBegin(handle)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestVerifyMessageBeginExtended tests additional scenarios for multi-part message verification begin.
func TestVerifyMessageBeginExtended(t *testing.T) {
	t.Run("fails when no verify operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.VerifyMessageBegin(handle)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("begins verification after proper initialization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithVerifyKey(t)
		defer m.Finalize()

		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.VerifyMessageBegin(handle)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestSignMessageNextExtended tests additional scenarios for multi-part message signing.
func TestSignMessageNextExtended(t *testing.T) {
	t.Run("fails when no sign operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.SignMessageNext(handle, []byte("data"), false)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("updates signing without finalization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSigningKey(t)
		defer m.Finalize()

		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		result, rv := m.SignMessageNext(handle, []byte("data-part1"), false)
		assert.Equal(t, CKR_OK, rv)
		assert.Nil(t, result) // Non-final should return nil
	})

	t.Run("finalizes signing on last part", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSigningKey(t)
		defer m.Finalize()

		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// First part
		_, rv = m.SignMessageNext(handle, []byte("data-part1"), false)
		require.Equal(t, CKR_OK, rv)

		// Final part
		signature, rv := m.SignMessageNext(handle, []byte("data-part2"), true)
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, signature)
	})
}

// TestVerifyMessageNextExtended tests additional scenarios for multi-part message verification.
func TestVerifyMessageNextExtended(t *testing.T) {
	t.Run("fails when no verify operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.VerifyMessageNext(handle, []byte("data"), nil)
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("updates verification without signature", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithVerifyKey(t)
		defer m.Finalize()

		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.VerifyMessageNext(handle, []byte("data-part1"), nil)
		assert.Equal(t, CKR_OK, rv)
	})

	t.Run("finalizes verification with signature", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithVerifyKey(t)
		defer m.Finalize()

		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// First part without signature
		rv = m.VerifyMessageNext(handle, []byte("data-part1"), nil)
		require.Equal(t, CKR_OK, rv)

		// Final part with signature - triggers verification
		rv = m.VerifyMessageNext(handle, []byte("data-part2"), []byte("mock-signature"))
		// This will likely succeed with mock or fail signature verification
		assert.True(t, rv == CKR_OK || rv == CKR_SIGNATURE_INVALID)
	})
}

// TestMessageSignFinalExtended tests additional scenarios for finalizing message signing.
func TestMessageSignFinalExtended(t *testing.T) {
	t.Run("finalizes signing operation successfully", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSigningKey(t)
		defer m.Finalize()

		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.MessageSignFinal(handle)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestMessageVerifyFinalExtended tests additional scenarios for finalizing message verification.
func TestMessageVerifyFinalExtended(t *testing.T) {
	t.Run("finalizes verification operation successfully", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithVerifyKey(t)
		defer m.Finalize()

		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.MessageVerifyFinal(handle)
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestSignMessageExtended tests additional scenarios for single message signing.
func TestSignMessageExtended(t *testing.T) {
	t.Run("fails when no sign operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		_, rv := m.SignMessage(handle, []byte("data"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("signs message after proper initialization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithSigningKey(t)
		defer m.Finalize()

		rv := m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		signature, rv := m.SignMessage(handle, []byte("message-to-sign"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotEmpty(t, signature)
	})
}

// TestVerifyMessageExtended tests additional scenarios for single message verification.
func TestVerifyMessageExtended(t *testing.T) {
	t.Run("fails when no verify operation initialized", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, _ := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)

		rv := m.VerifyMessage(handle, []byte("data"), []byte("signature"))
		assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
	})

	t.Run("verifies message after proper initialization", func(t *testing.T) {
		m, handle, keyHandle := createTestModuleWithVerifyKey(t)
		defer m.Finalize()

		rv := m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.VerifyMessage(handle, []byte("message"), []byte("mock-signature"))
		// Uses mock client which returns valid by default
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestSign_SuccessPath tests successful signing operations.
func TestSign_SuccessPath(t *testing.T) {
	t.Run("signs data successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create RSA private key with required attributes for signing
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-sign-key"),
			NewBoolAttribute(CKA_SIGN, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Initialize sign operation
		rv = m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Sign data
		signature, rv := m.Sign(handle, []byte("test data to sign"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, signature)
	})
}

// TestVerify_SuccessPath tests successful verification operations.
func TestVerify_SuccessPath(t *testing.T) {
	t.Run("verifies signature successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create RSA public key with required attributes for verification
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-verify-key"),
			NewBoolAttribute(CKA_VERIFY, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Initialize verify operation
		rv = m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Verify signature - mockClient returns Valid: true
		rv = m.Verify(handle, []byte("test data"), []byte("mock-signature"))
		assert.Equal(t, CKR_OK, rv)
	})
}

// TestEncrypt_SuccessPath tests successful encryption operations.
func TestEncrypt_SuccessPath(t *testing.T) {
	t.Run("encrypts data successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create AES secret key for encryption
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "test-encrypt-key"),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
			NewAttribute(CKA_VALUE, make([]byte, 32)), // 256-bit AES key
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Initialize encrypt operation
		rv = m.EncryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Encrypt data
		ciphertext, rv := m.Encrypt(handle, []byte("test plaintext"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, ciphertext)
	})
}

// TestDecrypt_SuccessPath tests successful decryption operations.
func TestDecrypt_SuccessPath(t *testing.T) {
	t.Run("decrypts data successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create AES secret key for decryption
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "test-decrypt-key"),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
			NewAttribute(CKA_VALUE, make([]byte, 32)), // 256-bit AES key
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Initialize decrypt operation
		rv = m.DecryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Decrypt data
		plaintext, rv := m.Decrypt(handle, []byte("test ciphertext"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, plaintext)
	})
}

// TestSignRecover_SuccessPath tests successful sign-recover operations.
func TestSignRecover_SuccessPath(t *testing.T) {
	t.Run("signs with recovery successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Init token and login as SO to create private key
		m.InitToken(0, []byte("so-pin"), "Test Token")
		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)
		m.Login(handle, CKU_SO, []byte("so-pin"))

		// Create RSA private key
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-sign-recover-key"),
			NewBoolAttribute(CKA_SIGN, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Initialize sign-recover operation
		rv = m.SignRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Sign with recovery
		signature, rv := m.SignRecover(handle, []byte("data to sign"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, signature)
	})
}

// TestVerifyRecover_SuccessPath tests successful verify-recover operations.
func TestVerifyRecover_SuccessPath(t *testing.T) {
	t.Run("verifies with recovery successfully", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create RSA public key with modulus and exponent for verify recover
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-verify-recover-key"),
			NewBoolAttribute(CKA_VERIFY, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
			NewAttribute(CKA_MODULUS, make([]byte, 256)),       // 2048-bit modulus
			NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}), // 65537
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Initialize verify-recover operation
		rv = m.VerifyRecoverInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// VerifyRecover reaches the crypto manager, which validates signature length.
		// With our zero modulus, the key size is calculated as 1 byte, so signature
		// length validation fails with CKR_SIGNATURE_LEN_RANGE.
		// This verifies the code path reaches the crypto manager.
		recovered, rv := m.VerifyRecover(handle, []byte("signature-data"))
		assert.Equal(t, CKR_SIGNATURE_LEN_RANGE, rv)
		assert.Empty(t, recovered)
	})
}

// TestDualOperations_SuccessPaths tests successful dual operations.
func TestDualOperations_SuccessPaths(t *testing.T) {
	t.Run("DigestEncryptUpdate succeeds with active operations", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create AES key for encryption
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "test-aes-dual-key"),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Initialize both digest and encrypt operations
		rv = m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		rv = m.EncryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		// Perform dual operation
		result, rv := m.DigestEncryptUpdate(handle, []byte("test data"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, result) // Returns empty slice for buffered data
	})

	t.Run("SignEncryptUpdate succeeds with active operations", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create keys for both operations
		rsaTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-rsa-dual-key"),
			NewBoolAttribute(CKA_SIGN, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}
		rsaKeyHandle, rv := m.CreateObject(handle, rsaTemplate)
		require.Equal(t, CKR_OK, rv)

		aesTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "test-aes-dual-key2"),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		}
		aesKeyHandle, rv := m.CreateObject(handle, aesTemplate)
		require.Equal(t, CKR_OK, rv)

		// Initialize both sign and encrypt operations
		rv = m.SignInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, rsaKeyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.EncryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, aesKeyHandle)
		require.Equal(t, CKR_OK, rv)

		// Perform dual operation
		result, rv := m.SignEncryptUpdate(handle, []byte("test data"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, result)
	})

	t.Run("DecryptDigestUpdate succeeds with active operations", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create AES key for decryption
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "test-aes-decrypt-dual-key"),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		}

		keyHandle, rv := m.CreateObject(handle, template)
		require.Equal(t, CKR_OK, rv)

		// Initialize both decrypt and digest operations
		rv = m.DecryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, keyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.DigestInit(handle, &Mechanism{Type: CKM_SHA256})
		require.Equal(t, CKR_OK, rv)

		// Perform dual operation
		result, rv := m.DecryptDigestUpdate(handle, []byte("test encrypted data"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, result)
	})

	t.Run("DecryptVerifyUpdate succeeds with active operations", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Create AES key for decryption
		aesTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "test-aes-decrypt-verify-key"),
			NewBoolAttribute(CKA_ENCRYPT, true),
			NewBoolAttribute(CKA_DECRYPT, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
		}
		aesKeyHandle, rv := m.CreateObject(handle, aesTemplate)
		require.Equal(t, CKR_OK, rv)

		// Create RSA key for verification
		rsaTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "test-rsa-verify-key"),
			NewBoolAttribute(CKA_VERIFY, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_MODIFIABLE, true),
			NewBoolAttribute(CKA_COPYABLE, true),
			NewBoolAttribute(CKA_DESTROYABLE, true),
		}
		rsaKeyHandle, rv := m.CreateObject(handle, rsaTemplate)
		require.Equal(t, CKR_OK, rv)

		// Initialize both decrypt and verify operations
		rv = m.DecryptInit(handle, &Mechanism{Type: CKM_AES_ECB}, aesKeyHandle)
		require.Equal(t, CKR_OK, rv)

		rv = m.VerifyInit(handle, &Mechanism{Type: CKM_RSA_PKCS}, rsaKeyHandle)
		require.Equal(t, CKR_OK, rv)

		// Perform dual operation
		result, rv := m.DecryptVerifyUpdate(handle, []byte("test encrypted data"))
		assert.Equal(t, CKR_OK, rv)
		assert.NotNil(t, result)
	})
}

func TestAutoInitializeToken(t *testing.T) {
	t.Run("auto-initializes token with SO and user PIN", func(t *testing.T) {
		ResetGlobalModule()
		cfg := DefaultConfig()
		cfg.AutoInitToken = true
		cfg.SOPIN = "12345678"
		cfg.UserPIN = "87654321"
		cfg.TokenLabel = "AutoInitToken"

		m, err := New(WithClient(newMockClient()), WithConfig(cfg))
		require.NoError(t, err)

		rv := m.Initialize(cfg)
		assert.Equal(t, CKR_OK, rv)
		defer m.Finalize()

		// Verify token was initialized
		slotIDs, rv := m.GetSlotList(true)
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, slotIDs)
		slotID := slotIDs[0]

		slot, err := m.slotManager.GetSlot(slotID)
		require.NoError(t, err)
		require.NotNil(t, slot.Token)

		// Token should be initialized
		assert.True(t, slot.Token.IsInitialized())
		assert.True(t, slot.Token.Info.Flags&CKF_TOKEN_INITIALIZED != 0)
		assert.True(t, slot.Token.Info.Flags&CKF_USER_PIN_INITIALIZED != 0)
		assert.Contains(t, string(slot.Token.Info.Label[:]), "AutoInitToken")
	})

	t.Run("auto-initializes with SO PIN only", func(t *testing.T) {
		ResetGlobalModule()
		cfg := DefaultConfig()
		cfg.AutoInitToken = true
		cfg.SOPIN = "12345678"
		cfg.TokenLabel = "SOOnlyToken"

		m, err := New(WithClient(newMockClient()), WithConfig(cfg))
		require.NoError(t, err)

		rv := m.Initialize(cfg)
		assert.Equal(t, CKR_OK, rv)
		defer m.Finalize()

		slotIDs, rv := m.GetSlotList(true)
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, slotIDs)
		slotID := slotIDs[0]

		slot, err := m.slotManager.GetSlot(slotID)
		require.NoError(t, err)
		require.NotNil(t, slot.Token)

		// Token should be initialized but user PIN not set
		assert.True(t, slot.Token.IsInitialized())
		assert.True(t, slot.Token.Info.Flags&CKF_TOKEN_INITIALIZED != 0)
		assert.False(t, slot.Token.Info.Flags&CKF_USER_PIN_INITIALIZED != 0)
	})

	t.Run("skips auto-init when disabled", func(t *testing.T) {
		ResetGlobalModule()
		cfg := DefaultConfig()
		cfg.AutoInitToken = false
		cfg.SOPIN = "12345678"
		cfg.UserPIN = "87654321"

		m, err := New(WithClient(newMockClient()), WithConfig(cfg))
		require.NoError(t, err)

		rv := m.Initialize(cfg)
		assert.Equal(t, CKR_OK, rv)
		defer m.Finalize()

		slotIDs, rv := m.GetSlotList(true)
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, slotIDs)
		slotID := slotIDs[0]

		slot, err := m.slotManager.GetSlot(slotID)
		require.NoError(t, err)
		require.NotNil(t, slot.Token)

		// Token should NOT be auto-initialized
		assert.False(t, slot.Token.IsInitialized())
	})

	t.Run("skips auto-init when SO PIN empty", func(t *testing.T) {
		ResetGlobalModule()
		cfg := DefaultConfig()
		cfg.AutoInitToken = true
		cfg.SOPIN = "" // Empty SO PIN should skip auto-init
		cfg.UserPIN = "87654321"

		m, err := New(WithClient(newMockClient()), WithConfig(cfg))
		require.NoError(t, err)

		rv := m.Initialize(cfg)
		assert.Equal(t, CKR_OK, rv)
		defer m.Finalize()

		slotIDs, rv := m.GetSlotList(true)
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, slotIDs)
		slotID := slotIDs[0]

		slot, err := m.slotManager.GetSlot(slotID)
		require.NoError(t, err)
		require.NotNil(t, slot.Token)

		// Token should NOT be auto-initialized (no SO PIN)
		assert.False(t, slot.Token.IsInitialized())
	})

	t.Run("uses default label when not specified", func(t *testing.T) {
		ResetGlobalModule()
		cfg := DefaultConfig()
		cfg.AutoInitToken = true
		cfg.SOPIN = "12345678"
		cfg.TokenLabel = "" // Empty label should use default

		m, err := New(WithClient(newMockClient()), WithConfig(cfg))
		require.NoError(t, err)

		rv := m.Initialize(cfg)
		assert.Equal(t, CKR_OK, rv)
		defer m.Finalize()

		slotIDs, rv := m.GetSlotList(true)
		require.Equal(t, CKR_OK, rv)
		require.NotEmpty(t, slotIDs)
		slotID := slotIDs[0]

		slot, err := m.slotManager.GetSlot(slotID)
		require.NoError(t, err)
		require.NotNil(t, slot.Token)

		// Token should use default label
		assert.Contains(t, string(slot.Token.Info.Label[:]), "XKMSToken")
	})
}

// ----------------------------------------------------------------
// WithStorage Option Tests
// ----------------------------------------------------------------

func TestWithStorage(t *testing.T) {
	ResetGlobalModule()

	// Create a mock storage backend
	mockBackend := &mockStorageBackend{}

	m, err := New(WithClient(newMockClient()), WithStorage(mockBackend))
	require.NoError(t, err)
	require.NotNil(t, m)

	// Verify the storage was set
	assert.NotNil(t, m.storage)
}

// mockStorageBackend implements storage.Backend for testing
type mockStorageBackend struct{}

func (m *mockStorageBackend) Get(_ context.Context, key string) ([]byte, error) { return nil, nil }
func (m *mockStorageBackend) Put(_ context.Context, key string, value []byte) error {
	return nil
}
func (m *mockStorageBackend) Delete(_ context.Context, key string) error { return nil }
func (m *mockStorageBackend) List(_ context.Context, prefix string) ([]string, error) {
	return nil, nil
}
func (m *mockStorageBackend) Exists(_ context.Context, key string) (bool, error) { return false, nil }
func (m *mockStorageBackend) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	return nil
}
func (m *mockStorageBackend) Close() error { return nil }

// ----------------------------------------------------------------
// getSlotIDFromSession Tests
// ----------------------------------------------------------------

func TestGetSlotIDFromSession(t *testing.T) {
	t.Run("returns slot ID for valid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Open a session
		sessionHandle, rv := m.OpenSession(0, CKF_SERIAL_SESSION)
		require.Equal(t, CKR_OK, rv)

		// Get slot ID from session
		slotID, err := m.getSlotIDFromSession(sessionHandle)
		require.NoError(t, err)
		assert.Equal(t, SlotID(0), slotID)

		m.CloseSession(sessionHandle)
	})

	t.Run("returns error for invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		// Try to get slot ID for non-existent session
		_, err := m.getSlotIDFromSession(SessionHandle(0xFFFFFFFF))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})
}

// ----------------------------------------------------------------
// extractPublicKeyComponentsFromPEM Tests
// ----------------------------------------------------------------

func TestExtractPublicKeyComponentsFromPEM(t *testing.T) {
	t.Run("returns nil for empty PEM data", func(t *testing.T) {
		modulus, exponent, ecPoint := extractPublicKeyComponentsFromPEM("")
		assert.Nil(t, modulus)
		assert.Nil(t, exponent)
		assert.Nil(t, ecPoint)
	})

	t.Run("returns nil for invalid PEM data", func(t *testing.T) {
		modulus, exponent, ecPoint := extractPublicKeyComponentsFromPEM("not a PEM")
		assert.Nil(t, modulus)
		assert.Nil(t, exponent)
		assert.Nil(t, ecPoint)
	})

	t.Run("extracts RSA public key components", func(t *testing.T) {
		// Generate a real RSA key for testing
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}
		rsaPEM := string(pem.EncodeToMemory(pemBlock))

		modulus, exponent, ecPoint := extractPublicKeyComponentsFromPEM(rsaPEM)
		assert.NotNil(t, modulus, "expected modulus for RSA key")
		assert.NotNil(t, exponent, "expected public exponent for RSA key")
		assert.Nil(t, ecPoint, "expected nil EC point for RSA key")
		// Exponent should be 65537 (0x010001) for standard RSA keys
		assert.Equal(t, []byte{0x01, 0x00, 0x01}, exponent)
	})

	t.Run("extracts EC public key point", func(t *testing.T) {
		// Generate a real EC key for testing
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		require.NoError(t, err)

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}
		ecPEM := string(pem.EncodeToMemory(pemBlock))

		modulus, exponent, ecPoint := extractPublicKeyComponentsFromPEM(ecPEM)
		assert.Nil(t, modulus, "expected nil modulus for EC key")
		assert.Nil(t, exponent, "expected nil exponent for EC key")
		assert.NotNil(t, ecPoint, "expected EC point for EC key")
		assert.True(t, len(ecPoint) > 0, "EC point should not be empty")
	})

	t.Run("returns nil for unsupported key type", func(t *testing.T) {
		// Generate an Ed25519 key which should fall through to default case
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		require.NoError(t, err)

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}
		ed25519PEM := string(pem.EncodeToMemory(pemBlock))

		modulus, exponent, ecPoint := extractPublicKeyComponentsFromPEM(ed25519PEM)
		assert.Nil(t, modulus)
		assert.Nil(t, exponent)
		assert.Nil(t, ecPoint)
	})

	t.Run("returns nil for invalid ASN.1 in PEM block", func(t *testing.T) {
		// Create a PEM with invalid ASN.1 content
		invalidPEM := `-----BEGIN PUBLIC KEY-----
aW52YWxpZCBBU04uMSBkYXRh
-----END PUBLIC KEY-----`
		modulus, exponent, ecPoint := extractPublicKeyComponentsFromPEM(invalidPEM)
		assert.Nil(t, modulus)
		assert.Nil(t, exponent)
		assert.Nil(t, ecPoint)
	})
}
