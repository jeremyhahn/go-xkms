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

package pkcs11test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// RunGeneralTests tests OASIS PKCS#11 v3.0 Section 5.4 General Purpose Functions:
// C_Initialize, C_Finalize, C_GetInfo, C_GetInterfaceList, C_GetInterface.
func (s *Suite) RunGeneralTests(t *testing.T) {
	t.Run("C_Initialize", s.testInitialize)
	t.Run("C_Finalize", s.testFinalize)
	t.Run("C_GetInfo", s.testGetInfo)
	t.Run("C_GetInterfaceList", s.testGetInterfaceList)
	t.Run("C_GetInterface", s.testGetInterface)
}

// testInitialize tests C_Initialize behavior per PKCS#11 v3.0 Section 5.4.
func (s *Suite) testInitialize(t *testing.T) {

	t.Run("Happy_InitializeReturnsOK", func(t *testing.T) {
		m, cleanup := s.factory(t)
		defer cleanup()

		rv := m.Initialize(nil)
		requireRV(t, module.CKR_OK, rv, "C_Initialize should return CKR_OK")

		if !m.IsInitialized() {
			t.Fatal("module should be initialized after successful C_Initialize")
		}

		// Clean up: finalize the module
		m.Finalize()
	})

	t.Run("Error_DoubleInitializeReturnsCryptokiAlreadyInitialized", func(t *testing.T) {
		m, cleanup := s.factory(t)
		defer cleanup()

		rv := m.Initialize(nil)
		requireRV(t, module.CKR_OK, rv, "first C_Initialize should succeed")

		rv = m.Initialize(nil)
		requireRV(t, module.CKR_CRYPTOKI_ALREADY_INITIALIZED, rv,
			"second C_Initialize should return CKR_CRYPTOKI_ALREADY_INITIALIZED")

		// Clean up: finalize the module
		m.Finalize()
	})
}

// testFinalize tests C_Finalize behavior per PKCS#11 v3.0 Section 5.4.
func (s *Suite) testFinalize(t *testing.T) {

	t.Run("Happy_FinalizeAfterInitializeReturnsOK", func(t *testing.T) {
		m, cleanup := s.factory(t)
		defer cleanup()

		rv := m.Initialize(nil)
		requireRV(t, module.CKR_OK, rv, "C_Initialize should succeed")

		rv = m.Finalize()
		requireRV(t, module.CKR_OK, rv, "C_Finalize should return CKR_OK")

		if m.IsInitialized() {
			t.Fatal("module should not be initialized after C_Finalize")
		}
	})

	t.Run("Error_FinalizeWithoutInitializeReturnsCryptokiNotInitialized", func(t *testing.T) {
		m, cleanup := s.factory(t)
		defer cleanup()

		rv := m.Finalize()
		requireRV(t, module.CKR_CRYPTOKI_NOT_INITIALIZED, rv,
			"C_Finalize without prior C_Initialize should return CKR_CRYPTOKI_NOT_INITIALIZED")
	})
}

// testGetInfo tests C_GetInfo behavior per PKCS#11 v3.0 Section 5.4.
//
// Per the PKCS#11 v3.0 specification, C_GetInfo may be called before
// C_Initialize. The module populates CK_INFO at construction time.
func (s *Suite) testGetInfo(t *testing.T) {

	t.Run("Happy_GetInfoAfterInitializeReturnsValidInfo", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		info, rv := m.GetInfo()
		requireRV(t, module.CKR_OK, rv, "C_GetInfo should return CKR_OK")

		if info == nil {
			t.Fatal("C_GetInfo returned nil CK_INFO")
		}

		// Verify the Cryptoki version is 3.0
		if info.CryptokiVersion.Major != module.CryptokiVersionMajor {
			t.Fatalf("CryptokiVersion.Major: expected %d, got %d",
				module.CryptokiVersionMajor, info.CryptokiVersion.Major)
		}
		if info.CryptokiVersion.Minor != module.CryptokiVersionMinor {
			t.Fatalf("CryptokiVersion.Minor: expected %d, got %d",
				module.CryptokiVersionMinor, info.CryptokiVersion.Minor)
		}

		// Verify ManufacturerID is non-empty
		mfr := info.GetManufacturerID()
		if mfr == "" {
			t.Fatal("ManufacturerID should be non-empty")
		}
	})

	t.Run("Happy_GetInfoBeforeInitializeReturnsOK", func(t *testing.T) {
		// Per PKCS#11 v3.0, C_GetInfo can be called before C_Initialize.
		m, cleanup := s.factory(t)
		defer cleanup()

		info, rv := m.GetInfo()
		requireRV(t, module.CKR_OK, rv,
			"C_GetInfo should return CKR_OK even before C_Initialize (PKCS#11 v3.0)")

		if info == nil {
			t.Fatal("C_GetInfo returned nil CK_INFO before C_Initialize")
		}

		// Version should still reflect the module's supported Cryptoki version
		if info.CryptokiVersion.Major != module.CryptokiVersionMajor {
			t.Fatalf("CryptokiVersion.Major before init: expected %d, got %d",
				module.CryptokiVersionMajor, info.CryptokiVersion.Major)
		}
		if info.CryptokiVersion.Minor != module.CryptokiVersionMinor {
			t.Fatalf("CryptokiVersion.Minor before init: expected %d, got %d",
				module.CryptokiVersionMinor, info.CryptokiVersion.Minor)
		}
	})
}

// testGetInterfaceList tests C_GetInterfaceList behavior per PKCS#11 v3.0 Section 5.4.
//
// Per the PKCS#11 v3.0 specification, C_GetInterfaceList may be called before
// C_Initialize to allow applications to discover interfaces.
func (s *Suite) testGetInterfaceList(t *testing.T) {

	t.Run("Happy_GetInterfaceListReturnsAtLeastOneInterface", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		interfaces, rv := m.GetInterfaceList()
		requireRV(t, module.CKR_OK, rv, "C_GetInterfaceList should return CKR_OK")

		if len(interfaces) == 0 {
			t.Fatal("C_GetInterfaceList should return at least one interface")
		}

		// The first interface should be the standard PKCS#11 interface
		if interfaces[0].Name != module.InterfaceNamePKCS11 {
			t.Fatalf("first interface name: expected %q, got %q",
				module.InterfaceNamePKCS11, interfaces[0].Name)
		}
	})

	t.Run("Happy_GetInterfaceListBeforeInitializeReturnsOK", func(t *testing.T) {
		// Per PKCS#11 v3.0, C_GetInterfaceList can be called before C_Initialize.
		m, cleanup := s.factory(t)
		defer cleanup()

		interfaces, rv := m.GetInterfaceList()
		requireRV(t, module.CKR_OK, rv,
			"C_GetInterfaceList should return CKR_OK even before C_Initialize (PKCS#11 v3.0)")

		if len(interfaces) == 0 {
			t.Fatal("C_GetInterfaceList should return at least one interface before C_Initialize")
		}

		if interfaces[0].Name != module.InterfaceNamePKCS11 {
			t.Fatalf("first interface name before init: expected %q, got %q",
				module.InterfaceNamePKCS11, interfaces[0].Name)
		}
	})
}

// testGetInterface tests C_GetInterface behavior per PKCS#11 v3.0 Section 5.4.
//
// Per the PKCS#11 v3.0 specification, C_GetInterface may be called before
// C_Initialize to allow applications to discover interfaces.
func (s *Suite) testGetInterface(t *testing.T) {

	t.Run("Happy_GetInterfaceByNameReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		iface, rv := m.GetInterface(module.InterfaceNamePKCS11, nil)
		requireRV(t, module.CKR_OK, rv, "C_GetInterface should return CKR_OK for standard interface")

		if iface == nil {
			t.Fatal("C_GetInterface returned nil for standard PKCS#11 interface")
		}

		if iface.Name != module.InterfaceNamePKCS11 {
			t.Fatalf("interface name: expected %q, got %q",
				module.InterfaceNamePKCS11, iface.Name)
		}
	})

	t.Run("Error_GetInterfaceUnknownNameReturnsArgumentsBad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		iface, rv := m.GetInterface("NonExistent Interface", nil)
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"C_GetInterface with unknown name should return CKR_ARGUMENTS_BAD")

		if iface != nil {
			t.Fatal("C_GetInterface should return nil interface for unknown name")
		}
	})

	t.Run("Happy_GetInterfaceBeforeInitializeReturnsOK", func(t *testing.T) {
		// Per PKCS#11 v3.0, C_GetInterface can be called before C_Initialize.
		m, cleanup := s.factory(t)
		defer cleanup()

		iface, rv := m.GetInterface(module.InterfaceNamePKCS11, nil)
		requireRV(t, module.CKR_OK, rv,
			"C_GetInterface should return CKR_OK even before C_Initialize (PKCS#11 v3.0)")

		if iface == nil {
			t.Fatal("C_GetInterface returned nil before C_Initialize for standard interface")
		}

		if iface.Name != module.InterfaceNamePKCS11 {
			t.Fatalf("interface name before init: expected %q, got %q",
				module.InterfaceNamePKCS11, iface.Name)
		}
	})

	t.Run("Error_GetInterfaceUnsupportedVersionReturnsArgumentsBad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		// Request a future version that the module does not support
		futureVersion := &module.Version{Major: module.CryptokiVersionMajor + 1, Minor: 0}
		iface, rv := m.GetInterface(module.InterfaceNamePKCS11, futureVersion)
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"C_GetInterface with unsupported future version should return CKR_ARGUMENTS_BAD")

		if iface != nil {
			t.Fatal("C_GetInterface should return nil interface for unsupported version")
		}
	})
}
